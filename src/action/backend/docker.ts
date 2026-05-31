import { randomBytes } from 'node:crypto';

import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess, runCommand } from './process.js';
import { stageRepoDirectory } from './stage.js';
import type { StagedRepo } from './stage.js';

export interface DockerBackendDeps {
  stderr?: { write(s: string): unknown };
  env?: NodeJS.ProcessEnv;
  /**
   * When true, a manifest entry that is still a bootstrap placeholder digest
   * (`...@sha256:PLACEHOLDER_*`) falls back to the tag-only ref so a fresh
   * first release works before the manifest is backfilled.  The CLI passes
   * `true`; the Action leaves it `false` (default), preserving its existing
   * behavior of returning the placeholder verbatim (which `docker pull` then
   * rejects — but `validateManifest` already fails the Action earlier).
   */
  allowTagFallback?: boolean;
}

interface HostOwner {
  uid: number;
  gid: number;
}

type RunCommand = (
  cmd: string,
  args: string[],
  opts?: { env?: NodeJS.ProcessEnv },
) => void;

export function createDockerBackend(deps: DockerBackendDeps = {}): AuditBackend {
  const env = deps.env ?? process.env;
  return {
    name: 'docker',
    async run(ctx: BackendContext) {
      if (!commandSucceeds('docker', ['version', '--format', '{{.Server.Version}}'], { env })) {
        throw new BackendUnavailableError('docker', 'docker is not installed or the daemon is unavailable');
      }

      const { ref: imageRef, warning } = resolveDockerImageRef(ctx, {
        allowTagFallback: deps.allowTagFallback ?? false,
      });
      if (warning !== undefined) writeDockerWarning(deps.stderr, warning);
      if (ctx.selfTest) {
        if (!commandSucceeds('docker', ['image', 'inspect', imageRef], { env })) {
          throw new BackendUnavailableError('docker', `local image ${imageRef} is missing`);
        }
      } else {
        try {
          runCommand('docker', ['pull', imageRef], { env });
        } catch (err) {
          throw new BackendUnavailableError(
            'docker',
            err instanceof Error ? err.message : String(err),
          );
        }
      }

      const staged = stageRepoDirectory({
        repoDir: ctx.repoDir,
        parentDir: ctx.scratchDir,
        extraRepoOverlayFiles: ctx.extraRepoOverlayFiles,
      });
      const containerName = `script-jail-${randomBytes(4).toString('hex')}`;
      try {
        const script = [
          'set -eu',
          'export VP_HOME=/opt/vp',
          'export COREPACK_HOME=/opt/vp/corepack',
          'export COREPACK_ENABLE_DOWNLOAD_PROMPT=0',
          'mkdir -p "${VP_HOME}" "${COREPACK_HOME}"',
          'NODE_VERSION="$(cat /etc/script-jail/node-version)"',
          'vp env install "${NODE_VERSION}" >&2',
          'NODE_BIN="$(find "${VP_HOME}/js_runtime" -maxdepth 4 -type d -name bin 2>/dev/null | head -n1)"',
          'test -n "${NODE_BIN}"',
          'export PATH="${NODE_BIN}:${PATH:-/usr/local/bin:/usr/bin:/bin}"',
          'corepack enable >&2',
          'mkdir -p /tmp/script-jail-strace',
          'export SCRIPT_JAIL_CONNECTION=stdio',
          'export SCRIPT_JAIL_CONFIG_PATH=/etc/script-jail/config.yml',
          'exec node /usr/local/lib/script-jail/guest-agent.cjs',
        ].join('; ');

        return await runAgentProcess({
          cmd: 'docker',
          args: [
            'run',
            '--rm',
            '-i',
            '--name', containerName,
            '--cap-add=SYS_PTRACE',
            '--security-opt', 'seccomp=unconfined',
            '-v', `${staged.path}:/work`,
            '-v', `${ctx.configPath}:/etc/script-jail/config.yml:ro`,
            imageRef,
            '/bin/sh',
            '-lc',
            script,
          ],
          env,
          label: 'docker',
          ...(deps.stderr !== undefined ? { stderr: deps.stderr } : {}),
          onFetchDone: async () => {
            runCommand('docker', ['network', 'disconnect', 'bridge', containerName], { env });
          },
        });
      } finally {
        try {
          runCommand('docker', ['rm', '-f', containerName], { env });
        } catch {
          // The --rm container is normally already gone.
        }
        cleanupStagedDockerRepo({
          staged,
          imageRef,
          env,
          ...(deps.stderr !== undefined ? { stderr: deps.stderr } : {}),
        });
      }
    },
  };
}

export function cleanupStagedDockerRepo(input: {
  staged: StagedRepo;
  imageRef: string;
  env?: NodeJS.ProcessEnv;
  stderr?: { write(s: string): unknown };
  hostOwner?: HostOwner | null;
  run?: RunCommand;
}): void {
  const run = input.run ?? runCommand;
  const hostOwner = Object.prototype.hasOwnProperty.call(input, 'hostOwner')
    ? (input.hostOwner ?? null)
    : getHostOwner();
  try {
    restoreStagedRepoOwnership({
      imageRef: input.imageRef,
      stagedPath: input.staged.path,
      hostOwner,
      run,
      ...(input.env !== undefined ? { env: input.env } : {}),
    });
  } catch (err) {
    writeDockerWarning(
      input.stderr,
      `failed to restore staged repo ownership: ${formatError(err)}`,
    );
  }

  try {
    input.staged.cleanup();
  } catch (err) {
    writeDockerWarning(
      input.stderr,
      `failed to remove staged repo: ${formatError(err)}`,
    );
  }
}

function restoreStagedRepoOwnership(input: {
  imageRef: string;
  stagedPath: string;
  env?: NodeJS.ProcessEnv;
  hostOwner: HostOwner | null;
  run: RunCommand;
}): void {
  if (input.hostOwner === null) return;
  input.run('docker', [
    'run',
    '--rm',
    '-v', `${input.stagedPath}:/work`,
    input.imageRef,
    '/bin/sh',
    '-lc',
    `find /work -xdev -exec chown -h ${input.hostOwner.uid}:${input.hostOwner.gid} {} +`,
  ], input.env !== undefined ? { env: input.env } : {});
}

function getHostOwner(): HostOwner | null {
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    return null;
  }
  return { uid: process.getuid(), gid: process.getgid() };
}

function writeDockerWarning(
  stderr: { write(s: string): unknown } | undefined,
  message: string,
): void {
  (stderr ?? process.stderr).write(`[docker:warn] ${message}\n`);
}

function formatError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export interface ResolvedDockerImage {
  ref: string;
  /** Set when a placeholder digest was downgraded to a tag-only ref. */
  warning?: string;
}

/**
 * Resolve the Docker image ref for this run.
 *
 * Throws `BackendUnavailableError` only when the manifest has NO entry for
 * `(arch, runnerImage)` — a genuine config error.  When the entry is still a
 * bootstrap placeholder digest and `allowTagFallback` is set, downgrade to the
 * tag-only ref (`split('@')[0]`) and return a warning; otherwise return the
 * (placeholder) ref verbatim — the Action's pre-flight `validateManifest`
 * rejects placeholders before any backend runs, so this preserves today's
 * behavior for the Action.
 */
export function resolveDockerImageRef(
  ctx: BackendContext,
  opts: { allowTagFallback?: boolean } = {},
): ResolvedDockerImage {
  if (ctx.selfTest) {
    return {
      ref:
        ctx.arch === 'arm64'
          ? `script-jail-rootfs:${ctx.runnerImage}-arm64`
          : `script-jail-rootfs:${ctx.runnerImage}`,
    };
  }
  const ref = ctx.manifest.dockerImages?.[ctx.arch]?.[ctx.runnerImage];
  if (ref === undefined || ref.trim() === '') {
    throw new BackendUnavailableError(
      'docker',
      `manifest has no Docker image for ${ctx.runnerImage}/${ctx.arch}`,
    );
  }
  if (ref.includes('PLACEHOLDER') && opts.allowTagFallback) {
    const tagRef = ref.split('@')[0] ?? ref;
    return {
      ref: tagRef,
      warning:
        `using non-digest-pinned image ${tagRef} (manifest digest is a bootstrap ` +
        `placeholder); pin a real digest in src/action/artifact-manifest.ts at v0.1.1`,
    };
  }
  return { ref };
}

import { randomBytes } from 'node:crypto';

import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess, runCommand } from './process.js';
import { stageRepoDirectory } from './stage.js';
import type { StagedRepo } from './stage.js';
import { stripDangerousEnv } from '../host-install.js';

export interface DockerBackendDeps {
  stderr?: { write(s: string): unknown };
  env?: NodeJS.ProcessEnv;
  commandSucceeds?: typeof commandSucceeds;
  runAgentProcess?: typeof runAgentProcess;
  runCommand?: typeof runCommand;
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
  const doCommandSucceeds = deps.commandSucceeds ?? commandSucceeds;
  const doRunAgentProcess = deps.runAgentProcess ?? runAgentProcess;
  const doRunCommand = deps.runCommand ?? runCommand;

  // SECURITY (pre-trust bare-name `docker` resolution): every HOST invocation
  // below runs the `docker` CLI by BARE NAME (resolved via PATH) BEFORE the audit
  // trust gate — the availability probe, the pull, the `docker run` agent, the
  // network-disconnect / `rm -f` teardown, and the ownership-restore chown.  A
  // checkout-prepended PATH dir could otherwise run a PR-committed `./docker`, or
  // an inherited LD_PRELOAD/DYLD_*/NODE_OPTIONS could inject into the host `docker`
  // process, BEFORE anything is trusted.  Sanitize ONCE here (same policy as the
  // host install + the bare backend) and use `safeEnv` for ALL host `docker` spawns.
  // NOTE: this is the HOST CLI env only — the IN-CONTAINER PATH/env the agent script
  // exports inside `docker run … /bin/sh -lc` is untouched (it runs in the guest).
  const safeEnv = stripDangerousEnv(env);

  return {
    name: 'docker',
    async run(ctx: BackendContext) {
      if (!doCommandSucceeds('docker', ['version', '--format', '{{.Server.Version}}'], { env: safeEnv })) {
        throw new BackendUnavailableError('docker', 'docker is not installed or the daemon is unavailable');
      }

      const { ref: imageRef, warning } = resolveDockerImageRef(ctx, {
        allowTagFallback: deps.allowTagFallback ?? false,
      });
      if (warning !== undefined) writeDockerWarning(deps.stderr, warning);
      if (ctx.selfTest) {
        if (!doCommandSucceeds('docker', ['image', 'inspect', imageRef], { env: safeEnv })) {
          throw new BackendUnavailableError('docker', `local image ${imageRef} is missing`);
        }
      } else {
        try {
          doRunCommand('docker', ['pull', imageRef], { env: safeEnv });
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
      // install:true cwd parity — mount the staged repo at the SAME absolute
      // path the host re-run uses (ctx.repoDir, threaded via auditWorkDir) so
      // the audited `process.cwd()` matches the host's, closing a cwd oracle;
      // falls back to `/work` for a normal audit.  The config's work_dir
      // matches (set by buildEffectiveConfig from installWorkDir), so the
      // agent cd's here.
      const workDir = ctx.auditWorkDir ?? '/work';
      // Container-side path of the host-owned pm-flags sidecar.  Passed to the guest
      // via the container ENV (`-e` below), NOT a shell `export` (#31) — see the note
      // at the `-e` flag for why interpolating workDir into `/bin/sh -lc` is unsafe.
      const pmFlagsPath = `${workDir}/etc/script-jail/pm-flags.json`;
      try {
        const script = [
          'set -eu',
          'export VP_HOME=/opt/vp',
          'export COREPACK_HOME=/opt/vp/corepack',
          'export COREPACK_ENABLE_DOWNLOAD_PROMPT=0',
          // round-17f (codex [critical], uniform policy): never load a PROJECT
          // `.corepack.env` (cwd=repoDir).  Docker already sets COREPACK_HOME (so the
          // file can't steer it — process.env wins, corepack.cjs:13556) and Phase B
          // direct-launches, so this is defense-in-depth, but pinning it on EVERY
          // backend + the host keeps one "ignore .corepack.env" policy (mirrors how
          // COREPACK_ENABLE_DOWNLOAD_PROMPT is pinned everywhere).
          'export COREPACK_ENV_FILE=0',
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
          // SCRIPT_JAIL_PM_FLAGS_PATH is delivered via the container `-e` env below,
          // NOT exported here — see the note at the `-e` flag (#31).
          'exec node /usr/local/lib/script-jail/guest-agent.cjs',
        ].join('; ');

        return await doRunAgentProcess({
          cmd: 'docker',
          args: [
            'run',
            '--rm',
            '-i',
            '--name', containerName,
            '--cap-add=SYS_PTRACE',
            '--security-opt', 'seccomp=unconfined',
            '-v', `${staged.path}:${workDir}`,
            '-v', `${ctx.configPath}:/etc/script-jail/config.yml:ro`,
            // The host-owned pm-flags sidecar is staged in the repo tree at
            // <workDir>/etc/script-jail/pm-flags.json (Docker does not copy it into
            // /etc the way Firecracker's init does).  Point the guest at it so the
            // sandbox fetch applies the SAME install args as the host part-1 install.
            // Delivered via the container ENV (`-e`), NOT a shell `export` interpolated
            // into `/bin/sh -lc` (#31): under install:true workDir IS the host repoDir
            // (SCRIPT_JAIL_REPO_DIR / process.cwd() / GITHUB_WORKSPACE — never validated
            // for spaces/metachars), so an unquoted `export SCRIPT_JAIL_PM_FLAGS_PATH=
            // ${workDir}/...` would split on a space (`export: not a valid identifier`
            // under `set -eu`, aborting the audit) or shell-evaluate a `$(...)`.  As a
            // single `-e NAME=value` argv element the value is literal regardless of its
            // content — mirroring how bare/mac-bare pass it via the process env object.
            // loadPmFlags re-sanitizes the file before use.
            '-e', `SCRIPT_JAIL_PM_FLAGS_PATH=${pmFlagsPath}`,
            imageRef,
            '/bin/sh',
            '-lc',
            script,
          ],
          env: safeEnv,
          label: 'docker',
          ...(deps.stderr !== undefined ? { stderr: deps.stderr } : {}),
          onFetchDone: async () => {
            doRunCommand('docker', ['network', 'disconnect', 'bridge', containerName], { env: safeEnv });
          },
        });
      } finally {
        try {
          doRunCommand('docker', ['rm', '-f', containerName], { env: safeEnv });
        } catch {
          // The --rm container is normally already gone.
        }
        cleanupStagedDockerRepo({
          staged,
          imageRef,
          env: safeEnv,
          run: doRunCommand,
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

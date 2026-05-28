import { randomBytes } from 'node:crypto';

import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess, runCommand } from './process.js';
import { stageRepoDirectory } from './stage.js';
import type { StagedRepo } from './stage.js';

export interface DockerBackendDeps {
  stderr?: { write(s: string): unknown };
  env?: NodeJS.ProcessEnv;
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

      const imageRef = resolveDockerImage(ctx);
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

function resolveDockerImage(ctx: BackendContext): string {
  if (ctx.selfTest) {
    return ctx.arch === 'arm64'
      ? `script-jail-rootfs:${ctx.runnerImage}-arm64`
      : `script-jail-rootfs:${ctx.runnerImage}`;
  }
  const ref = ctx.manifest.dockerImages?.[ctx.arch]?.[ctx.runnerImage];
  if (ref === undefined || ref.trim() === '') {
    throw new BackendUnavailableError(
      'docker',
      `manifest has no Docker image for ${ctx.runnerImage}/${ctx.arch}`,
    );
  }
  return ref;
}

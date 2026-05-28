import { randomBytes } from 'node:crypto';

import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess, runCommand } from './process.js';
import { stageRepoDirectory } from './stage.js';

export interface DockerBackendDeps {
  stderr?: { write(s: string): unknown };
  env?: NodeJS.ProcessEnv;
}

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
          'NODE_VERSION="$(cat /etc/script-jail/node-version)"',
          'vp env install "${NODE_VERSION}"',
          'NODE_BIN="$(find /opt/vp/js_runtime -maxdepth 4 -type d -name bin 2>/dev/null | head -n1)"',
          'test -n "${NODE_BIN}"',
          'export PATH="${NODE_BIN}:${PATH:-/usr/local/bin:/usr/bin:/bin}"',
          'corepack enable',
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
        staged.cleanup();
      }
    },
  };
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

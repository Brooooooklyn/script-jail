import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { platform } from 'node:process';

import { preFetchArtifacts } from '../pre-fetch-artifacts.js';
import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess } from './process.js';
import {
  controlSidecarEnv,
  partitionControlSidecars,
  rewriteConfigWorkDir,
  stageRepoDirectory,
} from './stage.js';
import { stripDangerousEnv } from '../host-install.js';

export interface BareBackendDeps {
  preFetchArtifacts?: typeof preFetchArtifacts;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  stderr?: { write(s: string): unknown };
  commandSucceeds?: typeof commandSucceeds;
  runAgentProcess?: typeof runAgentProcess;
}

export function createBareBackend(deps: BareBackendDeps = {}): AuditBackend {
  const hostPlatform = deps.platform ?? platform;
  const env = deps.env ?? process.env;
  const doPreFetchArtifacts = deps.preFetchArtifacts ?? preFetchArtifacts;
  const doCommandSucceeds = deps.commandSucceeds ?? commandSucceeds;
  const doRunAgentProcess = deps.runAgentProcess ?? runAgentProcess;

  // SECURITY (codex round-4 [critical]): the bare backend runs ON THE HOST with the
  // inherited runner env, so the capability PROBES below (strace/unshare, resolved
  // by BARE NAME) and the agent spawn must ALL use the sanitized env — otherwise a
  // checkout-prepended PATH could run a PR-provided `strace`/`unshare`, or an
  // inherited LD_PRELOAD/LD_AUDIT could inject into them, BEFORE any trust gate.
  // One policy, applied at every host-exec boundary on this backend.
  const safeEnv = stripDangerousEnv(env);

  return {
    name: 'bare',
    async run(ctx: BackendContext) {
      if (hostPlatform !== 'linux') {
        throw new BackendUnavailableError('bare', `requires Linux (detected ${hostPlatform})`);
      }
      if (!doCommandSucceeds('strace', ['-V'], { env: safeEnv })) {
        throw new BackendUnavailableError('bare', 'strace is not available');
      }
      if (!doCommandSucceeds('unshare', ['-n', '--', 'true'], { env: safeEnv })) {
        throw new BackendUnavailableError('bare', 'unshare -n is not available');
      }

      if (!ctx.selfTest) {
        await doPreFetchArtifacts({
          imagesDir: ctx.imagesDir,
          runnerImage: ctx.runnerImage,
          manifest: ctx.manifest,
          http: ctx.http,
          arch: ctx.arch,
          platform: ctx.arch === 'arm64' ? 'darwin' : 'linux',
        });
      }

      const runtime = resolveRuntimePaths(ctx);
      // SECURITY (audit-only sidecar oracle): deliver script-jail's control sidecars
      // (pm-flags.json / pnpm-arch.json) as env CONTENT, NOT a file in the staged repo
      // tree; `.yarnrc.yml` stays (genuine repo config).  The guest reads pm-flags from
      // SCRIPT_JAIL_{PM_FLAGS,PNPM_ARCH}_CONTENT (set below), so the audited repo root no
      // longer contains an `etc/script-jail/` that the host's real checkout lacks.
      // (bare/mac-bare are not install-aligned, so there is no host re-run to diverge from
      // here — this also removes the pure-audit surface pollution and keeps one delivery
      // policy uniform with docker/Firecracker.)
      const { repoOverlay, controlSidecars } = partitionControlSidecars(
        ctx.extraRepoOverlayFiles,
      );
      const staged = stageRepoDirectory({
        repoDir: ctx.repoDir,
        parentDir: ctx.scratchDir,
        extraRepoOverlayFiles: repoOverlay,
      });
      const controlEnv = controlSidecarEnv(controlSidecars);
      const backendConfigPath = rewriteConfigWorkDir({
        configPath: ctx.configPath,
        outDir: ctx.scratchDir,
        workDir: staged.path,
      });

      try {
        return await doRunAgentProcess({
          cmd: process.execPath,
          args: [runtime.agentPath],
          env: {
            // PARITY: the bare agent runs ON THE HOST and inherits the runner env
            // (unlike the clean-VM Firecracker/Docker guest).  `safeEnv` already
            // stripped the dangerous loader/tool/config selectors + sanitized PATH
            // (same policy as the host install + the probes above), so the bare
            // AUDIT sees the same env the hardened host install does and an
            // inherited NODE_OPTIONS can't inject into the agent process itself.
            ...safeEnv,
            // stripDangerousEnv now drops the whole COREPACK_* family (incl. any
            // inherited COREPACK_ENABLE_DOWNLOAD_PROMPT), so re-pin it here — corepack
            // 0.35.0 defaults the prompt ON, and an uncached pm download would block
            // the bare AUDIT otherwise (mac-bare/docker/init.sh re-pin it the same way).
            COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
            // round-17f (codex [critical]): corepack loads a PROJECT `.corepack.env`
            // (cwd=repoDir) at startup unless COREPACK_ENV_FILE=0; process.env WINS over
            // the file (corepack.cjs:13556).  The bare AUDIT has NO COREPACK_HOME set, so
            // a repo `.corepack.env` setting COREPACK_HOME=<checkout>/evil would steer
            // both Phase A AND the bare-launched Phase B corepack shim to a planted cache
            // (Phase B is straced → it would even diverge from the host part-2, which now
            // pins COREPACK_ENV_FILE=0).  Pin it here so the bare audit ignores the file,
            // matching the host install.  (Set as a literal AFTER the safeEnv strip, like
            // the download-prompt flag — survives into the agent's PM children.)
            COREPACK_ENV_FILE: '0',
            SCRIPT_JAIL_CONNECTION: 'stdio',
            SCRIPT_JAIL_CONFIG_PATH: backendConfigPath,
            // Bare mode runs the agent directly on the host (no container /etc).  Deliver
            // the pm-flags / pnpm-arch control sidecars as env CONTENT (no file at any
            // path), keeping `etc/script-jail/` out of the audited repo root (audit-only
            // sidecar oracle).  Empty dict when no sidecar → guest degrades to "no
            // override".  loadPmFlags / applyPnpmArchOverlay re-sanitize the content.
            ...controlEnv,
            SCRIPT_JAIL_NATIVE_PRELOAD_PATH: runtime.nativePreloadPath,
            SCRIPT_JAIL_PLATFORM_PRELOAD_PATH: runtime.platformPreloadPath,
            SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH: runtime.envSpyPreloadPath,
            SCRIPT_JAIL_PHASE_B_UNSHARE_NET: '1',
          },
          label: 'bare',
          ...(deps.stderr !== undefined ? { stderr: deps.stderr } : {}),
        });
      } finally {
        staged.cleanup();
      }
    },
  };
}

function resolveRuntimePaths(ctx: BackendContext): {
  agentPath: string;
  nativePreloadPath: string;
  platformPreloadPath: string;
  envSpyPreloadPath: string;
} {
  const moduleDir = currentModuleDir();
  const roots = [
    process.env['SCRIPT_JAIL_ACTION_ROOT'],
    process.env['GITHUB_ACTION_PATH'],
    moduleDir,
    join(moduleDir, '..'),
    join(moduleDir, '..', '..'),
    process.cwd(),
  ].filter((p): p is string => typeof p === 'string' && p.length > 0);

  const agentPath = findFirst([
    ...roots.map((root) => join(root, 'guest-agent.cjs')),
    ...roots.map((root) => join(root, 'dist', 'guest-agent.cjs')),
  ], 'guest-agent.cjs');

  const platformPreloadPath = findFirst([
    ...roots.map((root) => join(root, 'preloads', 'platform-spoof.cjs')),
    ...roots.map((root) => join(root, 'dist', 'preloads', 'platform-spoof.cjs')),
  ], 'platform-spoof.cjs');

  const envSpyPreloadPath = findFirst([
    ...roots.map((root) => join(root, 'preloads', 'env-spy.cjs')),
    ...roots.map((root) => join(root, 'dist', 'preloads', 'env-spy.cjs')),
  ], 'env-spy.cjs');

  const libName = ctx.arch === 'arm64' ? 'libscriptjail-arm64.so' : 'libscriptjail.so';
  const nativePreloadPath = findFirst([
    join(ctx.imagesDir, libName),
    join(ctx.imagesDir, 'libscriptjail.so'),
    ...roots.map((root) => join(root, 'images', libName)),
    ...roots.map((root) => join(root, 'images', 'libscriptjail.so')),
  ], libName);

  return {
    agentPath,
    nativePreloadPath,
    platformPreloadPath,
    envSpyPreloadPath,
  };
}

function currentModuleDir(): string {
  if (typeof __dirname === 'string') return __dirname;
  return process.cwd();
}

function findFirst(candidates: string[], label: string): string {
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new BackendUnavailableError('bare', `${label} was not found`);
}

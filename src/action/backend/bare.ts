import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { platform } from 'node:process';

import { preFetchArtifacts } from '../pre-fetch-artifacts.js';
import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds, runAgentProcess } from './process.js';
import { rewriteConfigWorkDir, stageRepoDirectory } from './stage.js';

export interface BareBackendDeps {
  preFetchArtifacts?: typeof preFetchArtifacts;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  stderr?: { write(s: string): unknown };
}

export function createBareBackend(deps: BareBackendDeps = {}): AuditBackend {
  const hostPlatform = deps.platform ?? platform;
  const env = deps.env ?? process.env;
  const doPreFetchArtifacts = deps.preFetchArtifacts ?? preFetchArtifacts;

  return {
    name: 'bare',
    async run(ctx: BackendContext) {
      if (hostPlatform !== 'linux') {
        throw new BackendUnavailableError('bare', `requires Linux (detected ${hostPlatform})`);
      }
      if (!commandSucceeds('strace', ['-V'], { env })) {
        throw new BackendUnavailableError('bare', 'strace is not available');
      }
      if (!commandSucceeds('unshare', ['-n', '--', 'true'], { env })) {
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
      const staged = stageRepoDirectory({
        repoDir: ctx.repoDir,
        parentDir: ctx.scratchDir,
        extraRepoOverlayFiles: ctx.extraRepoOverlayFiles,
      });
      const backendConfigPath = rewriteConfigWorkDir({
        configPath: ctx.configPath,
        outDir: ctx.scratchDir,
        workDir: staged.path,
      });

      try {
        return await runAgentProcess({
          cmd: process.execPath,
          args: [runtime.agentPath],
          env: {
            ...env,
            SCRIPT_JAIL_CONNECTION: 'stdio',
            SCRIPT_JAIL_CONFIG_PATH: backendConfigPath,
            // Bare mode runs the agent directly on the host (no container /etc),
            // so the host-owned pm-flags sidecar lives in the staged repo tree.
            // Point the guest at it so the sandbox fetch applies the SAME
            // install args as the host part-1 install.  loadPmFlags
            // re-sanitizes the file before use.
            SCRIPT_JAIL_PM_FLAGS_PATH: join(staged.path, 'etc/script-jail/pm-flags.json'),
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

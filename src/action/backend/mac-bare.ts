// script-jail — src/action/backend/mac-bare.ts
//
// macOS-native "bare" audit backend (Phase 5).  Unlike firecracker / docker /
// bare, this is NOT an `AuditBackend` in the `auto` selection order — there is
// no VM and no Linux guest, so it cannot be a drop-in among the Linux backends.
// Instead it is an `execute`-style closure the macOS CLI hands to
// `runAudit({ execute })` (the SAME shared diff / write / audit-bypass-gate
// path the Linux backends use).
//
// What it does:
//   1. Preconditions (fail-closed): host is darwin; the Mach-O shim dylib is
//      present; a re-signed Node toolchain can be provisioned.  If the shim
//      cannot load (R2), we HARD-FAIL rather than emit a clean-looking empty
//      lockfile.
//   2. Provision + ad-hoc re-sign Node (provision-node-mac.ts) so
//      DYLD_INSERT_LIBRARIES is honoured, plus re-signed shell/coreutils copies
//      for the shim's SIP redirect.
//   3. Stage the repo (so lifecycle scripts cannot mutate the user's tree) and
//      rewrite the config's work_dir to the staged copy.
//   4. Spawn the macOS orchestrator (`dist/guest-agent.cjs` in darwin mode) via
//      `runAgentProcess` over stdio, with the env contract the guest's `main()`
//      reads (SCRIPT_JAIL_CONNECTION=stdio + SCRIPT_JAIL_BACKEND=macos-bare +
//      config path + dylib + JS preloads + shell-shim dir + the provisioned
//      node bin dir PREPENDED to PATH).  NO SCRIPT_JAIL_PHASE_B_UNSHARE_NET —
//      macOS has no network namespace to drop, and macOS-bare does NOT enforce
//      offline: it is OBSERVE-ONLY and stays ONLINE.  net.rs forwards
//      connect/connectx and records the TRUE result (gated on
//      SCRIPT_JAIL_MACOS_AUDIT_OPS, Phase B only); parity-diff reconciles the
//      offline-Linux / online-macOS split by stripping the `<BLOCKED> ` prefix.
//      Firecracker is the high-assurance backend (see docs/divergence.md).
//
// Everything here is darwin-only.  No Linux path imports this module.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { platform as hostPlatform } from 'node:process';

import type { AuditExecutionInput, LauncherResult } from '../../shared/run-audit.js';
import { runAgentProcess } from './process.js';
import { rewriteConfigWorkDir, stageRepoDirectory } from './stage.js';
import {
  provisionNodeMac,
  defaultProvisionCacheDir,
  type ProvisionedNodeMac,
} from '../../cli/provision-node-mac.js';
import { expectedMachOCpuType, validateMachOShimFile } from '../../rootfs/macho.js';
import type { VitePlusArch } from '../../rootfs/vite-plus.js';

/** Raised when a precondition for the bare macOS backend is not met. */
export class MacBareUnavailableError extends Error {
  constructor(message: string) {
    super(`script-jail mac-bare: ${message}`);
    this.name = 'MacBareUnavailableError';
  }
}

export interface MacBareExecuteDeps {
  /**
   * Directory holding the runtime artifacts: the `libscriptjail-arm64.dylib`
   * Mach-O shim lives here (the resolved platform-package / dev `images/` dir).
   */
  imagesDir: string;
  /**
   * script-jail package root — anchors `dist/guest-agent.cjs` +
   * `dist/preloads/*.cjs` resolution (and the dev `images/` fallback).
   */
  repoRoot: string;
  /** Host arch (darwin-arm64; darwin-x64 builds the dylib from source — R10). */
  arch: VitePlusArch;
  /** stderr sink for the orchestrator's `[mac-bare:err]` stream. */
  stderr?: { write(s: string): unknown };
  /** Process env to seed the orchestrator's env from (default: process.env). */
  env?: NodeJS.ProcessEnv;
  // --- Test seams (production callers leave undefined) ---------------------
  platform?: NodeJS.Platform;
  existsSync?: typeof existsSync;
  provisionNodeMac?: typeof provisionNodeMac;
  runAgentProcess?: typeof runAgentProcess;
  validateMachOShimFile?: typeof validateMachOShimFile;
}

/**
 * Host env vars whose VALUE the orchestrator forwards into the audited install
 * children.  Everything else is reconstructed (PATH below) or pnpm-injected at
 * lifecycle time — so the macOS child env mirrors the Linux container's curated
 * set instead of inheriting the full host/CI env.
 *
 * Why this matters for parity: the install children enumerate `process.env`
 * (env-spy's Proxy records every key), so any host var present in the child env
 * lands in the lock's `env_read`.  Spreading the full GitHub-runner env floods
 * `env_read` with ~120 `ACTIONS_*` / `GITHUB_*` / `RUNNER_*` / `HOMEBREW_*` /
 * `JAVA_HOME_*` / … names that the Linux backend never sees (Docker/Firecracker
 * reconstruct env from scratch — see `src/rootfs/init.sh` + `docker.ts`).
 *
 * Keep this list MINIMAL and mirror init.sh:
 *   - PATH is rebuilt explicitly (`prependPath`) below, not forwarded here.
 *   - SCRIPT_JAIL_* control vars are set explicitly below.
 *   - npm_config_* / npm_package_* / INIT_CWD / NODE / PNPM_SCRIPT_SRC_DIR are
 *     injected by pnpm per-lifecycle on BOTH platforms — do NOT hoist them.
 *   - VP_HOME / COREPACK_HOME are Linux-only (the bare backend has no /opt/vp);
 *     they are reconciled as parity-only residuals at diff time, not forwarded.
 *   - HOME / TMPDIR are genuinely needed (npm/pnpm/corepack cache roots, the
 *     events-file dir, and `$HOME`/`$TMPDIR` path tokenization).
 */
const MACOS_ORCHESTRATOR_ENV_ALLOWLIST = ['HOME', 'TMPDIR'] as const;

/**
 * Reconstruct the orchestrator child env from `baseEnv` using
 * {@link MACOS_ORCHESTRATOR_ENV_ALLOWLIST} (allowlist, never a denylist — a new
 * host var must be opted in, not remembered-to-be-excluded).
 */
function pickOrchestratorEnv(baseEnv: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const name of MACOS_ORCHESTRATOR_ENV_ALLOWLIST) {
    const value = baseEnv[name];
    if (value !== undefined) out[name] = value;
  }
  return out;
}

/**
 * Build the `execute` closure the macOS CLI passes to `runAudit`.  The closure
 * is invoked ONCE per audit with the prepared `AuditExecutionInput` (effective
 * config path + extraRepoOverlayFiles + the private scratch dir).
 */
export function createMacBareExecute(
  deps: MacBareExecuteDeps,
): (input: AuditExecutionInput) => Promise<LauncherResult> {
  const platform = deps.platform ?? hostPlatform;
  const doExists = deps.existsSync ?? existsSync;
  const doProvision = deps.provisionNodeMac ?? provisionNodeMac;
  const doRunAgentProcess = deps.runAgentProcess ?? runAgentProcess;
  const doValidateShim = deps.validateMachOShimFile ?? validateMachOShimFile;
  const baseEnv = deps.env ?? process.env;

  return async function macBareExecute(
    input: AuditExecutionInput,
  ): Promise<LauncherResult> {
    // --- Preconditions (fail-closed) --------------------------------------
    if (platform !== 'darwin') {
      throw new MacBareUnavailableError(`requires macOS (detected ${platform})`);
    }

    const runtime = resolveRuntimePaths(deps.repoRoot, deps.imagesDir, doExists);

    // The Mach-O shim is the SOLE event source on macOS.  If it is missing we
    // would silently produce an empty lockfile — hard-fail instead (R2).
    if (!doExists(runtime.nativePreloadPath)) {
      throw new MacBareUnavailableError(
        `Mach-O shim not found at ${runtime.nativePreloadPath}. ` +
          `Build it with \`pnpm build\` on an Apple Silicon mac (or fetch the ` +
          `release dylib).`,
      );
    }

    // Present-but-broken guard (R2).  A dylib that exists but is the wrong
    // arch, an ELF, a fat binary, or is missing its `__DATA,__interpose`
    // section will silently fail to inject — leaving a clean-looking EMPTY
    // lock (the shim is the SOLE event source on macOS).  Validate the Mach-O
    // contract up front and hard-fail instead of producing a false negative.
    const shimError = doValidateShim(
      runtime.nativePreloadPath,
      expectedMachOCpuType(deps.arch),
    );
    if (shimError !== null) {
      throw new MacBareUnavailableError(
        `Mach-O shim at ${runtime.nativePreloadPath} is unusable: ${shimError}. ` +
          `Rebuild it with \`pnpm build\` on an Apple Silicon mac (or fetch the ` +
          `release dylib).`,
      );
    }

    // --- Provision (+ re-sign) Node + shell shims -------------------------
    // A hardened/notarized node strips DYLD_INSERT_LIBRARIES → empty audit.
    // provisionNodeMac re-signs ad-hoc; if the re-signed node is somehow
    // absent we hard-fail (do NOT fall back to a system node, which would
    // strip the shim).
    const provisioned: ProvisionedNodeMac = await doProvision({
      arch: deps.arch,
      cacheDir: defaultProvisionCacheDir(baseEnv),
      // The bundled plain-arm64 substitutes the shim's SIP redirect points at:
      // staged as <shellShimDir>/bash and <shellShimDir>/coreutils.
      macBashPath: runtime.bashPath,
      macCoreutilsPath: runtime.coreutilsPath,
    });
    if (!doExists(provisioned.nodePath)) {
      throw new MacBareUnavailableError(
        `re-signed node not found at ${provisioned.nodePath} after provisioning.`,
      );
    }

    // --- Stage the repo + rewrite config work_dir -------------------------
    const staged = stageRepoDirectory({
      repoDir: input.repoDir,
      parentDir: input.scratchDir,
      extraRepoOverlayFiles: input.extraRepoOverlayFiles,
    });
    const backendConfigPath = rewriteConfigWorkDir({
      configPath: input.configPath,
      outDir: input.scratchDir,
      workDir: staged.path,
    });

    try {
      // The orchestrator runs UNDER the provisioned (re-signed) node so the
      // shim can later inject into the install children it spawns.  The
      // provisioned bin dir is PREPENDED to PATH so the orchestrator's bare
      // `npm` / `pnpm` / `yarn` (+ corepack shims) resolve to this toolchain.
      return await doRunAgentProcess({
        cmd: provisioned.nodePath,
        args: [runtime.agentPath],
        env: {
          ...pickOrchestratorEnv(baseEnv),
          // Mirror init.sh / docker.ts: corepack must not prompt offline.
          COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
          PATH: prependPath(provisioned.nodeBinDir, baseEnv),
          SCRIPT_JAIL_CONNECTION: 'stdio',
          SCRIPT_JAIL_BACKEND: 'macos-bare',
          SCRIPT_JAIL_CONFIG_PATH: backendConfigPath,
          // macOS-bare runs the agent directly on the host (no container /etc),
          // so the host-owned pm-flags sidecar lives in the staged repo tree.
          // Point the guest at it so the sandbox fetch applies the SAME install
          // args as the host part-1 install.  loadPmFlags re-sanitizes it.
          SCRIPT_JAIL_PM_FLAGS_PATH: join(staged.path, 'etc/script-jail/pm-flags.json'),
          SCRIPT_JAIL_NATIVE_PRELOAD_PATH: runtime.nativePreloadPath,
          SCRIPT_JAIL_PLATFORM_PRELOAD_PATH: runtime.platformPreloadPath,
          SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH: runtime.envSpyPreloadPath,
          SCRIPT_JAIL_SHELL_SHIM_DIR: provisioned.shellShimDir,
          // The install/repo root (== the rewritten config work_dir, `staged.path`).
          // The shim's `shim_init` captures it into CANON_WORK_DIR and uses it as
          // is_external_system_tool keep-root #6 so the WHOLE install tree — incl.
          // top-level node_modules/.bin helpers that are SIBLINGS of a lifecycle
          // child's chdir'd cwd — stays audited (the top-level-.bin false-strip).
          // Sticky + re-injected into every kept child, exactly like
          // SCRIPT_JAIL_SHELL_SHIM_DIR.
          SCRIPT_JAIL_WORK_DIR: staged.path,
          // NO SCRIPT_JAIL_PHASE_B_UNSHARE_NET: macOS has no network namespace
          // to drop, and macOS-bare does NOT enforce offline.  It is OBSERVE-ONLY
          // and stays ONLINE: net.rs forwards connect/connectx and records the
          // TRUE result once SCRIPT_JAIL_MACOS_AUDIT_OPS is set (Phase B only);
          // parity-diff reconciles the offline-Linux / online-macOS split by
          // stripping the `<BLOCKED> ` prefix at diff time.  Audit-blind SIP
          // children and raw syscalls egress unrecorded — Firecracker is the
          // high-assurance backend (see docs/divergence.md).  So the host
          // launcher sets no network env here.
        },
        label: 'mac-bare',
        ...(deps.stderr !== undefined ? { stderr: deps.stderr } : {}),
      });
    } finally {
      staged.cleanup();
    }
  };
}

// ---------------------------------------------------------------------------
// Runtime path resolution
// ---------------------------------------------------------------------------

interface MacBareRuntimePaths {
  agentPath: string;
  platformPreloadPath: string;
  envSpyPreloadPath: string;
  nativePreloadPath: string;
  /** Bundled bash-from-source (arm64) staged as <shellShimDir>/bash. */
  bashPath: string;
  /** Bundled uutils multi-call binary (arm64) staged as <shellShimDir>/coreutils. */
  coreutilsPath: string;
}

/**
 * Resolve `dist/guest-agent.cjs`, `dist/preloads/{platform-spoof,env-spy}.cjs`
 * (under `repoRoot`), and the `libscriptjail-arm64.dylib` Mach-O shim (under
 * `imagesDir`).  Mirrors `bare.ts:resolveRuntimePaths` but for the macOS
 * artifact set (dylib instead of .so, no rootfs).
 *
 * The dylib path is returned even when absent — the caller's precondition check
 * produces the actionable "shim not found / hard-fail" error.
 */
function resolveRuntimePaths(
  repoRoot: string,
  imagesDir: string,
  doExists: typeof existsSync,
): MacBareRuntimePaths {
  const roots = [
    process.env['SCRIPT_JAIL_ACTION_ROOT'],
    process.env['GITHUB_ACTION_PATH'],
    repoRoot,
    join(repoRoot, '..'),
    process.cwd(),
  ].filter((p): p is string => typeof p === 'string' && p.length > 0);

  const agentPath = findFirst(
    [
      ...roots.map((root) => join(root, 'guest-agent.cjs')),
      ...roots.map((root) => join(root, 'dist', 'guest-agent.cjs')),
    ],
    'guest-agent.cjs',
    doExists,
  );

  const platformPreloadPath = findFirst(
    [
      ...roots.map((root) => join(root, 'preloads', 'platform-spoof.cjs')),
      ...roots.map((root) => join(root, 'dist', 'preloads', 'platform-spoof.cjs')),
    ],
    'platform-spoof.cjs',
    doExists,
  );

  const envSpyPreloadPath = findFirst(
    [
      ...roots.map((root) => join(root, 'preloads', 'env-spy.cjs')),
      ...roots.map((root) => join(root, 'dist', 'preloads', 'env-spy.cjs')),
    ],
    'env-spy.cjs',
    doExists,
  );

  // arm64-only dylib (R10); no x64 variant name.  Resolved against imagesDir
  // first, then the dev `images/` fallbacks under the resolved roots.
  const dylibName = 'libscriptjail-arm64.dylib';
  const nativePreloadPath = firstExistingOrDefault(
    [
      join(imagesDir, dylibName),
      ...roots.map((root) => join(root, 'images', dylibName)),
    ],
    doExists,
  );

  // arm64-only bundled shell-shim substitutes (R10).  Resolved the same way as
  // the dylib (imagesDir first, then dev `images/` fallbacks).  Returned even
  // when absent — provisionNodeMac hard-fails with an actionable "build it"
  // message if the source is missing when it stages the shell-shim dir.
  const bashPath = firstExistingOrDefault(
    [
      join(imagesDir, 'bash-arm64'),
      ...roots.map((root) => join(root, 'images', 'bash-arm64')),
    ],
    doExists,
  );
  const coreutilsPath = firstExistingOrDefault(
    [
      join(imagesDir, 'coreutils-arm64'),
      ...roots.map((root) => join(root, 'images', 'coreutils-arm64')),
    ],
    doExists,
  );

  return {
    agentPath,
    platformPreloadPath,
    envSpyPreloadPath,
    nativePreloadPath,
    bashPath,
    coreutilsPath,
  };
}

function findFirst(
  candidates: string[],
  label: string,
  doExists: typeof existsSync,
): string {
  for (const candidate of candidates) {
    if (doExists(candidate)) return candidate;
  }
  throw new MacBareUnavailableError(`${label} was not found`);
}

/**
 * Return the first existing candidate, else the FIRST candidate (so the caller
 * can surface a friendly "shim not found at <imagesDir path>" message rather
 * than a generic resolution failure).
 */
function firstExistingOrDefault(candidates: string[], doExists: typeof existsSync): string {
  for (const candidate of candidates) {
    if (doExists(candidate)) return candidate;
  }
  return candidates[0]!;
}

/** Prepend `dir` to a PATH value, preserving the rest. */
function prependPath(dir: string, env: NodeJS.ProcessEnv): string {
  const existing = env['PATH'] ?? '/usr/bin:/bin:/usr/sbin:/sbin';
  return `${dir}:${existing}`;
}

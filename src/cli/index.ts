// script-jail — src/cli/index.ts
//
// macOS-developer-facing CLI.  Invoked as `pnpm exec script-jail …` or
// `npx script-jail …` after the package is installed locally.
//
// Subcommands (default → `init` when no lockfile exists, otherwise `check`):
//   init    — boot the audit VM and write `.script-jail.lock.yml` from
//             scratch.  Aliased to `update` for now.
//   update  — boot the audit VM and overwrite `.script-jail.lock.yml`.
//   check   — boot the audit VM and diff the produced lockfile against the
//             committed one.  Exit 1 on drift.
//
// Flags:
//   --config <path>          (default: ./.script-jail.yml)
//   --lock <path>            (default: ./.script-jail.lock.yml)
//   --spoof-platform <p>     linux|darwin|win32 (default: linux)
//   --spoof-arch <a>         x64|arm64          (default: x64)
//   --help / --version
//
// Output streams:
//   - help / version → stdout
//   - warnings       → stderr (via shared `warn`, rebound to stderr here so
//                      the CLI user sees them on the diagnostic stream)
//   - fatal errors   → stderr

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, relative, isAbsolute, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  detectHost,
  NotMacOSError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  type DetectedHost,
} from './detect-host.js';
import { buildArchFlagOverlay } from './arch-flags.js';
import { spawnVm, type VmConfig, type VmMode } from './spawn-vm.js';
import { parseArgs } from './parse-args.js';
import { detectPm, BunUnsupportedError } from '../shared/detect-pm.js';
import { warn as sharedWarn } from '../shared/log.js';
import { resolveArtifacts } from '../shared/artifacts.js';
import { buildEffectiveConfig } from '../action/config-override.js';
import { makeOverlay, type OverlayResult } from '../action/firecracker/overlay.js';
import { resolveHostNodePrefix } from '../action/host-node-prefix.js';
import { renderDiff } from '../action/diff.js';

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

const VERSION = '0.0.0'; // synced with package.json at release time

const USAGE = `script-jail — Firecracker/VZ-sandboxed npm/pnpm/yarn lifecycle auditor.

Usage:
  script-jail [init|update|check] [options]

Subcommands:
  init                   Boot the audit VM and write .script-jail.lock.yml (default
                         when no lockfile exists).
  update                 Same as init: overwrite the lockfile.
  check                  Diff the audit output against the committed lockfile.
                         Exit non-zero on drift.  Default when a lockfile exists.

Options:
  --config <path>        Path to .script-jail.yml (default: ./.script-jail.yml)
  --lock <path>          Path to .script-jail.lock.yml (default: ./.script-jail.lock.yml)
  --spoof-platform <p>   linux | darwin | win32 (default: linux)
  --spoof-arch <a>       x64 | arm64 (default: x64)
  --help                 Print this help and exit.
  --version              Print version and exit.
`;

// ---------------------------------------------------------------------------
// VM-defaults — kept in sync with the Rust validator in config.rs
// ---------------------------------------------------------------------------

/** Vsock port the guest agent listens on; matches src/main.ts. */
const VSOCK_PORT = 10242;
/** Default vCPU count for the macOS audit VM. */
const DEFAULT_VCPU_COUNT = 2;
/** Default RAM for the macOS audit VM. */
const DEFAULT_MEMORY_MB = 2048;
/**
 * PR 4 default: Ubuntu 24.04 is the only flavor that will get a VZ kernel
 * shipped in PR 5.  Documented here rather than in artifact-manifest.ts
 * because the manifest restructure is also PR 5 scope.
 */
const DEFAULT_UBUNTU_MAJOR = '24.04' as const;
/**
 * Kernel cmdline mirrors the Firecracker path verbatim; PR 5 may tighten
 * this once the VZ kernel's quirks are characterised.
 */
const DEFAULT_KERNEL_CMDLINE =
  'reboot=k panic=1 pci=off init=/sbin/init.sh quiet';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/** Dependencies the CLI accepts for testability. */
export interface CliDeps {
  argv?: string[];
  cwd?: () => string;
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
  warn?: (msg: string) => void;
  detectHost?: typeof detectHost;
  detectPm?: typeof detectPm;
  spawnVm?: typeof spawnVm;
  /**
   * Optional override for the arch-flag-overlay builder.  Tests use this to
   * assert that `hostArch` comes from the injected `detectHost` return value
   * (NOT re-derived from `process.arch`).  Production callers do not set
   * this.
   */
  buildArchFlagOverlay?: typeof buildArchFlagOverlay;
  /**
   * Optional override for the overlay builder.  Tests use this to short-
   * circuit the (slow, root-needing) `mkfs.ext4` path; production callers
   * leave it undefined.
   */
  makeOverlay?: typeof makeOverlay;
  /**
   * Optional override for the host-node prefix resolution.  Defaults to the
   * real `resolveHostNodePrefix()`.  Tests inject a fake path because the
   * resolver walks the host's PATH for a real Node install.
   */
  resolveHostNodePrefix?: typeof resolveHostNodePrefix;
}

export async function run(deps: CliDeps = {}): Promise<number> {
  const argv = deps.argv ?? process.argv.slice(2);
  const cwd = (deps.cwd ?? (() => process.cwd()))();
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  // Default warn routes through the shared helper but emits to stderr so the
  // CLI user sees warnings on the diagnostic stream.  The action keeps the
  // GitHub-Actions ::warning:: form by using the shared default elsewhere.
  const warn = deps.warn ?? ((msg: string) => sharedWarn(msg, (s) => { stderr.write(s); }));
  const doDetectHost = deps.detectHost ?? detectHost;
  const doDetectPm = deps.detectPm ?? detectPm;
  const doSpawnVm = deps.spawnVm ?? spawnVm;
  const doBuildArchFlagOverlay = deps.buildArchFlagOverlay ?? buildArchFlagOverlay;
  const doMakeOverlay = deps.makeOverlay ?? makeOverlay;
  const doResolveHostNodePrefix = deps.resolveHostNodePrefix ?? resolveHostNodePrefix;

  const args = parseArgs(argv);
  if (args.errors.length > 0) {
    for (const e of args.errors) stderr.write(`script-jail: ${e}\n`);
    stderr.write(USAGE);
    return 1;
  }
  if (args.help) { stdout.write(USAGE); return 0; }
  if (args.version) { stdout.write(`${VERSION}\n`); return 0; }

  // --- Host check ---------------------------------------------------------
  let host: DetectedHost;
  try {
    host = doDetectHost();
  } catch (err) {
    if (
      err instanceof NotMacOSError ||
      err instanceof UnsupportedMacOSError ||
      err instanceof UnsupportedArchError
    ) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // --- Resolve paths + subcommand defaulting -------------------------------
  const configPath = resolve(cwd, args.configPath);
  const lockPath = resolve(cwd, args.lockPath);
  // init when no lockfile exists, check otherwise.  update is an alias for
  // init (both overwrite).
  const subcommand = args.subcommand ?? (existsSync(lockPath) ? 'check' : 'init');
  const mode: VmMode = subcommand === 'check' ? 'check' : 'update';

  // --- PM detection -------------------------------------------------------
  let pm: 'npm' | 'pnpm' | 'yarn';
  try {
    pm = doDetectPm({ repoDir: cwd, warn }).manager;
  } catch (err) {
    // Split specific-error handling from the generic fallback.  Since
    // BunUnsupportedError extends Error, a combined `instanceof X || instanceof Error`
    // check would make the X branch unreachable.
    if (err instanceof BunUnsupportedError) {
      stderr.write(`script-jail: ${err.message} (bun is not supported; see docs)\n`);
      return 1;
    }
    if (err instanceof Error) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // --- Arch-flag overlay --------------------------------------------------
  // detectPm returns 'yarn' for both yarn-classic and yarn-berry; the
  // distinction is deferred to PR 3+ (where `yarn --version` runs in the
  // VM).  For PR 2 we treat 'yarn' as berry by default — the worst case for
  // yarn-classic users on arm64 is a missed warning, not incorrect output.
  //
  // hostArch comes from the injected detectHost (NOT re-derived from
  // process.arch) so unit tests can exercise the arm64 codepath from an x64
  // dev box without monkey-patching process.arch.
  const archOverlay = doBuildArchFlagOverlay({ pm, hostArch: host.hostArch });
  for (const w of archOverlay.warnings) warn(w);

  // --- Build effective config (with arch overlays threaded through) ------
  // Thread archOverlay's optional sidecars into buildEffectiveConfig().  The
  // helper writes them next to the rewritten config YAML; we then hand the
  // paths to makeOverlay's `extraRepoOverlayFiles` so they land on the repo
  // disk inside the VM.
  const effectiveConfig = buildEffectiveConfig({
    userConfigPath: configPath,
    overrides: { spoofPlatform: args.spoofPlatform, spoofArch: args.spoofArch },
    ...(archOverlay.yarnrcOverlay !== undefined
      ? { yarnrcOverlay: archOverlay.yarnrcOverlay }
      : {}),
    ...(archOverlay.pmFlagsJson !== undefined
      ? { pmFlagsJson: archOverlay.pmFlagsJson }
      : {}),
  });

  // --- Resolve artifacts ---------------------------------------------------
  // Repo root for artifact discovery: prefer the script-jail package's own
  // root (so a developer running `node dist/cli.cjs` from a consumer repo
  // still resolves `images/` under the installed package).  Fallback to cwd.
  const repoRoot = resolveScriptJailRoot(cwd);

  const artifacts = resolveArtifacts({
    repoRoot,
    hostArch: host.hostArch,
    ubuntuMajor: DEFAULT_UBUNTU_MAJOR,
  });

  // --- Build per-run overlay (rootfs + repo + host-node) -------------------
  let hostNodePrefix: string;
  try {
    hostNodePrefix = doResolveHostNodePrefix();
  } catch (err) {
    if (err instanceof Error) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // Pre-flight rootfs existence check: surfacing "rootfs not found" before
  // makeOverlay (which would error inside its `cpSync`) gives the user an
  // actionable path.  spawnVm runs the same check via `checkArtifacts` but
  // only AFTER makeOverlay has already started copying.  We skip this when
  // makeOverlay is stubbed (deps.makeOverlay !== undefined) because tests do
  // not have the real images/ dir.
  if (deps.makeOverlay === undefined && !existsSync(artifacts.rootfsPath)) {
    const buildHint =
      host.hostArch === 'arm64'
        ? `pnpm build --runner-image=ubuntu-${DEFAULT_UBUNTU_MAJOR} --arch=arm64`
        : `pnpm build --runner-image=ubuntu-${DEFAULT_UBUNTU_MAJOR}`;
    stderr.write(
      `script-jail: rootfs not found at ${artifacts.rootfsPath}. ` +
      `Run \`${buildHint}\` (or fetch the release artifact) to produce it.\n`,
    );
    return 1;
  }

  const extraRepoOverlayFiles: Array<{ relPath: string; content: string }> = [];
  if (effectiveConfig.yarnrcPath !== undefined) {
    extraRepoOverlayFiles.push({
      relPath: '.yarnrc.yml',
      content: readFileSync(effectiveConfig.yarnrcPath, 'utf8'),
    });
  }
  if (effectiveConfig.pmFlagsPath !== undefined) {
    // Lands under `<repo>/etc/script-jail/pm-flags.json` inside the VM at
    // `/work/etc/script-jail/pm-flags.json`.  init.sh copies it into the
    // canonical `/etc/script-jail/pm-flags.json` location where
    // `loadPmFlags()` reads it.  This mirrors how config.yml flows.
    extraRepoOverlayFiles.push({
      relPath: 'etc/script-jail/pm-flags.json',
      content: readFileSync(effectiveConfig.pmFlagsPath, 'utf8'),
    });
  }

  let overlay: OverlayResult;
  try {
    overlay = await doMakeOverlay({
      baseRootfsPath: artifacts.rootfsPath,
      repoSrcPath: cwd,
      configPath: effectiveConfig.configPath,
      hostNodePrefix,
      extraRepoOverlayFiles,
    });
  } catch (err) {
    if (err instanceof Error) {
      stderr.write(`script-jail: failed to build overlay: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // --- Build VmConfig ------------------------------------------------------
  const vmConfig: VmConfig = {
    kernelPath: artifacts.kernelPath,
    kernelCmdline: DEFAULT_KERNEL_CMDLINE,
    rootfsDiskPath: overlay.rootfsCopyPath,
    repoDiskPath: overlay.repoDiskPath,
    hostNodeDiskPath: overlay.hostNodeDiskPath,
    // VZ does not consume a UDS path (the listener lives in-process) but the
    // Rust validator requires the field to be present.  Pass the workDir +
    // sentinel filename so the file path validates and so logs distinguish
    // it from any real UDS.
    vsockUdsPath: resolve(overlay.workDir, 'vsock.sock'),
    vsockPort: VSOCK_PORT,
    vcpuCount: DEFAULT_VCPU_COUNT,
    memoryMb: DEFAULT_MEMORY_MB,
    enableNetwork: true,
    mode,
    repoDir: cwd,
    configPath,
    lockPath,
  };

  // --- Run the VM ----------------------------------------------------------
  let finalYaml: string;
  try {
    const result = await doSpawnVm(vmConfig);
    finalYaml = result.finalYaml;
  } catch (err) {
    if (err instanceof Error) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  } finally {
    await overlay.cleanup();
  }

  // --- Post-VM: write or diff ---------------------------------------------
  if (mode === 'update') {
    writeFileSync(lockPath, finalYaml, 'utf8');
    stderr.write(
      `[script-jail] wrote ${Buffer.byteLength(finalYaml, 'utf8')} bytes to ${lockPath}\n`,
    );
    return 0;
  }

  // mode === 'check'
  const committed = existsSync(lockPath) ? readFileSync(lockPath, 'utf8') : '';
  const diff = renderDiff({
    lockPath: relativeForDisplay(lockPath, cwd),
    committed,
    generated: finalYaml,
  });
  if (diff.unified !== '') {
    stdout.write(diff.unified);
    if (!diff.unified.endsWith('\n')) stdout.write('\n');
  }
  for (const ann of diff.annotations) {
    stdout.write(`${ann}\n`);
  }
  return diff.match ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the script-jail package root.  Used to anchor `images/<arch>` and
 * the cargo `target/release/script-jail-vm` lookup.
 *
 * We DO NOT just use process.cwd() because users typically run the CLI from
 * their own repo; the artifacts live inside the script-jail install (either
 * the published npm package or the dev checkout this code is part of).
 *
 * Strategy: this module is bundled to `dist/cli.cjs`, so two `dirname`s up
 * from the bundle file lands at the package root.  In dev (oxnode src/...)
 * the same heuristic lands at the repo root.  When neither yields a usable
 * directory we fall back to `cwd`.
 */
function resolveScriptJailRoot(cwd: string): string {
  // The bundled CJS file has esbuild-injected `__filename` at module scope,
  // not on globalThis.  ESM (dev / oxnode) provides `import.meta.url`.  We
  // attempt both shapes: declared-but-may-be-undefined `__filename` for the
  // bundle, then the ESM fileURLToPath path.  Either yielding a string is
  // sufficient.
  let here: string = '';
  try {
    // `__filename` is provided by node's CJS wrapper for the bundle.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dn: unknown = (typeof __filename !== 'undefined' ? __filename : undefined);
    if (typeof dn === 'string') here = dn;
  } catch {
    /* ignore — __filename was not in scope */
  }
  if (here === '') {
    try {
      here = fileURLToPath(import.meta.url);
    } catch {
      /* neither available */
    }
  }
  if (here === '') return cwd;
  // dist/cli.cjs → dist → <pkg root>            (two parents)
  // src/cli/index.ts → src/cli → src → <repo>   (three parents)
  // Probe each candidate for `package.json` so we pick the right one regardless
  // of whether we're running from `dist/` or `src/`.
  const candidates = [
    resolve(dirname(dirname(here))),
    resolve(dirname(dirname(dirname(here)))),
  ];
  for (const c of candidates) {
    if (existsSync(join(c, 'package.json'))) return c;
  }
  return cwd;
}

// Allow the `__filename` reference above to type-check in both bundle (where
// esbuild injects it) and the ESM dev build (where it does not exist).  We
// declare it as a top-level binding so TS does not complain in either case.
declare const __filename: string | undefined;

/**
 * Returns `absPath` made relative to `repoDir` when it is inside the repo.
 * Falls back to the absolute path otherwise.  Used purely for cosmetic
 * annotation labels — the underlying read/write uses the absolute path.
 */
function relativeForDisplay(absPath: string, repoDir: string): string {
  const rel = relative(repoDir, absPath);
  if (rel.startsWith('..') || isAbsolute(rel)) return absPath;
  return rel;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

declare const require: { main?: unknown } | undefined;
declare const module: unknown;

const isMainCjs = (() => {
  try {
    return typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module;
  } catch { return false; }
})();
const isMainEsm = (() => {
  try {
    return typeof import.meta !== 'undefined' &&
      typeof process !== 'undefined' &&
      typeof process.argv[1] === 'string' &&
      import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch { return false; }
})();

if (isMainCjs || isMainEsm) {
  run().then(
    (code) => process.exit(code),
    (err: unknown) => {
      process.stderr.write(
        `${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
      );
      process.exit(1);
    },
  );
}

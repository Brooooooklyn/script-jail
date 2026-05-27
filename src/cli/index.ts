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
//   --spoof-arch <a>         x64|arm64          (default: host arch)
//   --help / --version
//
// Output streams:
//   - help / version → stdout
//   - warnings       → stderr (via shared `warn`, rebound to stderr here so
//                      the CLI user sees them on the diagnostic stream)
//   - fatal errors   → stderr
//
// Audit pipeline:
//   The orchestration logic (arch-flag overlay, makeOverlay, post-VM
//   diff / write / audit-bypass gate) lives in `../shared/run-audit.ts`
//   so the GitHub Action and the CLI run the SAME pipeline.  This file
//   owns only the macOS-specific bits: host detection, artifact lookup,
//   and the VZ launcher closure.

import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  detectHost,
  NotMacOSError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  type DetectedHost,
} from './detect-host.js';
import { spawnVm, type VmConfig, type VmMode } from './spawn-vm.js';
import { parseArgs } from './parse-args.js';
import { detectPm, BunUnsupportedError } from '../shared/detect-pm.js';
import { warn as sharedWarn } from '../shared/log.js';
import { resolveArtifacts } from '../shared/artifacts.js';
import {
  makeOverlay,
  type OverlayResult,
} from '../action/firecracker/overlay.js';
import { runAudit, type LauncherResult } from '../shared/run-audit.js';
import { buildArchFlagOverlay } from './arch-flags.js';

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
  --spoof-arch <a>       x64 | arm64 (default: host arch)
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
 * Kernel cmdline for the VZ runner.  Unlike Firecracker, VZ does not
 * auto-inject `root=` and its virtio transport rides on PCI — so `pci=off`
 * would disable the disk/vsock devices.  The rootfs ext4 image is the
 * first VZ block device (`/dev/vda`) and must be `rw` because the guest
 * writes to it at runtime; `console=hvc0` routes kernel logs to the
 * helper's stderr via the virtio console.
 *
 * `sj_net=dhcp` tells the guest `init.sh` to DHCP eth0 instead of taking the
 * Firecracker static 172.16.0.2: VZ's NAT device runs its own DHCP server on
 * a subnet it picks itself, so static addressing cannot reach Phase A's
 * network.
 *
 * `sj_vsock=connect` tells the guest `orchestrate.sh` to have socat CONNECT
 * out to the host (well-known CID 2, port 10242) instead of LISTEN: the VZ
 * host registers a VZVirtioSocketListener and waits for the guest to dial in
 * (src/host-mac/src/vsock.rs), whereas Firecracker's host VMM connects in to
 * a guest listener.  Without it both ends listen and the session never opens.
 *
 * `sj_epoch=<unix-seconds>` is deliberately NOT part of this constant — its
 * value changes every run, so it is appended per launch in the launcher
 * closure below.
 */
const DEFAULT_KERNEL_CMDLINE =
  'console=hvc0 root=/dev/vda rw rootfstype=ext4 reboot=k panic=1 init=/sbin/init sj_net=dhcp sj_vsock=connect';

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
   *
   * The overlay invocation moved into `runAudit` as part of the shared-core
   * refactor; this seam is threaded through to runAudit's `buildArchFlagOverlay`
   * input so existing tests keep working unchanged.
   */
  buildArchFlagOverlay?: typeof buildArchFlagOverlay;
  /**
   * Optional override for the overlay builder.  Tests use this to short-
   * circuit the (slow, root-needing) `mkfs.ext4` path; production callers
   * leave it undefined.
   */
  makeOverlay?: typeof makeOverlay;
  /**
   * Optional override for the shared audit pipeline.  Production callers
   * do not set this.  Tests use it to short-circuit the entire
   * makeOverlay → launch → diff path when they want to exercise the CLI's
   * pre-runAudit wiring (argv parsing, host detection, artifact lookup)
   * in isolation.
   */
  runAudit?: typeof runAudit;
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
  const doMakeOverlay = deps.makeOverlay ?? makeOverlay;
  const doRunAudit = deps.runAudit ?? runAudit;
  // buildArchFlagOverlay is threaded through to runAudit (see below).
  // Captured here so the production default flows through identically to
  // pre-refactor behaviour when no override is supplied.
  const doBuildArchFlagOverlay = deps.buildArchFlagOverlay ?? buildArchFlagOverlay;

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
  const effectiveSpoofArch = hasSpoofArchArg(argv) ? args.spoofArch : host.hostArch;
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

  // --- Build the VZ launcher closure --------------------------------------
  // runAudit hands us the overlay it built; we assemble VmConfig and call
  // spawnVm.  We do NOT clean up the overlay here — runAudit owns that
  // lifecycle and will call `overlay.cleanup()` after this closure returns
  // (or throws).
  const launch = async (overlay: OverlayResult): Promise<LauncherResult> => {
    const vmConfig: VmConfig = {
      kernelPath: artifacts.kernelPath,
      // Append the host wall clock as `sj_epoch=<unix-seconds>`.  A fresh VZ
      // microVM boots at 1970-01-01; a 1970 clock fails TLS certificate
      // validation and breaks Phase A's `vp env install` / `pnpm fetch`
      // HTTPS downloads.  init.sh reads the marker and runs `date -s`.
      kernelCmdline: `${DEFAULT_KERNEL_CMDLINE} sj_epoch=${Math.floor(Date.now() / 1000)}`,
      rootfsDiskPath: overlay.rootfsCopyPath,
      repoDiskPath: overlay.repoDiskPath,
      // VZ does not consume a UDS path (the listener lives in-process) but
      // the Rust validator requires the field to be present.  Pass the
      // workDir + sentinel filename so the file path validates and so logs
      // distinguish it from any real UDS.
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

    const result = await doSpawnVm(vmConfig);
    // spawnVm surfaces non-fatal `error` frames via `result.warnings`.
    // Pass them through verbatim so runAudit (or future callers) can wire
    // them into a "no final frame" diagnostic — today they are unused
    // post-launch, but keeping the contract makes the CLI parity-stable
    // with the Action's launcher closure.
    return {
      finalYaml: result.finalYaml,
      nonFatalWarnings: result.warnings,
    };
  };

  // --- Hand off to runAudit -----------------------------------------------
  // runAudit owns the arch-flag overlay, effective-config, makeOverlay,
  // diff/write, and the audit-bypass gate (which the CLI previously
  // skipped — closing that security gap is one of the wins from this
  // refactor).
  try {
    const result = await doRunAudit({
      repoDir: cwd,
      configPath,
      lockPath,
      mode,
      overrides: {
        spoofPlatform: args.spoofPlatform,
        spoofArch: effectiveSpoofArch,
      },
      pm,
      // hostArch comes from the injected detectHost (NOT re-derived from
      // process.arch) so unit tests can exercise the arm64 codepath from
      // an x64 dev box without monkey-patching process.arch.
      hostArch: host.hostArch,
      baseRootfsPath: artifacts.rootfsPath,
      // os.tmpdir() — never `cwd` — so the rewritten config YAML and any
      // arch-flag sidecars (.yarnrc.yml / pm-flags.json) cannot pollute
      // the user's repo.  runAudit creates a private mkdtemp dir under
      // this parent and removes it in `finally` even on crash.
      workDir: tmpdir(),
      launch,
      io: {
        warn,
        stdout,
        stderr,
        // CLI is not a GitHub Action: no setOutput, no annotations.
        // The audit-bypass gate STILL fires via the stderr message
        // inside runAudit.
      },
      // Thread the CLI's existing dependency-injection seams through to
      // runAudit so test stubs continue to intercept the same call sites
      // they did pre-refactor.
      buildArchFlagOverlay: doBuildArchFlagOverlay,
      makeOverlay: doMakeOverlay,
    });
    return result.exitCode;
  } catch (err) {
    if (err instanceof Error) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
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

function hasSpoofArchArg(argv: readonly string[]): boolean {
  return argv.includes('--spoof-arch');
}

// Allow the `__filename` reference above to type-check in both bundle (where
// esbuild injects it) and the ESM dev build (where it does not exist).  We
// declare it as a top-level binding so TS does not complain in either case.
declare const __filename: string | undefined;

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

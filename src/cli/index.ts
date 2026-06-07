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

import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  detectHost,
  type DetectedHost,
} from './detect-host.js';
import {
  detectPlatform,
  platformPackageName,
  NotMacOSError,
  NotSupportedPlatformError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  UnsupportedDarwinArchError,
  type DetectedPlatform,
} from './detect-platform.js';
import { spawnVm, type VmConfig, type VmMode } from './spawn-vm.js';
import { parseArgs, type CliBackend } from './parse-args.js';
import { detectPm, BunUnsupportedError } from '../shared/detect-pm.js';
import { warn as sharedWarn } from '../shared/log.js';
import {
  resolveArtifacts,
  resolvePlatformPackageDir,
  PlatformPackageMissingError,
} from '../shared/artifacts.js';
import { ensureRootfs } from './rootfs-cache.js';
import { createLocalPreFetchArtifacts } from './local-artifacts.js';
import {
  makeOverlay,
  type OverlayResult,
} from '../action/firecracker/overlay.js';
import { runAudit, type LauncherResult } from '../shared/run-audit.js';
import { buildArchFlagOverlay } from './arch-flags.js';
import { NodeHttpClient } from '../action/firecracker/download.js';
import { PINNED_MANIFEST } from '../action/artifact-manifest.js';
import { createFirecrackerBackend } from '../action/backend/firecracker.js';
import { createDockerBackend } from '../action/backend/docker.js';
import { createBareBackend } from '../action/backend/bare.js';
import { runSelectedBackend, type BackendMap } from '../action/backend/select.js';
import { createMacBareExecute } from '../action/backend/mac-bare.js';

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

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
  --backend <b>          macOS audit backend: vz | bare. vz boots the Linux guest
                         inside Apple Virtualization.framework (arm64 only); bare
                         runs the install natively on the Mac under the Mach-O
                         shim (no VM). Default: vz on Apple Silicon, bare on Intel.
                         Ignored on Linux (a warning is printed).
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
/** Default Ubuntu major for the macOS VZ rootfs. */
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
  /**
   * Generalized host/platform detector (darwin-arm64 / linux-x64 / linux-arm64).
   * Production callers leave this undefined; the default reads
   * `process.{platform,arch}` + `os.release()` via `detectPlatform`.
   */
  detectPlatform?: typeof detectPlatform;
  /**
   * Legacy macOS-only host detector.  Retained as an ACCEPTED ALIAS seam: the
   * existing I2 regression tests inject `detectHost: () => ({ macosMajor,
   * hostArch })` and expect that legacy shape to drive the darwin path
   * unchanged.  When supplied, its return is adapted into a darwin
   * `DetectedPlatform` directly (NOT routed through `detectPlatform`, which
   * would reject the injected `darwin/x64` shape).  `detectPlatform` takes
   * precedence when both are set.
   */
  detectHost?: typeof detectHost;
  /**
   * Locate the directory that holds the platform-package runtime artifacts
   * (rootfs + shim).  Injection seam so the friendly-error path
   * (`PlatformPackageMissingError`) and the dev-fallback path are exercised
   * without a real `@script-jail/*` install.
   */
  resolvePlatformPackageDir?: typeof resolvePlatformPackageDir;
  /**
   * Backend-execution seam for the Linux path.  Injected by smoke tests so
   * they never `.run()` a real firecracker/docker/bare backend (which would
   * probe `/dev/kvm`, tap devices, or the docker daemon).  Production callers
   * leave this undefined; the default is the shared `runSelectedBackend`.
   */
  runSelectedBackend?: typeof runSelectedBackend;
  /**
   * Backend-execution seam for the macOS `bare` path.  Injected by smoke tests
   * so they never provision/re-sign a real node or spawn the orchestrator.
   * Production callers leave this undefined; the default is the shared
   * `createMacBareExecute`.
   */
  createMacBareExecute?: typeof createMacBareExecute;
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
  const doDetectPm = deps.detectPm ?? detectPm;
  const doSpawnVm = deps.spawnVm ?? spawnVm;
  const doMakeOverlay = deps.makeOverlay ?? makeOverlay;
  const doRunAudit = deps.runAudit ?? runAudit;
  const doResolvePlatformPackageDir =
    deps.resolvePlatformPackageDir ?? resolvePlatformPackageDir;
  const doRunSelectedBackend = deps.runSelectedBackend ?? runSelectedBackend;
  const doCreateMacBareExecute = deps.createMacBareExecute ?? createMacBareExecute;
  // Platform detection seam.  When a test injects the LEGACY `detectHost`
  // (`{ macosMajor, hostArch }`) but no `detectPlatform`, adapt it to a darwin
  // `DetectedPlatform` directly — do NOT route through `detectPlatform`, which
  // would reject the injected `darwin/x64` shape some I2 tests rely on.
  const doDetectPlatform: typeof detectPlatform =
    deps.detectPlatform ??
    (deps.detectHost !== undefined
      ? (input) => {
          const host: DetectedHost = deps.detectHost!(input);
          return { os: 'darwin', arch: host.hostArch, macosMajor: host.macosMajor };
        }
      : detectPlatform);
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
  if (args.version) { stdout.write(`${readPackageVersion(cwd)}\n`); return 0; }

  // --- Host check ---------------------------------------------------------
  let platform: DetectedPlatform;
  try {
    platform = doDetectPlatform();
  } catch (err) {
    if (
      err instanceof NotMacOSError ||
      err instanceof NotSupportedPlatformError ||
      err instanceof UnsupportedMacOSError ||
      err instanceof UnsupportedDarwinArchError ||
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
  const effectiveSpoofArch = hasSpoofArchArg(argv) ? args.spoofArch : platform.arch;
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

  // --- Resolve the platform-package artifact directory --------------------
  // Repo root anchors the dev-checkout `images/` fallback.  Prefer the
  // script-jail package's own root (so a developer running `node dist/cli.cjs`
  // from a consumer repo still resolves `images/` under the installed
  // package).  The version lookup (`readPackageVersion`) also uses this root.
  const repoRoot = resolveScriptJailRoot(cwd);

  // The runtime artifacts (rootfs[.gz], shim, VZ helper) ship in the
  // locally-installed `@script-jail/<os>-<arch>` optional dependency, or — in
  // a dev checkout — the repo `images/` dir.  Resolve that directory once;
  // both branches consume it.  A missing package (no install + no dev images)
  // surfaces a friendly `PlatformPackageMissingError`.
  let packageImagesDir: string;
  try {
    packageImagesDir = doResolvePlatformPackageDir({
      packageName: platformPackageName(platform),
      devImagesDir: join(repoRoot, 'images'),
    }).imagesDir;
  } catch (err) {
    if (err instanceof PlatformPackageMissingError) {
      stderr.write(`script-jail: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // -----------------------------------------------------------------------
  // Linux: reuse the Action's firecracker → docker → bare backends through
  // `runAudit({ execute })`.  The CLI NEVER calls `validateManifest`:
  // PINNED_MANIFEST flows into `ctx` ONLY so the Docker backend can look up
  // its image digest.  `selfTest:false` is mandatory (else Docker would
  // require a pre-pulled local image).
  // -----------------------------------------------------------------------
  if (platform.os === 'linux') {
    // --backend is a darwin-only selector (vz vs bare).  Linux always uses the
    // firecracker → docker → bare auto order; warn (don't fail) so a script
    // sharing one invocation across OSes is not broken by the stray flag.
    if (args.backend !== null) {
      warn(`--backend is darwin-only; ignoring '--backend ${args.backend}' on Linux.`);
    }
    return runLinux({
      platform,
      packageImagesDir,
      cwd,
      configPath,
      lockPath,
      mode,
      pm,
      spoofPlatform: args.spoofPlatform,
      effectiveSpoofArch,
      warn,
      stdout,
      stderr,
      doRunAudit,
      doRunSelectedBackend,
      doBuildArchFlagOverlay,
    });
  }

  // -----------------------------------------------------------------------
  // macOS: resolve the effective backend.  Explicit --backend wins; otherwise
  // default to vz on Apple Silicon (the VZ microVM is arm64-only) and bare on
  // Intel (no VZ artifacts — the Mach-O shim runs natively).
  // -----------------------------------------------------------------------
  const effectiveBackend: CliBackend =
    args.backend ?? (platform.arch === 'arm64' ? 'vz' : 'bare');

  // VZ is arm64-only: its kernel/rootfs/helper artifacts are not shipped for
  // x64.  An Intel mac explicitly asking for --backend vz fails here with the
  // same typed error detectPlatform used to throw outright (now detection is
  // backend-agnostic and this gate lives in the CLI).
  if (effectiveBackend === 'vz' && platform.arch === 'x64') {
    stderr.write(`script-jail: ${new UnsupportedDarwinArchError().message}\n`);
    return 1;
  }

  // -----------------------------------------------------------------------
  // macOS bare: run the install NATIVELY on the Mac (no VM), observed by the
  // Mach-O shim.  Shares runAudit's diff / write / audit-bypass gate via the
  // `execute` closure — no overlay, no makeOverlay, no spawnVm.
  // -----------------------------------------------------------------------
  if (effectiveBackend === 'bare') {
    return runMacBare({
      platform,
      packageImagesDir,
      repoRoot,
      cwd,
      configPath,
      lockPath,
      mode,
      pm,
      spoofPlatform: args.spoofPlatform,
      effectiveSpoofArch,
      warn,
      stdout,
      stderr,
      doRunAudit,
      doBuildArchFlagOverlay,
      doCreateMacBareExecute,
    });
  }

  // -----------------------------------------------------------------------
  // macOS (arm64, vz): boot the install inside Apple Virtualization.framework.
  // Byte-for-byte the same path as before, except the artifact directory now
  // comes from the resolved platform package (npm install) / dev `images/`
  // fallback instead of always `<repoRoot>/images`.
  // -----------------------------------------------------------------------
  const artifacts = resolveArtifacts({
    imagesDir: packageImagesDir,
    hostArch: platform.arch,
    ubuntuMajor: DEFAULT_UBUNTU_MAJOR,
  });
  let baseRootfsPath = artifacts.rootfsPath;

  // Pre-flight rootfs existence check: surfacing "rootfs not found" before
  // makeOverlay (which would error inside its `cpSync`) gives the user an
  // actionable path.  spawnVm runs the same check via `checkArtifacts` but
  // only AFTER makeOverlay has already started copying.  We skip this when
  // makeOverlay is stubbed (deps.makeOverlay !== undefined) because tests do
  // not have the real images/ dir.
  if (deps.makeOverlay === undefined) {
    baseRootfsPath = await ensureRootfs({
      rootfsPath: artifacts.rootfsPath,
      compressedRootfsPath: artifacts.compressedRootfsPath,
    });
  }
  if (deps.makeOverlay === undefined && !existsSync(baseRootfsPath)) {
    const buildHint =
      platform.arch === 'arm64'
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

    // The VZ helper ships at the root of the resolved `@script-jail/<os>-<arch>`
    // package (packageImagesDir); pass it (plus repoRoot for the dev cargo-target
    // lookup) so resolveScriptJailVmBinary finds the npm-installed binary.
    const result = await doSpawnVm(vmConfig, {
      platformPackageDir: packageImagesDir,
      repoRoot,
    });
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
      // hostArch comes from the injected detectPlatform (NOT re-derived from
      // process.arch) so unit tests can exercise the arm64 codepath from
      // an x64 dev box without monkey-patching process.arch.
      hostArch: platform.arch,
      baseRootfsPath,
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
// Linux backend path
// ---------------------------------------------------------------------------

interface RunLinuxInput {
  platform: DetectedPlatform;
  packageImagesDir: string;
  cwd: string;
  configPath: string;
  lockPath: string;
  mode: VmMode;
  pm: 'npm' | 'pnpm' | 'yarn';
  spoofPlatform: 'linux' | 'darwin' | 'win32';
  effectiveSpoofArch: 'x64' | 'arm64';
  warn: (msg: string) => void;
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  doRunAudit: typeof runAudit;
  doRunSelectedBackend: typeof runSelectedBackend;
  doBuildArchFlagOverlay: typeof buildArchFlagOverlay;
}

/**
 * Linux audit path.  Reuses the Action's firecracker → docker → bare backends
 * via `runAudit({ execute })`, materializing the platform-package rootfs+shim
 * locally (no GitHub-release download, no manifest validation).
 */
async function runLinux(input: RunLinuxInput): Promise<number> {
  const { platform, stderr } = input;
  const arch = platform.arch;

  // CLI cache root for the materialized rootfs + shim.  Honour an explicit
  // SCRIPT_JAIL_CACHE_DIR; otherwise fall back to os.tmpdir() — NOT
  // RUNNER_TEMP, which is Action-only and absent for a developer CLI run.
  const imagesDir = process.env['SCRIPT_JAIL_CACHE_DIR']
    ? join(process.env['SCRIPT_JAIL_CACHE_DIR'], 'script-jail-images')
    : join(tmpdir(), 'script-jail-images');
  mkdirSync(imagesDir, { recursive: true });

  const http = new NodeHttpClient();
  const localPreFetch = createLocalPreFetchArtifacts({
    packageImagesDir: input.packageImagesDir,
    hostArch: arch,
    ubuntuMajor: DEFAULT_UBUNTU_MAJOR,
  });

  // Same backend-map shape as src/main.ts.  Differences from the Action:
  //   - firecracker/bare use the CLI-local pre-fetch (materialize from the
  //     platform package) instead of the release download;
  //   - cacheFirecracker:false (the CLI has no GitHub Actions cache);
  //   - the Docker backend opts into pull-by-tag fallback so a placeholder
  //     digest in the (pre-v0.1.1) manifest still resolves a usable tag.
  const backends: BackendMap = {
    firecracker: createFirecrackerBackend({
      preFetchArtifacts: localPreFetch,
      cacheFirecracker: false,
      warn: input.warn,
    }),
    docker: createDockerBackend({ stderr, allowTagFallback: true }),
    bare: createBareBackend({ preFetchArtifacts: localPreFetch, stderr }),
  };

  try {
    const result = await input.doRunAudit({
      repoDir: input.cwd,
      configPath: input.configPath,
      lockPath: input.lockPath,
      mode: input.mode,
      overrides: {
        spoofPlatform: input.spoofPlatform,
        spoofArch: input.effectiveSpoofArch,
      },
      pm: input.pm,
      hostArch: arch,
      workDir: tmpdir(),
      // Backend executor: runAudit prepares the common config/sidecars, then
      // hands control here to pick + run a Linux backend.  CRITICAL: no
      // `validateManifest` anywhere on this path.
      execute: (auditInput) =>
        input.doRunSelectedBackend({
          requested: 'auto',
          backends,
          warn: input.warn,
          ctx: {
            ...auditInput,
            imagesDir,
            runnerImage: 'ubuntu-24.04',
            arch,
            manifest: PINNED_MANIFEST,
            http,
            selfTest: false,
          },
        }),
      io: {
        warn: input.warn,
        stdout: input.stdout,
        stderr,
      },
      buildArchFlagOverlay: input.doBuildArchFlagOverlay,
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
// macOS bare backend path
// ---------------------------------------------------------------------------

interface RunMacBareInput {
  platform: DetectedPlatform;
  packageImagesDir: string;
  repoRoot: string;
  cwd: string;
  configPath: string;
  lockPath: string;
  mode: VmMode;
  pm: 'npm' | 'pnpm' | 'yarn';
  spoofPlatform: 'linux' | 'darwin' | 'win32';
  effectiveSpoofArch: 'x64' | 'arm64';
  warn: (msg: string) => void;
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  doRunAudit: typeof runAudit;
  doBuildArchFlagOverlay: typeof buildArchFlagOverlay;
  doCreateMacBareExecute: typeof createMacBareExecute;
}

/**
 * macOS-native bare audit path.  Runs the install DIRECTLY on the Mac (no VM)
 * under the Mach-O shim, reusing runAudit's shared diff / write /
 * audit-bypass gate via the `execute` closure (no overlay, no makeOverlay,
 * no spawnVm).  Observe-only + online (no offline enforcement).
 */
async function runMacBare(input: RunMacBareInput): Promise<number> {
  const { platform, stderr } = input;

  const execute = input.doCreateMacBareExecute({
    imagesDir: input.packageImagesDir,
    repoRoot: input.repoRoot,
    arch: platform.arch,
    stderr,
  });

  try {
    const result = await input.doRunAudit({
      repoDir: input.cwd,
      configPath: input.configPath,
      lockPath: input.lockPath,
      mode: input.mode,
      overrides: {
        spoofPlatform: input.spoofPlatform,
        spoofArch: input.effectiveSpoofArch,
      },
      pm: input.pm,
      hostArch: platform.arch,
      // os.tmpdir() — never `cwd` — so the rewritten config + sidecars cannot
      // pollute the user's repo.  runAudit creates a private mkdtemp dir here.
      workDir: tmpdir(),
      execute,
      io: {
        warn: input.warn,
        stdout: input.stdout,
        stderr,
      },
      buildArchFlagOverlay: input.doBuildArchFlagOverlay,
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

function readPackageVersion(cwd: string): string {
  const packageJsonPath = join(resolveScriptJailRoot(cwd), 'package.json');
  try {
    const pkg = JSON.parse(String(readFileSync(packageJsonPath, 'utf8'))) as Record<string, unknown>;
    if (typeof pkg['version'] === 'string') return pkg['version'];
  } catch {
    /* fall through */
  }
  return '0.0.0';
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

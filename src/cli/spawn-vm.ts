// script-jail — src/cli/spawn-vm.ts
//
// macOS VM launcher.  Spawns the `script-jail-vm` Rust helper (built from
// `src/host-mac`), drives the JSONL frame protocol over its stdio, and
// returns the `final` lockfile YAML the guest agent produces.
//
// Wire protocol (mirrors src/main.ts's Firecracker path):
//   - The helper writes JSONL guest frames to stdout (one per line).
//   - The helper accepts a literal `go\n` on stdin to release the guest from
//     the Phase A → Phase B handshake.
//   - The helper exits 0 on success, 2 on a VZ-side error, and 64 on a
//     pre-boot configuration error.  Anything else is "unknown".
//
// Binary lookup order (highest priority first):
//   1. `SCRIPT_JAIL_VM_BIN`           env override; used in tests.
//   2. `<repoRoot>/target/release/script-jail-vm`  for local `cargo build`.
//   3. `<packageRoot>/bin/darwin-<arch>/script-jail-vm` for the published
//      npm package.
//
// All three paths are checked before raising — the error message lists every
// one we tried so a dev who forgot to `cargo build` knows where the binary
// is expected to live.

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseFrames, type GuestFrame } from '../shared/vsock-protocol.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Run mode mirrors `ActionInputs.mode` (src/action/inputs.ts). */
export type VmMode = 'check' | 'update';

/**
 * Full config the macOS audit VM needs.  Mirrors the Rust-side `VmConfig` in
 * `src/host-mac/src/config.rs` AND the host-side bookkeeping the CLI needs
 * (repoDir / configPath / lockPath / mode are NOT forwarded to the Rust
 * helper — they are consumed by the CLI itself before / after the spawn).
 */
export interface VmConfig {
  /** Absolute path to the VZ-compatible kernel. */
  kernelPath: string;
  /** Kernel cmdline for the VZ guest. */
  kernelCmdline: string;
  /** Per-run rootfs ext4 (output of `makeOverlay()`). */
  rootfsDiskPath: string;
  /** Per-run repo ext4 (output of `makeOverlay()`). */
  repoDiskPath: string;
  /**
   * vsock UDS path.  Kept in the payload for parity with the Linux runner
   * (where the listener IS a UDS); on macOS the helper's listener lives
   * in-process so this is unused but still validated by `config.rs`.
   */
  vsockUdsPath: string;
  /** vsock port the guest agent listens on. */
  vsockPort: number;
  /** Number of vCPUs to expose. */
  vcpuCount: number;
  /** Memory size in MB. */
  memoryMb: number;
  /** Phase A networking. */
  enableNetwork: boolean;
  /** Run mode: drives the diff/write path AFTER the helper returns. */
  mode: VmMode;
  /** Absolute path to the user's repository on the host. */
  repoDir: string;
  /** Absolute path to the (effective) script-jail config YAML on the host. */
  configPath: string;
  /** Absolute path to the lockfile we will read/write. */
  lockPath: string;
}

export interface VmRunResult {
  /** YAML the guest produced as the audit's "final" frame. */
  finalYaml: string;
  /** Non-fatal `error` frames surfaced during the run.  May be empty. */
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Compatibility shim: kept exported so existing CLI tests that match on
 * `MacOSVmNotImplementedError` continue to compile. Production callers never
 * see this; tests that want the "unimplemented" code path inject a stub via
 * `CliDeps.spawnVm`.
 */
export class MacOSVmNotImplementedError extends Error {
  constructor(detail?: string) {
    super(
      detail !== undefined
        ? detail
        : 'macOS VM runner not yet implemented.',
    );
    this.name = 'MacOSVmNotImplementedError';
  }
}

/** The `script-jail-vm` binary could not be found in any of the lookup paths. */
export class MacOSVmBinaryNotFoundError extends Error {
  constructor(public readonly searched: ReadonlyArray<string>) {
    super(
      `script-jail-vm binary not found. Checked:\n  - ${searched.join('\n  - ')}\n` +
        'Run `cargo build --release -p script-jail-host-mac` to build it, ' +
        'or set SCRIPT_JAIL_VM_BIN to an explicit path.',
    );
    this.name = 'MacOSVmBinaryNotFoundError';
  }
}

/** Required artifact (kernel / rootfs / .so) is missing on disk. */
export class MacOSVmArtifactNotFoundError extends Error {
  constructor(public readonly artifact: string, public readonly path: string) {
    super(
      `${artifact} not found at ${path}. ` +
        'Run `pnpm build` for local artifacts or fetch the matching release artifact.',
    );
    this.name = 'MacOSVmArtifactNotFoundError';
  }
}

/** The helper exited with code 64 (pre-boot configuration error). */
export class MacOSVmConfigError extends Error {
  constructor(public readonly stderrTail: string) {
    super(
      'script-jail-vm rejected the VmConfig (exit 64). ' +
        (stderrTail.trim().length > 0 ? `stderr tail:\n${stderrTail}` : 'No stderr captured.'),
    );
    this.name = 'MacOSVmConfigError';
  }
}

/** The helper exited with code 2 (VZ-side runtime error). */
export class MacOSVmRuntimeError extends Error {
  constructor(public readonly stderrTail: string) {
    super(
      'script-jail-vm reported a Virtualization.framework runtime error (exit 2). ' +
        (stderrTail.trim().length > 0 ? `stderr tail:\n${stderrTail}` : 'No stderr captured.'),
    );
    this.name = 'MacOSVmRuntimeError';
  }
}

/** The helper exited non-zero with no recognizable diagnostic. */
export class MacOSVmUnknownError extends Error {
  constructor(public readonly exitCode: number | null, public readonly signal: NodeJS.Signals | null) {
    super(
      `script-jail-vm exited unexpectedly (code=${exitCode ?? 'null'}, signal=${signal ?? 'null'}).`,
    );
    this.name = 'MacOSVmUnknownError';
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the package root by walking up from this file looking for a
 * `package.json`.  Falls back to two levels up from this module when running
 * from `dist/cli.cjs`.  Pure path math; no IO beyond `existsSync` higher up
 * the call chain.
 *
 * The bundled CJS file has esbuild-injected `__filename` at module scope
 * (NOT on globalThis); the ESM dev build has `import.meta.url`.  We attempt
 * `__filename` first because that's the production path (npm-installed
 * package).
 */
function resolvePackageRoot(): string {
  let here: string = '';
  try {
    const dn: unknown = (typeof __filename !== 'undefined' ? __filename : undefined);
    if (typeof dn === 'string') here = dn;
  } catch {
    /* ignore */
  }
  if (here === '') {
    try {
      here = fileURLToPath(import.meta.url);
    } catch {
      here = process.argv[1] ?? process.cwd();
    }
  }
  // `here` is .../src/cli/spawn-vm.ts (dev) or .../dist/cli.cjs (bundle).
  // The package root is two `dirname`s up from either.
  return dirname(dirname(here));
}

// See note above resolvePackageRoot — the bundle gets a real `__filename`,
// the ESM dev build does not.  Declaring it as a possibly-undefined global
// lets the same source file compile under both.
declare const __filename: string | undefined;

/**
 * Locate the `script-jail-vm` binary on disk.  See file-level docs for the
 * lookup order.  Returns the first existing path or throws
 * `MacOSVmBinaryNotFoundError` listing every path we tried.
 */
export function resolveScriptJailVmBinary(opts?: {
  envOverride?: string;
  repoRoot?: string;
  packageRoot?: string;
  arch?: 'x64' | 'arm64';
}): string {
  const searched: string[] = [];

  // 1. Explicit env override (highest priority).
  const envBin =
    opts?.envOverride !== undefined ? opts.envOverride : process.env['SCRIPT_JAIL_VM_BIN'];
  if (envBin !== undefined && envBin !== '') {
    searched.push(`${envBin} (SCRIPT_JAIL_VM_BIN)`);
    if (existsSync(envBin)) return envBin;
  }

  // 2. Local cargo target dir.
  const repoRoot = opts?.repoRoot ?? resolvePackageRoot();
  const localTarget = join(repoRoot, 'target', 'release', 'script-jail-vm');
  searched.push(localTarget);
  if (existsSync(localTarget)) return localTarget;

  // 3. Published npm package bin/.
  const packageRoot = opts?.packageRoot ?? resolvePackageRoot();
  const arch = opts?.arch ?? (process.arch === 'arm64' ? 'arm64' : 'x64');
  const installedBin = join(
    packageRoot,
    'bin',
    `darwin-${arch}`,
    'script-jail-vm',
  );
  searched.push(installedBin);
  if (existsSync(installedBin)) return installedBin;

  throw new MacOSVmBinaryNotFoundError(searched);
}

/**
 * Verify that each required artifact exists on disk.  Throws
 * `MacOSVmArtifactNotFoundError` for the first missing file. Kernel is checked
 * first because VZ cannot build a useful VM config without it.
 *
 * Note: `libscriptjailSoPath` is NOT checked here — that ELF is baked into
 * the released rootfs (see scripts/build.ts) and the rootfs ext4 check above
 * is sufficient.  We keep the parameter on the signature so callers don't
 * have to think about which artifacts get host-side existence checks vs.
 * rootfs-internal verification.
 */
export function checkArtifacts(cfg: {
  kernelPath: string;
  rootfsDiskPath: string;
  libscriptjailSoPath?: string;
}): void {
  if (!existsSync(cfg.kernelPath)) {
    throw new MacOSVmArtifactNotFoundError('kernel', cfg.kernelPath);
  }
  if (!existsSync(cfg.rootfsDiskPath)) {
    throw new MacOSVmArtifactNotFoundError('rootfs', cfg.rootfsDiskPath);
  }
  if (
    cfg.libscriptjailSoPath !== undefined &&
    cfg.libscriptjailSoPath !== '' &&
    !existsSync(cfg.libscriptjailSoPath)
  ) {
    throw new MacOSVmArtifactNotFoundError('libscriptjail.so', cfg.libscriptjailSoPath);
  }
}

/**
 * JSON shape the Rust helper expects on disk.  Mirrors
 * `src/host-mac/src/config.rs::VmConfig`'s serde field names exactly.
 * We do NOT export this — the CLI talks in the camelCase `VmConfig`
 * interface above and the JSON translation is an internal concern.
 */
interface VmConfigJson {
  kernel_path: string;
  kernel_cmdline: string;
  rootfs_disk_path: string;
  repo_disk_path: string;
  vsock_uds_path: string;
  vsock_port: number;
  vcpu_count: number;
  memory_mb: number;
  enable_network: boolean;
}

/** Build the JSON payload to write to disk for the Rust helper. */
export function toJsonPayload(cfg: VmConfig): VmConfigJson {
  return {
    kernel_path: cfg.kernelPath,
    kernel_cmdline: cfg.kernelCmdline,
    rootfs_disk_path: cfg.rootfsDiskPath,
    repo_disk_path: cfg.repoDiskPath,
    vsock_uds_path: cfg.vsockUdsPath,
    vsock_port: cfg.vsockPort,
    vcpu_count: cfg.vcpuCount,
    memory_mb: cfg.memoryMb,
    enable_network: cfg.enableNetwork,
  };
}

// ---------------------------------------------------------------------------
// Stderr capture
// ---------------------------------------------------------------------------
//
// We mirror `script-jail-vm`'s stderr to the host's stderr so the user sees
// boot diagnostics live, AND we keep a bounded tail so the error-path
// classification can surface the last lines in the thrown error.  A bounded
// ring (4 KB) is plenty: every error message the helper writes is
// significantly smaller.

const STDERR_TAIL_BYTES = 4096;

class StderrTail {
  private buf: Buffer = Buffer.alloc(0);
  append(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk]);
    if (this.buf.length > STDERR_TAIL_BYTES) {
      this.buf = this.buf.subarray(this.buf.length - STDERR_TAIL_BYTES);
    }
  }
  text(): string {
    return this.buf.toString('utf8');
  }
}

// ---------------------------------------------------------------------------
// spawnVm
// ---------------------------------------------------------------------------

export interface SpawnVmOptions {
  /** Override the binary lookup (test seam). */
  binary?: string;
  /** Override the stderr sink (test seam).  Defaults to `process.stderr`. */
  stderr?: NodeJS.WritableStream;
}

/**
 * Spawn the Rust helper, drive the JSONL handshake, and return the audit's
 * final YAML.  Cleans up the temp config file and the child process whether
 * the run succeeds or fails.
 *
 * Note: `vmConfig.{repoDir,configPath,lockPath,mode}` are CLI-side
 * bookkeeping and are NOT serialized into the helper's config JSON.
 */
export async function spawnVm(
  vmConfig: VmConfig,
  options: SpawnVmOptions = {},
): Promise<VmRunResult> {
  const binary = options.binary ?? resolveScriptJailVmBinary();
  const stderrSink = options.stderr ?? process.stderr;

  // Pre-flight: every host-side artifact the helper will need.  Surfaces a
  // friendly "kernel not found" error before we ever touch the Rust binary.
  checkArtifacts({
    kernelPath: vmConfig.kernelPath,
    rootfsDiskPath: vmConfig.rootfsDiskPath,
  });

  // Write the JSON config to a per-run temp file.  We use a mkdtemp dir so
  // the path is unique per invocation and we can rm -rf at the end without
  // racing other concurrent runs.
  const tmpDir = mkdtempSync(join(tmpdir(), 'script-jail-vm-'));
  const configJsonPath = join(tmpDir, 'config.json');
  writeFileSync(configJsonPath, JSON.stringify(toJsonPayload(vmConfig), null, 2), 'utf8');

  let child: ChildProcess | null = null;
  const stderrTail = new StderrTail();
  const warnings: string[] = [];

  // Install SIGINT/SIGTERM forwarders so Ctrl-C in the host terminal
  // delivers a graceful shutdown to the helper.  We deinstall in `finally`.
  const onSignal = (sig: NodeJS.Signals) => {
    if (child !== null && !child.killed) {
      try { child.kill(sig); } catch { /* ignore */ }
    }
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  try {
    child = spawn(binary, ['boot', '--config', configJsonPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Forward + capture stderr.
    child.stderr!.on('data', (chunk: Buffer) => {
      stderrTail.append(chunk);
      stderrSink.write(chunk);
    });

    // Resolve when the child exits.
    const exitPromise: Promise<{ code: number | null; signal: NodeJS.Signals | null }> =
      new Promise((resolveExit) => {
        child!.once('exit', (code, signal) => resolveExit({ code, signal }));
      });

    // Drive the JSONL stream from stdout.  `parseFrames` is the same parser
    // the Linux action uses on the vsock stream, so any contract changes
    // surface in both runners at once.
    let finalYaml: string | null = null;
    let fatalError: Error | null = null;

    const frameStream: AsyncIterable<GuestFrame> = parseFrames(child.stdout!);
    for await (const frame of frameStream) {
      if (frame.kind === 'event') continue; // host-side normalization not on the macOS path
      if (frame.kind === 'handshake') {
        if (frame.phase === 'fetch_done') {
          // Release the guest from the Phase A → Phase B gate.
          await new Promise<void>((res, rej) => {
            child!.stdin!.write('go\n', (err) => (err ? rej(err) : res()));
          });
          continue;
        }
        // install_done is FYI; `final` follows.
        continue;
      }
      if (frame.kind === 'error') {
        if (frame.fatal) {
          fatalError = new Error(`script-jail-vm guest fatal: ${frame.message}`);
          break;
        }
        warnings.push(frame.message);
        stderrSink.write(`script-jail-vm: ${frame.message}\n`);
        continue;
      }
      if (frame.kind === 'final') {
        finalYaml = frame.yaml;
        // Close stdin to invite a clean shutdown.  The helper exits as soon
        // as the guest hangs up the vsock connection; closing stdin gives
        // it one extra hint that we're done.
        try { child!.stdin!.end(); } catch { /* ignore */ }
        break;
      }
    }

    // Wait for the child to exit so we can map exit codes to error classes.
    const { code, signal } = await exitPromise;

    if (fatalError !== null) {
      throw fatalError;
    }
    if (finalYaml === null) {
      // No final frame: classify the exit.
      if (code === 64) throw new MacOSVmConfigError(stderrTail.text());
      if (code === 2) throw new MacOSVmRuntimeError(stderrTail.text());
      if (code === 0) {
        // Clean exit with no final frame is still an error from our POV —
        // every successful audit emits exactly one `final`.  Surface as an
        // unknown error so the caller sees the stderr tail.
        throw new MacOSVmUnknownError(code, signal);
      }
      throw new MacOSVmUnknownError(code, signal);
    }

    return { finalYaml, warnings };
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);

    // Force-kill any lingering child (e.g. if the for-await loop threw
    // before the helper had a chance to exit cleanly).
    if (child !== null && child.exitCode === null && !child.killed) {
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
    }

    // Best-effort cleanup of the per-run config tmp dir.
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

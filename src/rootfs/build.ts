// script-jail — src/rootfs/build.ts
// Orchestrates building the Firecracker rootfs ext4 image.
//
// In v2 the rootfs is keyed by Ubuntu major (`ubuntu-22.04`, `ubuntu-24.04`)
// rather than by `(node-major, package-manager)`: Node ships into the VM at
// runtime via a third virtio drive packed by the action (see
// `src/action/firecracker/overlay.ts`).  The rootfs therefore only needs to
// be ABI-compatible with whatever the host runner provides.
//
// Steps:
//   1. Bundle src/guest/agent.ts → dist/guest-agent.cjs via esbuild
//   2. Copy the .cjs preloads to dist/preloads/
//   3. Ensure images/libscriptjail.so is present (build if not, skip on macOS)
//   4. docker build → script-jail-rootfs:<runnerImage>
//   5. docker export → tar → directory → ext4 image
//   6. Write images/rootfs-<runnerImage>.ext4
//   7. Report size; warn if > 200 MB

import { execSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  statSync,
  copyFileSync,
  readdirSync,
  rmSync,
  openSync,
  readSync,
  closeSync,
} from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';

import { shimArtifactIsStale, shimSourceInputs } from './shim-freshness.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported runner images.  Must stay in sync with `src/action/runner-image.ts`. */
export type RunnerImage = 'ubuntu-22.04' | 'ubuntu-24.04';

/**
 * Target architecture for the rootfs ext4.
 *
 *   - 'x64'    → x86_64 image, native on Linux CI, docker-buildx-linux/amd64 on macOS.
 *   - 'arm64'  → aarch64 image, native on arm64 Linux, docker-buildx-linux/arm64
 *                (qemu emulation on x86_64 hosts).  PR 4 wires the codepath;
 *                PR 5 hooks it into CI.  Local arm64 builds work today but
 *                are slow (qemu).
 */
export type BuildArch = 'x64' | 'arm64';

export interface BuildInput {
  runnerImage: RunnerImage;
  /** Directory where images/*.ext4 are written. Defaults to <repo root>/images */
  outputDir: string;
  /**
   * Target arch for the rootfs.  Defaults to 'x64' to preserve the existing
   * Firecracker pipeline.  PR 4 introduced this parameter; production callers
   * (release.yml, scripts/build.ts) must pass the desired value.
   */
  arch?: BuildArch;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
/** Repo root: two levels up from src/rootfs/ */
const REPO_ROOT = join(__dirname, '..', '..');

// ---------------------------------------------------------------------------
// Pure helpers (unit-testable)
// ---------------------------------------------------------------------------

/** Compute the output ext4 image filename. */
export function imageFilename(input: Pick<BuildInput, 'runnerImage' | 'arch'>): string {
  // x64 keeps the existing flat name for backwards-compat with the release
  // pipeline + PINNED_MANIFEST.  arm64 gets an explicit suffix so both
  // images can coexist under `images/`.
  const arch = input.arch ?? 'x64';
  if (arch === 'arm64') {
    return `rootfs-${input.runnerImage}-arm64.ext4`;
  }
  return `rootfs-${input.runnerImage}.ext4`;
}

/** Compute the full output path for the ext4 image. */
export function imageOutputPath(input: BuildInput): string {
  return join(input.outputDir, imageFilename(input));
}

/** Docker image tag for this runner image. */
export function dockerTag(input: Pick<BuildInput, 'runnerImage' | 'arch'>): string {
  // arm64 gets an arch suffix so x64 and arm64 tags can coexist in a local
  // docker engine.  The x64 tag stays unsuffixed for backwards-compat with
  // the existing release pipeline.
  const arch = input.arch ?? 'x64';
  if (arch === 'arm64') return `script-jail-rootfs:${input.runnerImage}-arm64`;
  return `script-jail-rootfs:${input.runnerImage}`;
}

/**
 * Map a target arch to the `docker buildx --platform` value.  Used by the
 * arm64 path so a macOS / x86_64 builder can produce a Linux/arm64 image
 * via qemu emulation; PR 4 wires this in, PR 5 enables it from CI.
 */
export function dockerPlatform(arch: BuildArch): string {
  return arch === 'arm64' ? 'linux/arm64' : 'linux/amd64';
}

/** Map a runner image to its `ubuntu:<version>` base tag. */
export function ubuntuBaseTag(input: Pick<BuildInput, 'runnerImage'>): string {
  const versions: Record<RunnerImage, string> = {
    'ubuntu-22.04': '22.04',
    'ubuntu-24.04': '24.04',
  };
  return `ubuntu:${versions[input.runnerImage]}`;
}

/** Extract the bare Ubuntu major version (e.g. `22.04`) from a runner image. */
export function ubuntuMajor(input: Pick<BuildInput, 'runnerImage'>): string {
  // ubuntuBaseTag is `ubuntu:<version>`; strip the prefix.
  return ubuntuBaseTag(input).slice('ubuntu:'.length);
}

/** Return true when the process is running on macOS. */
export function isMacOS(): boolean {
  return process.platform === 'darwin';
}

/** Return true when the process is running on Linux. */
export function isLinux(): boolean {
  return process.platform === 'linux';
}

/** Format bytes as a human-readable string (e.g. "123.4 MB"). */
export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Threshold in bytes above which we warn about image size. */
export const SIZE_WARN_THRESHOLD_BYTES = 200 * 1024 * 1024; // 200 MB

// ---------------------------------------------------------------------------
// ELF validation for libscriptjail.so
// ---------------------------------------------------------------------------
//
// The rootfs Dockerfile COPYs `images/libscriptjail.so` into the VM at
// `/lib/libscriptjail.so`; the guest agent then sets `LD_PRELOAD=/lib/libscriptjail.so`.
// If the host devloop produced a macOS Mach-O dylib (or some other non-ELF
// blob) and somebody renamed it to `.so`, the dynamic linker inside the VM
// silently refuses to load it, leaving the env-read audit chain absent.
// We therefore validate the on-disk file BEFORE accepting it.
//
// Validation depth is "loadability", not just the prefix: a 20-byte blob with
// a valid ELF magic prefix passes a magic check but ld.so cannot load it
// (no program headers, no PT_DYNAMIC, no symbol table). To catch that, we:
//   1. Verify the ELF identification bytes (magic, class, endianness).
//   2. Verify e_type / e_machine match a shared object for the rootfs target.
//   3. Read the program header table off `e_phoff` and require it to fit in
//      the file (e_phoff > 0, e_phoff + e_phnum * e_phentsize <= file_size).
//   4. Walk the program headers and require at least one PT_DYNAMIC entry.
//      A loadable shared object must have a dynamic section — that is what
//      ld.so consults for SONAME / DT_NEEDED / symbol resolution.
//
// Reference (ELF64 header, little-endian):
//   bytes 0..3     = 0x7F 'E' 'L' 'F'           (ELF magic)
//   byte  4        = EI_CLASS  (2 = ELFCLASS64)
//   byte  5        = EI_DATA   (1 = ELFDATA2LSB, little-endian)
//   bytes 16..17   = e_type    (3 = ET_DYN, shared object)
//   bytes 18..19   = e_machine (62 = EM_X86_64, 183 = EM_AARCH64)
//   bytes 32..39   = e_phoff   (u64, file offset of program header table)
//   bytes 54..55   = e_phentsize (u16, size of each phdr entry; 56 for ELF64)
//   bytes 56..57   = e_phnum   (u16, number of phdr entries)
//
// Program header entry (ELF64, 56 bytes):
//   bytes 0..3     = p_type    (u32; 1 = PT_LOAD, 2 = PT_DYNAMIC)
//
// All numeric ELF header fields above are stored little-endian per EI_DATA=1.

/** Size of the ELF64 header. */
export const ELF64_EHDR_SIZE = 64;
/** Size of a single ELF64 program header entry. */
export const ELF64_PHDR_SIZE = 56;

/** Program header types we care about. */
export const PT_LOAD = 1;
export const PT_DYNAMIC = 2;

/** ELF e_machine values we recognise.  Currently only x86-64 ships. */
export const EM_X86_64 = 62;
export const EM_AARCH64 = 183;

/** Map a runner image to the ELF e_machine value expected for that rootfs. */
export function expectedShimMachine(input: Pick<BuildInput, 'runnerImage' | 'arch'>): number {
  // x64 is the default arch (preserves existing Firecracker pipeline); PR 4
  // adds the arm64 fork so the macOS arm64 CLI can validate `libscriptjail-arm64.so`.
  const arch = input.arch ?? 'x64';
  return arch === 'arm64' ? EM_AARCH64 : EM_X86_64;
}

/** Human-readable label for an e_machine value (used in error messages). */
export function machineLabel(machine: number): string {
  if (machine === EM_X86_64) return 'x86-64 (EM_X86_64)';
  if (machine === EM_AARCH64) return 'aarch64 (EM_AARCH64)';
  return `e_machine=${machine}`;
}

/**
 * Validate that `buf` (the start of a file, at least 20 bytes) looks like a
 * Linux ELF64 little-endian shared object for the given machine. Returns
 * `null` on success or a descriptive error string on any mismatch.
 *
 * This is the prefix-only check used to identify clearly-wrong file shapes
 * (Mach-O, scripts, 32-bit ELF, big-endian ELF, wrong architecture). It does
 * NOT verify loadability — for that, callers must additionally inspect the
 * program header table via `validateElfProgramHeaders` (or, end-to-end, use
 * `validateShimFile`, which reads the full header and walks the phdrs).
 *
 * Pure / no IO.
 */
export function validateElfShimHeader(
  buf: Uint8Array,
  expectedMachine: number,
): string | null {
  if (buf.length < 20) {
    return `header too short (${buf.length} bytes; need ≥ 20)`;
  }

  // Bytes 0..3: ELF magic 0x7F 'E' 'L' 'F'.
  if (
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 || // 'E'
    buf[2] !== 0x4c || // 'L'
    buf[3] !== 0x46    // 'F'
  ) {
    // Mach-O 64-bit little-endian magics are 0xCFFAEDFE / 0xCEFAEDFE
    // (Mach-O fat is 0xCAFEBABE / 0xBEBAFECA).  Surface that when we see it
    // so the error directs the user to rebuild on Linux rather than to
    // hunt down a generic "bad magic" message.
    const m =
      (buf[0]! << 24) |
      (buf[1]! << 16) |
      (buf[2]! <<  8) |
       buf[3]!;
    const u = m >>> 0;
    if (u === 0xcffaedfe || u === 0xcefaedfe || u === 0xfeedfacf || u === 0xfeedface) {
      return 'file is a Mach-O binary, not a Linux ELF shared object';
    }
    if (u === 0xcafebabe || u === 0xbebafeca) {
      return 'file is a Mach-O universal binary, not a Linux ELF shared object';
    }
    return `bad ELF magic: expected 0x7F 45 4C 46, got 0x${u.toString(16).padStart(8, '0')}`;
  }

  // Byte 4: EI_CLASS — 2 = ELFCLASS64.
  if (buf[4] !== 2) {
    return `unsupported EI_CLASS=${buf[4]} (expected 2 = ELFCLASS64)`;
  }

  // Byte 5: EI_DATA — 1 = little-endian (ELFDATA2LSB).
  if (buf[5] !== 1) {
    return `unsupported EI_DATA=${buf[5]} (expected 1 = ELFDATA2LSB, little-endian)`;
  }

  // Bytes 16..17: e_type, little-endian u16.  3 = ET_DYN (shared object / PIE).
  const eType = buf[16]! | (buf[17]! << 8);
  if (eType !== 3) {
    return `unsupported e_type=${eType} (expected 3 = ET_DYN, shared object)`;
  }

  // Bytes 18..19: e_machine, little-endian u16.
  const eMachine = buf[18]! | (buf[19]! << 8);
  if (eMachine !== expectedMachine) {
    return (
      `wrong architecture: got ${machineLabel(eMachine)}, ` +
      `expected ${machineLabel(expectedMachine)}`
    );
  }

  return null;
}

/** Read a little-endian unsigned 16-bit integer from `buf` at `off`. */
function readU16LE(buf: Uint8Array, off: number): number {
  return (buf[off]! | (buf[off + 1]! << 8)) >>> 0;
}

/** Read a little-endian unsigned 32-bit integer from `buf` at `off`. */
function readU32LE(buf: Uint8Array, off: number): number {
  return (
    (buf[off]! |
      (buf[off + 1]! << 8) |
      (buf[off + 2]! << 16) |
      (buf[off + 3]! << 24)) >>>
    0
  );
}

/**
 * Read a little-endian unsigned 64-bit integer from `buf` at `off` as a
 * JavaScript number. We use Number rather than BigInt because ELF offsets in
 * a < 4 GiB shared object fit comfortably in a double's 53-bit mantissa, and
 * the rest of the validation does plain arithmetic. Returns `null` when the
 * value exceeds Number.MAX_SAFE_INTEGER (would indicate a corrupt header).
 */
function readU64LEAsNumber(buf: Uint8Array, off: number): number | null {
  const lo = readU32LE(buf, off);
  const hi = readU32LE(buf, off + 4);
  // hi * 2^32 + lo. Reject anything that would lose precision.
  if (hi > 0x001fffff) return null;
  return hi * 0x100000000 + lo;
}

/**
 * Walk the program header table and require at least one PT_DYNAMIC entry.
 * `ehdr` is the first 64 bytes of the file (the ELF64 header). `phdrs` is the
 * raw bytes of the program header table, exactly `phnum * phentsize` long.
 *
 * Returns `null` on success or a descriptive error string. Pure / no IO.
 *
 * The check is intentionally strict — a shared object that ld.so can load
 * MUST have a PT_DYNAMIC segment (that is what supplies SONAME, DT_NEEDED,
 * and the dynamic symbol table). We also require at least one PT_LOAD, which
 * supplies the actual mapped code/data: an .so with no PT_LOAD is meaningless.
 */
export function validateElfProgramHeaders(
  ehdr: Uint8Array,
  phdrs: Uint8Array,
  fileSize: number,
): string | null {
  if (ehdr.length < ELF64_EHDR_SIZE) {
    return `ELF header too short (${ehdr.length} bytes; need ${ELF64_EHDR_SIZE})`;
  }

  const ePhoff = readU64LEAsNumber(ehdr, 32);
  const ePhentsize = readU16LE(ehdr, 54);
  const ePhnum = readU16LE(ehdr, 56);

  if (ePhoff === null) {
    return 'e_phoff is unreasonably large (overflow / corrupt header)';
  }
  if (ePhoff === 0) {
    return 'no program header table (e_phoff=0); not a loadable shared object';
  }
  if (ePhnum === 0) {
    return 'no program header entries (e_phnum=0); not a loadable shared object';
  }
  if (ePhentsize !== ELF64_PHDR_SIZE) {
    return (
      `unsupported e_phentsize=${ePhentsize} ` +
      `(expected ${ELF64_PHDR_SIZE} for ELF64)`
    );
  }

  const phdrEnd = ePhoff + ePhnum * ePhentsize;
  if (phdrEnd > fileSize) {
    return (
      `program header table runs past end of file ` +
      `(e_phoff=${ePhoff} + ${ePhnum}*${ePhentsize} = ${phdrEnd}, file_size=${fileSize})`
    );
  }
  if (phdrs.length < ePhnum * ePhentsize) {
    return (
      `program header buffer truncated ` +
      `(got ${phdrs.length} bytes; need ${ePhnum * ePhentsize})`
    );
  }

  let sawDynamic = false;
  let sawLoad = false;
  for (let i = 0; i < ePhnum; i++) {
    const off = i * ePhentsize;
    const pType = readU32LE(phdrs, off);
    if (pType === PT_DYNAMIC) sawDynamic = true;
    if (pType === PT_LOAD) sawLoad = true;
  }
  if (!sawLoad) {
    return 'no PT_LOAD segment; not a loadable shared object';
  }
  if (!sawDynamic) {
    return (
      'no PT_DYNAMIC segment; ld.so cannot resolve symbols ' +
      '(stale / corrupt artifact?)'
    );
  }
  return null;
}

/**
 * Read `path` and validate that it is a Linux ELF64 little-endian shared
 * object for `expectedMachine` AND that it is loadable (has a program header
 * table containing at least one PT_DYNAMIC segment). Returns `null` on
 * success or a descriptive error string. Surfaces `read` / `open` errors as
 * strings rather than throwing so the caller can fold them into a single
 * error message.
 *
 * Validates loadability, not just the prefix: a 20-byte file with the right
 * magic was previously accepted but ld.so cannot load it; that escape is now
 * closed.
 */
export function validateShimFile(path: string, expectedMachine: number): string | null {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (err) {
    return `cannot open: ${err instanceof Error ? err.message : String(err)}`;
  }
  try {
    // 1. Read the full ELF64 header (64 bytes).
    const ehdr = Buffer.alloc(ELF64_EHDR_SIZE);
    const n = readSync(fd, ehdr, 0, ELF64_EHDR_SIZE, 0);
    if (n < ELF64_EHDR_SIZE) {
      return `header too short (${n} bytes; need ≥ ${ELF64_EHDR_SIZE})`;
    }

    // 2. Prefix check (magic + class + endian + e_type + e_machine).
    const prefixErr = validateElfShimHeader(ehdr, expectedMachine);
    if (prefixErr !== null) return prefixErr;

    // 3. Inspect the program header table for PT_DYNAMIC / PT_LOAD.
    let fileSize: number;
    try {
      fileSize = statSync(path).size;
    } catch (err) {
      return `cannot stat: ${err instanceof Error ? err.message : String(err)}`;
    }

    const ePhoff = readU64LEAsNumber(ehdr, 32);
    const ePhentsize = readU16LE(ehdr, 54);
    const ePhnum = readU16LE(ehdr, 56);

    // Quick-fail before the second read so the error matches what
    // validateElfProgramHeaders would report.
    if (ePhoff === null) {
      return 'e_phoff is unreasonably large (overflow / corrupt header)';
    }
    if (ePhoff === 0) {
      return 'no program header table (e_phoff=0); not a loadable shared object';
    }
    if (ePhnum === 0) {
      return 'no program header entries (e_phnum=0); not a loadable shared object';
    }
    if (ePhentsize !== ELF64_PHDR_SIZE) {
      return (
        `unsupported e_phentsize=${ePhentsize} ` +
        `(expected ${ELF64_PHDR_SIZE} for ELF64)`
      );
    }

    const phdrBytes = ePhnum * ePhentsize;
    if (ePhoff + phdrBytes > fileSize) {
      return (
        `program header table runs past end of file ` +
        `(e_phoff=${ePhoff} + ${ePhnum}*${ePhentsize} = ${ePhoff + phdrBytes}, file_size=${fileSize})`
      );
    }

    const phdrs = Buffer.alloc(phdrBytes);
    const m = readSync(fd, phdrs, 0, phdrBytes, ePhoff);
    if (m < phdrBytes) {
      return (
        `short read of program header table ` +
        `(got ${m} bytes; need ${phdrBytes} at offset ${ePhoff})`
      );
    }

    return validateElfProgramHeaders(ehdr, phdrs, fileSize);
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

function run(cmd: string, opts?: { cwd?: string }): void {
  execSync(cmd, { stdio: 'inherit', cwd: opts?.cwd ?? REPO_ROOT });
}

function runCapture(cmd: string, opts?: { cwd?: string }): string {
  return execSync(cmd, { cwd: opts?.cwd ?? REPO_ROOT }).toString().trim();
}

function commandExists(cmd: string): boolean {
  const result = spawnSync('which', [cmd], { stdio: 'ignore' });
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// Step 1 — Bundle agent
// ---------------------------------------------------------------------------

function bundleAgent(): void {
  const agentSrc = join(REPO_ROOT, 'src', 'guest', 'agent.ts');
  const agentOut = join(REPO_ROOT, 'dist', 'guest-agent.cjs');

  mkdirSync(join(REPO_ROOT, 'dist'), { recursive: true });

  const esbuildBin = join(REPO_ROOT, 'node_modules', '.bin', 'esbuild');
  run(
    `"${esbuildBin}" "${agentSrc}" ` +
    `--bundle --platform=node --format=cjs --target=node20 ` +
    `--outfile="${agentOut}"`,
  );
  console.log(`[rootfs] Bundled agent → dist/guest-agent.cjs`);
}

// ---------------------------------------------------------------------------
// Step 2 — Copy preloads
// ---------------------------------------------------------------------------

function copyPreloads(): void {
  const preloadsDir = join(REPO_ROOT, 'dist', 'preloads');
  mkdirSync(preloadsDir, { recursive: true });

  const files: ReadonlyArray<string> = ['platform-spoof.cjs', 'dlopen-block.cjs', 'env-spy.cjs'];
  for (const file of files) {
    const src = join(REPO_ROOT, 'src', 'guest', file);
    const dst = join(preloadsDir, file);
    copyFileSync(src, dst);
    console.log(`[rootfs] Copied ${file} → dist/preloads/${file}`);
  }
}

// ---------------------------------------------------------------------------
// Step 3 — Ensure libscriptjail.so
// ---------------------------------------------------------------------------

function ensureShim(input: BuildInput): boolean {
  // The Dockerfile COPYs `images/libscriptjail.so` unconditionally, so the
  // arm64 rootfs build needs the arm64-arch bytes at that exact path.  The
  // arch-suffixed sibling (`images/libscriptjail-arm64.so`) is produced
  // upstream by `scripts/build.ts:buildShimArm64()` via cargo-zigbuild;
  // stage it to the canonical path so the validator + Docker COPY see one
  // file and the existing validation + freshness logic keeps working.
  //
  // The staging is a one-way copy: subsequent x86_64 rootfs builds in the
  // same checkout would re-build `libscriptjail.so` via cargo (host arch =
  // x86_64) and clobber the arm64 bytes back to x86_64.  In practice each
  // CI job is single-arch, so the clobber happens at most once per workflow
  // run and is the intended behaviour.
  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail.so');
  const archSuffixedShim = join(REPO_ROOT, 'images', 'libscriptjail-arm64.so');
  const expectedMachine = expectedShimMachine(input);

  if (input.arch === 'arm64' && existsSync(archSuffixedShim)) {
    console.log('[rootfs] Staging libscriptjail-arm64.so → libscriptjail.so (arm64 rootfs build).');
    copyFileSync(archSuffixedShim, shimOut);
  }

  if (existsSync(shimOut)) {
    // The file is on disk, but we must NOT trust it blindly: a previous
    // macOS-side build may have left a Mach-O dylib here (see
    // `validateElfShimHeader` for the rationale).  If validation fails on
    // Linux we rebuild from source; on macOS we surface a fatal error
    // because we cannot produce a Linux .so from a Darwin toolchain.
    const err = validateShimFile(shimOut, expectedMachine);
    if (err !== null) {
      console.warn(`[rootfs] images/libscriptjail.so failed ELF validation: ${err}`);
      if (isMacOS()) {
        throw new Error(
          `[rootfs] images/libscriptjail.so is not a valid Linux ELF shared object (${err}). ` +
          'Cannot rebuild from macOS (Darwin cargo produces a Mach-O .dylib, not a Linux .so). ' +
          'Delete images/libscriptjail.so and run the rootfs build on a Linux host (or in CI) ' +
          'so cargo can produce a real x86-64 ELF shared object.',
        );
      }
      console.warn('[rootfs] Removing stale artifact and rebuilding via cargo …');
      rmSync(shimOut, { force: true });
    } else {
      // ELF validation passed.  Finding 3 (audit-trust): the ELF check only
      // detects MALFORMED artifacts (wrong magic, no PT_DYNAMIC, etc.) — a
      // structurally-valid `.so` produced from out-of-date Rust source still
      // looks fine to the validator.  Before accepting the artifact, gate it
      // through the same mtime-based freshness check that
      // `scripts/build.ts:buildShim` uses, so a caller that bypasses the
      // top-level build script (direct `oxnode src/rootfs/build.ts`, future
      // tooling, etc.) cannot embed a stale shim into the Firecracker rootfs.
      const sources = shimSourceInputs(REPO_ROOT);
      if (!shimArtifactIsStale(shimOut, sources)) {
        console.log(`[rootfs] libscriptjail.so already present (validated ELF + fresh).`);
        return true;
      }
      if (isMacOS()) {
        // Same constraint as the ELF-validation failure path: we cannot
        // produce a Linux .so from Darwin cargo.  Fail closed with a clear
        // message rather than silently keeping the stale artifact.
        throw new Error(
          `[rootfs] images/libscriptjail.so is older than the shim source inputs ` +
          `(${sources.join(', ')}). Cannot rebuild from macOS — touch the artifact, ` +
          'or run the rootfs build on a Linux host / CI so cargo can produce a fresh ' +
          'x86-64 ELF shared object.',
        );
      }
      console.warn(
        '[rootfs] libscriptjail.so is older than shim sources; rebuilding via cargo …',
      );
      rmSync(shimOut, { force: true });
    }
  } else if (isMacOS()) {
    console.warn(
      '[rootfs] WARNING: Running on macOS — cannot build libscriptjail.so (requires Linux toolchain).\n' +
      '[rootfs]          Skipping shim build. The docker build step will also be skipped.\n' +
      '[rootfs]          To build the full rootfs, run this script on a Linux host or CI.',
    );
    return false;
  }

  console.log(`[rootfs] Building libscriptjail.so via cargo …`);
  const manifest = join(REPO_ROOT, 'src', 'shim', 'Cargo.toml');
  run(`cargo build --release --manifest-path "${manifest}"`);

  mkdirSync(join(REPO_ROOT, 'images'), { recursive: true });
  copyFileSync(
    join(REPO_ROOT, 'target', 'release', 'libscriptjail.so'),
    shimOut,
  );

  if (!existsSync(shimOut)) {
    throw new Error(`[rootfs] cargo build ran but ${shimOut} was not produced.`);
  }

  // Validate the freshly-built artifact too — a cargo misconfiguration
  // (cross-compiling to the wrong target, building for the host arch on a
  // mismatched runner) is exactly the kind of mistake this check catches.
  const buildErr = validateShimFile(shimOut, expectedMachine);
  if (buildErr !== null) {
    throw new Error(
      `[rootfs] cargo built ${shimOut} but it failed ELF validation: ${buildErr}. ` +
      'Check src/shim/Cargo.toml and the active rustup target.',
    );
  }
  return true;
}

/**
 * Test entry point for Finding 3: simulate the decision `ensureShim` makes
 * for an artifact whose ELF validation already passed.  Returns `'reject'`
 * (artifact is stale and must be rebuilt or fail closed) or `'accept'`
 * (artifact is fresh).  Production code paths must continue to call
 * `ensureShim` itself.
 */
export function ensureShimFreshnessDecision(
  shimOut: string,
  sources: ReadonlyArray<string>,
): 'accept' | 'reject' {
  return shimArtifactIsStale(shimOut, sources) ? 'reject' : 'accept';
}

// ---------------------------------------------------------------------------
// Step 4 — Docker build
// ---------------------------------------------------------------------------

function dockerBuild(input: BuildInput): void {
  const tag = dockerTag(input);
  const dockerfile = join(REPO_ROOT, 'src', 'rootfs', 'Dockerfile.base');
  const arch = input.arch ?? 'x64';

  // arm64 uses `docker buildx build --platform=linux/arm64` (qemu on x86_64
  // hosts; native on arm64).  x64 keeps the plain `docker build` path so the
  // existing CI runners (which may not have buildx pre-configured) keep
  // working unchanged.
  if (arch === 'arm64') {
    run(
      `docker buildx build ` +
      `--platform=${dockerPlatform(arch)} ` +
      `--load ` +
      `--build-arg UBUNTU_MAJOR=${ubuntuMajor(input)} ` +
      `-f "${dockerfile}" ` +
      `-t "${tag}" ` +
      `.`,
    );
  } else {
    run(
      `docker build ` +
      `--build-arg UBUNTU_MAJOR=${ubuntuMajor(input)} ` +
      `-f "${dockerfile}" ` +
      `-t "${tag}" ` +
      `.`,
    );
  }
  console.log(`[rootfs] Built docker image: ${tag} (arch=${arch})`);
}

// ---------------------------------------------------------------------------
// Step 5+6 — Export container → ext4
// ---------------------------------------------------------------------------

/** On Linux, use native mkfs.ext4 (from e2fsprogs). */
function makeExt4Native(exportDir: string, outImage: string): void {
  // We size at 512 MB to give headroom; the Firecracker VM never writes much.
  run(
    `mkfs.ext4 -d "${exportDir}" ` +
    `-L rootfs -O ^has_journal ` +
    `-m 0 ` +
    `"${outImage}" ` +
    `512M`,
  );
}

/** On macOS (no native mkfs.ext4), use an Alpine container to create the image. */
function makeExt4ViaDocker(exportDir: string, outImage: string): void {
  const outDir = dirname(outImage);
  const imageName = 'rootfs.ext4';
  // Mount exportDir as /work (source) and outDir as /out (destination).
  run(
    `docker run --rm ` +
    `-v "${exportDir}:/work:ro" ` +
    `-v "${outDir}:/out" ` +
    `alpine:latest ` +
    `sh -c ` +
    `"apk add --no-cache e2fsprogs && ` +
    ` mkfs.ext4 -d /work -L rootfs -O ^has_journal -m 0 /out/${imageName} 512M"`,
  );
  // The container writes rootfs.ext4 into outDir; rename to the expected filename.
  const tmpOut = join(outDir, imageName);
  if (tmpOut !== outImage) {
    // Rename the file to the expected target path.
    execSync(`mv "${tmpOut}" "${outImage}"`);
  }
}

function exportAndConvert(input: BuildInput): void {
  const tag = dockerTag(input);
  const outImage = imageOutputPath(input);
  mkdirSync(dirname(outImage), { recursive: true });

  // Create a temp directory to hold the exported filesystem tree.
  const tmpBase = tmpdir();
  const tmpDir = join(tmpBase, `script-jail-rootfs-${randomBytes(6).toString('hex')}`);
  mkdirSync(tmpDir, { recursive: true });

  try {
    // Create a container (not running) so we can export its filesystem.
    const containerId = runCapture(`docker create "${tag}"`);
    console.log(`[rootfs] Created container ${containerId.slice(0, 12)} for export`);

    try {
      // Export container filesystem as a tar stream and extract it.
      run(`docker export "${containerId}" | tar -x -C "${tmpDir}"`);
      console.log(`[rootfs] Exported filesystem to ${tmpDir}`);
    } finally {
      // Always remove the temporary container.
      try { execSync(`docker rm "${containerId}"`, { stdio: 'ignore' }); } catch { /* ignore */ }
    }

    // Verify we got something.
    const exported = readdirSync(tmpDir);
    if (exported.length === 0) {
      throw new Error(`[rootfs] docker export produced an empty directory: ${tmpDir}`);
    }

    // Convert to ext4.
    if (isLinux()) {
      console.log(`[rootfs] Creating ext4 image (native mkfs.ext4) …`);
      makeExt4Native(tmpDir, outImage);
    } else {
      console.log(`[rootfs] Creating ext4 image (via Alpine docker helper) …`);
      makeExt4ViaDocker(tmpDir, outImage);
    }
  } finally {
    // Clean up the temp directory.
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  console.log(`[rootfs] Wrote: ${outImage}`);
}

// ---------------------------------------------------------------------------
// Step 7 — Size check
// ---------------------------------------------------------------------------

function reportSize(input: BuildInput): void {
  const outImage = imageOutputPath(input);
  if (!existsSync(outImage)) return;

  const { size } = statSync(outImage);
  const formatted = formatBytes(size);

  if (size > SIZE_WARN_THRESHOLD_BYTES) {
    console.warn(
      `[rootfs] WARNING: ${imageFilename(input)} is ${formatted}, ` +
      `which exceeds the 200 MB target. Consider stripping more content from the image.`,
    );
  } else {
    console.log(`[rootfs] Image size: ${formatted} ✓`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function buildRootfs(input: BuildInput): Promise<void> {
  console.log(
    `[rootfs] Building rootfs for ${input.runnerImage} → ${imageFilename(input)}`,
  );

  if (!commandExists('docker')) {
    throw new Error(
      '[rootfs] docker is not available. ' +
      'Install Docker Desktop (macOS) or docker-ce (Linux) before running the rootfs build.',
    );
  }

  // Step 1: bundle agent
  bundleAgent();

  // Step 2: copy preloads
  copyPreloads();

  // Step 3: ensure shim
  const shimOk = ensureShim(input);

  if (!shimOk) {
    // On macOS without the .so we cannot build the docker image because the
    // Dockerfile COPY would fail. Emit a clear warning and return.
    console.warn(
      '[rootfs] Skipping docker build and ext4 conversion (libscriptjail.so not available on macOS).',
    );
    return;
  }

  // Step 4: docker build
  dockerBuild(input);

  // Steps 5+6: export + convert to ext4
  exportAndConvert(input);

  // Step 7: report size
  reportSize(input);

  console.log(`[rootfs] Done.`);
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

// This file may also be imported as a module by scripts/build.ts.
// When run directly (via oxnode src/rootfs/build.ts), build with defaults.
//
// Use an exact resolved-path comparison against import.meta.url so that
// importing this module from scripts/build.ts does NOT trigger a build:
// both files end in "build.ts", but only one of them IS this file.
const isMain =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === __filename;

if (isMain) {
  // CLI: `oxnode src/rootfs/build.ts [--runner-image=ubuntu-22.04|ubuntu-24.04] [--arch=x64|arm64]`
  const cliArgs = process.argv.slice(2);
  const runnerImage = parseRunnerImageArg(cliArgs) ?? 'ubuntu-24.04';
  const arch = parseArchArg(cliArgs) ?? 'x64';
  const defaultInput: BuildInput = {
    runnerImage,
    outputDir: join(REPO_ROOT, 'images'),
    arch,
  };

  buildRootfs(defaultInput).catch((err: unknown) => {
    console.error(String(err instanceof Error ? err.stack ?? err.message : err));
    process.exit(1);
  });
}

/**
 * Parse `--runner-image=ubuntu-22.04|ubuntu-24.04` from argv.  Returns
 * `undefined` when the flag is absent so callers can apply their own default.
 * Throws on an unknown value so the user sees a clear error rather than
 * silently getting the default.
 */
export function parseRunnerImageArg(args: ReadonlyArray<string>): RunnerImage | undefined {
  for (const arg of args) {
    const m = /^--runner-image=(.+)$/.exec(arg);
    if (m === null) continue;
    const value = m[1];
    if (value === 'ubuntu-22.04' || value === 'ubuntu-24.04') return value;
    throw new Error(
      `[rootfs] Unknown --runner-image value: ${String(value)}. ` +
      `Expected one of: ubuntu-22.04, ubuntu-24.04.`,
    );
  }
  return undefined;
}

/**
 * Parse `--arch=x64|arm64` (or `--arch x64`) from argv.  Returns `undefined`
 * when the flag is absent so callers can apply their own default.  Throws
 * on an unknown value.  Used by both `scripts/build.ts` and the direct CLI
 * entrypoint below so the same syntax works in both places.
 */
export function parseArchArg(args: ReadonlyArray<string>): BuildArch | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    const m = /^--arch=(.+)$/.exec(arg);
    let value: string | undefined;
    if (m !== null) {
      value = m[1];
    } else if (arg === '--arch') {
      value = args[i + 1];
    } else {
      continue;
    }
    if (value === 'x64' || value === 'arm64') return value;
    throw new Error(
      `[rootfs] Unknown --arch value: ${String(value)}. ` +
      `Expected one of: x64, arm64.`,
    );
  }
  return undefined;
}

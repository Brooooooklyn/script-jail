// script-jail — src/rootfs/build.ts
// Orchestrates building the Linux guest rootfs ext4 image.
//
// The rootfs is keyed by Ubuntu major (`ubuntu-22.04`, `ubuntu-24.04`) and
// arch.  It bakes the standalone `vp` (vite-plus) binary; the guest's
// init.sh runs `vp env install <pinned NODE_VERSION>` during Phase A to
// download a real Linux Node toolchain (see src/rootfs/Dockerfile.base and
// src/rootfs/vite-plus.ts).  There is no host-node virtio drive.
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
  writeFileSync,
} from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';

import { shimArtifactIsStale, shimSourceInputs } from './shim-freshness.js';
import {
  NODE_VERSION,
  VITE_PLUS_SHA256,
  VITE_PLUS_VERSION,
} from './vite-plus.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported runner images.  Must stay in sync with `src/action/runner-image.ts`. */
export type RunnerImage = 'ubuntu-22.04' | 'ubuntu-24.04';

/**
 * Target architecture for the rootfs ext4.
 *
 *   - 'x64'    → x86_64 image, native on Linux x64, docker-buildx-linux/amd64 on macOS.
 *   - 'arm64'  → aarch64 image, native on arm64 Linux, docker-buildx-linux/arm64
 *                with qemu emulation on x86_64 hosts.
 */
export type BuildArch = 'x64' | 'arm64';

export interface BuildInput {
  runnerImage: RunnerImage;
  /** Directory where images/*.ext4 are written. Defaults to <repo root>/images */
  outputDir: string;
  /**
   * Target arch for the rootfs. Defaults to 'x64' for compatibility;
   * release and parity callers pass the desired value explicitly.
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
 * via qemu emulation.
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

// ---------------------------------------------------------------------------
// Digest-pinned base images (R1: byte-reproducible rootfs)
// ---------------------------------------------------------------------------
//
// Pinning the Ubuntu base to a PER-ARCH image digest (not the manifest-list
// tag) makes `docker build`/`buildx --platform` resolve to the exact same
// layers across builds, which is a precondition for a byte-stable ext4.  A
// bare `ubuntu:24.04` tag would silently float to a new daily rebuild.
//
// Refresh after a base bump with:
//   docker buildx imagetools inspect ubuntu:24.04 --raw
// and copy the per-`linux/<arch>` manifest digest below (NOT the index/list
// digest, NOT the attestation manifest).  `BuildArch` x64↔amd64 / arm64↔arm64.
//
// These were resolved 2026-06-01 from Docker Hub (real, not placeholder).

/** Per-arch, digest-pinned `ubuntu@sha256:…` refs threaded as UBUNTU_REF. */
export const UBUNTU_BASE_DIGEST: Record<RunnerImage, Record<BuildArch, string>> = {
  'ubuntu-22.04': {
    x64: 'ubuntu@sha256:ce941a2a18bbb922e434d6d6d2b31e571a5c3826eaf6ada0a41dcc905bd2d906',
    arm64: 'ubuntu@sha256:c1fc012913af7a4dd0d86553d9dae19b323e7fb60d5407e800cbfbc8f7e6aa63',
  },
  'ubuntu-24.04': {
    x64: 'ubuntu@sha256:cdb5fd928fced577cfecf12c8966e830fcdf42ee481fb0b91904eeddc2fe5eff',
    arm64: 'ubuntu@sha256:7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05',
  },
};

/**
 * Digest-pinned Alpine helper image used by the macOS ext4 conversion path
 * (makeExt4ViaDocker).  This is the multi-arch index digest so the local host
 * arch resolves correctly; the helper only runs on the best-effort macOS path,
 * so an index pin (vs per-arch) is sufficient here.
 *
 * Refresh with: docker buildx imagetools inspect alpine:latest
 */
export const ALPINE_HELPER_REF =
  'alpine@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11';

/**
 * Build the shared `--build-arg …` string consumed by BOTH docker build paths
 * (plain `docker build` x64 and `docker buildx build` arm64).  Threads the
 * pinned per-arch `UBUNTU_REF` (so the byte-stable base is inherited
 * everywhere) while RETAINING `UBUNTU_MAJOR` (still consumed by the
 * Dockerfile's apt-mirror sed logic).  Pure; unit-tested.
 *
 * Returns a string with a trailing space so it concatenates cleanly into the
 * existing command builders in `dockerBuild`.
 */
export function buildDockerBuildArgs(input: BuildInput): string {
  const arch = input.arch ?? 'x64';
  return (
    `--build-arg UBUNTU_REF=${UBUNTU_BASE_DIGEST[input.runnerImage][arch]} ` +
    `--build-arg UBUNTU_MAJOR=${ubuntuMajor(input)} ` +
    `--build-arg VP_VERSION=${VITE_PLUS_VERSION} ` +
    `--build-arg VP_ARCH=${arch} ` +
    `--build-arg VP_SHA256=${VITE_PLUS_SHA256[arch]} ` +
    `--build-arg NODE_VERSION=${NODE_VERSION} `
  );
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

/** ELF e_machine values we recognise. */
export const EM_X86_64 = 62;
export const EM_AARCH64 = 183;

/** Map a runner image to the ELF e_machine value expected for that rootfs. */
export function expectedShimMachine(input: Pick<BuildInput, 'runnerImage' | 'arch'>): number {
  // x64 is the default arch for compatibility; arm64 validates
  // `libscriptjail-arm64.so`.
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

/**
 * Wrap `s` in POSIX single quotes so it survives intact through an outer shell
 * (e.g. the host `/bin/sh -c` that `run()`/execSync uses) and reaches an inner
 * `sh -c` verbatim — no `$`, backtick, or `"` expansion.  The only character
 * that cannot appear literally inside single quotes is `'` itself, which is
 * emitted as the standard `'\''` (close-quote, escaped quote, re-open).  Pure;
 * unit-tested.
 */
export function singleQuoteForSh(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
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

  // Shared build args: digest-pinned UBUNTU_REF + UBUNTU_MAJOR (apt-mirror sed)
  // + the vite-plus toolchain args.  `VP_ARCH` matches our BuildArch values
  // (`x64` / `arm64`) one-to-one — the vp npm package name embeds the same
  // tokens.  The SHA-256 is pinned per-arch so the Dockerfile can verify the
  // download.  See src/rootfs/vite-plus.ts and buildDockerBuildArgs().
  const buildArgs = buildDockerBuildArgs(input);

  // arm64 uses `docker buildx build --platform=linux/arm64` (qemu on x86_64
  // hosts; native on arm64).  x64 keeps the plain `docker build` path so the
  // existing CI runners (which may not have buildx pre-configured) keep
  // working unchanged.
  if (arch === 'arm64') {
    run(
      `docker buildx build ` +
      `--platform=${dockerPlatform(arch)} ` +
      `--load ` +
      buildArgs +
      `-f "${dockerfile}" ` +
      `-t "${tag}" ` +
      `.`,
    );
  } else {
    run(
      `docker build ` +
      buildArgs +
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

/**
 * ext4 size for the rootfs image.  The guest writes the `vp env install`
 * Node toolchain (~200 MB under /opt/vp) plus corepack's package-manager
 * cache at runtime, so the filesystem needs real headroom beyond the
 * baked image content.  The repo's node_modules / pnpm store live on the
 * separate 4 GB repo disk, not here.
 */
export const ROOTFS_SIZE_MB = 1024;

// ---------------------------------------------------------------------------
// Reproducible-ext4 determinism (R1)
// ---------------------------------------------------------------------------
//
// mkfs.ext4 bakes three sources of nondeterminism into the image: the
// filesystem UUID (random by default), the directory-hash seed (also random),
// and wall-clock timestamps (superblock create/write, and every inode's
// atime/ctime/mtime/crtime).  The UUID and hash-seed are pinned via mkfs argv
// (`-U` / `-E hash_seed`); the UUID is the ASCII bytes of "SJ-jail-root..."
// laid out as a UUID — recognisable in `tune2fs -l` and impossible to collide
// with a real random UUID by accident.
//
// SOURCE_DATE_EPOCH is set too, BUT it is NOT sufficient on the build runner:
// it is only honoured by e2fsprogs >= 1.47.1, and the build runners ship older
// e2fsprogs (ubuntu-24.04 → 1.47.0, ubuntu-22.04 → 1.46.5).  With 1.47.0 /
// 1.46.5, mkfs.ext4 STILL writes wall-clock build time into the superblock
// (Filesystem created / Last write), into the reserved inodes (root=2,
// lost+found=11, …), and into the crtime/ctime of every `-d`-populated file —
// so two rebuilds seconds apart diverge.  We therefore run a deterministic
// `debugfs -w` POST-PASS (pinExt4TimestampsViaDebugfs) that rewrites the
// superblock time fields and every inode's atime/ctime/mtime/crtime to the
// fixed epoch.  debugfs is checksum-aware, so rewriting inodes also re-stamps
// the (now-deterministic) metadata_csum.  SOURCE_DATE_EPOCH is kept so that a
// future runner with e2fsprogs >= 1.47.1 produces the same bytes WITHOUT the
// post-pass having anything left to change (the post-pass stays a no-op-by-
// value belt-and-suspenders, not a correctness dependency).
//
// All of this is load-bearing for the v0.1.1 manifest backfill, which must
// reproduce v0.1.0's released SHAs.  The two-run byte-identity guard lives in
// CI (test/integration/rootfs-reproducibility.test.ts and the
// "Assert x64 rootfs ext4s are byte-reproducible" step in release.yml) — it
// cannot be exercised on macOS, which has no native mkfs.ext4 / debugfs.

/** Fixed filesystem UUID for the rootfs ext4 (byte-reproducibility). */
export const ROOTFS_FIXED_UUID = '5343524a-2d6a-6169-6c2d-726f6f746673';

/** Fixed SOURCE_DATE_EPOCH (seconds) for ext4 timestamps + mtime normalize. */
export const ROOTFS_SOURCE_DATE_EPOCH = 1700000000;

/**
 * Build the `mkfs.ext4` argv for the rootfs image.  Pure; unit-tested.
 *
 * `-U`/`-E hash_seed` pin the two random sources; `-d`/`-L`/`-m` are the
 * pre-existing populate/label/no-reserve flags.  The two positionals
 * (`<outImage>`, `<sizeMB>M`) come last, as mke2fs requires.
 *
 * Geometry/feature flags pin the on-disk layout so it does NOT depend on the
 * host's e2fsprogs-version defaults (R1 byte-reproducibility):
 *   - `-b 4096`  fixed block size (else mke2fs heuristically picks 1k/4k by size)
 *   - `-I 256`   fixed inode size (default has varied across e2fsprogs versions)
 *   - `-i 16384` fixed bytes-per-inode (inode COUNT).  Pinned on argv — NOT left
 *     to the conf — because mke2fs resolves inode_ratio from a size-class
 *     `[fs_types]` entry (small/default/big/huge) selected by image size, and the
 *     checked-in mke2fs.conf intentionally omits those size classes.  Without an
 *     argv `-i`, the effective ratio falls back to a path that differs across
 *     e2fsprogs versions, so a runner-image e2fsprogs bump between the v0.1.0 and
 *     v0.1.1 builds could change the inode count and break the SHA backfill.  The
 *     value matches the conf's `inode_ratio` (belt-and-suspenders).
 *   - `-O ^has_journal,^metadata_csum_seed`  no journal AND no independent
 *     metadata-checksum seed.  Disabling metadata_csum_seed makes the metadata
 *     checksum seed derive from the pinned `-U` UUID instead of an independent
 *     random seed — the classic remaining ext4 nondeterminism.
 *
 * The `MKE2FS_CONFIG` env (see mkfsEnv) pins the rest of the feature set; these
 * argv flags pin the size-dependent geometry that the conf cannot express.
 */
export function buildMkfsExt4Args(
  exportDir: string,
  outImage: string,
  sizeMB: number,
): string[] {
  return [
    '-b', '4096',
    '-I', '256',
    '-i', '16384',
    '-d', exportDir,
    '-L', 'rootfs',
    '-O', '^has_journal,^metadata_csum_seed',
    '-m', '0',
    '-U', ROOTFS_FIXED_UUID,
    '-E', `hash_seed=${ROOTFS_FIXED_UUID}`,
    outImage,
    `${sizeMB}M`,
  ];
}

/**
 * Absolute path to the checked-in `mke2fs.conf` (lives next to this module in
 * `src/rootfs/`).  Resolved via `__dirname` (derived from
 * `fileURLToPath(import.meta.url)` above) so it works under `oxnode` running
 * the source directly.  `build.ts` is build-time-only and is never folded into
 * the action bundle, so `__dirname` is reliably `src/rootfs/`.
 */
export const ROOTFS_MKE2FS_CONFIG_PATH = join(__dirname, 'mke2fs.conf');

/**
 * Container-side path the checked-in `mke2fs.conf` is bind-mounted to (see
 * makeExt4ViaDocker), exported as `MKE2FS_CONFIG` in the helper script so the
 * Alpine path pins the same feature set as the native path instead of reading
 * Alpine's stock `/etc/mke2fs.conf`.
 */
const DOCKER_MKE2FS_CONFIG_PATH = '/etc/script-jail/mke2fs.conf';

/**
 * Env overlay merged onto `process.env` when spawning `mkfs.ext4`.  Exported
 * for unit assertion; in production it is spread into the spawn env.
 *
 * `MKE2FS_CONFIG` points mke2fs at the checked-in conf instead of the host's
 * `/etc/mke2fs.conf`, so the [defaults]/[fs_types] feature set + sizes are
 * pinned and do NOT inherit the runner host's config (R1 byte-reproducibility).
 * `SOURCE_DATE_EPOCH` clamps inode/superblock timestamps.
 */
export function mkfsEnv(): { SOURCE_DATE_EPOCH: string; MKE2FS_CONFIG: string } {
  return {
    SOURCE_DATE_EPOCH: String(ROOTFS_SOURCE_DATE_EPOCH),
    MKE2FS_CONFIG: ROOTFS_MKE2FS_CONFIG_PATH,
  };
}

/**
 * argv to normalize every file/dir/symlink mtime under `dir` to `epoch`.
 * `touch --no-dereference` stamps symlinks themselves (not their targets);
 * `-exec ... +` batches into few touch invocations.  Pure; unit-tested.
 */
export function buildNormalizeMtimesArgv(dir: string, epoch: number): string[] {
  return [
    'find', dir,
    '-exec', 'touch', '--no-dereference', `--date=@${epoch}`, '{}', '+',
  ];
}

// ---------------------------------------------------------------------------
// Export-tree content sanitization (R1 — drop build-time-volatile CONTENT)
// ---------------------------------------------------------------------------
//
// mtime normalization fixes timestamps, but it does NOTHING for build-time-
// volatile FILE CONTENT that `docker export` bakes into the tree:
//
//   - /etc/hostname        — the random per-build container ID
//   - /etc/hosts           — carries that container ID + its assigned IP
//   - /etc/resolv.conf     — the build host's resolver(s)
//   - /etc/machine-id      — a random per-build machine id
//   - /var/log/dpkg.log,
//     /var/log/alternatives.log,
//     /var/log/apt/*,
//     /var/log/bootstrap.log — embed wall-clock timestamps AS CONTENT
//
// Docker REGENERATES the /etc trio at `docker create` time, so even though the
// Dockerfile cleanup RUN removes/zeroes them in the image layer they reappear
// in the exported container.  We therefore canonicalize/remove them in the
// EXPORTED TREE (the bytes that actually feed mkfs.ext4), which is the only
// place guaranteed to win.  Canonicalizing the /etc trio to empty is safe: the
// guest's init.sh rewrites /etc/resolv.conf unconditionally at boot, and
// /etc/hostname + /etc/hosts are not read by init/orchestrate.

/**
 * Relative paths under the export root whose CONTENT is build-time-volatile.
 * `truncate` entries are zeroed (kept as empty files so anything that opens
 * them still finds a file); `remove` entries are deleted outright.  Pure;
 * unit-tested.  The Alpine helper script mirrors this exact list.
 */
export const EXPORT_TREE_VOLATILE_CONTENT: {
  truncate: ReadonlyArray<string>;
  remove: ReadonlyArray<string>;
} = {
  truncate: ['etc/hostname', 'etc/hosts', 'etc/resolv.conf', 'etc/machine-id'],
  remove: [
    'var/log/dpkg.log',
    'var/log/alternatives.log',
    'var/log/bootstrap.log',
    'var/log/apt',
  ],
};

/**
 * Canonicalize the export tree in place: zero the volatile /etc files and
 * delete the timestamped logs.  Only touches paths that exist (a future base
 * image that drops one of these must not make the build fail).  `var/log/apt`
 * is a directory, so it is removed recursively.
 */
function sanitizeExportTree(exportDir: string): void {
  for (const rel of EXPORT_TREE_VOLATILE_CONTENT.truncate) {
    const p = join(exportDir, rel);
    if (existsSync(p)) writeFileSync(p, '');
  }
  for (const rel of EXPORT_TREE_VOLATILE_CONTENT.remove) {
    const p = join(exportDir, rel);
    if (existsSync(p)) rmSync(p, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// debugfs timestamp post-pass (R1 — works around e2fsprogs < 1.47.1)
// ---------------------------------------------------------------------------
//
// See the determinism comment block above for WHY this is needed.  These pure
// helpers build the `debugfs -w` command stream that pins every wall-clock
// timestamp to the fixed epoch.  debugfs time values use the `@<seconds>` form
// (decimal seconds since the Unix epoch); inodes are referenced as `<N>`.

/**
 * debugfs commands that pin the SUPERBLOCK time fields to `epoch`.  Returns a
 * newline-joined string (no trailing newline) suitable for a `debugfs -f`
 * command file.  Pure; unit-tested.
 *
 * `wtime` (last-write time) is set LAST so debugfs persists the pinned value
 * rather than a wall-clock write time when it flushes the superblock on close.
 */
export function buildDebugfsSuperblockTimeCommands(epoch: number): string {
  return [
    `ssv mkfs_time @${epoch}`,
    `ssv lastcheck @${epoch}`,
    `ssv wtime @${epoch}`,
  ].join('\n');
}

/**
 * debugfs commands that pin all four time fields of a single inode to `epoch`.
 * `set_inode_field` (`sif`) takes one field per command, so we emit four.
 * Returns a newline-joined string (no trailing newline).  Pure; unit-tested.
 */
export function buildDebugfsInodeTimeCommands(inode: number, epoch: number): string {
  return [
    `sif <${inode}> atime @${epoch}`,
    `sif <${inode}> ctime @${epoch}`,
    `sif <${inode}> mtime @${epoch}`,
    `sif <${inode}> crtime @${epoch}`,
  ].join('\n');
}

/**
 * Full debugfs `-f` command stream that pins the superblock AND every inode
 * (1..inodeCount inclusive) to `epoch`.  Pure; unit-tested.  The native path
 * (pinExt4TimestampsViaDebugfs) computes `inodeCount` from the image's
 * superblock and feeds it here; the Alpine path mirrors this with an in-shell
 * `seq` loop so it does not have to ship a multi-thousand-line literal.
 */
export function buildDebugfsTimeScript(epoch: number, inodeCount: number): string {
  const lines: string[] = [buildDebugfsSuperblockTimeCommands(epoch)];
  for (let inode = 1; inode <= inodeCount; inode++) {
    lines.push(buildDebugfsInodeTimeCommands(inode, epoch));
  }
  // Trailing `quit` is implicit (EOF), but an explicit one keeps the intent
  // obvious when the command file is dumped for debugging.
  lines.push('quit');
  return lines.join('\n');
}

/**
 * Read the total inode count out of an ext4 image's superblock via
 * `dumpe2fs -h`.  Throws on parse failure (a missing count would silently skip
 * the timestamp sweep and reintroduce the nondeterminism this guards against).
 */
function readExt4InodeCount(outImage: string): number {
  const result = spawnSync('dumpe2fs', ['-h', outImage], {
    encoding: 'utf8',
    env: { ...process.env, ...mkfsEnv() },
  });
  if (result.status !== 0) {
    throw new Error(
      `dumpe2fs -h failed for ${outImage} (exit ${result.status ?? 'unknown'}, ` +
      `signal ${result.signal ?? 'none'})`,
    );
  }
  const m = /^Inode count:\s*(\d+)\s*$/m.exec(result.stdout);
  if (m === null) {
    throw new Error(`could not parse "Inode count:" from dumpe2fs -h ${outImage}`);
  }
  return Number(m[1]);
}

/**
 * Deterministic timestamp post-pass for the native (Linux) path.  Computes the
 * image's inode count, then runs a single `debugfs -w -f <cmdfile>` that pins
 * the superblock + every inode's times to the fixed epoch.  A nonzero status
 * is FATAL — a partially-applied sweep would leave wall-clock bytes behind and
 * break reproducibility silently.
 */
function pinExt4TimestampsViaDebugfs(outImage: string): void {
  const inodeCount = readExt4InodeCount(outImage);
  const script = buildDebugfsTimeScript(ROOTFS_SOURCE_DATE_EPOCH, inodeCount);

  const cmdFile = join(
    tmpdir(),
    `script-jail-debugfs-${randomBytes(6).toString('hex')}.cmd`,
  );
  try {
    writeFileSync(cmdFile, script);
    const result = spawnSync('debugfs', ['-w', '-f', cmdFile, outImage], {
      stdio: 'inherit',
      env: { ...process.env, ...mkfsEnv() },
    });
    if (result.status !== 0) {
      throw new Error(
        `debugfs timestamp post-pass failed for ${outImage} ` +
        `(exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
      );
    }
  } finally {
    try { rmSync(cmdFile, { force: true }); } catch { /* ignore */ }
  }
}

/** On Linux, use native mkfs.ext4 (from e2fsprogs), then pin timestamps. */
function makeExt4Native(exportDir: string, outImage: string): void {
  runMkfs(buildMkfsExt4Args(exportDir, outImage, ROOTFS_SIZE_MB));
  pinExt4TimestampsViaDebugfs(outImage);
}

/**
 * Conversion seam (Linux only): normalize the export tree's mtimes to the
 * fixed epoch, then run native `mkfs.ext4` with the pinned UUID/hash-seed.
 * Exported so the reproducibility integration test can build the docker image
 * ONCE and run this twice over the same exported tree, comparing SHAs — which
 * isolates mkfs+normalize determinism from the (non-deterministic) docker
 * build/export cost.  Production callers go through `exportAndConvert`.
 */
export function convertExportTreeToExt4(exportDir: string, outImage: string): void {
  // Order matters: drop build-time-volatile CONTENT first (this rewrites
  // mtimes on the truncated files), THEN normalize every mtime to the fixed
  // epoch, THEN mkfs + the debugfs timestamp post-pass.
  sanitizeExportTree(exportDir);
  normalizeMtimes(exportDir);
  makeExt4Native(exportDir, outImage);
}

/**
 * Spawn `mkfs.ext4 <args>` with `SOURCE_DATE_EPOCH` set, mirroring the argv
 * form + explicit nonzero-status throw used by the Firecracker overlay builder
 * (src/action/firecracker/overlay.ts).  Using spawnSync (not the shell `run`)
 * avoids quoting the export-dir path and keeps the determinism env scoped.
 */
function runMkfs(args: ReadonlyArray<string>): void {
  const result = spawnSync('mkfs.ext4', [...args], {
    stdio: 'inherit',
    env: { ...process.env, ...mkfsEnv() },
  });
  if (result.status !== 0) {
    throw new Error(
      `mkfs.ext4 failed (exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
    );
  }
}

/**
 * Normalize all mtimes under `dir` to the fixed epoch.  Touch failures are
 * FATAL (a stray un-normalized mtime would silently break reproducibility),
 * so a nonzero status throws rather than being swallowed.
 */
function normalizeMtimes(dir: string): void {
  const argv = buildNormalizeMtimesArgv(dir, ROOTFS_SOURCE_DATE_EPOCH);
  const result = spawnSync(argv[0]!, argv.slice(1), { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(
      `mtime normalize (find/touch) failed (exit ${result.status ?? 'unknown'}, ` +
      `signal ${result.signal ?? 'none'}) for ${dir}`,
    );
  }
}

/**
 * On macOS (no native mkfs.ext4), build the ext4 inside an Alpine container.
 *
 * The `docker export` tar is piped STRAIGHT into the Alpine container, which
 * extracts it and runs `mkfs.ext4` entirely on the Linux side.  An earlier
 * version extracted to a macOS temp dir and bind-mounted it `:ro`, but
 * `mkfs.ext4 -d` calls `llistxattr` on every symlink and OrbStack's virtiofs
 * returns ENOENT for that on symlinks — aborting the populate with
 * `set_inode_xattr: No such file or directory`.  Keeping the source tree on
 * the container's own overlayfs avoids virtiofs entirely; only `/out` (the
 * destination image) stays a macOS bind mount, and it is write-only.
 */
function makeExt4ViaDocker(containerId: string, outImage: string): void {
  const outDir = dirname(outImage);
  const imageName = 'rootfs.ext4';
  // The helper script is a real POSIX sh program containing shell variables
  // (`$i`, `$cmd`, …), command substitution, and double quotes — all of which
  // the OUTER host `/bin/sh -c` (run() → execSync) would otherwise expand
  // BEFORE handing the line to docker.  Single-quote the whole script for the
  // host so it reaches the container's `sh -c` verbatim; the only character
  // that needs escaping inside POSIX single quotes is `'` itself (`'\''`).
  const script = singleQuoteForSh(buildMkfsExt4ViaDockerScript(imageName, ROOTFS_SIZE_MB));
  // Mount the checked-in mke2fs.conf into the container `:ro` so the Alpine
  // helper's mkfs.ext4 pins the same feature set as the native path (the
  // helper script exports MKE2FS_CONFIG=<this path>).
  run(
    `docker export "${containerId}" | ` +
    `docker run --rm -i -v "${outDir}:/out" ` +
    `-v "${ROOTFS_MKE2FS_CONFIG_PATH}:${DOCKER_MKE2FS_CONFIG_PATH}:ro" ` +
    `${ALPINE_HELPER_REF} sh -c ${script}`,
  );
  // The container writes rootfs.ext4 into outDir; rename to the expected filename.
  const tmpOut = join(outDir, imageName);
  if (tmpOut !== outImage) {
    execSync(`mv "${tmpOut}" "${outImage}"`);
  }
}

/**
 * The Alpine-helper shell script: extract the piped export tar, normalize
 * mtimes, `mkfs.ext4` with the SAME UUID/hash-seed/SOURCE_DATE_EPOCH AND
 * MKE2FS_CONFIG as the native Linux path, then run the SAME deterministic
 * debugfs timestamp post-pass (mirrors pinExt4TimestampsViaDebugfs).  Pure;
 * unit-tested.  This best-effort macOS path mirrors the determinism flags so a
 * mac-built image matches the native one; the authoritative released SHA still
 * comes from the native Linux build.
 *
 * The post-pass reads the image's inode count from `dumpe2fs -h`, then writes a
 * debugfs command file: the fixed superblock commands followed by one inode's
 * commands per inode (1..count) via a `seq` loop, mirroring
 * `buildDebugfsTimeScript`.  We loop in-shell rather than embedding a
 * multi-thousand-line literal so the script stays compact.
 *
 * `MKE2FS_CONFIG` points at the bind-mounted conf (makeExt4ViaDocker mounts the
 * checked-in src/rootfs/mke2fs.conf to that path `:ro`).
 *
 * Embedded inside a double-quoted `sh -c "..."` (see makeExt4ViaDocker), so it
 * must contain no unescaped double quotes — single quotes only.
 */
export function buildMkfsExt4ViaDockerScript(imageName: string, sizeMB: number): string {
  const outImage = `/out/${imageName}`;
  // mkfs argv with /rootfs as the populate dir and /out/<image> as the target.
  const mkfsArgs = buildMkfsExt4Args('/rootfs', outImage, sizeMB).join(' ');
  const normalize = buildNormalizeMtimesArgv('/rootfs', ROOTFS_SOURCE_DATE_EPOCH).join(' ');
  const epoch = ROOTFS_SOURCE_DATE_EPOCH;
  // Drop build-time-volatile CONTENT before the normalize (mirrors
  // sanitizeExportTree on the native path): zero the Docker-injected /etc files
  // and delete the timestamped logs.  Generated from EXPORT_TREE_VOLATILE_CONTENT
  // so the two paths cannot drift.  Each truncate is guarded on existence (so a
  // missing file is NOT created, matching the native existsSync gate); `rm -rf`
  // is a no-op when the log is absent.
  const sanitize = [
    ...EXPORT_TREE_VOLATILE_CONTENT.truncate.map(
      (rel) => `if [ -e /rootfs/${rel} ]; then : > /rootfs/${rel}; fi`,
    ),
    ...EXPORT_TREE_VOLATILE_CONTENT.remove.map((rel) => `rm -rf /rootfs/${rel}`),
  ].join('; ');
  // Superblock commands (fixed; printed verbatim into the debugfs command file).
  // Each becomes one `printf '%s\n'` argument so the lines survive intact.
  const superblockArgs = buildDebugfsSuperblockTimeCommands(epoch)
    .split('\n')
    .map((line) => `'${line}'`)
    .join(' ');
  // Per-inode commands: four `sif <%s> <field> @epoch` lines fed the loop
  // counter via printf's `%s` (NOT shell-expanded `$i`, which single quotes
  // would suppress).  Mirrors buildDebugfsInodeTimeCommands.
  const inodeFmt =
    `sif <%s> atime @${epoch}\\n` +
    `sif <%s> ctime @${epoch}\\n` +
    `sif <%s> mtime @${epoch}\\n` +
    `sif <%s> crtime @${epoch}\\n`;
  // Build the debugfs command file, then apply it in one `debugfs -w` pass.
  // The inode count is parsed from dumpe2fs -h with the SAME MKE2FS_CONFIG in
  // scope (the export above stays set for the whole `sh -c`).
  const postPass =
    `ic=$(dumpe2fs -h ${outImage} 2>/dev/null | sed -n 's/^Inode count:[[:space:]]*//p') && ` +
    `cmd=/tmp/sj-debugfs.cmd && ` +
    `printf '%s\\n' ${superblockArgs} > "$cmd" && ` +
    `i=1; while [ "$i" -le "$ic" ]; do ` +
    `printf '${inodeFmt}' "$i" "$i" "$i" "$i" >> "$cmd"; i=$((i+1)); done && ` +
    `printf 'quit\\n' >> "$cmd" && ` +
    `debugfs -w -f "$cmd" ${outImage}`;
  return (
    `apk add --no-cache e2fsprogs tar && ` +
    `mkdir /rootfs && tar -x -C /rootfs && ` +
    `${sanitize} && ` +
    `${normalize} && ` +
    `export MKE2FS_CONFIG=${DOCKER_MKE2FS_CONFIG_PATH} && ` +
    `SOURCE_DATE_EPOCH=${epoch} mkfs.ext4 ${mkfsArgs} && ` +
    `${postPass}`
  );
}

function exportAndConvert(input: BuildInput): void {
  const tag = dockerTag(input);
  const outImage = imageOutputPath(input);
  mkdirSync(dirname(outImage), { recursive: true });

  // Create a container (not running) so we can export its filesystem.
  const containerId = runCapture(`docker create "${tag}"`);
  console.log(`[rootfs] Created container ${containerId.slice(0, 12)} for export`);

  try {
    if (isLinux()) {
      // Native path: extract the export tar to a temp dir, then mkfs.ext4 -d.
      const tmpDir = join(
        tmpdir(),
        `script-jail-rootfs-${randomBytes(6).toString('hex')}`,
      );
      mkdirSync(tmpDir, { recursive: true });
      try {
        run(`docker export "${containerId}" | tar -x -C "${tmpDir}"`);
        const exported = readdirSync(tmpDir);
        if (exported.length === 0) {
          throw new Error(`[rootfs] docker export produced an empty directory: ${tmpDir}`);
        }
        console.log(`[rootfs] Creating ext4 image (native mkfs.ext4) …`);
        convertExportTreeToExt4(tmpDir, outImage);
      } finally {
        try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
      }
    } else {
      // macOS path: pipe the export tar straight into the Alpine helper.
      console.log(`[rootfs] Creating ext4 image (via Alpine docker helper) …`);
      makeExt4ViaDocker(containerId, outImage);
    }
  } finally {
    // Always remove the temporary container.
    try { execSync(`docker rm "${containerId}"`, { stdio: 'ignore' }); } catch { /* ignore */ }
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

// script-jail — src/action/firecracker/download.ts
//
// Downloads the Firecracker binary (from a GitHub release tarball) and a
// precompiled vmlinux kernel image, caches both under `imagesDir`, and
// verifies each against a pinned SHA-256 hash.
//
// Design decisions:
//   - HttpClient is an interface so unit tests can inject a fake without
//     touching the filesystem or network.  Interface + production impl
//     (`NodeHttpClient`) live in `src/shared/http-download.ts` and are
//     re-exported here for back-compat with existing callers.
//   - KNOWN_VERSIONS holds pinned hashes for supported Firecracker releases.
//     Update the map whenever you pin a new release; the CI gate will catch
//     missing entries at plan time.

import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { chmod, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { createGunzip } from 'node:zlib';

import {
  NodeHttpClient,
  sha256File,
  type HttpClient,
} from '../../shared/http-download.js';

// Re-export the generic HTTP surface so existing internal callers (main.ts,
// pre-fetch-artifacts.ts, download.test.ts, pre-fetch-artifacts.test.ts)
// keep working unchanged.  New code that only wants the generic primitives
// should import from `src/shared/http-download.js` directly.
export { NodeHttpClient };
export type { HttpClient };

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface DownloadInput {
  /** Directory where cached binaries are stored (e.g. `<repo>/images`). */
  imagesDir: string;
  /** Host/guest architecture for the Firecracker binary. Defaults to x64. */
  arch?: FirecrackerArch;
  /** Firecracker semver without the leading "v" (e.g. `"1.8.0"`). */
  firecrackerVersion: string;
  /** Full URL for the precompiled vmlinux kernel image. */
  kernelUrl: string;
  /** Pinned SHA-256 for the vmlinux download. */
  kernelSha256: string;
  http: HttpClient;
}

export interface DownloadResult {
  /** Absolute path to the extracted `firecracker` binary. */
  firecrackerPath: string;
  /** Absolute path to the cached vmlinux image. */
  vmlinuxPath: string;
}

export type FirecrackerArch = 'x64' | 'arm64';

type FirecrackerReleaseArch = 'x86_64' | 'aarch64';

// ---------------------------------------------------------------------------
// Pinned hashes
// ---------------------------------------------------------------------------

/**
 * KNOWN_TARBALL_SHA256 maps Firecracker release versions to the SHA-256 of
 * their per-arch release tarball.
 *
 * These are pinned values fetched from the official GitHub release tarballs at:
 *   https://github.com/firecracker-microvm/firecracker/releases/download/v<ver>/firecracker-v<ver>-<arch>.tgz
 *
 * To re-verify or pin a new release, run:
 *
 *   curl -sL <tarball-url> | sha256sum
 *
 * and add the resulting 64-char lowercase hex digest as a new entry.
 */
const KNOWN_X64_VERSIONS: Readonly<Record<string, string>> = {
  '1.8.0': 'bc899bdaef8d0aa7b0fafbf49a2bf647e0298558f4faee44970d87a1c6d1ae2d',
  '1.9.0': '95c13740c7ca1a6dfb40e0f51cd0a9eefee1f223cd2c3538755d03c3a9ba5237',
};

const KNOWN_ARM64_VERSIONS: Readonly<Record<string, string>> = {
  '1.8.0': '64b49ceb53167d7616bf4fd2c73def696a320259ea6e07cf1447c9091c5f9271',
  '1.9.0': 'c5564e76dec2b8e8092c52f0f8a4c5f45cf31791e95a9302f4360a771df78f69',
};

export const KNOWN_TARBALL_SHA256: Readonly<Record<FirecrackerArch, Readonly<Record<string, string>>>> = {
  x64: KNOWN_X64_VERSIONS,
  arm64: KNOWN_ARM64_VERSIONS,
};

/** Back-compat alias for tests/callers that historically meant x86_64. */
export const KNOWN_VERSIONS = KNOWN_X64_VERSIONS;

// ---------------------------------------------------------------------------
// ensureBinaries — main export
// ---------------------------------------------------------------------------

/**
 * Ensures the Firecracker binary and vmlinux are present in `imagesDir`.
 *
 * Cache policy (per file):
 *   1. File exists AND sha256 matches → reuse, skip download.
 *   2. File missing OR sha256 mismatch → (re-)download.
 *
 * Throws if `firecrackerVersion` is not in `KNOWN_VERSIONS`.
 */
export async function ensureBinaries(input: DownloadInput): Promise<DownloadResult> {
  const { imagesDir, firecrackerVersion, kernelUrl, kernelSha256, http } = input;
  const arch: FirecrackerArch = input.arch ?? 'x64';
  const releaseArch = firecrackerReleaseArch(arch);

  const expectedTarSha = KNOWN_TARBALL_SHA256[arch][firecrackerVersion];
  if (expectedTarSha === undefined) {
    throw new Error(
      `script-jail: unknown Firecracker version "${firecrackerVersion}" for ${arch}. ` +
      `Add it (with a pinned SHA-256) to KNOWN_TARBALL_SHA256 in src/action/firecracker/download.ts.`,
    );
  }

  mkdirSync(imagesDir, { recursive: true });

  // --- Download both files in parallel ------------------------------------
  //
  // We fetch the tarball and the vmlinux concurrently.  Extraction of the
  // firecracker binary from the tarball happens after both downloads complete.

  const tarUrl =
    `https://github.com/firecracker-microvm/firecracker/releases/download/` +
    `v${firecrackerVersion}/firecracker-v${firecrackerVersion}-${releaseArch}.tgz`;

  const tarPath = join(imagesDir, `firecracker-v${firecrackerVersion}-${releaseArch}.tgz`);
  const fcBinPath = join(imagesDir, `firecracker-v${firecrackerVersion}`);
  const vmlinuxPath = join(imagesDir, 'vmlinux');

  // Download tarball and vmlinux concurrently (each is idempotent).
  // `ensureFile` returns true when the file was freshly downloaded/replaced.
  const [tarFresh] = await Promise.all([
    ensureFile(http, tarUrl, tarPath, expectedTarSha),
    ensureFile(http, kernelUrl, vmlinuxPath, kernelSha256),
  ]);

  // --- Extract firecracker binary -----------------------------------------
  //
  // Security: always re-extract when the tarball was freshly downloaded to
  // ensure the extracted binary is derived from the verified tarball.  If the
  // tarball was already cached (tarFresh=false) and the binary exists we still
  // re-extract — the binary cannot be verified independently without an
  // additional pinned hash.  Re-extraction is the only safe option.
  //
  // TODO(v2): pin a separate SHA-256 for the extracted binary so a cache hit
  // on both the tarball and the binary can skip the extraction step safely.
  if (existsSync(fcBinPath)) {
    await unlink(fcBinPath);
  }
  void tarFresh; // always re-extract (see comment above)
  await extractFirecrackerBinary(tarPath, fcBinPath, firecrackerVersion, releaseArch);

  return { firecrackerPath: fcBinPath, vmlinuxPath };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Download `url` to `destPath` if missing or hash-stale.
 *
 * Returns `true` when the file was freshly downloaded, `false` when the
 * cached copy was already valid (cache hit).
 */
async function ensureFile(
  http: HttpClient,
  url: string,
  destPath: string,
  expectedSha256: string,
): Promise<boolean> {
  // Skip download if the file is present and the hash matches.
  if (existsSync(destPath)) {
    const actual = await sha256File(destPath);
    if (actual === expectedSha256) return false; // cache hit
    // Hash mismatch — fall through to re-download.
    console.warn(
      `[download] SHA-256 mismatch for cached ${destPath}. ` +
      `Expected ${expectedSha256}, got ${actual}. Re-downloading.`,
    );
  }

  await http.download(url, destPath, expectedSha256);
  return true; // freshly downloaded
}

/**
 * Strictly parse a fixed-width ustar numeric (octal) field.  POSIX shape:
 * optional leading spaces, one or more octal digits, then a terminator that is
 * NUL or space, then ONLY NUL/space padding to the end of the field.  ANY other
 * byte — including garbage AFTER a NUL terminator (e.g. "016020\0X") — makes the
 * field malformed; a strict reader (bsdtar) rejects such an archive, so we
 * return null rather than parse a lenient prefix.  Also rejects GNU base-256
 * encoded values (high-bit-set leading byte is not an octal digit) — the
 * official Firecracker tarball uses plain octal.
 */
function parseOctalField(field: Buffer): number | null {
  let i = 0;
  const n = field.length;
  while (i < n && field[i] === 0x20) i++; // leading spaces
  const start = i;
  while (i < n && field[i]! >= 0x30 && field[i]! <= 0x37) i++; // octal digits
  if (i === start) return null; // no digits
  const digits = field.subarray(start, i).toString('utf8');
  for (; i < n; i++) {
    // Terminator + padding region: only NUL or space permitted.
    if (field[i] !== 0x00 && field[i] !== 0x20) return null;
  }
  const val = parseInt(digits, 8);
  return Number.isFinite(val) && val >= 0 ? val : null;
}

/**
 * Validate a 512-byte ustar header checksum.  The stored checksum (bytes
 * 148..156, octal) must equal the unsigned sum of all header bytes with the
 * checksum field itself counted as ASCII spaces.  This is the canonical "is
 * this a real tar header" gate — a header with random/forged fields fails it,
 * so we verify it before trusting the name/size.  (Standard tar uses the
 * unsigned sum; the historical signed variant is not used by the Firecracker
 * release tarball.)  The field shape is validated strictly via
 * {@link parseOctalField} so a valid-octal-prefix-then-garbage field a
 * compliant reader (e.g. bsdtar) rejects is not silently accepted.
 */
function tarHeaderChecksumValid(header: Buffer): boolean {
  const stored = parseOctalField(header.subarray(148, 156));
  if (stored === null) return false;
  let unsigned = 0;
  for (let i = 0; i < 512; i++) {
    unsigned += i >= 148 && i < 156 ? 0x20 : header[i]!;
  }
  return unsigned === stored;
}

/**
 * Extracts the `firecracker` binary from a `.tgz` tarball.
 *
 * The official Firecracker release tarball contains a single directory
 * `release-v<ver>-<arch>/` with the binary named `firecracker-v<ver>-<arch>`.
 * We extract that binary to `destPath`.
 *
 * NOTE: This helper is intentionally NOT exported — extraction is an internal
 * detail of `ensureBinaries`. Tests exercise it indirectly through that function.
 */
async function extractFirecrackerBinary(
  tarPath: string,
  destPath: string,
  version: string,
  releaseArch: FirecrackerReleaseArch,
): Promise<void> {
  const tmpOut = join(
    tmpdir(),
    `script-jail-fc-${randomBytes(4).toString('hex')}`,
  );

  // Exact documented archive path for the binary inside the official tarball:
  // `release-v<ver>-<arch>/firecracker-v<ver>-<arch>`.  We match the FULL path,
  // not just the basename — a compliant reader extracts the named release-dir
  // entry, never a same-basename file placed at some other (e.g. attacker-chosen)
  // path.  (47 chars — well within the 100-byte ustar name field, no prefix field.)
  const targetEntry = `release-v${version}-${releaseArch}/firecracker-v${version}-${releaseArch}`;

  await new Promise<void>((resolve, reject) => {
    // We manually parse the tar stream to avoid depending on the `tar` package.
    // Firecracker tarballs are small (<10 MB) so reading it all in Node is fine.
    const gunzip = createGunzip();
    const input = createReadStream(tarPath);

    // Simple tar header parser — tar blocks are 512 bytes.
    const BLOCK = 512;
    let buf = Buffer.alloc(0);
    let state: 'header' | 'data' = 'header';
    // `paddedRemaining` tracks bytes left in the padded block region (rounded
    // up to 512-byte boundaries).  `declaredRemaining` tracks bytes left from
    // the actual declared file size.  We only write `declaredRemaining` bytes
    // to avoid appending NUL padding to the extracted executable.
    let paddedRemaining = 0;
    let declaredRemaining = 0;
    let capturing = false;
    let outStream: ReturnType<typeof createWriteStream> | null = null;
    let foundEntry = false;
    let settled = false;
    // Set once the first all-zero (end-of-archive) block is seen.  Subsequent
    // all-zero blocks are record padding; any NON-zero block after this is
    // trailing content a compliant tar reader would never extract → reject.
    let archiveEnded = false;
    // Success requires BOTH conditions: the gzip stream reached 'end' (so the
    // gzip CRC32/length trailer was validated — a corrupt archive emits 'error'
    // instead, never 'end') AND the captured entry's WriteStream has flushed +
    // closed (so the subsequent rename/chmod cannot race the async flush).
    let gunzipEnded = false;
    let targetClosed = false;

    // The outer promise settles EXACTLY once.  `fail` rejects (tearing down any
    // open output stream and the source streams + dropping the partial temp
    // file).  `maybeSucceed` resolves only once both success conditions hold.
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      if (outStream) {
        outStream.destroy();
        outStream = null;
      }
      input.destroy();
      gunzip.destroy();
      // Best-effort: drop any partial temp output so it can never be renamed in.
      void unlink(tmpOut).catch(() => { /* ignore */ });
      reject(err);
    };

    const maybeSucceed = (): void => {
      if (settled) return;
      if (!gunzipEnded) return;                 // gzip integrity not yet validated
      if (foundEntry && !targetClosed) return;  // extracted file not yet flushed
      settled = true;
      resolve();
    };

    // Open the output stream for the captured entry.  The 'error' handler is
    // attached at CREATION time (not later) so an open/write failure rejects the
    // outer promise cleanly instead of surfacing as an unhandled 'error' event
    // that crashes the process.  'close' fires only after the fd is flushed +
    // closed; we do NOT resolve here — we still let gunzip drain to 'end' so the
    // gzip integrity trailer is validated before we accept the bytes.
    const openOutStream = (): void => {
      const s = createWriteStream(tmpOut);
      outStream = s;
      s.once('error', fail);
      s.once('close', () => {
        targetClosed = true;
        maybeSucceed();
      });
    };

    // Finalize the captured entry stream: flush remaining writes; the 'close'
    // handler attached in openOutStream() flips `targetClosed`.  Idempotent — a
    // no-op once the stream has been handed off (outStream === null).
    const finalizeStream = (): void => {
      if (!outStream) return;
      const s = outStream;
      outStream = null;
      capturing = false;
      s.end();
    };

    gunzip.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      processBuffer();
    });

    gunzip.on('end', () => {
      gunzipEnded = true;
      if (!foundEntry) {
        fail(new Error(
          `script-jail: entry "${targetEntry}" not found in tarball ${tarPath}`,
        ));
        return;
      }
      // Reject any incomplete trailing data at end-of-stream (a SHA-verified
      // tarball cannot be truncated; this guards the extractor's own contract
      // for callers that do not pre-verify).  Two cases:
      //   * mid-entry: `state === 'data' && paddedRemaining > 0` — the current
      //     entry's padded region was not fully consumed; OR
      //   * a partial trailing block: `buf.length !== 0` — leftover bytes
      //     smaller than a 512-byte block (a truncated header/data fragment).
      // A well-formed archive consumes every byte in whole 512-byte blocks
      // (including the trailing zero EOF blocks), so `buf` is empty in the
      // header state at end.
      if ((state === 'data' && paddedRemaining > 0) || buf.length !== 0) {
        fail(new Error(
          `script-jail: truncated tarball ${tarPath} ` +
          `(incomplete trailing data: ${paddedRemaining} block byte(s) missing, ` +
          `${buf.length} stray byte(s))`,
        ));
        return;
      }
      // Entry complete and gzip trailer validated.  Flush + close any still-open
      // stream; its 'close' handler flips `targetClosed` and calls maybeSucceed.
      // If the stream already closed in the data branch, resolve now.
      finalizeStream();
      maybeSucceed();
    });

    gunzip.on('error', fail);
    input.on('error', fail);

    const processBuffer = (): void => {
      while (buf.length >= BLOCK) {
        if (state === 'header') {
          const header = buf.subarray(0, BLOCK);
          buf = buf.subarray(BLOCK);

          // All-zero block = end-of-archive marker.  Mark it and consume any
          // further zero blocks as record padding.
          if (header.every((b) => b === 0)) {
            archiveEnded = true;
            continue;
          }
          // A non-zero block after the end-of-archive marker is trailing/hidden
          // content that a compliant tar reader stops before — reject rather
          // than extract an entry placed past EOF.
          if (archiveEnded) {
            fail(new Error(
              `script-jail: unexpected data after end-of-archive marker in tarball ${tarPath}`,
            ));
            return;
          }
          // Validate the header checksum before trusting name/size — rejects
          // forged/garbage headers a compliant tar reader would not accept.
          if (!tarHeaderChecksumValid(header)) {
            fail(new Error(
              `script-jail: invalid tar header checksum in tarball ${tarPath}`,
            ));
            return;
          }

          // Reject any typeflag a strict reader would interpret specially —
          // they either OVERRIDE the following entry's name/size, or carry data
          // whose block count differs from ceil(size/512), so blindly skipping
          // them by the size field would mis-frame a later header (and could
          // shift a forged target into view):
          //   x / X / g   PAX & Solaris extended headers (override path/size)
          //   L / K / N   GNU long name / long link / old long name (override name)
          //   S           GNU sparse (archived data < declared size)
          //   M           GNU multi-volume continuation
          // The official Firecracker tarball is plain ustar (regular files plus
          // optional directory entries) and never uses any of these; rejecting
          // is simpler and safer than implementing each record's semantics.
          const typeflag = header[156]!;
          if (
            typeflag === 0x78 /* x */ || typeflag === 0x58 /* X */ ||
            typeflag === 0x67 /* g */ || typeflag === 0x4c /* L */ ||
            typeflag === 0x4b /* K */ || typeflag === 0x4e /* N */ ||
            typeflag === 0x53 /* S */ || typeflag === 0x4d /* M */
          ) {
            fail(new Error(
              `script-jail: unsupported tar typeflag ` +
              `0x${typeflag.toString(16)} in tarball ${tarPath}`,
            ));
            return;
          }

          // Reconstruct the entry path.  Bytes 345..500 are a path PREFIX only
          // in POSIX ustar, identified by the 6-byte MAGIC field (257..263)
          // being exactly "ustar\0".  GNU format uses "ustar  " (byte 262 is a
          // SPACE, not NUL) and repurposes 345..500 for atime/ctime/sparse
          // metadata; v7 has no magic and no prefix field.  A compliant reader
          // (libarchive/bsdtar) keys this decision on the magic field ALONE and
          // honors the prefix for any "ustar\0" header regardless of the version
          // bytes (263..265) — so we must too: gating on version == "00" would
          // ignore the prefix on a "ustar\0" + non-"00"-version header that
          // bsdtar lists under the prefixed path.
          const magic = header.subarray(257, 263); // 6-byte magic field
          const isPosixUstar =
            magic[0] === 0x75 && magic[1] === 0x73 && magic[2] === 0x74 &&
            magic[3] === 0x61 && magic[4] === 0x72 && magic[5] === 0x00; // "ustar\0"
          const namePart = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
          const prefixPart = isPosixUstar
            ? header.subarray(345, 500).toString('utf8').replace(/\0.*$/u, '')
            : '';
          const name = prefixPart.length > 0 ? `${prefixPart}/${namePart}` : namePart;

          // The ustar size field is octal digits terminated by NUL/space.
          // parseOctalField validates the WHOLE fixed-width field strictly
          // (octal digits then only NUL/space padding) — a prefix-then-garbage
          // field is malformed and rejected (also prevents a NaN size from
          // making `take` NaN below and stalling the parser loop forever → hang).
          const declaredSize = parseOctalField(header.subarray(124, 136));
          if (declaredSize === null) {
            fail(new Error(
              `script-jail: invalid tar header size in tarball ${tarPath}`,
            ));
            return;
          }
          // NOTE: we intentionally do NOT validate the mode/uid/gid/mtime octal
          // fields.  They are irrelevant to selecting and extracting the binary
          // (only name/size/typeflag/checksum/prefix matter), and the official
          // Firecracker release tarball legitimately encodes a large uid in GNU
          // base-256 form (leading byte 0x80, e.g. uid 1720533490) — which a
          // strict octal check would falsely reject, breaking real extraction.
          // bsdtar accepts these; matching that here keeps the genuine tarball
          // extractable.  (Adversarial metadata is excluded by the pinned SHA-256.)
          // POSIX framing: only regular ('0'/NUL) and contiguous ('7') entries
          // carry data blocks; link/device/directory/fifo types ('1'..'6') have
          // NONE regardless of the size field, and a compliant reader (bsdtar)
          // ignores a non-zero size on them — treating the next block as the
          // next header / EOF.  We fail closed: silently advancing ceil(size/512)
          // blocks for such an entry would let it SWALLOW the end-of-archive
          // zero-block and expose a forged target hidden past where a compliant
          // reader stops.  (The official tarball's only non-regular entries are
          // zero-size directory records.)
          const bearsData =
            typeflag === 0x30 /* '0' */ || typeflag === 0x00 /* NUL */ ||
            typeflag === 0x37 /* '7' contiguous */;
          if (!bearsData && declaredSize !== 0) {
            fail(new Error(
              `script-jail: non-regular tar entry ` +
              `(typeflag 0x${typeflag.toString(16)}) declares a non-zero size ` +
              `in tarball ${tarPath}`,
            ));
            return;
          }
          const blocks = Math.ceil(declaredSize / BLOCK);
          // Track padded size for advancing past this entry's data blocks.
          paddedRemaining = blocks * BLOCK;
          // Track declared size for writing only the real bytes (no NUL padding).
          declaredRemaining = declaredSize;

          if (name === targetEntry) {
            // A well-formed Firecracker tarball has exactly ONE matching entry.
            // A second one (of ANY size) is malformed/ambiguous — reject rather
            // than let a stale `targetClosed` from the first entry race the
            // second flush, or let a later zero-size duplicate silently diverge
            // from what a compliant reader (which would overwrite) produces.
            if (foundEntry) {
              fail(new Error(
                `script-jail: duplicate entry "${targetEntry}" in tarball ${tarPath}`,
              ));
              return;
            }
            foundEntry = true;
            // The captured entry must be a regular file (typeflag '0' or NUL).
            // A symlink/dir/special header carrying the target path is not the
            // firecracker executable — reject rather than write its payload out
            // as the binary.  (PAX/GNU records were already rejected above.)
            if (typeflag !== 0x30 && typeflag !== 0x00) {
              fail(new Error(
                `script-jail: target entry "${targetEntry}" is not a regular file ` +
                `(typeflag 0x${typeflag.toString(16)}) in tarball ${tarPath}`,
              ));
              return;
            }
            // A zero-byte firecracker binary is never valid — fail closed rather
            // than produce an empty executable (also covers a zero-size match).
            if (declaredSize === 0) {
              fail(new Error(
                `script-jail: target entry "${targetEntry}" is empty in tarball ${tarPath}`,
              ));
              return;
            }
            capturing = true;
            openOutStream();
          } else {
            capturing = false;
          }

          state = 'data';
        } else {
          // state === 'data'
          // Always advance past the full padded block region.
          const take = Math.min(paddedRemaining, buf.length);
          if (capturing && outStream && declaredRemaining > 0) {
            // Write only up to the declared (non-padded) byte count.
            const writeBytes = Math.min(take, declaredRemaining);
            outStream.write(buf.subarray(0, writeBytes));
            declaredRemaining -= writeBytes;
          }
          buf = buf.subarray(take);
          paddedRemaining -= take;
          if (paddedRemaining === 0) {
            if (capturing && outStream) {
              finalizeStream();
            }
            state = 'header';
          }
        }
      }
    };

    input.pipe(gunzip);
  });

  // Move tmp file to final location.
  await rename(tmpOut, destPath);

  // Make executable.
  await chmod(destPath, 0o755);
}

function firecrackerReleaseArch(arch: FirecrackerArch): FirecrackerReleaseArch {
  return arch === 'arm64' ? 'aarch64' : 'x86_64';
}

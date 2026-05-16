// npm-jar — src/action/firecracker/download.ts
//
// Downloads the Firecracker binary (from a GitHub release tarball) and a
// precompiled vmlinux kernel image, caches both under `imagesDir`, and
// verifies each against a pinned SHA-256 hash.
//
// Design decisions:
//   - HttpClient is an interface so unit tests can inject a fake without
//     touching the filesystem or network.
//   - Production impl (`NodeHttpClient`) uses the built-in `node:https`
//     module via a redirect-following `downloadFile` helper, staying
//     dependency-free.
//   - KNOWN_VERSIONS holds pinned hashes for supported Firecracker releases.
//     Update the map whenever you pin a new release; the CI gate will catch
//     missing entries at plan time.

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { chmod, rename, unlink } from 'node:fs/promises';
import { get as httpsGet } from 'node:https';
import { get as httpGet } from 'node:http';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createGunzip } from 'node:zlib';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface HttpClient {
  /** Download `url` to `destPath`, verify SHA-256, throw on mismatch. */
  download(url: string, destPath: string, expectedSha256: string): Promise<void>;
}

export interface DownloadInput {
  /** Directory where cached binaries are stored (e.g. `<repo>/images`). */
  imagesDir: string;
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

// ---------------------------------------------------------------------------
// Pinned hashes
// ---------------------------------------------------------------------------

/**
 * KNOWN_VERSIONS maps Firecracker release versions to the SHA-256 of their
 * x86_64 release tarball (firecracker-v<ver>-x86_64.tgz).
 *
 * IMPORTANT: These are placeholder values. Before using this in production,
 * replace each hash with the actual SHA-256 of the official GitHub release
 * tarball, which you can verify with:
 *
 *   curl -sL <tarball-url> | sha256sum
 *
 * The release tarballs live at:
 *   https://github.com/firecracker-microvm/firecracker/releases/download/v<ver>/firecracker-v<ver>-x86_64.tgz
 *
 * TODO(ops): populate real hashes before shipping.
 */
export const KNOWN_VERSIONS: Readonly<Record<string, string>> = {
  '1.8.0': 'PLACEHOLDER_SHA256_FIRECRACKER_1_8_0_x86_64_TGZ',
  '1.9.0': 'PLACEHOLDER_SHA256_FIRECRACKER_1_9_0_x86_64_TGZ',
};

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

  const expectedTarSha = KNOWN_VERSIONS[firecrackerVersion];
  if (expectedTarSha === undefined) {
    throw new Error(
      `npm-jar: unknown Firecracker version "${firecrackerVersion}". ` +
      `Add it (with a pinned SHA-256) to KNOWN_VERSIONS in src/action/firecracker/download.ts.`,
    );
  }

  mkdirSync(imagesDir, { recursive: true });

  // --- Download both files in parallel ------------------------------------
  //
  // We fetch the tarball and the vmlinux concurrently.  Extraction of the
  // firecracker binary from the tarball happens after both downloads complete.

  const tarUrl =
    `https://github.com/firecracker-microvm/firecracker/releases/download/` +
    `v${firecrackerVersion}/firecracker-v${firecrackerVersion}-x86_64.tgz`;

  const tarPath = join(imagesDir, `firecracker-v${firecrackerVersion}-x86_64.tgz`);
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
  await extractFirecrackerBinary(tarPath, fcBinPath, firecrackerVersion);

  return { firecrackerPath: fcBinPath, vmlinuxPath };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Returns the SHA-256 hex digest of a local file. */
async function sha256File(filePath: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk: Buffer) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

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
 * Extracts the `firecracker` binary from a `.tgz` tarball.
 *
 * The official Firecracker release tarball contains a single directory
 * `release-v<ver>-x86_64/` with the binary named `firecracker-v<ver>-x86_64`.
 * We extract that binary to `destPath`.
 *
 * NOTE: This helper is intentionally NOT exported — extraction is an internal
 * detail of `ensureBinaries`. Tests exercise it indirectly through that function.
 */
async function extractFirecrackerBinary(
  tarPath: string,
  destPath: string,
  version: string,
): Promise<void> {
  const tmpOut = join(
    tmpdir(),
    `npm-jar-fc-${randomBytes(4).toString('hex')}`,
  );

  // Target entry inside the tarball (strip the leading directory component).
  const targetEntry = `firecracker-v${version}-x86_64`;

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

    const cleanup = (err?: Error): void => {
      outStream?.close();
      outStream = null;
      if (err) reject(err);
      else resolve();
    };

    gunzip.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      processBuffer();
    });

    gunzip.on('end', () => {
      if (outStream) outStream.close();
      if (!foundEntry) {
        reject(new Error(
          `npm-jar: entry "${targetEntry}" not found in tarball ${tarPath}`,
        ));
        return;
      }
      resolve();
    });

    gunzip.on('error', cleanup);
    input.on('error', cleanup);

    const processBuffer = (): void => {
      while (buf.length >= BLOCK) {
        if (state === 'header') {
          const header = buf.subarray(0, BLOCK);
          buf = buf.subarray(BLOCK);

          // Null block = end of archive.
          if (header.every((b) => b === 0)) continue;

          const nameRaw = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
          // Strip leading path component.
          const name = nameRaw.includes('/') ? nameRaw.split('/').pop()! : nameRaw;

          const sizeField = header.subarray(124, 136).toString('utf8').trim().replace(/\0.*$/u, '');
          const declaredSize = parseInt(sizeField, 8);
          const blocks = Math.ceil(declaredSize / BLOCK);
          // Track padded size for advancing past this entry's data blocks.
          paddedRemaining = blocks * BLOCK;
          // Track declared size for writing only the real bytes (no NUL padding).
          declaredRemaining = declaredSize;

          if (name === targetEntry && declaredSize > 0) {
            capturing = true;
            foundEntry = true;
            outStream = createWriteStream(tmpOut);
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
              outStream.close();
              outStream = null;
              capturing = false;
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

// ---------------------------------------------------------------------------
// Production HttpClient
// ---------------------------------------------------------------------------

/**
 * Production HTTP(S) client that follows up to 5 redirects and verifies
 * the downloaded file's SHA-256 before moving it into place.
 */
export class NodeHttpClient implements HttpClient {
  async download(url: string, destPath: string, expectedSha256: string): Promise<void> {
    const tmpPath = `${destPath}.tmp.${randomBytes(4).toString('hex')}`;

    try {
      await downloadToFile(url, tmpPath, 0);

      // Verify hash.
      const actual = await sha256File(tmpPath);
      if (actual !== expectedSha256) {
        throw new Error(
          `SHA-256 mismatch for ${url}: expected ${expectedSha256}, got ${actual}`,
        );
      }

      await rename(tmpPath, destPath);
    } catch (err) {
      // Clean up temp file on failure.
      try { await unlink(tmpPath); } catch { /* ignore */ }
      throw err;
    }
  }
}

/** Recursive redirect-following downloader. */
async function downloadToFile(url: string, destPath: string, redirects: number): Promise<void> {
  if (redirects > 5) throw new Error(`Too many redirects fetching ${url}`);

  const getter = url.startsWith('https://') ? httpsGet : httpGet;

  await new Promise<void>((resolve, reject) => {
    getter(url, (res) => {
      if (
        res.statusCode !== undefined &&
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location
      ) {
        res.resume(); // drain
        downloadToFile(res.headers.location, destPath, redirects + 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode ?? '?'} fetching ${url}`));
        return;
      }

      const out = createWriteStream(destPath);
      res.pipe(out);
      out.on('finish', () => resolve());
      out.on('error', reject);
      res.on('error', reject);
    }).on('error', reject);
  });
}


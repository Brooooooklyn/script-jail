// script-jail — src/shared/http-download.ts
//
// Generic HTTP(S) download primitives reused by both the Firecracker
// download path (src/action/firecracker/download.ts) and the macOS CLI
// artifact prefetcher (added in a later PR).  No knowledge of Firecracker,
// release URLs, or pinned version tables lives here — see the per-runtime
// orchestration modules for that.
//
// What lives here:
//   - `HttpClient` interface — the injection seam used by tests + by
//     orchestration modules that want to swap in a fake.
//   - `NodeHttpClient` — production impl built on `node:http(s)`'s
//     redirect-following `get()`.  Dependency-free.
//   - `sha256File` — streaming SHA-256 over a path on disk.

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, unlink } from 'node:fs/promises';
import { get as httpsGet } from 'node:https';
import { get as httpGet } from 'node:http';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface HttpClient {
  /**
   * Download `url` to `destPath`, verify its digest against `expectedDigest`,
   * throw on mismatch.
   *
   * `computeDigest` selects HOW the on-disk file is hashed.  It defaults to a
   * plain streaming SHA-256 (`sha256File`) — the digest kind used for every
   * artifact except the rootfs ext4.  The rootfs path passes
   * `canonicalRootfsHash` (time-masked SHA-256) so verification matches the
   * canonical digest the manifest pins; see src/rootfs/repro-hash.ts.
   */
  download(
    url: string,
    destPath: string,
    expectedDigest: string,
    computeDigest?: (filePath: string) => Promise<string>,
  ): Promise<void>;
}

// ---------------------------------------------------------------------------
// sha256File
// ---------------------------------------------------------------------------

/** Returns the SHA-256 hex digest of a local file. */
export async function sha256File(filePath: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk: Buffer) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Production HttpClient
// ---------------------------------------------------------------------------

/**
 * Production HTTP(S) client that follows up to 5 redirects and verifies
 * the downloaded file's SHA-256 before moving it into place.
 */
export class NodeHttpClient implements HttpClient {
  async download(
    url: string,
    destPath: string,
    expectedDigest: string,
    computeDigest: (filePath: string) => Promise<string> = sha256File,
  ): Promise<void> {
    const tmpPath = `${destPath}.tmp.${randomBytes(4).toString('hex')}`;

    try {
      await downloadToFile(url, tmpPath, 0);

      // Verify digest (plain SHA-256 by default; canonical/time-masked for the
      // rootfs ext4 — see the HttpClient.download doc comment).
      const actual = await computeDigest(tmpPath);
      if (actual !== expectedDigest) {
        throw new Error(
          `SHA-256 mismatch for ${url}: expected ${expectedDigest}, got ${actual}`,
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

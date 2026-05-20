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
  /** Download `url` to `destPath`, verify SHA-256, throw on mismatch. */
  download(url: string, destPath: string, expectedSha256: string): Promise<void>;
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

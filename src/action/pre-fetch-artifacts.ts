// npm-jar — src/action/pre-fetch-artifacts.ts
//
// Action-side pre-fetch step.  At action runtime (inside `main.ts`, before
// `ensureBinaries` is called), this module downloads the per-runner rootfs
// ext4 plus the libnpmjar.so shim from the GitHub release matching the
// pinned manifest (`./artifact-manifest.ts`) and caches them under
// `imagesDir`.
//
// Why this lives in main.ts and not in `runs.pre`:
//   GitHub JavaScript actions (`runs.using: node20`) do not support
//   `runs.pre`.  The pre-fetch must therefore happen inside `main.ts` itself,
//   before the orchestrator's real work.  This file is the helper it calls.
//
// Asymmetry note (libnpmjar.so):
//   The .so is baked INTO the released rootfs ext4 at rootfs-build time
//   (Dockerfile: `COPY images/libnpmjar.so /lib/libnpmjar.so`).  At action
//   runtime the .so is therefore strictly informational for the v1 production
//   path that consumes the released rootfs as-is.  We still download it for
//   symmetry and to support a future "build your own rootfs from this release"
//   workflow where the .so lands in `imagesDir/libnpmjar.so` and is referenced
//   by a user-driven rootfs rebuild.
//
// Cache policy mirrors `ensureBinaries`: file present + SHA-256 matches → skip
// download; missing or mismatched → (re-)download.  The HttpClient interface
// and underlying download logic are reused from `./firecracker/download.ts`
// so unit tests can inject a fake HTTP client without touching the network.

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import type { HttpClient } from './firecracker/download.js';
import type { RunnerImage } from './runner-image.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ArtifactManifest {
  /** GitHub repo "owner/name" for the release.  E.g. "brooklyn/npm-jar". */
  repo: string;
  /** Release tag, e.g. "v1.0.0". */
  tag: string;
  /** Map of asset filename → expected SHA-256 hex digest. */
  expected: Readonly<Record<string, string>>;
}

export interface PreFetchInput {
  imagesDir: string;
  runnerImage: RunnerImage;
  manifest: ArtifactManifest;
  http: HttpClient;
}

// ---------------------------------------------------------------------------
// Asset names
// ---------------------------------------------------------------------------

/** Asset filename for the per-runner rootfs. */
function rootfsAssetName(runnerImage: RunnerImage): string {
  return `rootfs-${runnerImage}.ext4`;
}

const LIBNPMJAR_ASSET = 'libnpmjar.so';

// ---------------------------------------------------------------------------
// preFetchArtifacts — main export
// ---------------------------------------------------------------------------

/**
 * Ensure the per-runner rootfs ext4 and libnpmjar.so are present and valid
 * in `imagesDir`.  Downloads from
 *   https://github.com/<repo>/releases/download/<tag>/<asset>
 * and verifies against the manifest's pinned SHA-256.
 *
 * Only the rootfs that matches `runnerImage` is fetched — the "other" rootfs
 * is intentionally skipped because each runner only ever consumes one.
 *
 * Throws when the manifest is missing an entry for an asset we expect to
 * download, or when a downloaded file's hash does not match the manifest.
 */
export async function preFetchArtifacts(input: PreFetchInput): Promise<void> {
  const { imagesDir, runnerImage, manifest, http } = input;

  mkdirSync(imagesDir, { recursive: true });

  const wantedRootfs = rootfsAssetName(runnerImage);

  // Build the list of (asset, destPath, expectedSha) tuples we actually need.
  const assets: ReadonlyArray<{ name: string; expected: string }> = [
    { name: wantedRootfs, expected: requireExpected(manifest, wantedRootfs) },
    { name: LIBNPMJAR_ASSET, expected: requireExpected(manifest, LIBNPMJAR_ASSET) },
  ];

  // Download all assets in parallel; each call is independently idempotent.
  await Promise.all(
    assets.map(({ name, expected }) =>
      ensureAsset({
        http,
        url: assetUrl(manifest, name),
        destPath: join(imagesDir, name),
        expectedSha256: expected,
      }),
    ),
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function assetUrl(manifest: ArtifactManifest, asset: string): string {
  return (
    `https://github.com/${manifest.repo}/releases/download/` +
    `${manifest.tag}/${asset}`
  );
}

function requireExpected(manifest: ArtifactManifest, asset: string): string {
  const sha = manifest.expected[asset];
  if (sha === undefined) {
    throw new Error(
      `npm-jar: artifact manifest is missing an expected SHA-256 for "${asset}". ` +
      `Update src/action/artifact-manifest.ts for tag ${manifest.tag}.`,
    );
  }
  return sha;
}

/**
 * Download `url` to `destPath` if missing or hash-stale.
 *
 * Mirrors `ensureFile` from `./firecracker/download.ts`: present + SHA-256
 * match → skip; otherwise (re-)download via the injected HttpClient (which
 * itself verifies the SHA before renaming into place).
 */
async function ensureAsset(args: {
  http: HttpClient;
  url: string;
  destPath: string;
  expectedSha256: string;
}): Promise<void> {
  const { http, url, destPath, expectedSha256 } = args;

  if (existsSync(destPath)) {
    const actual = await sha256File(destPath);
    if (actual === expectedSha256) return; // cache hit
    console.warn(
      `[pre-fetch] SHA-256 mismatch for cached ${destPath}. ` +
      `Expected ${expectedSha256}, got ${actual}. Re-downloading.`,
    );
  }

  await http.download(url, destPath, expectedSha256);
}

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

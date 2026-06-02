// script-jail — src/action/pre-fetch-artifacts.ts
//
// Action-side pre-fetch step.  At action runtime (inside `main.ts`, before
// `ensureBinaries` is called), this module downloads the per-runner rootfs
// ext4 plus the libscriptjail.so shim from the GitHub release matching the
// pinned manifest (`./artifact-manifest.ts`) and caches them under
// `imagesDir`.
//
// Why this lives in main.ts and not in `runs.pre`:
//   GitHub JavaScript actions (`runs.using: node20`) do not support
//   `runs.pre`.  The pre-fetch must therefore happen inside `main.ts` itself,
//   before the orchestrator's real work.  This file is the helper it calls.
//
// Asymmetry note (libscriptjail.so):
//   The .so is baked INTO the released rootfs ext4 at rootfs-build time
//   (Dockerfile: `COPY images/libscriptjail.so /lib/libscriptjail.so`).  At action
//   runtime the .so is therefore strictly informational for the v1 production
//   path that consumes the released rootfs as-is.  We still download it for
//   symmetry and to support a future "build your own rootfs from this release"
//   workflow where the .so lands in `imagesDir/libscriptjail.so` and is referenced
//   by a user-driven rootfs rebuild.
//
// Cache policy mirrors `ensureBinaries`: file present + SHA-256 matches → skip
// download; missing or mismatched → (re-)download.  The HttpClient interface
// and underlying download logic are reused from `./firecracker/download.ts`
// so unit tests can inject a fake HTTP client without touching the network.

import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import type { HttpClient } from './firecracker/download.js';
import { sha256File } from '../shared/http-download.js';
import { canonicalRootfsHash } from '../rootfs/repro-hash.js';
import type { RunnerImage } from './runner-image.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Platform key for the nested `expected` map. The action and macOS CLI pin
 * distinct asset sets without two manifest files.
 */
export type ManifestPlatform = 'linux' | 'darwin';
export type ArtifactArch = 'x64' | 'arm64';

/**
 * Per-asset SHA-256 map for one platform section.  Asset filename → 64-char
 * lowercase hex digest (or a `PLACEHOLDER_SHA256_*` bootstrap string until
 * the first release is cut).
 */
export type ManifestSection = Readonly<Record<string, string>>;

export interface ArtifactManifest {
  /** GitHub repo "owner/name" for the release. E.g. "Brooooooklyn/scriptjail". */
  repo: string;
  /** Release tag, e.g. "v1.0.0". */
  tag: string;
  /**
   * Platform-keyed map of asset SHAs.  The Linux runner consumes
   * `expected.linux`; the macOS CLI consumes `expected.darwin`.  The two
   * sections never share asset filenames — the .so/rootfs/binary names are
   * arch-suffixed so a copy-paste between sections is immediately obvious.
   */
  expected: Readonly<Record<ManifestPlatform, ManifestSection>>;
  /**
   * Runnable Docker rootfs image references keyed by arch and runner image.
   * References must be digest-pinned (`name@sha256:<64 lowercase hex>`).
   */
  dockerImages?: Readonly<
    Record<ArtifactArch, Readonly<Partial<Record<RunnerImage, string>>>>
  >;
}

export interface PreFetchInput {
  imagesDir: string;
  runnerImage: RunnerImage;
  /**
   * Host/guest architecture for the rootfs and shim assets. Defaults to x64
   * for backwards compatibility with the original Linux action runner.
   */
  arch?: ArtifactArch;
  manifest: ArtifactManifest;
  http: HttpClient;
  /**
   * Which platform section of the manifest to consult.  Defaults to `'linux'`
   * because this helper is invoked from the GitHub Action's `main.ts`, which
   * only runs on Linux. The macOS CLI does not call preFetchArtifacts at all
   * — it resolves artifacts from the local `images/` dir via
   * `src/shared/artifacts.ts`.
   */
  platform?: ManifestPlatform;
}

// ---------------------------------------------------------------------------
// Asset names
// ---------------------------------------------------------------------------

/** Asset filename for the per-runner rootfs. */
function rootfsAssetName(runnerImage: RunnerImage, arch: ArtifactArch): string {
  return arch === 'arm64'
    ? `rootfs-${runnerImage}-arm64.ext4`
    : `rootfs-${runnerImage}.ext4`;
}

function libscriptjailAssetName(arch: ArtifactArch): string {
  return arch === 'arm64' ? 'libscriptjail-arm64.so' : 'libscriptjail.so';
}

// ---------------------------------------------------------------------------
// preFetchArtifacts — main export
// ---------------------------------------------------------------------------

/**
 * Ensure the per-runner rootfs ext4 and libscriptjail.so are present and valid
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
  const platform: ManifestPlatform = input.platform ?? 'linux';
  const arch: ArtifactArch = input.arch ?? 'x64';

  mkdirSync(imagesDir, { recursive: true });

  const wantedRootfs = rootfsAssetName(runnerImage, arch);
  const wantedLibscriptjail = libscriptjailAssetName(arch);

  // Build the list of (asset, destPath, expected, digest-fn) tuples we need.
  // Each asset carries HOW its on-disk bytes are hashed: the rootfs ext4 by its
  // canonical (time-masked) digest, the shim by a plain SHA-256.
  const assets: ReadonlyArray<{
    name: string;
    expected: string;
    digest: (filePath: string) => Promise<string>;
  }> = [
    {
      name: wantedRootfs,
      expected: requireExpected(manifest, platform, wantedRootfs),
      // The rootfs ext4 is pinned by its CANONICAL (time-masked) hash — see
      // src/rootfs/repro-hash.ts.  Both the cache-hit check and the download
      // verification below must hash it this way or every consumer rejects a
      // perfectly valid release (raw bytes carry a build-time s_wtime that the
      // manifest digest deliberately ignores).
      digest: canonicalRootfsHash,
    },
    {
      name: wantedLibscriptjail,
      expected: requireExpected(manifest, platform, wantedLibscriptjail),
      // The shim is a plain ELF: a raw SHA-256 of the released bytes.
      digest: sha256File,
    },
  ];

  // Download all assets in parallel; each call is independently idempotent.
  await Promise.all(
    assets.map(({ name, expected, digest }) =>
      ensureAsset({
        http,
        url: assetUrl(manifest, name),
        destPath: join(imagesDir, name),
        expectedDigest: expected,
        computeDigest: digest,
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

function requireExpected(
  manifest: ArtifactManifest,
  platform: ManifestPlatform,
  asset: string,
): string {
  const section = manifest.expected[platform];
  if (section === undefined) {
    throw new Error(
      `script-jail: artifact manifest is missing the "${platform}" platform ` +
        `section.  Update src/action/artifact-manifest.ts for tag ${manifest.tag}.`,
    );
  }
  const sha = section[asset];
  if (sha === undefined) {
    throw new Error(
      `script-jail: artifact manifest is missing an expected SHA-256 for "${asset}". ` +
      `Update src/action/artifact-manifest.ts for tag ${manifest.tag}.`,
    );
  }
  return sha;
}

/**
 * Download `url` to `destPath` if missing or digest-stale.
 *
 * Mirrors `ensureFile` from `./firecracker/download.ts`: present + digest
 * match → skip; otherwise (re-)download via the injected HttpClient (which
 * itself verifies the digest before renaming into place).  `computeDigest`
 * selects the hash kind (plain SHA-256, or canonical/time-masked for the
 * rootfs) and is used for BOTH the cache-hit check and the download.
 */
async function ensureAsset(args: {
  http: HttpClient;
  url: string;
  destPath: string;
  expectedDigest: string;
  computeDigest: (filePath: string) => Promise<string>;
}): Promise<void> {
  const { http, url, destPath, expectedDigest, computeDigest } = args;

  if (existsSync(destPath)) {
    const actual = await computeDigest(destPath);
    if (actual === expectedDigest) return; // cache hit
    console.warn(
      `[pre-fetch] digest mismatch for cached ${destPath}. ` +
      `Expected ${expectedDigest}, got ${actual}. Re-downloading.`,
    );
  }

  await http.download(url, destPath, expectedDigest, computeDigest);
}

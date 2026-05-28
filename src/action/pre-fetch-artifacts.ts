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

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import type { HttpClient } from './firecracker/download.js';
import type { RunnerImage } from './runner-image.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Platform key for the nested `expected` map.  PR 5 split the manifest by
 * platform so the action (which only runs on Linux) and the macOS CLI (PR 4)
 * can pin distinct asset sets without two manifest files.
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
   * only runs on Linux.  The macOS CLI (PR 4) does not call preFetchArtifacts
   * at all — it resolves artifacts from the local `images/` dir via
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

  // Build the list of (asset, destPath, expectedSha) tuples we actually need.
  const assets: ReadonlyArray<{ name: string; expected: string }> = [
    {
      name: wantedRootfs,
      expected: requireExpected(manifest, platform, wantedRootfs),
    },
    {
      name: wantedLibscriptjail,
      expected: requireExpected(manifest, platform, wantedLibscriptjail),
    },
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

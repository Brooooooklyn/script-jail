// script-jail — src/cli/local-artifacts.ts
//
// CLI-local replacement for the Action's `preFetchArtifacts`.
//
// On Linux the CLI reuses the Action's firecracker/bare backends. Both call
// `deps.preFetchArtifacts(input)` to ensure the per-runner rootfs ext4 and the
// libscriptjail.so shim are present in `ctx.imagesDir` before the VM/sandbox
// boots. The Action's implementation DOWNLOADS those assets from the GitHub
// release matching the pinned manifest (`src/action/pre-fetch-artifacts.ts`).
//
// The CLI has no business hitting the network or the manifest: the runtime
// artifacts already ship in the locally-installed `@script-jail/<os>-<arch>`
// platform package (or, in a dev checkout, the repo `images/` dir). This module
// builds a closure with the SAME signature as `preFetchArtifacts` that instead:
//
//   1. sparse-gunzips `packageImagesDir/rootfs-ubuntu-<major>[-arm64].ext4.gz`
//      into the user cache (via `ensureRootfs`, which is already on disk and
//      digest-keyed), then LINKS (or COPIES on EXDEV) the materialized raw
//      ext4 into the backend's `imagesDir` under the FC-rule name
//      `rootfs-<runnerImage>[-arm64].ext4`; and
//   2. COPIES `libscriptjail[-arm64].so` into `imagesDir`.
//
// It NEVER touches `input.manifest` or `input.http` — those fields exist only
// because the closure must satisfy the `preFetchArtifacts` type (the backends
// always pass `ctx.manifest` / `ctx.http`).
//
// Idempotency (LOW fix, WS1 reviewer #6): `linkSync` to an existing path throws
// EEXIST and a re-run should not re-pay the gunzip cost. Both materialize steps
// short-circuit when the destination already exists with the expected byte
// length, so a second invocation is a cheap no-op.

import { copyFileSync, existsSync, linkSync, mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { ensureRootfs as defaultEnsureRootfs } from './rootfs-cache.js';
import type { preFetchArtifacts } from '../action/pre-fetch-artifacts.js';
import type { ArtifactArch } from '../action/pre-fetch-artifacts.js';
import type { RunnerImage } from '../action/runner-image.js';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export interface CreateLocalPreFetchArtifactsInput {
  /**
   * Directory holding the platform-package artifacts directly (the `.ext4.gz`
   * rootfs + the libscriptjail.so shim). Typically the resolved
   * `@script-jail/<os>-<arch>` package root, or the dev `images/` fallback —
   * see `resolvePlatformPackageDir` in `src/shared/artifacts.ts`.
   */
  packageImagesDir: string;
  /** Host architecture; selects the rootfs/shim filename variant. */
  hostArch: ArtifactArch;
  /** Ubuntu major version. The CLI only ships 24.04 today. */
  ubuntuMajor: '24.04';
  /**
   * Cache directory forwarded to `ensureRootfs`. When omitted, `ensureRootfs`
   * uses its own platform default. Primarily an injection seam for tests.
   */
  cacheDir?: string;
  /** Injection seam for `ensureRootfs` (tests assert it is run at most once). */
  ensureRootfs?: typeof defaultEnsureRootfs;
}

/**
 * Build a `preFetchArtifacts`-shaped closure that materializes the platform
 * package's rootfs + shim into the backend's `imagesDir`, replacing the
 * GitHub-release download path. Drops directly into
 * `FirecrackerBackendDeps.preFetchArtifacts` / `BareBackendDeps.preFetchArtifacts`.
 */
export function createLocalPreFetchArtifacts(
  input: CreateLocalPreFetchArtifactsInput,
): typeof preFetchArtifacts {
  const { packageImagesDir, hostArch, ubuntuMajor } = input;
  const ensureRootfs = input.ensureRootfs ?? defaultEnsureRootfs;

  return async function localPreFetchArtifacts(prefetch) {
    const { imagesDir, runnerImage } = prefetch;
    // The backends pass `ctx.arch`; fall back to the configured hostArch (and
    // ultimately x64) so the closure stays robust if `arch` is ever omitted.
    const arch: ArtifactArch = prefetch.arch ?? hostArch;

    mkdirSync(imagesDir, { recursive: true });

    await materializeRootfs({
      packageImagesDir,
      imagesDir,
      runnerImage,
      arch,
      ubuntuMajor,
      cacheDir: input.cacheDir,
      ensureRootfs,
    });

    materializeShim({ packageImagesDir, imagesDir, arch });
  };
}

// ---------------------------------------------------------------------------
// rootfs
// ---------------------------------------------------------------------------

async function materializeRootfs(args: {
  packageImagesDir: string;
  imagesDir: string;
  runnerImage: RunnerImage;
  arch: ArtifactArch;
  ubuntuMajor: '24.04';
  cacheDir: string | undefined;
  ensureRootfs: typeof defaultEnsureRootfs;
}): Promise<void> {
  const wantedRootfs = rootfsAssetName(args.runnerImage, args.arch);
  const dest = join(args.imagesDir, wantedRootfs);

  // Idempotency: a prior run already linked/copied a verified rootfs here. Skip
  // the (expensive) sparse-gunzip entirely and avoid the EEXIST `linkSync`
  // would throw. ensureRootfs is therefore NOT re-run on the second call.
  if (existsSync(dest)) return;

  // The platform package ships `<name>.ext4.gz`; point `ensureRootfs` at the
  // would-be raw path (which does NOT exist in the package, only the .gz does)
  // so it materializes a sparse raw ext4 into the digest-keyed cache and
  // returns that cache path.
  const packagedRootfs = join(args.packageImagesDir, wantedRootfs);
  const materialized = await args.ensureRootfs({
    rootfsPath: packagedRootfs,
    compressedRootfsPath: `${packagedRootfs}.gz`,
    // Only forward `cacheDir` when set: under exactOptionalPropertyTypes an
    // explicit `undefined` is not assignable to the optional field.
    ...(args.cacheDir !== undefined ? { cacheDir: args.cacheDir } : {}),
  });

  // Defensive size-gated re-check before linkSync (handles a concurrent writer
  // that created `dest` during materialization): skip when dest already exists
  // with the materialized byte length.
  if (existsSync(dest) && statSync(dest).size === statSync(materialized).size) {
    return;
  }

  linkOrCopy(materialized, dest);
}

// ---------------------------------------------------------------------------
// shim
// ---------------------------------------------------------------------------

function materializeShim(args: {
  packageImagesDir: string;
  imagesDir: string;
  arch: ArtifactArch;
}): void {
  const soName = libscriptjailAssetName(args.arch);
  const src = join(args.packageImagesDir, soName);
  const dest = join(args.imagesDir, soName);

  // Size-gate the copy the same way as the rootfs link: skip when dest already
  // exists with the expected byte length.
  if (existsSync(dest) && statSync(dest).size === statSync(src).size) return;

  copyFileSync(src, dest);
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

/**
 * Hard-link `src` → `dest`; fall back to a byte copy when the two paths live on
 * different filesystems (`EXDEV`), which is common when the cache dir and the
 * CLI images dir resolve to different mounts.
 */
function linkOrCopy(src: string, dest: string): void {
  try {
    linkSync(src, dest);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EXDEV') {
      copyFileSync(src, dest);
      return;
    }
    throw err;
  }
}

/** Asset filename for the per-runner rootfs (mirrors the FC backend's rule). */
function rootfsAssetName(runnerImage: RunnerImage, arch: ArtifactArch): string {
  return arch === 'arm64'
    ? `rootfs-${runnerImage}-arm64.ext4`
    : `rootfs-${runnerImage}.ext4`;
}

function libscriptjailAssetName(arch: ArtifactArch): string {
  return arch === 'arm64' ? 'libscriptjail-arm64.so' : 'libscriptjail.so';
}

// script-jail — src/shared/artifacts.ts
//
// Pure-helper that maps `(hostArch, ubuntuMajor)` to the file paths the
// macOS CLI needs in order to boot the audit VM:
//
//   - kernelPath           — VZ-compatible kernel image.
//   - rootfsPath           — Linux ext4 image keyed by Ubuntu major + arch.
//   - libscriptjailSoPath  — LD_PRELOAD shim, ELF for the guest arch.
//   - macShimDylibPath     — DYLD_INSERT_LIBRARIES shim, Mach-O for the macOS
//                            bare backend (arm64 only; no VM/guest involved).
//
// Path resolution is intentionally PURE: this function never touches the
// filesystem, throws no errors, and does not validate that the files exist.
// The caller (`src/cli/spawn-vm.ts`) is responsible for `existsSync` checks
// and friendly missing-artifact diagnostics. Keeping the helper
// pure lets tests assert on the expected paths without needing the actual
// artifacts on disk.
//
// File-naming convention (kept in sync with `src/rootfs/build.ts:imageFilename()`):
//   images/
//     vmlinux-vz-x86_64
//     vmlinux-vz-arm64
//     rootfs-ubuntu-<major>.ext4                   (x64; existing Firecracker
//                                                   pipeline; also used by VZ on x64)
//     rootfs-ubuntu-<major>-arm64.ext4             (arm64 rootfs build)
//     libscriptjail.so                             (existing x86_64 ELF)
//     libscriptjail-arm64.so                       (cross-compiled in CI)
//     libscriptjail-arm64.dylib                     (macOS-native Mach-O shim;
//                                                   arm64-only, built + ad-hoc
//                                                   signed on the macos leg)
//
// VZ does not require a fundamentally different rootfs from Firecracker —
// the kernel/cmdline differ but the disk image is the same OS install.  So
// we reuse the existing rootfs naming. If a future kernel ABI forces a
// divergent rootfs, add an explicit artifact key rather than overloading
// the existing names.

import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** ELF / kernel architecture for the audit VM. */
export type ArtifactArch = 'x64' | 'arm64';

/** Ubuntu major version the rootfs is keyed by. */
export type ArtifactUbuntuMajor = '22.04' | '24.04';

export interface ArtifactInput {
  /**
   * Absolute path to the repository root.  `images/` is appended.  Exactly one
   * of `repoRoot` / `imagesDir` must be provided.
   */
  repoRoot?: string;
  /**
   * Absolute path to the directory that contains the artifacts directly (no
   * `images/` suffix is appended).  Platform packages ship their artifacts at
   * the package root, so the CLI passes the resolved package dir here.
   * Exactly one of `repoRoot` / `imagesDir` must be provided.
   */
  imagesDir?: string;
  /** Host architecture (matches the in-VM guest arch). */
  hostArch: ArtifactArch;
  /**
   * Ubuntu major version for the rootfs. The CLI defaults to 24.04, but
   * accepting both supported majors keeps the helper forward-compatible.
   */
  ubuntuMajor: ArtifactUbuntuMajor;
}

export interface ResolvedArtifacts {
  /** Absolute path to the VZ kernel for `hostArch`. */
  kernelPath: string;
  /** Absolute path to the rootfs ext4 image for `(hostArch, ubuntuMajor)`. */
  rootfsPath: string;
  /** Absolute path to the compressed npm-shipped rootfs, when present. */
  compressedRootfsPath: string;
  /** Absolute path to the libscriptjail.so ELF for `hostArch`. */
  libscriptjailSoPath: string;
  /**
   * Absolute path to the macOS-native `libscriptjail-arm64.dylib` Mach-O shim,
   * injected via `DYLD_INSERT_LIBRARIES` by the bare macOS backend.  This is a
   * SEPARATE artifact from `libscriptjailSoPath` (the ELF baked into the Linux
   * guest rootfs): the macOS bare backend runs no VM, so the dylib loads
   * directly into the host install process.  arm64-only (see R10); the name
   * has no x64 variant.  Callers on a non-macOS host can ignore it.
   */
  macShimDylibPath: string;
}

/**
 * Which kind of artifact a `manifestKey()` lookup is asking about.  Mirrors
 * the `ResolvedArtifacts` fields.
 */
export type ArtifactKind = 'kernel' | 'rootfs' | 'libscriptjail' | 'macshim';

// ---------------------------------------------------------------------------
// resolveArtifacts
// ---------------------------------------------------------------------------

/**
 * Map `(hostArch, ubuntuMajor)` to per-arch artifact paths under `images/`.
 *
 * Pure: no IO, no validation, no throws.  Callers check existence and produce
 * friendly errors that point at the right `pnpm build` invocation (or release
 * artifact) for the missing path.
 */
export function resolveArtifacts(input: ArtifactInput): ResolvedArtifacts {
  const { repoRoot, hostArch, ubuntuMajor } = input;

  // Exactly one of `repoRoot` / `imagesDir` is the artifact-directory source:
  //   - `repoRoot`  → dev checkout / Action repo, artifacts live under images/.
  //   - `imagesDir` → an already-resolved directory (e.g. a platform package
  //                   root) whose artifacts sit directly inside it.
  const hasRepoRoot = repoRoot !== undefined;
  const hasImagesDir = input.imagesDir !== undefined;
  if (hasRepoRoot === hasImagesDir) {
    throw new Error(
      'resolveArtifacts: provide exactly one of { repoRoot, imagesDir }',
    );
  }
  const imagesDir = hasImagesDir ? input.imagesDir! : join(repoRoot!, 'images');

  // Kernel naming mirrors `vmlinux-vz-<arch>` where <arch> is the canonical
  // Linux kernel arch label (x86_64 / arm64), not Node's process.arch label
  // (x64 / arm64).  We translate here once so the rest of the code can keep
  // talking in process.arch terms.
  const kernelArch = hostArch === 'x64' ? 'x86_64' : 'arm64';
  const kernelPath = join(imagesDir, `vmlinux-vz-${kernelArch}`);

  // Rootfs naming matches `src/rootfs/build.ts:imageFilename()`:
  //   x64   -> rootfs-ubuntu-<major>.ext4         (existing Firecracker name)
  //   arm64 -> rootfs-ubuntu-<major>-arm64.ext4   (arm64 variant)
  // VZ reuses the same disk image as Firecracker - the divergence is in the
  // kernel + cmdline, not the rootfs ext4.
  const rootfsName =
    hostArch === 'arm64'
      ? `rootfs-ubuntu-${ubuntuMajor}-arm64.ext4`
      : `rootfs-ubuntu-${ubuntuMajor}.ext4`;
  const rootfsPath = join(imagesDir, rootfsName);
  const compressedRootfsPath = `${rootfsPath}.gz`;

  // libscriptjail.so: the existing x86_64 file ships as `libscriptjail.so`
  // (no arch suffix) to keep the action surface backwards compatible.  The
  // arm64 variant gets a suffix so both can coexist in `images/`.
  const libscriptjailSoPath = join(
    imagesDir,
    hostArch === 'x64' ? 'libscriptjail.so' : 'libscriptjail-arm64.so',
  );

  // libscriptjail-arm64.dylib: the macOS-native Mach-O shim for the bare
  // backend.  arm64-only (R10), so the name is fixed regardless of `hostArch` —
  // a darwin-x64 host has no published dylib and must build from source.  The
  // path is resolved unconditionally (pure helper, no IO); the macOS bare
  // backend is the only caller that reads it.
  const macShimDylibPath = join(imagesDir, 'libscriptjail-arm64.dylib');

  return {
    kernelPath,
    rootfsPath,
    compressedRootfsPath,
    libscriptjailSoPath,
    macShimDylibPath,
  };
}

// ---------------------------------------------------------------------------
// resolvePlatformPackageDir
// ---------------------------------------------------------------------------

/**
 * Thrown when neither the installed `@script-jail/<os>-<arch>` platform
 * package nor a dev `images/` fallback directory could be located.  The
 * message names the expected package so the user can install it, and hints
 * that the platform may simply be unsupported.
 */
export class PlatformPackageMissingError extends Error {
  constructor(packageName: string) {
    super(
      `Could not locate runtime artifacts for ${packageName}: the optional ` +
        `platform package is not installed and no dev images/ directory was ` +
        `found. Reinstall script-jail so npm can fetch ${packageName}, or — ` +
        `if your OS/CPU has no matching package — this platform is not ` +
        `supported.`,
    );
    this.name = 'PlatformPackageMissingError';
  }
}

export interface ResolvePlatformPackageDirInput {
  /** The scoped package name, e.g. `@script-jail/linux-x64`. */
  packageName: string;
  /**
   * Injection seam for the resolver.  Defaults to the ambient CJS `require`
   * when available (the bundled `dist/cli.cjs`), otherwise a `createRequire`
   * built from `import.meta.url` (ESM dev / oxnode).
   */
  require?: NodeRequire;
  /**
   * Dev-checkout fallback directory (typically `<repoRoot>/images`).  Used
   * when the platform package is not installed/resolvable.
   */
  devImagesDir?: string;
}

export interface ResolvedPlatformPackageDir {
  /** Directory that contains the runtime artifacts directly (no images/). */
  imagesDir: string;
  /** Where the artifacts came from. */
  source: 'package' | 'dev';
}

/**
 * Locate the directory that holds the runtime artifacts (rootfs, shim, VZ
 * helper) for `packageName`.
 *
 * Resolution order:
 *   1. The installed platform package — `require.resolve(`${packageName}/package.json`)`.
 *      On success, the artifacts ship at the package **root** (spec §4.1), so
 *      we return `dirname(resolvedPkgJson)` with `source:'package'`.
 *   2. The dev `images/` fallback — when the package cannot be resolved for
 *      ANY reason (MODULE_NOT_FOUND, ERR_PACKAGE_PATH_NOT_EXPORTED, or any
 *      other throw), fall back to `devImagesDir` if it exists on disk, with
 *      `source:'dev'`.
 *   3. Otherwise throw `PlatformPackageMissingError`.
 *
 * No `@script-jail/*` platform package is published yet during this phase, so
 * the only working real path is the dev `images/` fallback; the package branch
 * is exercised exclusively via injected `require` in unit tests.
 */
export function resolvePlatformPackageDir(
  input: ResolvePlatformPackageDirInput,
): ResolvedPlatformPackageDir {
  const { packageName, devImagesDir } = input;

  // Mirror the `__filename` / `import.meta.url` dance in `src/cli/index.ts`:
  // prefer the injected/ambient `require` (CJS bundle), else synthesize one
  // from the ESM module URL (dev / oxnode).
  const req: NodeRequire =
    input.require ??
    (typeof require !== 'undefined'
      ? require
      : createRequire(import.meta.url));

  try {
    const resolvedPkgJson = req.resolve(`${packageName}/package.json`);
    return { imagesDir: dirname(resolvedPkgJson), source: 'package' };
  } catch {
    // Any resolve failure means the package is not usable: fall through to the
    // dev fallback rather than rethrowing (fix #5: do not gate on err.code).
  }

  if (devImagesDir !== undefined && existsSync(devImagesDir)) {
    return { imagesDir: devImagesDir, source: 'dev' };
  }

  throw new PlatformPackageMissingError(packageName);
}

// ---------------------------------------------------------------------------
// manifestKey
// ---------------------------------------------------------------------------

/**
 * Map `(hostArch, ubuntuMajor, kind)` to the asset filename used as a key in
 * `PINNED_MANIFEST.expected[platform]`.  Pure — no IO, no error throws on
 * missing data; callers do their own existence/SHA checks.
 *
 * The key strings here MUST match the asset names in
 * `src/action/artifact-manifest.ts` exactly: the CLI uses this helper to
 * look up the expected SHA for a downloaded artifact when (in a future
 * follow-up) the macOS CLI starts to fetch its own release assets from
 * github.com.  v1 only consumes the path side (resolveArtifacts above);
 * shipping the helper now keeps the (manifest key ↔ on-disk filename)
 * mapping in one place so the future fetch path doesn't have to re-invent
 * it.
 */
export function manifestKey(input: {
  hostArch: ArtifactArch;
  ubuntuMajor: ArtifactUbuntuMajor;
  kind: ArtifactKind;
}): string {
  const { hostArch, ubuntuMajor, kind } = input;
  if (kind === 'kernel') {
    return `vmlinux-vz-${hostArch === 'x64' ? 'x86_64' : 'arm64'}`;
  }
  if (kind === 'rootfs') {
    return hostArch === 'arm64'
      ? `rootfs-ubuntu-${ubuntuMajor}-arm64.ext4`
      : `rootfs-ubuntu-${ubuntuMajor}.ext4`;
  }
  if (kind === 'macshim') {
    // The macOS-native Mach-O shim is arm64-only (R10); the key has no x64
    // variant, mirroring the single `libscriptjail-arm64.dylib` asset pinned
    // under `expected.darwin` in src/action/artifact-manifest.ts.
    return 'libscriptjail-arm64.dylib';
  }
  // kind === 'libscriptjail'
  return hostArch === 'arm64' ? 'libscriptjail-arm64.so' : 'libscriptjail.so';
}

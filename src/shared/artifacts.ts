// script-jail — src/shared/artifacts.ts
//
// Pure-helper that maps `(hostArch, ubuntuMajor)` to the file paths the
// macOS CLI needs in order to boot the audit VM:
//
//   - kernelPath           — VZ-compatible kernel image (PR 5 ships this).
//   - rootfsPath           — Linux ext4 image keyed by Ubuntu major + arch.
//   - libscriptjailSoPath  — LD_PRELOAD shim, ELF for the guest arch.
//
// Path resolution is intentionally PURE: this function never touches the
// filesystem, throws no errors, and does not validate that the files exist.
// The caller (`src/cli/spawn-vm.ts`) is responsible for `existsSync` checks
// and friendly "missing artifact (PR 5)" diagnostics.  Keeping the helper
// pure lets tests assert on the expected paths without needing the actual
// artifacts on disk.
//
// File-naming convention (kept in sync with `src/rootfs/build.ts:imageFilename()`):
//   images/
//     vmlinux-vz-x86_64                            (PR 5)
//     vmlinux-vz-arm64                             (PR 5)
//     rootfs-ubuntu-<major>.ext4                   (x64; existing Firecracker
//                                                   pipeline; also used by VZ on x64)
//     rootfs-ubuntu-<major>-arm64.ext4             (PR 4: arm64 rootfs build)
//     libscriptjail.so                             (existing x86_64 ELF)
//     libscriptjail-arm64.so                       (PR 4: cross-compiled in CI)
//
// VZ does not require a fundamentally different rootfs from Firecracker —
// the kernel/cmdline differ but the disk image is the same OS install.  So
// we reuse the existing rootfs naming.  PR 5 may revisit if the kernel ABI
// forces a divergent rootfs.

import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** ELF / kernel architecture for the audit VM. */
export type ArtifactArch = 'x64' | 'arm64';

/** Ubuntu major version the rootfs is keyed by. */
export type ArtifactUbuntuMajor = '22.04' | '24.04';

export interface ArtifactInput {
  /** Absolute path to the repository root. */
  repoRoot: string;
  /** Host architecture (matches the in-VM guest arch). */
  hostArch: ArtifactArch;
  /**
   * Ubuntu major version for the rootfs.  PR 4 defaults to 24.04 in the CLI
   * (the only flavor that has a VZ kernel coming in PR 5); accepting both
   * keeps the helper forward-compatible.
   */
  ubuntuMajor: ArtifactUbuntuMajor;
}

export interface ResolvedArtifacts {
  /** Absolute path to the VZ kernel for `hostArch`. */
  kernelPath: string;
  /** Absolute path to the rootfs ext4 image for `(hostArch, ubuntuMajor)`. */
  rootfsPath: string;
  /** Absolute path to the libscriptjail.so ELF for `hostArch`. */
  libscriptjailSoPath: string;
}

/**
 * Which kind of artifact a `manifestKey()` lookup is asking about.  Mirrors
 * the `ResolvedArtifacts` fields.
 */
export type ArtifactKind = 'kernel' | 'rootfs' | 'libscriptjail';

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
  const imagesDir = join(repoRoot, 'images');

  // Kernel naming mirrors `vmlinux-vz-<arch>` where <arch> is the canonical
  // Linux kernel arch label (x86_64 / arm64), not Node's process.arch label
  // (x64 / arm64).  We translate here once so the rest of the code can keep
  // talking in process.arch terms.
  const kernelArch = hostArch === 'x64' ? 'x86_64' : 'arm64';
  const kernelPath = join(imagesDir, `vmlinux-vz-${kernelArch}`);

  // Rootfs naming matches `src/rootfs/build.ts:imageFilename()`:
  //   x64   -> rootfs-ubuntu-<major>.ext4         (existing Firecracker name)
  //   arm64 -> rootfs-ubuntu-<major>-arm64.ext4   (new PR 4 arm64 variant)
  // VZ reuses the same disk image as Firecracker - the divergence is in the
  // kernel + cmdline, not the rootfs ext4.
  const rootfsName =
    hostArch === 'arm64'
      ? `rootfs-ubuntu-${ubuntuMajor}-arm64.ext4`
      : `rootfs-ubuntu-${ubuntuMajor}.ext4`;
  const rootfsPath = join(imagesDir, rootfsName);

  // libscriptjail.so: the existing x86_64 file ships as `libscriptjail.so`
  // (no arch suffix) to keep the action surface backwards compatible.  The
  // arm64 variant gets a suffix so both can coexist in `images/`.
  const libscriptjailSoPath = join(
    imagesDir,
    hostArch === 'x64' ? 'libscriptjail.so' : 'libscriptjail-arm64.so',
  );

  return { kernelPath, rootfsPath, libscriptjailSoPath };
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
  // kind === 'libscriptjail'
  return hostArch === 'arm64' ? 'libscriptjail-arm64.so' : 'libscriptjail.so';
}

// script-jail — src/action/artifact-manifest.ts
//
// Pinned manifest of release artifacts the action AND the macOS CLI consume
// at runtime.  See `./pre-fetch-artifacts.ts` for release-asset downloads,
// `./backend/docker.ts` for digest-pinned GHCR image pulls, and
// `.github/workflows/release.yml` for the tag-triggered workflow that
// downloads and publishes both forms. `expected` is split by platform so the
// action (Linux-only) and the macOS CLI can pin distinct asset sets from one
// source of truth.
//
// Build-once / download-forever release flow:
//
//   1. Run `.github/workflows/release-build.yml` (workflow_dispatch, required
//      `tag` input).  The producer builds every image asset ONCE — rootfs
//      ext4s (per runner image + arm64 variants), Docker rootfs images,
//      libscriptjail.so / libscriptjail-arm64.so, the VZ vmlinux kernels, and
//      the script-jail-vm-arm64-darwin Mach-O binary — pushes the 4 GHCR
//      rootfs images, and prints a paste-block of the 9 file SHAs + 4 GHCR
//      digests in the job output.
//   2. Paste the 9 file SHAs and 4 GHCR digests from the producer run's
//      paste-block into the maps below.
//   3. Bump `tag` to match the new release.
//   4. Rebuild `dist/` (`pnpm build:bundle`), commit, and push the tag.
//   5. `release.yml` fires on the tag, DOWNLOADS the producer's artifacts,
//      and verifies them against this manifest — it never rebuilds the images.
//
// Supply-chain note:
//
//   At Action/CLI runtime, `./pre-fetch-artifacts.ts` re-checks every
//   downloaded asset against the SHAs pinned here.  That supply-chain
//   verification is independent of the release flow above and is always on.
//
// Bootstrap caveat:
//
//   The values below are PLACEHOLDERS until the first producer-backed release
//   is cut.  Until then, any action run will (correctly) fail the hash check.
//   After pasting in the real SHAs/digests from a `release-build.yml` run and
//   tagging, the manifest is self-consistent.
//
// Why no `script-jail-vm-x86_64-darwin`:
//   The Intel macOS runner is deprecated by GitHub; building an Intel
//   Mach-O cross-compile from Apple Silicon is feasible but out of v1
//   scope.  v1 ships the arm64 binary only and a developer on an Intel
//   Mac must build from source via `cargo build -p script-jail-host-mac`.

import type { ArtifactManifest } from './pre-fetch-artifacts.js';

/**
 * Pinned manifest.  Paste the 9 file SHAs + 4 GHCR digests from the
 * `release-build.yml` producer run's paste-block, bump `tag`, rebuild
 * `dist/`, and commit before pushing the release tag.  See the file header
 * for the full build-once / download-forever update workflow.
 */
export const PINNED_MANIFEST: ArtifactManifest = {
  repo: 'Brooooooklyn/scriptjail', // update when forked
  tag: 'v0.1.0',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': 'PLACEHOLDER_SHA256_LINUX_ROOTFS_UBUNTU_22_04',
      'rootfs-ubuntu-24.04.ext4': 'PLACEHOLDER_SHA256_LINUX_ROOTFS_UBUNTU_24_04',
      'libscriptjail.so':         'PLACEHOLDER_SHA256_LINUX_LIBSCRIPTJAIL_SO',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': 'PLACEHOLDER_SHA256_DARWIN_ROOTFS_UBUNTU_22_04_ARM64',
      'rootfs-ubuntu-24.04-arm64.ext4': 'PLACEHOLDER_SHA256_DARWIN_ROOTFS_UBUNTU_24_04_ARM64',
      'libscriptjail-arm64.so':         'PLACEHOLDER_SHA256_DARWIN_LIBSCRIPTJAIL_ARM64_SO',
      'vmlinux-vz-x86_64':              'PLACEHOLDER_SHA256_VMLINUX_VZ_X86_64',
      'vmlinux-vz-arm64':               'PLACEHOLDER_SHA256_VMLINUX_VZ_ARM64',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    'PLACEHOLDER_SHA256_SCRIPT_JAIL_VM_ARM64_DARWIN',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_22_04_X64',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_X64',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_22_04_ARM64',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_ARM64',
    },
  },
};

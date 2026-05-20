// script-jail — src/action/artifact-manifest.ts
//
// Pinned manifest of release artifacts the action AND the macOS CLI download
// at runtime.  See `./pre-fetch-artifacts.ts` for the Linux-action download
// logic and `.github/workflows/release.yml` for the workflow that builds and
// publishes the matching release assets.  PR 5 split `expected` by platform
// so the action (Linux-only) and the macOS CLI can pin distinct asset sets
// from one source of truth.
//
// Manifest-update workflow:
//
//   1. Cut a new tag (e.g. `v0.2.0`).  The release workflow runs, builds the
//      rootfs ext4 (per runner image + arm64 variants), libscriptjail.so /
//      libscriptjail-arm64.so, the VZ vmlinux kernels, and the
//      script-jail-vm-arm64-darwin Mach-O binary, uploads them to the
//      release, and prints a SHA summary in the job's GITHUB_STEP_SUMMARY.
//   2. Copy the SHAs from the job summary into the per-platform maps below.
//   3. Bump `tag` to match the new release.
//   4. Commit, then cut the NEXT release.
//
// Bootstrap caveat:
//
//   The values below are PLACEHOLDERS until the first release is cut.  This
//   mirrors the pre-`KNOWN_VERSIONS`-pinning state of
//   `./firecracker/download.ts`: the very first tag pushed to a new fork will
//   produce assets whose SHAs do not match these placeholders, and the
//   first run of the action against that tag will (correctly) fail the
//   hash check.  After copying the real SHAs in and cutting the next tag,
//   the manifest is self-consistent.
//
// Why no `script-jail-vm-x86_64-darwin`:
//   The Intel macOS runner is deprecated by GitHub; building an Intel
//   Mach-O cross-compile from Apple Silicon is feasible but out of v1
//   scope.  v1 ships the arm64 binary only and a developer on an Intel
//   Mac must build from source via `cargo build -p script-jail-host-mac`.

import type { ArtifactManifest } from './pre-fetch-artifacts.js';

/**
 * Pinned manifest.  Bump CURRENT_TAG and the SHAs together when cutting a
 * new release.  See the file header for the full update workflow.
 */
export const PINNED_MANIFEST: ArtifactManifest = {
  repo: 'brooklyn/script-jail', // update when forked
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
};

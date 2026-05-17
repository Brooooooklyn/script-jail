// script-jail — src/action/artifact-manifest.ts
//
// Pinned manifest of release artifacts the action downloads at runtime.
// See `./pre-fetch-artifacts.ts` for the download logic and
// `.github/workflows/release.yml` for the workflow that builds and publishes
// the matching release assets.
//
// Manifest-update workflow:
//
//   1. Cut a new tag (e.g. `v0.2.0`).  The release workflow runs, builds the
//      rootfs ext4 (per runner image) and libscriptjail.so, uploads them to the
//      release, and prints a SHA summary in the job's GITHUB_STEP_SUMMARY.
//   2. Copy the SHAs from the job summary into the `expected` map below.
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

import type { ArtifactManifest } from './pre-fetch-artifacts.js';

/**
 * Pinned manifest.  Bump CURRENT_TAG and the SHAs together when cutting a
 * new release.  See the file header for the full update workflow.
 */
export const PINNED_MANIFEST: ArtifactManifest = {
  repo: 'brooklyn/script-jail', // update when forked
  tag: 'v0.1.0',
  expected: {
    'rootfs-ubuntu-22.04.ext4': 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
    'rootfs-ubuntu-24.04.ext4': 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_24_04',
    'libscriptjail.so':              'PLACEHOLDER_SHA256_LIBSCRIPTJAIL_SO',
  },
};

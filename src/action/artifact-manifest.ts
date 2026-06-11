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
//      libscriptjail.so / libscriptjail-arm64.so, the VZ vmlinux kernels, the
//      script-jail-vm-arm64-darwin Mach-O binary, and the macOS-native
//      libscriptjail-arm64.dylib shim — pushes the 4 GHCR rootfs images, and
//      prints a paste-block of the 10 file SHAs + 4 GHCR digests in the job
//      output.
//   2. Paste the 10 file SHAs and 4 GHCR digests from the producer run's
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
  tag: 'v0.2.0',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': '8a0a4c2060eac5d65d2ec73aac9082b9ada9481d0eca300f53aa0d6d8f00505e',
      'rootfs-ubuntu-24.04.ext4': 'daee13379e61b0ab9f70d1f315573dadf1292470b54a20aebb9c83a64df693d7',
      'libscriptjail.so':         '00ad21620189c80228d46ecf50009350906660ee0fd68e0f695108fdccd48251',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': '8796fe96bb772b7c1b47928fc0256a5ecac309077b83d75f21e729b81c01087f',
      'rootfs-ubuntu-24.04-arm64.ext4': 'b5c5efb30073f9f56e9f5be7f743010841f17fb225faa4b9b6d8dd7f7c35fe86',
      'libscriptjail-arm64.so':         '865379b96a5b5b79af3d2e0c5125ee71a14340fadbba34fdcc318e2f734e9911',
      // macOS-native Mach-O shim for the bare backend (DYLD_INSERT_LIBRARIES),
      // ad-hoc signed in build-mac-bin; pinned by a plain sha256 of the signed
      // dylib (backfilled from the v0.2.0 producer run 27341865124).
      'libscriptjail-arm64.dylib':      '9ed31f985f610a5c5466096c0eee42f5c985f02b24cde04591bba73a07e7e95b',
      // Bare-backend SIP-substitution binaries (the shim redirects /bin/sh +
      // coreutils to these plain-arm64 binaries, so no arm64e dylib is needed).
      // coreutils-arm64 is the official uutils 0.4.0 prebuilt — a fixed upstream
      // artifact with a stable BINARY sha (producer recomputed it to the same
      // value).  bash-arm64 is built-from-source by the producer; pinned to the
      // v0.2.0 producer run's signed binary.
      'coreutils-arm64':                '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21',
      'bash-arm64':                     'b067972c856c90d3147b179b4269db57bb78fc65f0e92c9b6f66efd505cec722',
      'vmlinux-vz-x86_64':              '81bb2b1ed63ff02844cc3b09e00de4c99d15f182ae5ca6411510e7f7b67c32a3',
      'vmlinux-vz-arm64':               '2131a7bd4a78a3541b04c624e4d137a0a050574e00d1578b2e76776d14b5f88a',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    '961642267c02554a7a098273b915cf16a7c2f939d4caaf8aaea658e5cb1a69fe',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:7d4a0e7fb69d6ccd66b7488d2eca1fd23a6d273c37ea8a3d5370ca02d515f483',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:07a73cccc09039be7384b62626d85b6d104cfa482101a65fa1d5a4221f9f9f30',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:2ed56076414f375fd002ba87ccfce2660f6306fc56128095cd2f534c2e6f3de5',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:9b0c8a93a878f5a69cba4b995c3f0b4688db5f1b6d9604e51b979efe67b2845f',
    },
  },
};

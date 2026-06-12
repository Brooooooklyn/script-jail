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
  repo: 'Brooooooklyn/script-jail', // renamed from scriptjail (old name redirects)
  tag: 'v0.2.3',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': 'c281c89be8cee4d2b292776e5c68f86735220a6bccd1fc86bf0a544a456c8efb',
      'rootfs-ubuntu-24.04.ext4': 'fdc5c01d9d93b66ef5613e12f914343574583f91c0053af5cb077d2ba25445ed',
      'libscriptjail.so':         '00ad21620189c80228d46ecf50009350906660ee0fd68e0f695108fdccd48251',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': '773134387b1ce7595c7a86981176dd9da1682c80e38ad824d5c61427a4b3785c',
      'rootfs-ubuntu-24.04-arm64.ext4': '6cf19f91221b3e051bdb53d065ee0b88b30a0bd026d02d1b038bda2b36e6d383',
      'libscriptjail-arm64.so':         '865379b96a5b5b79af3d2e0c5125ee71a14340fadbba34fdcc318e2f734e9911',
      // macOS-native Mach-O shim for the bare backend (DYLD_INSERT_LIBRARIES),
      // ad-hoc signed in build-mac-bin; pinned by a plain sha256 of the signed
      // dylib (backfilled from the v0.2.2 producer run 27406262406).
      'libscriptjail-arm64.dylib':      '8f7276bc5d9148a93a5ef32d48fd80aafdf9179eb2f02a2941f4608ccd2dad95',
      // Bare-backend SIP-substitution binaries (the shim redirects /bin/sh +
      // coreutils to these plain-arm64 binaries, so no arm64e dylib is needed).
      // coreutils-arm64 is the official uutils 0.4.0 prebuilt — a fixed upstream
      // artifact with a stable BINARY sha (producer recomputed it to the same
      // value).  bash-arm64 is built-from-source by the producer; byte-identical
      // across the v0.2.0/v0.2.1/v0.2.2 producer runs.
      'coreutils-arm64':                '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21',
      'bash-arm64':                     'b067972c856c90d3147b179b4269db57bb78fc65f0e92c9b6f66efd505cec722',
      'vmlinux-vz-x86_64':              '24f56b679fc4c7f3fd97f77540f69452fe0ff1322cf16833209a6a8a6619c9ef',
      'vmlinux-vz-arm64':               '2b39cb0b9c912a7b95422333fb7d408015cf530467141e51a92e3c3d7d362e21',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    '6a14ab8d03874e189216b4bdd5d9f5ea1a5bdc7c3ed9cdb20350b818ee91c13d',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:9c97649a05e92a87cbeca912678b13ac5bfea469cfa0a24ab48c849c8245f0d9',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:a6778960ea41d3125784f6237b193dddd4c3ef4298a05cb433b5a7f89b3c399f',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:f97847a06ad4a17ed674bcc8f7fee0c5facbc639cf8aacd84ccac1be3445dc47',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:0dd8aef6c2e2b58baae5b95d0f75b0d39b99fe9b06f3428d94ef75f050432cba',
    },
  },
};

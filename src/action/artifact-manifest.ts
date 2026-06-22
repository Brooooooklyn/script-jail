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
  tag: 'v0.2.8',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': '244bb531354ab2ae376a656dc3c1ec47a0adf790acc225433d68112caeca2b25',
      'rootfs-ubuntu-24.04.ext4': '8d9ccc9aa7cc27955b75b4aa4f1f1513ec055d9ab6301e096e4e4425e2288dca',
      'libscriptjail.so':         '00ad21620189c80228d46ecf50009350906660ee0fd68e0f695108fdccd48251',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': '553fcb696c76f6d1ca1c75ec63e59efff9f2cd1e748c6dfee5d005acd079dee3',
      'rootfs-ubuntu-24.04-arm64.ext4': '970880aa5d8377d3afd47c0aeef54ea5f68f5c7ecc0d3e6bebf604a4fdb8de79',
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
      'vmlinux-vz-x86_64':              'acf3bcc0d520f40d56df3fb334feb06f917f8412ad653c2769d0128ac092b5cb',
      'vmlinux-vz-arm64':               '7988d6ef9cf3c7e9c0e2a4c5c72f6ba63919de03b511ee1b1d1bddb488c5ab37',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    '6a14ab8d03874e189216b4bdd5d9f5ea1a5bdc7c3ed9cdb20350b818ee91c13d',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:99b6cad57dcf2a50a20701494129f40ff98faad8c612c77b7097fed02e902dd6',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:72bc29830842e14e7ee25e17cf4873afe4e72c6599c9f5db25e1b55cae50abd0',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:c8248ca28ca3412c524437b14ab5570f2e83e42a06e805b78e9c160b99cb9d4c',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:7a10dd272416ea9c785ccdf1bb1732335c59f5afb6faa5f96a5b9d54cbc91890',
    },
  },
};

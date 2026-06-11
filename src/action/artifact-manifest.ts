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
  tag: 'v0.1.1',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': 'f95caefaa1f4cfa09b54ba5ab48bbbb52f76742db38ceda1c7620bacc6dfbfc8',
      'rootfs-ubuntu-24.04.ext4': 'f301f1727e93ab4ccb5c6a31636d10674f60d0d9eaca942e72c28eacf357c167',
      'libscriptjail.so':         '5d7b8d1a584ad4fce4922a2c558eaab24f3f52fef93b30b12a154569adf19890',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': 'e29dd8113b08fdc81441d2be3709127bf2ccaeaba3798b103ce7a57abca5039d',
      'rootfs-ubuntu-24.04-arm64.ext4': 'b45c85495f6537223d74e0903efe9d9148d38c4027f00fbe497b113680489eff',
      'libscriptjail-arm64.so':         '31d98f738131a11f58cdf7b07d1576511b2fd3906d46937b953e7f4b4cab5ec3',
      // macOS-native Mach-O shim for the bare backend (DYLD_INSERT_LIBRARIES).
      // PLACEHOLDER until the first release-build.yml run that emits its SHA:
      // the dylib is a NEW artifact with no producer-backed bytes yet.  This
      // makes the manifest MIXED (real entries + this placeholder), so the
      // publish-job gate (scripts/check-publish-artifacts.sh) will reject a
      // release until this is backfilled from a producer run that built the
      // dylib — exactly the all-or-nothing contract.  Paste the real SHA from
      // the producer paste-block, then cut the tag.
      'libscriptjail-arm64.dylib':      'PLACEHOLDER_SHA256_DARWIN_LIBSCRIPTJAIL_ARM64_DYLIB',
      // Bare-backend SIP-substitution binaries (the shim redirects /bin/sh +
      // coreutils to these plain-arm64 binaries, so no arm64e dylib is needed).
      // coreutils-arm64 is the official uutils 0.4.0 prebuilt — a fixed upstream
      // artifact with a stable BINARY sha, so it is pinned real now.  bash-arm64
      // is built-from-source by the producer (not byte-reproducible across
      // toolchains), so it is a PLACEHOLDER until a release-build.yml run emits
      // its SHA — same backfill contract as the dylib above.
      'coreutils-arm64':                '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21',
      'bash-arm64':                     'PLACEHOLDER_SHA256_DARWIN_BASH_ARM64',
      'vmlinux-vz-x86_64':              '012e33842367483ffad908d878d5682fa891d2a4f476a229b631e16780404953',
      'vmlinux-vz-arm64':               '4b42d3b912065a92a3816c788ed9c4dac92a12ece4c478c4fb1396c76cffd255',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    '2fc6aefe66ae8275baa4c4d60efb14e18a5b07fbfe217920a84224fae09e281c',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:4c29ddb7a81dfe5e2faa9ae24a4f40cb70d46cfc9e9024e9c7888b42b077163e',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:127c98bf505d5ed45c69612395b08f36a5e2d661f1d02e4cbdf38e72aa030c8f',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:9eb6a7084ce7b0ec321e81954f4e5dde588bcbfe116da82e798987b30a005cbe',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:25eff7b65351001691c9c8591695338bea23d7272181eda499c624abfb0fd971',
    },
  },
};

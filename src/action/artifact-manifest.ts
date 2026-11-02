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
  tag: 'v0.2.11',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4': '904f93b28a00ea9e2ee3890b2adff9cf87c03c7c10e1e069f5e034f5d84b9b69',
      'rootfs-ubuntu-24.04.ext4': '818501b59f732564f6ea5966f20884930e82ef8a0ec63a91cea638b74652de4c',
      'libscriptjail.so':         '00ad21620189c80228d46ecf50009350906660ee0fd68e0f695108fdccd48251',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4': 'c77b4c1fa6c3f685b559e0e47085dcb905aeb556179254a678a32716c56f9ffd',
      'rootfs-ubuntu-24.04-arm64.ext4': 'ab08c17c1e39ce818fb8133f992778dba38ed1f5f963371a692bceb2e56b8550',
      'libscriptjail-arm64.so':         '865379b96a5b5b79af3d2e0c5125ee71a14340fadbba34fdcc318e2f734e9911',
      // macOS-native Mach-O shim for the bare backend (DYLD_INSERT_LIBRARIES),
      // ad-hoc signed in build-mac-bin; pinned by a plain sha256 of the signed
      // dylib (backfilled from the v0.2.2 producer run 27406262406).
      'libscriptjail-arm64.dylib':      '17c9c74783a1823c51fa46d8a20c32b6528907dede246b52e1fcd7133a397d56',
      // Bare-backend SIP-substitution binaries (the shim redirects /bin/sh +
      // coreutils to these plain-arm64 binaries, so no arm64e dylib is needed).
      // coreutils-arm64 is the official uutils 0.4.0 prebuilt — a fixed upstream
      // artifact with a stable BINARY sha (producer recomputed it to the same
      // value).  bash-arm64 is built-from-source by the producer; byte-identical
      // across the v0.2.0/v0.2.1/v0.2.2 producer runs.
      'coreutils-arm64':                '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21',
      'bash-arm64':                     '8657fa071d05093da842054382bc9112bfaf4462764abc11593d15fd6aca48b5',
      'vmlinux-vz-x86_64':              'd5acbeae749287ff60d782afb47d5d95d5728d4e3e91242e364530f326fdea54',
      'vmlinux-vz-arm64':               '0757e065303d76e01c4fa4b1b1beb692c43020b1132cff71b7abec140bdacff0',
      // No `script-jail-vm-x86_64-darwin` — see the file header for the
      // Intel-macOS-runner deprecation note.
      'script-jail-vm-arm64-darwin':    '2387e0a4f0cd7eac187887ff552bf23cbe11de3af4c5620df15a57800d398472',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:aceb4e18aabc9327ba607213891c25766489d76340d1ce084f9d69a21a3e22e8',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:9a7dbbc20bdffe6901f56527eb15b7974575d629b83ea01d7f69f0ca2bdc3591',
    },
    arm64: {
      'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:26f6a89d30b262282b99e0d76d61977c6a92520699273023deb75196e521bb2d',
      'ubuntu-24.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:3ae672d73ca4b4cce07254265d67df138dd389a0b9e6bf392f0b6eb242853963',
    },
  },
};

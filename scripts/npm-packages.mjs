// script-jail — scripts/npm-packages.mjs
//
// PKG-1: the canonical, single source of truth for the cross-platform npm
// split. `npmPackages(version)` returns the four packages published from a
// release: the tiny main `script-jail` (JS-only) plus three per-platform
// optional packages `@script-jail/{darwin-arm64,linux-x64,linux-arm64}` that
// carry the runtime artifacts (rootfs gz / shim / VZ helper + kernel).
//
// Everything else derives from this module:
//   - scripts/assemble-npm-packages.mjs stages each package's `package.json`
//     and copies/gzips its `artifacts` into the staging dir,
//   - scripts/assert-npm-packlist.mjs gates each staged dir's `npm pack`
//     output against this `files` list and `maxPackBytes`,
//   - the release `publish` job iterates these packages (platform-first, main
//     last) using the sanitized `dir` names.
//
// LOAD-BEARING FILENAME CONTRACT: the platform packages' `files` basenames
// (rootfs-ubuntu-24.04.ext4.gz / rootfs-ubuntu-24.04-arm64.ext4.gz,
// libscriptjail.so / libscriptjail-arm64.so, libscriptjail-arm64.dylib,
// vmlinux-vz-arm64, script-jail-vm) MUST match what `src/shared/artifacts.ts`
// resolves at runtime (Phase 1). A drift would only surface at install time on
// a real Linux/macOS box, so it is mechanically enforced by the
// filename-contract test (Phase 4, Task 4.1). Do not rename these here without
// updating the resolver in lockstep.
//
// This module is the single source of truth for the published main package's
// `files`; the repo-root `package.json` (PKG-4) lists the same entries and is
// guarded against drift by main-package-manifest.test.ts + npm-packages.test.ts.
//
// PRELOADS ARE LISTED EXPLICITLY (not via a `dist/preloads/*.cjs` glob): a glob
// makes the packlist gate (scripts/assert-npm-packlist.mjs) blind to a MISSING
// preload, because it would derive the expected set by globbing the same staged
// dir it checks. Enumerating `MAIN_PRELOADS` lets the gate fail when a required
// preload is absent, and keeps the published set deterministic for a security
// tool (a stray preload cannot ride along, a dropped one cannot slip through).
// scripts/assemble-npm-packages.mjs imports MAIN_PRELOADS so the staged set and
// the gated set come from this one list.
//
// Reproducible-gzip note: artifact gzipping uses Node's `zlib` at a fixed
// level, which is run-to-run deterministic (no mtime / FNAME header). The gz
// bytes intentionally differ from legacy GNU `gzip -n`; nothing pins the
// `.ext4.gz` SHA, so this is the only determinism guarantee required.

const DESCRIPTION =
  'Backend-isolated install auditor for npm/pnpm/yarn lifecycle scripts.';

// Generous cap for platform packages that ship a gzipped ext4 rootfs.
const PLATFORM_MAX_PACK_BYTES = 200 * 1024 * 1024; // 200 MiB
// JS-only main package: a small cap is plenty (and catches accidental
// inclusion of a runtime artifact).
const MAIN_MAX_PACK_BYTES = 16 * 1024 * 1024; // 16 MiB

/**
 * The default preloads injected at build time and shipped by the main package,
 * enumerated explicitly (see header). Basenames under `dist/preloads/`.
 */
export const MAIN_PRELOADS = [
  'env-spy.cjs',
  'platform-spoof.cjs',
  'dlopen-block.cjs',
];

const MAIN_FILES = [
  'dist/cli.cjs',
  'dist/guest-agent.cjs',
  ...MAIN_PRELOADS.map((name) => `dist/preloads/${name}`),
  'README.md',
];

const OPTIONAL_DEP_NAMES = [
  '@script-jail/darwin-arm64',
  '@script-jail/linux-x64',
  '@script-jail/linux-arm64',
];

/**
 * Fields shared by every published `package.json`.
 * @param {string} version
 */
function sharedPackageJson(version) {
  return {
    version,
    description: DESCRIPTION,
    license: 'MIT',
    type: 'module',
    engines: { node: '>=20.0.0' },
    publishConfig: { access: 'public' },
  };
}

/**
 * The canonical 4-package source of truth.
 *
 * @param {string} version  Release version; threaded into every package's
 *   `version` and into the main package's `optionalDependencies` ranges.
 * @returns {Array<{
 *   name: string;
 *   dir: string;
 *   packageJson: Record<string, unknown>;
 *   artifacts: Array<{ src: string; dest: string; gzip?: boolean; mode?: number }>;
 *   maxPackBytes: number;
 * }>}
 */
export function npmPackages(version) {
  const main = {
    name: 'script-jail',
    dir: 'script-jail',
    packageJson: {
      name: 'script-jail',
      ...sharedPackageJson(version),
      bin: { 'script-jail': 'dist/cli.cjs' },
      files: [...MAIN_FILES],
      optionalDependencies: Object.fromEntries(
        OPTIONAL_DEP_NAMES.map((name) => [name, version]),
      ),
    },
    // The main package ships only committed JS bundles + README, which the
    // assembler copies from the build artifacts / repo root — no images/ or
    // bin/ artifact transforms.
    artifacts: [],
    maxPackBytes: MAIN_MAX_PACK_BYTES,
  };

  const darwinArm64 = {
    name: '@script-jail/darwin-arm64',
    dir: 'script-jail-darwin-arm64',
    packageJson: {
      name: '@script-jail/darwin-arm64',
      ...sharedPackageJson(version),
      os: ['darwin'],
      cpu: ['arm64'],
      files: [
        'rootfs-ubuntu-24.04-arm64.ext4.gz',
        'vmlinux-vz-arm64',
        'libscriptjail-arm64.so',
        'libscriptjail-arm64.dylib',
        'coreutils-arm64',
        'bash-arm64',
        'script-jail-vm',
      ],
    },
    artifacts: [
      {
        src: 'images/rootfs-ubuntu-24.04-arm64.ext4',
        dest: 'rootfs-ubuntu-24.04-arm64.ext4.gz',
        gzip: true,
        mode: 0o644,
      },
      { src: 'images/vmlinux-vz-arm64', dest: 'vmlinux-vz-arm64', mode: 0o644 },
      {
        src: 'images/libscriptjail-arm64.so',
        dest: 'libscriptjail-arm64.so',
        mode: 0o644,
      },
      // The macOS-native Mach-O shim (DYLD_INSERT_LIBRARIES, bare backend) is
      // built + ad-hoc signed by the release-build.yml producer `build-mac-bin`
      // job and downloaded to the artifacts ROOT by release.yml as
      // `libscriptjail-arm64.dylib` (alongside `script-jail-vm-arm64-darwin`).
      // It is data, not executable — mode 0o644, mirroring the .so shims.
      {
        src: 'libscriptjail-arm64.dylib',
        dest: 'libscriptjail-arm64.dylib',
        mode: 0o644,
      },
      // Bare-backend SIP-substitution binaries (plain arm64): the shim redirects
      // /bin/sh + /bin/bash → bash-arm64 and coreutils → coreutils-arm64 so no
      // arm64e dylib is needed.  Produced by the `build-mac-bin` producer job
      // (uutils prebuilt fetched + bash built from source) and downloaded to the
      // artifacts ROOT by release.yml.  Executables — mode 0o755.
      { src: 'coreutils-arm64', dest: 'coreutils-arm64', mode: 0o755 },
      { src: 'bash-arm64', dest: 'bash-arm64', mode: 0o755 },
      // The VZ helper Mach-O binary is built by the release-build.yml producer
      // `build-mac-bin` job and downloaded to the artifacts root by release.yml
      // as `script-jail-vm-arm64-darwin`; it ships as the executable
      // `script-jail-vm`.
      {
        src: 'script-jail-vm-arm64-darwin',
        dest: 'script-jail-vm',
        mode: 0o755,
      },
    ],
    maxPackBytes: PLATFORM_MAX_PACK_BYTES,
  };

  const linuxX64 = {
    name: '@script-jail/linux-x64',
    dir: 'script-jail-linux-x64',
    packageJson: {
      name: '@script-jail/linux-x64',
      ...sharedPackageJson(version),
      os: ['linux'],
      cpu: ['x64'],
      files: ['rootfs-ubuntu-24.04.ext4.gz', 'libscriptjail.so'],
    },
    artifacts: [
      {
        src: 'images/rootfs-ubuntu-24.04.ext4',
        dest: 'rootfs-ubuntu-24.04.ext4.gz',
        gzip: true,
        mode: 0o644,
      },
      { src: 'images/libscriptjail.so', dest: 'libscriptjail.so', mode: 0o644 },
    ],
    maxPackBytes: PLATFORM_MAX_PACK_BYTES,
  };

  const linuxArm64 = {
    name: '@script-jail/linux-arm64',
    dir: 'script-jail-linux-arm64',
    packageJson: {
      name: '@script-jail/linux-arm64',
      ...sharedPackageJson(version),
      os: ['linux'],
      cpu: ['arm64'],
      files: ['rootfs-ubuntu-24.04-arm64.ext4.gz', 'libscriptjail-arm64.so'],
    },
    artifacts: [
      {
        src: 'images/rootfs-ubuntu-24.04-arm64.ext4',
        dest: 'rootfs-ubuntu-24.04-arm64.ext4.gz',
        gzip: true,
        mode: 0o644,
      },
      {
        src: 'images/libscriptjail-arm64.so',
        dest: 'libscriptjail-arm64.so',
        mode: 0o644,
      },
    ],
    maxPackBytes: PLATFORM_MAX_PACK_BYTES,
  };

  return [main, darwinArm64, linuxX64, linuxArm64];
}

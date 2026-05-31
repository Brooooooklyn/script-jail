// script-jail — test/scripts/npm-packages.test.ts
//
// PKG-1 guard for the canonical 4-package source of truth
// `scripts/npm-packages.mjs`. This module is the single place that defines the
// names, published `package.json` fields, artifact maps, and per-package pack
// caps for the cross-platform npm split:
//
//   - main `script-jail` (JS-only; no os/cpu; optionalDependencies pinned to
//     the same version),
//   - `@script-jail/darwin-arm64` (rootfs gz + VZ kernel + arm64 shim + VZ
//     helper `script-jail-vm` at mode 0o755),
//   - `@script-jail/linux-x64` (rootfs gz + x64 shim),
//   - `@script-jail/linux-arm64` (rootfs gz + arm64 shim).
//
// Everything else (assemble-npm-packages, assert-npm-packlist, the release
// publish loop) derives from this module — so the contract is asserted here.
//
// The main package's `files` array is a mirror of the authoritative PKG-4
// `package.json`; the platform packages' `files` basenames are a load-bearing
// filename contract with `src/shared/artifacts.ts` (enforced mechanically by
// Phase 4 Task 4.1).

import { describe, it, expect } from 'vitest';
// Types come from the co-located `scripts/npm-packages.d.mts` declaration file.
import { npmPackages } from '../../scripts/npm-packages.mjs';
import type {
  NpmArtifact,
  NpmPackageSpec as NpmPackage,
} from '../../scripts/npm-packages.mjs';

const MAIN_FILES = [
  'dist/cli.cjs',
  'dist/guest-agent.cjs',
  'dist/preloads/*.cjs',
  'README.md',
];

const OPTIONAL_DEP_NAMES = [
  '@script-jail/darwin-arm64',
  '@script-jail/linux-x64',
  '@script-jail/linux-arm64',
];

function byName(version: string): Map<string, NpmPackage> {
  const map = new Map<string, NpmPackage>();
  for (const pkg of npmPackages(version)) {
    map.set(pkg.name, pkg);
  }
  return map;
}

// `Map.get` returns `T | undefined`; every lookup in this suite expects the
// named package to exist, so fail loudly (and narrow the type) if it does not.
function get(map: Map<string, NpmPackage>, name: string): NpmPackage {
  const pkg = map.get(name);
  if (!pkg) throw new Error(`expected npm package ${name}`);
  return pkg;
}

function findArtifact(pkg: NpmPackage, dest: string): NpmArtifact {
  const artifact = pkg.artifacts.find((a) => a.dest === dest);
  if (!artifact) throw new Error(`expected ${pkg.name} artifact dest ${dest}`);
  return artifact;
}

describe('npmPackages (PKG-1)', () => {
  it('returns exactly the four package names', () => {
    const names = npmPackages('0.1.0').map((p) => p.name);
    expect([...names].sort()).toEqual(
      [
        'script-jail',
        '@script-jail/darwin-arm64',
        '@script-jail/linux-x64',
        '@script-jail/linux-arm64',
      ].sort(),
    );
  });

  it('main package has no os/cpu and mirrors PKG-4 files exactly', () => {
    const main = get(byName('0.1.0'), 'script-jail');
    expect(main.packageJson).not.toHaveProperty('os');
    expect(main.packageJson).not.toHaveProperty('cpu');
    expect(main.packageJson.files).toEqual(MAIN_FILES);
    expect(main.packageJson.bin['script-jail']).toBe('dist/cli.cjs');
    expect(main.artifacts).toEqual([]);
  });

  it('main optionalDependencies are the three scoped packages, all pinned to the version', () => {
    const main = get(byName('0.1.0'), 'script-jail');
    const optional = main.packageJson.optionalDependencies;
    expect(Object.keys(optional).sort()).toEqual([...OPTIONAL_DEP_NAMES].sort());
    for (const name of OPTIONAL_DEP_NAMES) {
      expect(optional[name]).toBe('0.1.0');
    }
  });

  it('darwin-arm64 has the exact os/cpu/files', () => {
    const pkg = get(byName('0.1.0'), '@script-jail/darwin-arm64');
    expect(pkg.packageJson.os).toEqual(['darwin']);
    expect(pkg.packageJson.cpu).toEqual(['arm64']);
    expect(pkg.packageJson.files).toEqual([
      'rootfs-ubuntu-24.04-arm64.ext4.gz',
      'vmlinux-vz-arm64',
      'libscriptjail-arm64.so',
      'script-jail-vm',
    ]);
  });

  it('linux-x64 has the exact os/cpu/files', () => {
    const pkg = get(byName('0.1.0'), '@script-jail/linux-x64');
    expect(pkg.packageJson.os).toEqual(['linux']);
    expect(pkg.packageJson.cpu).toEqual(['x64']);
    expect(pkg.packageJson.files).toEqual([
      'rootfs-ubuntu-24.04.ext4.gz',
      'libscriptjail.so',
    ]);
  });

  it('linux-arm64 has the exact os/cpu/files', () => {
    const pkg = get(byName('0.1.0'), '@script-jail/linux-arm64');
    expect(pkg.packageJson.os).toEqual(['linux']);
    expect(pkg.packageJson.cpu).toEqual(['arm64']);
    expect(pkg.packageJson.files).toEqual([
      'rootfs-ubuntu-24.04-arm64.ext4.gz',
      'libscriptjail-arm64.so',
    ]);
  });

  it('darwin VZ helper artifact maps to dest script-jail-vm with mode 0o755', () => {
    const pkg = get(byName('0.1.0'), '@script-jail/darwin-arm64');
    const vmHelper = findArtifact(pkg, 'script-jail-vm');
    expect(vmHelper.mode).toBe(0o755);
    // It is copied (not gzipped) from the mac-bin artifact at the artifacts root.
    expect(vmHelper.gzip).toBeFalsy();
    expect(vmHelper.src).toBe('script-jail-vm-arm64-darwin');
  });

  it('every rootfs artifact is gzipped and lands at a .ext4.gz dest', () => {
    for (const pkg of npmPackages('0.1.0')) {
      for (const artifact of pkg.artifacts) {
        if (artifact.dest.includes('rootfs')) {
          expect(artifact.gzip).toBe(true);
          expect(artifact.dest.endsWith('.ext4.gz')).toBe(true);
          // Source is the raw uncompressed ext4 under images/.
          expect(artifact.src.endsWith('.ext4')).toBe(true);
        }
      }
    }
  });

  it('platform-package shim/kernel artifacts are copied (not gzipped)', () => {
    const expectedNonRootfs = {
      '@script-jail/darwin-arm64': [
        { src: 'images/vmlinux-vz-arm64', dest: 'vmlinux-vz-arm64' },
        { src: 'images/libscriptjail-arm64.so', dest: 'libscriptjail-arm64.so' },
      ],
      '@script-jail/linux-x64': [
        { src: 'images/libscriptjail.so', dest: 'libscriptjail.so' },
      ],
      '@script-jail/linux-arm64': [
        { src: 'images/libscriptjail-arm64.so', dest: 'libscriptjail-arm64.so' },
      ],
    };
    const map = byName('0.1.0');
    for (const [name, expected] of Object.entries(expectedNonRootfs)) {
      const pkg = get(map, name);
      for (const { src, dest } of expected) {
        const artifact = findArtifact(pkg, dest);
        expect(artifact.src).toBe(src);
        expect(artifact.gzip).toBeFalsy();
      }
    }
  });

  it('rootfs gz sources come from images/<raw>.ext4', () => {
    const map = byName('0.1.0');
    expect(
      findArtifact(get(map, '@script-jail/darwin-arm64'), 'rootfs-ubuntu-24.04-arm64.ext4.gz').src,
    ).toBe('images/rootfs-ubuntu-24.04-arm64.ext4');
    expect(
      findArtifact(get(map, '@script-jail/linux-x64'), 'rootfs-ubuntu-24.04.ext4.gz').src,
    ).toBe('images/rootfs-ubuntu-24.04.ext4');
    expect(
      findArtifact(get(map, '@script-jail/linux-arm64'), 'rootfs-ubuntu-24.04-arm64.ext4.gz').src,
    ).toBe('images/rootfs-ubuntu-24.04-arm64.ext4');
  });

  it('shared published fields are present on every package', () => {
    for (const pkg of npmPackages('0.1.0')) {
      expect(pkg.packageJson.version).toBe('0.1.0');
      expect(pkg.packageJson.license).toBe('MIT');
      expect(pkg.packageJson.type).toBe('module');
      expect(pkg.packageJson.publishConfig).toEqual({ access: 'public' });
      expect(pkg.packageJson.engines).toEqual({ node: '>=20.0.0' });
      expect(typeof pkg.packageJson.description).toBe('string');
      expect(pkg.packageJson.description.length).toBeGreaterThan(0);
    }
  });

  it('version threads through every package version and optional-dep value', () => {
    const map = byName('0.1.1');
    for (const pkg of map.values()) {
      expect(pkg.packageJson.version).toBe('0.1.1');
    }
    const optional = get(map, 'script-jail').packageJson.optionalDependencies;
    for (const name of OPTIONAL_DEP_NAMES) {
      expect(optional[name]).toBe('0.1.1');
    }
  });

  it('each platform package has a generous maxPackBytes; main has a small cap', () => {
    const map = byName('0.1.0');
    const platformNames = OPTIONAL_DEP_NAMES;
    for (const name of platformNames) {
      const pkg = get(map, name);
      expect(typeof pkg.maxPackBytes).toBe('number');
      // Generous enough for a gzipped ext4 rootfs (>= 100 MiB).
      expect(pkg.maxPackBytes).toBeGreaterThanOrEqual(100 * 1024 * 1024);
    }
    const main = get(map, 'script-jail');
    expect(typeof main.maxPackBytes).toBe('number');
    expect(main.maxPackBytes).toBeGreaterThan(0);
    // Main is JS-only: its cap must be far below the platform packages' cap.
    expect(main.maxPackBytes).toBeLessThan(get(map, '@script-jail/linux-x64').maxPackBytes);
  });

  it('each package carries a sanitized publish dir name', () => {
    const map = byName('0.1.0');
    expect(get(map, 'script-jail').dir).toBe('script-jail');
    expect(get(map, '@script-jail/darwin-arm64').dir).toBe('script-jail-darwin-arm64');
    expect(get(map, '@script-jail/linux-x64').dir).toBe('script-jail-linux-x64');
    expect(get(map, '@script-jail/linux-arm64').dir).toBe('script-jail-linux-arm64');
  });
});

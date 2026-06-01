// script-jail — test/scripts/filename-contract.test.ts
//
// Phase 4 Task 4.1: the cross-workstream filename-contract binding test
// (WS1 `scripts/npm-packages.mjs` ↔ WS2 `src/shared/artifacts.ts`).
//
// The platform packages' `files` basenames in `scripts/npm-packages.mjs` are a
// LOAD-BEARING contract: at runtime the CLI resolves an installed
// `@script-jail/<os>-<arch>` package dir and asks `resolveArtifacts` for the
// rootfs / kernel / shim paths inside it. If a `files` basename here drifts
// from what the resolver looks up, the package would publish, install, and then
// fail only when the CLI tries to boot the VM on a real Linux/macOS box — long
// after CI. This test mechanically pins the two sides together so a rename in
// either module fails here, in the cheap `unit` vitest project, instead.
//
// `resolveArtifacts` is PURE (no IO, no validation) so we feed it a dummy
// `imagesDir` and compare only basenames; the directory prefix is irrelevant to
// the filename contract.

import { basename } from 'node:path';
import { describe, it, expect } from 'vitest';

import { npmPackages } from '../../scripts/npm-packages.mjs';
import type { NpmPackageSpec } from '../../scripts/npm-packages.mjs';
import { resolveArtifacts } from '../../src/shared/artifacts.js';
import type { ArtifactArch } from '../../src/shared/artifacts.js';

// All platform packages ship the 24.04 rootfs (see npm-packages.mjs).
const UBUNTU_MAJOR = '24.04' as const;

// A dummy artifact directory: `resolveArtifacts` is pure, so the prefix never
// touches disk and only the basenames it produces matter for this contract.
const DUMMY_IMAGES_DIR = '/x';

const packages = npmPackages('0.1.0');

function packageByName(name: string): NpmPackageSpec {
  const pkg = packages.find((p) => p.name === name);
  if (!pkg) throw new Error(`expected npm package ${name} in npmPackages()`);
  return pkg;
}

function filesOf(name: string): string[] {
  return packageByName(name).packageJson.files as string[];
}

function resolvedBasenames(hostArch: ArtifactArch) {
  const resolved = resolveArtifacts({
    imagesDir: DUMMY_IMAGES_DIR,
    hostArch,
    ubuntuMajor: UBUNTU_MAJOR,
  });
  return {
    rootfs: basename(resolved.rootfsPath),
    compressedRootfs: basename(resolved.compressedRootfsPath),
    kernel: basename(resolved.kernelPath),
    libscriptjail: basename(resolved.libscriptjailSoPath),
  };
}

describe('filename contract: npm-packages files ↔ resolveArtifacts basenames', () => {
  it('@script-jail/linux-x64 files match the x64 resolver basenames', () => {
    const files = filesOf('@script-jail/linux-x64');
    const expected = resolvedBasenames('x64');

    // The gzipped rootfs the package ships is what the resolver downloads/looks
    // up at `compressedRootfsPath`.
    expect(files).toContain(expected.compressedRootfs);
    expect(expected.compressedRootfs).toBe('rootfs-ubuntu-24.04.ext4.gz');

    expect(files).toContain(expected.libscriptjail);
    expect(expected.libscriptjail).toBe('libscriptjail.so');
  });

  it('@script-jail/linux-arm64 files match the arm64 resolver basenames', () => {
    const files = filesOf('@script-jail/linux-arm64');
    const expected = resolvedBasenames('arm64');

    expect(files).toContain(expected.compressedRootfs);
    expect(expected.compressedRootfs).toBe('rootfs-ubuntu-24.04-arm64.ext4.gz');

    expect(files).toContain(expected.libscriptjail);
    expect(expected.libscriptjail).toBe('libscriptjail-arm64.so');
  });

  it('@script-jail/darwin-arm64 files match the arm64 resolver basenames (+ kernel)', () => {
    const files = filesOf('@script-jail/darwin-arm64');
    const expected = resolvedBasenames('arm64');

    // macOS boots the same arm64 disk image as Linux/arm64, plus a VZ kernel.
    expect(files).toContain(expected.compressedRootfs);
    expect(expected.compressedRootfs).toBe('rootfs-ubuntu-24.04-arm64.ext4.gz');

    expect(files).toContain(expected.kernel);
    expect(expected.kernel).toBe('vmlinux-vz-arm64');

    expect(files).toContain(expected.libscriptjail);
    expect(expected.libscriptjail).toBe('libscriptjail-arm64.so');

    // The VZ helper Mach-O has no `resolveArtifacts` entry — it is resolved by
    // `src/cli/spawn-vm.ts` from the platform-package root — so we only assert
    // it is present in the darwin `files` list.
    expect(files).toContain('script-jail-vm');
  });

  it('compressedRootfsPath derives as `${rootfsPath}.gz` for both arches', () => {
    for (const hostArch of ['x64', 'arm64'] as const) {
      const resolved = resolveArtifacts({
        imagesDir: DUMMY_IMAGES_DIR,
        hostArch,
        ubuntuMajor: UBUNTU_MAJOR,
      });
      expect(resolved.compressedRootfsPath).toBe(`${resolved.rootfsPath}.gz`);
    }
  });
});

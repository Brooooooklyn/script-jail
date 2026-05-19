// script-jail — test/shared/artifacts.test.ts
//
// Pure-path tests for src/shared/artifacts.ts.  Verifies the per-arch
// filename conventions documented in that file:
//
//   - arm64 → vmlinux-vz-arm64 / rootfs-arm64-vz.ext4 / libscriptjail-arm64.so
//   - x64   → vmlinux-vz-x86_64 / rootfs-x86_64-vz.ext4 / libscriptjail.so
//             (no arch suffix on the .so — backwards compat with the existing
//             release pipeline).

import { describe, it, expect } from 'vitest';

import { manifestKey, resolveArtifacts } from '../../src/shared/artifacts.js';

const FAKE_REPO = '/Users/test/repo';

describe('resolveArtifacts — arm64', () => {
  const arm = resolveArtifacts({
    repoRoot: FAKE_REPO,
    hostArch: 'arm64',
    ubuntuMajor: '24.04',
  });

  it('kernel path encodes kernel-arch arm64', () => {
    expect(arm.kernelPath).toBe('/Users/test/repo/images/vmlinux-vz-arm64');
  });

  it('rootfs path encodes the arm64 suffix matching imageFilename()', () => {
    expect(arm.rootfsPath).toBe(
      '/Users/test/repo/images/rootfs-ubuntu-24.04-arm64.ext4',
    );
  });

  it('libscriptjail.so carries the arch suffix on arm64', () => {
    expect(arm.libscriptjailSoPath).toBe(
      '/Users/test/repo/images/libscriptjail-arm64.so',
    );
  });

  it('host-node staging path lives under images/', () => {
    expect(arm.hostNodePath).toBe('/Users/test/repo/images/host-node.ext4');
  });
});

describe('resolveArtifacts — x64', () => {
  const x64 = resolveArtifacts({
    repoRoot: FAKE_REPO,
    hostArch: 'x64',
    ubuntuMajor: '24.04',
  });

  it('kernel path translates Node x64 → kernel x86_64', () => {
    expect(x64.kernelPath).toBe('/Users/test/repo/images/vmlinux-vz-x86_64');
  });

  it('rootfs path uses the existing Firecracker-pipeline name on x64', () => {
    // VZ reuses the same rootfs image as Firecracker on x64; only the
    // kernel/cmdline differ.  Keeps the release pipeline simple — no new
    // artifact, no manifest churn.
    expect(x64.rootfsPath).toBe(
      '/Users/test/repo/images/rootfs-ubuntu-24.04.ext4',
    );
  });

  it('libscriptjail.so has NO arch suffix on x64 (backwards-compat)', () => {
    // The existing release pipeline produces `images/libscriptjail.so` for
    // x86_64; the arm64 build is the new variant.  Keep the legacy path
    // alive so the macOS x64 CLI works without changes to the release.yml
    // produced asset names.
    expect(x64.libscriptjailSoPath).toBe(
      '/Users/test/repo/images/libscriptjail.so',
    );
  });
});

describe('manifestKey', () => {
  it('kernel key encodes the kernel-arch label (x86_64 / arm64)', () => {
    expect(
      manifestKey({ hostArch: 'x64', ubuntuMajor: '24.04', kind: 'kernel' }),
    ).toBe('vmlinux-vz-x86_64');
    expect(
      manifestKey({ hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'kernel' }),
    ).toBe('vmlinux-vz-arm64');
  });

  it('rootfs key uses the existing Firecracker name on x64', () => {
    expect(
      manifestKey({ hostArch: 'x64', ubuntuMajor: '22.04', kind: 'rootfs' }),
    ).toBe('rootfs-ubuntu-22.04.ext4');
    expect(
      manifestKey({ hostArch: 'x64', ubuntuMajor: '24.04', kind: 'rootfs' }),
    ).toBe('rootfs-ubuntu-24.04.ext4');
  });

  it('rootfs key gets the -arm64 suffix on arm64', () => {
    expect(
      manifestKey({ hostArch: 'arm64', ubuntuMajor: '22.04', kind: 'rootfs' }),
    ).toBe('rootfs-ubuntu-22.04-arm64.ext4');
    expect(
      manifestKey({ hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'rootfs' }),
    ).toBe('rootfs-ubuntu-24.04-arm64.ext4');
  });

  it('libscriptjail key has NO arch suffix on x64, -arm64 on arm64', () => {
    expect(
      manifestKey({
        hostArch: 'x64',
        ubuntuMajor: '24.04',
        kind: 'libscriptjail',
      }),
    ).toBe('libscriptjail.so');
    expect(
      manifestKey({
        hostArch: 'arm64',
        ubuntuMajor: '24.04',
        kind: 'libscriptjail',
      }),
    ).toBe('libscriptjail-arm64.so');
  });

  it('returned key matches the basename of resolveArtifacts() paths', () => {
    // The intent of manifestKey is to let a future fetch path look up the
    // SHA for an artifact resolved by resolveArtifacts.  The two helpers
    // must agree on the filename portion.
    const resolved = resolveArtifacts({
      repoRoot: '/r',
      hostArch: 'arm64',
      ubuntuMajor: '24.04',
    });
    expect(resolved.kernelPath.endsWith(manifestKey({
      hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'kernel',
    }))).toBe(true);
    expect(resolved.rootfsPath.endsWith(manifestKey({
      hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'rootfs',
    }))).toBe(true);
    expect(resolved.libscriptjailSoPath.endsWith(manifestKey({
      hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'libscriptjail',
    }))).toBe(true);
  });
});

describe('resolveArtifacts — ubuntu major versions', () => {
  it('22.04 and 24.04 produce different rootfs paths, same kernel path', () => {
    const a = resolveArtifacts({
      repoRoot: FAKE_REPO,
      hostArch: 'arm64',
      ubuntuMajor: '22.04',
    });
    const b = resolveArtifacts({
      repoRoot: FAKE_REPO,
      hostArch: 'arm64',
      ubuntuMajor: '24.04',
    });
    // Rootfs differs by Ubuntu major (matches imageFilename()).  Kernel does
    // NOT differ — PR 5 ships one VZ kernel per arch, regardless of which
    // userland the rootfs targets.
    expect(a.rootfsPath).toBe('/Users/test/repo/images/rootfs-ubuntu-22.04-arm64.ext4');
    expect(b.rootfsPath).toBe('/Users/test/repo/images/rootfs-ubuntu-24.04-arm64.ext4');
    expect(a.kernelPath).toBe(b.kernelPath);
  });
});

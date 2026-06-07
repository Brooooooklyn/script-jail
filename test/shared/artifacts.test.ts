// script-jail — test/shared/artifacts.test.ts
//
// Pure-path tests for src/shared/artifacts.ts.  Verifies the per-arch
// filename conventions documented in that file:
//
//   - arm64 → vmlinux-vz-arm64 / rootfs-arm64-vz.ext4 / libscriptjail-arm64.so
//   - x64   → vmlinux-vz-x86_64 / rootfs-x86_64-vz.ext4 / libscriptjail.so
//             (no arch suffix on the .so — backwards compat with the existing
//             release pipeline).

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, it, expect } from 'vitest';

import {
  manifestKey,
  resolveArtifacts,
  resolvePlatformPackageDir,
  PlatformPackageMissingError,
} from '../../src/shared/artifacts.js';

const FAKE_REPO = '/Users/test/repo';

// ---------------------------------------------------------------------------
// Fake NodeRequire helpers for resolvePlatformPackageDir injection tests.
//
// No `@script-jail/*` platform package is installed during this phase, so the
// "package" branch is only ever exercised through an injected fake `require`.
// The real, working resolution path until WS2 publishes is the dev fallback.
// ---------------------------------------------------------------------------

/** A fake `require` whose `.resolve` returns a fixed path. */
function fakeRequireResolving(resolvedPath: string): NodeRequire {
  const req = (() => {
    throw new Error('not used');
  }) as unknown as NodeRequire;
  const resolve = (() => resolvedPath) as unknown as NodeRequire['resolve'];
  req.resolve = resolve;
  return req;
}

/** A fake `require` whose `.resolve` throws an error with the given `code`. */
function fakeRequireThrowing(code: string): NodeRequire {
  const req = (() => {
    throw new Error('not used');
  }) as unknown as NodeRequire;
  const resolve = (() => {
    const err = new Error(`cannot resolve (${code})`) as Error & { code?: string };
    err.code = code;
    throw err;
  }) as unknown as NodeRequire['resolve'];
  req.resolve = resolve;
  return req;
}

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
    expect(arm.compressedRootfsPath).toBe(
      '/Users/test/repo/images/rootfs-ubuntu-24.04-arm64.ext4.gz',
    );
  });

  it('libscriptjail.so carries the arch suffix on arm64', () => {
    expect(arm.libscriptjailSoPath).toBe(
      '/Users/test/repo/images/libscriptjail-arm64.so',
    );
  });

  it('macShimDylibPath resolves to the arm64-only Mach-O shim', () => {
    expect(arm.macShimDylibPath).toBe(
      '/Users/test/repo/images/libscriptjail-arm64.dylib',
    );
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
    expect(x64.compressedRootfsPath).toBe(
      '/Users/test/repo/images/rootfs-ubuntu-24.04.ext4.gz',
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

  it('macShimDylibPath is the arm64-only name even on an x64 host', () => {
    // The macOS-native shim is arm64-only (R10); the resolved name carries no
    // x64 variant.  A darwin-x64 host has no published dylib and builds from
    // source, but the pure resolver still returns the canonical arm64 name.
    expect(x64.macShimDylibPath).toBe(
      '/Users/test/repo/images/libscriptjail-arm64.dylib',
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

  it('macshim key is the arm64-only dylib name regardless of host arch', () => {
    // arm64-only (R10): both arches map to the single pinned manifest asset.
    expect(
      manifestKey({ hostArch: 'arm64', ubuntuMajor: '24.04', kind: 'macshim' }),
    ).toBe('libscriptjail-arm64.dylib');
    expect(
      manifestKey({ hostArch: 'x64', ubuntuMajor: '24.04', kind: 'macshim' }),
    ).toBe('libscriptjail-arm64.dylib');
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
    // Rootfs differs by Ubuntu major (matches imageFilename()). Kernel does
    // NOT differ — there is one VZ kernel per arch, regardless of which
    // userland the rootfs targets.
    expect(a.rootfsPath).toBe('/Users/test/repo/images/rootfs-ubuntu-22.04-arm64.ext4');
    expect(b.rootfsPath).toBe('/Users/test/repo/images/rootfs-ubuntu-24.04-arm64.ext4');
    expect(a.compressedRootfsPath).toBe(`${a.rootfsPath}.gz`);
    expect(b.compressedRootfsPath).toBe(`${b.rootfsPath}.gz`);
    expect(a.kernelPath).toBe(b.kernelPath);
  });
});

// ---------------------------------------------------------------------------
// resolvePlatformPackageDir
// ---------------------------------------------------------------------------

describe('resolvePlatformPackageDir', () => {
  // A real, existing directory used as the dev `images/` fallback.  We create
  // a throwaway temp dir so the `existsSync` guard sees it as present.
  const devImagesDir = mkdtempSync(join(tmpdir(), 'script-jail-images-'));

  afterAll(() => {
    rmSync(devImagesDir, { recursive: true, force: true });
  });

  it('uses the installed platform package when require.resolve succeeds', () => {
    const resolved = resolvePlatformPackageDir({
      packageName: '@script-jail/linux-x64',
      require: fakeRequireResolving(
        '/fake/node_modules/@script-jail/linux-x64/package.json',
      ),
      devImagesDir,
    });
    expect(resolved).toEqual({
      imagesDir: '/fake/node_modules/@script-jail/linux-x64',
      source: 'package',
    });
  });

  it('falls back to devImagesDir when require throws MODULE_NOT_FOUND', () => {
    const resolved = resolvePlatformPackageDir({
      packageName: '@script-jail/linux-x64',
      require: fakeRequireThrowing('MODULE_NOT_FOUND'),
      devImagesDir,
    });
    expect(resolved).toEqual({ imagesDir: devImagesDir, source: 'dev' });
  });

  it('falls back when require throws ERR_PACKAGE_PATH_NOT_EXPORTED (fix #5)', () => {
    // Any resolve failure — not only MODULE_NOT_FOUND — must be treated as
    // "package not usable → try devImagesDir".
    const resolved = resolvePlatformPackageDir({
      packageName: '@script-jail/linux-x64',
      require: fakeRequireThrowing('ERR_PACKAGE_PATH_NOT_EXPORTED'),
      devImagesDir,
    });
    expect(resolved).toEqual({ imagesDir: devImagesDir, source: 'dev' });
  });

  it('throws PlatformPackageMissingError when package + devImagesDir both missing', () => {
    const missingDev = join(devImagesDir, 'does-not-exist');
    let thrown: unknown;
    try {
      resolvePlatformPackageDir({
        packageName: '@script-jail/linux-arm64',
        require: fakeRequireThrowing('MODULE_NOT_FOUND'),
        devImagesDir: missingDev,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(PlatformPackageMissingError);
    expect((thrown as Error).message).toContain('@script-jail/linux-arm64');
  });

  it('throws PlatformPackageMissingError when no devImagesDir is given and package missing', () => {
    let thrown: unknown;
    try {
      resolvePlatformPackageDir({
        packageName: '@script-jail/linux-arm64',
        require: fakeRequireThrowing('MODULE_NOT_FOUND'),
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(PlatformPackageMissingError);
    expect((thrown as Error).message).toContain('@script-jail/linux-arm64');
  });
});

// ---------------------------------------------------------------------------
// resolveArtifacts — imagesDir override (platform-package root)
// ---------------------------------------------------------------------------

describe('resolveArtifacts — imagesDir override', () => {
  it('resolves x64 artifacts directly under the provided imagesDir', () => {
    const r = resolveArtifacts({
      imagesDir: '/pkg',
      hostArch: 'x64',
      ubuntuMajor: '24.04',
    });
    expect(r.rootfsPath).toBe('/pkg/rootfs-ubuntu-24.04.ext4');
    expect(r.compressedRootfsPath).toBe('/pkg/rootfs-ubuntu-24.04.ext4.gz');
    expect(r.libscriptjailSoPath).toBe('/pkg/libscriptjail.so');
  });

  it('resolves arm64 artifacts (suffix on rootfs and .so) under imagesDir', () => {
    const r = resolveArtifacts({
      imagesDir: '/pkg',
      hostArch: 'arm64',
      ubuntuMajor: '24.04',
    });
    expect(r.rootfsPath).toBe('/pkg/rootfs-ubuntu-24.04-arm64.ext4');
    expect(r.compressedRootfsPath).toBe('/pkg/rootfs-ubuntu-24.04-arm64.ext4.gz');
    expect(r.libscriptjailSoPath).toBe('/pkg/libscriptjail-arm64.so');
  });

  it('throws when both repoRoot and imagesDir are provided', () => {
    expect(() =>
      resolveArtifacts({
        repoRoot: FAKE_REPO,
        imagesDir: '/pkg',
        hostArch: 'x64',
        ubuntuMajor: '24.04',
      } as unknown as Parameters<typeof resolveArtifacts>[0]),
    ).toThrow();
  });

  it('throws when neither repoRoot nor imagesDir is provided', () => {
    expect(() =>
      resolveArtifacts({
        hostArch: 'x64',
        ubuntuMajor: '24.04',
      } as unknown as Parameters<typeof resolveArtifacts>[0]),
    ).toThrow();
  });
});

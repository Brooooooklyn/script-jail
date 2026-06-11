// script-jail — test/cli/detect-platform.test.ts
//
// Tests for src/cli/detect-platform.ts.  All inputs are injected so the suite
// is cross-platform; no `os.release()` / `process.platform` / `process.arch`
// reads happen here.
//
// detect-platform.ts is the generalized successor to detect-host.ts: it must
// classify both macOS (VZ) and Linux (firecracker/docker/bare) hosts and
// reject everything else (Windows, Intel mac, exotic arches) with typed
// errors whose messages stay actionable.

import { describe, it, expect } from 'vitest';

import {
  detectPlatform,
  platformPackageName,
  NotMacOSError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  NotSupportedPlatformError,
  UnsupportedDarwinArchError,
  MIN_MACOS_MAJOR,
  type DetectedPlatform,
} from '../../src/cli/detect-platform.js';

describe('detectPlatform — darwin', () => {
  it('Darwin 23 (macOS 14 Sonoma) arm64 → {os:darwin, arch:arm64, macosMajor:14}', () => {
    expect(detectPlatform({ platform: 'darwin', release: '23.6.0', arch: 'arm64' }))
      .toEqual({ os: 'darwin', arch: 'arm64', macosMajor: 14 } satisfies DetectedPlatform);
  });

  it('Darwin 24 (macOS 15 Sequoia) arm64 → macosMajor:15', () => {
    expect(detectPlatform({ platform: 'darwin', release: '24.1.0', arch: 'arm64' }))
      .toEqual({ os: 'darwin', arch: 'arm64', macosMajor: 15 } satisfies DetectedPlatform);
  });

  it('Darwin 22 (macOS 13 Ventura) throws UnsupportedMacOSError', () => {
    expect(() => detectPlatform({ platform: 'darwin', release: '22.0.0', arch: 'arm64' }))
      .toThrow(UnsupportedMacOSError);
  });

  it('UnsupportedMacOSError carries resolved major + minimum', () => {
    try {
      detectPlatform({ platform: 'darwin', release: '22.5.0', arch: 'arm64' });
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(UnsupportedMacOSError);
      const e = err as UnsupportedMacOSError;
      expect(e.resolvedMajor).toBe(13);
      expect(e.minimum).toBe(MIN_MACOS_MAJOR);
    }
  });

  it('NaN release throws UnsupportedMacOSError', () => {
    expect(() => detectPlatform({ platform: 'darwin', release: 'not-a-version', arch: 'arm64' }))
      .toThrow(UnsupportedMacOSError);
  });

  it('darwin/x64 (Intel mac) is DETECTED, not rejected — bare backend builds the shim from source', () => {
    // Behaviour change (Phase 5): detection is now backend-agnostic.  The bare
    // macOS backend runs the install natively under the Mach-O shim (no VM), so
    // an Intel mac CAN audit via `--backend bare`.  detectPlatform therefore
    // RETURNS a darwin/x64 capability report rather than throwing.  The VZ-only
    // arm64 gate (darwin + vz + x64 → UnsupportedDarwinArchError) moved into
    // src/cli/index.ts; see the index.test.ts dispatch tests.
    expect(detectPlatform({ platform: 'darwin', release: '23.0.0', arch: 'x64' }))
      .toEqual({ os: 'darwin', arch: 'x64', macosMajor: 14 } satisfies DetectedPlatform);
  });

  it('darwin/x64 still honours the macOS-major floor (Darwin 22 → UnsupportedMacOSError)', () => {
    // The macOS-version gate is shared across arches: an Intel mac on an
    // unsupported macOS still throws before the arch branch is reached.
    expect(() => detectPlatform({ platform: 'darwin', release: '22.0.0', arch: 'x64' }))
      .toThrow(UnsupportedMacOSError);
  });

  it('darwin/ia32 (neither x64 nor arm64) throws UnsupportedArchError', () => {
    expect(() => detectPlatform({ platform: 'darwin', release: '23.0.0', arch: 'ia32' }))
      .toThrow(UnsupportedArchError);
  });

  it('UnsupportedDarwinArchError remains re-exported for the index.ts vz-gating path', () => {
    // detectPlatform no longer throws it, but src/cli/index.ts does (darwin +
    // vz + x64).  Keep the class resolvable so that gate can construct it.
    expect(typeof UnsupportedDarwinArchError).toBe('function');
    expect(new UnsupportedDarwinArchError().message).toMatch(/darwin-x64/);
  });
});

describe('detectPlatform — linux', () => {
  it('linux/x64 → {os:linux, arch:x64} with no macosMajor', () => {
    const result = detectPlatform({ platform: 'linux', release: '6.5.0', arch: 'x64' });
    expect(result).toEqual({ os: 'linux', arch: 'x64' } satisfies DetectedPlatform);
    expect('macosMajor' in result).toBe(false);
  });

  it('linux/arm64 → {os:linux, arch:arm64} with no macosMajor', () => {
    const result = detectPlatform({ platform: 'linux', release: '6.5.0', arch: 'arm64' });
    expect(result).toEqual({ os: 'linux', arch: 'arm64' } satisfies DetectedPlatform);
    expect('macosMajor' in result).toBe(false);
  });

  it('linux/ia32 throws UnsupportedArchError', () => {
    expect(() => detectPlatform({ platform: 'linux', release: '6.5.0', arch: 'ia32' }))
      .toThrow(UnsupportedArchError);
  });
});

describe('detectPlatform — other platforms', () => {
  it('win32 throws NotSupportedPlatformError; message references the GitHub Action', () => {
    try {
      detectPlatform({ platform: 'win32', release: '10.0.19045', arch: 'x64' });
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(NotSupportedPlatformError);
      expect((err as Error).message).toMatch(/GitHub Action/i);
    }
  });

  it('NotMacOSError is re-exported (legacy class still resolvable)', () => {
    expect(typeof NotMacOSError).toBe('function');
  });
});

describe('platformPackageName', () => {
  it('linux-x64', () => {
    expect(platformPackageName({ os: 'linux', arch: 'x64' })).toBe('@script-jail/linux-x64');
  });

  it('linux-arm64', () => {
    expect(platformPackageName({ os: 'linux', arch: 'arm64' })).toBe('@script-jail/linux-arm64');
  });

  it('darwin-arm64', () => {
    expect(platformPackageName({ os: 'darwin', arch: 'arm64', macosMajor: 14 }))
      .toBe('@script-jail/darwin-arm64');
  });
});

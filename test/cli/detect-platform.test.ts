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

  it('darwin/x64 (Intel mac) is rejected; message mentions darwin-x64 / VZ / not supported', () => {
    try {
      detectPlatform({ platform: 'darwin', release: '23.0.0', arch: 'x64' });
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(UnsupportedDarwinArchError);
      const msg = (err as Error).message;
      expect(msg).toContain('darwin-x64');
      expect(msg).toMatch(/Virtualization\.framework|VZ/);
      expect(msg).toMatch(/not supported/i);
    }
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

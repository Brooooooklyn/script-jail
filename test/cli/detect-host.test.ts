// script-jail — test/cli/detect-host.test.ts
//
// Tests for src/cli/detect-host.ts.  All inputs are injected so the suite is
// cross-platform; no `os.release()` / `process.platform` reads happen here.

import { describe, it, expect } from 'vitest';

import {
  detectHost,
  NotMacOSError,
  UnsupportedMacOSError,
  UnsupportedArchError,
} from '../../src/cli/detect-host.js';

describe('detectHost', () => {
  it('returns macosMajor=14 + arm64 on macOS Sonoma (Darwin 23) arm64', () => {
    expect(detectHost({ platform: 'darwin', release: '23.6.0', arch: 'arm64' }))
      .toEqual({ macosMajor: 14, hostArch: 'arm64' });
  });

  it('returns macosMajor=14 + x64 on macOS Sonoma (Darwin 23) x64', () => {
    expect(detectHost({ platform: 'darwin', release: '23.0.0', arch: 'x64' }))
      .toEqual({ macosMajor: 14, hostArch: 'x64' });
  });

  it('returns macosMajor=15 on macOS Sequoia (Darwin 24)', () => {
    expect(detectHost({ platform: 'darwin', release: '24.1.0', arch: 'arm64' }))
      .toEqual({ macosMajor: 15, hostArch: 'arm64' });
  });

  it('throws UnsupportedMacOSError on Darwin 22 (macOS 13 Ventura)', () => {
    expect(() => detectHost({ platform: 'darwin', release: '22.0.0', arch: 'arm64' }))
      .toThrow(UnsupportedMacOSError);
  });

  it('UnsupportedMacOSError carries the resolved major and minimum', () => {
    try {
      detectHost({ platform: 'darwin', release: '22.5.0', arch: 'arm64' });
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(UnsupportedMacOSError);
      const e = err as UnsupportedMacOSError;
      expect(e.resolvedMajor).toBe(13);
      expect(e.minimum).toBe(14);
      expect(e.message).toContain('macOS 14+');
      expect(e.message).toContain('detected macOS 13');
    }
  });

  it('throws NotMacOSError on linux', () => {
    expect(() => detectHost({ platform: 'linux', release: '6.5.0', arch: 'x64' }))
      .toThrow(NotMacOSError);
  });

  it('throws NotMacOSError on win32', () => {
    expect(() => detectHost({ platform: 'win32', release: '10.0.19045', arch: 'x64' }))
      .toThrow(NotMacOSError);
  });

  it('throws UnsupportedArchError on ia32', () => {
    expect(() => detectHost({ platform: 'darwin', release: '23.0.0', arch: 'ia32' }))
      .toThrow(UnsupportedArchError);
  });

  it('NotMacOSError message points to the GitHub Action for Linux CI', () => {
    try {
      detectHost({ platform: 'linux', release: '6.5.0', arch: 'x64' });
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(NotMacOSError);
      expect((err as Error).message).toMatch(/requires macOS/);
      expect((err as Error).message).toMatch(/Linux CI|GitHub Action/i);
    }
  });
});

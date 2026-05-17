// script-jail — test/action/runner-image.test.ts
//
// Tests for detectRunnerImage() — runner-image detection used to pick the
// matching rootfs.  All tests use injection seams so no real process.env or
// filesystem is touched.

import { describe, it, expect } from 'vitest';

import {
  detectRunnerImage,
  UnsupportedRunnerImageError,
  type DetectRunnerImageInput,
} from '../../src/action/runner-image.js';

// ---------------------------------------------------------------------------
// Fake fs helper
// ---------------------------------------------------------------------------

function makeFs(files: Record<string, string>): DetectRunnerImageInput['fs'] {
  return {
    existsSync: (p: string): boolean => Object.prototype.hasOwnProperty.call(files, p),
    readFileSync: (p: string, _enc: 'utf8'): string => {
      const s = files[p];
      if (s === undefined) throw new Error(`ENOENT: ${p}`);
      return s;
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('detectRunnerImage — ImageOS env', () => {
  it('returns ubuntu-22.04 for ImageOS=ubuntu22', () => {
    const r = detectRunnerImage({
      imageOsEnv: 'ubuntu22',
      fs: makeFs({}),
    });
    expect(r).toBe('ubuntu-22.04');
  });

  it('returns ubuntu-24.04 for ImageOS=ubuntu24', () => {
    const r = detectRunnerImage({
      imageOsEnv: 'ubuntu24',
      fs: makeFs({}),
    });
    expect(r).toBe('ubuntu-24.04');
  });

  it('does NOT consult /etc/os-release when ImageOS is a known value', () => {
    // Even if /etc/os-release would have disagreed, ImageOS wins.
    const r = detectRunnerImage({
      imageOsEnv: 'ubuntu24',
      fs: makeFs({
        '/etc/os-release': 'ID=ubuntu\nVERSION_ID="22.04"\n',
      }),
    });
    expect(r).toBe('ubuntu-24.04');
  });
});

describe('detectRunnerImage — /etc/os-release fallback', () => {
  it('falls back to /etc/os-release when ImageOS is unset', () => {
    const r = detectRunnerImage({
      imageOsEnv: undefined,
      fs: makeFs({
        '/etc/os-release': 'ID=ubuntu\nVERSION_ID="22.04"\n',
      }),
    });
    expect(r).toBe('ubuntu-22.04');
  });

  it('falls back to /etc/os-release when ImageOS is empty', () => {
    const r = detectRunnerImage({
      imageOsEnv: '',
      fs: makeFs({
        '/etc/os-release': 'ID=ubuntu\nVERSION_ID="24.04"\n',
      }),
    });
    expect(r).toBe('ubuntu-24.04');
  });

  it('falls back to /etc/os-release on unknown ImageOS values', () => {
    const r = detectRunnerImage({
      imageOsEnv: 'ubuntu20',
      fs: makeFs({
        '/etc/os-release': 'ID=ubuntu\nVERSION_ID="22.04"\n',
      }),
    });
    expect(r).toBe('ubuntu-22.04');
  });

  it('tolerates unquoted VERSION_ID', () => {
    const r = detectRunnerImage({
      imageOsEnv: undefined,
      fs: makeFs({
        '/etc/os-release': 'ID=ubuntu\nVERSION_ID=24.04\n',
      }),
    });
    expect(r).toBe('ubuntu-24.04');
  });

  it('tolerates single-quoted VERSION_ID and ID', () => {
    const r = detectRunnerImage({
      imageOsEnv: undefined,
      fs: makeFs({
        '/etc/os-release': "ID='ubuntu'\nVERSION_ID='22.04'\n",
      }),
    });
    expect(r).toBe('ubuntu-22.04');
  });

  it('tolerates surrounding whitespace, comments, and unrelated keys', () => {
    const r = detectRunnerImage({
      imageOsEnv: undefined,
      fs: makeFs({
        '/etc/os-release': [
          '# os-release sample',
          '',
          'PRETTY_NAME="Ubuntu 24.04.1 LTS"',
          '  NAME="Ubuntu"  ',
          '\tVERSION_ID="24.04"\t',
          'ID=ubuntu',
          'ID_LIKE=debian',
          'HOME_URL="https://www.ubuntu.com/"',
        ].join('\n') + '\n',
      }),
    });
    expect(r).toBe('ubuntu-24.04');
  });
});

describe('detectRunnerImage — error paths', () => {
  it('throws when ImageOS is unset and /etc/os-release does not exist', () => {
    expect(() =>
      detectRunnerImage({
        imageOsEnv: undefined,
        fs: makeFs({}),
      }),
    ).toThrow(
      'script-jail: cannot detect runner image — ImageOS env not set and /etc/os-release missing/unreadable.',
    );
  });

  it('throws when /etc/os-release is unreadable', () => {
    const fs: DetectRunnerImageInput['fs'] = {
      existsSync: (): boolean => true,
      readFileSync: (): string => {
        throw new Error('EACCES: permission denied');
      },
    };
    expect(() =>
      detectRunnerImage({ imageOsEnv: undefined, fs }),
    ).toThrow(
      'script-jail: cannot detect runner image — ImageOS env not set and /etc/os-release missing/unreadable.',
    );
  });

  it('throws UnsupportedRunnerImageError when ID is not ubuntu', () => {
    let err: unknown;
    try {
      detectRunnerImage({
        imageOsEnv: undefined,
        fs: makeFs({
          '/etc/os-release': 'ID=debian\nVERSION_ID="12"\n',
        }),
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(UnsupportedRunnerImageError);
    expect((err as Error).message).toContain('ID=debian');
    expect((err as Error).message).toContain('VERSION_ID=12');
  });

  it('throws UnsupportedRunnerImageError when VERSION_ID is unsupported', () => {
    let err: unknown;
    try {
      detectRunnerImage({
        imageOsEnv: undefined,
        fs: makeFs({
          '/etc/os-release': 'ID=ubuntu\nVERSION_ID="20.04"\n',
        }),
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(UnsupportedRunnerImageError);
    expect((err as Error).message).toContain('ID=ubuntu');
    expect((err as Error).message).toContain('VERSION_ID=20.04');
  });

  it('throws UnsupportedRunnerImageError when ID is missing entirely', () => {
    let err: unknown;
    try {
      detectRunnerImage({
        imageOsEnv: undefined,
        fs: makeFs({
          '/etc/os-release': 'VERSION_ID="22.04"\n',
        }),
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(UnsupportedRunnerImageError);
    // The message should still show what we did/didn't see, including the
    // unset ID, so users can debug.
    expect((err as Error).message).toMatch(/ID=/);
  });
});

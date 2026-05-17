// script-jail — test/action/inputs.test.ts
//
// Tests for parseInputs().  All tests use the injection seams so no real
// process.env or filesystem is touched.

import { describe, it, expect } from 'vitest';
import { join, isAbsolute } from 'node:path';

import { parseInputs, type ParseInput } from '../../src/action/inputs.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeGetInput(map: Record<string, string>): ParseInput['getInput'] {
  return (name: string): string | undefined => map[name];
}

interface FakeFsEntry {
  /** Relative path inside the repo root. */
  name: string;
  contents: string;
}

function makeFs(repoDir: string, files: FakeFsEntry[]): ParseInput['fs'] {
  const byPath = new Map<string, string>();
  for (const f of files) byPath.set(join(repoDir, f.name), f.contents);

  return {
    existsSync: (p: string): boolean => byPath.has(p),
    readFileSync: (p: string, _enc: 'utf8'): string => {
      const s = byPath.get(p);
      if (s === undefined) throw new Error(`ENOENT: ${p}`);
      return s;
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('parseInputs — defaults', () => {
  const repoDir = '/fake/repo';

  it('applies all defaults when no inputs are set', () => {
    const result = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, []),
    });

    expect(result.mode).toBe('check');
    expect(result.spoofPlatform).toBe('linux');
    expect(result.spoofArch).toBe('x64');
    expect(result.cacheFirecracker).toBe(true);
    // Default config/lock paths are resolved relative to repoDir.
    expect(result.configPath).toBe(join(repoDir, '.script-jail.yml'));
    expect(result.lockPath).toBe(join(repoDir, '.script-jail.lock.yml'));
    expect(isAbsolute(result.configPath)).toBe(true);
    expect(isAbsolute(result.lockPath)).toBe(true);
  });
});

describe('parseInputs — mode', () => {
  const repoDir = '/fake/repo';

  it('accepts "check"', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ mode: 'check' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.mode).toBe('check');
  });

  it('accepts "update"', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ mode: 'update' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.mode).toBe('update');
  });

  it('throws on unknown value', () => {
    expect(() =>
      parseInputs({
        repoDir,
        getInput: makeGetInput({ mode: 'bogus' }),
        fs: makeFs(repoDir, []),
      }),
    ).toThrow(/mode/);
  });
});

describe('parseInputs — spoof-platform', () => {
  const repoDir = '/fake/repo';

  it.each(['linux', 'darwin', 'win32'] as const)('accepts %s', (p) => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'spoof-platform': p }),
      fs: makeFs(repoDir, []),
    });
    expect(r.spoofPlatform).toBe(p);
  });

  it('throws on unknown value', () => {
    expect(() =>
      parseInputs({
        repoDir,
        getInput: makeGetInput({ 'spoof-platform': 'freebsd' }),
        fs: makeFs(repoDir, []),
      }),
    ).toThrow(/spoof-platform/);
  });
});

describe('parseInputs — spoof-arch', () => {
  const repoDir = '/fake/repo';

  it.each(['x64', 'arm64'] as const)('accepts %s', (a) => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'spoof-arch': a }),
      fs: makeFs(repoDir, []),
    });
    expect(r.spoofArch).toBe(a);
  });

  it('throws on unknown value', () => {
    expect(() =>
      parseInputs({
        repoDir,
        getInput: makeGetInput({ 'spoof-arch': 'riscv64' }),
        fs: makeFs(repoDir, []),
      }),
    ).toThrow(/spoof-arch/);
  });
});

describe('parseInputs — cache-firecracker', () => {
  const repoDir = '/fake/repo';

  it('parses "true" as true', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'cache-firecracker': 'true' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.cacheFirecracker).toBe(true);
  });

  it('parses "false" as false', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'cache-firecracker': 'false' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.cacheFirecracker).toBe(false);
  });

  it('defaults to true when empty', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'cache-firecracker': '' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.cacheFirecracker).toBe(true);
  });
});

describe('parseInputs — path resolution', () => {
  const repoDir = '/fake/repo';

  it('resolves relative config and lock paths against repoDir', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({
        config: 'configs/jar.yml',
        lock: 'locks/jar.lock.yml',
      }),
      fs: makeFs(repoDir, []),
    });
    expect(r.configPath).toBe(join(repoDir, 'configs/jar.yml'));
    expect(r.lockPath).toBe(join(repoDir, 'locks/jar.lock.yml'));
  });

  it('preserves absolute config and lock paths', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({
        config: '/abs/cfg.yml',
        lock: '/abs/lock.yml',
      }),
      fs: makeFs(repoDir, []),
    });
    expect(r.configPath).toBe('/abs/cfg.yml');
    expect(r.lockPath).toBe('/abs/lock.yml');
  });
});

describe('parseInputs — default getInput from process.env', () => {
  const repoDir = '/fake/repo';

  // GitHub Actions sets one env var per input as `INPUT_<NAME>`, where
  // `<NAME>` has spaces replaced with underscores, is upper-cased, and
  // crucially PRESERVES hyphens.  Compare `@actions/core@3.0.1` lib/core.js
  // `getInput`:  process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`]
  //
  // We assert against the real env-var names a runner would set so that
  // wiring `spoof-platform` / `spoof-arch` / `cache-firecracker` through
  // parseInputs in production actually works.  An earlier version of
  // `defaultGetInput` incorrectly mapped hyphens to underscores, silently
  // breaking every hyphenated input in production — this suite is the gate.
  it('reads non-hyphenated inputs via INPUT_<UPPER> (e.g. mode → INPUT_MODE)', () => {
    const prev = process.env['INPUT_MODE'];
    try {
      process.env['INPUT_MODE'] = 'update';
      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.mode).toBe('update');
    } finally {
      if (prev === undefined) delete process.env['INPUT_MODE'];
      else process.env['INPUT_MODE'] = prev;
    }
  });

  it('reads hyphenated inputs via INPUT_<UPPER-WITH-HYPHENS> (spoof-platform → INPUT_SPOOF-PLATFORM)', () => {
    const prev = process.env['INPUT_SPOOF-PLATFORM'];
    try {
      process.env['INPUT_SPOOF-PLATFORM'] = 'darwin';
      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.spoofPlatform).toBe('darwin');
    } finally {
      if (prev === undefined) delete process.env['INPUT_SPOOF-PLATFORM'];
      else process.env['INPUT_SPOOF-PLATFORM'] = prev;
    }
  });

  it('reads spoof-arch via INPUT_SPOOF-ARCH', () => {
    const prev = process.env['INPUT_SPOOF-ARCH'];
    try {
      process.env['INPUT_SPOOF-ARCH'] = 'arm64';
      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.spoofArch).toBe('arm64');
    } finally {
      if (prev === undefined) delete process.env['INPUT_SPOOF-ARCH'];
      else process.env['INPUT_SPOOF-ARCH'] = prev;
    }
  });

  it('reads cache-firecracker via INPUT_CACHE-FIRECRACKER', () => {
    const prev = process.env['INPUT_CACHE-FIRECRACKER'];
    try {
      process.env['INPUT_CACHE-FIRECRACKER'] = 'false';
      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.cacheFirecracker).toBe(false);
    } finally {
      if (prev === undefined) delete process.env['INPUT_CACHE-FIRECRACKER'];
      else process.env['INPUT_CACHE-FIRECRACKER'] = prev;
    }
  });

  it('does NOT read hyphenated inputs from INPUT_<UPPER>_<UNDER> (regression guard for the old hyphen→underscore bug)', () => {
    // If a runner-set env var with the WRONG (underscore) name is the only
    // thing present, parseInputs must fall back to the action default, not
    // pick it up.  This guards against regressing to the pre-Task #18 fix.
    const prevWrong = process.env['INPUT_SPOOF_PLATFORM'];
    const prevRight = process.env['INPUT_SPOOF-PLATFORM'];
    try {
      // Ensure the correct env name is NOT set so the default-fallback
      // branch is exercised cleanly.
      delete process.env['INPUT_SPOOF-PLATFORM'];
      process.env['INPUT_SPOOF_PLATFORM'] = 'darwin';

      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.spoofPlatform).toBe('linux'); // default, not darwin
    } finally {
      if (prevWrong === undefined) delete process.env['INPUT_SPOOF_PLATFORM'];
      else process.env['INPUT_SPOOF_PLATFORM'] = prevWrong;
      if (prevRight === undefined) delete process.env['INPUT_SPOOF-PLATFORM'];
      else process.env['INPUT_SPOOF-PLATFORM'] = prevRight;
    }
  });
});

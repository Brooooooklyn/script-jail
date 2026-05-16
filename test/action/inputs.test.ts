// npm-jar — test/action/inputs.test.ts
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
    expect(result.nodeVersion).toBe('20');
    // Default config/lock paths are resolved relative to repoDir.
    expect(result.configPath).toBe(join(repoDir, '.npm-jar.yml'));
    expect(result.lockPath).toBe(join(repoDir, '.npm-jar.lock.yml'));
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

describe('parseInputs — node-version resolution', () => {
  const repoDir = '/fake/repo';

  it('uses the literal node-version input when set', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'node-version': '22' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.nodeVersion).toBe('22');
  });

  it('strips a leading "v" from the input', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({ 'node-version': 'v20' }),
      fs: makeFs(repoDir, []),
    });
    expect(r.nodeVersion).toBe('20');
  });

  it('reads .nvmrc when node-version is empty', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [{ name: '.nvmrc', contents: '18.17.0\n' }]),
    });
    expect(r.nodeVersion).toBe('18');
  });

  it('strips leading v from .nvmrc', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [{ name: '.nvmrc', contents: 'v22\n' }]),
    });
    expect(r.nodeVersion).toBe('22');
  });

  it('falls back to engines.node when no .nvmrc', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [
        {
          name: 'package.json',
          contents: JSON.stringify({ engines: { node: '>=21.0.0' } }),
        },
      ]),
    });
    expect(r.nodeVersion).toBe('21');
  });

  it('handles caret in engines.node', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [
        {
          name: 'package.json',
          contents: JSON.stringify({ engines: { node: '^20.10.0' } }),
        },
      ]),
    });
    expect(r.nodeVersion).toBe('20');
  });

  it('prefers .nvmrc over engines.node', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [
        { name: '.nvmrc', contents: '18\n' },
        {
          name: 'package.json',
          contents: JSON.stringify({ engines: { node: '>=22.0.0' } }),
        },
      ]),
    });
    expect(r.nodeVersion).toBe('18');
  });

  it('defaults to "20" when nothing is set', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, []),
    });
    expect(r.nodeVersion).toBe('20');
  });

  it('defaults to "20" when package.json has no engines.node', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [
        { name: 'package.json', contents: JSON.stringify({ name: 'x' }) },
      ]),
    });
    expect(r.nodeVersion).toBe('20');
  });

  it('defaults to "20" when package.json is malformed', () => {
    const r = parseInputs({
      repoDir,
      getInput: makeGetInput({}),
      fs: makeFs(repoDir, [
        { name: 'package.json', contents: 'not json' },
      ]),
    });
    expect(r.nodeVersion).toBe('20');
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

  it('reads INPUT_<UPPER>_<SNAKE> from process.env when no getInput injected', () => {
    const prevMode = process.env['INPUT_MODE'];
    const prevPlatform = process.env['INPUT_SPOOF_PLATFORM'];
    try {
      process.env['INPUT_MODE'] = 'update';
      process.env['INPUT_SPOOF_PLATFORM'] = 'darwin';

      const r = parseInputs({
        repoDir,
        fs: makeFs(repoDir, []),
      });
      expect(r.mode).toBe('update');
      expect(r.spoofPlatform).toBe('darwin');
    } finally {
      if (prevMode === undefined) delete process.env['INPUT_MODE'];
      else process.env['INPUT_MODE'] = prevMode;
      if (prevPlatform === undefined) delete process.env['INPUT_SPOOF_PLATFORM'];
      else process.env['INPUT_SPOOF_PLATFORM'] = prevPlatform;
    }
  });
});

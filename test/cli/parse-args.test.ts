// script-jail — test/cli/parse-args.test.ts
//
// Unit tests for src/cli/parse-args.ts.  The parser is hand-rolled and
// accumulates errors instead of short-circuiting (so the CLI can print every
// problem before exiting); these tests pin that behaviour as well as the
// happy-path defaults / values.

import { describe, it, expect } from 'vitest';

import { parseArgs } from '../../src/cli/parse-args.js';

describe('parseArgs — happy paths', () => {
  it('returns the default ParsedArgs shape for an empty argv', () => {
    const out = parseArgs([]);
    expect(out).toEqual({
      subcommand: null,
      configPath: '.script-jail.yml',
      lockPath: '.script-jail.lock.yml',
      spoofPlatform: 'linux',
      spoofArch: 'x64',
      // `--backend` defaults to null; src/cli/index.ts resolves the effective
      // backend per host (darwin: vz on arm64, bare otherwise).
      backend: null,
      args: [],
      help: false,
      version: false,
      errors: [],
    });
  });

  it('parses a bare `init` subcommand with defaults populated', () => {
    const out = parseArgs(['init']);
    expect(out.subcommand).toBe('init');
    expect(out.configPath).toBe('.script-jail.yml');
    expect(out.lockPath).toBe('.script-jail.lock.yml');
    expect(out.errors).toEqual([]);
  });

  it('parses `update` and `check` subcommands', () => {
    expect(parseArgs(['update']).subcommand).toBe('update');
    expect(parseArgs(['check']).subcommand).toBe('check');
  });

  it('--config <path> populates configPath', () => {
    const out = parseArgs(['check', '--config', 'foo.yml']);
    expect(out.subcommand).toBe('check');
    expect(out.configPath).toBe('foo.yml');
    expect(out.errors).toEqual([]);
  });

  it('--lock <path> populates lockPath', () => {
    const out = parseArgs(['--lock', 'custom.lock.yml']);
    expect(out.lockPath).toBe('custom.lock.yml');
    expect(out.errors).toEqual([]);
  });

  it('--spoof-platform parses valid values', () => {
    for (const p of ['linux', 'darwin', 'win32'] as const) {
      const out = parseArgs(['--spoof-platform', p]);
      expect(out.spoofPlatform).toBe(p);
      expect(out.errors).toEqual([]);
    }
  });

  it('--spoof-arch parses valid values', () => {
    for (const a of ['x64', 'arm64'] as const) {
      const out = parseArgs(['--spoof-arch', a]);
      expect(out.spoofArch).toBe(a);
      expect(out.errors).toEqual([]);
    }
  });

  it('--backend parses valid values (vz | bare); default is null', () => {
    expect(parseArgs([]).backend).toBeNull();
    for (const b of ['vz', 'bare'] as const) {
      const out = parseArgs(['--backend', b]);
      expect(out.backend).toBe(b);
      expect(out.errors).toEqual([]);
    }
  });

  it('--backend pairs with a subcommand without consuming it', () => {
    const out = parseArgs(['check', '--backend', 'bare']);
    expect(out.subcommand).toBe('check');
    expect(out.backend).toBe('bare');
    expect(out.errors).toEqual([]);
  });

  it('-h is an alias for --help', () => {
    expect(parseArgs(['-h']).help).toBe(true);
    expect(parseArgs(['--help']).help).toBe(true);
  });

  it('-V is an alias for --version (uppercase V; lowercase v is unknown)', () => {
    expect(parseArgs(['-V']).version).toBe(true);
    expect(parseArgs(['--version']).version).toBe(true);
  });
});

describe('parseArgs — errors', () => {
  it('--config without a value records an error', () => {
    const out = parseArgs(['--config']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--config requires a value/);
  });

  it('rejects multiple positional args', () => {
    const out = parseArgs(['init', 'check']);
    expect(out.errors.length).toBeGreaterThanOrEqual(1);
    expect(out.errors.join('\n')).toMatch(/unexpected positional argument/);
  });

  it('--spoof-platform with an invalid value errors', () => {
    const out = parseArgs(['--spoof-platform', 'invalid']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--spoof-platform must be one of/);
    expect(out.errors[0]).toMatch(/invalid/);
  });

  it('--spoof-arch with an invalid value errors', () => {
    const out = parseArgs(['--spoof-arch', 'mips']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--spoof-arch must be one of/);
  });

  it('--backend with an invalid value errors (and leaves backend null)', () => {
    const out = parseArgs(['--backend', 'firecracker']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--backend must be one of: vz, bare/);
    expect(out.errors[0]).toMatch(/firecracker/);
    expect(out.backend).toBeNull();
  });

  it('--backend without a value records a requires-a-value error', () => {
    const out = parseArgs(['--backend']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--backend requires a value/);
    expect(out.backend).toBeNull();
  });

  it('rejects an unknown flag', () => {
    const out = parseArgs(['--bogus']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/unknown flag/);
    expect(out.errors[0]).toMatch(/--bogus/);
  });

  it('rejects an unknown positional subcommand', () => {
    const out = parseArgs(['nope']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/unknown subcommand/);
  });
});

describe('parseArgs — multi-error accumulation', () => {
  // The parser is intentionally non-short-circuiting: it records every
  // problem so the CLI can print all of them in one shot.
  it('reports errors for BOTH --config (missing value) and --lock (missing value)', () => {
    const out = parseArgs(['--config', '--lock']);
    expect(out.errors).toHaveLength(2);
    expect(out.errors[0]).toMatch(/--config requires a value/);
    expect(out.errors[1]).toMatch(/--lock requires a value/);
  });

  it('flag-consumes-flag is rejected: --config followed by --help reports config-missing AND still parses --help', () => {
    // Regression for the "argv[++i] consumes the next token as a value even
    // if it starts with `-`" bug.  After the fix, `--config --help` must
    // record a missing-value error for `--config` AND record `help: true`.
    const out = parseArgs(['--config', '--help']);
    expect(out.errors).toHaveLength(1);
    expect(out.errors[0]).toMatch(/--config requires a value/);
    expect(out.help).toBe(true);
  });

  it('accumulates errors for an unknown flag plus an invalid spoof value', () => {
    const out = parseArgs(['--bogus', '--spoof-arch', 'mips']);
    expect(out.errors).toHaveLength(2);
    expect(out.errors[0]).toMatch(/unknown flag/);
    expect(out.errors[1]).toMatch(/--spoof-arch must be one of/);
  });

  it('accumulates an invalid --backend alongside a missing-value --config', () => {
    const out = parseArgs(['--backend', 'docker', '--config']);
    expect(out.errors).toHaveLength(2);
    expect(out.errors[0]).toMatch(/--backend must be one of/);
    expect(out.errors[1]).toMatch(/--config requires a value/);
    // The invalid backend value must NOT be accepted.
    expect(out.backend).toBeNull();
  });
});

describe('parseArgs — --args', () => {
  it('splits a quoted --args value (dash-leading, joined form)', () => {
    const out = parseArgs(['check', '--args=-D --omit=dev']);
    expect(out.errors).toEqual([]);
    expect(out.args).toEqual(['-D', '--omit=dev']);
  });

  it('consumes a dash-leading value in the split form', () => {
    const out = parseArgs(['check', '--args', '-P --frozen-lockfile']);
    expect(out.errors).toEqual([]);
    expect(out.args).toEqual(['-P', '--frozen-lockfile']);
  });

  it('records an error when --args has no value', () => {
    const out = parseArgs(['check', '--args']);
    expect(out.errors).toContain('--args requires a value');
  });

  it('defaults to [] when --args is absent', () => {
    expect(parseArgs(['check']).args).toEqual([]);
  });
});

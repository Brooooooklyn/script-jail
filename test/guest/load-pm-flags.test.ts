// script-jail — test/guest/load-pm-flags.test.ts
//
// The pm-flags sidecar is delivered through the repo-controlled staging
// namespace, so the guest loader MUST re-sanitize what it reads: a backend
// delivery gap (or a repo-committed file the host overlay failed to overwrite)
// must never let a script-re-enabling flag survive into the network-on Phase A
// fetch.  These tests pin that defense-in-depth behavior.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadPmFlags } from '../../src/guest/load-pm-flags.js';

const dirs: string[] = [];
function writeFlags(obj: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'sj-pmflags-'));
  dirs.push(dir);
  const p = join(dir, 'pm-flags.json');
  writeFileSync(p, JSON.stringify(obj), 'utf8');
  return p;
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('loadPmFlags — defense-in-depth sanitize', () => {
  it('strips script-re-enabling user_install_args (double- and single-dash)', () => {
    const p = writeFlags({
      extra_install_args: [],
      user_install_args: [
        '--ignore-scripts',
        'false',
        '-no-ignore-scripts',
        '--config.ignore-scripts=false',
        '-D',
      ],
    });
    // Only the benign `-D` survives; every re-enabler (and the split value
    // token `false`) is dropped.
    expect(loadPmFlags(p)).toEqual({ extraInstallArgs: [], userInstallArgs: ['-D'] });
  });

  it('strips npm/nopt ABBREVIATIONS of ignore-scripts at load', () => {
    const p = writeFlags({
      extra_install_args: [],
      user_install_args: ['--ignore=false', '--ig=false', '--ignore-script', 'false', '-D'],
    });
    expect(loadPmFlags(p)).toEqual({ extraInstallArgs: [], userInstallArgs: ['-D'] });
  });

  it('strips the pnpm DOTTED config alias at load', () => {
    const p = writeFlags({
      extra_install_args: [],
      user_install_args: ['--config.ignore.scripts=false', '--config.ignore.scripts', 'false', '-P'],
    });
    expect(loadPmFlags(p)).toEqual({ extraInstallArgs: [], userInstallArgs: ['-P'] });
  });

  it('re-sanitizes extra_install_args through the arch-hint allowlist (channel survives, steering smuggle dropped)', () => {
    // BOTH array fields flow into the install argv, so both are re-sanitized at
    // this untrusted-file boundary — sanitizing only `user_install_args` would
    // just move the smuggling surface to `extra_install_args`.  This channel is
    // the npm cross-arch hints (`--cpu/--os/--libc`, dormant today), so it has
    // its OWN allowlist: the hints survive, but a steering flag smuggled here
    // (`--dir`) is dropped.
    const p = writeFlags({
      extra_install_args: ['--cpu=arm64', '--os=linux', '--libc=glibc', '--dir', '/tmp/alt'],
      user_install_args: [],
    });
    expect(loadPmFlags(p)).toEqual({
      extraInstallArgs: ['--cpu=arm64', '--os=linux', '--libc=glibc'],
      userInstallArgs: [],
    });
    // The production path (empty channel) is unaffected — byte-identical no-op.
    const empty = writeFlags({ extra_install_args: [], user_install_args: [] });
    expect(loadPmFlags(empty)).toEqual({ extraInstallArgs: [], userInstallArgs: [] });
  });

  it('keeps a clean, benign override untouched', () => {
    const p = writeFlags({ extra_install_args: [], user_install_args: ['--omit=dev', '-P'] });
    expect(loadPmFlags(p)).toEqual({ extraInstallArgs: [], userInstallArgs: ['--omit=dev', '-P'] });
  });

  it('degrades to empty on a missing / malformed file (never throws)', () => {
    expect(loadPmFlags('/nonexistent/pm-flags.json')).toEqual({
      extraInstallArgs: [],
      userInstallArgs: [],
    });
  });
});

// script-jail — test/shared/pm-commands.test.ts
//
// Unit tests for the shared per-PM command tables and the install-arg helpers.

import { describe, it, expect } from 'vitest';

import {
  FETCH_CMD,
  INSTALL_CMD,
  pnpmStoreDirArg,
  sanitizeInstallArgs,
  splitInstallArgs,
} from '../../src/shared/pm-commands.js';

describe('FETCH_CMD / INSTALL_CMD tables', () => {
  it('FETCH_CMD disables lifecycle scripts for every manager', () => {
    expect(FETCH_CMD.npm).toEqual({ cmd: 'npm', args: ['ci', '--ignore-scripts'] });
    expect(FETCH_CMD.pnpm.args).toContain('--ignore-scripts');
    expect(FETCH_CMD.yarn.args).toContain('--mode=skip-build');
  });

  it('INSTALL_CMD runs the deferred scripts and yarn has no --offline', () => {
    expect(INSTALL_CMD.npm).toEqual({ cmd: 'npm', args: ['rebuild', '--foreground-scripts'] });
    expect(INSTALL_CMD.pnpm.args).toContain('--pending');
    expect(INSTALL_CMD.yarn.args).toEqual(['install', '--immutable']);
    expect(INSTALL_CMD.yarn.args).not.toContain('--offline');
  });
});

describe('pnpmStoreDirArg', () => {
  it('returns the repo-local store flag for pnpm only', () => {
    expect(pnpmStoreDirArg('pnpm', '/repo')).toEqual(['--store-dir=/repo/.pnpm-store']);
    expect(pnpmStoreDirArg('npm', '/repo')).toEqual([]);
    expect(pnpmStoreDirArg('yarn', '/repo')).toEqual([]);
  });

  it('roots the store at the given cwd', () => {
    expect(pnpmStoreDirArg('pnpm', '/home/runner/work/app')).toEqual([
      '--store-dir=/home/runner/work/app/.pnpm-store',
    ]);
  });
});

describe('sanitizeInstallArgs', () => {
  it('keeps ordinary install flags untouched', () => {
    expect(sanitizeInstallArgs(['-D', '--omit=dev', '--prod'])).toEqual({
      kept: ['-D', '--omit=dev', '--prod'],
      dropped: [],
      droppedKeys: [],
    });
  });

  it('drops every joined ignore-scripts spelling (kebab/snake/camel, value, no- prefix)', () => {
    const r = sanitizeInstallArgs([
      '--no-ignore-scripts',
      '--ignore-scripts=false',
      '--ignore-scripts=true',
      '--ignore_scripts=false',
      '--ignoreScripts=false',
      '-D',
    ]);
    expect(r.kept).toEqual(['-D']);
    expect(r.dropped).toEqual([
      '--no-ignore-scripts',
      '--ignore-scripts=false',
      '--ignore-scripts=true',
      '--ignore_scripts=false',
      '--ignoreScripts=false',
    ]);
  });

  it('drops the SPLIT boolean form `--ignore-scripts false` WITH its value token', () => {
    // Regression for the critical finding: `npm ci --ignore-scripts
    // --ignore-scripts false` re-enables postinstall.  Both tokens must go.
    expect(sanitizeInstallArgs(['--ignore-scripts', 'false', '-D'])).toEqual({
      kept: ['-D'],
      dropped: ['--ignore-scripts', 'false'],
      droppedKeys: ['--ignore-scripts'],
    });
  });

  it('drops SINGLE-dash long forms (nopt normalizes them — verified against real npm)', () => {
    // Regression for the re-review critical: npm/pnpm collapse any number of
    // leading dashes to the canonical long option, so `-ignore-scripts=false`,
    // `-ignore-scripts false`, and `-no-ignore-scripts` all re-enable scripts.
    expect(sanitizeInstallArgs(['-ignore-scripts=false', '-D'])).toEqual({
      kept: ['-D'],
      dropped: ['-ignore-scripts=false'],
      droppedKeys: ['--ignore-scripts'],
    });
    expect(sanitizeInstallArgs(['-ignore-scripts', 'false', '-D'])).toEqual({
      kept: ['-D'],
      dropped: ['-ignore-scripts', 'false'],
      droppedKeys: ['--ignore-scripts'],
    });
    expect(sanitizeInstallArgs(['-no-ignore-scripts', '-D'])).toEqual({
      kept: ['-D'],
      dropped: ['-no-ignore-scripts'],
      droppedKeys: ['--ignore-scripts'],
    });
    // Triple-dash (and a single-dash yarn --mode) are over-matched on purpose —
    // dropping MORE is the safe direction.
    expect(sanitizeInstallArgs(['---ignore-scripts=false']).dropped).toEqual([
      '---ignore-scripts=false',
    ]);
    expect(sanitizeInstallArgs(['-mode', 'update-lockfile', '-P'])).toEqual({
      kept: ['-P'],
      dropped: ['-mode', 'update-lockfile'],
      droppedKeys: ['--mode'],
    });
  });

  it('drops npm/nopt ABBREVIATIONS of ignore-scripts (verified against real npm)', () => {
    // Regression for the round-3 critical: nopt resolves any unambiguous prefix
    // of a config option, so `--ignore=false`, `--ignore-s=false`, `--ig=false`,
    // and the split `--ignore-script false` all set ignore-scripts.
    expect(sanitizeInstallArgs(['--ignore=false', '-D']).kept).toEqual(['-D']);
    expect(sanitizeInstallArgs(['--ignore-s=false', '-D']).kept).toEqual(['-D']);
    expect(sanitizeInstallArgs(['--ig=false', '-D']).kept).toEqual(['-D']);
    expect(sanitizeInstallArgs(['-ignore=false', '-D']).kept).toEqual(['-D']);
    expect(sanitizeInstallArgs(['--config.ignore=false', '-P']).kept).toEqual(['-P']);
    expect(sanitizeInstallArgs(['--no-ig', '-D']).kept).toEqual(['-D']);
    expect(sanitizeInstallArgs(['--ignore-script', 'false', '-D'])).toEqual({
      kept: ['-D'],
      dropped: ['--ignore-script', 'false'],
      droppedKeys: ['--ignore-scripts'],
    });
  });

  it('preserves legit flags that merely share a leading letter (NOT a prefix of ignore-scripts)', () => {
    // `--include`, `--omit`, `--no-optional`, `-D`, `-P` are not prefixes of
    // "ignorescripts" and must survive.  Only `ignore`-prefixes are dropped.
    for (const arg of ['--include=optional', '--omit=dev', '--no-optional', '-D', '-P', '--prod']) {
      expect(sanitizeInstallArgs([arg]).kept).toEqual([arg]);
    }
  });

  it('preserves the single-letter `--i` (npm expands it to include-workspace-root, NOT ignore-scripts)', () => {
    // Regression for the round-5 medium false-positive: `i` is ambiguous across
    // npm options, so npm resolves `--i` to `--include-workspace-root` (verified
    // on npm 11.13).  Dropping it would silently omit root workspace deps.  The
    // shortest UNAMBIGUOUS ignore-scripts prefix is `ig`, so the drop starts there.
    for (const arg of ['--i', '--i=true', '-i', '--iwr', '--include-workspace-root']) {
      expect(sanitizeInstallArgs([arg]).kept).toEqual([arg]);
    }
    // …but every prefix of length ≥ 2 is still dropped.
    expect(sanitizeInstallArgs(['--ig=false']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--ign=false']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--ignore=false']).kept).toEqual([]);
  });

  it('drops pnpm `--config.ignore-scripts` aliases (joined and split)', () => {
    expect(sanitizeInstallArgs(['--config.ignore-scripts=false', '-P']).kept).toEqual(['-P']);
    expect(sanitizeInstallArgs(['--config.ignore_scripts=false']).dropped).toEqual([
      '--config.ignore_scripts=false',
    ]);
    expect(sanitizeInstallArgs(['--config.ignore-scripts', 'false', '-P'])).toEqual({
      kept: ['-P'],
      dropped: ['--config.ignore-scripts', 'false'],
      droppedKeys: ['--ignore-scripts'],
    });
  });

  it('drops the pnpm DOTTED config alias `--config.ignore.scripts` (verified against real pnpm)', () => {
    // Regression for the round-4 high: pnpm 11.x resolves the dotted form to
    // ignore-scripts, so `.` is a separator just like `-`/`_`.
    expect(sanitizeInstallArgs(['--config.ignore.scripts=false', '-P']).kept).toEqual(['-P']);
    expect(sanitizeInstallArgs(['--config.ignore.scripts', 'false', '-P'])).toEqual({
      kept: ['-P'],
      dropped: ['--config.ignore.scripts', 'false'],
      droppedKeys: ['--ignore-scripts'],
    });
    // A legit dotted pnpm config that is NOT a script control survives.
    expect(sanitizeInstallArgs(['--config.store-dir=/tmp/x']).kept).toEqual([
      '--config.store-dir=/tmp/x',
    ]);
  });

  it('a bare ignore-scripts flag followed by another FLAG does not swallow it', () => {
    expect(sanitizeInstallArgs(['--ignore-scripts', '--omit=dev'])).toEqual({
      kept: ['--omit=dev'],
      dropped: ['--ignore-scripts'],
      droppedKeys: ['--ignore-scripts'],
    });
  });

  it('drops yarn --mode in joined form', () => {
    expect(sanitizeInstallArgs(['--mode=update-lockfile', '-P'])).toEqual({
      kept: ['-P'],
      dropped: ['--mode=update-lockfile'],
      droppedKeys: ['--mode'],
    });
  });

  it('drops yarn --mode in split form WITH its value token (no dangling positional)', () => {
    expect(sanitizeInstallArgs(['--mode', 'update-lockfile', '--prod'])).toEqual({
      kept: ['--prod'],
      dropped: ['--mode', 'update-lockfile'],
      droppedKeys: ['--mode'],
    });
  });

  it('drops yarn lockfile-negating flags (--no-immutable / --immutable=false) — every spelling', () => {
    // Regression for the P2: the fixed base `--immutable` pins the install to the
    // committed yarn.lock; a trailing `--no-immutable` would win (last-flag) and
    // unfreeze the install → unpinned tree.  All spellings canonicalize to
    // `immutable` and must be dropped.
    for (const arg of ['--no-immutable', '--immutable=false', '--config.immutable=false']) {
      expect(sanitizeInstallArgs([arg, '-P']).kept).toEqual(['-P']);
      expect(sanitizeInstallArgs([arg]).droppedKeys).toEqual(['--immutable']);
    }
    // The bare positive `--immutable` (redundant with the fixed flag) is also
    // dropped — harmless, the base already pins it.
    expect(sanitizeInstallArgs(['--immutable']).kept).toEqual([]);
    // A DIFFERENT flag that merely shares the prefix survives (exact match).
    expect(sanitizeInstallArgs(['--immutable-cache']).kept).toEqual(['--immutable-cache']);
  });

  it('drops pnpm lockfile-negating flags (--no-frozen-lockfile / --frozen-lockfile=false) — every spelling', () => {
    // Regression for the P2: the fixed base `--frozen-lockfile` pins pnpm to the
    // committed pnpm-lock.yaml; a trailing negation would unfreeze it.
    for (const arg of [
      '--no-frozen-lockfile',
      '--frozen-lockfile=false',
      '--config.frozen-lockfile=false',
    ]) {
      expect(sanitizeInstallArgs([arg, '-P']).kept).toEqual(['-P']);
      expect(sanitizeInstallArgs([arg]).droppedKeys).toEqual(['--frozen-lockfile']);
    }
  });

  it('drops pnpm ABBREVIATED frozen-lockfile negations (nopt prefix expansion)', () => {
    // pnpm parses via nopt-style abbreviation (like npm), so an UNAMBIGUOUS
    // prefix of `frozen-lockfile` unfreezes the install just like the full
    // spelling — verified against real pnpm 10.34.x.  An exact-match denylist
    // missed these (the P2 hole); the prefix-match must catch every abbreviation
    // and still report the canonical `--frozen-lockfile` reason.
    for (const arg of ['--no-frozen', '--no-froz', '--no-frozen-lock', '--no-frozen-lockfil']) {
      expect(sanitizeInstallArgs([arg, '-P']).kept).toEqual(['-P']);
      expect(sanitizeInstallArgs([arg]).droppedKeys).toEqual(['--frozen-lockfile']);
    }
  });

  it('does NOT over-drop non-frozen flags that merely start with "f"', () => {
    // Only prefixes of `frozenlockfile` resolve to --frozen-lockfile.  `--force`
    // (force), `--filter` (filter), `--fix-lockfile` (fixlockfile) are NOT
    // prefixes and must survive — confirms the prefix-match has no `f*` collision.
    for (const arg of ['--force', '--filter', '--fix-lockfile', '--frozen-lockfile-extra']) {
      expect(sanitizeInstallArgs([arg]).kept).toEqual([arg]);
      expect(sanitizeInstallArgs([arg]).dropped).toEqual([]);
    }
  });
});

describe('splitInstallArgs', () => {
  it('returns [] for empty / blank', () => {
    expect(splitInstallArgs('')).toEqual([]);
    expect(splitInstallArgs('   \t ')).toEqual([]);
  });

  it('splits on whitespace', () => {
    expect(splitInstallArgs('-D --omit=dev -P')).toEqual(['-D', '--omit=dev', '-P']);
  });

  it('groups single- and double-quoted values containing spaces', () => {
    expect(splitInstallArgs('--filter "my pkg" --x \'a b\'')).toEqual([
      '--filter',
      'my pkg',
      '--x',
      'a b',
    ]);
  });

  it('keeps an empty quoted token', () => {
    expect(splitInstallArgs('--name ""')).toEqual(['--name', '']);
  });
});

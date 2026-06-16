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

describe('sanitizeInstallArgs (fail-closed allowlist)', () => {
  // The sanitizer is a FAIL-CLOSED ALLOWLIST: it keeps ONLY canonical flag keys
  // on the proven-safe dependency-SELECTION set and drops everything else,
  // including every unknown flag and every positional.  A denylist was proven
  // structurally unsafe here (steering flags + abbreviations + per-PM aliases
  // are an open-ended surface).  The empirical basis for the short-flag keys
  // (`-D`/`-P` → `d`/`p`) and the steering keys is captured in pm-commands.ts.

  it('empty input is byte-identical (preserves the no-args parity path)', () => {
    expect(sanitizeInstallArgs([])).toEqual({ kept: [], dropped: [], droppedKeys: [] });
  });

  it('MUST-PASS: keeps every allowlisted dependency-selection flag verbatim', () => {
    // Joined value form, boolean forms, the `--no-` negation that folds to an
    // allowlisted key (`--no-optional` → `optional`), and the short flags
    // (`-D`/`-P`, which are pnpm `--dev`/`--prod` and inert npm save flags).
    for (const arg of [
      '--omit=dev',
      '--include=optional',
      '--prod',
      '--production',
      '--dev',
      '--no-optional',
      '-D',
      '-P',
    ]) {
      expect(sanitizeInstallArgs([arg])).toEqual({ kept: [arg], dropped: [], droppedKeys: [] });
    }
  });

  it('MUST-PASS: a SPLIT value-taking allowlisted flag keeps its value token too', () => {
    // `--omit dev` / `--include optional` — the following non-flag token is the
    // value and must travel WITH the flag (not dropped, not left as a positional).
    expect(sanitizeInstallArgs(['--omit', 'optional'])).toEqual({
      kept: ['--omit', 'optional'],
      dropped: [],
      droppedKeys: [],
    });
    expect(sanitizeInstallArgs(['--include', 'optional', '-D'])).toEqual({
      kept: ['--include', 'optional', '-D'],
      dropped: [],
      droppedKeys: [],
    });
  });

  it('MUST-PASS: the documented `-D --omit=dev` example survives intact', () => {
    expect(sanitizeInstallArgs(['-D', '--omit=dev'])).toEqual({
      kept: ['-D', '--omit=dev'],
      dropped: [],
      droppedKeys: [],
    });
  });

  it('boolean allowlisted flags do NOT consume the following token', () => {
    // `-D` / `--prod` are boolean; a following allowlisted flag stays separate,
    // and a following positional is dropped on its OWN iteration (fail-closed).
    expect(sanitizeInstallArgs(['-D', '--prod'])).toEqual({
      kept: ['-D', '--prod'],
      dropped: [],
      droppedKeys: [],
    });
    expect(sanitizeInstallArgs(['--prod', 'some-package'])).toEqual({
      kept: ['--prod'],
      dropped: ['some-package'],
      droppedKeys: ['<positional>'],
    });
  });

  it('MUST-DROP: root/output redirect flags (dir/-C/prefix/modules-dir/virtual-store-dir/store-dir)', () => {
    // These steer WHERE the tree materializes — the proven `--dir alt
    // --modules-dir ../node_modules` bypass family.  Split value tokens consumed.
    expect(sanitizeInstallArgs(['--dir', 'alt'])).toEqual({
      kept: [],
      dropped: ['--dir', 'alt'],
      droppedKeys: ['--dir'],
    });
    expect(sanitizeInstallArgs(['-C', 'alt']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['-C', 'alt']).dropped).toEqual(['-C', 'alt']);
    expect(sanitizeInstallArgs(['--prefix', '/x']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--prefix', '/x']).dropped).toEqual(['--prefix', '/x']);
    expect(sanitizeInstallArgs(['--modules-dir', '../node_modules'])).toEqual({
      kept: [],
      dropped: ['--modules-dir', '../node_modules'],
      droppedKeys: ['--modules-dir'],
    });
    expect(sanitizeInstallArgs(['--virtual-store-dir', 'x']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--virtual-store-dir', 'x']).droppedKeys).toEqual([
      '--virtual-store-dir',
    ]);
    expect(sanitizeInstallArgs(['--store-dir', 'x']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--store-dir', 'x']).droppedKeys).toEqual(['--store-dir']);
  });

  it('MUST-DROP: lockfile location / enforcement family', () => {
    expect(sanitizeInstallArgs(['--lockfile-dir', 'alt'])).toEqual({
      kept: [],
      dropped: ['--lockfile-dir', 'alt'],
      droppedKeys: ['--lockfile-dir'],
    });
    expect(sanitizeInstallArgs(['--lockfile-only']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--no-lockfile']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--lockfile=false']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--fix-lockfile']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--fix']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--no-frozen-lockfile']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--no-frozen']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--no-immutable']).kept).toEqual([]);
  });

  it('MUST-DROP: script re-enable (ignore-scripts + its --no- negation + abbreviation)', () => {
    expect(sanitizeInstallArgs(['--ignore-scripts']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--ignore-scripts']).droppedKeys).toEqual(['--ignore-scripts']);
    expect(sanitizeInstallArgs(['--no-ignore-scripts']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--no-ignore-scripts']).droppedKeys).toEqual(['--ignore-scripts']);
    expect(sanitizeInstallArgs(['--ig']).kept).toEqual([]);
  });

  it('MUST-DROP: scope steering (global/-g/workspace-root/-w/recursive/-r/filter)', () => {
    expect(sanitizeInstallArgs(['--global']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['-g']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--workspace-root']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['-w']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--recursive']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['-r']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--filter', 'pkg'])).toEqual({
      kept: [],
      dropped: ['--filter', 'pkg'],
      droppedKeys: ['--filter'],
    });
  });

  it('MUST-DROP: source swap (registry / config.registry)', () => {
    expect(sanitizeInstallArgs(['--registry=http://evil']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--registry=http://evil']).droppedKeys).toEqual(['--registry']);
    expect(sanitizeInstallArgs(['--config.registry=http://evil']).kept).toEqual([]);
    expect(sanitizeInstallArgs(['--config.registry=http://evil']).droppedKeys).toEqual([
      '--registry',
    ]);
  });

  it('MUST-DROP: a bare positional fails closed and reports <positional> (never the raw token)', () => {
    expect(sanitizeInstallArgs(['some-package'])).toEqual({
      kept: [],
      dropped: ['some-package'],
      droppedKeys: ['<positional>'],
    });
    // A path-shaped positional with a secret-looking value is reported as the
    // grammar constant, NOT the raw value.
    expect(sanitizeInstallArgs(['/tmp/SECRET']).droppedKeys).toEqual(['<positional>']);
  });

  it('MUST-DROP: an unknown flag NEVER echoes its raw key (log-injection / secret-leak safe)', () => {
    // `canonicalFlagKey` strips dashes / `=value` / `no-` / `config.` / `-_.` but
    // NOT newlines, `::`, `%`, or a flag NAME with no `=`.  A dropped unknown flag
    // must report the fixed sentinel `<flag>` so a value like `\n::warning::owned`
    // (GitHub-Actions workflow-command injection) or a credential embedded in the
    // flag name can never reach `hostInstallNoScripts`'s warning log.
    for (const arg of ['--x\n::warning::pwned', '--evilTOKENs3cret', '--%0Aset-output', '--🦝']) {
      const r = sanitizeInstallArgs([arg]);
      expect(r.kept).toEqual([]);
      expect(r.droppedKeys).toEqual(['<flag>']);
      // No entry may carry a newline, ':' command marker, or the secret text.
      for (const k of r.droppedKeys) {
        expect(k).not.toMatch(/[\n\r:%]/);
        expect(k.toLowerCase()).not.toContain('s3cret');
      }
    }
    // Known steering flags still report their FIXED conventional name (helpful,
    // and injection-safe because the switch matches only clean canonical keys).
    expect(sanitizeInstallArgs(['--dir', 'x']).droppedKeys).toEqual(['--dir']);
    // …but an injected variant of a known key (extra chars) falls to <flag>.
    expect(sanitizeInstallArgs(['--dir\n::warning::x']).droppedKeys).toEqual(['<flag>']);
  });

  it('end-to-end bypass family is fully stripped (dir + modules-dir steering removed)', () => {
    // The reproduced pin-bypass: with the OLD denylist this argv installed an
    // alternate locked tree into the root node_modules at exit 0.  Under the
    // allowlist NOTHING survives, so the executed install is just the fixed
    // pinned `pnpm install --frozen-lockfile` (which fails closed on a stale
    // lock with ERR_PNPM_OUTDATED_LOCKFILE — verified against real pnpm).
    const r = sanitizeInstallArgs([
      '--frozen-lockfile',
      '--ignore-scripts',
      '--dir',
      'alt',
      '--modules-dir',
      '../node_modules',
    ]);
    expect(r.kept).toEqual([]);
    expect(r.kept).not.toContain('--dir');
    expect(r.kept).not.toContain('--modules-dir');
  });

  it('value-taking flag value is NOT misread as a value when the flag is dropped', () => {
    // A dropped bare flag still consumes its following non-flag token so the
    // value cannot dangle as a kept positional.  `--registry http://x` (split).
    expect(sanitizeInstallArgs(['--registry', 'http://x', '--prod'])).toEqual({
      kept: ['--prod'],
      dropped: ['--registry', 'http://x'],
      droppedKeys: ['--registry'],
    });
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

// Tests for resolvePrepareCommand (src/guest/agent.ts).
//
// The guest runs a SECOND Phase-B pass to audit the ROOT project's `prepare`
// script, because `npm rebuild --foreground-scripts` and `yarn install
// --immutable` never run a root `prepare`. resolvePrepareCommand decides what
// (if anything) that second pass traces. It returns an ARRAY of commands (empty
// = no prepare pass):
//   - npm  → reads package.json. The single `npm run prepare --if-present` is
//            ALWAYS present (historical behavior — a no-op when prepare is
//            absent), and #44 APPENDS one `npm run <wrapper> --if-present` per
//            present wrapper ONLY when there is no base `prepare` (a real
//            `npm install` runs the wrappers even with no base prepare; a base
//            prepare's single pass already covers pre+prepare+post).
//              • base prepare present → [single]
//              • base absent, wrapper(s) present → [single, ...wrappers]
//              • base + wrappers absent / unreadable / malformed → [single]
//   - yarn → [yarn run prepare] only when package.json has a non-empty
//            `scripts.prepare` (yarn-berry has no --if-present); else [].
//   - pnpm → [] (already covered by `pnpm rebuild --pending`).

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolvePrepareCommand } from '../../src/guest/agent.js';

const NPM_SINGLE = {
  cmd: 'npm',
  args: ['run', 'prepare', '--if-present', '--foreground-scripts'],
};
const npmWrapper = (name: string) => ({
  cmd: 'npm',
  args: ['run', name, '--if-present', '--foreground-scripts'],
});

let dir: string;

beforeEach(() => {
  dir = join(tmpdir(), `sj-resolve-prepare-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
});

afterEach(() => {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function writePkg(scripts: Record<string, unknown> | undefined): void {
  const pkg = scripts === undefined ? { name: 'root', version: '1.0.0' } : { name: 'root', version: '1.0.0', scripts };
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg), 'utf8');
}

describe('resolvePrepareCommand', () => {
  // ---- npm ----
  it('npm WITH a base prepare → [single npm run prepare] (runs the whole triplet)', () => {
    writePkg({ prepare: 'tsc -p .' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  it('npm with a base prepare AND wrappers → still just [single] (one pass runs pre+prepare+post)', () => {
    writePkg({ preprepare: 'a', prepare: 'tsc -p .', postprepare: 'b' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  it('npm unreadable/missing package.json → [single] (historical no-op fallback)', () => {
    // No package.json written → read fails → fall back to the single command,
    // which `--if-present` makes a clean exit-0 no-op when prepare is absent.
    expect(resolvePrepareCommand('npm', '/nonexistent-dir-xyz')).toEqual([NPM_SINGLE]);
  });

  it('npm malformed package.json JSON → [single] (parse error → fallback)', () => {
    writeFileSync(join(dir, 'package.json'), '{ not json', 'utf8');
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  it('#44: npm with preprepare only (no base prepare) → [single, npm run preprepare]', () => {
    writePkg({ preprepare: 'node danger.js' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE, npmWrapper('preprepare')]);
  });

  it('#44: npm with postprepare only (no base prepare) → [single, npm run postprepare]', () => {
    writePkg({ postprepare: 'node danger.js' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE, npmWrapper('postprepare')]);
  });

  it('#44: npm with BOTH wrappers (no base prepare) → [single, preprepare, postprepare] in order', () => {
    writePkg({ postprepare: 'b', preprepare: 'a' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([
      NPM_SINGLE,
      npmWrapper('preprepare'),
      npmWrapper('postprepare'),
    ]);
  });

  it('npm with neither prepare nor wrappers → [single] (historical no-op pass preserved)', () => {
    writePkg({ build: 'tsc -p .' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  it('npm with a non-string wrapper (e.g. number) → ignored, [single] only', () => {
    writePkg({ preprepare: 42, postprepare: '' });
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  it('npm with an empty scripts block → [single]', () => {
    writePkg({});
    expect(resolvePrepareCommand('npm', dir)).toEqual([NPM_SINGLE]);
  });

  // ---- yarn ----
  it('yarn WITH a non-empty prepare script → [yarn run prepare]', () => {
    writePkg({ prepare: 'tsc -p .' });
    expect(resolvePrepareCommand('yarn', dir)).toEqual([{ cmd: 'yarn', args: ['run', 'prepare'] }]);
  });

  it('yarn WITHOUT a prepare script → [] (avoids a wasted exit-1 pass)', () => {
    writePkg({ build: 'tsc -p .' });
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn does NOT get the npm wrapper-only treatment (wrappers ride yarn run prepare)', () => {
    // yarn-berry runs preprepare/postprepare as part of `run prepare`; with no
    // base prepare there is nothing to run, so we skip — no separate wrapper pass.
    writePkg({ preprepare: 'a', postprepare: 'b' });
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn with an empty-string prepare → []', () => {
    writePkg({ prepare: '' });
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn with a non-string prepare (e.g. number) → []', () => {
    writePkg({ prepare: 42 });
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn with no scripts block → []', () => {
    writePkg(undefined);
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn with a missing package.json → [] (read error swallowed)', () => {
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  it('yarn with malformed package.json JSON → [] (parse error swallowed)', () => {
    writeFileSync(join(dir, 'package.json'), '{ this is not json', 'utf8');
    expect(resolvePrepareCommand('yarn', dir)).toEqual([]);
  });

  // ---- pnpm ----
  it('pnpm → [] (root prepare already covered by pnpm rebuild --pending)', () => {
    writePkg({ prepare: 'tsc -p .' });
    expect(resolvePrepareCommand('pnpm', dir)).toEqual([]);
  });
});

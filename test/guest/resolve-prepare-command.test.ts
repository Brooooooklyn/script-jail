// Tests for resolvePrepareCommand (src/guest/agent.ts).
//
// The guest runs a SECOND Phase-B pass to audit the ROOT project's `prepare`
// script, because `npm rebuild --foreground-scripts` and `yarn install
// --immutable` never run a root `prepare`. resolvePrepareCommand decides what
// (if anything) that second pass traces:
//   - npm  → always `npm run prepare --if-present --foreground-scripts`
//            (--if-present makes it a clean exit-0 no-op when absent).
//   - yarn → only when ${cwd}/package.json has a non-empty `scripts.prepare`
//            (yarn-berry has no --if-present; a missing prepare exits 1).
//   - pnpm → null (already covered by `pnpm rebuild --pending`).

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolvePrepareCommand } from '../../src/guest/agent.js';

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
  it('npm → npm run prepare --if-present --foreground-scripts (no package.json read needed)', () => {
    // npm does not read package.json — --if-present is the no-op guard.
    const cmd = resolvePrepareCommand('npm', '/nonexistent-dir');
    expect(cmd).toEqual({
      cmd: 'npm',
      args: ['run', 'prepare', '--if-present', '--foreground-scripts'],
    });
  });

  it('yarn WITH a non-empty prepare script → yarn run prepare', () => {
    writePkg({ prepare: 'tsc -p .' });
    const cmd = resolvePrepareCommand('yarn', dir);
    expect(cmd).toEqual({ cmd: 'yarn', args: ['run', 'prepare'] });
  });

  it('yarn WITHOUT a prepare script → null (avoids a wasted exit-1 pass)', () => {
    writePkg({ build: 'tsc -p .' });
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('yarn with an empty-string prepare → null', () => {
    writePkg({ prepare: '' });
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('yarn with a non-string prepare (e.g. number) → null', () => {
    writePkg({ prepare: 42 });
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('yarn with no scripts block → null', () => {
    writePkg(undefined);
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('yarn with a missing package.json → null (read error swallowed)', () => {
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('yarn with malformed package.json JSON → null (parse error swallowed)', () => {
    writeFileSync(join(dir, 'package.json'), '{ this is not json', 'utf8');
    expect(resolvePrepareCommand('yarn', dir)).toBeNull();
  });

  it('pnpm → null (root prepare already covered by pnpm rebuild --pending)', () => {
    writePkg({ prepare: 'tsc -p .' });
    expect(resolvePrepareCommand('pnpm', dir)).toBeNull();
  });
});

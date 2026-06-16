// script-jail — test/action/backend/stage.test.ts
//
// Tests for stageRepoDirectory() — the shared docker/bare/mac-bare repo
// stager (src/action/backend/stage.ts).

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { stageRepoDirectory } from '../../../src/action/backend/stage.js';

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'script-jail-stage-test-'));
});

afterEach(() => {
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('stageRepoDirectory', () => {
  it('stages only repoDir contents, never host ancestor files (sandbox-isolation invariant)', () => {
    // WHY THIS MATTERS (ancestor-pnpmfile divergence safety):
    //
    // A codex [high] claimed an ANCESTOR `.pnpmfile.mjs` (when repoDir is a
    // subdir of the workspace root) could bypass the install preflight via
    // sandbox-vs-host tree divergence: the host suppresses pnpmfiles with
    // `--ignore-pnpmfile`, but if the SANDBOX ran an ancestor pnpmfile it
    // could rewrite the audited graph while the host stayed blind.
    //
    // That finding is inert ONLY because every backend stages exactly
    // `ctx.repoDir` — a single `cpSync(repoDir, …)` with no parent walk
    // (stage.ts:26; overlay.ts:170 for Firecracker) — and the guest pnpm
    // runs at `/work` = the staged repoDir root.  An ancestor file ABOVE
    // repoDir on the host is therefore never copied into the sandbox and
    // cannot be loaded by the guest pnpm.  This test pins that invariant so
    // a future change that staged the workspace root / an ancestor above
    // `/work` (which WOULD make the codex finding a real bypass) fails loudly
    // instead of silently regressing the security boundary.

    // Parent dir holds sentinel ancestor files that must NOT leak into the
    // stage (these are exactly the pnpm config files the finding worried
    // about).
    const parent = join(testDir, 'workspace-root');
    mkdirSync(parent, { recursive: true });
    writeFileSync(
      join(parent, '.pnpmfile.mjs'),
      'export function readPackage(pkg) { return pkg; }\n',
    );
    writeFileSync(
      join(parent, 'pnpm-workspace.yaml'),
      'packages:\n  - "repo"\n',
    );
    writeFileSync(join(parent, 'ancestor-secret.txt'), 'do-not-stage-me\n');

    // The actual repoDir is a child of the parent and has its own files.
    const repoDir = join(parent, 'repo');
    mkdirSync(join(repoDir, 'src'), { recursive: true });
    writeFileSync(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'inner-repo', version: '1.0.0' }),
    );
    writeFileSync(join(repoDir, 'src', 'index.js'), 'console.log("hi")\n');

    const staged = stageRepoDirectory({
      repoDir,
      parentDir: testDir,
      extraRepoOverlayFiles: [],
    });

    try {
      // The repoDir's own files ARE present in the stage.
      expect(existsSync(join(staged.path, 'package.json'))).toBe(true);
      expect(existsSync(join(staged.path, 'src', 'index.js'))).toBe(true);

      // The ancestor sentinels are NOT present anywhere in the stage root —
      // staging copies repoDir contents directly into the stage root, so any
      // parent-of-repoDir content would have to come from an ancestor walk
      // that does not (and must not) exist.
      expect(existsSync(join(staged.path, '.pnpmfile.mjs'))).toBe(false);
      expect(existsSync(join(staged.path, 'pnpm-workspace.yaml'))).toBe(false);
      expect(existsSync(join(staged.path, 'ancestor-secret.txt'))).toBe(false);

      // And the stage root is the repoDir content itself — there is no nested
      // `repo/` directory and no `workspace-root/`, i.e. the host ancestor
      // chain is absent.
      expect(existsSync(join(staged.path, 'repo'))).toBe(false);
      expect(existsSync(join(staged.path, 'workspace-root'))).toBe(false);
    } finally {
      staged.cleanup();
    }
  });

  it('cleanup() removes the entire stage root, not just the work subdir', () => {
    const repoDir = join(testDir, 'repo');
    mkdirSync(repoDir, { recursive: true });
    writeFileSync(join(repoDir, 'package.json'), '{"name":"x"}');

    const staged = stageRepoDirectory({
      repoDir,
      parentDir: testDir,
      extraRepoOverlayFiles: [],
    });

    expect(existsSync(staged.path)).toBe(true);
    staged.cleanup();
    expect(existsSync(staged.path)).toBe(false);
  });
});

// script-jail — test/scripts/parity-diff.test.ts
//
// These tests drive the workflow script through oxnode so they exercise the
// same parser, canonicalizer, and exit-code contract as parity-test.yml.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const SCRIPT = join(repoRoot, 'scripts/parity-diff.ts');
const OXNODE = join(repoRoot, 'node_modules/.bin/oxnode');

const tempDirs: string[] = [];

afterAll(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function makeWorkspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-parity-diff-'));
  tempDirs.push(dir);
  return dir;
}

function runParityDiff(left: string, right: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    OXNODE,
    [
      SCRIPT,
      '--left', left,
      '--right', right,
      '--left-label', 'linux-backend',
      '--right-label', 'macos-arm64-vz',
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 10_000,
    },
  );

  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

const COMMON_LOCK_PREFIX = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "canonicalized-away"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
`;

describe('scripts/parity-diff.ts', () => {
  it('filters known backend env/network noise and the exact esbuild native self-verify spawn', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX}        env_read:
          - HOSTNAME
          - PATH
          - SCRIPT_JAIL_CONFIG_PATH
          - SCRIPT_JAIL_CONNECTION
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts:
          - <BLOCKED> connect 168.63.129.16:53
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
          - POSIXLY_CORRECT
          - TERM
        spawn_attempts:
          - $PKG/bin/esbuild --version
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('keeps arbitrary spawn divergence visible', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
        spawn_attempts:
          - $PKG/bin/other --version
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$PKG/bin/other --version');
    expect(result.stderr).toBe('');
  });

  it('collapses lists that become empty after parity-only filtering', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX}        env_read: []
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - POSIXLY_CORRECT
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });
});

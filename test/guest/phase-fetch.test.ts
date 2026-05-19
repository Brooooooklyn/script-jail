// Tests for src/guest/phase-fetch.ts
// Injects a mock Spawner; no real processes are spawned.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runFetchPhase, type Spawner, type PhaseFetchInput } from '../../src/guest/phase-fetch.js';

interface SpawnCall {
  cmd: string;
  args: string[];
  opts: { env: NodeJS.ProcessEnv; cwd: string };
}

function mockSpawner(exitCode = 0): { spawner: Spawner; calls: SpawnCall[] } {
  const calls: SpawnCall[] = [];
  const spawner: Spawner = {
    async spawn(cmd, args, opts) {
      calls.push({ cmd, args, opts });
      return { exitCode, stdout: '', stderr: exitCode !== 0 ? 'mock error' : '' };
    },
  };
  return { spawner, calls };
}

const BASE_ENV: NodeJS.ProcessEnv = {
  PATH: '/usr/bin',
  LD_PRELOAD: '/lib/libscriptjail.so',
};

describe('runFetchPhase', () => {
  describe('npm', () => {
    it('runs npm ci --ignore-scripts', async () => {
      const { spawner, calls } = mockSpawner();
      const input: PhaseFetchInput = {
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
      };
      const result = await runFetchPhase(input);
      expect(result.ok).toBe(true);
      expect(calls).toHaveLength(1);
      expect(calls[0]!.cmd).toBe('npm');
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
    });

    it('passes cwd and env to spawner', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner });
      expect(calls[0]!.opts.cwd).toBe('/work');
      expect(calls[0]!.opts.env).toBe(BASE_ENV);
    });

    it('returns ok=false when exitCode != 0', async () => {
      const { spawner } = mockSpawner(1);
      const result = await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner });
      expect(result.ok).toBe(false);
      expect(result.stderr).toBe('mock error');
    });
  });

  describe('pnpm', () => {
    it('runs pnpm fetch with --store-dir pinned to cwd', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner });
      expect(calls[0]!.cmd).toBe('pnpm');
      expect(calls[0]!.args).toEqual(['fetch', '--store-dir=/work/.pnpm-store']);
    });

    it('returns ok=true on success', async () => {
      const { spawner } = mockSpawner(0);
      const result = await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner });
      expect(result.ok).toBe(true);
    });
  });

  describe('yarn', () => {
    it('runs yarn install --immutable --mode=skip-build', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'yarn', cwd: '/work', env: BASE_ENV, spawner });
      expect(calls[0]!.cmd).toBe('yarn');
      expect(calls[0]!.args).toEqual(['install', '--immutable', '--mode=skip-build']);
    });

    it('returns ok=false on failure', async () => {
      const { spawner } = mockSpawner(2);
      const result = await runFetchPhase({ manager: 'yarn', cwd: '/work', env: BASE_ENV, spawner });
      expect(result.ok).toBe(false);
    });
  });

  describe('env passthrough', () => {
    it('passes the full env dict unchanged', async () => {
      const env: NodeJS.ProcessEnv = {
        PATH: '/usr/bin:/usr/local/bin',
        HOME: '/root',
        LD_PRELOAD: '/lib/libscriptjail.so',
        SCRIPT_JAIL_SPOOF_PLATFORM: 'darwin',
      };
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env, spawner });
      expect(calls[0]!.opts.env).toBe(env);
    });
  });

  describe('spy integration', () => {
    it('spawner.spawn is called exactly once per runFetchPhase', async () => {
      const spawnSpy = vi.fn().mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });
      const spawner: Spawner = { spawn: spawnSpy };
      await runFetchPhase({ manager: 'npm', cwd: '/work', env: {}, spawner });
      expect(spawnSpy).toHaveBeenCalledOnce();
    });
  });

  // -------------------------------------------------------------------------
  // pm-flags.json integration (PR 2 — C1 fix)
  // -------------------------------------------------------------------------
  //
  // The macOS CLI lands /etc/script-jail/pm-flags.json with
  // `{ extra_install_args: [...] }` to force a Linux/x64 dependency
  // resolution from an arm64 host (`--cpu=x64 --os=linux --libc=glibc`).
  // Those flags MUST be spliced into Phase A (fetch/resolve) for npm + pnpm.
  // Phase B is too late — the tree is already resolved by then.
  describe('pm-flags.json integration', () => {
    let testDir: string;
    let pmFlagsPath: string;

    beforeEach(() => {
      testDir = mkdtempSync(join(tmpdir(), 'script-jail-fetch-pm-flags-'));
      pmFlagsPath = join(testDir, 'pm-flags.json');
    });
    afterEach(() => {
      try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
    });

    it('appends extra_install_args to npm ci when pm-flags.json is present', async () => {
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] }),
      );
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
      });
      expect(calls[0]!.cmd).toBe('npm');
      expect(calls[0]!.args).toEqual([
        'ci', '--ignore-scripts', '--cpu=x64', '--os=linux', '--libc=glibc',
      ]);
    });

    it('appends extra_install_args to pnpm fetch when pm-flags.json is present', async () => {
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] }),
      );
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
      });
      expect(calls[0]!.cmd).toBe('pnpm');
      expect(calls[0]!.args).toEqual([
        'fetch', '--cpu=x64', '--os=linux', '--libc=glibc',
        '--store-dir=/work/.pnpm-store',
      ]);
    });

    it('leaves yarn argv unchanged even when pm-flags.json is present', async () => {
      // Yarn does not accept --cpu/--os/--libc on the CLI; the equivalent
      // overlay is .yarnrc.yml supportedArchitectures, materialised by the
      // CLI on the repo disk before the VM boots.
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] }),
      );
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'yarn',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
      });
      expect(calls[0]!.cmd).toBe('yarn');
      expect(calls[0]!.args).toEqual(['install', '--immutable', '--mode=skip-build']);
    });

    it('argv is unchanged when pm-flags.json is absent', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath: join(testDir, 'absent.json'),
      });
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
    });

    it('argv is unchanged when pm-flags.json is malformed JSON', async () => {
      writeFileSync(pmFlagsPath, 'not json');
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
      });
      // pm-flags malformed → no extra_install_args spliced; --store-dir
      // is still pinned (it's not pm-flags-derived).
      expect(calls[0]!.args).toEqual(['fetch', '--store-dir=/work/.pnpm-store']);
    });

    it('argv is unchanged when pm-flags.json has the wrong schema', async () => {
      writeFileSync(pmFlagsPath, JSON.stringify({ other_field: 'oops' }));
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
      });
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
    });
  });
});

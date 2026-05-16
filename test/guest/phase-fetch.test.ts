// Tests for src/guest/phase-fetch.ts
// Injects a mock Spawner; no real processes are spawned.

import { describe, it, expect, vi } from 'vitest';
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
  LD_PRELOAD: '/lib/libnpmjar.so',
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
    it('runs pnpm fetch', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner });
      expect(calls[0]!.cmd).toBe('pnpm');
      expect(calls[0]!.args).toEqual(['fetch']);
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
        LD_PRELOAD: '/lib/libnpmjar.so',
        NPM_JAR_SPOOF_PLATFORM: 'darwin',
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
});

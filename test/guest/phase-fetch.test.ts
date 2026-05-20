// Tests for src/guest/phase-fetch.ts
// Injects a mock Spawner; no real processes are spawned.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
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
    it('runs pnpm install --frozen-lockfile --ignore-scripts with --store-dir pinned to cwd', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner });
      expect(calls[0]!.cmd).toBe('pnpm');
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
        '--store-dir=/work/.pnpm-store',
      ]);
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

    it('does NOT splice pm-flags.json into pnpm install (pnpm rejects CLI arch flags)', async () => {
      // pnpm errors on --cpu/--os/--libc.  Even if a pm-flags.json is staged,
      // pnpm install's argv must stay clean — the arch hint goes into
      // package.json via the pnpm-arch.json overlay instead.
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
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
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
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
        '--store-dir=/work/.pnpm-store',
      ]);
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

  // -------------------------------------------------------------------------
  // pnpm-arch.json integration (cross-arch parity for pnpm)
  // -------------------------------------------------------------------------
  //
  // pnpm rejects --cpu/--os/--libc on the CLI, so the macOS CLI instead lands
  // /etc/script-jail/pnpm-arch.json with a `supportedArchitectures` object.
  // Phase A must merge that block into the repo's package.json (under the
  // `pnpm` key) BEFORE `pnpm install` runs, since `pnpm install` reads it to
  // pick which platform variants to download.
  describe('pnpm-arch.json integration', () => {
    let repoDir: string;
    let pnpmArchPath: string;

    const ARCH_OVERLAY =
      '{\n' +
      '  "supportedArchitectures": {\n' +
      '    "os": ["linux"],\n' +
      '    "cpu": ["x64"],\n' +
      '    "libc": ["glibc"]\n' +
      '  }\n' +
      '}\n';

    beforeEach(() => {
      repoDir = mkdtempSync(join(tmpdir(), 'script-jail-fetch-pnpm-arch-'));
      pnpmArchPath = join(repoDir, 'pnpm-arch.json');
    });
    afterEach(() => {
      try { rmSync(repoDir, { recursive: true, force: true }); } catch { /* ignore */ }
    });

    it('merges supportedArchitectures into package.json before pnpm install', async () => {
      writeFileSync(
        join(repoDir, 'package.json'),
        JSON.stringify({ name: 'demo', version: '1.0.0' }, null, 2) + '\n',
      );
      writeFileSync(pnpmArchPath, ARCH_OVERLAY);

      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: repoDir,
        env: BASE_ENV,
        spawner,
        pnpmArchPath,
      });

      // argv stays clean — no CLI arch flags.
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
        `--store-dir=${repoDir}/.pnpm-store`,
      ]);

      const pkg = JSON.parse(
        readFileSync(join(repoDir, 'package.json'), 'utf8'),
      ) as Record<string, unknown>;
      expect(pkg['pnpm']).toEqual({
        supportedArchitectures: { os: ['linux'], cpu: ['x64'], libc: ['glibc'] },
      });
      // Sibling keys preserved.
      expect(pkg['name']).toBe('demo');
      expect(pkg['version']).toBe('1.0.0');
    });

    it('leaves package.json untouched when pnpm-arch.json is absent', async () => {
      const original = JSON.stringify({ name: 'demo' }, null, 2) + '\n';
      writeFileSync(join(repoDir, 'package.json'), original);

      const { spawner } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: repoDir,
        env: BASE_ENV,
        spawner,
        pnpmArchPath: join(repoDir, 'absent.json'),
      });

      expect(
        readFileSync(join(repoDir, 'package.json'), 'utf8'),
      ).toBe(original);
    });

    it('preserves sibling keys inside an existing pnpm block', async () => {
      writeFileSync(
        join(repoDir, 'package.json'),
        JSON.stringify(
          { name: 'demo', pnpm: { overrides: { foo: '1.0.0' } } },
          null,
          2,
        ) + '\n',
      );
      writeFileSync(pnpmArchPath, ARCH_OVERLAY);

      const { spawner } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: repoDir,
        env: BASE_ENV,
        spawner,
        pnpmArchPath,
      });

      const pkg = JSON.parse(
        readFileSync(join(repoDir, 'package.json'), 'utf8'),
      ) as Record<string, unknown>;
      expect(pkg['pnpm']).toEqual({
        overrides: { foo: '1.0.0' },
        supportedArchitectures: { os: ['linux'], cpu: ['x64'], libc: ['glibc'] },
      });
    });

    it('does not consult pnpm-arch.json for npm or yarn', async () => {
      writeFileSync(
        join(repoDir, 'package.json'),
        JSON.stringify({ name: 'demo' }, null, 2) + '\n',
      );
      writeFileSync(pnpmArchPath, ARCH_OVERLAY);

      for (const manager of ['npm', 'yarn'] as const) {
        const original = readFileSync(
          join(repoDir, 'package.json'),
          'utf8',
        );
        const { spawner } = mockSpawner();
        await runFetchPhase({
          manager,
          cwd: repoDir,
          env: BASE_ENV,
          spawner,
          pnpmArchPath,
        });
        // npm/yarn never touch package.json via the pnpm-arch path.
        expect(
          readFileSync(join(repoDir, 'package.json'), 'utf8'),
        ).toBe(original);
      }
    });
  });
});

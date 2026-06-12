// script-jail — test/cli/index.test.ts
//
// Light end-to-end tests for the CLI orchestration in src/cli/index.ts.
// We inject all I/O seams (argv, cwd, stdout/stderr, host/pm/spawn-vm
// detectors) so the suite is fast and cross-platform.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { run, type CliDeps } from '../../src/cli/index.js';
import { NotMacOSError } from '../../src/cli/detect-host.js';
import { MacOSVmNotImplementedError } from '../../src/cli/spawn-vm.js';
import { PINNED_MANIFEST } from '../../src/action/artifact-manifest.js';
import { PlatformPackageMissingError } from '../../src/shared/artifacts.js';

class Sink {
  chunks: string[] = [];
  write(s: string): boolean { this.chunks.push(s); return true; }
  get text(): string { return this.chunks.join(''); }
}

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'script-jail-cli-test-'));
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** Build a fake repo with the named lockfile present so detectPm succeeds. */
function fakeRepo(lockfile: string = 'pnpm-lock.yaml'): string {
  const dir = join(testDir, 'repo');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));
  writeFileSync(join(dir, lockfile), '');
  // The fake repo needs a minimal .script-jail.yml for the config-overlay
  // step to succeed. The contents are intentionally trivial — every test that
  // depends on this stubs out makeOverlay below, so the rewritten config is
  // never actually read by anything downstream.
  writeFileSync(
    join(dir, '.script-jail.yml'),
    'spoof:\n  platform: linux\n  arch: x64\n',
  );
  return dir;
}

function fakeOverlay(workDir: string) {
  // Tests stub makeOverlay to return a fake OverlayResult whose paths look
  // reasonable but never exist on disk.
  // spawnVm is itself stubbed in these tests so the missing files never
  // matter.
  return {
    rootfsCopyPath: join(workDir, 'rootfs.ext4'),
    repoDiskPath: join(workDir, 'repo.ext4'),
    scratchDiskPath: join(workDir, 'scratch.ext4'),
    workDir,
    cleanup: async () => { /* no-op */ },
  };
}

function macOsDeps(over: Partial<CliDeps>): CliDeps {
  // A "happy path" host detector: pretend we're on macOS 14 arm64.  All the
  // post-PR-4 dependencies (overlay) are stubbed so the CLI can exercise its
  // orchestration logic without real fs / VZ access.
  return {
    detectHost: () => ({ macosMajor: 14, hostArch: 'arm64' }),
    makeOverlay: async () => fakeOverlay(testDir),
    ...over,
  };
}

describe('CLI — --help / --version', () => {
  it('--help prints usage with init/update/check and exits 0', async () => {
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run({
      argv: ['--help'],
      stdout, stderr,
    });
    expect(code).toBe(0);
    expect(stdout.text).toMatch(/init/);
    expect(stdout.text).toMatch(/update/);
    expect(stdout.text).toMatch(/check/);
    expect(stderr.text).toBe('');
  });

  it('--version prints the version and exits 0', async () => {
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run({ argv: ['--version'], stdout, stderr });
    expect(code).toBe(0);
    expect(stdout.text.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('unknown flag exits 1 and prints an error + usage', async () => {
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run({
      argv: ['--unknown-flag'],
      stdout, stderr,
    });
    expect(code).toBe(1);
    expect(stderr.text).toMatch(/unknown flag/);
    expect(stderr.text).toMatch(/Usage:/);
  });
});

describe('CLI — host gating', () => {
  it('exits 1 with a "macOS required" message on non-darwin', async () => {
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run({
      argv: ['init'],
      cwd: () => fakeRepo(),
      stdout, stderr,
      detectHost: () => { throw new NotMacOSError('linux'); },
    });
    expect(code).toBe(1);
    expect(stderr.text).toMatch(/requires macOS/);
    expect(stdout.text).toBe('');
  });
});

describe('CLI — VM-launch stub', () => {
  it('surfaces injected spawnVm errors via stderr and exits 1', async () => {
    // The dependency-injection seam stays intact: tests can still stub
    // `spawnVm` to throw, and the CLI must surface the message verbatim to
    // stderr. We keep
    // `MacOSVmNotImplementedError` exported for backwards compat with this
    // test, which exercises the generic "spawnVm threw" code path.
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run(macOsDeps({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      spawnVm: async () => { throw new MacOSVmNotImplementedError('synthetic test error'); },
    }));
    expect(code).toBe(1);
    expect(stderr.text).toMatch(/synthetic test error/);
  });

  it('hostArch passed to buildArchFlagOverlay comes from detectHost return value, not process.arch (I2)', async () => {
    // Regression for issue I2: pre-fix, hostArch was re-derived from
    // `process.arch` after the detectHost call, so an injected detectHost
    // returning `{ hostArch: 'arm64' }` had no effect on the overlay.
    // Post-fix, the overlay's hostArch must equal the injected value
    // regardless of the dev box's real process.arch.
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let capturedHostArch: string | null = null;
    const code = await run({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      // Injected arm64 host even from an x64 dev box.
      detectHost: () => ({ macosMajor: 15, hostArch: 'arm64' }),
      buildArchFlagOverlay: (input) => {
        capturedHostArch = input.hostArch;
        // Return the real shape to keep the rest of run() happy.
        return { warnings: [], pmFlagsJson: { extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] } };
      },
      makeOverlay: async () => fakeOverlay(testDir),
      spawnVm: async () => { throw new MacOSVmNotImplementedError(); },
    });
    expect(code).toBe(1);
    expect(capturedHostArch).toBe('arm64');
  });

  it('hostArch=x64 from detectHost reaches buildArchFlagOverlay even on an arm64 dev box (now via the bare backend)', async () => {
    // The complementary half of the I2 regression: injecting `x64` from
    // an arm64 dev box must also be honoured.  Without the fix, hostArch
    // would mirror process.arch.
    //
    // Behaviour change (Phase 5): darwin/x64 now defaults to the `bare`
    // backend (VZ is arm64-only), so this exercises runMacBare → runAudit.
    // `buildArchFlagOverlay` is still threaded into runAudit's input on the
    // bare path; we capture it from the injected runAudit (which never runs a
    // real VM) and invoke it to assert the propagated hostArch.
    const repoDir = fakeRepo('package-lock.json');
    let capturedHostArch: string | null = null;
    const code = await run({
      argv: ['init'],
      cwd: () => repoDir,
      stdout: new Sink(),
      stderr: new Sink(),
      detectHost: () => ({ macosMajor: 14, hostArch: 'x64' }),
      runAudit: async (input) => {
        // The CLI threads its buildArchFlagOverlay through to runAudit; drive
        // it once with the audit's hostArch (as the real runAudit would).
        const buildOverlay = input.buildArchFlagOverlay;
        if (buildOverlay) {
          buildOverlay({
            pm: input.pm,
            hostArch: input.hostArch,
            spoofPlatform: input.overrides.spoofPlatform ?? 'linux',
            spoofArch: input.overrides.spoofArch ?? input.hostArch,
          });
        }
        return { exitCode: 0 };
      },
      buildArchFlagOverlay: (input) => {
        capturedHostArch = input.hostArch;
        return { warnings: [] };
      },
    });
    expect(code).toBe(0);
    expect(capturedHostArch).toBe('x64');
  });

  it('defaults spoofArch to the detected host arch when --spoof-arch is omitted', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    let capturedSpoofArch: string | null = null;

    const code = await run(macOsDeps({
      argv: ['init'],
      cwd: () => repoDir,
      detectHost: () => ({ macosMajor: 15, hostArch: 'arm64' }),
      runAudit: async (input) => {
        capturedSpoofArch = input.overrides.spoofArch ?? null;
        return { exitCode: 0 };
      },
    }));

    expect(code).toBe(0);
    expect(capturedSpoofArch).toBe('arm64');
  });

  it('honours an explicit --spoof-arch over the detected host arch', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    let capturedSpoofArch: string | null = null;

    const code = await run(macOsDeps({
      argv: ['init', '--spoof-arch', 'x64'],
      cwd: () => repoDir,
      detectHost: () => ({ macosMajor: 15, hostArch: 'arm64' }),
      runAudit: async (input) => {
        capturedSpoofArch = input.overrides.spoofArch ?? null;
        return { exitCode: 0 };
      },
    }));

    expect(code).toBe(0);
    expect(capturedSpoofArch).toBe('x64');
  });

  it('defaults to init when no lockfile yet exists and check otherwise', async () => {
    // No subcommand + no .script-jail.lock.yml → init (mode=update).
    // We verify by inspecting the VmConfig handed to spawnVm.
    const repoDir = fakeRepo('package-lock.json');
    let capturedMode: string | null = null;
    const stderr = new Sink();
    const code = await run(macOsDeps({
      argv: [], // no subcommand
      cwd: () => repoDir,
      stderr,
      spawnVm: async (cfg) => {
        capturedMode = cfg.mode;
        throw new MacOSVmNotImplementedError();
      },
    }));
    expect(code).toBe(1);
    expect(capturedMode).toBe('update');

    // Now create the lockfile and re-run → should default to check.
    writeFileSync(join(repoDir, '.script-jail.lock.yml'), '# stub\n');
    capturedMode = null;
    await run(macOsDeps({
      argv: [],
      cwd: () => repoDir,
      stderr,
      spawnVm: async (cfg) => {
        capturedMode = cfg.mode;
        throw new MacOSVmNotImplementedError();
      },
    }));
    expect(capturedMode).toBe('check');
  });
});

describe('CLI — macOS backend selection (vz vs bare)', () => {
  // detectPlatform seam: report a concrete darwin host so the CLI's
  // effective-backend resolution (args.backend ?? (arm64 ? vz : bare)) and the
  // darwin+vz+x64 gate are exercised without reading the real host.
  function macPlatformDeps(
    platform: { os: 'darwin'; arch: 'x64' | 'arm64'; macosMajor: number },
    over: Partial<CliDeps>,
  ): CliDeps {
    return {
      detectPlatform: () => platform,
      resolvePlatformPackageDir: () => ({ imagesDir: join(testDir, 'pkg'), source: 'dev' }),
      ...over,
    };
  }

  it('darwin/x64 + explicit --backend vz → exits 1 with the Intel-mac VZ error (gate lives in index.ts)', async () => {
    // detectPlatform now RETURNS darwin/x64 (it no longer throws); the VZ-only
    // arm64 gate is enforced here in the CLI.  An Intel mac that explicitly
    // asks for `--backend vz` must hit the typed UnsupportedDarwinArchError
    // message and exit 1 BEFORE any provisioning/VM work.
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let reachedExecute = false;
    let reachedAudit = false;
    const code = await run(macPlatformDeps(
      { os: 'darwin', arch: 'x64', macosMajor: 14 },
      {
        argv: ['check', '--backend', 'vz'],
        cwd: () => repoDir,
        stdout, stderr,
        createMacBareExecute: () => { reachedExecute = true; return async () => ({ finalYaml: '', nonFatalWarnings: [] }); },
        runAudit: async () => { reachedAudit = true; return { exitCode: 0 }; },
        spawnVm: async () => { throw new MacOSVmNotImplementedError(); },
      },
    ));
    expect(code).toBe(1);
    expect(stderr.text).toMatch(/darwin-x64/);
    expect(stderr.text).toMatch(/Virtualization\.framework|VZ/);
    // The gate fires before backend execution: neither the bare execute nor
    // runAudit is reached.
    expect(reachedExecute).toBe(false);
    expect(reachedAudit).toBe(false);
  });

  it('darwin/x64 defaults to the bare backend → builds createMacBareExecute and hands runAudit an execute closure', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let macBareArgs: Record<string, unknown> | null = null;
    let capturedExecute: unknown = null;
    const code = await run(macPlatformDeps(
      { os: 'darwin', arch: 'x64', macosMajor: 14 },
      {
        argv: ['check'], // no --backend → x64 defaults to bare
        cwd: () => repoDir,
        stdout, stderr,
        createMacBareExecute: (deps) => {
          macBareArgs = deps as unknown as Record<string, unknown>;
          return async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] });
        },
        runAudit: async (input) => {
          capturedExecute = input.execute ?? null;
          // The bare path must NOT use the VZ launch closure.
          expect(input.launch).toBeUndefined();
          expect(input.hostArch).toBe('x64');
          return { exitCode: 0 };
        },
      },
    ));
    expect(code).toBe(0);
    expect(macBareArgs).not.toBeNull();
    expect(macBareArgs!['arch']).toBe('x64');
    expect(typeof capturedExecute).toBe('function');
  });

  it('darwin/arm64 + explicit --backend bare → uses the bare backend (overrides the vz default)', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let builtBare = false;
    const code = await run(macPlatformDeps(
      { os: 'darwin', arch: 'arm64', macosMajor: 15 },
      {
        argv: ['check', '--backend', 'bare'],
        cwd: () => repoDir,
        stdout, stderr,
        createMacBareExecute: (deps) => {
          builtBare = true;
          expect((deps as unknown as Record<string, unknown>)['arch']).toBe('arm64');
          return async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] });
        },
        runAudit: async (input) => {
          expect(typeof input.execute).toBe('function');
          return { exitCode: 0 };
        },
        // If the vz default leaked through, spawnVm would throw and fail us.
        spawnVm: async () => { throw new MacOSVmNotImplementedError('vz path should not run'); },
      },
    ));
    expect(code).toBe(0);
    expect(builtBare).toBe(true);
  });
});

describe('CLI — Linux backend wiring', () => {
  // Linux deps factory: pretend we're on a Linux x64 host. The platform
  // package is resolved via an injected seam to the dev images/ fallback, and
  // backend execution is short-circuited via the `runSelectedBackend` seam so
  // these smoke tests never `.run()` a real backend or probe /dev/kvm/docker.
  function linuxDeps(over: Partial<CliDeps>): CliDeps {
    return {
      detectPlatform: () => ({ os: 'linux', arch: 'x64' }),
      // Resolve to a real-looking dir so resolvePlatformPackageDir's default
      // is never reached; tests that want the missing-package path override it.
      resolvePlatformPackageDir: () => ({ imagesDir: join(testDir, 'pkg'), source: 'dev' }),
      // Default: never actually run a backend.
      runSelectedBackend: async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] }),
      ...over,
    };
  }

  it('LINUX smoke: hands runAudit an execute closure (not launch) with hostArch from detectPlatform', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let captured: Record<string, unknown> | null = null;
    const code = await run(linuxDeps({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      runAudit: async (input) => {
        captured = input as unknown as Record<string, unknown>;
        return { exitCode: 0 };
      },
    }));
    expect(code).toBe(0);
    expect(captured).not.toBeNull();
    expect(typeof captured!['execute']).toBe('function');
    expect(captured!['launch']).toBeUndefined();
    expect(captured!['hostArch']).toBe('x64');
    expect(captured!['baseRootfsPath']).toBeUndefined();
  });

  it('LINUX ctx: execute(...) routes through runSelectedBackend with the right backend context', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let capturedCtx: Record<string, unknown> | null = null;
    let capturedRequested: string | null = null;
    const code = await run(linuxDeps({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      // Real runAudit override that drives the execute closure once so the CLI
      // actually builds the BackendContext and calls runSelectedBackend.
      runAudit: async (input) => {
        await input.execute!({
          repoDir,
          configPath: join(testDir, 'cfg.yml'),
          extraRepoOverlayFiles: [],
          scratchDir: testDir,
          pm: 'pnpm',
          hostArch: 'x64',
          mode: 'update',
        });
        return { exitCode: 0 };
      },
      runSelectedBackend: async (sel) => {
        capturedRequested = sel.requested;
        capturedCtx = sel.ctx as unknown as Record<string, unknown>;
        return { finalYaml: 'x: 1\n', nonFatalWarnings: [] };
      },
    }));
    expect(code).toBe(0);
    expect(capturedRequested).toBe('auto');
    expect(capturedCtx).not.toBeNull();
    expect(capturedCtx!['runnerImage']).toBe('ubuntu-24.04');
    expect(capturedCtx!['arch']).toBe('x64');
    expect(capturedCtx!['manifest']).toBe(PINNED_MANIFEST);
    expect(capturedCtx!['selfTest']).toBe(false);
    expect(typeof capturedCtx!['imagesDir']).toBe('string');
    expect((capturedCtx!['imagesDir'] as string).length).toBeGreaterThan(0);
    expect(capturedCtx!['http']).toBeDefined();
  });

  it('LINUX no-validateManifest: placeholder PINNED_MANIFEST does NOT block reaching the backend', async () => {
    // The CLI must NEVER call validateManifest. With the real (placeholder-SHA)
    // PINNED_MANIFEST flowing into ctx, run() must reach runAudit/execute and
    // NOT exit 1 with a packaging-bug message before backend selection.
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    let reachedBackend = false;
    const code = await run(linuxDeps({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      runAudit: async (input) => {
        await input.execute!({
          repoDir,
          configPath: join(testDir, 'cfg.yml'),
          extraRepoOverlayFiles: [],
          scratchDir: testDir,
          pm: 'pnpm',
          hostArch: 'x64',
          mode: 'update',
        });
        return { exitCode: 0 };
      },
      runSelectedBackend: async () => {
        reachedBackend = true;
        return { finalYaml: 'x: 1\n', nonFatalWarnings: [] };
      },
    }));
    expect(code).toBe(0);
    expect(reachedBackend).toBe(true);
    expect(stderr.text).not.toMatch(/packaging bug/i);
  });

  it('LINUX friendly-error: a PlatformPackageMissingError exits 1 naming the package', async () => {
    const repoDir = fakeRepo('pnpm-lock.yaml');
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await run(linuxDeps({
      argv: ['init'],
      cwd: () => repoDir,
      stdout, stderr,
      resolvePlatformPackageDir: () => {
        throw new PlatformPackageMissingError('@script-jail/linux-x64');
      },
    }));
    expect(code).toBe(1);
    expect(stderr.text).toMatch(/@script-jail\/linux-x64/);
  });
});

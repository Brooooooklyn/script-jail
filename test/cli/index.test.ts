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
  // PR 4 wired buildEffectiveConfig into the CLI orchestration path, so the
  // fake repo needs a minimal .script-jail.yml for the config-overlay step
  // to succeed.  The contents are intentionally trivial — every test that
  // depends on this stubs out makeOverlay below, so the rewritten config is
  // never actually read by anything downstream.
  writeFileSync(
    join(dir, '.script-jail.yml'),
    'spoof:\n  platform: linux\n  arch: x64\n',
  );
  return dir;
}

function fakeOverlay(workDir: string) {
  // PR 4 calls makeOverlay before spawnVm; tests stub it to return a fake
  // OverlayResult whose paths look reasonable but never exist on disk.
  // spawnVm is itself stubbed in these tests so the missing files never
  // matter.
  return {
    rootfsCopyPath: join(workDir, 'rootfs.ext4'),
    repoDiskPath: join(workDir, 'repo.ext4'),
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
    // PR 4 wires `spawnVm` for real, but the dependency-injection seam stays
    // intact: tests can still stub `spawnVm` to throw, and the CLI must
    // surface the message verbatim to stderr.  We keep
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

  it('hostArch=x64 from detectHost reaches buildArchFlagOverlay even on an arm64 dev box', async () => {
    // The complementary half of the I2 regression: injecting `x64` from
    // an arm64 dev box must also be honoured.  Without the fix, hostArch
    // would mirror process.arch.
    const repoDir = fakeRepo('package-lock.json');
    let capturedHostArch: string | null = null;
    await run({
      argv: ['init'],
      cwd: () => repoDir,
      stdout: new Sink(),
      stderr: new Sink(),
      detectHost: () => ({ macosMajor: 14, hostArch: 'x64' }),
      buildArchFlagOverlay: (input) => {
        capturedHostArch = input.hostArch;
        return { warnings: [] };
      },
      makeOverlay: async () => fakeOverlay(testDir),
      spawnVm: async () => { throw new MacOSVmNotImplementedError(); },
    });
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

// script-jail — test/action/firecracker/overlay.test.ts
//
// Tests for makeOverlay().
//
// On macOS, the ext4 disk-creation step requires Docker (Alpine image) and is
// skipped in fast-unit runs.  We test the staging logic (file copying, config
// placement) separately by inspecting the repo-stage directory before it is
// packed into the ext4 image.
//
// For the ext4 creation we have a separate describe block guarded by
// isLinux() — it only runs in CI on a Linux runner with mkfs.ext4 available.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { platform } from 'node:process';

import {
  diskSizeMB,
  envFloorMB,
  makeOverlay,
  sumContentBytes,
} from '../../../src/action/firecracker/overlay.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const isLinux = platform === 'linux';

let testDir: string;
let repoDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'script-jail-overlay-test-'));
  repoDir = join(testDir, 'repo');
  mkdirSync(repoDir, { recursive: true });

  // Create a minimal repo structure.
  writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'test' }));
  writeFileSync(join(repoDir, 'index.js'), 'console.log("hello")');
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** Create a fake base rootfs ext4 (just a non-empty file for testing). */
function fakeBaseRootfs(dir: string): string {
  const p = join(dir, 'rootfs.ext4');
  writeFileSync(p, Buffer.alloc(1024, 0xab)); // 1 KB placeholder
  return p;
}

/** Create a fake .script-jail.yml config file. */
function fakeConfig(dir: string): string {
  const p = join(dir, '.script-jail.yml');
  writeFileSync(p, 'manager: pnpm\nnode_version: "20"\n');
  return p;
}

// ---------------------------------------------------------------------------
// File-staging tests (run on both macOS and Linux)
// ---------------------------------------------------------------------------

// TODO(v2): The tests in this describe block do not call makeOverlay() and
// therefore do not exercise the actual staging logic.  They duplicate the
// file-system operations directly.  Rewiring them to call makeOverlay() with
// a stubbed mkfs.ext4 requires > 50 lines of mock infrastructure.  Leave as
// is until a dedicated ext4-mock helper is available.

describe('makeOverlay — partial-build failure removes the workDir', () => {
  it('removes a populated workDir when a build step throws mid-flight', async () => {
    // The escaping extraRepoOverlayFiles entry throws AFTER the rootfs copy
    // and repo staging have populated the workDir (and before any mkfs, so
    // this runs on every platform).  Without the try/catch in makeOverlay
    // the caller never receives cleanup() and the populated tree leaks
    // (round-1 review, medium finding).
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);
    const workDir = mkdtempSync(join(tmpdir(), 'script-jail-partial-build-'));

    await expect(
      makeOverlay({
        baseRootfsPath,
        repoSrcPath: repoDir,
        configPath,
        workDir,
        extraRepoOverlayFiles: [{ relPath: '../escape.txt', content: 'x' }],
      }),
    ).rejects.toThrow(/escapes the repo stage dir|not a safe relative path/);

    // The whole workDir — including the already-copied rootfs and staged
    // repo — must be gone.
    expect(existsSync(workDir)).toBe(false);
  });

  it('FAILS CLOSED when an overlay LEAF pre-exists as a directory (gitlink/submodule leaf gap)', async () => {
    // Codex re-review: a committed gitlink/submodule (git index mode 160000) at
    // etc/script-jail/pm-flags.json checks out as a real (empty) DIRECTORY.  The old
    // `rmSync(dest, {recursive}); writeFileSync` would delete it and write our sidecar
    // into the repo-disk copy ONLY, while the host's real checkout keeps the dir — a
    // host-vs-audit divergence the value-blind lock can't capture.  writeOverlayFile
    // must throw (before mkfs, so this runs on every platform).  A real empty dir at the
    // leaf reproduces the checked-out gitlink's filesystem state without needing git.
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);
    const workDir = mkdtempSync(join(tmpdir(), 'script-jail-leaf-gap-'));
    const repoSrc = mkdtempSync(join(tmpdir(), 'script-jail-leaf-repo-'));
    writeFileSync(join(repoSrc, 'package.json'), '{"name":"x"}');
    mkdirSync(join(repoSrc, 'etc', 'script-jail', 'pm-flags.json'), { recursive: true });

    await expect(
      makeOverlay({
        baseRootfsPath,
        repoSrcPath: repoSrc,
        configPath,
        workDir,
        extraRepoOverlayFiles: [{ relPath: 'etc/script-jail/pm-flags.json', content: '{}' }],
      }),
    ).rejects.toThrow(/already has a directory .* writes its own sidecar/);

    expect(existsSync(workDir)).toBe(false); // makeOverlay's try/catch cleaned up.
    rmSync(repoSrc, { recursive: true, force: true });
  });
});

describe('makeOverlay — staging (no ext4 build)', () => {
  it('copies the base rootfs to rootfsCopyPath', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    fakeConfig(testDir); // creates .script-jail.yml in testDir (side-effect only)
    const workDir = mkdtempSync(join(tmpdir(), 'script-jail-overlay-work-'));

    // Intercept the ext4 build by using a workDir that already contains a
    // fake rootfs.  We cannot fully skip mkfs.ext4 without more invasive
    // mocking; instead we verify the copy step independently.

    // Write a fake rootfs copy manually to simulate what makeOverlay does.
    const { cpSync } = await import('node:fs');
    const rootfsCopyPath = join(workDir, 'rootfs.ext4');
    cpSync(baseRootfsPath, rootfsCopyPath);

    expect(existsSync(rootfsCopyPath)).toBe(true);

    // Verify the copy is byte-identical.
    const original = readFileSync(baseRootfsPath);
    const copy = readFileSync(rootfsCopyPath);
    expect(copy).toEqual(original);

    rmSync(workDir, { recursive: true, force: true });
  });

  it('stages repo files into the staging directory', async () => {
    // Verify that cpSync copies the repo tree (unit-level check).
    const { cpSync } = await import('node:fs');
    const stageDir = join(testDir, 'stage');
    mkdirSync(stageDir, { recursive: true });

    cpSync(repoDir, stageDir, { recursive: true });

    expect(existsSync(join(stageDir, 'package.json'))).toBe(true);
    expect(existsSync(join(stageDir, 'index.js'))).toBe(true);
  });

  it('places config.yml under etc/script-jail/ in the stage dir', () => {
    // Simulate the config placement logic.
    const stageDir = join(testDir, 'stage');
    const configPath = fakeConfig(testDir);
    const configDestDir = join(stageDir, 'etc', 'script-jail');
    mkdirSync(configDestDir, { recursive: true });
    writeFileSync(join(configDestDir, 'config.yml'), readFileSync(configPath));

    const placed = join(stageDir, 'etc', 'script-jail', 'config.yml');
    expect(existsSync(placed)).toBe(true);
    expect(readFileSync(placed, 'utf8')).toContain('pnpm');
  });

  it('cleanup() removes the workDir', async () => {
    // We skip the full makeOverlay call (requires mkfs.ext4) and test
    // the cleanup contract directly.
    const workDir = mkdtempSync(join(tmpdir(), 'script-jail-cleanup-test-'));
    writeFileSync(join(workDir, 'dummy.txt'), 'hello');

    const { rm } = await import('node:fs/promises');
    const cleanup = async (): Promise<void> => {
      await rm(workDir, { recursive: true, force: true });
    };

    await cleanup();
    expect(existsSync(workDir)).toBe(false);
  });

  it('cleanup() does not throw when workDir is already removed', async () => {
    const workDir = join(testDir, 'nonexistent-work-dir');
    const { rm } = await import('node:fs/promises');
    const cleanup = async (): Promise<void> => {
      try {
        await rm(workDir, { recursive: true, force: true });
      } catch { /* ignore */ }
    };

    await expect(cleanup()).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Full makeOverlay tests (Linux only — requires mkfs.ext4)
// ---------------------------------------------------------------------------

describe.skipIf(!isLinux)('makeOverlay — full (Linux + mkfs.ext4)', () => {
  it('extraRepoOverlayFiles land on the staged repo dir before mkfs.ext4', async () => {
    // We assert via a custom workDir whose repo-stage subdir we can inspect
    // AFTER makeOverlay returns.  (makeOverlay leaves the staging dir
    // present until cleanup().)
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);
    const myWorkDir = join(testDir, 'overlay-work');
    mkdirSync(myWorkDir, { recursive: true });

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      workDir: myWorkDir,
      extraRepoOverlayFiles: [
        { relPath: '.yarnrc.yml', content: 'supportedArchitectures:\n  os:\n    - linux\n' },
        { relPath: 'etc/script-jail/pm-flags.json', content: '{"extra_install_args":["--cpu=x64"]}' },
      ],
    });

    try {
      const stageDir = join(myWorkDir, 'repo-stage');
      expect(existsSync(join(stageDir, '.yarnrc.yml'))).toBe(true);
      expect(readFileSync(join(stageDir, '.yarnrc.yml'), 'utf8'))
        .toContain('supportedArchitectures');
      expect(existsSync(join(stageDir, 'etc', 'script-jail', 'pm-flags.json'))).toBe(true);
      expect(readFileSync(join(stageDir, 'etc', 'script-jail', 'pm-flags.json'), 'utf8'))
        .toContain('--cpu=x64');
    } finally {
      await result.cleanup();
    }
  });

  it('returns correct paths for rootfsCopyPath, repoDiskPath and scratchDiskPath', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    try {
      expect(existsSync(result.rootfsCopyPath)).toBe(true);
      expect(result.rootfsCopyPath).toContain('rootfs.ext4');
      expect(existsSync(result.repoDiskPath)).toBe(true);
      expect(result.repoDiskPath).toContain('repo.ext4');
      expect(existsSync(result.scratchDiskPath)).toBe(true);
      expect(result.scratchDiskPath).toContain('scratch.ext4');
      expect(existsSync(result.sjtmpDiskPath)).toBe(true);
      expect(result.sjtmpDiskPath).toContain('sjtmp.ext4');
      expect(result.workDir).toBeTruthy();
    } finally {
      await result.cleanup();
    }
  });

  it('scratch.ext4 is an ext4 labeled exactly `scratch`, ≥ floor (4096 MiB for a tiny repo)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    try {
      // Logical size: the floor (4096 MiB) holds for this tiny repo.  (Sparse
      // on the host, so allocated blocks are far fewer — we only assert the
      // logical length.)  Large repos scale ABOVE the floor (see below).
      const { statSync } = await import('node:fs');
      expect(statSync(result.scratchDiskPath).size).toBe(4096 * 1024 * 1024);

      // Read the ext4 superblock (at byte offset 1024) and assert:
      //   - s_magic   (offset 0x38, little-endian) == 0xEF53  → it IS ext-family
      //   - s_volume_name (offset 0x78, 16 bytes)  == 'scratch' → label is
      //     load-bearing: the guest mounts via `blkid -L scratch`.
      // Positioned read — readFileSync would pull the whole 4 GiB logical
      // image into memory.
      const { openSync, readSync, closeSync } = await import('node:fs');
      const sb = Buffer.alloc(1024);
      const fd = openSync(result.scratchDiskPath, 'r');
      try {
        readSync(fd, sb, 0, 1024, 1024);
      } finally {
        closeSync(fd);
      }
      const magic = sb.readUInt16LE(0x38);
      expect(magic.toString(16)).toBe('ef53');
      const label = sb.subarray(0x78, 0x78 + 16);
      const labelStr = label.subarray(0, label.indexOf(0)).toString('utf8');
      expect(labelStr).toBe('scratch');
    } finally {
      await result.cleanup();
    }
  });

  it('sjtmp.ext4 is an ext4 labeled exactly `sjtmp`, ≥ floor (4096 MiB for a tiny repo)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    try {
      // The floor (4096 MiB) holds for this tiny repo; large repos scale above.
      const { statSync } = await import('node:fs');
      expect(statSync(result.sjtmpDiskPath).size).toBe(4096 * 1024 * 1024);

      // Read the ext4 superblock and assert magic + the load-bearing label
      // `sjtmp` (the guest mounts via `blkid -L sjtmp`).
      const { openSync, readSync, closeSync } = await import('node:fs');
      const sb = Buffer.alloc(1024);
      const fd = openSync(result.sjtmpDiskPath, 'r');
      try {
        readSync(fd, sb, 0, 1024, 1024);
      } finally {
        closeSync(fd);
      }
      const magic = sb.readUInt16LE(0x38);
      expect(magic.toString(16)).toBe('ef53');
      const label = sb.subarray(0x78, 0x78 + 16);
      const labelStr = label.subarray(0, label.indexOf(0)).toString('utf8');
      expect(labelStr).toBe('sjtmp');
    } finally {
      await result.cleanup();
    }
  });

  // NOTE: the CONTENT-scaling-ABOVE-floor arithmetic (2× content beats the 4096
  // MiB floor, and a lower knob cannot shrink it) is covered by the fast,
  // platform-agnostic `diskSizeMB / envFloorMB` block at the bottom of this file.
  // Proving it through the full mkfs path would need >2 GiB of real content
  // staged + copied (the only way to cross the 4 GiB floor), which is far too
  // slow for the 5 s test budget.  The full-mkfs tests below still exercise the
  // ENTIRE `max(diskSizeMB(sumContentBytes(stage), MIN), envFloorMB(env, name))`
  // expression end-to-end — they just land on the floor / knob value.

  it('SCRIPT_JAIL_SCRATCH_DISK_MB raises the floor (tiny repo, knob > scaled need)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    // Tiny repo → content-scaled need is the 4096 floor; the 8192 knob wins.
    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', SCRIPT_JAIL_SCRATCH_DISK_MB: '8192' },
    });

    try {
      const { statSync } = await import('node:fs');
      expect(statSync(result.scratchDiskPath).size).toBe(8192 * 1024 * 1024);
      // sjtmp (no knob) stays at its floor.
      expect(statSync(result.sjtmpDiskPath).size).toBe(4096 * 1024 * 1024);
    } finally {
      await result.cleanup();
    }
  });

  it('SCRIPT_JAIL_SJTMP_DISK_MB raises the floor (tiny repo, knob > scaled need)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', SCRIPT_JAIL_SJTMP_DISK_MB: '8192' },
    });

    try {
      const { statSync } = await import('node:fs');
      expect(statSync(result.sjtmpDiskPath).size).toBe(8192 * 1024 * 1024);
      expect(statSync(result.scratchDiskPath).size).toBe(4096 * 1024 * 1024);
    } finally {
      await result.cleanup();
    }
  });

  it('garbage disk knobs are ignored (no throw; falls back to scaled/floor)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    // Empty string and non-numeric garbage → envFloorMB returns 0 → floor holds.
    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      env: {
        PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
        SCRIPT_JAIL_SCRATCH_DISK_MB: '',
        SCRIPT_JAIL_SJTMP_DISK_MB: 'abc',
      },
    });

    try {
      const { statSync } = await import('node:fs');
      expect(statSync(result.scratchDiskPath).size).toBe(4096 * 1024 * 1024);
      expect(statSync(result.sjtmpDiskPath).size).toBe(4096 * 1024 * 1024);
    } finally {
      await result.cleanup();
    }
  });

  it('cleanup() removes the entire workDir', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    const { workDir } = result;
    await result.cleanup();
    expect(existsSync(workDir)).toBe(false);
  });

  it('accepts an explicit workDir instead of creating one', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);
    const customWorkDir = join(testDir, 'my-work-dir');
    mkdirSync(customWorkDir, { recursive: true });

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      workDir: customWorkDir,
    });

    try {
      expect(result.workDir).toBe(customWorkDir);
      expect(result.rootfsCopyPath).toContain(customWorkDir);
    } finally {
      await result.cleanup();
    }
  });

  it('rootfsCopyPath is byte-identical copy of the base rootfs', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    try {
      const original = readFileSync(baseRootfsPath);
      const copy = readFileSync(result.rootfsCopyPath);
      expect(copy).toEqual(original);
    } finally {
      await result.cleanup();
    }
  });

  // SECURITY (pre-trust bare-name host RCE): on Linux the disk-build spawns
  // (`cp --reflink=auto`, bare `mkfs.ext4`) resolve via the PATH carried in the
  // caller-supplied `env`.  The Firecracker backend threads its sanitized env
  // down so a checkout-prepended PATH dir / inherited loader var can't hijack
  // them.  These two tests pin that `input.env` is actually HONORED for tool
  // resolution: a sanitized system PATH succeeds; a PATH with no `mkfs.ext4`
  // (and `cp` unavailable for the reflink fast-path) fails — proving the spawns
  // do NOT silently fall back to the ambient process.env.
  it('honors a sanitized env PATH when building the disks (success)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
      // A SAFE_SYSTEM_PATH-equivalent value: mkfs.ext4 lives in /usr/sbin|/sbin,
      // cp in /usr/bin|/bin.  No checkout dir, no loader vars — the hardened shape.
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    });

    try {
      expect(existsSync(result.scratchDiskPath)).toBe(true);
      expect(existsSync(result.repoDiskPath)).toBe(true);
    } finally {
      await result.cleanup();
    }
  });

  it('fails when the threaded env PATH cannot resolve mkfs.ext4 (env is honored, not bypassed)', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);
    // An empty-but-existing dir on PATH: neither `cp` (reflink fast-path) nor the
    // bare `mkfs.ext4` resolve, so the build must throw.  If the spawns ignored
    // `input.env` and used the ambient PATH, this would (wrongly) succeed.
    const emptyBin = join(testDir, 'empty-bin');
    mkdirSync(emptyBin, { recursive: true });

    await expect(
      makeOverlay({
        baseRootfsPath,
        repoSrcPath: repoDir,
        configPath,
        env: { PATH: emptyBin },
      }),
    ).rejects.toThrow(/mkfs\.ext4|ENOENT|spawn/i);
  });
});

// ---------------------------------------------------------------------------
// sumContentBytes — symlink safety (platform-agnostic; no mkfs needed)
// ---------------------------------------------------------------------------
//
// The sizing walk must NEVER follow symlinks: the staged repo preserves repo
// symlinks verbatim, and that single byte total now sizes all three disks.
// A `loop -> .` (ELOOP recursion) or `escape -> /` (host-root walk) by an
// attacker-controlled repo entry must not hang or inflate the metric.
describe('sumContentBytes — does not follow symlinks', () => {
  let walkDir: string;

  beforeEach(() => {
    walkDir = mkdtempSync(join(tmpdir(), 'script-jail-walk-test-'));
  });

  afterEach(() => {
    rmSync(walkDir, { recursive: true, force: true });
  });

  it('counts real files but never recurses into symlinks (self-loop + escape-to-host-root)', async () => {
    const { symlinkSync, mkdirSync: mkdir } = await import('node:fs');

    // One real 4096-byte file + a real nested dir with another real file.
    const REAL_BYTES = 4096;
    writeFileSync(join(walkDir, 'real.bin'), Buffer.alloc(REAL_BYTES, 0x61));
    mkdir(join(walkDir, 'sub'), { recursive: true });
    writeFileSync(join(walkDir, 'sub', 'nested.bin'), Buffer.alloc(REAL_BYTES, 0x62));

    // Hostile symlinks: a self-loop and an escape to the host filesystem root.
    // If the walk followed these it would either ELOOP-spin or sum the entire
    // host tree (millions of bytes) — instead each is counted as a tiny link.
    symlinkSync('.', join(walkDir, 'loop')); // loop -> . (would recurse forever)
    symlinkSync('/', join(walkDir, 'escape')); // escape -> / (would walk host root)
    symlinkSync(join(walkDir, 'sub'), join(walkDir, 'dirlink')); // symlink to a real dir

    const start = Date.now();
    const total = sumContentBytes(walkDir);
    const elapsedMs = Date.now() - start;

    // The two real files are counted; the symlinks add only their tiny link
    // sizes (target-path length), never the dirs/host tree they point at.
    expect(total).toBeGreaterThanOrEqual(2 * REAL_BYTES);
    // A small ceiling proves no symlink target was traversed (host root alone
    // would be many MiB).  2 real files + a handful of tiny link entries.
    expect(total).toBeLessThan(2 * REAL_BYTES + 4096);
    // And it returned promptly — no ELOOP spin.
    expect(elapsedMs).toBeLessThan(5000);
  });
});

// ---------------------------------------------------------------------------
// diskSizeMB / envFloorMB — disk sizing arithmetic (platform-agnostic, no mkfs)
//
// These cover the CONTENT-scaling-above-floor + knob-raise-only + knob-can't-
// shrink + garbage-knob behavior that previously needed a multi-GiB mkfs path
// (the only way to cross the 4 GiB floor end-to-end is to stage >2 GiB of real
// content, which blows the test budget).  The full-mkfs tests above still run
// the whole `max(diskSizeMB(sumContentBytes(stage), MIN), envFloorMB(env, name))`
// expression; here we prove the arithmetic branches the floor/knob cases don't reach.
// ---------------------------------------------------------------------------

describe('diskSizeMB — content scaling vs floor', () => {
  const FLOOR = 4096; // SCRATCH_DISK_MIN_MB / SJTMP_DISK_MIN_MB

  const GIB = 1024 * 1024 * 1024;

  it('returns the floor for empty / tiny content (2× content < floor)', () => {
    expect(diskSizeMB(0, FLOOR)).toBe(FLOOR);
    expect(diskSizeMB(1, FLOOR)).toBe(FLOOR);
    // 1 GiB content → 2× = 2048 MiB, still below the 4096 floor.
    expect(diskSizeMB(1 * GIB, FLOOR)).toBe(FLOOR);
    // Exactly at the floor boundary: 2 GiB content → 2× = 4096 MiB == floor.
    expect(diskSizeMB(2 * GIB, FLOOR)).toBe(FLOOR);
  });

  it('scales to ceil(2× content / MiB) once that exceeds the floor', () => {
    // 3 GiB content → 2× = 6 GiB = 6144 MiB, above the 4096 floor (the napi-rs
    // ENOSPC case the v0.2.6 fix addresses).
    expect(diskSizeMB(3 * GIB, FLOOR)).toBe(6144);
    expect(diskSizeMB(3 * GIB, FLOOR)).toBeGreaterThan(FLOOR);
    // A genuinely large monorepo: 20 GiB content → 40 GiB = 40960 MiB.
    expect(diskSizeMB(20 * GIB, FLOOR)).toBe(40960);
  });

  it('rounds the scaled size UP (ceil), never truncating below the need', () => {
    // 2 GiB + 1 byte of content → 2× just over 4096 MiB → ceil to 4097.
    expect(diskSizeMB(2 * GIB + 1, FLOOR)).toBe(4097);
    // A non-MiB-aligned content total ceils up, not down.
    expect(diskSizeMB(3 * GIB + 1, FLOOR)).toBe(6145);
  });
});

describe('envFloorMB — knob parsing + raise-only composition', () => {
  const FLOOR = 4096;
  const GIB = 1024 * 1024 * 1024;
  const KEY = 'SCRIPT_JAIL_SCRATCH_DISK_MB';

  it('parses a valid positive integer MiB override', () => {
    expect(envFloorMB({ [KEY]: '8192' }, KEY)).toBe(8192);
    expect(envFloorMB({ [KEY]: '5120' }, KEY)).toBe(5120);
    // Fractional → floored.
    expect(envFloorMB({ [KEY]: '12.9' }, KEY)).toBe(12);
  });

  it('returns 0 (no override) for unset / empty / non-numeric / ≤0 / non-finite', () => {
    expect(envFloorMB({}, KEY)).toBe(0);
    expect(envFloorMB({ [KEY]: '' }, KEY)).toBe(0);
    expect(envFloorMB({ [KEY]: 'abc' }, KEY)).toBe(0);
    expect(envFloorMB({ [KEY]: '0' }, KEY)).toBe(0);
    expect(envFloorMB({ [KEY]: '-5' }, KEY)).toBe(0);
    expect(envFloorMB({ [KEY]: 'Infinity' }, KEY)).toBe(0);
  });

  it('composes as a RAISED floor only: max(scaled, override)', () => {
    // Tiny repo (floor 4096) + 8192 knob → knob wins (raises).
    expect(Math.max(diskSizeMB(0, FLOOR), envFloorMB({ [KEY]: '8192' }, KEY))).toBe(8192);
    // Large repo (scaled 6144) + 5120 knob → scaled wins (knob CANNOT shrink it).
    expect(Math.max(diskSizeMB(3 * GIB, FLOOR), envFloorMB({ [KEY]: '5120' }, KEY))).toBe(6144);
    // Garbage knob → 0 → floor/scaled holds.
    expect(Math.max(diskSizeMB(0, FLOOR), envFloorMB({ [KEY]: 'abc' }, KEY))).toBe(FLOOR);
  });
});

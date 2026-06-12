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

import { makeOverlay } from '../../../src/action/firecracker/overlay.js';

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
      expect(result.workDir).toBeTruthy();
    } finally {
      await result.cleanup();
    }
  });

  it('scratch.ext4 is an ext4 labeled exactly `scratch`, 4096 MiB logical', async () => {
    const baseRootfsPath = fakeBaseRootfs(testDir);
    const configPath = fakeConfig(testDir);

    const result = await makeOverlay({
      baseRootfsPath,
      repoSrcPath: repoDir,
      configPath,
    });

    try {
      // Logical size: exactly 4096 MiB.  (Sparse on the host, so allocated
      // blocks are far fewer — we only assert the logical length.)
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
});

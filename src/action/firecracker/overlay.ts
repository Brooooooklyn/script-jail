// npm-jar — src/action/firecracker/overlay.ts
//
// Builds a per-run rootfs overlay and a separate repo disk for the VM.
//
// Design: TWO-DISK APPROACH
// ──────────────────────────
// Rather than mounting and mutating the base ext4 in-place we use two separate
// ext4 images:
//
//   1. rootfs.ext4  — a copy of the base image (CoW with `cp --reflink=auto`
//                     on Linux; plain copy on macOS).  Firecracker mounts this
//                     as the root device (read-write).  Any writes by the VM
//                     are isolated to this per-run copy; the base image is never
//                     touched.
//
//   2. repo.ext4    — a small ext4 containing only the user's repository files
//                     and the npm-jar config YAML.  The guest's init.sh mounts
//                     this read-only at /work.  Building a separate disk keeps
//                     the rootfs copy fast and predictable (same size every run)
//                     and avoids needing `mount`/`umount` root privileges on
//                     the host.
//
// The repo disk is created with `mkfs.ext4 -d <dir>` on Linux or via a Docker
// helper on macOS (same pattern as rootfs/build.ts).  On macOS the test suite
// skips filesystem-level assertions and only verifies the file-staging logic.
//
// Cleanup contract: `overlay.cleanup()` removes the entire `workDir`.  The
// caller MUST invoke it (via teardown.ts) whether the VM run succeeds or fails.
//
// TODO(v2): The repo disk and config.yml placement only work if the guest's
// init.sh mounts the second drive at /work and copies
// /work/etc/npm-jar/config.yml → /etc/npm-jar/config.yml before exec-ing the
// agent.  The current src/rootfs/init.sh does not yet do this.  Until that is
// implemented, a real VM boot will fail because the agent cannot read its config.
// Tracked issue: update init.sh to:
//   1. Mount the second virtio disk (/dev/vdb) at /work.
//   2. mkdir -p /etc/npm-jar && cp /work/etc/npm-jar/config.yml /etc/npm-jar/
//   3. exec dumb-init /usr/local/bin/node /usr/local/lib/npm-jar/guest-agent.cjs

import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  copyFileSync,
  statSync,
  existsSync,
} from 'node:fs';
import { rm } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { execSync, spawnSync } from 'node:child_process';
import { platform } from 'node:process';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface OverlayInput {
  /** Absolute path to the base rootfs ext4 (e.g. images/rootfs-node20-pnpm.ext4). */
  baseRootfsPath: string;
  /** Absolute path to the user's repository on the host. */
  repoSrcPath: string;
  /** Absolute path to .npm-jar.yml on the host. */
  configPath: string;
  /**
   * Per-run working directory.  If empty the function creates a mkdtemp dir
   * under os.tmpdir() automatically.
   */
  workDir?: string | undefined;
}

export interface OverlayResult {
  /** Per-run rootfs copy that Firecracker mounts as the root device. */
  rootfsCopyPath: string;
  /** Small ext4 containing the user's repo + npm-jar config, mounted at /work. */
  repoDiskPath: string;
  /** The working directory (contains both ext4 images). */
  workDir: string;
  /** Removes the entire workDir tree.  Never throws. */
  cleanup: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// makeOverlay
// ---------------------------------------------------------------------------

export async function makeOverlay(input: OverlayInput): Promise<OverlayResult> {
  const { baseRootfsPath, repoSrcPath, configPath, workDir: maybeWorkDir } = input;

  // 1. Create per-run work dir if not supplied.
  const workDir = maybeWorkDir ?? mkdtempSync(join(tmpdir(), 'npm-jar-run-'));
  mkdirSync(workDir, { recursive: true });

  // 2. Copy the base rootfs (CoW where supported, plain copy otherwise).
  const rootfsCopyPath = join(workDir, 'rootfs.ext4');
  copyRootfs(baseRootfsPath, rootfsCopyPath);

  // 3. Stage the repo + config into a temp directory tree that will become
  //    the content of repo.ext4.
  const repoStageDir = join(workDir, 'repo-stage');
  mkdirSync(repoStageDir, { recursive: true });

  // Copy repository files.
  cpSync(repoSrcPath, repoStageDir, { recursive: true, dereference: false });

  // Overlay the npm-jar config at the path the guest agent expects:
  //   /etc/npm-jar/config.yml  →  inside the repo stage dir we write it at
  //   repo-stage/etc/npm-jar/config.yml so it is accessible after the guest
  //   mounts this disk at /work.
  //
  // NOTE: The guest's init.sh mounts the repo disk at /work, so paths inside
  // the disk are relative to /work.  The agent reads config from
  // /etc/npm-jar/config.yml which is on the rootfs; the init.sh copies it
  // from /work/etc/npm-jar/config.yml into /etc/npm-jar/ at boot.
  const configDestDir = join(repoStageDir, 'etc', 'npm-jar');
  mkdirSync(configDestDir, { recursive: true });
  copyFileSync(configPath, join(configDestDir, 'config.yml'));

  // 4. Build the repo disk ext4.
  const repoDiskPath = join(workDir, 'repo.ext4');
  await buildRepoDisk(repoStageDir, repoDiskPath);

  const cleanup = async (): Promise<void> => {
    try {
      await rm(workDir, { recursive: true, force: true });
    } catch (err) {
      console.warn(`[overlay] cleanup warning: ${String(err)}`);
    }
  };

  return { rootfsCopyPath, repoDiskPath, workDir, cleanup };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Copy the base rootfs image to `destPath`.
 *
 * On Linux we attempt `cp --reflink=auto` for a CoW clone (fast on btrfs/xfs).
 * Falls back to a regular copy on any error or on macOS.
 */
function copyRootfs(src: string, dest: string): void {
  if (platform === 'linux') {
    const result = spawnSync('cp', ['--reflink=auto', src, dest], { stdio: 'ignore' });
    if (result.status === 0) return;
    // Fallback: plain cp (e.g. ext4 host fs that doesn't support reflink).
  }
  // macOS or Linux fallback.
  cpSync(src, dest);
}

/**
 * Build a small ext4 image from `srcDir` content.
 *
 * On Linux: `mkfs.ext4 -d <srcDir>` (no mount required, no root).
 * On macOS: delegate to an Alpine docker container (same as rootfs/build.ts).
 *
 * Size is estimated at max(32 MB, 2× the source dir size) to leave headroom
 * for filesystem overhead.
 */
async function buildRepoDisk(srcDir: string, outPath: string): Promise<void> {
  const sizeMB = estimateDiskSizeMB(srcDir);
  const sizeSpec = `${sizeMB}M`;

  if (platform === 'linux') {
    execSync(
      `mkfs.ext4 -d "${srcDir}" -L repo -O ^has_journal -m 0 "${outPath}" ${sizeSpec}`,
      { stdio: 'inherit' },
    );
  } else {
    // macOS: use Docker Alpine helper.
    const outDir = join(outPath, '..');
    const imageName = basename(outPath);
    execSync(
      `docker run --rm ` +
      `-v "${srcDir}:/work:ro" ` +
      `-v "${outDir}:/out" ` +
      `alpine:latest ` +
      `sh -c ` +
      `"apk add --no-cache e2fsprogs && ` +
      ` mkfs.ext4 -d /work -L repo -O ^has_journal -m 0 /out/${imageName} ${sizeSpec}"`,
      { stdio: 'inherit' },
    );
  }
}

/** Recursively sum the size of files under `dir` and return a size in MB. */
function estimateDiskSizeMB(dir: string): number {
  let totalBytes = 0;

  const visit = (p: string): void => {
    try {
      const stat = statSync(p, { bigint: false });
      if (stat.isDirectory()) {
        for (const child of readdirSync(p)) {
          visit(join(p, child));
        }
      } else if (stat.isFile() || stat.isSymbolicLink()) {
        totalBytes += stat.size;
      }
    } catch { /* ignore permission errors etc. */ }
  };

  if (existsSync(dir)) visit(dir);

  const estimatedMB = Math.ceil((totalBytes * 2) / (1024 * 1024));
  return Math.max(32, estimatedMB);
}

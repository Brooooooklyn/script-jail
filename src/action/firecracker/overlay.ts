// npm-jar — src/action/firecracker/overlay.ts
//
// Builds a per-run rootfs overlay plus side disks for the VM.
//
// Design: THREE-DISK APPROACH
// ────────────────────────────
// Rather than mounting and mutating the base ext4 in-place we use three
// separate ext4 images:
//
//   1. rootfs.ext4    — a copy of the base image (CoW with `cp --reflink=auto`
//                       on Linux; plain copy on macOS).  Firecracker mounts
//                       this as the root device (read-write).  Any writes by
//                       the VM are isolated to this per-run copy; the base
//                       image is never touched.
//
//   2. repo.ext4      — a small ext4 containing only the user's repository
//                       files and the npm-jar config YAML.  The guest's
//                       init.sh mounts this read-only at /work.  Building a
//                       separate disk keeps the rootfs copy fast and
//                       predictable (same size every run) and avoids needing
//                       `mount`/`umount` root privileges on the host.
//
//   3. host-node.ext4 — a tiny ext4 containing the runner's Node install (the
//                       directory tree rooted at the prefix detected by
//                       resolveHostNodePrefix()).  Mounted by the guest at
//                       /opt/host-node read-only.  The rootfs no longer
//                       bundles a Node binary; whichever Node the user's
//                       workflow set up is the Node the audit runs against.
//
// The side disks are created with `mkfs.ext4 -d <dir>` on Linux or via a
// Docker helper on macOS (same pattern as rootfs/build.ts).  On macOS the
// test suite skips filesystem-level assertions and only verifies the
// file-staging logic.
//
// Cleanup contract: `overlay.cleanup()` removes the entire `workDir`.  The
// caller MUST invoke it (via teardown.ts) whether the VM run succeeds or fails.
//
// Guest mount contract (closed by Task #13, see src/rootfs/init.sh):
//   1. /dev/vdb (label `repo`)      → mounted read-only at /work.
//   2. /work/etc/npm-jar/config.yml → copied into /etc/npm-jar/config.yml.
//   3. /dev/vdc (label `host-node`) → mounted read-only at /opt/host-node,
//      /opt/host-node/bin prepended to PATH.
//   4. The agent execs as `node /usr/local/lib/npm-jar/guest-agent.cjs` so
//      `node` resolves to the host-mounted binary.

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
  /** Absolute path to the base rootfs ext4 (e.g. images/rootfs-ubuntu-24.04.ext4). */
  baseRootfsPath: string;
  /** Absolute path to the user's repository on the host. */
  repoSrcPath: string;
  /** Absolute path to .npm-jar.yml on the host. */
  configPath: string;
  /**
   * Absolute path to the runner's Node install prefix (the directory that
   * contains bin/node, lib/, include/, etc.).  Derived at the action level
   * by `resolveHostNodePrefix()`, which walks PATH (NOT process.execPath —
   * that would resolve to the GitHub Actions runner's bundled Node20 used
   * to execute dist/main.js, not the user-selected Node).  The whole tree
   * is packed into a tiny ext4 attached to the VM at /opt/host-node and
   * mounted read-only by the guest.
   */
  hostNodePrefix: string;
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
  /** Tiny ext4 containing the runner's Node install.  Mounted at /opt/host-node. */
  hostNodeDiskPath: string;
  /** The working directory (contains all ext4 images). */
  workDir: string;
  /** Removes the entire workDir tree.  Never throws. */
  cleanup: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// makeOverlay
// ---------------------------------------------------------------------------

export async function makeOverlay(input: OverlayInput): Promise<OverlayResult> {
  const {
    baseRootfsPath,
    repoSrcPath,
    configPath,
    hostNodePrefix,
    workDir: maybeWorkDir,
  } = input;

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

  // 5. Build the host-node disk ext4.  The guest mounts this at
  //    /opt/host-node read-only and prepends /opt/host-node/bin to PATH so
  //    that whichever Node the runner installed is the Node the audit runs
  //    against.
  const hostNodeDiskPath = join(workDir, 'host-node.ext4');
  await buildHostNodeDisk(hostNodePrefix, hostNodeDiskPath);

  const cleanup = async (): Promise<void> => {
    try {
      await rm(workDir, { recursive: true, force: true });
    } catch (err) {
      console.warn(`[overlay] cleanup warning: ${String(err)}`);
    }
  };

  return { rootfsCopyPath, repoDiskPath, hostNodeDiskPath, workDir, cleanup };
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

/**
 * Build a tiny ext4 image containing the runner's Node install.
 *
 * `hostNodePrefix` is the directory that contains `bin/node` + `lib/` (etc.) —
 * see resolveHostNodePrefix() for how it is derived from the runner's PATH
 * (the location `actions/setup-node` planted the user-selected Node).
 * The whole tree is packed; the guest mounts the disk at /opt/host-node and
 * prepends /opt/host-node/bin to PATH so that whichever Node the runner
 * installed is the Node the audit runs against.
 *
 * Size: max(64 MB, 1.5× the source-tree size) — Node installs are typically
 * ~70-100 MB so the floor matters more than the multiplier in practice.
 *
 * On Linux: `mkfs.ext4 -d <prefix>` (no mount required, no root).
 * On macOS: delegate to an Alpine docker container (same as buildRepoDisk).
 *
 * Label is `host-node` so the guest's init.sh can identify the drive by
 * label rather than by /dev/vdc (which depends on Firecracker's drive order).
 */
async function buildHostNodeDisk(hostNodePrefix: string, outPath: string): Promise<void> {
  const sizeMB = estimateHostNodeDiskSizeMB(hostNodePrefix);
  const sizeSpec = `${sizeMB}M`;

  // Defensive: even though `hostNodePrefix` is validated by
  // resolveHostNodePrefix() before reaching here, we use argv-form spawn so
  // any path-with-spaces or stray shell metacharacters cannot break out.
  // buildRepoDisk() uses the older string-form execSync; that path operates on
  // a workDir we created via mkdtempSync() so the same risk does not apply.
  if (platform === 'linux') {
    const result = spawnSync(
      'mkfs.ext4',
      [
        '-d', hostNodePrefix,
        '-L', 'host-node',
        '-O', '^has_journal',
        '-m', '0',
        outPath,
        sizeSpec,
      ],
      { stdio: 'inherit' },
    );
    if (result.status !== 0) {
      throw new Error(
        `mkfs.ext4 for host-node disk failed (exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
      );
    }
  } else {
    // macOS: use Docker Alpine helper.  Mount the prefix read-only and the
    // out dir read-write; mkfs.ext4 runs inside the container at a fixed
    // path so the user-controlled prefix never reaches the inner shell.
    const outDir = join(outPath, '..');
    const imageName = basename(outPath);
    const result = spawnSync(
      'docker',
      [
        'run', '--rm',
        '-v', `${hostNodePrefix}:/work:ro`,
        '-v', `${outDir}:/out`,
        'alpine:latest',
        'sh', '-c',
        `apk add --no-cache e2fsprogs && mkfs.ext4 -d /work -L host-node -O ^has_journal -m 0 /out/${imageName} ${sizeSpec}`,
      ],
      { stdio: 'inherit' },
    );
    if (result.status !== 0) {
      throw new Error(
        `docker mkfs.ext4 for host-node disk failed (exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
      );
    }
  }
}

/**
 * Size estimator for the host-node disk: max(64 MB, 1.5× source-tree size).
 *
 * Separate from estimateDiskSizeMB() because the floor (64 vs 32 MB) and
 * multiplier (1.5 vs 2) differ — Node installs are well-known in size so we
 * don't need as much slack.
 */
function estimateHostNodeDiskSizeMB(dir: string): number {
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

  const estimatedMB = Math.ceil((totalBytes * 1.5) / (1024 * 1024));
  return Math.max(64, estimatedMB);
}

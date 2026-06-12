// script-jail — src/action/firecracker/overlay.ts
//
// Builds a per-run rootfs overlay plus side disks for the VM.
//
// Design: THREE-DISK APPROACH
// ───────────────────────────
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
//                       files and the script-jail config YAML.  The guest's
//                       init.sh mounts this read-only at /work.  Building a
//                       separate disk keeps the rootfs copy fast and
//                       predictable (same size every run) and avoids needing
//                       `mount`/`umount` root privileges on the host.
//
//   3. scratch.ext4   — an EMPTY ext4 (filesystem label `scratch`) the guest
//                       mounts read-write for audit by-products: strace -ff
//                       logs and the events JSONL.  Large repos overflow the
//                       guest's 64 MB /tmp tmpfs (→ ENOSPC mid-audit); this
//                       disk gives those files a 4 GiB logical home.  Sparse,
//                       so the host-side footprint is metadata only.
//
// The Node toolchain is NOT shipped as a side disk: the rootfs bakes the
// standalone `vp` binary and init.sh runs `vp env install` at guest boot
// (Phase A, network on) to download a real Linux Node toolchain.
//
// The side disks are created with `mkfs.ext4` (`-d <dir>` seeds the repo
// disk; the scratch disk gets no seed) on Linux or via a Docker helper on
// macOS (same pattern as rootfs/build.ts).  On macOS the test suite skips
// filesystem-level assertions and only verifies the file-staging logic.
//
// Cleanup contract: `overlay.cleanup()` removes the entire `workDir`.  The
// caller MUST invoke it (via teardown.ts) whether the VM run succeeds or fails.
//
// Guest mount contract (see src/rootfs/init.sh):
//   1. Disk with filesystem label `repo` (resolved via `blkid -L repo`)
//      → mounted read-only at /work.
//   2. /work/etc/script-jail/config.yml → copied into /etc/script-jail/config.yml.
//   3. Disk with filesystem label `scratch` (resolved via `blkid -L scratch`)
//      → mounted read-write for strace/event spill.  The label string is
//      load-bearing: the guest finds the disk ONLY by label, never by device
//      name, so it must be exactly `scratch`.

import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  copyFileSync,
  statSync,
  existsSync,
  lstatSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { rm } from 'node:fs/promises';
import { join, basename, resolve } from 'node:path';
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
  /** Absolute path to .script-jail.yml on the host. */
  configPath: string;
  /**
   * Per-run working directory.  If empty the function creates a mkdtemp dir
   * under os.tmpdir() automatically.
   */
  workDir?: string | undefined;
  /**
   * Optional additional files to land on the repo disk inside the VM.
   * Each entry's `relPath` is relative to the repo root inside the VM
   * (e.g. `.yarnrc.yml`, `etc/script-jail/pm-flags.json`).  Files are
   * staged into the repo-staging dir BEFORE `mkfs.ext4 -d` runs so they
   * become part of the immutable repo disk.
   *
   * Used by the macOS CLI to layer per-PM install-arg overlays; the existing
   * action surface leaves this undefined.
   */
  extraRepoOverlayFiles?: ReadonlyArray<{ relPath: string; content: string }>;
}

export interface OverlayResult {
  /** Per-run rootfs copy that Firecracker mounts as the root device. */
  rootfsCopyPath: string;
  /** Small ext4 containing the user's repo + script-jail config, mounted at /work. */
  repoDiskPath: string;
  /**
   * EMPTY per-run ext4 (filesystem label `scratch`, 4096 MiB logical, sparse)
   * the guest mounts read-write for strace logs + the events JSONL.
   */
  scratchDiskPath: string;
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
    workDir: maybeWorkDir,
    extraRepoOverlayFiles,
  } = input;

  // 1. Create per-run work dir if not supplied.
  const workDir = maybeWorkDir ?? mkdtempSync(join(tmpdir(), 'script-jail-run-'));
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

  // Overlay the script-jail config at the path the guest agent expects:
  //   /etc/script-jail/config.yml  →  inside the repo stage dir we write it at
  //   repo-stage/etc/script-jail/config.yml so it is accessible after the guest
  //   mounts this disk at /work.
  //
  // NOTE: The guest's init.sh mounts the repo disk at /work, so paths inside
  // the disk are relative to /work.  The agent reads config from
  // /etc/script-jail/config.yml which is on the rootfs; the init.sh copies it
  // from /work/etc/script-jail/config.yml into /etc/script-jail/ at boot.
  const configDestDir = join(repoStageDir, 'etc', 'script-jail');
  mkdirSync(configDestDir, { recursive: true });
  copyFileSync(configPath, join(configDestDir, 'config.yml'));

  // 3b. Layer any caller-supplied extra files onto the repo stage dir.
  //     Written before mkfs.ext4 -d so they end up on the immutable repo
  //     disk. Used by the macOS CLI to inject .yarnrc.yml and
  //     etc/script-jail/pm-flags.json. Defence in depth: reject any
  //     relPath that resolves outside the stage dir so a malicious caller
  //     can't traverse via `..` into the host filesystem.
  if (extraRepoOverlayFiles !== undefined) {
    const stageRoot = resolve(repoStageDir);
    for (const entry of extraRepoOverlayFiles) {
      const dest = resolve(stageRoot, entry.relPath);
      if (dest !== stageRoot && !dest.startsWith(stageRoot + '/')) {
        throw new Error(
          `[overlay] extraRepoOverlayFiles entry '${entry.relPath}' escapes the repo stage dir`,
        );
      }
      writeOverlayFile(stageRoot, entry.relPath, entry.content);
    }
  }

  // 4. Build the repo disk ext4.
  const repoDiskPath = join(workDir, 'repo.ext4');
  await buildExt4Disk({
    srcDir: repoStageDir,
    label: 'repo',
    sizeMB: estimateDiskSizeMB(repoStageDir),
    outPath: repoDiskPath,
  });

  // 5. Build the EMPTY scratch disk ext4.  Same creation mechanism as
  //    repo.ext4, just no content seed.  The guest resolves it via
  //    `blkid -L scratch`, so the label must be exactly `scratch`.
  const scratchDiskPath = join(workDir, 'scratch.ext4');
  await buildExt4Disk({
    label: SCRATCH_DISK_LABEL,
    sizeMB: SCRATCH_DISK_MB,
    outPath: scratchDiskPath,
  });

  const cleanup = async (): Promise<void> => {
    try {
      await rm(workDir, { recursive: true, force: true });
    } catch (err) {
      console.warn(`[overlay] cleanup warning: ${String(err)}`);
    }
  };

  return { rootfsCopyPath, repoDiskPath, scratchDiskPath, workDir, cleanup };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function writeOverlayFile(root: string, relPath: string, content: string): void {
  const parts = relPath.split('/').filter((part) => part.length > 0);
  if (parts.length === 0 || parts.some((part) => part === '..')) {
    throw new Error(
      `[overlay] extraRepoOverlayFiles entry '${relPath}' is not a safe relative path`,
    );
  }

  let dir = root;
  for (const part of parts.slice(0, -1)) {
    dir = join(dir, part);
    ensureRealDirectory(dir);
  }

  const dest = join(dir, parts[parts.length - 1]!);
  rmSync(dest, { recursive: true, force: true });
  writeFileSync(dest, content, { encoding: 'utf8', flag: 'wx' });
}

function ensureRealDirectory(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
    return;
  }
  const stat = lstatSync(path);
  if (stat.isDirectory() && !stat.isSymbolicLink()) return;
  rmSync(path, { recursive: true, force: true });
  mkdirSync(path, { recursive: true });
}

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
 * Build a small ext4 image, optionally seeded from `srcDir` content.
 *
 * On Linux: `mkfs.ext4 [-d <srcDir>]` (no mount required, no root).  mke2fs
 * creates the output file itself when an explicit size is given, so an
 * EMPTY disk (no `srcDir`) needs no pre-allocation step.
 * On macOS: prefer native `mkfs.ext4` from homebrew's `e2fsprogs` (keg-only,
 * located under `$(brew --prefix e2fsprogs)/sbin`); fall back to a Docker
 * Alpine helper if e2fsprogs isn't installed.  Docker is no longer
 * pre-installed on GitHub-hosted macOS runners, so CI relies on the native
 * path.
 *
 * The image is sparse, so the actual host disk footprint is just
 * `metadata + content` — not the full logical `sizeMB`.
 */
async function buildExt4Disk(opts: {
  /**
   * Directory whose content seeds the image (`mkfs.ext4 -d`).  Omit to
   * produce an empty filesystem (scratch disk).
   */
  srcDir?: string;
  /** Filesystem label (`mkfs.ext4 -L`).  The guest mounts by label. */
  label: string;
  /** Logical image size in MiB. */
  sizeMB: number;
  outPath: string;
}): Promise<void> {
  const { srcDir, label, sizeMB, outPath } = opts;
  const sizeSpec = `${sizeMB}M`;

  const mkfs = resolveMkfsExt4();
  if (mkfs !== null) {
    const result = spawnSync(
      mkfs,
      [
        ...(srcDir !== undefined ? ['-d', srcDir] : []),
        '-L', label,
        '-O', '^has_journal',
        '-m', '0',
        outPath,
        sizeSpec,
      ],
      { stdio: 'inherit' },
    );
    if (result.status !== 0) {
      throw new Error(
        `mkfs.ext4 for ${label} disk failed (exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
      );
    }
    return;
  }

  // Last-resort macOS fallback: Docker Alpine.  Only reachable when e2fsprogs
  // is not installed; on CI we install it explicitly so this branch is dead.
  const outDir = join(outPath, '..');
  const imageName = basename(outPath);
  const srcMount = srcDir !== undefined ? `-v "${srcDir}:/work:ro" ` : '';
  const seedFlag = srcDir !== undefined ? '-d /work ' : '';
  execSync(
    `docker run --rm ` +
    srcMount +
    `-v "${outDir}:/out" ` +
    `alpine:latest ` +
    `sh -c ` +
    `"apk add --no-cache e2fsprogs && ` +
    ` mkfs.ext4 ${seedFlag}-L ${label} -O ^has_journal -m 0 /out/${imageName} ${sizeSpec}"`,
    { stdio: 'inherit' },
  );
}

/**
 * Locate a usable `mkfs.ext4` binary.
 *
 * - Linux: returns the bare command name; PATH lookup is fine and the binary
 *   ships with the e2fsprogs package every Ubuntu/Debian/etc. ships by default.
 * - macOS: probes the homebrew keg-only e2fsprogs install (Apple Silicon
 *   `/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4`, Intel
 *   `/usr/local/opt/e2fsprogs/sbin/mkfs.ext4`), then falls back to PATH so a
 *   user who manually symlinked or PATH-exported the binary still works.
 *   Returns `null` when nothing was found so the caller can fall back to the
 *   docker helper.
 */
function resolveMkfsExt4(): string | null {
  if (platform === 'linux') return 'mkfs.ext4';
  if (platform !== 'darwin') return null;
  for (const candidate of [
    '/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4',
    '/usr/local/opt/e2fsprogs/sbin/mkfs.ext4',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH lookup via `command -v`; cheap and avoids hard-coding more paths.
  const lookup = spawnSync('command', ['-v', 'mkfs.ext4'], { shell: '/bin/sh', encoding: 'utf8' });
  if (lookup.status === 0 && lookup.stdout.trim()) return lookup.stdout.trim();
  return null;
}

/**
 * Floor for the repo overlay disk. Sized so that real-world monorepos
 * (vuejs/core, next.js, etc.) have room to materialise their full
 * dependency graph + pnpm-store hard-link tree without ENOSPC.
 *
 * The image is sparse, so the on-host footprint is just `metadata + content`
 * — bumping this number doesn't bloat the rootfs artifact or the per-VM
 * temp dir; it only enlarges the *logical* address space the guest sees.
 */
const REPO_DISK_MIN_MB = 4096;

/**
 * Filesystem label of the scratch disk.  LOAD-BEARING: the guest resolves the
 * device via `blkid -L scratch` — change it and the guest silently loses its
 * strace/event spill space.
 */
const SCRATCH_DISK_LABEL = 'scratch';

/**
 * Logical size of the empty scratch disk (MiB).  Sized so strace -ff logs and
 * the events JSONL of large monorepo installs fit comfortably; sparse on the
 * host, so the actual footprint is just ext4 metadata.
 */
const SCRATCH_DISK_MB = 4096;

/**
 * Recursively sum the size of files under `dir` and return a size in MB
 * (`max(REPO_DISK_MIN_MB, 2× content)` — headroom for node_modules writes).
 */
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
  return Math.max(REPO_DISK_MIN_MB, estimatedMB);
}

// script-jail — src/action/firecracker/overlay.ts
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
//                       files and the script-jail config YAML.  The guest's
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
//   1. Disk with filesystem label `repo` (resolved via `blkid -L repo`)
//      → mounted read-only at /work.
//   2. /work/etc/script-jail/config.yml → copied into /etc/script-jail/config.yml.
//   3. Disk with filesystem label `host-node` (resolved via `blkid -L host-node`)
//      → mounted read-only at /opt/host-node, /opt/host-node/bin prepended to PATH.
//   4. The agent execs as `node /usr/local/lib/script-jail/guest-agent.cjs` so
//      `node` resolves to the host-mounted binary.

import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  copyFileSync,
  statSync,
  existsSync,
  writeFileSync,
} from 'node:fs';
import { rm } from 'node:fs/promises';
import { join, basename, dirname } from 'node:path';
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
   * Absolute path to the runner's Node install prefix (the directory that
   * contains bin/node, lib/, include/, etc.).  Derived at the action level
   * by `resolveHostNodePrefix()`, which walks PATH (NOT process.execPath —
   * that would resolve to the GitHub Actions runner's bundled Node20 used
   * to execute dist/main.cjs, not the user-selected Node).  The whole tree
   * is packed into a tiny ext4 attached to the VM at /opt/host-node and
   * mounted read-only by the guest.
   */
  hostNodePrefix: string;
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
   * Used by the macOS CLI (PR 2+) to layer per-PM install-arg overlays;
   * the existing action surface leaves this undefined.
   */
  extraRepoOverlayFiles?: ReadonlyArray<{ relPath: string; content: string }>;
}

export interface OverlayResult {
  /** Per-run rootfs copy that Firecracker mounts as the root device. */
  rootfsCopyPath: string;
  /** Small ext4 containing the user's repo + script-jail config, mounted at /work. */
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
  //     disk.  Used by the macOS CLI (PR 2+) to inject .yarnrc.yml and
  //     etc/script-jail/pm-flags.json.  Defence in depth: reject any
  //     relPath that resolves outside the stage dir so a malicious caller
  //     can't traverse via `..` into the host filesystem.
  if (extraRepoOverlayFiles !== undefined) {
    for (const entry of extraRepoOverlayFiles) {
      const dest = join(repoStageDir, entry.relPath);
      const destNormalized = join(dest); // collapses .. segments
      if (!destNormalized.startsWith(repoStageDir + '/') && destNormalized !== repoStageDir) {
        throw new Error(
          `[overlay] extraRepoOverlayFiles entry '${entry.relPath}' escapes the repo stage dir`,
        );
      }
      mkdirSync(dirname(destNormalized), { recursive: true });
      writeFileSync(destNormalized, entry.content, 'utf8');
    }
  }

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
 * On macOS: prefer native `mkfs.ext4` from homebrew's `e2fsprogs` (keg-only,
 * located under `$(brew --prefix e2fsprogs)/sbin`); fall back to a Docker
 * Alpine helper if e2fsprogs isn't installed.  Docker is no longer
 * pre-installed on GitHub-hosted macOS runners, so CI relies on the native
 * path.
 *
 * Size is estimated at max(REPO_DISK_MIN_MB, 2× the source dir size). The
 * floor (4 GB) gives the guest enough headroom to run `pnpm install` /
 * `npm install` against real-world monorepos (e.g. vuejs/core's ~500 MB
 * dependency graph) without ENOSPC inside the VM. The image is sparse, so
 * the actual host disk footprint is just `metadata + content` — not 4 GB.
 */
async function buildRepoDisk(srcDir: string, outPath: string): Promise<void> {
  const sizeMB = estimateDiskSizeMB(srcDir);
  const sizeSpec = `${sizeMB}M`;

  const mkfs = resolveMkfsExt4();
  if (mkfs !== null) {
    const result = spawnSync(
      mkfs,
      [
        '-d', srcDir,
        '-L', 'repo',
        '-O', '^has_journal',
        '-m', '0',
        outPath,
        sizeSpec,
      ],
      { stdio: 'inherit' },
    );
    if (result.status !== 0) {
      throw new Error(
        `mkfs.ext4 for repo disk failed (exit ${result.status ?? 'unknown'}, signal ${result.signal ?? 'none'})`,
      );
    }
    return;
  }

  // Last-resort macOS fallback: Docker Alpine.  Only reachable when e2fsprogs
  // is not installed; on CI we install it explicitly so this branch is dead.
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
  return Math.max(REPO_DISK_MIN_MB, estimatedMB);
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
 * label (via `blkid -L host-node`) rather than by a /dev/vd* path, which
 * depends on Firecracker's drive registration order and which drives the
 * caller chose to register.
 */
async function buildHostNodeDisk(hostNodePrefix: string, outPath: string): Promise<void> {
  const sizeMB = estimateHostNodeDiskSizeMB(hostNodePrefix);
  const sizeSpec = `${sizeMB}M`;

  // Defensive: even though `hostNodePrefix` is validated by
  // resolveHostNodePrefix() before reaching here, we use argv-form spawn so
  // any path-with-spaces or stray shell metacharacters cannot break out.
  // buildRepoDisk() uses the older string-form execSync for the docker
  // fallback; that path operates on a workDir we created via mkdtempSync()
  // so the same risk does not apply.
  const mkfs = resolveMkfsExt4();
  if (mkfs !== null) {
    const result = spawnSync(
      mkfs,
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
    return;
  }

  // Last-resort macOS fallback: Docker Alpine.  Mount the prefix read-only
  // and the out dir read-write; mkfs.ext4 runs inside the container at a
  // fixed path so the user-controlled prefix never reaches the inner shell.
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

/**
 * Size estimator for the host-node disk: max(64 MB, 1.5× source-tree size).
 *
 * Separate from estimateDiskSizeMB() because the floor (64 MB vs the repo
 * disk's 4 GB) and multiplier (1.5 vs 2) differ — Node installs are
 * well-known in size so we don't need as much slack.
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

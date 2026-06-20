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
  /**
   * SECURITY (pre-trust bare-name host RCE): env handed to the host disk-build
   * spawns below (`cp --reflink=auto`, `mkfs.ext4`, the `command -v` probe, and
   * the macOS Docker-Alpine fallback).  These resolve by BARE NAME on the host
   * BEFORE the audit trust gate, so the caller MUST pass an env whose dangerous
   * loader/config selectors are stripped and whose PATH has checkout-controlled
   * dirs dropped — the Firecracker backend threads its ONE `stripDangerousEnv`
   * result down (see backend/firecracker.ts).  Omitted ⇒ `process.env` (the
   * legacy macOS CLI / VZ launch path keeps its prior behaviour; this module
   * never derives the sanitized env itself — it only receives it).
   */
  env?: NodeJS.ProcessEnv | undefined;
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
  /**
   * EMPTY per-run ext4 (filesystem label `sjtmp`, 4096 MiB logical, sparse)
   * the guest mounts read-write at /sjtmp and exports as TMPDIR.  A dedicated
   * disk (not /work, not /scratch): yarn Berry's tarball→zip staging needs
   * gigabytes of tmp on large monorepos, and a MOUNTPOINT cannot be symlink-
   * swapped by a Phase-A lifecycle script — init.sh drops CAP_SYS_ADMIN before
   * any repo code runs, so umount/`mount --bind` over /sjtmp return EPERM
   * (closing the TOCTOU that the old `/work/.sj-tmp` repo-disk scheme could
   * not).
   */
  sjtmpDiskPath: string;
  /** The working directory (contains all ext4 images). */
  workDir: string;
  /** Removes the entire workDir tree.  Never throws. */
  cleanup: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// makeOverlay
// ---------------------------------------------------------------------------

export async function makeOverlay(input: OverlayInput): Promise<OverlayResult> {
  // 1. Create per-run work dir if not supplied.
  const workDir = input.workDir ?? mkdtempSync(join(tmpdir(), 'script-jail-run-'));
  mkdirSync(workDir, { recursive: true });

  // Everything below populates workDir.  If any build step throws after this
  // point (rootfs copy, repo staging, repo/scratch mkfs), the caller never
  // receives the `cleanup` closure and could not remove the partially built
  // tree — which by then can hold a full rootfs copy plus a multi-GB-logical
  // repo image (Codex review 2026-06-12, round-1 medium finding).  Remove the
  // workDir ourselves before rethrowing; mirror cleanup()'s never-throw rule
  // so the removal failure can't mask the original error.
  try {
    return await buildOverlayInto(workDir, input);
  } catch (err) {
    try {
      await rm(workDir, { recursive: true, force: true });
    } catch (rmErr) {
      console.warn(`[overlay] partial-build cleanup warning: ${String(rmErr)}`);
    }
    throw err;
  }
}

/** Body of {@link makeOverlay}: builds all three images inside `workDir`. */
async function buildOverlayInto(
  workDir: string,
  input: OverlayInput,
): Promise<OverlayResult> {
  const { baseRootfsPath, repoSrcPath, configPath, extraRepoOverlayFiles } = input;
  // SECURITY: the host disk-build spawns below are bare-name + pre-trust — use the
  // caller-sanitized env (Firecracker backend threads `stripDangerousEnv` down).
  // Default to process.env only for the legacy macOS CLI / VZ path that omits it.
  const env = input.env ?? process.env;

  // 2. Copy the base rootfs (CoW where supported, plain copy otherwise).
  const rootfsCopyPath = join(workDir, 'rootfs.ext4');
  copyRootfs(baseRootfsPath, rootfsCopyPath, env);

  // 3. Stage the repo + config into a temp directory tree that will become
  //    the content of repo.ext4.
  const repoStageDir = join(workDir, 'repo-stage');
  mkdirSync(repoStageDir, { recursive: true });

  // Copy repository files.  `verbatimSymlinks` keeps a committed RELATIVE symlink
  // relative (cpSync would otherwise rewrite it to its realpath absolute target),
  // so the audit and the host part-2 re-run resolve it identically — closing the
  // staged-symlink escape (Codex re-review; mirror of stage.ts).  No-op for current
  // fixtures (none commit a symlink).
  cpSync(repoSrcPath, repoStageDir, { recursive: true, dereference: false, verbatimSymlinks: true });

  // Overlay the script-jail config at the path the guest agent expects:
  //   /etc/script-jail/config.yml  →  inside the repo stage dir we write it at
  //   repo-stage/etc/script-jail/config.yml so it is accessible after the guest
  //   mounts this disk at /work.
  //
  // NOTE: The guest's init.sh mounts the repo disk at /work, so paths inside
  // the disk are relative to /work.  The agent reads config from
  // /etc/script-jail/config.yml which is on the rootfs; the init.sh copies it
  // from /work/etc/script-jail/config.yml into /etc/script-jail/ at boot.
  // Create the overlay dirs through the same fail-closed helper writeOverlayFile
  // uses, per-segment, so a committed symlink/file at `etc` or `etc/script-jail`
  // aborts the audit instead of being silently replaced in the staged copy only
  // (Codex re-review, overlay-ancestor-symlink escape).
  ensureRealDirectory(join(repoStageDir, 'etc'));
  const configDestDir = join(repoStageDir, 'etc', 'script-jail');
  ensureRealDirectory(configDestDir);
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
    env,
  });

  // 5. Build the EMPTY scratch disk ext4.  Same creation mechanism as
  //    repo.ext4, just no content seed.  The guest resolves it via
  //    `blkid -L scratch`, so the label must be exactly `scratch`.
  const scratchDiskPath = join(workDir, 'scratch.ext4');
  await buildExt4Disk({
    label: SCRATCH_DISK_LABEL,
    sizeMB: SCRATCH_DISK_MB,
    outPath: scratchDiskPath,
    env,
  });

  // 6. Build the EMPTY sjtmp disk ext4.  Dedicated TMPDIR space: a separate
  //    filesystem from /work (repo) and /scratch (audit), so a large-repo
  //    install's tmp churn can't ENOSPC either, and — being a MOUNTPOINT —
  //    cannot be symlink-redirected by Phase-A repo code.  Guest resolves it
  //    via `blkid -L sjtmp`, so the label must be exactly `sjtmp`.
  const sjtmpDiskPath = join(workDir, 'sjtmp.ext4');
  await buildExt4Disk({
    label: SJTMP_DISK_LABEL,
    sizeMB: SJTMP_DISK_MB,
    outPath: sjtmpDiskPath,
    env,
  });

  const cleanup = async (): Promise<void> => {
    try {
      await rm(workDir, { recursive: true, force: true });
    } catch (err) {
      console.warn(`[overlay] cleanup warning: ${String(err)}`);
    }
  };

  return { rootfsCopyPath, repoDiskPath, scratchDiskPath, sjtmpDiskPath, workDir, cleanup };
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
  let stat;
  try {
    // lstat (no-follow on the FINAL component): inspect THIS ancestor segment
    // itself, called per-segment so a symlinked `etc` is seen as a symlink here.
    stat = lstatSync(path);
  } catch {
    mkdirSync(path, { recursive: true }); // absent → create a real dir
    return;
  }
  if (stat.isDirectory() && !stat.isSymbolicLink()) return; // already a real dir
  // SECURITY (Codex re-review, overlay-ancestor-symlink escape): the segment EXISTS
  // but is NOT a real directory (a committed SYMLINK incl. dangling/symlink-to-dir, or
  // a regular FILE).  Replacing it would mutate the staged copy ONLY — the host's real
  // checkout keeps the committed symlink/file, so host part-2 resolves a path through it
  // to PR content the audit (seeing a fresh real dir) never resolved, executing it under
  // a trusted lock.  Fail closed: throw aborts the audit (untrusted ⇒ no host install).
  // Single chokepoint over every overlay path × ancestor segment.  (Mirror of stage.ts.)
  throw new Error(
    `[overlay] cannot stage script-jail overlay: the checkout has a non-directory at ` +
      `'${path}' (a committed symlink or file) where script-jail needs a real directory. ` +
      `install:true refuses to replace it — that would make the audit diverge from the ` +
      `host checkout. Remove it from the checkout, or audit without 'install'.`,
  );
}

/**
 * Copy the base rootfs image to `destPath`.
 *
 * On Linux we attempt `cp --reflink=auto` for a CoW clone (fast on btrfs/xfs).
 * Falls back to a regular copy on any error or on macOS.
 */
function copyRootfs(src: string, dest: string, env: NodeJS.ProcessEnv): void {
  if (platform === 'linux') {
    // SECURITY: `cp` is bare-name + pre-trust — the caller-sanitized `env`
    // ensures a checkout-prepended PATH or inherited loader var can't hijack it.
    const result = spawnSync('cp', ['--reflink=auto', src, dest], { stdio: 'ignore', env });
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
  /**
   * SECURITY: env for the bare-name + pre-trust host spawns (`mkfs.ext4`, the
   * `command -v` probe, the macOS Docker fallback).  Caller-sanitized — see
   * OverlayInput.env.
   */
  env: NodeJS.ProcessEnv;
}): Promise<void> {
  const { srcDir, label, sizeMB, outPath, env } = opts;
  const sizeSpec = `${sizeMB}M`;

  const mkfs = resolveMkfsExt4(env);
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
      // SECURITY: bare `mkfs.ext4` on Linux is resolved via PATH pre-trust — the
      // caller-sanitized `env` prevents a checkout-prepended PATH / loader var hijack.
      { stdio: 'inherit', env },
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
    // SECURITY: `docker`/`sh` resolve by bare name pre-trust — use the
    // caller-sanitized `env` so a checkout PATH / loader var can't hijack them.
    { stdio: 'inherit', env },
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
function resolveMkfsExt4(env: NodeJS.ProcessEnv): string | null {
  if (platform === 'linux') return 'mkfs.ext4';
  if (platform !== 'darwin') return null;
  for (const candidate of [
    '/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4',
    '/usr/local/opt/e2fsprogs/sbin/mkfs.ext4',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  // Try PATH lookup via `command -v`; cheap and avoids hard-coding more paths.
  // SECURITY: the `command -v` probe (and the `mkfs.ext4` it resolves) run
  // bare-name + pre-trust — pass the caller-sanitized `env` so a checkout PATH
  // entry can't surface a PR-planted `mkfs.ext4` here.
  const lookup = spawnSync('command', ['-v', 'mkfs.ext4'], { shell: '/bin/sh', encoding: 'utf8', env });
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
 * Filesystem label of the sjtmp disk.  LOAD-BEARING: the guest resolves the
 * device via `blkid -L sjtmp` and mounts it at /sjtmp (exported as TMPDIR) —
 * change it and the guest fails closed at boot (init.sh).
 */
const SJTMP_DISK_LABEL = 'sjtmp';

/**
 * Logical size of the empty sjtmp disk (MiB).  Sized so a large monorepo's
 * package-manager tmp churn (yarn Berry stages every tarball→zip conversion
 * in TMPDIR — ~488 MiB for napi-rs) fits comfortably; sparse on the host, so
 * the actual footprint is just ext4 metadata.
 */
const SJTMP_DISK_MB = 4096;

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

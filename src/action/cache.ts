// npm-jar — src/action/cache.ts
//
// Honors the `cache-firecracker` action input.
//
// When `cache-firecracker: true` (the default) we leave `imagesDir` alone so
// repeat workflow runs reuse the previously downloaded Firecracker binary +
// vmlinux.  This is the fast path.
//
// When `cache-firecracker: false`, we remove only the artifacts that
// `ensureBinaries` knows how to re-download (the Firecracker release tarball,
// the extracted binary, and the vmlinux kernel image), forcing a fresh
// download path on the next run.  Useful for forcing a re-pull after
// rotating the pinned SHAs in `src/main.ts`, or to validate the download
// path on demand.
//
// CRITICAL: we deliberately do NOT wipe the entire `imagesDir` tree.  The
// per-runner-image rootfs (`rootfs-<runner>.ext4`) also lives there but is
// provisioned by an out-of-band step (see `src/main.ts` comments next to
// `baseRootfsPath`), not by `ensureBinaries`.  A blanket `rmSync(imagesDir,
// { recursive: true })` would delete the rootfs without anything restoring
// it before `makeOverlay()` runs, breaking the VM launch.  Owner-scoped
// removal keeps `cache-firecracker: false` safe.

import { rmSync } from 'node:fs';
import { join } from 'node:path';

export interface MaybeClearCacheInput {
  imagesDir: string;
  cacheFirecracker: boolean;
  /**
   * Firecracker release version used to derive the tarball + binary
   * filenames inside `imagesDir`.  Must match the value passed to
   * `ensureBinaries`.
   */
  firecrackerVersion: string;
  /**
   * Optional injection seam for tests.  Production uses the real `node:fs`
   * `rmSync`.  Tests inject a spy to assert which paths get removed without
   * touching the real filesystem.
   */
  fs?: {
    rmSync: typeof rmSync;
  };
}

/**
 * If `cacheFirecracker` is `false`, remove the Firecracker tarball, the
 * extracted binary, and the vmlinux kernel image from `imagesDir`.  These
 * are the only artifacts `ensureBinaries` re-downloads on the next run.
 * Other files in `imagesDir` (notably the rootfs ext4 image, which lives
 * alongside but is provisioned by a separate step) are left untouched.
 *
 * No-op when `cacheFirecracker` is `true`.
 */
export function maybeClearCache(input: MaybeClearCacheInput): void {
  if (input.cacheFirecracker) return;

  const fs = input.fs ?? { rmSync };
  const tarPath = join(
    input.imagesDir,
    `firecracker-v${input.firecrackerVersion}-x86_64.tgz`,
  );
  const fcBinPath = join(
    input.imagesDir,
    `firecracker-v${input.firecrackerVersion}`,
  );
  const vmlinuxPath = join(input.imagesDir, 'vmlinux');

  // `force: true` swallows ENOENT — first-run case where there's nothing to
  // delete is a valid no-op, not an error.
  fs.rmSync(tarPath, { force: true });
  fs.rmSync(fcBinPath, { force: true });
  fs.rmSync(vmlinuxPath, { force: true });
}

// npm-jar — test/action/cache.test.ts
//
// Tests for `maybeClearCache`.  We use the `fs` injection seam exclusively so
// the tests assert call ordering and arguments without touching the real
// filesystem.

import { describe, it, expect, vi } from 'vitest';
import { join } from 'node:path';

import { maybeClearCache } from '../../src/action/cache.js';

const imagesDir = '/tmp/npm-jar-images';
const firecrackerVersion = '1.8.0';
const tarPath = join(imagesDir, `firecracker-v${firecrackerVersion}-x86_64.tgz`);
const fcBinPath = join(imagesDir, `firecracker-v${firecrackerVersion}`);
const vmlinuxPath = join(imagesDir, 'vmlinux');

describe('maybeClearCache', () => {
  it('is a no-op when cacheFirecracker is true', () => {
    const rmSync = vi.fn();

    maybeClearCache({
      imagesDir,
      firecrackerVersion,
      cacheFirecracker: true,
      fs: { rmSync },
    });

    expect(rmSync).not.toHaveBeenCalled();
  });

  it('removes only the Firecracker tarball, binary, and vmlinux when cacheFirecracker is false', () => {
    const rmSync = vi.fn();

    maybeClearCache({
      imagesDir,
      firecrackerVersion,
      cacheFirecracker: false,
      fs: { rmSync },
    });

    // Three targeted removals — and only these three.
    expect(rmSync).toHaveBeenCalledTimes(3);
    expect(rmSync).toHaveBeenCalledWith(tarPath, { force: true });
    expect(rmSync).toHaveBeenCalledWith(fcBinPath, { force: true });
    expect(rmSync).toHaveBeenCalledWith(vmlinuxPath, { force: true });
  });

  it('does NOT remove the rootfs ext4 image (provisioned out-of-band, not by ensureBinaries)', () => {
    // Regression guard for the original "wipe entire imagesDir" design which
    // would have deleted the rootfs `ensureBinaries` does not recreate,
    // breaking the next `makeOverlay()` call.
    const rmSync = vi.fn();

    maybeClearCache({
      imagesDir,
      firecrackerVersion,
      cacheFirecracker: false,
      fs: { rmSync },
    });

    const targets = rmSync.mock.calls.map((call) => call[0] as string);
    // No call should target `imagesDir` itself or anything that looks like a
    // rootfs image.
    expect(targets).not.toContain(imagesDir);
    for (const t of targets) {
      expect(t).not.toMatch(/rootfs-.*\.ext4$/);
    }
  });
});

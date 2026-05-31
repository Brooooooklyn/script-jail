// script-jail — test/cli/rootfs-cache.test.ts
//
// Unit tests for the npm-shipped compressed rootfs path. The CLI receives a
// .ext4.gz in the published package, then materializes a sparse raw ext4 under
// the user's cache before makeOverlay copies it for a VM run.

import { afterEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { ensureRootfs } from '../../src/cli/rootfs-cache.js';

let scratch: string | undefined;

afterEach(() => {
  if (scratch !== undefined) {
    rmSync(scratch, { recursive: true, force: true });
    scratch = undefined;
  }
});

function tempDir(): string {
  scratch = mkdtempSync(join(tmpdir(), 'script-jail-rootfs-cache-test-'));
  return scratch;
}

function sampleRootfsBytes(): Buffer {
  const bytes = Buffer.alloc(128 * 1024, 0);
  Buffer.from('script-jail-rootfs-cache-test').copy(bytes, 4096);
  Buffer.from('non-zero-tail').copy(bytes, bytes.length - 4096);
  return bytes;
}

describe('ensureRootfs', () => {
  it('returns the raw rootfs path when it already exists', async () => {
    const dir = tempDir();
    const rootfsPath = join(dir, 'rootfs-ubuntu-24.04-arm64.ext4');
    const compressedRootfsPath = `${rootfsPath}.gz`;
    const cacheDir = join(dir, 'cache');
    writeFileSync(rootfsPath, 'raw-rootfs');
    writeFileSync(compressedRootfsPath, gzipSync(Buffer.from('ignored')));

    await expect(ensureRootfs({ rootfsPath, compressedRootfsPath, cacheDir }))
      .resolves.toBe(rootfsPath);
    expect(existsSync(cacheDir)).toBe(false);
  });

  it('returns the requested raw path when neither raw nor compressed rootfs exists', async () => {
    const dir = tempDir();
    const rootfsPath = join(dir, 'missing.ext4');

    await expect(ensureRootfs({
      rootfsPath,
      compressedRootfsPath: `${rootfsPath}.gz`,
      cacheDir: join(dir, 'cache'),
    })).resolves.toBe(rootfsPath);
  });

  it('expands a compressed rootfs into a reusable cache entry', async () => {
    const dir = tempDir();
    const rootfsPath = join(dir, 'rootfs-ubuntu-24.04-arm64.ext4');
    const compressedRootfsPath = `${rootfsPath}.gz`;
    const cacheDir = join(dir, 'cache');
    const original = sampleRootfsBytes();
    writeFileSync(compressedRootfsPath, gzipSync(original));

    const materialized = await ensureRootfs({ rootfsPath, compressedRootfsPath, cacheDir });
    expect(materialized).not.toBe(rootfsPath);
    expect(materialized.startsWith(cacheDir)).toBe(true);
    expect(materialized.endsWith('.ext4')).toBe(true);
    expect(statSync(materialized).size).toBe(original.length);
    expect(readFileSync(materialized)).toEqual(original);

    const meta = JSON.parse(readFileSync(`${materialized}.json`, 'utf8')) as Record<string, unknown>;
    expect(meta['logicalSize']).toBe(original.length);
    expect(meta['compressedSha256']).toMatch(/^[a-f0-9]{64}$/);

    await expect(ensureRootfs({ rootfsPath, compressedRootfsPath, cacheDir }))
      .resolves.toBe(materialized);
  });

  it('rematerializes a cache entry when its metadata no longer matches', async () => {
    const dir = tempDir();
    const rootfsPath = join(dir, 'rootfs-ubuntu-24.04-arm64.ext4');
    const compressedRootfsPath = `${rootfsPath}.gz`;
    const cacheDir = join(dir, 'cache');
    const original = sampleRootfsBytes();
    writeFileSync(compressedRootfsPath, gzipSync(original));

    const materialized = await ensureRootfs({ rootfsPath, compressedRootfsPath, cacheDir });
    writeFileSync(`${materialized}.json`, JSON.stringify({
      compressedSha256: '0'.repeat(64),
      logicalSize: original.length,
    }));

    await expect(ensureRootfs({ rootfsPath, compressedRootfsPath, cacheDir }))
      .resolves.toBe(materialized);
    expect(readFileSync(materialized)).toEqual(original);
  });
});

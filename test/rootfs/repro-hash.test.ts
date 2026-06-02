// script-jail — test/rootfs/repro-hash.test.ts
//
// Unit coverage for the canonical (time-masked) rootfs hash.  No real ext4 is
// built here — the byte math is exercised against pinned offsets and synthetic
// buffers/files.  The end-to-end "does the mask match a REAL ext4's superblock
// layout" check lives in test/integration/rootfs-reproducibility.test.ts (it
// cross-checks these computed offsets against dumpe2fs on Linux CI).

import { describe, it, expect, afterEach } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  EXT4_BLOCK_SIZE,
  EXT4_BLOCKS_PER_GROUP,
  EXT4_VOLATILE_SUPERBLOCK_FIELDS,
  hasSuperblock,
  superblockByteOffset,
  ext4VolatileByteRanges,
  applyMaskToBuffer,
  canonicalRootfsHash,
} from '../../src/rootfs/repro-hash.js';

const ONE_GIB = 1024 * 1024 * 1024;

const tmpFiles: string[] = [];
function tmpFile(): string {
  const p = join(tmpdir(), `script-jail-reprohash-${randomBytes(6).toString('hex')}.bin`);
  tmpFiles.push(p);
  return p;
}
afterEach(() => {
  while (tmpFiles.length > 0) {
    try { rmSync(tmpFiles.pop()!, { force: true }); } catch { /* ignore */ }
  }
});

describe('hasSuperblock (classic sparse_super)', () => {
  it('includes 0, 1, and powers of 3/5/7', () => {
    for (const g of [0, 1, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343]) {
      expect(hasSuperblock(g)).toBe(true);
    }
  });
  it('excludes everything else', () => {
    for (const g of [2, 4, 6, 8, 10, 11, 15, 24, 26, 35, 50, 100]) {
      expect(hasSuperblock(g)).toBe(false);
    }
  });
});

describe('superblockByteOffset', () => {
  it('places the primary superblock at byte 1024', () => {
    expect(superblockByteOffset(0)).toBe(1024);
  });
  it('places backups at the first byte of their group', () => {
    expect(superblockByteOffset(1)).toBe(EXT4_BLOCKS_PER_GROUP * EXT4_BLOCK_SIZE);
    expect(superblockByteOffset(3)).toBe(3 * EXT4_BLOCKS_PER_GROUP * EXT4_BLOCK_SIZE);
    // Concrete values for the 1 GiB rootfs geometry.
    expect(superblockByteOffset(1)).toBe(134217728);
    expect(superblockByteOffset(3)).toBe(402653184);
    expect(superblockByteOffset(5)).toBe(671088640);
    expect(superblockByteOffset(7)).toBe(939524096);
  });
});

describe('ext4VolatileByteRanges for the 1 GiB rootfs', () => {
  const ranges = ext4VolatileByteRanges(ONE_GIB);

  it('covers exactly the primary + sparse_super backups {0,1,3,5,7}', () => {
    // 8 groups (262144 blocks / 32768), superblocks in groups 0,1,3,5,7.
    const bases = [1024, 134217728, 402653184, 671088640, 939524096];
    const expected = bases.flatMap((base) =>
      EXT4_VOLATILE_SUPERBLOCK_FIELDS.map(([off, len]) => [base + off, len]),
    );
    expect(ranges).toEqual(expected);
    expect(ranges).toHaveLength(5 * EXT4_VOLATILE_SUPERBLOCK_FIELDS.length); // 25
  });

  it('does NOT include a group-9 superblock (out of range for 8 groups)', () => {
    const group9 = 9 * EXT4_BLOCKS_PER_GROUP * EXT4_BLOCK_SIZE;
    expect(ranges.some(([off]) => off >= group9)).toBe(false);
  });

  it('is sorted by offset', () => {
    const offs = ranges.map(([o]) => o);
    expect([...offs].sort((a, b) => a - b)).toEqual(offs);
  });

  it('includes s_wtime and s_checksum of the primary superblock', () => {
    expect(ranges).toContainEqual([1024 + 0x30, 4]); // s_wtime
    expect(ranges).toContainEqual([1024 + 0x3fc, 4]); // s_checksum
  });
});

describe('ext4VolatileByteRanges edge cases', () => {
  it('a single-block image has only the primary superblock', () => {
    const ranges = ext4VolatileByteRanges(EXT4_BLOCK_SIZE); // 4096 → 1 group
    expect(ranges).toHaveLength(EXT4_VOLATILE_SUPERBLOCK_FIELDS.length);
    expect(ranges.every(([off]) => off >= 1024 && off < 2048)).toBe(true);
  });

  it('skips a backup superblock that would not fully fit in the image', () => {
    // Image just one byte short of holding group 1's full superblock struct.
    const justShort = superblockByteOffset(1) + 1024 - 1;
    const ranges = ext4VolatileByteRanges(justShort);
    // Only the primary's fields remain.
    expect(ranges.every(([off]) => off < 2048)).toBe(true);
  });
});

describe('applyMaskToBuffer', () => {
  it('zeros a range fully inside the buffer', () => {
    const buf = Buffer.alloc(16, 0xff);
    applyMaskToBuffer(buf, 0, [[4, 4]]);
    expect([...buf]).toEqual([
      0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
  });

  it('zeros only the overlapping half of a range straddling the buffer start', () => {
    // Range [6,10) over a buffer representing file bytes [8,16): zero [8,10).
    const buf = Buffer.alloc(8, 0xff);
    applyMaskToBuffer(buf, 8, [[6, 4]]);
    expect([...buf.subarray(0, 2)]).toEqual([0, 0]);
    expect([...buf.subarray(2)]).toEqual([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  });

  it('leaves a non-overlapping buffer untouched', () => {
    const buf = Buffer.alloc(8, 0xff);
    applyMaskToBuffer(buf, 100, [[0, 4]]);
    expect(buf.every((b) => b === 0xff)).toBe(true);
  });
});

describe('canonicalRootfsHash', () => {
  // A 4 KiB synthetic "image": one block group, so only the primary
  // superblock's fields are masked (offsets 1024 + {0x2C,0x30,0x40,0x108,0x3FC}).
  function synthetic(fill: number): Buffer {
    return Buffer.alloc(EXT4_BLOCK_SIZE, fill);
  }

  it('is invariant to the masked superblock time fields', async () => {
    const a = synthetic(0xaa);
    const b = synthetic(0xaa);
    // Differ ONLY inside the masked s_wtime + s_checksum of the primary SB.
    b.writeUInt32LE(0xdeadbeef, 1024 + 0x30); // s_wtime
    b.writeUInt32LE(0x12345678, 1024 + 0x3fc); // s_checksum
    const fa = tmpFile();
    const fb = tmpFile();
    writeFileSync(fa, a);
    writeFileSync(fb, b);
    expect(await canonicalRootfsHash(fa)).toBe(await canonicalRootfsHash(fb));
  });

  it('still changes when a NON-masked byte differs', async () => {
    const a = synthetic(0xaa);
    const b = synthetic(0xaa);
    b[100] = 0x00; // not inside any masked range
    const fa = tmpFile();
    const fb = tmpFile();
    writeFileSync(fa, a);
    writeFileSync(fb, b);
    expect(await canonicalRootfsHash(fa)).not.toBe(await canonicalRootfsHash(fb));
  });

  it('matches a hand-computed hash of the zeroed image', async () => {
    const a = synthetic(0xaa);
    a.writeUInt32LE(0xdeadbeef, 1024 + 0x30);
    const f = tmpFile();
    writeFileSync(f, a);
    // Reference: zero every masked range ourselves, then plain sha256.
    const ref = Buffer.from(a);
    for (const [off, len] of ext4VolatileByteRanges(ref.length)) {
      ref.fill(0, off, off + len);
    }
    const expected = createHash('sha256').update(ref).digest('hex');
    expect(await canonicalRootfsHash(f)).toBe(expected);
  });

  it('is independent of streaming chunk size (boundary-split fields)', async () => {
    const a = synthetic(0xaa);
    a.writeUInt32LE(0xcafef00d, 1024 + 0x30);
    const f = tmpFile();
    writeFileSync(f, a);
    const big = await canonicalRootfsHash(f);
    // 1074 puts a chunk boundary in the middle of the s_wtime field (1072..1076).
    expect(await canonicalRootfsHash(f, 1074)).toBe(big);
    expect(await canonicalRootfsHash(f, 1)).toBe(big);
  });
});

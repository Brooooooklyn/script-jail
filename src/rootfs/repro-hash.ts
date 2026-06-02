// script-jail — src/rootfs/repro-hash.ts
//
// Canonical (time-masked) SHA-256 of a rootfs ext4 image.
//
// Why this exists:
//   The rootfs build is reproducible CONTENT-wise (pinned mkfs layout +
//   SOURCE_DATE_EPOCH + a debugfs timestamp post-pass), but the SHIPPED
//   e2fsprogs (< 1.47.1 on ubuntu-22.04/24.04 runners) re-stamps the ext4
//   superblock `s_wtime` to the wall clock when it flushes on close — see the
//   comment in src/rootfs/build.ts:pinExt4TimestampsViaDebugfs.  That single
//   wall-clock field (and the metadata_csum that covers it) is the only thing
//   that drifts between two otherwise-identical builds at different times.
//
//   Rather than pin the build clock (libfaketime — fragile, extra apt dep), we
//   define the rootfs digest as the SHA-256 of the image with those volatile
//   superblock fields ZEROED.  Two builds that differ ONLY in the close-flush
//   wall clock hash identically; any real content/layout difference still
//   changes the hash.  Masking ignores time, it does not hide drift.
//
// This is THE definition of a rootfs ext4 digest everywhere it matters:
//   - the reproducibility gate (release.yml + the integration test),
//   - the value pinned into src/action/artifact-manifest.ts (Compute SHAs),
//   - the publish-job re-verification (scripts/check-publish-artifacts.sh, via
//     the committed dist/repro-hash-cli.cjs bundle),
//   - the consumer's download verification (src/action/pre-fetch-artifacts.ts).
//   The pinned manifest value is therefore a CANONICAL hash, not a raw
//   `sha256sum` of the released bytes.
//
// Pure: node built-ins only, no project imports — so it bundles cleanly into
// dist/main.cjs (consumer) AND into the standalone dist/repro-hash-cli.cjs the
// no-install publish job runs.

import { createHash } from 'node:crypto';
import { createReadStream, statSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Pinned ext4 geometry
// ---------------------------------------------------------------------------
//
// These mirror the layout buildMkfsExt4Args + src/rootfs/mke2fs.conf pin.  The
// canonical hash depends on them only to locate backup superblocks; if the
// geometry ever changes, the integration test's dumpe2fs cross-check
// (test/integration/rootfs-reproducibility.test.ts) fails loudly on Linux CI.

/** Block size pinned by `-b 4096` / mke2fs.conf `blocksize = 4096`. */
export const EXT4_BLOCK_SIZE = 4096;

/**
 * Blocks per group for a 4 KiB block size: one block bitmap block addresses
 * `8 * blocksize` blocks, and bigalloc (which would change this) is disabled.
 * This is the e2fsprogs default for our layout.
 */
export const EXT4_BLOCKS_PER_GROUP = 8 * EXT4_BLOCK_SIZE; // 32768

/**
 * Volatile superblock fields as `[offsetWithinSuperblock, lengthBytes]`.  The
 * superblock struct is 1024 bytes; these offsets are from struct
 * ext2_super_block:
 *   0x2C s_mtime, 0x30 s_wtime, 0x40 s_lastcheck, 0x108 s_mkfs_time,
 *   0x3FC s_checksum.
 *
 * `s_wtime` is the ONLY field the close-flush actually re-stamps on the shipped
 * e2fsprogs; `s_checksum` (metadata_csum) is recomputed whenever `s_wtime`
 * changes.  The other three time fields are pinned to the fixed epoch by the
 * debugfs post-pass and do not drift, but we zero them too so the canonical
 * hash stays time-agnostic regardless of future e2fsprogs behaviour.  Zeroing
 * deterministic fields is harmless: both builds zero the identical bytes.
 *
 * Scope/limitation of masking `s_checksum`: we MUST zero it (it tracks the
 * masked `s_wtime`, so leaving it would just reintroduce the drift through the
 * checksum).  The cost is that a difference confined to these few-hundred
 * superblock-metadata bytes — including a superblock whose metadata_csum
 * disagrees with its own contents — does not change the canonical hash.  That
 * is an accepted, narrow gap: these are superblock fields, not data/inode
 * blocks, so masking CANNOT hide tampered or injected file content (the threat
 * the publish gate defends against — that lives in unmasked bytes and still
 * changes the hash).  It can only fail to notice a self-inconsistent superblock
 * checksum.  Structural validity (would `e2fsck -fn` pass?) is deliberately out
 * of this digest's scope; the digest answers "same content/layout?", not "is
 * this a mountable filesystem?".
 */
export const EXT4_VOLATILE_SUPERBLOCK_FIELDS: ReadonlyArray<readonly [number, number]> = [
  [0x2c, 4], // s_mtime
  [0x30, 4], // s_wtime      — re-stamped to wall-clock on close (the real culprit)
  [0x40, 4], // s_lastcheck
  [0x108, 4], // s_mkfs_time
  [0x3fc, 4], // s_checksum   — metadata_csum over the superblock, follows s_wtime
];

/** Width of a superblock struct in bytes (must fully fit in the image). */
const SUPERBLOCK_STRUCT_BYTES = 1024;

// ---------------------------------------------------------------------------
// Superblock location math (classic sparse_super)
// ---------------------------------------------------------------------------

/**
 * Whether block group `group` carries a (backup) superblock under the classic
 * `sparse_super` rule: group 0, group 1, and every power of 3, 5, or 7.
 */
export function hasSuperblock(group: number): boolean {
  if (group === 0 || group === 1) return true;
  for (const base of [3, 5, 7]) {
    let power = base;
    while (power < group) power *= base;
    if (power === group) return true;
  }
  return false;
}

/**
 * Byte offset of the superblock struct for `group`.  Group 0's superblock lives
 * at byte 1024 (after the 1 KiB boot-block reservation); every backup starts at
 * the first byte of its group's first block.
 */
export function superblockByteOffset(group: number): number {
  return group === 0
    ? SUPERBLOCK_STRUCT_BYTES
    : group * EXT4_BLOCKS_PER_GROUP * EXT4_BLOCK_SIZE;
}

/**
 * The sorted, non-overlapping list of `[absoluteByteOffset, length]` ranges to
 * zero before hashing an ext4 image of `imageSizeBytes`: every volatile
 * superblock field in the primary AND every sparse_super backup superblock that
 * fully fits in the image.
 *
 * Ranges come out sorted by offset (groups ascending, fields ascending within a
 * group) — the streaming hasher relies on that ordering.
 */
export function ext4VolatileByteRanges(imageSizeBytes: number): Array<[number, number]> {
  const totalBlocks = Math.floor(imageSizeBytes / EXT4_BLOCK_SIZE);
  const numGroups = Math.ceil(totalBlocks / EXT4_BLOCKS_PER_GROUP);
  const ranges: Array<[number, number]> = [];
  for (let group = 0; group < numGroups; group += 1) {
    if (!hasSuperblock(group)) continue;
    const base = superblockByteOffset(group);
    // A backup superblock near the tail of a truncated image might not fully
    // fit; skip it rather than mask bytes past EOF.
    if (base + SUPERBLOCK_STRUCT_BYTES > imageSizeBytes) continue;
    for (const [fieldOffset, length] of EXT4_VOLATILE_SUPERBLOCK_FIELDS) {
      ranges.push([base + fieldOffset, length]);
    }
  }
  return ranges;
}

// ---------------------------------------------------------------------------
// Masking + hashing
// ---------------------------------------------------------------------------

/**
 * Zero, in place, the bytes of `buf` (a slice of the file starting at absolute
 * offset `bufStart`) that fall inside any `[offset, length]` range in `ranges`.
 * Handles ranges that straddle the chunk boundary: only the overlapping portion
 * is zeroed here; the remainder is zeroed when the adjacent chunk is processed.
 */
export function applyMaskToBuffer(
  buf: Buffer,
  bufStart: number,
  ranges: ReadonlyArray<readonly [number, number]>,
): void {
  const bufEnd = bufStart + buf.length;
  for (const [rangeStart, length] of ranges) {
    const rangeEnd = rangeStart + length;
    const start = Math.max(rangeStart, bufStart);
    const end = Math.min(rangeEnd, bufEnd);
    if (start >= end) continue; // no overlap with this chunk
    buf.fill(0, start - bufStart, end - bufStart);
  }
}

/**
 * Streaming SHA-256 over `filePath` with `ranges` zeroed.  Streams so a ~1 GiB
 * rootfs never lands fully in memory.  `chunkSize` is exposed for tests that
 * force a tiny highWaterMark to exercise range/chunk-boundary splitting.
 */
export function hashFileWithMaskedRanges(
  filePath: string,
  ranges: ReadonlyArray<readonly [number, number]>,
  chunkSize?: number,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(
      filePath,
      chunkSize === undefined ? undefined : { highWaterMark: chunkSize },
    );
    let offset = 0;
    stream.on('data', (chunk: Buffer) => {
      applyMaskToBuffer(chunk, offset, ranges);
      offset += chunk.length;
      hash.update(chunk);
    });
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Canonical (time-masked) SHA-256 of a rootfs ext4 image at `filePath`.  The
 * single definition of a rootfs ext4 digest across the build, the manifest, the
 * publish-job re-verification, and the consumer download check.
 */
export async function canonicalRootfsHash(
  filePath: string,
  chunkSize?: number,
): Promise<string> {
  const size = statSync(filePath).size;
  const ranges = ext4VolatileByteRanges(size);
  return hashFileWithMaskedRanges(filePath, ranges, chunkSize);
}

"use strict";

// src/rootfs/repro-hash.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var EXT4_BLOCK_SIZE = 4096;
var EXT4_BLOCKS_PER_GROUP = 8 * EXT4_BLOCK_SIZE;
var EXT4_VOLATILE_SUPERBLOCK_FIELDS = [
  [44, 4],
  // s_mtime
  [48, 4],
  // s_wtime      — re-stamped to wall-clock on close (the real culprit)
  [64, 4],
  // s_lastcheck
  [264, 4],
  // s_mkfs_time
  [1020, 4]
  // s_checksum   — metadata_csum over the superblock, follows s_wtime
];
var SUPERBLOCK_STRUCT_BYTES = 1024;
function hasSuperblock(group) {
  if (group === 0 || group === 1) return true;
  for (const base of [3, 5, 7]) {
    let power = base;
    while (power < group) power *= base;
    if (power === group) return true;
  }
  return false;
}
function superblockByteOffset(group) {
  return group === 0 ? SUPERBLOCK_STRUCT_BYTES : group * EXT4_BLOCKS_PER_GROUP * EXT4_BLOCK_SIZE;
}
function ext4VolatileByteRanges(imageSizeBytes) {
  const totalBlocks = Math.floor(imageSizeBytes / EXT4_BLOCK_SIZE);
  const numGroups = Math.ceil(totalBlocks / EXT4_BLOCKS_PER_GROUP);
  const ranges = [];
  for (let group = 0; group < numGroups; group += 1) {
    if (!hasSuperblock(group)) continue;
    const base = superblockByteOffset(group);
    if (base + SUPERBLOCK_STRUCT_BYTES > imageSizeBytes) continue;
    for (const [fieldOffset, length] of EXT4_VOLATILE_SUPERBLOCK_FIELDS) {
      ranges.push([base + fieldOffset, length]);
    }
  }
  return ranges;
}
function applyMaskToBuffer(buf, bufStart, ranges) {
  const bufEnd = bufStart + buf.length;
  for (const [rangeStart, length] of ranges) {
    const rangeEnd = rangeStart + length;
    const start = Math.max(rangeStart, bufStart);
    const end = Math.min(rangeEnd, bufEnd);
    if (start >= end) continue;
    buf.fill(0, start - bufStart, end - bufStart);
  }
}
function hashFileWithMaskedRanges(filePath, ranges, chunkSize) {
  return new Promise((resolve, reject) => {
    const hash = (0, import_node_crypto.createHash)("sha256");
    const stream = (0, import_node_fs.createReadStream)(
      filePath,
      chunkSize === void 0 ? void 0 : { highWaterMark: chunkSize }
    );
    let offset = 0;
    stream.on("data", (chunk) => {
      applyMaskToBuffer(chunk, offset, ranges);
      offset += chunk.length;
      hash.update(chunk);
    });
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}
async function canonicalRootfsHash(filePath, chunkSize) {
  const size = (0, import_node_fs.statSync)(filePath).size;
  const ranges = ext4VolatileByteRanges(size);
  return hashFileWithMaskedRanges(filePath, ranges, chunkSize);
}

// src/rootfs/repro-hash-cli.ts
async function main() {
  const filePath = process.argv[2];
  if (filePath === void 0 || filePath === "") {
    process.stderr.write("usage: repro-hash-cli <rootfs.ext4>\n");
    process.exitCode = 2;
    return;
  }
  const hash = await canonicalRootfsHash(filePath);
  process.stdout.write(`${hash}
`);
}
main().catch((err) => {
  process.stderr.write(
    `repro-hash-cli: ${err instanceof Error ? err.message : String(err)}
`
  );
  process.exitCode = 1;
});

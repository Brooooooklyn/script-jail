// script-jail — test/integration/rootfs-reproducibility.test.ts
// Integration test for R1 (CANONICAL-reproducible rootfs ext4).
//
// The expensive, non-deterministic part of a rootfs build is the docker
// image build + export.  The reproducibility contract lives entirely in the
// CONVERSION seam (`convertExportTreeToExt4`): normalize mtimes + native
// `mkfs.ext4` with a pinned UUID / hash-seed / SOURCE_DATE_EPOCH, then a
// debugfs timestamp post-pass.  So we build a throwaway image ONCE,
// `docker export` its filesystem to a temp tree ONCE, then run the conversion
// TWICE over the SAME tree and assert the two ext4s have the same CANONICAL
// hash.  This isolates mkfs+normalize determinism without paying the
// docker-build/export cost twice.
//
// Why canonical, not raw sha256: the shipped e2fsprogs (< 1.47.1) re-stamps the
// superblock `s_wtime` to the wall clock when debugfs flushes on close, so two
// builds seconds apart can differ in that one field (+ its metadata_csum).  We
// mask exactly those volatile superblock fields before hashing
// (`canonicalRootfsHash`) — any NON-time difference still changes the hash, so
// this stays a real reproducibility gate.  A second assertion cross-checks that
// the masked offsets we compute match the superblock locations dumpe2fs reports
// for the REAL image — a geometry change would otherwise silently under-mask.
//
// Gated to Linux + docker (the native mkfs.ext4 path) and self-skips
// elsewhere — it must NEVER fail on macOS / non-docker CI, only no-op.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  rmSync,
  readFileSync,
  existsSync,
  statSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';

import { convertExportTreeToExt4 } from '../../src/rootfs/build.js';
import {
  canonicalRootfsHash,
  hasSuperblock,
  superblockByteOffset,
  EXT4_BLOCK_SIZE,
  EXT4_BLOCKS_PER_GROUP,
} from '../../src/rootfs/repro-hash.js';

/** True when a working docker client is reachable (mirrors overlay.test.ts). */
function dockerAvailable(): boolean {
  const r = spawnSync('docker', ['version'], { stdio: 'ignore' });
  return r.status === 0;
}

const ENABLED = process.platform === 'linux' && dockerAvailable();

/** Raw sha256 of a file, hex — used only for an informational log line. */
function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Superblock byte offsets we WILL mask for an image of `size`, derived from the
 * pinned geometry.  The dumpe2fs cross-check compares this against the kernel's
 * own view of where superblock copies live.
 */
function computedSuperblockOffsets(size: number): number[] {
  const totalBlocks = Math.floor(size / EXT4_BLOCK_SIZE);
  const numGroups = Math.ceil(totalBlocks / EXT4_BLOCKS_PER_GROUP);
  const offsets: number[] = [];
  for (let g = 0; g < numGroups; g += 1) {
    if (!hasSuperblock(g)) continue;
    const base = superblockByteOffset(g);
    if (base + 1024 <= size) offsets.push(base);
  }
  return offsets.sort((a, b) => a - b);
}

/** Parse `dumpe2fs` for the block size + every superblock copy's byte offset. */
function dumpe2fsSuperblockOffsets(image: string): { blockSize: number; offsets: number[] } {
  const r = spawnSync('dumpe2fs', [image], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) {
    throw new Error(`dumpe2fs failed (exit ${r.status ?? 'unknown'}): ${r.stderr}`);
  }
  const out = r.stdout;
  const bs = /^Block size:\s+(\d+)/m.exec(out);
  if (bs === null) throw new Error('dumpe2fs: could not parse Block size');
  const blockSize = Number(bs[1]);
  const offsets = [...out.matchAll(/(?:Primary|Backup) superblock at (\d+)/g)]
    // Group 0's superblock struct lives at byte 1024 (after the boot block);
    // every backup starts at the first byte of its group.
    .map((m) => (Number(m[1]) === 0 ? 1024 : Number(m[1]) * blockSize))
    .sort((a, b) => a - b);
  return { blockSize, offsets };
}

describe.skipIf(!ENABLED)('rootfs ext4 canonical-reproducibility', () => {
  // A tiny base image keeps the build fast; the determinism contract is in the
  // conversion, not in which packages the tree contains.  alpine:latest gives a
  // realistic mix of files, dirs, and symlinks for the mtime-normalize path.
  const TAG = `script-jail-repro-test:${randomBytes(4).toString('hex')}`;
  let workDir = '';
  let exportDir = '';

  beforeAll(() => {
    workDir = join(tmpdir(), `script-jail-repro-${randomBytes(6).toString('hex')}`);
    exportDir = join(workDir, 'tree');
    mkdirSync(exportDir, { recursive: true });

    // Build a throwaway image and export its filesystem ONCE.
    const build = spawnSync(
      'docker',
      ['build', '-t', TAG, '-'],
      {
        input: 'FROM alpine:latest\nRUN mkdir -p /work && echo hi > /work/marker\n',
        stdio: ['pipe', 'inherit', 'inherit'],
      },
    );
    if (build.status !== 0) {
      throw new Error(`docker build failed (exit ${build.status ?? 'unknown'})`);
    }

    const create = spawnSync('docker', ['create', TAG], { encoding: 'utf8' });
    if (create.status !== 0) {
      throw new Error(`docker create failed (exit ${create.status ?? 'unknown'})`);
    }
    const containerId = create.stdout.trim();
    try {
      // docker export <id> | tar -x -C <exportDir>
      const exp = spawnSync('docker', ['export', containerId], {
        maxBuffer: 512 * 1024 * 1024,
      });
      if (exp.status !== 0 || exp.stdout.length === 0) {
        throw new Error(`docker export failed (exit ${exp.status ?? 'unknown'})`);
      }
      const untar = spawnSync('tar', ['-x', '-C', exportDir], { input: exp.stdout });
      if (untar.status !== 0) {
        throw new Error(`tar extract failed (exit ${untar.status ?? 'unknown'})`);
      }
    } finally {
      spawnSync('docker', ['rm', containerId], { stdio: 'ignore' });
    }
  }, 120_000);

  afterAll(() => {
    if (workDir) {
      try { rmSync(workDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    spawnSync('docker', ['rmi', '-f', TAG], { stdio: 'ignore' });
  });

  it('produces canonical-identical ext4 across two conversions of the same tree', async () => {
    const img1 = join(workDir, 'first.ext4');
    const img2 = join(workDir, 'second.ext4');

    convertExportTreeToExt4(exportDir, img1);
    convertExportTreeToExt4(exportDir, img2);

    expect(existsSync(img1)).toBe(true);
    expect(existsSync(img2)).toBe(true);

    // The masked offsets we'll zero MUST match where the kernel/dumpe2fs say
    // the superblock copies actually are; otherwise a drifting s_wtime in an
    // un-masked backup superblock would slip through.
    const { blockSize, offsets: dumped } = dumpe2fsSuperblockOffsets(img1);
    expect(blockSize).toBe(EXT4_BLOCK_SIZE);
    expect(dumped).toEqual(computedSuperblockOffsets(statSync(img1).size));

    // Informational: raw sha256 may or may not differ depending on whether the
    // two close-flushes landed in the same wall-clock second; the canonical
    // hash must be equal regardless.
    // eslint-disable-next-line no-console
    console.log(`[repro] raw sha: ${sha256(img1)} vs ${sha256(img2)}`);

    expect(await canonicalRootfsHash(img1)).toBe(await canonicalRootfsHash(img2));
  }, 120_000);
});

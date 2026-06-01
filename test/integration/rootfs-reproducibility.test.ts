// script-jail — test/integration/rootfs-reproducibility.test.ts
// Integration test for R1 (byte-reproducible rootfs ext4).
//
// The expensive, non-deterministic part of a rootfs build is the docker
// image build + export.  The byte-reproducibility contract lives entirely in
// the CONVERSION seam (`convertExportTreeToExt4`): normalize mtimes + native
// `mkfs.ext4` with a pinned UUID / hash-seed / SOURCE_DATE_EPOCH.  So we build
// a throwaway image ONCE, `docker export` its filesystem to a temp tree ONCE,
// then run the conversion TWICE over the SAME tree and assert byte-identical
// ext4 (equal sha256).  This isolates mkfs+normalize determinism without
// paying the docker-build/export cost twice.
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
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';

import { convertExportTreeToExt4 } from '../../src/rootfs/build.js';

/** True when a working docker client is reachable (mirrors overlay.test.ts). */
function dockerAvailable(): boolean {
  const r = spawnSync('docker', ['version'], { stdio: 'ignore' });
  return r.status === 0;
}

const ENABLED = process.platform === 'linux' && dockerAvailable();

/** sha256 of a file, hex. */
function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe.skipIf(!ENABLED)('rootfs ext4 byte-reproducibility', () => {
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

  it('produces byte-identical ext4 across two conversions of the same tree', () => {
    const img1 = join(workDir, 'first.ext4');
    const img2 = join(workDir, 'second.ext4');

    convertExportTreeToExt4(exportDir, img1);
    convertExportTreeToExt4(exportDir, img2);

    expect(existsSync(img1)).toBe(true);
    expect(existsSync(img2)).toBe(true);
    expect(sha256(img1)).toBe(sha256(img2));
  }, 120_000);
});

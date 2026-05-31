// script-jail — test/cli/local-artifacts.test.ts
//
// Unit tests for the CLI-local `preFetchArtifacts` replacement
// (`src/cli/local-artifacts.ts`). On Linux the CLI reuses the Action's
// firecracker/bare backends, which both call a `preFetchArtifacts(input)`
// closure to materialize the per-runner rootfs + libscriptjail.so into
// `ctx.imagesDir`. The Action version downloads those assets from the GitHub
// release; the CLI version instead pulls them out of the locally installed
// `@script-jail/<os>-<arch>` platform package (or the dev `images/` fallback).
//
// Invariants asserted here:
//   - the rootfs .ext4.gz shipped in the platform package is sparse-gunzipped
//     into the cache (via `ensureRootfs`) and then linked/copied into the
//     backend's `imagesDir` under the FC-rule name `rootfs-<runnerImage>[-arm64].ext4`;
//   - the libscriptjail[-arm64].so is copied into `imagesDir`;
//   - the closure NEVER touches the manifest or `http.download` (it is a
//     local-materialize path, not a GitHub-release download);
//   - it is idempotent: a second call does not re-run `ensureRootfs`, does not
//     re-copy, and does not throw `EEXIST`.

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { createLocalPreFetchArtifacts } from '../../src/cli/local-artifacts.js';
import { ensureRootfs } from '../../src/cli/rootfs-cache.js';
import type {
  ArtifactManifest,
  PreFetchInput,
} from '../../src/action/pre-fetch-artifacts.js';
import type { HttpClient } from '../../src/shared/http-download.js';

const scratchDirs: string[] = [];

afterEach(() => {
  while (scratchDirs.length > 0) {
    const dir = scratchDirs.pop();
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  }
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-local-artifacts-test-'));
  scratchDirs.push(dir);
  return dir;
}

/**
 * A non-trivial, partially-sparse rootfs body so the sparse-gunzip path in
 * `ensureRootfs` is meaningfully exercised and the materialized byte length is
 * verifiable.
 */
function sampleRootfsBytes(marker: string): Buffer {
  const bytes = Buffer.alloc(96 * 1024, 0);
  Buffer.from(marker).copy(bytes, 4096);
  Buffer.from('tail-marker').copy(bytes, bytes.length - 2048);
  return bytes;
}

/** Manifest is required by the PreFetchInput shape but must never be read. */
const UNUSED_MANIFEST: ArtifactManifest = {
  repo: 'Brooooooklyn/scriptjail',
  tag: 'v0.0.0-test',
  expected: { linux: {}, darwin: {} },
};

/** An `http` whose download spy must never fire on the local path. */
function spyHttp(): { http: HttpClient; download: ReturnType<typeof vi.fn> } {
  const download = vi.fn(async () => {
    throw new Error('http.download must not be called on the local path');
  });
  const http = { download } as unknown as HttpClient;
  return { http, download };
}

describe('createLocalPreFetchArtifacts', () => {
  it('materializes the arm64 rootfs + arm64 shim from the platform package', async () => {
    const root = tempDir();
    const packageImagesDir = join(root, 'pkg');
    const imagesDir = join(root, 'images-cache');
    const cacheDir = join(root, 'rootfs-cache');

    const rootfsBytes = sampleRootfsBytes('arm64-rootfs-body');
    const soBytes = Buffer.from('arm64-shim-bytes');
    mkdirSync(packageImagesDir, { recursive: true });
    writeFileSync(
      join(packageImagesDir, 'rootfs-ubuntu-24.04-arm64.ext4.gz'),
      gzipSync(rootfsBytes),
    );
    writeFileSync(join(packageImagesDir, 'libscriptjail-arm64.so'), soBytes);

    const { http, download } = spyHttp();
    const preFetch = createLocalPreFetchArtifacts({
      packageImagesDir,
      hostArch: 'arm64',
      ubuntuMajor: '24.04',
      cacheDir,
    });

    await preFetch(prefetchInput({ imagesDir, arch: 'arm64', http }));

    const destRootfs = join(imagesDir, 'rootfs-ubuntu-24.04-arm64.ext4');
    const destSo = join(imagesDir, 'libscriptjail-arm64.so');
    expect(existsSync(destRootfs)).toBe(true);
    expect(statSync(destRootfs).size).toBe(rootfsBytes.length);
    expect(readFileSync(destRootfs)).toEqual(rootfsBytes);
    expect(existsSync(destSo)).toBe(true);
    expect(readFileSync(destSo)).toEqual(soBytes);
    expect(download).not.toHaveBeenCalled();
  });

  it('materializes the x64 rootfs + un-suffixed x64 shim from the platform package', async () => {
    const root = tempDir();
    const packageImagesDir = join(root, 'pkg');
    const imagesDir = join(root, 'images-cache');
    const cacheDir = join(root, 'rootfs-cache');

    const rootfsBytes = sampleRootfsBytes('x64-rootfs-body');
    const soBytes = Buffer.from('x64-shim-bytes');
    mkdirSync(packageImagesDir, { recursive: true });
    writeFileSync(
      join(packageImagesDir, 'rootfs-ubuntu-24.04.ext4.gz'),
      gzipSync(rootfsBytes),
    );
    writeFileSync(join(packageImagesDir, 'libscriptjail.so'), soBytes);

    const { http, download } = spyHttp();
    const preFetch = createLocalPreFetchArtifacts({
      packageImagesDir,
      hostArch: 'x64',
      ubuntuMajor: '24.04',
      cacheDir,
    });

    await preFetch(prefetchInput({ imagesDir, arch: 'x64', http }));

    const destRootfs = join(imagesDir, 'rootfs-ubuntu-24.04.ext4');
    const destSo = join(imagesDir, 'libscriptjail.so');
    expect(existsSync(destRootfs)).toBe(true);
    expect(statSync(destRootfs).size).toBe(rootfsBytes.length);
    expect(readFileSync(destRootfs)).toEqual(rootfsBytes);
    expect(existsSync(destSo)).toBe(true);
    expect(readFileSync(destSo)).toEqual(soBytes);
    // no arch suffix on the x64 .so
    expect(existsSync(join(imagesDir, 'libscriptjail-arm64.so'))).toBe(false);
    expect(download).not.toHaveBeenCalled();
  });

  it('is idempotent: a second call does not re-run ensureRootfs, re-copy, or throw', async () => {
    const root = tempDir();
    const packageImagesDir = join(root, 'pkg');
    const imagesDir = join(root, 'images-cache');
    const cacheDir = join(root, 'rootfs-cache');

    const rootfsBytes = sampleRootfsBytes('idem-rootfs-body');
    const soBytes = Buffer.from('idem-shim-bytes');
    mkdirSync(packageImagesDir, { recursive: true });
    writeFileSync(
      join(packageImagesDir, 'rootfs-ubuntu-24.04.ext4.gz'),
      gzipSync(rootfsBytes),
    );
    writeFileSync(join(packageImagesDir, 'libscriptjail.so'), soBytes);

    const ensureRootfsSpy = vi.fn(ensureRootfs);
    const { http, download } = spyHttp();
    const preFetch = createLocalPreFetchArtifacts({
      packageImagesDir,
      hostArch: 'x64',
      ubuntuMajor: '24.04',
      cacheDir,
      ensureRootfs: ensureRootfsSpy,
    });

    const input = prefetchInput({ imagesDir, arch: 'x64', http });
    await preFetch(input);
    expect(ensureRootfsSpy).toHaveBeenCalledTimes(1);

    // Second call: must not throw EEXIST, must not re-run ensureRootfs, must
    // not re-copy (dest-exists-with-right-size short-circuits before linkSync).
    await expect(preFetch(input)).resolves.toBeUndefined();
    expect(ensureRootfsSpy).toHaveBeenCalledTimes(1);
    expect(download).not.toHaveBeenCalled();

    // Artifacts are intact after the no-op second call.
    const destRootfs = join(imagesDir, 'rootfs-ubuntu-24.04.ext4');
    expect(statSync(destRootfs).size).toBe(rootfsBytes.length);
    expect(readFileSync(join(imagesDir, 'libscriptjail.so'))).toEqual(soBytes);
  });
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function prefetchInput(args: {
  imagesDir: string;
  arch: 'x64' | 'arm64';
  http: HttpClient;
}): PreFetchInput {
  return {
    imagesDir: args.imagesDir,
    runnerImage: 'ubuntu-24.04',
    arch: args.arch,
    manifest: UNUSED_MANIFEST,
    http: args.http,
  };
}

// npm-jar — test/action/pre-fetch-artifacts.test.ts
//
// Unit tests for preFetchArtifacts().  All filesystem I/O is sandboxed to a
// per-test tmp dir; the HttpClient is a fake that writes a fixed payload
// (no network).

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import {
  preFetchArtifacts,
  type ArtifactManifest,
} from '../../src/action/pre-fetch-artifacts.js';
import type { HttpClient } from '../../src/action/firecracker/download.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'npm-jar-prefetch-test-'));
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function sha(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

interface MockHttp {
  client: HttpClient;
  calls: Array<{ url: string; dest: string; expected: string }>;
}

/**
 * Build a mock HttpClient backed by a `url → payload` map.  The mock
 * verifies the SHA-256 of the payload against the caller's `expectedSha256`
 * (matching production behaviour) and writes the payload to `destPath`
 * on success.
 */
function mockHttpClient(payloads: Readonly<Record<string, string>>): MockHttp {
  const calls: MockHttp['calls'] = [];

  const client: HttpClient = {
    async download(url, destPath, expectedSha256) {
      calls.push({ url, dest: destPath, expected: expectedSha256 });
      const payload = payloads[url];
      if (payload === undefined) {
        throw new Error(`Mock: no payload registered for ${url}`);
      }
      const actual = sha(payload);
      if (actual !== expectedSha256) {
        throw new Error(
          `Mock: SHA-256 mismatch for ${url}: expected ${expectedSha256}, got ${actual}`,
        );
      }
      writeFileSync(destPath, payload);
    },
  };

  return { client, calls };
}

const REPO = 'brooklyn/npm-jar';
const TAG = 'v0.1.0';

function urlFor(asset: string): string {
  return `https://github.com/${REPO}/releases/download/${TAG}/${asset}`;
}

// Realistic payloads + matching SHAs.
const ROOTFS_22_CONTENT = 'fake-rootfs-ubuntu-22.04-bytes';
const ROOTFS_24_CONTENT = 'fake-rootfs-ubuntu-24.04-bytes';
const LIB_CONTENT = 'fake-libnpmjar-so-bytes';

function manifest(): ArtifactManifest {
  return {
    repo: REPO,
    tag: TAG,
    expected: {
      'rootfs-ubuntu-22.04.ext4': sha(ROOTFS_22_CONTENT),
      'rootfs-ubuntu-24.04.ext4': sha(ROOTFS_24_CONTENT),
      'libnpmjar.so': sha(LIB_CONTENT),
    },
  };
}

function defaultPayloads(): Record<string, string> {
  return {
    [urlFor('rootfs-ubuntu-22.04.ext4')]: ROOTFS_22_CONTENT,
    [urlFor('rootfs-ubuntu-24.04.ext4')]: ROOTFS_24_CONTENT,
    [urlFor('libnpmjar.so')]: LIB_CONTENT,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('preFetchArtifacts', () => {
  it('downloads the rootfs for the requested runner image and libnpmjar.so', async () => {
    const { client, calls } = mockHttpClient(defaultPayloads());

    await preFetchArtifacts({
      imagesDir: testDir,
      runnerImage: 'ubuntu-24.04',
      manifest: manifest(),
      http: client,
    });

    const rootfsPath = join(testDir, 'rootfs-ubuntu-24.04.ext4');
    const libPath = join(testDir, 'libnpmjar.so');
    expect(existsSync(rootfsPath)).toBe(true);
    expect(existsSync(libPath)).toBe(true);
    expect(readFileSync(rootfsPath, 'utf8')).toBe(ROOTFS_24_CONTENT);
    expect(readFileSync(libPath, 'utf8')).toBe(LIB_CONTENT);

    // Exactly two downloads, and neither URL is for the "wrong" runner image.
    expect(calls).toHaveLength(2);
    const urls = calls.map((c) => c.url).sort();
    expect(urls).toEqual([
      urlFor('libnpmjar.so'),
      urlFor('rootfs-ubuntu-24.04.ext4'),
    ]);
  });

  it('skips the rootfs for the OTHER runner image', async () => {
    const { client, calls } = mockHttpClient(defaultPayloads());

    await preFetchArtifacts({
      imagesDir: testDir,
      runnerImage: 'ubuntu-22.04',
      manifest: manifest(),
      http: client,
    });

    // The 24.04 rootfs must not be downloaded or materialised on disk.
    const wrongRootfs = join(testDir, 'rootfs-ubuntu-24.04.ext4');
    expect(existsSync(wrongRootfs)).toBe(false);

    const urls = calls.map((c) => c.url);
    expect(urls).not.toContain(urlFor('rootfs-ubuntu-24.04.ext4'));
    expect(urls).toContain(urlFor('rootfs-ubuntu-22.04.ext4'));
  });

  it('cache hit: skips download when files already exist with correct hash', async () => {
    // Pre-create both files with matching content.
    writeFileSync(join(testDir, 'rootfs-ubuntu-22.04.ext4'), ROOTFS_22_CONTENT);
    writeFileSync(join(testDir, 'libnpmjar.so'), LIB_CONTENT);

    const { client, calls } = mockHttpClient(defaultPayloads());

    await preFetchArtifacts({
      imagesDir: testDir,
      runnerImage: 'ubuntu-22.04',
      manifest: manifest(),
      http: client,
    });

    // Neither asset should have been downloaded.
    expect(calls).toHaveLength(0);
  });

  it('re-downloads when a cached file has the wrong hash', async () => {
    // Pre-create the rootfs with WRONG content (different hash).
    writeFileSync(join(testDir, 'rootfs-ubuntu-22.04.ext4'), 'tampered-bytes');
    // libnpmjar.so is fine.
    writeFileSync(join(testDir, 'libnpmjar.so'), LIB_CONTENT);

    const { client, calls } = mockHttpClient(defaultPayloads());

    await preFetchArtifacts({
      imagesDir: testDir,
      runnerImage: 'ubuntu-22.04',
      manifest: manifest(),
      http: client,
    });

    // Only the rootfs was re-fetched; libnpmjar.so was a cache hit.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(urlFor('rootfs-ubuntu-22.04.ext4'));

    // And the cached file now contains the correct payload.
    expect(readFileSync(join(testDir, 'rootfs-ubuntu-22.04.ext4'), 'utf8'))
      .toBe(ROOTFS_22_CONTENT);
  });

  it('throws clearly on a hash mismatch from the server', async () => {
    // The server returns tampered content for the rootfs.  The mock HttpClient
    // mirrors production behaviour: it hashes the payload and throws when it
    // does not match the caller's expected SHA.
    const tamperedPayloads = {
      ...defaultPayloads(),
      [urlFor('rootfs-ubuntu-22.04.ext4')]: 'tampered-by-mitm',
    };
    const { client } = mockHttpClient(tamperedPayloads);

    await expect(
      preFetchArtifacts({
        imagesDir: testDir,
        runnerImage: 'ubuntu-22.04',
        manifest: manifest(),
        http: client,
      }),
    ).rejects.toThrow(/SHA-256 mismatch/);
  });

  it('throws when the manifest is missing an expected SHA for a needed asset', async () => {
    const incomplete: ArtifactManifest = {
      repo: REPO,
      tag: TAG,
      expected: {
        // libnpmjar.so missing on purpose.
        'rootfs-ubuntu-22.04.ext4': sha(ROOTFS_22_CONTENT),
        'rootfs-ubuntu-24.04.ext4': sha(ROOTFS_24_CONTENT),
      },
    };

    const { client } = mockHttpClient(defaultPayloads());

    await expect(
      preFetchArtifacts({
        imagesDir: testDir,
        runnerImage: 'ubuntu-22.04',
        manifest: incomplete,
        http: client,
      }),
    ).rejects.toThrow(/missing an expected SHA-256 for "libnpmjar\.so"/);
  });

  it('creates imagesDir if it does not exist', async () => {
    const nested = join(testDir, 'a', 'b', 'c');
    const { client } = mockHttpClient(defaultPayloads());

    await preFetchArtifacts({
      imagesDir: nested,
      runnerImage: 'ubuntu-24.04',
      manifest: manifest(),
      http: client,
    });

    expect(existsSync(nested)).toBe(true);
    expect(existsSync(join(nested, 'rootfs-ubuntu-24.04.ext4'))).toBe(true);
  });

  it('builds the download URL from manifest repo + tag', async () => {
    const altManifest: ArtifactManifest = {
      repo: 'someone/elsewhere',
      tag: 'v9.9.9',
      expected: {
        'rootfs-ubuntu-22.04.ext4': sha(ROOTFS_22_CONTENT),
        'rootfs-ubuntu-24.04.ext4': sha(ROOTFS_24_CONTENT),
        'libnpmjar.so': sha(LIB_CONTENT),
      },
    };
    const altPayloads: Record<string, string> = {
      'https://github.com/someone/elsewhere/releases/download/v9.9.9/rootfs-ubuntu-22.04.ext4':
        ROOTFS_22_CONTENT,
      'https://github.com/someone/elsewhere/releases/download/v9.9.9/libnpmjar.so':
        LIB_CONTENT,
    };

    const { client, calls } = mockHttpClient(altPayloads);

    await preFetchArtifacts({
      imagesDir: testDir,
      runnerImage: 'ubuntu-22.04',
      manifest: altManifest,
      http: client,
    });

    const urls = calls.map((c) => c.url).sort();
    expect(urls).toEqual([
      'https://github.com/someone/elsewhere/releases/download/v9.9.9/libnpmjar.so',
      'https://github.com/someone/elsewhere/releases/download/v9.9.9/rootfs-ubuntu-22.04.ext4',
    ]);
  });
});

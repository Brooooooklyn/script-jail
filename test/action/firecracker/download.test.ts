// npm-jar — test/action/firecracker/download.test.ts
//
// Unit tests for ensureBinaries().  All filesystem and network I/O is mocked;
// these tests never touch the real filesystem beyond a tmp dir.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import {
  ensureBinaries,
  KNOWN_VERSIONS,
  type HttpClient,
  type DownloadInput,
} from '../../../src/action/firecracker/download.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'npm-jar-dl-test-'));
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** Compute a fake SHA-256 from a string (deterministic, arbitrary). */
function fakeHash(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/** Build a fake tarball buffer with a single file entry for the firecracker binary. */
function fakeTarGz(version: string): Buffer {
  // We won't actually extract in these tests — the extraction is tested by
  // ensuring the HttpClient is (or is not) called.  We just need a non-empty
  // buffer to write so the hash check can work.
  return Buffer.from(`fake-firecracker-v${version}-tarball`);
}

/** Build a mock HttpClient that writes a fixed payload to destPath. */
function mockHttpClient(
  payload: Buffer | string,
  sha256Override?: string,
): { client: HttpClient; calls: Array<{ url: string; dest: string; sha: string }> } {
  const calls: Array<{ url: string; dest: string; sha: string }> = [];

  const client: HttpClient = {
    async download(url, destPath, expectedSha256) {
      calls.push({ url, dest: destPath, sha: expectedSha256 });
      // Write the payload so the caller's hash check (if any) works.
      writeFileSync(destPath, payload);
      // If a sha256Override is set we simulate a hash check inside the mock.
      if (sha256Override !== undefined && expectedSha256 !== sha256Override) {
        throw new Error(`Mock: SHA mismatch for ${url}`);
      }
    },
  };

  return { client, calls };
}

// ---------------------------------------------------------------------------
// Helper to build a DownloadInput with pinned hashes that match mock payloads.
// ---------------------------------------------------------------------------

const FAKE_VERSION = '1.8.0';
const FAKE_KERNEL_CONTENT = 'fake-vmlinux-kernel-binary';
const FAKE_KERNEL_SHA = fakeHash(FAKE_KERNEL_CONTENT);

function makeInput(
  overrides: Partial<DownloadInput> & { http: HttpClient },
): DownloadInput {
  return {
    imagesDir: testDir,
    firecrackerVersion: FAKE_VERSION,
    kernelUrl: 'https://example.com/vmlinux',
    kernelSha256: FAKE_KERNEL_SHA,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ensureBinaries', () => {
  it('throws for an unknown Firecracker version', async () => {
    const { client } = mockHttpClient(Buffer.from('x'));

    await expect(
      ensureBinaries(makeInput({ firecrackerVersion: '0.0.0', http: client })),
    ).rejects.toThrow(/unknown Firecracker version/);
  });

  it('includes the unknown version name in the error message', async () => {
    const { client } = mockHttpClient(Buffer.from('x'));

    await expect(
      ensureBinaries(makeInput({ firecrackerVersion: '99.0.0', http: client })),
    ).rejects.toThrow('"99.0.0"');
  });

  it('calls http.download for the firecracker tarball and vmlinux on first run', async () => {
    const tarPayload = fakeTarGz(FAKE_VERSION);
    // We need the tarball SHA to match what KNOWN_VERSIONS holds.
    // Since KNOWN_VERSIONS has placeholder hashes, override the download
    // function to always succeed (we're only checking it's called, not
    // the actual hash verification flow here).
    const calls: Array<{ url: string }> = [];
    const client: HttpClient = {
      async download(url, destPath) {
        calls.push({ url });
        // Write payload so the function doesn't throw on file-not-found later.
        if (url.includes('firecracker')) {
          writeFileSync(destPath, tarPayload);
        } else {
          writeFileSync(destPath, FAKE_KERNEL_CONTENT);
        }
      },
    };

    // Will throw during extraction because tarPayload is not a real tar.
    // We only care that the download was called for both URLs.
    try {
      await ensureBinaries(makeInput({ http: client }));
    } catch {
      // Expected — fake tarball cannot be extracted.
    }

    const urls = calls.map((c) => c.url);
    expect(urls.some((u) => u.includes('firecracker'))).toBe(true);
    expect(urls.some((u) => u.includes('vmlinux') || u === 'https://example.com/vmlinux')).toBe(true);
  });

  it('skips re-download for vmlinux when hash matches (idempotent)', async () => {
    // Pre-create a vmlinux with the correct hash.
    const vmlinuxPath = join(testDir, 'vmlinux');
    writeFileSync(vmlinuxPath, FAKE_KERNEL_CONTENT);

    const { client, calls } = mockHttpClient(Buffer.from('x'));

    // Also pre-create a fake tarball so the tarball-present check finds it.
    const tarContent = fakeTarGz(FAKE_VERSION);
    const tarPath = join(testDir, `firecracker-v${FAKE_VERSION}-x86_64.tgz`);
    writeFileSync(tarPath, tarContent);
    void tarPath; // referenced for its side-effect (file creation)

    // Override KNOWN_VERSIONS via module internals is not possible directly,
    // so we use a version where KNOWN_VERSIONS sha happens to equal our tarSha.
    // Instead we test only the vmlinux idempotency by checking download not called
    // for the vmlinux URL when the file exists with correct hash.

    try {
      await ensureBinaries({
        imagesDir: testDir,
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      });
    } catch {
      // May fail on tar extraction — that's ok for this test.
    }

    // Crucially: the vmlinux download should NOT have been called.
    const vmlinuxCalls = calls.filter((c) => c.url.includes('vmlinux'));
    expect(vmlinuxCalls).toHaveLength(0);
  });

  it('re-downloads vmlinux when hash does not match', async () => {
    // Pre-create a vmlinux with WRONG content (different hash).
    const vmlinuxPath = join(testDir, 'vmlinux');
    writeFileSync(vmlinuxPath, 'wrong-content-different-hash');

    const { client, calls } = mockHttpClient(FAKE_KERNEL_CONTENT);

    try {
      await ensureBinaries({
        imagesDir: testDir,
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      });
    } catch {
      // May fail on tar extraction.
    }

    // vmlinux should be re-downloaded because the cached file hash was wrong.
    const vmlinuxCalls = calls.filter((c) => c.url.includes('vmlinux'));
    expect(vmlinuxCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('creates imagesDir if it does not exist', async () => {
    const nestedDir = join(testDir, 'a', 'b', 'c');
    const { client } = mockHttpClient(Buffer.from('x'));

    try {
      await ensureBinaries({
        imagesDir: nestedDir,
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      });
    } catch {
      // Expected to fail on tar extraction.
    }

    // Directory should have been created.
    const { existsSync } = await import('node:fs');
    expect(existsSync(nestedDir)).toBe(true);
  });

  it('KNOWN_VERSIONS includes 1.8.0 and 1.9.0', () => {
    expect(Object.keys(KNOWN_VERSIONS)).toContain('1.8.0');
    expect(Object.keys(KNOWN_VERSIONS)).toContain('1.9.0');
  });

  it('firecracker tarball URL includes the version string', async () => {
    const calls: Array<{ url: string }> = [];
    const client: HttpClient = {
      async download(url, destPath) {
        calls.push({ url });
        writeFileSync(destPath, 'x');
      },
    };

    try {
      await ensureBinaries({
        imagesDir: testDir,
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      });
    } catch { /* ignore */ }

    const tarCalls = calls.filter((c) => c.url.includes('firecracker'));
    expect(tarCalls.length).toBeGreaterThanOrEqual(1);
    expect(tarCalls[0]!.url).toContain(FAKE_VERSION);
    expect(tarCalls[0]!.url).toContain('github.com');
  });
});

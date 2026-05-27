// script-jail — test/action/firecracker/download.test.ts
//
// Unit tests for ensureBinaries().  All filesystem and network I/O is mocked;
// these tests never touch the real filesystem beyond a tmp dir.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { createGzip } from 'node:zlib';

import {
  ensureBinaries,
  KNOWN_TARBALL_SHA256,
  KNOWN_VERSIONS,
  type HttpClient,
  type DownloadInput,
} from '../../../src/action/firecracker/download.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'script-jail-dl-test-'));
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

/**
 * Build a minimal real .tgz buffer containing one file entry named `entryName`
 * with the given `content`.  This is used to test the tar parser path inside
 * `extractFirecrackerBinary`.
 */
function buildTarGz(entryName: string, content: Buffer): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    // Construct a POSIX ustar tar block manually.
    const BLOCK = 512;
    const nameBytes = Buffer.alloc(100);
    Buffer.from(entryName).copy(nameBytes);

    const header = Buffer.alloc(BLOCK);
    nameBytes.copy(header, 0);

    // File mode: 0755
    Buffer.from('0000755\0').copy(header, 100);
    // UID / GID
    Buffer.from('0000000\0').copy(header, 108);
    Buffer.from('0000000\0').copy(header, 116);
    // Size (octal, 11 digits + space)
    const sizeOctal = content.length.toString(8).padStart(11, '0') + ' ';
    Buffer.from(sizeOctal).copy(header, 124);
    // mtime
    Buffer.from('00000000000 ').copy(header, 136);
    // typeflag: '0' = regular file
    header[156] = 0x30;
    // ustar magic
    Buffer.from('ustar  \0').copy(header, 257);

    // Compute checksum (unsigned sum of all header bytes with checksum field as spaces).
    Buffer.from('        ').copy(header, 148); // 8 spaces for checksum field
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += header[i]!;
    const checksumStr = sum.toString(8).padStart(6, '0') + '\0 ';
    Buffer.from(checksumStr).copy(header, 148);

    // Pad content to a multiple of 512 bytes.
    const paddedSize = Math.ceil(content.length / BLOCK) * BLOCK;
    const dataPadded = Buffer.alloc(paddedSize);
    content.copy(dataPadded);

    // End-of-archive: two 512-byte zero blocks.
    const eof = Buffer.alloc(BLOCK * 2);

    const tarBuf = Buffer.concat([header, dataPadded, eof]);

    // Gzip compress.
    const gz = createGzip();
    const chunks: Buffer[] = [];
    gz.on('data', (c: Buffer) => chunks.push(c));
    gz.on('end', () => resolve(Buffer.concat(chunks)));
    gz.on('error', reject);
    gz.end(tarBuf);
  });
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
    // The mock HttpClient bypasses real hash verification — it writes the
    // payload to destPath without checking it against the expected SHA.
    // We're only asserting that download() is called for both URLs here;
    // the hash-verification path is exercised by other tests in this file.
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

    // The pinned tarball SHA in KNOWN_VERSIONS won't match our fake tarball,
    // so the firecracker re-download path will fire; that's fine — we only
    // assert the vmlinux side here.  The mock client doesn't enforce SHAs,
    // so the firecracker download succeeds and extraction is what fails
    // (caught by the try/catch).

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
    expect(Object.keys(KNOWN_TARBALL_SHA256.arm64)).toContain('1.8.0');
    expect(Object.keys(KNOWN_TARBALL_SHA256.arm64)).toContain('1.9.0');
  });

  it('uses the aarch64 Firecracker tarball and entry when arch=arm64', async () => {
    const binaryContent = randomBytes(32);
    const tarGzBuffer = await buildTarGz(
      `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`,
      binaryContent,
    );
    const calls: Array<{ url: string; dest: string }> = [];
    const client: HttpClient = {
      async download(url, destPath) {
        calls.push({ url, dest: destPath });
        if (url.includes('firecracker')) {
          writeFileSync(destPath, tarGzBuffer);
        } else {
          writeFileSync(destPath, FAKE_KERNEL_CONTENT);
        }
      },
    };

    const result = await ensureBinaries({
      imagesDir: testDir,
      arch: 'arm64',
      firecrackerVersion: FAKE_VERSION,
      kernelUrl: 'https://example.com/vmlinux',
      kernelSha256: FAKE_KERNEL_SHA,
      http: client,
    });

    const tarCall = calls.find((c) => c.url.includes('firecracker'));
    expect(tarCall?.url).toContain(`firecracker-v${FAKE_VERSION}-aarch64.tgz`);
    expect(tarCall?.dest).toContain(`firecracker-v${FAKE_VERSION}-aarch64.tgz`);
    const { readFileSync } = await import('node:fs');
    expect(readFileSync(result.firecrackerPath)).toEqual(binaryContent);
  });

  it('rejects with a descriptive error when the tar entry is missing from the tarball', async () => {
    // Build a real .tgz containing an entry named "wrong-entry", not the
    // expected "firecracker-v1.8.0-x86_64".
    const tarGzBuffer = await buildTarGz('wrong-entry-name', randomBytes(64));
    const tarHash = fakeHash(tarGzBuffer.toString('latin1'));

    // Inject a client that writes the real tarball payload.
    const client: HttpClient = {
      async download(url, destPath) {
        if (url.includes('firecracker')) {
          writeFileSync(destPath, tarGzBuffer);
        } else {
          writeFileSync(destPath, FAKE_KERNEL_CONTENT);
        }
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/entry "firecracker-v1\.8\.0-x86_64" not found in tarball/);

    void tarHash; // used implicitly via tarGzBuffer content
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

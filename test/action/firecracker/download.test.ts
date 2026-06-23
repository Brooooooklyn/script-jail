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

/**
 * Build a .tgz whose single entry's header declares `declaredSize` bytes but
 * the archive only delivers `actualContent` (block-aligned) with NO
 * end-of-archive blocks — i.e. a truncated/corrupt tarball where the stream
 * ends mid-entry.  Used to prove the extractor rejects partial extractions.
 */
function buildTruncatedTarGz(
  entryName: string,
  actualContent: Buffer,
  declaredSize: number,
): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const BLOCK = 512;
    const header = Buffer.alloc(BLOCK);
    Buffer.from(entryName).copy(header, 0);
    Buffer.from('0000755\0').copy(header, 100);
    Buffer.from('0000000\0').copy(header, 108);
    Buffer.from('0000000\0').copy(header, 116);
    // Declared size (octal) — intentionally larger than the bytes we deliver.
    Buffer.from(declaredSize.toString(8).padStart(11, '0') + ' ').copy(header, 124);
    Buffer.from('00000000000 ').copy(header, 136);
    header[156] = 0x30; // regular file
    Buffer.from('ustar  \0').copy(header, 257);
    Buffer.from('        ').copy(header, 148);
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += header[i]!;
    Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);

    // Only the actual (block-aligned) content, fewer bytes than declared, and
    // deliberately NO end-of-archive zero blocks.
    const dataPadded = Buffer.alloc(Math.ceil(actualContent.length / BLOCK) * BLOCK);
    actualContent.copy(dataPadded);

    const gz = createGzip();
    const chunks: Buffer[] = [];
    gz.on('data', (c: Buffer) => chunks.push(c));
    gz.on('end', () => resolve(Buffer.concat(chunks)));
    gz.on('error', reject);
    gz.end(Buffer.concat([header, dataPadded]));
  });
}

/**
 * Build a single 512-byte ustar header.  `rawSizeField` (12 bytes, copied into
 * the size field at offset 124) overrides the octal `declaredSize` encoding —
 * used to inject a malformed (non-octal) size field.  `checksumOverride`
 * replaces the computed checksum field (to inject a forged/garbage checksum).
 * `typeflag` overrides the default regular-file flag (computed INTO the valid
 * checksum, so the header is checksum-valid but a non-regular type).  `prefix`
 * fills the ustar prefix field (bytes 345..500), also computed into the checksum.
 * `magic` selects the magic/version bytes (257..265): 'gnu' (default) =
 * "ustar  \0", 'posix' = "ustar\0" + "00", 'posix-altver' = "ustar\0" + "  "
 * (POSIX magic field with non-"00" version bytes), 'v7' = none (zeroed) — the
 * prefix field is honored whenever the 6-byte magic field is "ustar\0".
 */
function tarHeader(
  entryName: string,
  declaredSize: number,
  rawSizeField?: string,
  checksumOverride?: string,
  typeflag?: number,
  prefix?: string,
  magic: 'gnu' | 'posix' | 'posix-altver' | 'v7' = 'gnu',
): Buffer {
  const BLOCK = 512;
  const header = Buffer.alloc(BLOCK);
  Buffer.from(entryName).copy(header, 0);
  Buffer.from('0000755\0').copy(header, 100);
  Buffer.from('0000000\0').copy(header, 108);
  Buffer.from('0000000\0').copy(header, 116);
  Buffer.from(
    rawSizeField !== undefined ? rawSizeField : declaredSize.toString(8).padStart(11, '0') + ' ',
  ).copy(header, 124);
  Buffer.from('00000000000 ').copy(header, 136);
  header[156] = typeflag ?? 0x30; // default: '0' = regular file
  if (magic === 'gnu') Buffer.from('ustar  \0').copy(header, 257);
  else if (magic === 'posix') Buffer.from('ustar\x0000').copy(header, 257); // "ustar\0" + "00"
  else if (magic === 'posix-altver') Buffer.from('ustar\x00  ').copy(header, 257); // "ustar\0" + "  "
  // 'v7' leaves bytes 257..265 zeroed (no magic).
  if (prefix !== undefined) Buffer.from(prefix).copy(header, 345);
  Buffer.from('        ').copy(header, 148);
  if (checksumOverride !== undefined) {
    Buffer.from(checksumOverride).copy(header, 148); // deliberately wrong checksum
  } else {
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += header[i]!;
    Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);
  }
  return header;
}

/**
 * Build a header whose uid field (108..116) is GNU base-256 encoded (leading
 * byte 0x80), exactly as the official Firecracker tarball does for its large
 * build uid.  The checksum is recomputed over the patched header so it stays
 * valid.  Used to prove the extractor does NOT octal-validate uid/gid/mtime.
 */
function tarHeaderBase256Uid(entryName: string, declaredSize: number): Buffer {
  const header = tarHeader(entryName, declaredSize);
  // The exact base-256 uid bytes observed in firecracker-v1.8.0-x86_64.tgz.
  Buffer.from([0x80, 0x00, 0x00, 0x00, 0x01, 0x6c, 0x6b, 0xf2]).copy(header, 108);
  // Recompute the checksum over the patched header.
  Buffer.from('        ').copy(header, 148);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i]!;
  Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);
  return header;
}

/** Pad a buffer up to the next 512-byte tar block boundary. */
function padBlock(content: Buffer): Buffer {
  const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
  content.copy(padded);
  return padded;
}

/** Gzip an assembled raw tar buffer. */
function gzipBuffer(tarBuf: Buffer): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
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

  it('rejects a truncated target entry (declares more bytes than the tarball delivers)', async () => {
    // Header declares 1024 bytes; the archive delivers only one 512-byte block
    // and no end-of-archive marker — the gunzip stream ends mid-entry.
    const tarGzBuffer = await buildTruncatedTarGz(
      `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`,
      randomBytes(512),
      1024,
    );
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(
          destPath,
          url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT,
        );
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/truncated/u);
  });

  it('rejects cleanly (no unhandled crash) when the extraction scratch file cannot be opened', async () => {
    const tarGzBuffer = await buildTarGz(
      `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`,
      randomBytes(64),
    );
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(
          destPath,
          url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT,
        );
      },
    };

    // Point the OS temp dir (where the extractor opens its scratch file) at a
    // path whose parent does not exist, so createWriteStream(tmpOut) fails to
    // open.  The fix routes that stream 'error' to a clean reject instead of an
    // unhandled 'error' event that would crash the process.
    const savedTmp = process.env['TMPDIR'];
    process.env['TMPDIR'] = join(testDir, 'no-such-tmp-subdir');
    try {
      await expect(
        ensureBinaries({
          imagesDir: testDir,
          arch: 'arm64',
          firecrackerVersion: FAKE_VERSION,
          kernelUrl: 'https://example.com/vmlinux',
          kernelSha256: FAKE_KERNEL_SHA,
          http: client,
        }),
      ).rejects.toThrow();
    } finally {
      if (savedTmp === undefined) delete process.env['TMPDIR'];
      else process.env['TMPDIR'] = savedTmp;
    }
  });

  it('rejects when the gzip integrity trailer is corrupt even though the entry decompressed', async () => {
    const valid = await buildTarGz(
      `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`,
      randomBytes(256),
    );
    // Flip a byte inside the gzip CRC32/length trailer (last 8 bytes).  The
    // target entry still decompresses and its WriteStream closes, but gunzip
    // raises an integrity error at end-of-stream — extraction must reject rather
    // than accept the (unvalidated) bytes.
    const corrupt = Buffer.from(valid);
    corrupt[corrupt.length - 5] = corrupt[corrupt.length - 5]! ^ 0xff;
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(
          destPath,
          url.includes('firecracker') ? corrupt : FAKE_KERNEL_CONTENT,
        );
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow();
  });

  it('rejects a tarball containing duplicate matching entries', async () => {
    // Two entries with the same target basename — a well-formed Firecracker
    // tarball has exactly one, so a second is malformed (and would otherwise let
    // the first entry's stale close state race the second flush).
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const c1 = randomBytes(128);
    const c2 = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, c1.length), padBlock(c1),
      tarHeader(entryName, c2.length), padBlock(c2),
      Buffer.alloc(1024), // end-of-archive
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/duplicate/u);
  });

  it('rejects (does not hang) on a malformed tar size field after the target entry', async () => {
    // A valid target entry followed by a trailing header whose size field is
    // prefix-valid-then-garbage ("0000000010Z").  parseInt is prefix-tolerant
    // (parses to 8), so the strict /^[0-7]+$/ shape check is what rejects it;
    // a non-octal field would otherwise misread the size (or, fully garbage,
    // yield NaN and stall the parser loop forever).
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length), padBlock(content),
      // Trailing header with a prefix-valid-then-non-octal 12-byte size field.
      tarHeader('junk-entry', 0, '0000000010Z '), padBlock(randomBytes(64)),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/invalid tar header size/u);
  });

  it('rejects when a trailing non-target entry is truncated (archive ends mid-entry)', async () => {
    // A complete target entry followed by a non-target entry whose header
    // declares more padded data than the archive delivers, with no EOF blocks.
    // The truncation guard must fire for ANY entry left mid-data, not only the
    // captured target.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length), padBlock(content),
      // Declares 1024 bytes but delivers only one 512-byte block, and no EOF.
      tarHeader('trailing-entry', 1024), padBlock(randomBytes(512)),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/truncated/u);
  });

  it('rejects a partial trailing header fragment after the target entry (stray sub-block bytes)', async () => {
    // A complete target entry followed by a single stray byte (< 512) and no
    // EOF blocks.  The leftover fragment must be rejected, not silently ignored
    // as a successful extraction.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length), padBlock(content),
      Buffer.from([0x58]), // single stray byte, no EOF blocks
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/truncated/u);
  });

  it('rejects a target entry placed after the end-of-archive marker', async () => {
    // The target entry sits AFTER the tar EOF zero-blocks.  A compliant reader
    // stops at EOF and never extracts it; the extractor must reject rather than
    // pull a binary hidden past the end-of-archive marker.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      Buffer.alloc(1024), // end-of-archive marker (two zero blocks) FIRST
      tarHeader(entryName, content.length), padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/end-of-archive/u);
  });

  it('rejects a tar header with an invalid checksum', async () => {
    // A header whose name/size match the target but whose checksum field is
    // wrong — a compliant tar reader rejects it; the extractor must too,
    // rather than trust the forged name/size.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length, undefined, '000000\0 '), // bogus checksum
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/checksum/u);
  });

  it('rejects a tar header whose checksum field is prefix-valid-then-garbage', async () => {
    // The checksum field holds the REAL 6-octal-digit checksum followed by a
    // non-octal byte ("X") and no NUL terminator.  parseInt is prefix-tolerant
    // (parses the leading "NNNNNN" === the real checksum), so the value compare
    // alone would accept it; the strict /^[0-7]+$/ shape check is what rejects
    // it — matching a compliant reader (bsdtar) that treats the field as invalid.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    // Compute the real checksum digits from a valid header, then corrupt only
    // the field's terminator region with a trailing non-octal char.
    const validHdr = tarHeader(entryName, content.length);
    const realCksum6 = validHdr.subarray(148, 154).toString('utf8'); // "NNNNNN"
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length, undefined, realCksum6 + 'X '),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/checksum/u);
  });

  it('rejects a zero-size duplicate of the target entry (no silent divergence)', async () => {
    // First target entry carries real content; a SECOND target entry declares
    // size 0.  The duplicate guard must fire regardless of the duplicate's size
    // — otherwise this extractor returns the first entry while a compliant
    // reader would overwrite it with the (empty) later one.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const c1 = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, c1.length), padBlock(c1),
      tarHeader(entryName, 0), // zero-size duplicate (no data blocks)
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/duplicate/u);
  });

  it('rejects a target entry that is not a regular file (non-zero typeflag)', async () => {
    // A zero-size header carrying the exact target path but a directory typeflag
    // ('5'), with a VALID checksum.  A compliant reader treats it as a directory,
    // not the firecracker binary; the extractor must reject rather than accept a
    // directory record as the executable.  (Size 0 so it passes the framing gate
    // and reaches the per-target regular-file check.)
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const tarBuf = Buffer.concat([
      tarHeader(entryName, 0, undefined, undefined, 0x35), // '5' = directory, size 0
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/regular file/u);
  });

  it('does not select a same-basename entry at an unexpected path', async () => {
    // The entry's BASENAME matches the target binary but it sits at a different
    // directory than the documented `release-v<ver>-<arch>/` path.  Full-path
    // matching must NOT pick it up — a compliant reader extracts the named
    // release-dir entry, not any same-basename file at an attacker-chosen path.
    const tarGzBuffer = await buildTarGz(
      `some-other-dir/firecracker-v${FAKE_VERSION}-aarch64`,
      randomBytes(64),
    );
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/not found in tarball/u);
  });

  it('does not match the target when a non-empty POSIX ustar prefix changes the full path', async () => {
    // POSIX ustar header (magic "ustar\0"+"00"): the 100-byte name field holds
    // the raw target path, but the prefix field (bytes 345..500) is non-empty.
    // A compliant reader reports the entry under `<prefix>/<name>`, so full-path
    // reconstruction must NOT match the documented target — otherwise we'd
    // extract a binary a ustar reader lists at a different (prefix-hidden) path.
    const rawName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(rawName, content.length, undefined, undefined, undefined, 'hidden-prefix', 'posix'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/not found in tarball/u);
  });

  it('reassembles a POSIX ustar prefix-split path and extracts the target', async () => {
    // A legitimate POSIX ustar split: prefix = `release-v<ver>-<arch>`, name =
    // `firecracker-v<ver>-<arch>`.  A compliant reader joins them to the
    // documented target path; the extractor must do the same and extract it.
    const prefix = `release-v${FAKE_VERSION}-aarch64`;
    const namePart = `firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(64);
    const tarBuf = Buffer.concat([
      tarHeader(namePart, content.length, undefined, undefined, undefined, prefix, 'posix'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
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
    const { readFileSync } = await import('node:fs');
    expect(readFileSync(result.firecrackerPath)).toEqual(content);
  });

  it('rejects a PAX/GNU extension record rather than matching the next entry raw', async () => {
    // A PAX extended-header record (typeflag 'x', 0x78) precedes a plain target
    // header.  PAX records override the following entry's path/size; a strict
    // reader must honor them, so accepting the next header by its raw name/size
    // would diverge.  We reject the extension record outright.
    const target = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const paxData = Buffer.from('30 path=hidden/firecracker\n'); // a PAX record body
    const tarBuf = Buffer.concat([
      tarHeader('PaxHeaders/0/firecracker', paxData.length, undefined, undefined, 0x78), // 'x'
      padBlock(paxData),
      tarHeader(target, content.length), padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/unsupported tar typeflag/u);
  });

  it('rejects a size field with valid octal then NUL then garbage', async () => {
    // The size field holds valid octal digits, a NUL terminator, then a stray
    // non-padding byte ("0000000027\0X").  Stripping at the NUL would accept the
    // octal prefix, but a strict reader (bsdtar) rejects the whole field — the
    // padding region after the terminator must be NUL/space only.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length), padBlock(content),
      tarHeader('junk-entry', 0, '0000000027\0X'), padBlock(randomBytes(64)),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/invalid tar header size/u);
  });

  it('rejects a checksum field with valid octal then NUL then garbage', async () => {
    // Same NUL-then-garbage class on the checksum field: the REAL checksum
    // digits, a NUL, then a stray "X".  Must be rejected as an invalid checksum,
    // not silently accepted by parsing only the pre-NUL prefix.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const validHdr = tarHeader(entryName, content.length);
    const realCksum6 = validHdr.subarray(148, 154).toString('utf8'); // "NNNNNN"
    const tarBuf = Buffer.concat([
      tarHeader(entryName, content.length, undefined, realCksum6 + '\0X'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/checksum/u);
  });

  it('rejects a Solaris X extended header rather than matching the next entry raw', async () => {
    // Solaris uses typeflag 'X' (0x58) for extended path/size records — the
    // uppercase sibling of POSIX 'x'.  It must be rejected globally, exactly
    // like 'x', so it cannot retarget the following plain header.
    const target = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const xData = Buffer.from('27 path=hidden/firecracker\n');
    const tarBuf = Buffer.concat([
      tarHeader('SolarisHdr', xData.length, undefined, undefined, 0x58), // 'X'
      padBlock(xData),
      tarHeader(target, content.length), padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/unsupported tar typeflag/u);
  });

  it('rejects a GNU sparse (S) or multi-volume (M) typeflag before it can mis-frame', async () => {
    // GNU sparse 'S' archives fewer data blocks than the declared size, and
    // multi-volume 'M' continues an entry from another volume — a reader that
    // advances by ceil(size/512) would mis-frame the following header.  Both
    // must be rejected up front (regardless of being non-target).  We assert on
    // the sparse case; a leading 'S' header precedes the real target.
    const target = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader('sparse-file', 4096, undefined, undefined, 0x53), // 'S', declares 4096
      padBlock(randomBytes(512)), // but only delivers one block (sparse)
      tarHeader(target, content.length), padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/unsupported tar typeflag/u);
  });

  it('does not honor a prefix on a v7 (no-magic) header', async () => {
    // v7 / pre-ustar header: NO magic at bytes 257..265.  Bytes 345..500 are
    // not a prefix field for v7, so a compliant reader uses the name field only.
    // A spoof that puts `firecracker-v<ver>-<arch>` in the name and
    // `release-v<ver>-<arch>` in the prefix region must NOT join to the target.
    const namePart = `firecracker-v${FAKE_VERSION}-aarch64`;
    const prefixRegion = `release-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(namePart, content.length, undefined, undefined, undefined, prefixRegion, 'v7'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/not found in tarball/u);
  });

  it('treats bytes 345..500 of a GNU header as metadata, not a path prefix', async () => {
    // GNU format (magic "ustar  \0") repurposes bytes 345..500 for atime/ctime/
    // sparse metadata — NOT a path prefix.  The full target path already fits in
    // the 100-byte name field, so a GNU header with non-empty 345..500 must
    // still extract by name (no corruption / no false "not found").  Guards the
    // real-tarball path against the POSIX-only prefix join.
    const target = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(96);
    const tarBuf = Buffer.concat([
      // GNU magic (default) + non-empty 345..500 region.
      tarHeader(target, content.length, undefined, undefined, undefined, 'gnu-metadata-noise', 'gnu'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
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
    const { readFileSync } = await import('node:fs');
    expect(readFileSync(result.firecrackerPath)).toEqual(content);
  });

  it('rejects a non-regular non-target entry that declares data (EOF-swallow attack)', async () => {
    // The exact round-11 framing attack: a non-target directory ('5') header
    // declares size 512, followed by ONE zero block, then a forged regular
    // target + payload.  A compliant reader (bsdtar) ignores the directory's
    // size, treats the zero block as EOF, and stops — never seeing the forged
    // target.  Advancing ceil(512/512)=1 block would consume the EOF zero block
    // as the directory's "data" and then extract the hidden target, so the
    // framing gate must fail closed on the non-regular non-zero-size entry.
    const target = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const forged = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader('decoy-dir', 512, undefined, undefined, 0x35), // '5', declares 512 bytes
      Buffer.alloc(512), // a single zero block (the would-be EOF a reader stops at)
      tarHeader(target, forged.length), padBlock(forged), // forged target hidden past EOF
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/non-regular tar entry/u);
  });

  it('honors the prefix on a ustar header with a non-00 version (matches bsdtar)', async () => {
    // bsdtar keys ustar (prefix-honoring) detection on the 6-byte MAGIC field
    // "ustar\0" alone, regardless of the version bytes.  A header with magic
    // "ustar\0", version "  " (two spaces, not "00"), the raw target path in the
    // name field, and a non-empty prefix is listed by bsdtar under
    // "<prefix>/<name>".  So the extractor must ALSO honor the prefix here and
    // therefore NOT match the documented (prefix-less) target.
    const rawName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(128);
    const tarBuf = Buffer.concat([
      tarHeader(rawName, content.length, undefined, undefined, undefined, 'hidden-prefix', 'posix-altver'),
      padBlock(content),
      Buffer.alloc(1024),
    ]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
      },
    };

    await expect(
      ensureBinaries({
        imagesDir: testDir,
        arch: 'arm64',
        firecrackerVersion: FAKE_VERSION,
        kernelUrl: 'https://example.com/vmlinux',
        kernelSha256: FAKE_KERNEL_SHA,
        http: client,
      }),
    ).rejects.toThrow(/not found in tarball/u);
  });

  it('accepts a header whose uid field is GNU base-256 encoded (real tarball shape)', async () => {
    // The official Firecracker tarball encodes a large uid in GNU base-256 form
    // (leading byte 0x80).  The extractor must NOT validate uid/gid/mtime as
    // octal — doing so would falsely reject the genuine archive.  Here the
    // target header carries a base-256 uid and must still extract.
    const entryName = `release-v${FAKE_VERSION}-aarch64/firecracker-v${FAKE_VERSION}-aarch64`;
    const content = randomBytes(96);
    const header = tarHeaderBase256Uid(entryName, content.length);
    const tarBuf = Buffer.concat([header, padBlock(content), Buffer.alloc(1024)]);
    const tarGzBuffer = await gzipBuffer(tarBuf);
    const client: HttpClient = {
      async download(url, destPath) {
        writeFileSync(destPath, url.includes('firecracker') ? tarGzBuffer : FAKE_KERNEL_CONTENT);
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
    const { readFileSync } = await import('node:fs');
    expect(readFileSync(result.firecrackerPath)).toEqual(content);
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
    ).rejects.toThrow(
      /entry "release-v1\.8\.0-x86_64\/firecracker-v1\.8\.0-x86_64" not found in tarball/,
    );

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

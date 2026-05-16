// npm-jar — test/action/detect-pm.test.ts
//
// Tests for detectPm() — lockfile-based package-manager detection.
//
// All tests use the `fs` injection seam (no real filesystem touched).

import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import {
  detectPm,
  BunUnsupportedError,
  type DetectInput,
} from '../../src/action/detect-pm.js';

// ---------------------------------------------------------------------------
// Fake fs helper
// ---------------------------------------------------------------------------

interface FakeFile {
  /** Relative basename inside the repo root (e.g. "pnpm-lock.yaml"). */
  name: string;
  /** Raw contents (bytes). */
  contents: Buffer;
}

function makeFs(repoDir: string, files: FakeFile[]): DetectInput['fs'] {
  const byPath = new Map<string, Buffer>();
  for (const f of files) byPath.set(join(repoDir, f.name), f.contents);

  return {
    existsSync: (p: string): boolean => byPath.has(p),
    readFileSync: (p: string): Buffer => {
      const buf = byPath.get(p);
      if (buf === undefined) throw new Error(`ENOENT: ${p}`);
      return buf;
    },
  };
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('detectPm', () => {
  const repoDir = '/fake/repo';

  it('detects pnpm from pnpm-lock.yaml', async () => {
    const contents = Buffer.from('lockfileVersion: 9\n');
    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'pnpm-lock.yaml', contents }]),
    });

    expect(result.manager).toBe('pnpm');
    expect(result.lockfilePath).toBe(join(repoDir, 'pnpm-lock.yaml'));
    expect(result.lockfileSha256).toBe(sha256Hex(contents));
  });

  it('detects yarn from yarn.lock', async () => {
    const contents = Buffer.from('# yarn lockfile v1\n');
    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'yarn.lock', contents }]),
    });

    expect(result.manager).toBe('yarn');
    expect(result.lockfilePath).toBe(join(repoDir, 'yarn.lock'));
    expect(result.lockfileSha256).toBe(sha256Hex(contents));
  });

  it('detects npm from package-lock.json', async () => {
    const contents = Buffer.from('{"lockfileVersion": 3}\n');
    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'package-lock.json', contents }]),
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'package-lock.json'));
  });

  it('detects npm from npm-shrinkwrap.json', async () => {
    const contents = Buffer.from('{"lockfileVersion": 2}\n');
    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'npm-shrinkwrap.json', contents }]),
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'npm-shrinkwrap.json'));
  });

  it('prefers pnpm-lock.yaml over yarn.lock and package-lock.json (priority order)', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
        { name: 'package-lock.json', contents: Buffer.from('npm') },
      ]),
    });

    expect(result.manager).toBe('pnpm');
    expect(warnSpy).toHaveBeenCalled();
    const msg = warnSpy.mock.calls[0]?.[0];
    expect(typeof msg).toBe('string');
    expect(msg).toMatch(/pnpm-lock\.yaml/);
    warnSpy.mockRestore();
  });

  it('prefers yarn.lock over package-lock.json when both present', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
        { name: 'package-lock.json', contents: Buffer.from('npm') },
      ]),
    });

    expect(result.manager).toBe('yarn');
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('prefers package-lock.json over npm-shrinkwrap.json when both present', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'package-lock.json', contents: Buffer.from('a') },
        { name: 'npm-shrinkwrap.json', contents: Buffer.from('b') },
      ]),
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'package-lock.json'));
    warnSpy.mockRestore();
  });

  it('throws BunUnsupportedError when only bun.lock is present', async () => {
    const fs = makeFs(repoDir, [{ name: 'bun.lock', contents: Buffer.from('') }]);
    await expect(detectPm({ repoDir, fs })).rejects.toBeInstanceOf(BunUnsupportedError);
    await expect(detectPm({ repoDir, fs })).rejects.toThrow(/does not support bun/);
  });

  it('throws BunUnsupportedError when only bun.lockb is present', async () => {
    const fs = makeFs(repoDir, [{ name: 'bun.lockb', contents: Buffer.from('') }]);
    await expect(detectPm({ repoDir, fs })).rejects.toBeInstanceOf(BunUnsupportedError);
  });

  it('does NOT throw BunUnsupportedError when bun.lock coexists with a supported lockfile', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'bun.lock', contents: Buffer.from('') },
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
      ]),
    });
    // bun.lock is ignored; we use pnpm.  No warning required for bun because
    // detection ignores it entirely when a supported lockfile is present.
    expect(result.manager).toBe('pnpm');
    warnSpy.mockRestore();
  });

  it('throws a clear error when no lockfile is found', async () => {
    const fs = makeFs(repoDir, []);
    await expect(detectPm({ repoDir, fs })).rejects.toThrow(/no lockfile found/);
    await expect(detectPm({ repoDir, fs })).rejects.toThrow(repoDir);
  });

  it('SHA-256 is hex of raw bytes', async () => {
    const contents = Buffer.from('hello world');
    const expected = sha256Hex(contents);
    const result = await detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'pnpm-lock.yaml', contents }]),
    });
    expect(result.lockfileSha256).toBe(expected);
    expect(result.lockfileSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns absolute lockfilePath joined from repoDir', async () => {
    const result = await detectPm({
      repoDir: '/abs/path',
      fs: makeFs('/abs/path', [{ name: 'pnpm-lock.yaml', contents: Buffer.from('') }]),
    });
    expect(result.lockfilePath).toBe('/abs/path/pnpm-lock.yaml');
  });
});

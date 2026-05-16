// npm-jar — test/action/detect-pm.test.ts
//
// Tests for detectPm() — lockfile-based package-manager detection.
//
// All tests use the `fs` injection seam (no real filesystem touched).  The
// `warn` injection seam is used to capture warning messages without writing
// to the real process stdout.

import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import {
  detectPm,
  BunUnsupportedError,
  type DetectInput,
} from '../../src/action/detect-pm.js';

// ---------------------------------------------------------------------------
// Fake fs / warn helpers
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

interface WarnCapture {
  messages: string[];
  warn: (msg: string) => void;
}

function makeWarn(): WarnCapture {
  const messages: string[] = [];
  return {
    messages,
    warn: (msg: string): void => { messages.push(msg); },
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

  it('detects pnpm from pnpm-lock.yaml', () => {
    const contents = Buffer.from('lockfileVersion: 9\n');
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'pnpm-lock.yaml', contents }]),
    });

    expect(result.manager).toBe('pnpm');
    expect(result.lockfilePath).toBe(join(repoDir, 'pnpm-lock.yaml'));
    expect(result.lockfileSha256).toBe(sha256Hex(contents));
  });

  it('detects yarn from yarn.lock', () => {
    const contents = Buffer.from('# yarn lockfile v1\n');
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'yarn.lock', contents }]),
    });

    expect(result.manager).toBe('yarn');
    expect(result.lockfilePath).toBe(join(repoDir, 'yarn.lock'));
    expect(result.lockfileSha256).toBe(sha256Hex(contents));
  });

  it('detects npm from package-lock.json', () => {
    const contents = Buffer.from('{"lockfileVersion": 3}\n');
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'package-lock.json', contents }]),
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'package-lock.json'));
  });

  it('detects npm from npm-shrinkwrap.json', () => {
    const contents = Buffer.from('{"lockfileVersion": 2}\n');
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'npm-shrinkwrap.json', contents }]),
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'npm-shrinkwrap.json'));
  });

  it('prefers pnpm-lock.yaml over yarn.lock and package-lock.json (priority order)', () => {
    const warnSink = makeWarn();

    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
        { name: 'package-lock.json', contents: Buffer.from('npm') },
      ]),
      warn: warnSink.warn,
    });

    expect(result.manager).toBe('pnpm');
    expect(warnSink.messages.length).toBeGreaterThan(0);
    expect(warnSink.messages[0]).toMatch(/pnpm-lock\.yaml/);
  });

  it('prefers yarn.lock over package-lock.json when both present', () => {
    const warnSink = makeWarn();

    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
        { name: 'package-lock.json', contents: Buffer.from('npm') },
      ]),
      warn: warnSink.warn,
    });

    expect(result.manager).toBe('yarn');
    expect(warnSink.messages.length).toBeGreaterThan(0);
  });

  it('prefers package-lock.json over npm-shrinkwrap.json when both present', () => {
    const warnSink = makeWarn();

    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'package-lock.json', contents: Buffer.from('a') },
        { name: 'npm-shrinkwrap.json', contents: Buffer.from('b') },
      ]),
      warn: warnSink.warn,
    });

    expect(result.manager).toBe('npm');
    expect(result.lockfilePath).toBe(join(repoDir, 'package-lock.json'));
  });

  it('prefers pnpm over all others when all four supported lockfiles are present', () => {
    // Locks the full priority table, not just adjacent pairs.
    const warnSink = makeWarn();

    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
        { name: 'package-lock.json', contents: Buffer.from('npm') },
        { name: 'npm-shrinkwrap.json', contents: Buffer.from('shr') },
      ]),
      warn: warnSink.warn,
    });

    expect(result.manager).toBe('pnpm');
    expect(result.lockfilePath).toBe(join(repoDir, 'pnpm-lock.yaml'));
    expect(warnSink.messages.length).toBe(1);
    // The warning should mention every ignored lockfile.
    const msg = warnSink.messages[0]!;
    expect(msg).toMatch(/yarn\.lock/);
    expect(msg).toMatch(/package-lock\.json/);
    expect(msg).toMatch(/npm-shrinkwrap\.json/);
  });

  it('emits the warning through the injected sink (not console.warn)', () => {
    // Regression guard: detect-pm must route warnings through the `warn`
    // seam so the action surfaces them as ::warning:: annotations.
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const warnSink = makeWarn();

    detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
        { name: 'yarn.lock', contents: Buffer.from('yarn') },
      ]),
      warn: warnSink.warn,
    });

    expect(warnSink.messages.length).toBe(1);
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('throws BunUnsupportedError when only bun.lock is present', () => {
    const fs = makeFs(repoDir, [{ name: 'bun.lock', contents: Buffer.from('') }]);
    expect(() => detectPm({ repoDir, fs })).toThrow(BunUnsupportedError);
    expect(() => detectPm({ repoDir, fs })).toThrow(/does not support bun/);
  });

  it('throws BunUnsupportedError when only bun.lockb is present', () => {
    const fs = makeFs(repoDir, [{ name: 'bun.lockb', contents: Buffer.from('') }]);
    expect(() => detectPm({ repoDir, fs })).toThrow(BunUnsupportedError);
  });

  it('does NOT throw BunUnsupportedError when bun.lock coexists with a supported lockfile', () => {
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [
        { name: 'bun.lock', contents: Buffer.from('') },
        { name: 'pnpm-lock.yaml', contents: Buffer.from('pnpm') },
      ]),
      warn: () => {},
    });
    // bun.lock is ignored; we use pnpm.  No warning required for bun because
    // detection ignores it entirely when a supported lockfile is present.
    expect(result.manager).toBe('pnpm');
  });

  it('throws a clear error when no lockfile is found', () => {
    const fs = makeFs(repoDir, []);
    expect(() => detectPm({ repoDir, fs })).toThrow(/no lockfile found/);
    expect(() => detectPm({ repoDir, fs })).toThrow(repoDir);
  });

  it('SHA-256 is hex of raw bytes', () => {
    const contents = Buffer.from('hello world');
    const expected = sha256Hex(contents);
    const result = detectPm({
      repoDir,
      fs: makeFs(repoDir, [{ name: 'pnpm-lock.yaml', contents }]),
    });
    expect(result.lockfileSha256).toBe(expected);
    expect(result.lockfileSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns absolute lockfilePath joined from repoDir', () => {
    const result = detectPm({
      repoDir: '/abs/path',
      fs: makeFs('/abs/path', [{ name: 'pnpm-lock.yaml', contents: Buffer.from('') }]),
    });
    expect(result.lockfilePath).toBe('/abs/path/pnpm-lock.yaml');
  });
});

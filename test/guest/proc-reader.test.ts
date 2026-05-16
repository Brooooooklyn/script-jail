// Tests for src/guest/proc-reader.ts
// Uses vitest project: "guest" (see vitest.config.ts)
// Creates a real fake /proc tree under a temp directory.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LinuxProcReader } from '../../src/guest/proc-reader.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

let fakeRoot: string;

function makeFakeProc(): string {
  fakeRoot = mkdtempSync(join(tmpdir(), 'npm-jar-proc-'));
  return fakeRoot;
}

function makePidDir(root: string, pid: number): string {
  const dir = join(root, String(pid));
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Write a minimal /proc/<pid>/status file with the given PPid value.
 * Includes a few realistic extra fields to validate that the parser
 * only cares about the PPid line.
 */
function writeStatus(dir: string, ppid: number): void {
  const content = [
    `Name:\tnode`,
    `Pid:\t${parseInt(dir.split('/').at(-1) ?? '0', 10)}`,
    `PPid:\t${ppid}`,
    `Uid:\t1000\t1000\t1000\t1000`,
    `VmRSS:\t12345 kB`,
  ].join('\n') + '\n';
  writeFileSync(join(dir, 'status'), content, 'utf8');
}

/**
 * Write a /proc/<pid>/environ file from a plain object.
 * Keys and values are joined with '=' and records are separated by NUL.
 */
function writeEnviron(dir: string, env: Record<string, string>): void {
  // Real /proc/<pid>/environ ends with a trailing NUL byte.
  const buf = Object.entries(env)
    .map(([k, v]) => `${k}=${v}`)
    .join('\0') + '\0';
  // Write as a Buffer so NUL bytes are literal (not escaped).
  writeFileSync(join(dir, 'environ'), Buffer.from(buf, 'utf8'));
}

afterEach(() => {
  if (fakeRoot) {
    rmSync(fakeRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// readPpid tests
// ---------------------------------------------------------------------------

describe('LinuxProcReader.readPpid', () => {
  it('returns the PPid from a valid status file', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeStatus(dir, 1);
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(100)).toBe(1);
  });

  it('returns the correct PPid when it is non-1', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 200);
    writeStatus(dir, 150);
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(200)).toBe(150);
  });

  it('returns null when the pid directory does not exist', () => {
    const root = makeFakeProc();
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(9999)).toBeNull();
  });

  it('returns null when the status file does not exist', () => {
    const root = makeFakeProc();
    makePidDir(root, 100); // dir exists but no status file
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(100)).toBeNull();
  });

  it('returns null when status file has no PPid line', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeFileSync(join(dir, 'status'), 'Name:\tnode\nUid:\t1000\n', 'utf8');
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(100)).toBeNull();
  });

  it('parses PPid: with tab separator', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeFileSync(join(dir, 'status'), 'PPid:\t42\n', 'utf8');
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(100)).toBe(42);
  });

  it('parses PPid: with multiple spaces', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeFileSync(join(dir, 'status'), 'PPid:  42\n', 'utf8');
    const reader = new LinuxProcReader(root);
    expect(reader.readPpid(100)).toBe(42);
  });

  // On macOS /proc does not exist, so this is a no-op returning null.
  // On Linux pid 1 always exists and returns 0 (kernel).
  it.skipIf(process.platform !== 'linux')('reads from default /proc root on Linux', () => {
    const reader = new LinuxProcReader();
    const result = reader.readPpid(1);
    // On Linux pid 1's PPid is 0 (kernel pseudo-process).
    expect(result).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// readEnviron tests
// ---------------------------------------------------------------------------

describe('LinuxProcReader.readEnviron', () => {
  it('returns correct map for a valid environ file', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeEnviron(dir, {
      HOME: '/root',
      npm_package_name: 'esbuild',
      npm_package_version: '0.21.5',
      npm_lifecycle_event: 'postinstall',
    });
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.get('HOME')).toBe('/root');
    expect(env!.get('npm_package_name')).toBe('esbuild');
    expect(env!.get('npm_package_version')).toBe('0.21.5');
    expect(env!.get('npm_lifecycle_event')).toBe('postinstall');
  });

  it('returns null when the pid directory does not exist', () => {
    const root = makeFakeProc();
    const reader = new LinuxProcReader(root);
    expect(reader.readEnviron(9999)).toBeNull();
  });

  it('returns null when the environ file does not exist', () => {
    const root = makeFakeProc();
    makePidDir(root, 100);
    const reader = new LinuxProcReader(root);
    expect(reader.readEnviron(100)).toBeNull();
  });

  it('returns an empty Map for an empty environ file', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeFileSync(join(dir, 'environ'), Buffer.alloc(0));
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.size).toBe(0);
  });

  it('skips tokens without an = sign', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    // Write a mix of valid and no-equals tokens, NUL-separated
    const buf = Buffer.from('GOOD=value\0NOEQUALSSIGN\0ALSO_GOOD=yes\0', 'utf8');
    writeFileSync(join(dir, 'environ'), buf);
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.has('NOEQUALSSIGN')).toBe(false);
    expect(env!.get('GOOD')).toBe('value');
    expect(env!.get('ALSO_GOOD')).toBe('yes');
    expect(env!.size).toBe(2);
  });

  it('handles = in the value (splits on first = only)', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    // KEY=foo=bar should result in key='KEY', value='foo=bar'
    const buf = Buffer.from('KEY=foo=bar\0', 'utf8');
    writeFileSync(join(dir, 'environ'), buf);
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.get('KEY')).toBe('foo=bar');
  });

  it('handles trailing NUL byte in environ file gracefully', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    // Real /proc/<pid>/environ files often end with a NUL
    const buf = Buffer.from('A=1\0B=2\0', 'utf8');
    writeFileSync(join(dir, 'environ'), buf);
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.size).toBe(2);
    expect(env!.get('A')).toBe('1');
    expect(env!.get('B')).toBe('2');
  });

  it('handles a single entry with no trailing NUL', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 100);
    writeFileSync(join(dir, 'environ'), Buffer.from('FOO=bar', 'utf8'));
    const reader = new LinuxProcReader(root);
    const env = reader.readEnviron(100);
    expect(env).not.toBeNull();
    expect(env!.get('FOO')).toBe('bar');
    expect(env!.size).toBe(1);
  });

  it('readEnviron handles leading and consecutive NUL bytes gracefully', () => {
    const root = makeFakeProc();
    const dir = makePidDir(root, 300);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'environ'), Buffer.from('\0KEY1=val1\0\0KEY2=val2\0', 'utf8'));
    const reader = new LinuxProcReader(root);
    const result = reader.readEnviron(300);
    expect(result?.size).toBe(2);
    expect(result?.get('KEY1')).toBe('val1');
    expect(result?.get('KEY2')).toBe('val2');
  });
});

// ---------------------------------------------------------------------------
// Integration: both readPpid and readEnviron from the same fake pid tree
// ---------------------------------------------------------------------------

describe('LinuxProcReader integration', () => {
  it('reads both ppid and environ for multiple pids', () => {
    const root = makeFakeProc();

    const dir100 = makePidDir(root, 100);
    writeStatus(dir100, 1);
    writeEnviron(dir100, {
      npm_package_name: 'esbuild',
      npm_package_version: '0.21.5',
      npm_lifecycle_event: 'postinstall',
    });

    const dir200 = makePidDir(root, 200);
    writeStatus(dir200, 100);
    writeEnviron(dir200, { HOME: '/root' });

    const reader = new LinuxProcReader(root);

    expect(reader.readPpid(100)).toBe(1);
    expect(reader.readPpid(200)).toBe(100);

    const env100 = reader.readEnviron(100);
    expect(env100!.get('npm_package_name')).toBe('esbuild');

    const env200 = reader.readEnviron(200);
    expect(env200!.get('HOME')).toBe('/root');
    expect(env200!.has('npm_package_name')).toBe(false);
  });
});

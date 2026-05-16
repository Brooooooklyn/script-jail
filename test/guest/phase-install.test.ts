// Tests for src/guest/phase-install.ts
// Injects mock StraceRunner (which owns the install process); no real processes spawned.

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { runInstallPhase, type StraceRunner } from '../../src/guest/phase-install.js';
import { Emitter } from '../../src/guest/emit.js';
import { Attribution } from '../../src/guest/attribution.js';
import type { ProcReader } from '../../src/guest/attribution.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEmitter(): { emitter: Emitter; lines: string[] } {
  const pt = new PassThrough();
  const lines: string[] = [];
  pt.on('data', (chunk: Buffer) => {
    for (const l of chunk.toString().split('\n')) {
      if (l.trim()) lines.push(l);
    }
  });
  return { emitter: new Emitter(pt), lines };
}

/**
 * A StraceRunner that yields pre-canned (pid, line) records and reports a
 * configurable exit code. The StraceRunner is the sole owner of the install
 * process — no separate Spawner is used in Phase B.
 */
function cannedStraceRunner(
  records: Array<{ pid: number; line: string }>,
  exitCode = 0,
): StraceRunner {
  let _exitCode = exitCode;
  return {
    async *run() {
      for (const r of records) yield r;
      // Finalize exit code after yielding all records
    },
    getExitCode() { return _exitCode; },
    // Allow tests to change exitCode after construction
    _setExitCode(code: number) { _exitCode = code; },
  } as unknown as StraceRunner;
}

/** A ProcReader backed by a simple in-memory map. */
function mockProcReader(
  spec: Record<number, { ppid: number | null; env: Record<string, string> | null }>,
): ProcReader {
  return {
    readPpid(pid) {
      return spec[pid]?.ppid ?? null;
    },
    readEnviron(pid) {
      const e = spec[pid]?.env;
      if (e == null) return null;
      return new Map(Object.entries(e));
    },
  };
}

const BASE_ENV: NodeJS.ProcessEnv = { PATH: '/usr/bin' };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('runInstallPhase', () => {
  describe('per-manager commands (via StraceRunner)', () => {
    it('npm → npm rebuild --foreground-scripts', async () => {
      const calls: Array<{ cmd: string; args: string[] }> = [];
      const strace: StraceRunner = {
        async *run(cmd, args) { calls.push({ cmd, args }); },
        getExitCode() { return 0; },
      };
      const proc = mockProcReader({});
      const attr = new Attribution(proc);
      const { emitter } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: attr,
        emitter,
      });

      expect(calls).toHaveLength(1);
      expect(calls[0]!.cmd).toBe('npm');
      expect(calls[0]!.args).toEqual(['rebuild', '--foreground-scripts']);
    });

    it('pnpm → pnpm install --frozen-lockfile --offline --config.side-effects-cache=false', async () => {
      const calls: Array<{ cmd: string; args: string[] }> = [];
      const strace: StraceRunner = {
        async *run(cmd, args) { calls.push({ cmd, args }); },
        getExitCode() { return 0; },
      };
      const { emitter } = makeEmitter();
      await runInstallPhase({
        manager: 'pnpm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(calls[0]!.cmd).toBe('pnpm');
      expect(calls[0]!.args).toEqual([
        'install', '--frozen-lockfile', '--offline', '--config.side-effects-cache=false',
      ]);
    });

    it('yarn → yarn install --immutable --offline', async () => {
      const calls: Array<{ cmd: string; args: string[] }> = [];
      const strace: StraceRunner = {
        async *run(cmd, args) { calls.push({ cmd, args }); },
        getExitCode() { return 0; },
      };
      const { emitter } = makeEmitter();
      await runInstallPhase({
        manager: 'yarn',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(calls[0]!.cmd).toBe('yarn');
      expect(calls[0]!.args).toEqual(['install', '--immutable', '--offline']);
    });

    it('StraceRunner is called exactly once per runInstallPhase', async () => {
      let callCount = 0;
      const strace: StraceRunner = {
        async *run() { callCount++; },
        getExitCode() { return 0; },
      };
      const { emitter } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(callCount).toBe(1);
    });
  });

  describe('strace line processing', () => {
    it('emits attributed events for valid strace lines', async () => {
      // pid 42 → has npm env → attribution returns my-pkg@1.0.0 / postinstall
      const proc = mockProcReader({
        42: {
          ppid: 1,
          env: {
            npm_package_name: 'my-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/work/src/index.js", O_RDONLY) = 3' },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(parsed['kind']).toBe('event');
      expect(parsed['pkg']).toBe('my-pkg@1.0.0');
      expect(parsed['lifecycle']).toBe('postinstall');
    });

    it('drops strace lines that parse to null', async () => {
      const proc = mockProcReader({
        42: {
          ppid: 1,
          env: {
            npm_package_name: 'my-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const straceLines = [
        { pid: 42, line: '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---' }, // dropped
        { pid: 42, line: 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 4' },             // kept
      ];

      const { emitter, lines } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
      });

      // Only the second line produces an event
      expect(lines).toHaveLength(1);
      expect(result.eventCount).toBe(1);
    });

    it('drops events when attribution returns null (no npm ancestry)', async () => {
      const proc = mockProcReader({
        99: { ppid: 1, env: { HOME: '/root' } }, // no npm vars
      });

      const straceLines = [
        { pid: 99, line: 'openat(AT_FDCWD, "/work/index.js", O_RDONLY) = 3' },
      ];

      const { emitter, lines } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(0);
      expect(result.eventCount).toBe(0);
    });

    it('correctly counts eventCount', async () => {
      const proc = mockProcReader({
        10: {
          ppid: 1,
          env: {
            npm_package_name: 'pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'install',
          },
        },
      });

      const straceLines = [
        { pid: 10, line: 'openat(AT_FDCWD, "/work/a.js", O_RDONLY) = 3' },
        { pid: 10, line: 'openat(AT_FDCWD, "/work/b.js", O_RDONLY) = 4' },
        { pid: 10, line: 'openat(AT_FDCWD, "/work/c.js", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5' },
      ];

      const { emitter } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
      });

      expect(result.eventCount).toBe(3);
    });
  });

  describe('shim JSONL lines', () => {
    it('processes env_read shim lines', async () => {
      const proc = mockProcReader({
        55: {
          ppid: 1,
          env: {
            npm_package_name: 'shim-pkg',
            npm_package_version: '2.0.0',
            npm_lifecycle_event: 'install',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'env_read',
        name: 'HOME',
        pid: 55,
        ts: 12345,
        hidden: false,
      });

      const strace = cannedStraceRunner([{ pid: 55, line: shimLine }]);
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(parsed['kind']).toBe('event');
      expect((parsed['raw'] as Record<string, unknown>)['kind']).toBe('env_read');
      expect((parsed['raw'] as Record<string, unknown>)['name']).toBe('HOME');
    });

    it('processes dlopen shim lines', async () => {
      const proc = mockProcReader({
        77: {
          ppid: 1,
          env: {
            npm_package_name: 'native-pkg',
            npm_package_version: '3.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'dlopen',
        filename: '/tmp/foo.node',
        result: 'blocked',
        pid: 77,
        ts: 99999,
      });

      const strace = cannedStraceRunner([{ pid: 77, line: shimLine }]);
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
      const raw = parsed['raw'] as Record<string, unknown>;
      expect(raw['kind']).toBe('dlopen');
      expect(raw['filename']).toBe('/tmp/foo.node');
      expect(raw['result']).toBe('blocked');
    });
  });

  describe('exit code propagation via StraceRunner.getExitCode()', () => {
    it('returns non-zero exitCode when StraceRunner reports failure', async () => {
      const { emitter } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner([], 2),
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(result.exitCode).toBe(2);
    });

    it('returns exitCode=0 on success', async () => {
      const { emitter } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner([], 0),
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(result.exitCode).toBe(0);
    });

    it('exit code comes from getExitCode(), not a separate spawner', async () => {
      // Verify no separate spawn call happens by ensuring the StraceRunner
      // is the ONLY thing that runs (no Spawner in PhaseInstallInput).
      const strace = cannedStraceRunner([], 42);
      const { emitter } = makeEmitter();
      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(mockProcReader({})),
        emitter,
      });
      expect(result.exitCode).toBe(42);
    });
  });

  describe('attribution result used as pkg/lifecycle', () => {
    it('sets pkg and lifecycle from attribution on emitted events', async () => {
      const proc = mockProcReader({
        20: {
          ppid: 1,
          env: {
            npm_package_name: 'awesome-lib',
            npm_package_version: '5.1.0',
            npm_lifecycle_event: 'prepare',
          },
        },
      });

      const strace = cannedStraceRunner([
        { pid: 20, line: 'openat(AT_FDCWD, "/work/lib/index.js", O_RDONLY) = 7' },
      ]);

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(parsed['pkg']).toBe('awesome-lib@5.1.0');
      expect(parsed['lifecycle']).toBe('prepare');
    });
  });

  describe('parseShimLine (exported for testing)', () => {
    it('parses env_read lines', async () => {
      // Import parseShimLine directly
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({ kind: 'env_read', name: 'HOME', pid: 1, ts: 0, hidden: false });
      const ev = parseShimLine(line);
      expect(ev).not.toBeNull();
      expect(ev?.kind).toBe('env_read');
    });

    it('parses dlopen lines', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({ kind: 'dlopen', filename: '/tmp/x.node', result: 'blocked', pid: 2, ts: 100 });
      const ev = parseShimLine(line);
      expect(ev).not.toBeNull();
      expect(ev?.kind).toBe('dlopen');
    });

    it('returns null for invalid JSON', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      expect(parseShimLine('not json')).toBeNull();
    });

    it('returns null for unknown kind', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      expect(parseShimLine(JSON.stringify({ kind: 'unknown', pid: 1 }))).toBeNull();
    });
  });
});

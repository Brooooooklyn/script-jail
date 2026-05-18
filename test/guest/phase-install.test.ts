// Tests for src/guest/phase-install.ts
// Injects mock StraceRunner (which owns the install process); no real processes spawned.

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { runInstallPhase, type StraceRunner } from '../../src/guest/phase-install.js';
import { Emitter } from '../../src/guest/emit.js';
import { Attribution } from '../../src/guest/attribution.js';
import type { ProcReader } from '../../src/guest/attribution.js';
import { ProtectedPathsMatcher } from '../../src/guest/protected-paths.js';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';
import type { AttributedEvent } from '../../src/lock/schema.js';

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
 *
 * Records may carry an explicit `source` ('shim' | 'strace'); when omitted,
 * we heuristically infer 'shim' for lines that look like JSONL (start with
 * `{`) and 'strace' for everything else.  This keeps the bulk of pre-
 * existing tests (which omit `source`) working unchanged while letting new
 * tests pin the channel deliberately.
 */
function cannedStraceRunner(
  records: Array<{ pid: number; line: string; source?: 'shim' | 'strace' }>,
  exitCode = 0,
): StraceRunner & { recordedTamper(): string | null } {
  let _exitCode = exitCode;
  let _tamperReason: string | null = null;
  return {
    async *run() {
      for (const r of records) {
        const source: 'shim' | 'strace' =
          r.source ?? (r.line.startsWith('{') ? 'shim' : 'strace');
        yield { pid: r.pid, line: r.line, source };
      }
    },
    getExitCode() { return _exitCode; },
    // Finding D: tamper reporting is part of the StraceRunner contract;
    // canned runners don't audit a real events file but we DO record any
    // tamper plumbed through `recordTamper()` so tests can assert on it.
    getTamperReason() { return _tamperReason; },
    recordTamper(reason: string) {
      if (_tamperReason === null) _tamperReason = reason;
    },
    // Exposed for tests.  Same value as `getTamperReason()` but named
    // explicitly to make the assertion intent obvious at the call site.
    recordedTamper() { return _tamperReason; },
    // Allow tests to change exitCode after construction
    _setExitCode(code: number) { _exitCode = code; },
  } as unknown as StraceRunner & { recordedTamper(): string | null };
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
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* no-op */ },
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
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* no-op */ },
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
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* no-op */ },
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
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* no-op */ },
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

    it('processes exec shim lines (envp_alloc_failed=false)', async () => {
      const proc = mockProcReader({
        61: {
          ppid: 1,
          env: {
            npm_package_name: 'exec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'exec',
        prog: '/usr/bin/node',
        argv0: 'node',
        envp_alloc_failed: false,
        pid: 61,
        ts: 4242,
      });

      const strace = cannedStraceRunner([{ pid: 61, line: shimLine }]);
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
      expect(raw['kind']).toBe('exec');
      expect(raw['prog']).toBe('/usr/bin/node');
      expect(raw['argv0']).toBe('node');
      expect(raw['envp_alloc_failed']).toBe(false);
    });

    it('processes exec shim lines (envp_alloc_failed=true) — audit-bypass signal', async () => {
      const proc = mockProcReader({
        62: {
          ppid: 1,
          env: {
            npm_package_name: 'audit-bypass-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'exec',
        prog: 'sh',
        argv0: null, // posix_spawnp can elide argv0
        envp_alloc_failed: true,
        pid: 62,
        ts: 4243,
      });

      const strace = cannedStraceRunner([{ pid: 62, line: shimLine }]);
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
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['kind']).toBe('exec');
      expect(raw['argv0']).toBeNull();
      expect(raw['envp_alloc_failed']).toBe(true);
    });

    it('processes env_tamper shim lines with a name (unsetenv LD_PRELOAD)', async () => {
      const proc = mockProcReader({
        63: {
          ppid: 1,
          env: {
            npm_package_name: 'tamper-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'env_tamper',
        op: 'unsetenv',
        name: 'LD_PRELOAD',
        refused: true,
        pid: 63,
        ts: 4244,
      });

      const strace = cannedStraceRunner([{ pid: 63, line: shimLine }]);
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
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['kind']).toBe('env_tamper');
      expect(raw['op']).toBe('unsetenv');
      expect(raw['name']).toBe('LD_PRELOAD');
      expect(raw['refused']).toBe(true);
    });

    it('processes env_tamper shim lines without a name (clearenv)', async () => {
      const proc = mockProcReader({
        64: {
          ppid: 1,
          env: {
            npm_package_name: 'clearenv-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const shimLine = JSON.stringify({
        kind: 'env_tamper',
        op: 'clearenv',
        refused: true,
        pid: 64,
        ts: 4245,
      });

      const strace = cannedStraceRunner([{ pid: 64, line: shimLine }]);
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
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['kind']).toBe('env_tamper');
      expect(raw['op']).toBe('clearenv');
      expect(raw['name']).toBeUndefined();
      expect(raw['refused']).toBe(true);
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

  // ─────────────────────────────────────────────────────────────────────────
  // Shim-channel parse-failure fail-closed (critical-severity fix)
  //
  // Threat model: SCRIPT_JAIL_LOG_FILE leaks through the child env, so a
  // lifecycle script can open the events file in append mode and write a
  // partial JSONL prefix (no trailing newline). When the Rust shim's next
  // legitimate write lands, the bytes concatenate onto the attacker's prefix,
  // JSON.parse fails on the corrupted line, and (under the OLD fall-through
  // design) parseStraceLine fails too — silently dropping the real event.
  //
  // Fix: the install-phase dispatcher keys on `source`, never falls through,
  // and treats any shim-channel parse failure as fatal tamper.  Strace-channel
  // failures stay silent (best-effort) because strace's text format is noisy
  // and lines can split across reads.
  // ─────────────────────────────────────────────────────────────────────────
  describe('shim-channel parse failure → fail-closed (tamper)', () => {
    const proc = mockProcReader({
      88: {
        ppid: 1,
        env: {
          npm_package_name: 'evil-pkg',
          npm_package_version: '1.0.0',
          npm_lifecycle_event: 'postinstall',
        },
      },
    });

    it('records tamper for a shim-channel line with unknown kind (JSON.parse succeeds)', async () => {
      // Well-formed JSON, but `kind` is not in our enum. parseShimLine
      // returns null. Old design: silently drop. New design: tamper.
      const strace = cannedStraceRunner([
        { pid: 88, line: JSON.stringify({ kind: 'totally_made_up', pid: 88, ts: 1 }), source: 'shim' },
      ]);
      const { emitter, lines } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      // No event emitted; tamper recorded for main()'s post-install gate.
      expect(lines).toHaveLength(0);
      expect(result.eventCount).toBe(0);
      expect(strace.getTamperReason()).not.toBeNull();
      expect(strace.getTamperReason()).toMatch(/shim channel had unparseable JSONL line/);
    });

    it('records tamper for a shim-channel line that fails JSON.parse (malformed)', async () => {
      // Simulates the partial-prefix concat attack: attacker wrote
      // `{"kind":"env_read","name":"PARTIAL` without a newline; the next
      // legitimate shim write produced one mangled line on read.
      const malformed =
        '{"kind":"env_read","name":"PARTIAL{"kind":"env_read","name":"NPM_TOKEN","pid":88,"ts":99,"hidden":true}';
      const strace = cannedStraceRunner([
        { pid: 88, line: malformed, source: 'shim' },
      ]);
      const { emitter, lines } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(0);
      expect(result.eventCount).toBe(0);
      const reason = strace.getTamperReason();
      expect(reason).not.toBeNull();
      expect(reason).toMatch(/shim channel had unparseable JSONL line/);
      // Reason must reference the originating pid so a triager can correlate.
      expect(reason).toMatch(/pid=88/);
    });

    it('truncates the offending prefix in the tamper reason (≤ ~100 bytes)', async () => {
      // A 500-byte payload — the agent should NOT echo all of it back into
      // its error reason (could contain secret-like content captured by the
      // shim's getenv interceptor before the parse failure).
      const longPayload = 'X'.repeat(500);
      const strace = cannedStraceRunner([
        { pid: 88, line: longPayload, source: 'shim' },
      ]);
      const { emitter } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      const reason = strace.getTamperReason();
      expect(reason).not.toBeNull();
      // The reason should not contain the full 500-X payload.
      expect((reason ?? '').length).toBeLessThan(500);
      // It should include a truncation marker.
      expect(reason).toMatch(/…/);
    });

    it('does NOT record tamper for a valid shim-channel event (happy path)', async () => {
      // env_read, exec, env_tamper, dlopen — all four shapes must be
      // accepted without tamper.
      const lines: Array<{ pid: number; line: string; source: 'shim' }> = [
        { pid: 88, source: 'shim', line: JSON.stringify({ kind: 'env_read', name: 'HOME', pid: 88, ts: 1, hidden: false }) },
        { pid: 88, source: 'shim', line: JSON.stringify({ kind: 'exec', prog: '/bin/ls', argv0: 'ls', envp_alloc_failed: false, pid: 88, ts: 2 }) },
        { pid: 88, source: 'shim', line: JSON.stringify({ kind: 'env_tamper', op: 'unsetenv', name: 'LD_PRELOAD', refused: true, pid: 88, ts: 3 }) },
        { pid: 88, source: 'shim', line: JSON.stringify({ kind: 'dlopen', filename: '/tmp/x.node', result: 'blocked', pid: 88, ts: 4 }) },
      ];

      const strace = cannedStraceRunner(lines);
      const { emitter, lines: emitted } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      // All four reach normalize.
      expect(emitted).toHaveLength(4);
      expect(result.eventCount).toBe(4);
      expect(strace.getTamperReason()).toBeNull();
    });

    it('strace-channel parse failure is silently dropped (no tamper)', async () => {
      // Strace's text format is noisy: signal-delivered lines, partial
      // lines split across reads, unhandled syscall families.  A strict
      // gate here would break every install.  We assert that an
      // un-parseable strace line does NOT record tamper and does NOT
      // emit an event.
      const strace = cannedStraceRunner([
        { pid: 88, source: 'strace', line: '--- this is not a recognized strace syscall record ---' },
      ]);
      const { emitter, lines } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(lines).toHaveLength(0);
      expect(result.eventCount).toBe(0);
      expect(strace.getTamperReason()).toBeNull();
    });

    it('shim-channel line is never fed to the strace parser', async () => {
      // Regression guard for the original bug: a malformed JSON fragment
      // that ALSO happens to vaguely match a strace pattern must not be
      // emitted as a strace event when arriving on the shim channel.
      // Instead, it must record tamper.
      //
      // (Construct a string that looks somewhat like a syscall but is
      // invalid JSON when delivered on the shim channel.)
      const strace = cannedStraceRunner([
        { pid: 88, source: 'shim', line: 'openat(AT_FDCWD, "/x", O_RDONLY) = 3' },
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

      // The would-be openat event must NOT have been emitted — shim
      // channel never falls through to the strace parser.
      expect(lines).toHaveLength(0);
      expect(strace.getTamperReason()).not.toBeNull();
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

  describe('protected-paths policy filter', () => {
    const roots = {
      repo: '/work',
      nodeModules: '/work/node_modules',
      home: '/root',
      tmp: '/tmp',
      cache: '/root/.cache/pnpm',
    };

    function makeProtectedMatcher(patterns: string[]): ProtectedPathsMatcher {
      return new ProtectedPathsMatcher({ patterns, roots });
    }

    const npmEnv = {
      npm_package_name: 'my-pkg',
      npm_package_version: '1.0.0',
      npm_lifecycle_event: 'postinstall',
    };

    it('protected ENOENT read → emitted with hidden=true (no errno in event)', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)' },
      ];
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]!) as Record<string, unknown>;
      const raw = parsed['raw'] as Record<string, unknown>;
      expect(raw['kind']).toBe('read');
      expect(raw['path']).toBe('/root/.ssh/id_rsa');
      expect(raw['hidden']).toBe(true);
      expect(raw).not.toHaveProperty('errno'); // never leak errno to emit
    });

    it('unprotected ENOENT read → dropped silently (existing noise filter)', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/usr/local/missing.so", O_RDONLY) = -1 ENOENT (No such file or directory)' },
      ];
      const { emitter, lines } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      expect(lines).toHaveLength(0);
      expect(result.eventCount).toBe(0);
    });

    it('protected EACCES read → emitted with hidden=true', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 EACCES (Permission denied)' },
      ];
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      expect(lines).toHaveLength(1);
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['hidden']).toBe(true);
      expect(raw).not.toHaveProperty('errno');
    });

    it('unprotected EACCES read → emitted with hidden=false (existing behaviour)', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)' },
      ];
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      expect(lines).toHaveLength(1);
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['hidden']).toBe(false);
      expect(raw).not.toHaveProperty('errno');
    });

    it('without protectedPaths the default no-op matcher drops ENOENT and emits EACCES', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)' }, // dropped
        { pid: 42, line: 'openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)' },               // emitted plain
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
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['path']).toBe('/etc/shadow');
      expect(raw['hidden']).toBe(false);
      expect(raw).not.toHaveProperty('errno');
    });

    it('end-to-end: ENOENT on protected path → emitted event → normalize → render shows <HIDDEN> $HOME/...', async () => {
      // Cross-check: a strace ENOENT line for ~/.ssh/id_rsa flows all the way
      // through to the rendered YAML as `<HIDDEN> $HOME/.ssh/id_rsa` (and the
      // errno never appears in the rendered output).
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)' },
      ];

      // Custom emitter that captures AttributedEvents (same shape agent.ts uses).
      const collected: AttributedEvent[] = [];
      const pt = new PassThrough();
      pt.on('data', (chunk: Buffer) => {
        for (const l of chunk.toString().split('\n')) {
          if (!l.trim()) continue;
          const parsed = JSON.parse(l) as Record<string, unknown>;
          if (parsed['kind'] === 'event') {
            collected.push({
              raw: parsed['raw'] as AttributedEvent['raw'],
              pkg: parsed['pkg'] as string,
              lifecycle: parsed['lifecycle'] as AttributedEvent['lifecycle'],
            });
          }
        }
      });
      const emitter = new Emitter(pt);

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      expect(collected).toHaveLength(1);

      // Now normalize + render exactly the way agent.ts does.
      const ctx: NormalizeContext = {
        roots,
        pkgDirs: new Map([['my-pkg@1.0.0', '/work/node_modules/my-pkg']]),
      };
      const packages = normalize(collected, ctx);

      const yaml = render({
        manager: 'npm',
        manager_lockfile_sha256: 'deadbeef',
        node_version: '20.19.0',
        generated_at: '2026-05-17T00:00:00Z',
        packages,
      });

      // The rendered YAML must surface the hidden probe.
      expect(yaml).toContain('<HIDDEN> $HOME/.ssh/id_rsa');
      // And the errno transport field must never reach the rendered output.
      expect(yaml).not.toContain('errno');
      expect(yaml).not.toContain('ENOENT');
    });

    it('successful read passes through unchanged (no errno -> no policy intervention)', async () => {
      const proc = mockProcReader({ 42: { ppid: 1, env: npmEnv } });
      const straceLines = [
        { pid: 42, line: 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3' },
      ];
      const { emitter, lines } = makeEmitter();

      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(straceLines),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: makeProtectedMatcher(['~/.ssh/**']),
      });

      // Note: a successful read of ~/.ssh/id_rsa would naturally already have
      // hidden=false from the strace-parser; the policy filter doesn't touch
      // successful syscalls. This is intentional: <HIDDEN> exists to surface
      // probes for paths absent from the sandbox, not to redact successful
      // reads (which contain real data the script presumably needed).
      expect(lines).toHaveLength(1);
      const raw = (JSON.parse(lines[0]!) as Record<string, unknown>)['raw'] as Record<string, unknown>;
      expect(raw['hidden']).toBe(false);
      expect(raw).not.toHaveProperty('errno');
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

    it('parses well-formed exec lines (envp_alloc_failed=false)', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'exec',
        prog: '/usr/bin/node',
        argv0: 'node',
        envp_alloc_failed: false,
        pid: 3,
        ts: 1,
      });
      const ev = parseShimLine(line);
      expect(ev).not.toBeNull();
      expect(ev?.kind).toBe('exec');
      if (ev?.kind === 'exec') {
        expect(ev.envp_alloc_failed).toBe(false);
        expect(ev.argv0).toBe('node');
        expect(ev.prog).toBe('/usr/bin/node');
      }
    });

    it('parses exec lines with envp_alloc_failed=true and argv0=null', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'exec',
        prog: 'sh',
        argv0: null,
        envp_alloc_failed: true,
        pid: 4,
        ts: 2,
      });
      const ev = parseShimLine(line);
      expect(ev?.kind).toBe('exec');
      if (ev?.kind === 'exec') {
        expect(ev.envp_alloc_failed).toBe(true);
        expect(ev.argv0).toBeNull();
      }
    });

    it('rejects exec lines missing envp_alloc_failed', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'exec',
        prog: '/usr/bin/node',
        argv0: 'node',
        pid: 5,
        ts: 3,
      });
      expect(parseShimLine(line)).toBeNull();
    });

    it('parses env_tamper lines with a name', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'env_tamper',
        op: 'unsetenv',
        name: 'LD_PRELOAD',
        refused: true,
        pid: 6,
        ts: 4,
      });
      const ev = parseShimLine(line);
      expect(ev?.kind).toBe('env_tamper');
      if (ev?.kind === 'env_tamper') {
        expect(ev.op).toBe('unsetenv');
        expect(ev.name).toBe('LD_PRELOAD');
        expect(ev.refused).toBe(true);
      }
    });

    it('parses env_tamper clearenv lines without a name', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'env_tamper',
        op: 'clearenv',
        refused: true,
        pid: 7,
        ts: 5,
      });
      const ev = parseShimLine(line);
      expect(ev?.kind).toBe('env_tamper');
      if (ev?.kind === 'env_tamper') {
        expect(ev.op).toBe('clearenv');
        expect(ev.name).toBeUndefined();
      }
    });

    it('rejects env_tamper lines with refused != true', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'env_tamper',
        op: 'setenv',
        name: 'LD_PRELOAD',
        refused: false,
        pid: 8,
        ts: 6,
      });
      expect(parseShimLine(line)).toBeNull();
    });

    it('rejects env_tamper lines with invalid op', async () => {
      const { parseShimLine } = await import('../../src/guest/phase-install.js');
      const line = JSON.stringify({
        kind: 'env_tamper',
        op: 'setenv_unknown',
        name: 'LD_PRELOAD',
        refused: true,
        pid: 9,
        ts: 7,
      });
      expect(parseShimLine(line)).toBeNull();
    });
  });
});

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
 *
 * `opts.rootPid` (codex bug-fix #1, 2026-05-19) is exposed via
 * `getRootPid()` so the install-phase dispatcher seeds `pidCwd` for
 * EXACTLY that pid (rather than the first pid yielded — which could be
 * a forked child whose strace per-pid file was drained before the
 * parent's, in the real `LinuxStraceRunner`).  When omitted, defaults
 * to the first record's pid (mirrors the pre-fix "first observed pid
 * wins" heuristic, which most legacy tests assume).  Tests that
 * specifically exercise the root-pid bug fix pass `rootPid` explicitly
 * (or `null` to opt out of seeding entirely).
 */
function cannedStraceRunner(
  records: Array<{ pid: number; line: string; source?: 'shim' | 'strace' }>,
  exitCode = 0,
  opts: { rootPid?: number | null } = {},
): StraceRunner & { recordedTamper(): string | null } {
  let _exitCode = exitCode;
  let _tamperReason: string | null = null;
  // Default root: first record's pid (legacy "first observed pid wins"
  // for tests written before the bug-fix).  Explicit `null` opts out.
  // Explicit numeric pid pins the root regardless of yield order — this
  // is the test seam for the bug-#1 regression test.
  const rootPid: number | null = (() => {
    if (Object.prototype.hasOwnProperty.call(opts, 'rootPid')) {
      return opts.rootPid ?? null;
    }
    return records[0]?.pid ?? null;
  })();
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
    getRootPid() { return rootPid; },
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
        getRootPid() { return null; },
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
        getRootPid() { return null; },
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
        getRootPid() { return null; },
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
        getRootPid() { return null; },
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

  // ─────────────────────────────────────────────────────────────────────────
  // Finding 1 (audit-trust): runtime-exhaustive LineSource dispatch.
  // `LineSource` is only a TypeScript type; the install-phase dispatcher must
  // not fall through to the strace parser when the runtime value is anything
  // other than 'shim' or 'strace'.  Any other discriminator (undefined, a
  // typo, a future-renamed channel) is treated as an audit-pipeline contract
  // breach and recorded as fatal tamper.
  // ─────────────────────────────────────────────────────────────────────────
  describe('Finding 1 — unknown LineSource → fail-closed (tamper)', () => {
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

    /**
     * cannedStraceRunner heuristically infers `source` when it's omitted.
     * For these tests we have to bypass that helper so we can yield a
     * record whose runtime `source` field is literally `undefined`,
     * `'shim '` (trailing space — looks shim-y but isn't equal to 'shim'),
     * or a totally unknown value.
     */
    function rawRunner(
      records: Array<{ pid: number; line: string; source: unknown }>,
    ): StraceRunner & { recordedTamper(): string | null } {
      let _tamperReason: string | null = null;
      return {
        async *run() {
          for (const r of records) {
            yield { pid: r.pid, line: r.line, source: r.source as 'shim' | 'strace' };
          }
        },
        getExitCode() { return 0; },
        getTamperReason() { return _tamperReason; },
        recordTamper(reason: string) {
          if (_tamperReason === null) _tamperReason = reason;
        },
        getRootPid() { return records[0]?.pid ?? null; },
        recordedTamper() { return _tamperReason; },
      } as unknown as StraceRunner & { recordedTamper(): string | null };
    }

    it('source: undefined carrying shim JSONL → fatal tamper', async () => {
      // Looks like a legitimate shim env_read, but `source` is undefined —
      // the dispatcher MUST NOT trust it as a shim line and MUST NOT fall
      // through to the strace parser.
      const shimLine = JSON.stringify({
        kind: 'env_read', name: 'NPM_TOKEN', pid: 88, ts: 1, hidden: true,
      });
      const strace = rawRunner([{ pid: 88, line: shimLine, source: undefined }]);
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
      expect(reason).toMatch(/unknown LineSource/);
      expect(reason).toMatch(/pid=88/);
    });

    it("source: 'shim ' (trailing space) → fatal tamper", async () => {
      const shimLine = JSON.stringify({
        kind: 'env_read', name: 'NPM_TOKEN', pid: 88, ts: 1, hidden: true,
      });
      const strace = rawRunner([{ pid: 88, line: shimLine, source: 'shim ' }]);
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
      expect(reason).toMatch(/unknown LineSource/);
      // The actual offending value should appear in the reason for triage.
      expect(reason).toMatch(/shim /);
    });

    it("source: 'unknown' → fatal tamper", async () => {
      const strace = rawRunner([
        { pid: 88, line: 'whatever', source: 'unknown' },
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
      expect(reason).toMatch(/unknown LineSource/);
      expect(reason).toMatch(/unknown/);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Finding 2 (audit-trust): runInstallPhase owns its own tamper signal.
  // The StraceRunner.recordTamper() contract allows no-op implementations,
  // so the dispatcher MUST surface shim-channel parse failures (and unknown
  // LineSource values) via PhaseInstallResult.tamperReason — not just via
  // optional runner side state.  agent.main() consumes this slot as the
  // canonical fail-closed signal alongside straceRunner.getTamperReason().
  // ─────────────────────────────────────────────────────────────────────────
  describe('Finding 2 — runInstallPhase owns tamperReason in PhaseInstallResult', () => {
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

    /**
     * A StraceRunner whose `recordTamper` is intentionally a no-op — models
     * a wrapper / decorator / test fake whose author decided not to bother
     * surfacing tamper through the runner contract.  Even with this no-op
     * runner, runInstallPhase MUST still report tamper through its return
     * value.  This is the defence-in-depth gap that Finding 2 closes.
     */
    function noopTamperRunner(
      records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }>,
    ): StraceRunner {
      return {
        async *run() {
          for (const r of records) yield r;
        },
        getExitCode() { return 0; },
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* deliberately no-op */ },
        getRootPid() { return records[0]?.pid ?? null; },
      };
    }

    it('no-op recordTamper runner: shim parse fails → result.tamperReason is non-null', async () => {
      const strace = noopTamperRunner([
        { pid: 88, source: 'shim', line: '{not json' },
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

      // No event reached the emitter.
      expect(lines).toHaveLength(0);
      // Runner has no record of the tamper (its recordTamper is a no-op).
      expect(strace.getTamperReason()).toBeNull();
      // BUT runInstallPhase itself surfaces it via PhaseInstallResult — this
      // is the slot main() consults as the canonical fail-closed signal.
      expect(result.tamperReason).not.toBeNull();
      expect(result.tamperReason).toMatch(/shim channel had unparseable JSONL line/);
    });

    it('no-op recordTamper runner: unknown LineSource → result.tamperReason is non-null', async () => {
      const strace: StraceRunner = {
        async *run() {
          yield { pid: 88, line: 'x', source: 'definitely-not-real' as 'shim' };
        },
        getExitCode() { return 0; },
        getTamperReason() { return null; },
        recordTamper(_reason: string) { /* deliberately no-op */ },
        getRootPid() { return 88; },
      };
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
      expect(strace.getTamperReason()).toBeNull();
      expect(result.tamperReason).not.toBeNull();
      expect(result.tamperReason).toMatch(/unknown LineSource/);
    });

    it('runner with working recordTamper still receives the reason (defence in depth)', async () => {
      // The canned runner records tamper through its own sink as well —
      // both PhaseInstallResult.tamperReason AND strace.getTamperReason()
      // should be non-null and carry the same reason.
      const strace = cannedStraceRunner([
        { pid: 88, source: 'shim', line: '{"kind":"made_up","pid":88,"ts":1}' },
      ]);
      const { emitter } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(result.tamperReason).not.toBeNull();
      expect(strace.getTamperReason()).not.toBeNull();
      // First-writer-wins on both sides — same reason in both slots.
      expect(strace.getTamperReason()).toBe(result.tamperReason);
    });

    it('happy path: result.tamperReason is null', async () => {
      const strace = cannedStraceRunner([
        {
          pid: 88, source: 'shim',
          line: JSON.stringify({ kind: 'env_read', name: 'HOME', pid: 88, ts: 1, hidden: false }),
        },
      ]);
      const { emitter } = makeEmitter();

      const result = await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace,
        attribution: new Attribution(proc),
        emitter,
      });

      expect(result.tamperReason).toBeNull();
    });
  });

  // Audit-trust Finding 1 (2026-05-18) — raw-syscall execve bypass detection
  //
  // The shim interposes libc symbols only.  A lifecycle script that issues
  // `syscall(SYS_execve, …)` directly bypasses every libc wrapper: the child
  // runs without our re-injected LD_PRELOAD / NODE_OPTIONS / SCRIPT_JAIL_*
  // envelope but strace still observes the execve syscall.  runInstallPhase
  // must cross-check: each strace-source `spawn` (execve) must be matched by
  // a shim-source `exec` event for the same pid; unmatched strace execve
  // calls are surfaced as a synthesised `exec` event with
  // `syscall_bypass: true`, which normalize.ts emits as a
  // `<SYSCALL_EXEC_BYPASS> …` entry under `audit_bypass`.
  describe('Finding 1 — strace execve without shim ack → syscall-bypass synthesised', () => {
    it('emits a syscall_bypass exec event when a strace execve has no matching shim exec', async () => {
      const proc = mockProcReader({
        101: {
          ppid: 1,
          env: {
            npm_package_name: 'bypass-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // One strace-source execve, NO shim-source exec event for pid 101.
      // The post-loop pass should synthesise an exec event with
      // syscall_bypass:true.
      const straceLines = [
        {
          pid: 101,
          line: 'execve("/usr/bin/curl", ["curl", "https://evil.example"], 0x1234 /* 0 vars */) = 0',
          source: 'strace' as const,
        },
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

      // Two events: the original spawn (from strace) + the synthesised
      // exec (from the post-loop cross-check).
      expect(lines.length).toBeGreaterThanOrEqual(2);
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synthExec = events.find((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synthExec).toBeDefined();
      const raw = synthExec!['raw'] as Record<string, unknown>;
      expect(raw['pid']).toBe(101);
      expect(raw['argv0']).toBe('curl');
      expect(raw['envp_alloc_failed']).toBe(false);
      expect(synthExec!['pkg']).toBe('bypass-pkg@1.0.0');
    });

    it('does NOT emit syscall_bypass when shim exec count matches strace count', async () => {
      const proc = mockProcReader({
        102: {
          ppid: 1,
          env: {
            npm_package_name: 'happy-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Strace sees execve; shim sees a matching exec event for the same
      // pid.  The bookkeeping is per-pid counts, so this should NOT
      // synthesise any bypass entry.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 102,
          line: 'execve("/usr/bin/node", ["node", "-e", "1"], 0x1234 /* 0 vars */) = 0',
          source: 'strace',
        },
        {
          pid: 102,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/node',
            argv0: 'node',
            envp_alloc_failed: false,
            pid: 102,
            ts: 7777,
          }),
          source: 'shim',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synthExec = events.find((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synthExec).toBeUndefined();
    });

    it('emits N synthetic bypass events when strace count exceeds shim count by N', async () => {
      const proc = mockProcReader({
        103: {
          ppid: 1,
          env: {
            npm_package_name: 'multi-bypass-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // 3 strace execve, 1 shim exec → 2 synthetic bypass events.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 103,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "a"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
        {
          pid: 103,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/sh',
            argv0: 'sh',
            envp_alloc_failed: false,
            pid: 103,
            ts: 1,
          }),
          source: 'shim',
        },
        {
          pid: 103,
          line: 'execve("/usr/bin/curl", ["curl", "x"], 0x2 /* 0 vars */) = 0',
          source: 'strace',
        },
        {
          pid: 103,
          line: 'execve("/usr/bin/wget", ["wget", "y"], 0x3 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synthExecs = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synthExecs).toHaveLength(2);
      // The TAIL samples (most-recent execve calls on this pid) are the
      // ones surfaced: curl + wget.  The first sh exec matched the single
      // shim event.
      const argv0s = synthExecs
        .map((e) => ((e['raw'] as Record<string, unknown>)['argv0']) as string)
        .sort();
      expect(argv0s).toEqual(['curl', 'wget']);
    });

    it('failed execve (ENOENT) does NOT count toward the bypass delta', async () => {
      const proc = mockProcReader({
        104: {
          ppid: 1,
          env: {
            npm_package_name: 'enoent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // strace observes ENOENT execve (no exec actually happened); shim
      // also won't see one (no successful libc wrapper return).  The
      // bypass-count delta must therefore be 0.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 104,
          line:
            'execve("/usr/bin/missing", ["missing"], 0x1 /* 0 vars */) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synthExec = events.find((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synthExec).toBeUndefined();
    });

    it('syscall_bypass exec event renders to <SYSCALL_EXEC_BYPASS> in audit_bypass via normalize', async () => {
      // End-to-end through normalize.ts: the synthesised exec event with
      // syscall_bypass:true must land as `<SYSCALL_EXEC_BYPASS> …` under
      // audit_bypass.  This is the exact entry shape `findAuditBypass` in
      // src/action/diff.ts scans for.
      const ev: AttributedEvent = {
        raw: {
          kind: 'exec',
          prog: '/usr/bin/curl',
          argv0: 'curl',
          envp_alloc_failed: false,
          syscall_bypass: true,
          events_file_forgery: false,
          unresolved_path: false,
          result: 'ok',
          pid: 1,
          ts: 0,
        },
        pkg: 'bypass-pkg@1.0.0',
        lifecycle: 'postinstall',
      };
      const ctx: NormalizeContext = {
        roots: { repo: '/work', nodeModules: '/work/node_modules', home: '/root', tmp: '/tmp', cache: '/cache' },
        pkgDirs: new Map([['bypass-pkg@1.0.0', '/work/node_modules/bypass-pkg']]),
      };
      const out = normalize([ev], ctx);
      const block = out.get('bypass-pkg@1.0.0')!.lifecycle.postinstall!;
      expect(block.audit_bypass).toContain('<SYSCALL_EXEC_BYPASS> curl');
    });
  });

  // Audit-trust Finding 3 (2026-05-18) — bypass counting must NOT gate on
  // attribution.  The most damaging variant of the raw-syscall bypass is
  // `syscall(SYS_execve, ..., attacker_envp)`: the child runs WITHOUT
  // npm_package_name / npm_lifecycle_event in its environ, so
  // `Attribution.attribute` returns null, and the pre-fix code
  // `continue`'d before incrementing the per-pid strace exec counter.
  // The strace observation was thus silently dropped and the lockfile
  // looked clean.
  //
  // The fix has two halves: (a) count BEFORE the attribution gate, (b)
  // use a snapshot of the FIRST attribution success for that pid so
  // synthesised events still carry a meaningful pkg / lifecycle.
  describe('Finding 3 — bypass-count fires even when attribution returns null', () => {
    it('synthesises bypass entry for raw-execve child whose environ was scrubbed', async () => {
      // Pid 105 has NO env entries (the raw execve wiped the env), AND no
      // ppid mapping — Attribution will return null.  Before the fix the
      // bypass counter would `continue` past this strace observation and
      // emit no audit_bypass entry.  After the fix the synth event still
      // fires, attributed to "<unattributed>" so the lockfile diff still
      // contains a <SYSCALL_EXEC_BYPASS> entry the host can hard-fail on.
      const proc = mockProcReader({});
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 105,
          line: 'execve("/usr/bin/curl", ["curl", "https://evil"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synth = events.find((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synth).toBeDefined();
      const raw = synth!['raw'] as Record<string, unknown>;
      expect(raw['pid']).toBe(105);
      expect(raw['argv0']).toBe('curl');
      // pkg falls back to the "<unattributed>" sentinel when no prior
      // snapshot existed.  The audit_bypass entry must still appear in
      // the lockfile diff so findAuditBypass in src/action/diff.ts can
      // hard-fail the PR.
      expect(synth!['pkg']).toBe('<unattributed>');
    });

    it('reuses snapshot attribution from earlier shim event for later raw-execve from same pid', async () => {
      // The pid had a successful shim exec earlier (when env was still
      // intact) — we snapshot that attribution.  Then the script does
      // a raw syscall(SYS_execve) with a scrubbed envp.  Attribution
      // now returns null for the strace observation, but the bypass
      // detector must still fire with the snapshot's pkg, not the
      // <unattributed> sentinel.
      const proc = mockProcReader({
        // First call: env is intact (snapshot succeeds).
        // Subsequent calls go through the Attribution cache, so we
        // don't actually need to flip the env mid-test — the cache
        // captured the result already.
        201: {
          ppid: 1,
          env: {
            npm_package_name: 'snapshot-pkg',
            npm_package_version: '2.0.0',
            npm_lifecycle_event: 'install',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // First a shim event so the attribution succeeds (and the
        // snapshot is recorded).
        {
          pid: 201,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/node',
            argv0: 'node',
            envp_alloc_failed: false,
            pid: 201,
            ts: 1,
          }),
          source: 'shim',
        },
        // Then TWO strace execves on the same pid (only one shim
        // event was paired).  The unmatched one becomes the
        // synthesised bypass entry — attributed via the snapshot.
        {
          pid: 201,
          line: 'execve("/usr/bin/node", ["node", "-e", "1"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
        {
          pid: 201,
          line: 'execve("/usr/bin/curl", ["curl", "x"], 0x2 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(1);
      // The synth event must carry the snapshot's pkg, not <unattributed>.
      expect(synths[0]!['pkg']).toBe('snapshot-pkg@2.0.0');
      expect(synths[0]!['lifecycle']).toBe('install');
    });
  });

  // Audit-trust Finding (high, 2026-05-18) — shim exec events carry a
  // `result: 'ok' | 'failed'` field so the cross-check can ignore failed
  // wrapped execves when pairing against successful strace observations.
  //
  // The threat: the shim's pre-fix behaviour was to emit ONE event per
  // libc-exec call BEFORE forwarding to real_execve.  That meant a failed
  // `execve("/missing", argv, envp)` still contributed +1 to
  // `shimExecCountByPid`, while strace correctly recorded the failure
  // (result=-1 ENOENT) and contributed +0 to `straceExecsByPid`.  An
  // attacker could thus pad the shim count with N failed wrapped execves
  // and then perform N successful raw `syscall(SYS_execve, …)` calls
  // (which the shim never sees) — the cross-check delta was 0 and no
  // `<SYSCALL_EXEC_BYPASS>` was synthesised.
  //
  // Fix: the shim now emits a `result:'failed'` event AFTER real_execve
  // returns (which only happens on failure since success replaces the
  // image); for posix_spawn it emits a single event with the outcome
  // tagged.  The cross-check computes `okEvents - failedEvents` per pid
  // so failed-attempt libc wrappers cancel out, and only true successful
  // libc-wrapper exec calls contribute to the strace/shim pairing.
  describe('Finding — shim exec result field cancels failed wrapped execs', () => {
    it('failed wrapped execve + successful raw syscall in same pid → 1 bypass', async () => {
      const proc = mockProcReader({
        301: {
          ppid: 1,
          env: {
            npm_package_name: 'fail-pad-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Scenario: attacker calls execve("/missing") via libc — shim emits
      // result:'ok' pre-call and result:'failed' post-call (net 0).  Then
      // attacker issues a raw syscall(SYS_execve, "/usr/bin/node", …) —
      // strace observes one successful execve, shim sees nothing.
      // Cross-check: shimOkNet=0, straceOk=1 → 1 bypass synthesised.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 301,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: 'missing',
            envp_alloc_failed: false,
            result: 'ok',
            pid: 301,
            ts: 1,
          }),
          source: 'shim',
        },
        {
          pid: 301,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: 'missing',
            envp_alloc_failed: false,
            result: 'failed',
            pid: 301,
            ts: 2,
          }),
          source: 'shim',
        },
        {
          pid: 301,
          line: 'execve("/usr/bin/node", ["node", "-e", "evil()"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(1);
      const raw = synths[0]!['raw'] as Record<string, unknown>;
      expect(raw['argv0']).toBe('node');
      expect(synths[0]!['pkg']).toBe('fail-pad-pkg@1.0.0');
    });

    it('5 failed wrapped + 3 successful raw → 3 bypass entries', async () => {
      const proc = mockProcReader({
        302: {
          ppid: 1,
          env: {
            npm_package_name: 'multi-fail-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // 5 failed wrapped execves → 5 'ok' + 5 'failed' shim events (net 0).
      // 3 successful raw syscalls → 3 strace 'ok' observations, 0 shim.
      // Cross-check: 3 - 0 = 3 bypass entries.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
      for (let i = 0; i < 5; i++) {
        records.push({
          pid: 302,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: `attempt-${i}`,
            envp_alloc_failed: false,
            result: 'ok',
            pid: 302,
            ts: i * 2 + 1,
          }),
          source: 'shim',
        });
        records.push({
          pid: 302,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: `attempt-${i}`,
            envp_alloc_failed: false,
            result: 'failed',
            pid: 302,
            ts: i * 2 + 2,
          }),
          source: 'shim',
        });
      }
      const rawProgs = ['curl', 'wget', 'sh'];
      for (const argv0 of rawProgs) {
        records.push({
          pid: 302,
          line: `execve("/usr/bin/${argv0}", ["${argv0}", "x"], 0x1 /* 0 vars */) = 0`,
          source: 'strace',
        });
      }

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(3);
      const argv0s = synths
        .map((e) => ((e['raw'] as Record<string, unknown>)['argv0']) as string)
        .sort();
      expect(argv0s).toEqual(['curl', 'sh', 'wget']);
    });

    it('2 successful wrapped + 0 raw → 0 bypass entries', async () => {
      const proc = mockProcReader({
        303: {
          ppid: 1,
          env: {
            npm_package_name: 'happy-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // 2 successful wrapped execves → 2 shim 'ok' events, no 'failed'
      // (real_execve never returned because the image was replaced).
      // 2 strace 'ok' observations.  Cross-check: 2 - 2 = 0, no bypass.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 303,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/sh',
            argv0: 'sh',
            envp_alloc_failed: false,
            result: 'ok',
            pid: 303,
            ts: 1,
          }),
          source: 'shim',
        },
        {
          pid: 303,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "a"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
        {
          pid: 303,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/node',
            argv0: 'node',
            envp_alloc_failed: false,
            result: 'ok',
            pid: 303,
            ts: 2,
          }),
          source: 'shim',
        },
        {
          pid: 303,
          line: 'execve("/usr/bin/node", ["node", "-v"], 0x2 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    it('legacy shim events without result field default to ok', async () => {
      // Backwards-compat check: an older shim build (or any test fixture
      // that doesn't include `result`) should still cross-check correctly
      // — the zod default makes the missing field equivalent to
      // `result:'ok'`, so a single legacy shim event + a single strace
      // execve still pairs to 0 bypasses.
      const proc = mockProcReader({
        304: {
          ppid: 1,
          env: {
            npm_package_name: 'legacy-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 304,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/node',
            argv0: 'node',
            envp_alloc_failed: false,
            // No `result` field — legacy shim build.
            pid: 304,
            ts: 1,
          }),
          source: 'shim',
        },
        {
          pid: 304,
          line: 'execve("/usr/bin/node", ["node", "-v"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(0);
    });
  });

  // Audit-trust Finding C (medium, 2026-05-18) — standalone failed shim
  // exec events (no paired optimistic 'ok' on the same pid) drive the
  // per-pid net counter NEGATIVE.  A subsequent legitimate wrapped exec
  // from the same pid then incorrectly produces
  // `straceCount - shimNet > 0` and a spurious `<SYSCALL_EXEC_BYPASS>`
  // entry — a false positive that would hard-fail clean installs.
  //
  // Fix: clamp the net at zero before the strace comparison.  The
  // invariant being enforced is "every successful strace execve has a
  // matching successful shim wrapper event"; an unbounded NEGATIVE
  // delta has no semantic content and must not contribute to the
  // bypass count.
  describe('Finding C — clamp shim-exec delta at zero', () => {
    it('1 standalone failed posix_spawn + 1 successful wrapped exec → 0 bypass entries', async () => {
      const proc = mockProcReader({
        401: {
          ppid: 1,
          env: {
            npm_package_name: 'clamp-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Pre-fix: shim emits a `result:'failed'` event for the
      // standalone posix_spawn rc!=0 with no prior optimistic 'ok',
      // driving the per-pid net to -1.  A subsequent legitimate
      // wrapped exec emits a pre-call 'ok' (raising net to 0); strace
      // also observes the successful execve (straceCount=1).  The
      // post-loop `straceCount > shimCount` test then yields 1 > 0
      // → 1 spurious `<SYSCALL_EXEC_BYPASS>` entry against a clean
      // install.
      //
      // Post-fix: the dispatcher's per-event saturating subtraction
      // clamps the failed-delta at the floor 0, so the standalone
      // failed event leaves the counter at 0, the subsequent 'ok'
      // raises it to 1, and `straceCount > shimCount` yields 1 > 1
      // → no bypass synthesised.  The shim's libc-wrapper net
      // correctly reflects "1 successful libc exec", matching the
      // single strace observation.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Standalone failed posix_spawn (rc!=0 — no child created, no
        // strace pair).  Shim emits a single failed event with no
        // prior optimistic 'ok'.
        {
          pid: 401,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: 'missing',
            envp_alloc_failed: false,
            result: 'failed',
            pid: 401,
            ts: 1,
          }),
          source: 'shim',
        },
        // Then a legitimate wrapped exec on the same pid.  Shim emits
        // pre-call 'ok'; post-call 'failed' does NOT fire because the
        // exec succeeded.  Strace observes one successful execve.
        {
          pid: 401,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/usr/bin/node',
            argv0: 'node',
            envp_alloc_failed: false,
            result: 'ok',
            pid: 401,
            ts: 2,
          }),
          source: 'shim',
        },
        {
          pid: 401,
          line: 'execve("/usr/bin/node", ["node", "build.js"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    it('3 standalone failures + 1 successful wrapped exec → 0 bypass entries', async () => {
      const proc = mockProcReader({
        402: {
          ppid: 1,
          env: {
            npm_package_name: 'multi-clamp-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
      for (let i = 0; i < 3; i++) {
        // Each standalone failed posix_spawn has no paired 'ok'.
        records.push({
          pid: 402,
          line: JSON.stringify({
            kind: 'exec',
            prog: '/missing',
            argv0: `attempt-${i}`,
            envp_alloc_failed: false,
            result: 'failed',
            pid: 402,
            ts: i + 1,
          }),
          source: 'shim',
        });
      }
      // One legitimate wrapped exec — emits a single 'ok' event.
      records.push({
        pid: 402,
        line: JSON.stringify({
          kind: 'exec',
          prog: '/usr/bin/sh',
          argv0: 'sh',
          envp_alloc_failed: false,
          result: 'ok',
          pid: 402,
          ts: 10,
        }),
        source: 'shim',
      });
      // Strace sees one successful execve on the same pid.
      records.push({
        pid: 402,
        line: 'execve("/usr/bin/sh", ["sh", "-c", "echo ok"], 0x1 /* 0 vars */) = 0',
        source: 'strace',
      });

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    it('regression: 0 shim events + 1 strace execve → 1 bypass entry', async () => {
      const proc = mockProcReader({
        403: {
          ppid: 1,
          env: {
            npm_package_name: 'pure-bypass-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 403,
          line: 'execve("/usr/bin/curl", ["curl", "evil"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: BASE_ENV,
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(synths).toHaveLength(1);
    });
  });

  // Audit-trust Finding A (high, 2026-05-18) — events-file write forgery
  // detection.  A lifecycle script that issues a raw-syscall exec with
  // a scrubbed envp will not have ld.so map `/lib/libscriptjail.so`
  // into the child process; so the child is NOT in the trusted writer
  // set and any openat-write of `SCRIPT_JAIL_LOG_FILE` from that pid
  // is forgery.  We surface the attempt as `<EVENTS_FILE_FORGERY>`
  // under audit_bypass so findAuditBypass hard-fails the lockfile.
  describe('Finding A — events-file write forgery detection', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';
    const SHIM_PATH = '/lib/libscriptjail.so';

    it('non-shim-loaded pid opens events file for write → 1 forgery entry', async () => {
      const proc = mockProcReader({
        501: {
          ppid: 1,
          env: {
            npm_package_name: 'forge-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Pid 501 never opens libscriptjail.so (raw-syscall exec
      // bypassed ld.so), then attempts to openat the events file for
      // write to inject a forged JSONL line.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 501,
          line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(1);
      const raw = synths[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe(EVENTS_FILE);
      expect(synths[0]!['pkg']).toBe('forge-pkg@1.0.0');
    });

    it('shim-loaded pid opens events file for write → 0 forgery entries (legitimate)', async () => {
      const proc = mockProcReader({
        502: {
          ppid: 1,
          env: {
            npm_package_name: 'shim-loaded-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Pid 502 first opens libscriptjail.so (ld.so does this on
      // every LD_PRELOAD-honoured process startup), then the shim's
      // shim_init opens the events file for write.  This is the
      // legitimate flow — no forgery entry.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 502,
          line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
          source: 'strace',
        },
        {
          pid: 502,
          line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    it('forgery + raw-syscall exec on same pid → both audit_bypass entries', async () => {
      const proc = mockProcReader({
        503: {
          ppid: 1,
          env: {
            npm_package_name: 'combined-attack-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // Pid 503 issued a raw `syscall(SYS_execve, …)` with scrubbed
      // envp (ld.so never loaded the shim) AND attempted to forge a
      // shim event by writing to the events file.  Both signals must
      // surface so findAuditBypass hard-fails.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 503,
          line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
          source: 'strace',
        },
        {
          pid: 503,
          line: 'execve("/usr/bin/curl", ["curl", "evil"], 0x1 /* 0 vars */) = 0',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const forgeries = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      const syscallBypasses = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['syscall_bypass'] === true;
      });
      expect(forgeries).toHaveLength(1);
      expect(syscallBypasses).toHaveLength(1);
    });

    // Audit-trust Finding 2 (high, 2026-05-18): path-alias forgery —
    // a `..`/`.` or extra-slash spelling of the events file path that
    // path.resolve collapses to the canonical form.  Exact-string
    // comparison would miss these; canonicalization catches them.
    it('path-alias forgery (dot-dot, dot, extra slash) is caught via canonicalization', async () => {
      const proc = mockProcReader({
        511: {
          ppid: 1,
          env: {
            npm_package_name: 'alias-forge-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      // Same canonical path as EVENTS_FILE, but spelled differently.
      // path.resolve('/tmp/foo/../script-jail-events/./events.jsonl')
      // collapses to '/tmp/script-jail-events/events.jsonl'.
      const ALIASED = '/tmp/foo/../script-jail-events/./events.jsonl';
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 511,
          line: `openat(AT_FDCWD, "${ALIASED}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(1);
      const raw = synths[0]!['raw'] as Record<string, unknown>;
      // The forensic prog is the canonical resolved path, not the aliased form.
      expect(raw['prog']).toBe(EVENTS_FILE);
    });

    // Audit-trust Finding 2: dirfd-relative open of the events file —
    // open the parent directory, then openat(<dirfd>, "events.jsonl",
    // O_WRONLY|O_APPEND).  The dirfd→path table built from the prior
    // openat must resolve the relative path to the canonical events
    // file path.
    it('dirfd-relative forgery via openat(<dirfd>, "events.jsonl") is caught', async () => {
      const proc = mockProcReader({
        512: {
          ppid: 1,
          env: {
            npm_package_name: 'dirfd-forge-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });

      // EVENTS_FILE is '/tmp/script-jail-events/events.jsonl'; the parent
      // dir is '/tmp/script-jail-events'.  Pid 512 opens that dir → fd 9,
      // then `openat(9, "events.jsonl", O_WRONLY|O_APPEND) = 10`.
      const EVENTS_DIR = '/tmp/script-jail-events';
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 512,
          line: `openat(AT_FDCWD, "${EVENTS_DIR}", O_RDONLY|O_DIRECTORY) = 9`,
          source: 'strace',
        },
        {
          pid: 512,
          line: 'openat(9, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 10',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(1);
      const raw = synths[0]!['raw'] as Record<string, unknown>;
      // The forensic prog carries the canonical absolute events file path.
      expect(raw['prog']).toBe(EVENTS_FILE);
    });

    // Audit-trust Finding 2: dirfd-relative open of an UNRELATED file
    // (not the events file) must NOT be flagged as forgery.
    it('dirfd-relative open of unrelated file → 0 forgery entries', async () => {
      const proc = mockProcReader({
        513: {
          ppid: 1,
          env: {
            npm_package_name: 'innocent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 513,
          line: 'openat(AT_FDCWD, "/work", O_RDONLY|O_DIRECTORY) = 9',
          source: 'strace',
        },
        {
          pid: 513,
          line: 'openat(9, "build.log", O_WRONLY|O_APPEND|O_CREAT, 0644) = 10',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    // Audit-trust Finding (high, 2026-05-19): dirfd whose source we never
    // observed (e.g. inherited across exec, or strace -ff dropped a line),
    // BUT the relative path basename matches the events file basename →
    // we DO flag forgery via the Layer-1 basename safety net.
    //
    // The previous behaviour ("conservative drop") was the pre-fix gap:
    // a non-shim-loaded pid that wrote to ANY file with basename
    // `events.jsonl` could escape detection if strace -ff missed the
    // dirfd's source line.  In the controlled microVM rootfs the
    // basename `events.jsonl` is unique to this audit channel; there
    // is no legitimate reason for a lifecycle script to write to it.
    it('dirfd whose openat source is missing but basename matches → forgery (Layer-1 safety net)', async () => {
      const proc = mockProcReader({
        514: {
          ppid: 1,
          env: {
            npm_package_name: 'orphan-dirfd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // No prior openat for fd 9 on this pid.  Canonical resolution
        // fails — but the basename "events.jsonl" matches the events
        // file basename, so the Layer-1 safety net flags it.
        {
          pid: 514,
          line: 'openat(9, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 10',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(1);
      const raw = synths[0]!['raw'] as Record<string, unknown>;
      // The forensic prog falls back to the canonical events file path
      // since canonical resolution failed for the dirfd-relative open.
      expect(raw['prog']).toBe(EVENTS_FILE);
    });

    // Defence-in-depth: a dirfd-relative open whose basename does NOT
    // match the events file basename and whose source is missing must
    // NOT be flagged.  This preserves the original conservative drop
    // for unrelated orphan-dirfd opens.
    it('dirfd whose openat source is missing AND basename does not match → no forgery', async () => {
      const proc = mockProcReader({
        515: {
          ppid: 1,
          env: {
            npm_package_name: 'innocent-orphan-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 515,
          line: 'openat(9, "build.log", O_WRONLY|O_APPEND|O_CREAT, 0644) = 10',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const synths = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
      });
      expect(synths).toHaveLength(0);
    });

    // Audit-trust Finding (high, 2026-05-19) — cwd-relative openat forgery.
    // A non-shim-loaded attacker pid can:
    //   1. chdir(events-dir)
    //   2. openat(AT_FDCWD, "events.jsonl", O_APPEND|O_WRONLY)
    // The strace line for step 2 is
    //   `openat(AT_FDCWD, "events.jsonl", O_APPEND|O_WRONLY) = N`
    // Pre-fix, `path.resolve("events.jsonl")` resolved against the AGENT
    // process's cwd (not the attacker's), producing a path that did NOT
    // equal `eventsFilePathCanonical` — silently dropping the forgery
    // signal.  With chdir/fchdir tracking + basename safety net we now
    // catch this.
    describe('cwd-relative openat forgery (Finding, 2026-05-19)', () => {
      it('chdir(events-dir) + openat(AT_FDCWD, "events.jsonl") from non-shim-loaded pid → forgery (Layer 2)', async () => {
        const proc = mockProcReader({
          601: {
            ppid: 1,
            env: {
              npm_package_name: 'cwd-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 601,
            line: 'chdir("/tmp/script-jail-events") = 0',
            source: 'strace',
          },
          {
            pid: 601,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(1);
        const raw = synths[0]!['raw'] as Record<string, unknown>;
        // Layer-2 canonical resolution succeeds: chdir('/tmp/script-jail-events')
        // + openat(AT_FDCWD, "events.jsonl") resolves to EVENTS_FILE.
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('chdir(events-dir) + openat(AT_FDCWD, "events.jsonl") from shim-loaded pid → no forgery', async () => {
        const proc = mockProcReader({
          602: {
            ppid: 1,
            env: {
              npm_package_name: 'cwd-shim-loaded-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // Pid 602 is shim-loaded — it legitimately wrote to the events
        // file via the shim_init code path.  Even if it chdir'd to the
        // events directory beforehand, we trust it.  This pins the
        // same-UID gap documented in docs/architecture.md.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 602,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 602,
            line: 'chdir("/tmp/script-jail-events") = 0',
            source: 'strace',
          },
          {
            pid: 602,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(0);
      });

      it('legitimate cwd-relative open of unrelated file → no forgery', async () => {
        const proc = mockProcReader({
          603: {
            ppid: 1,
            env: {
              npm_package_name: 'cwd-innocent-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // chdir to some build dir then write a build log via a
        // relative path.  Different basename, must not flag forgery.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 603,
            line: 'chdir("/tmp/build") = 0',
            source: 'strace',
          },
          {
            pid: 603,
            line: 'openat(AT_FDCWD, "./tmp/some-other-file.jsonl", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(0);
      });

      it('cwd-relative open with no chdir but basename matches → forgery via Layer-1 basename match', async () => {
        const proc = mockProcReader({
          // Codex follow-up #1 (2026-05-19): a dummy first observed
          // event from pid 0 (a sentinel pid that has no proc entry)
          // burns the install-root-seeded flag so pid 604 in this
          // test scenario does NOT inherit `input.cwd` from the
          // install-root seeding path.  Without this, pid 604 would
          // be the first observed pid → pidCwd[604]=/work → canonical
          // resolution succeeds with /work/events.jsonl, which is
          // still Layer-1 flagged (basename matches) but the
          // forensic forgery path would be the resolved /work path
          // rather than the canonical EVENTS_FILE.  The test wants
          // to exercise the *Layer-1 fallback* path where canonical
          // resolution returns null.
          604: {
            ppid: 1,
            env: {
              npm_package_name: 'cwd-no-chdir-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // No chdir line.  The agent has no pidCwd entry for this pid,
        // so canonical resolution returns null.  Layer-1 basename
        // safety net catches the open.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          // Burn the install-root-seeded flag with a benign
          // observation on a different pid (the simulated install
          // root) so pid 604 reaches the dispatcher WITHOUT being
          // seeded.  See the comment above.
          {
            pid: 1,
            line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
            source: 'strace',
          },
          {
            pid: 604,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(1);
        const raw = synths[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('fchdir(<events-dirfd>) + openat(AT_FDCWD, "events.jsonl") from non-shim-loaded pid → forgery (Layer 2 via fchdir)', async () => {
        const proc = mockProcReader({
          605: {
            ppid: 1,
            env: {
              npm_package_name: 'fchdir-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // Open the events dir to get a dirfd, fchdir to it, then open
        // the relative path.  pidCwd should resolve correctly via the
        // dirfdTable lookup driven by the openat retFd.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 605,
            line: 'openat(AT_FDCWD, "/tmp/script-jail-events", O_RDONLY|O_DIRECTORY) = 9',
            source: 'strace',
          },
          {
            pid: 605,
            line: 'fchdir(9) = 0',
            source: 'strace',
          },
          {
            pid: 605,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 10',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(1);
        const raw = synths[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });
    });

    // Audit-trust Finding (medium, 2026-05-19) — per-run random basename
    // eliminates Layer-1 false positives.  The Layer-1 safety net flags
    // any non-shim-loaded openat-write whose target basename equals the
    // events file basename.  With the pre-fix generic basename
    // `events.jsonl`, a legitimate package that writes `./events.jsonl`
    // to its own cwd would falsely trip Layer 1.  After the fix, the
    // events file basename is `events-<32-hex>.jsonl` (minted per VM run
    // in `createEventsFile`), so:
    //   - a package writing the generic `events.jsonl` no longer matches
    //     and is NOT flagged (false-positive gone);
    //   - a package that writes the actual per-run-random basename in a
    //     wrong directory IS still flagged via Layer 1 (the basename is
    //     unguessable, so the only way to hit it is by reading
    //     SCRIPT_JAIL_LOG_FILE — i.e. genuine attacker behaviour).
    describe('per-run random basename eliminates Layer-1 false positives (Finding, 2026-05-19)', () => {
      // Per-run-random basename, as `createEventsFile` would produce
      // (events-<32-hex>.jsonl).  The exact hex value is irrelevant —
      // what matters is that it differs from the generic `events.jsonl`
      // a package might legitimately write.
      const RANDOM_TAG = 'a'.repeat(32);
      const RANDOM_EVENTS_FILE = `/tmp/script-jail-events-${RANDOM_TAG}/events-${RANDOM_TAG}.jsonl`;

      it('non-shim-loaded pid writes generic ./events.jsonl with no chdir → NOT flagged (false-positive fix)', async () => {
        const proc = mockProcReader({
          801: {
            ppid: 1,
            env: {
              npm_package_name: 'innocent-generic-events-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // The package writes a file literally named `events.jsonl`
        // in its own cwd via AT_FDCWD-relative openat.  Pre-fix this
        // matched the Layer-1 safety net (basename == 'events.jsonl')
        // even though the canonical target is nowhere near the audit
        // events file.  Post-fix, the events file basename is
        // `events-<tag>.jsonl`, so the generic name no longer collides.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 801,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: RANDOM_EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(0);
      });

      it('non-shim-loaded pid writes the actual per-run-random basename in a wrong directory → flagged via Layer 1', async () => {
        const proc = mockProcReader({
          802: {
            ppid: 1,
            env: {
              npm_package_name: 'random-basename-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // Attacker scraped SCRIPT_JAIL_LOG_FILE from /proc/self/environ
        // and now knows the per-run-random basename.  They open it from
        // a *different* directory (no chdir) — canonical resolution
        // returns a path that doesn't equal the canonical events file,
        // but Layer 1 still catches it because the basename matches the
        // unguessable random tag.
        //
        // Codex follow-up #1 (2026-05-19): a benign first event on a
        // different pid burns the install-root-seeded flag so pid 802
        // doesn't get pidCwd=/work via that path — canonical
        // resolution must return null for the Layer-1 fallback test
        // to be meaningful.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 1,
            line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
            source: 'strace',
          },
          {
            pid: 802,
            line: `openat(AT_FDCWD, "events-${RANDOM_TAG}.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: RANDOM_EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const synths = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(synths).toHaveLength(1);
        const raw = synths[0]!['raw'] as Record<string, unknown>;
        // Forensic path falls back to the canonical events file path
        // because canonical resolution of the relative path against
        // the agent's cwd does NOT produce the configured events file
        // (the package is in a different directory).
        expect(raw['prog']).toBe(RANDOM_EVENTS_FILE);
      });
    });

    // Audit-trust Finding (high, 2026-05-19) — shim-trust must NOT survive
    // exec image replacement.  A pid becomes shim-trusted when ld.so maps
    // `/lib/libscriptjail.so` into the ORIGINAL process image.  A
    // subsequent successful execve replaces the address space; unless the
    // new image is also LD_PRELOADed (which produces a fresh openat of
    // libscriptjail.so), the new image is unshimmed.  Without clearing
    // the trust bit on the exec syscall, the new (unshimmed) image
    // remains exempt from the events-file forgery detector — letting
    // the attacker forge JSONL into the trusted channel from a
    // post-exec image.
    describe('shim-trust cleared on successful exec (Finding, 2026-05-19)', () => {
      it('pid loads shim, then execve to /bin/sh, then writes events file → forgery flagged', async () => {
        const proc = mockProcReader({
          701: {
            ppid: 1,
            env: {
              npm_package_name: 'exec-trust-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // 1. Pid 701 ld.so loads libscriptjail.so → shim-trusted.
        // 2. Pid 701 successful execve to /bin/sh → trust cleared.
        // 3. Pid 701 (now unshimmed; no fresh shim openat after exec)
        //    writes events file → flagged as forgery.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 701,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 701,
            line: 'execve("/bin/sh", ["sh"], 0x7ffd... /* 0 vars */) = 0',
            source: 'strace',
          },
          {
            pid: 701,
            line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
      });

      it('shim re-loaded after exec → trust re-established → no forgery', async () => {
        const proc = mockProcReader({
          702: {
            ppid: 1,
            env: {
              npm_package_name: 'shim-reloaded-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // A legitimate exec where the new image is ALSO LD_PRELOADed
        // (LD_PRELOAD survives the exec via the inherited env, and ld.so
        // re-maps libscriptjail.so into the new image — producing a
        // fresh openat line).  No forgery: trust is cleared on the
        // exec and immediately re-granted by the new openat.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 702,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 702,
            line: 'execve("/usr/bin/node", ["node", "install.js"], 0x7ffd... /* 38 vars */) = 0',
            source: 'strace',
          },
          {
            pid: 702,
            // ld.so in the new image re-maps the shim — trust restored.
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 702,
            line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(0);
      });

      it('failed execve does NOT clear trust (no image replacement)', async () => {
        const proc = mockProcReader({
          703: {
            ppid: 1,
            env: {
              npm_package_name: 'failed-exec-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // execve that returns -1 ENOENT does NOT replace the address
        // space, so the shim mapping is still in place and trust should
        // remain.  Only `result === 'ok'` spawns clear trust.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 703,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 703,
            line: 'execve("/no/such/bin", ["x"], 0x7ffd...) = -1 ENOENT (No such file or directory)',
            source: 'strace',
          },
          {
            pid: 703,
            line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(0);
      });

      it('execveat (successful) also clears trust (not just execve)', async () => {
        const proc = mockProcReader({
          704: {
            ppid: 1,
            env: {
              npm_package_name: 'execveat-trust-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // Same threat as execve: an attacker pid that was shim-trusted
        // issues a raw `syscall(SYS_execveat, ...)` to swap to an
        // unshimmed image, then forges into the events file.  The
        // dispatcher must treat the resulting spawn event identically
        // to execve and clear trust.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 704,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 704,
            line: 'execveat(AT_FDCWD, "/bin/sh", ["sh"], 0x7ffd... /* 0 vars */, 0) = 0',
            source: 'strace',
          },
          {
            pid: 704,
            line: `openat(AT_FDCWD, "${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
      });

      it('pidCwd survives execve (cwd is preserved across image replacement)', async () => {
        const proc = mockProcReader({
          705: {
            ppid: 1,
            env: {
              npm_package_name: 'cwd-survives-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // chdir(events-dir) sets the kernel cwd.  execve preserves the
        // cwd (per execve(2)).  After the successful exec, the
        // post-exec image is unshimmed (trust cleared) AND can use the
        // inherited cwd to issue a cwd-relative openat that the
        // canonicalizer resolves to the canonical events path — so
        // Layer 2 still catches the forgery.  If we cleared pidCwd on
        // exec we'd miss this and only Layer 1 (basename) would catch
        // it; this test pins that pidCwd is intentionally preserved.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 705,
            line: `openat(AT_FDCWD, "${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 705,
            line: 'chdir("/tmp/script-jail-events") = 0',
            source: 'strace',
          },
          {
            pid: 705,
            line: 'execve("/bin/sh", ["sh"], 0x7ffd... /* 0 vars */) = 0',
            source: 'strace',
          },
          {
            pid: 705,
            line: 'openat(AT_FDCWD, "events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        // Layer 2 (canonical) resolved via inherited cwd → canonical events path.
        expect(raw['prog']).toBe(EVENTS_FILE);
      });
    });

    // Audit-trust Finding (high, 2026-05-19) — openat2 (Linux 5.6+) forgery.
    // A raw `syscall(SYS_openat2, ...)` would previously slip past both
    // the strace `-e trace=` filter AND the parser dispatch.  These tests
    // pin the full path: agent traces openat2, parser emits a write event,
    // forgery detector flags it the same way it flags openat.
    describe('openat2 forgery detection (Finding, 2026-05-19)', () => {
      it('absolute-path openat2 write from non-shim-loaded pid → forgery', async () => {
        const proc = mockProcReader({
          801: {
            ppid: 1,
            env: {
              npm_package_name: 'openat2-abs-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 801,
            line: `openat2(AT_FDCWD, "${EVENTS_FILE}", {flags=O_WRONLY|O_APPEND|O_CREAT, mode=0644, resolve=0x0}, 24) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('cwd-relative openat2 write after chdir(events-dir) from non-shim-loaded pid → forgery (Layer 2)', async () => {
        const proc = mockProcReader({
          802: {
            ppid: 1,
            env: {
              npm_package_name: 'openat2-cwd-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 802,
            line: 'chdir("/tmp/script-jail-events") = 0',
            source: 'strace',
          },
          {
            pid: 802,
            line: 'openat2(AT_FDCWD, "events.jsonl", {flags=O_WRONLY|O_APPEND|O_CREAT, mode=0644, resolve=0x0}, 24) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('dirfd-relative openat2 write via openat2(<events-dir-fd>, "events.jsonl", ...) → forgery', async () => {
        const proc = mockProcReader({
          803: {
            ppid: 1,
            env: {
              npm_package_name: 'openat2-dirfd-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const EVENTS_DIR = '/tmp/script-jail-events';
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 803,
            line: `openat2(AT_FDCWD, "${EVENTS_DIR}", {flags=O_RDONLY|O_DIRECTORY, mode=0, resolve=0x0}, 24) = 9`,
            source: 'strace',
          },
          {
            pid: 803,
            line: 'openat2(9, "events.jsonl", {flags=O_WRONLY|O_APPEND|O_CREAT, mode=0644, resolve=0x0}, 24) = 10',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('openat2 of /lib/libscriptjail.so grants shim-trust just like openat', async () => {
        // Defence in depth: ld.so on a system that prefers openat2 (Linux
        // 5.6+ with glibc 2.36+) would map the shim via openat2 instead
        // of openat.  The shim-trust set must include the pid in either
        // case — otherwise legitimate writes by shim_init would be
        // flagged as forgery.
        const proc = mockProcReader({
          804: {
            ppid: 1,
            env: {
              npm_package_name: 'openat2-shim-loaded-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 804,
            line: `openat2(AT_FDCWD, "${SHIM_PATH}", {flags=O_RDONLY|O_CLOEXEC, mode=0, resolve=0x0}, 24) = 3`,
            source: 'strace',
          },
          {
            pid: 804,
            line: `openat2(AT_FDCWD, "${EVENTS_FILE}", {flags=O_WRONLY|O_APPEND|O_CREAT, mode=0644, resolve=0x0}, 24) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(0);
      });
    });

    // Audit-trust Finding (high, 2026-05-19) — legacy `open` / `creat`
    // forgery.  A raw `syscall(SYS_open, "/tmp/.../events.jsonl",
    // O_WRONLY|O_APPEND)` or `syscall(SYS_creat, path, mode)` would
    // previously slip past both the strace `-e trace=` filter AND the
    // parser dispatch.  These tests pin the full path: agent traces
    // open/creat, parser emits a write event, forgery detector flags
    // it the same way it flags openat.
    describe('legacy open/creat forgery detection (Finding, 2026-05-19)', () => {
      it('absolute-path legacy open write from non-shim-loaded pid → forgery', async () => {
        const proc = mockProcReader({
          901: {
            ppid: 1,
            env: {
              npm_package_name: 'legacy-open-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 901,
            line: `open("${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('absolute-path legacy creat from non-shim-loaded pid → forgery', async () => {
        const proc = mockProcReader({
          902: {
            ppid: 1,
            env: {
              npm_package_name: 'legacy-creat-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        // creat(path, mode) is equivalent to open(path, O_WRONLY|O_CREAT|
        // O_TRUNC, mode) — always a write.  parseCreat unconditionally
        // emits a write event so the forgery detector flags it.
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 902,
            line: `creat("${EVENTS_FILE}", 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('cwd-relative legacy open write after chdir(events-dir) from non-shim-loaded pid → forgery (Layer 2)', async () => {
        const proc = mockProcReader({
          903: {
            ppid: 1,
            env: {
              npm_package_name: 'legacy-open-cwd-forge-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 903,
            line: 'chdir("/tmp/script-jail-events") = 0',
            source: 'strace',
          },
          {
            pid: 903,
            line: 'open("events.jsonl", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7',
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(1);
        const raw = forgeries[0]!['raw'] as Record<string, unknown>;
        expect(raw['prog']).toBe(EVENTS_FILE);
      });

      it('legacy open of /lib/libscriptjail.so grants shim-trust just like openat', async () => {
        // Defence in depth: a pid that reads the shim via legacy open
        // (rather than openat) must still be admitted to the trusted
        // writer set; otherwise legitimate writes would be flagged as
        // forgery.  This pins the parser → forgery-detector contract:
        // parseOpen emits a `read` RawEvent with `path === SHIM_PATH`,
        // and the same shimLoadedPids grant arm in phase-install
        // applies.
        const proc = mockProcReader({
          904: {
            ppid: 1,
            env: {
              npm_package_name: 'legacy-shim-loaded-pkg',
              npm_package_version: '1.0.0',
              npm_lifecycle_event: 'postinstall',
            },
          },
        });
        const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
          {
            pid: 904,
            line: `open("${SHIM_PATH}", O_RDONLY|O_CLOEXEC) = 3`,
            source: 'strace',
          },
          {
            pid: 904,
            line: `open("${EVENTS_FILE}", O_WRONLY|O_APPEND|O_CREAT, 0644) = 7`,
            source: 'strace',
          },
        ];

        const { emitter, lines } = makeEmitter();
        await runInstallPhase({
          manager: 'npm',
          cwd: '/work',
          env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
          strace: cannedStraceRunner(records),
          attribution: new Attribution(proc),
          emitter,
        });

        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        const forgeries = events.filter((e) => {
          const raw = e['raw'] as Record<string, unknown>;
          return raw['kind'] === 'exec' && raw['events_file_forgery'] === true;
        });
        expect(forgeries).toHaveLength(0);
      });
    });

    it('events_file_forgery renders to <EVENTS_FILE_FORGERY> in audit_bypass via normalize', async () => {
      const ev: AttributedEvent = {
        raw: {
          kind: 'exec',
          prog: EVENTS_FILE,
          argv0: EVENTS_FILE,
          envp_alloc_failed: false,
          syscall_bypass: false,
          events_file_forgery: true,
          unresolved_path: false,
          result: 'ok',
          pid: 1,
          ts: 0,
        },
        pkg: 'forge-pkg@1.0.0',
        lifecycle: 'postinstall',
      };
      const ctx: NormalizeContext = {
        roots: {
          repo: '/work',
          nodeModules: '/work/node_modules',
          home: '/root',
          tmp: '/tmp',
          cache: '/cache',
        },
        pkgDirs: new Map([['forge-pkg@1.0.0', '/work/node_modules/forge-pkg']]),
      };
      const out = normalize([ev], ctx);
      const block = out.get('forge-pkg@1.0.0')!.lifecycle.postinstall!;
      expect(block.audit_bypass.some((e) => e.startsWith('<EVENTS_FILE_FORGERY>'))).toBe(true);
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

  // Audit-trust Finding (high, 2026-05-19) — dirfd/cwd-relative path
  // resolution before emit.  Pre-fix, strace-parsed openat events with
  // a numeric dirfd or AT_FDCWD-relative path were emitted with the
  // LITERAL relative `path` field; the protected-paths matcher and
  // cross-package matcher then saw the relative form and bypassed
  // their checks.
  //
  // The fix canonicalizes the path via the dirfd table + per-pid cwd
  // BEFORE applyProtectedPathsPolicy and emit.  When resolution
  // succeeds, the absolute path replaces the relative one.  When
  // resolution fails (numeric dirfd we never observed), we fail
  // closed: the raw event is dropped and a synthetic `<UNRESOLVED_PATH>`
  // audit_bypass entry is surfaced so `findAuditBypass` in
  // src/action/diff.ts hard-fails the lockfile diff.
  //
  // For AT_FDCWD-relative opens, the canonicalizer falls back to
  // `input.cwd` when no explicit chdir was observed (covers the
  // common case of the install command itself + its children that
  // never chdir'd).
  describe('dirfd/cwd-relative path resolved before emit (Finding, 2026-05-19)', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Case 1: dirfd-relative write inside the package.  The package
    // helper opens its own directory (giving a numeric dirfd), then
    // writes to `build.log` via openat(<pkg-dirfd>, "build.log", …).
    // The emitted fs.write event MUST have an absolute path
    // ($PKG/build.log) — NOT the relative form — so the
    // cross-package matcher in normalize.ts doesn't false-positive on
    // the package's own intra-dir write.
    it('dirfd-relative write inside package dir → absolute path emitted (no false escaped_write)', async () => {
      const proc = mockProcReader({
        901: {
          ppid: 1,
          env: {
            npm_package_name: 'helper-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const PKG_DIR = '/work/node_modules/helper-pkg';
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Pkg helper opens its own dir → fd 12.
        {
          pid: 901,
          line: `openat(AT_FDCWD, "${PKG_DIR}", O_RDONLY|O_DIRECTORY) = 12`,
          source: 'strace',
        },
        // Pkg helper writes build.log via the dirfd.
        {
          pid: 901,
          line: 'openat(12, "build.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 13',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // We expect two write events: the dir open (read) and the build.log write.
      const writes = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'write';
      });
      expect(writes).toHaveLength(1);
      const raw = writes[0]!['raw'] as Record<string, unknown>;
      // Resolved to absolute path, not the literal "build.log".
      expect(raw['path']).toBe(`${PKG_DIR}/build.log`);
      // No <UNRESOLVED_PATH> audit_bypass entry for this legitimate write.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Case 2: AT_FDCWD-relative read of a protected file after chdir.
    // Pre-fix, `openat(AT_FDCWD, ".ssh/id_rsa", …)` was emitted with
    // path=".ssh/id_rsa" and the protected-paths matcher
    // (`$HOME/.ssh/**`) couldn't match the relative form — the probe
    // leaked past the hidden/drop logic.  With chdir tracking + cwd
    // resolution, the event now carries `/root/.ssh/id_rsa` so the
    // matcher fires and marks the read hidden.
    it('AT_FDCWD-relative protected probe after chdir($HOME) → resolved, hidden=true', async () => {
      const proc = mockProcReader({
        902: {
          ppid: 1,
          env: {
            npm_package_name: 'probe-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 902,
          line: 'chdir("/root") = 0',
          source: 'strace',
        },
        {
          pid: 902,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read';
      });
      expect(reads).toHaveLength(1);
      const raw = reads[0]!['raw'] as Record<string, unknown>;
      // Path resolved to absolute via pidCwd table populated by chdir.
      expect(raw['path']).toBe('/root/.ssh/id_rsa');
      // Protected-paths matcher saw the absolute form and marked it hidden.
      expect(raw['hidden']).toBe(true);
      // No <UNRESOLVED_PATH> for this — chdir was observed, cwd is tracked.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Case 3: dirfd-relative open with an UNRESOLVABLE dirfd (we
    // never observed it being opened — could happen if strace -ff
    // dropped a line, or if the dirfd was inherited across an
    // unobserved fork).  Fail closed: drop the raw event, surface a
    // synthetic `<UNRESOLVED_PATH>` audit_bypass entry so
    // findAuditBypass hard-fails the diff.
    it('numeric dirfd never observed → raw event dropped, <UNRESOLVED_PATH> audit_bypass surfaced', async () => {
      const proc = mockProcReader({
        903: {
          ppid: 1,
          env: {
            npm_package_name: 'orphan-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // No prior openat for fd 99 on this pid → dirfdTable miss.
        {
          pid: 903,
          line: 'openat(99, "secret", O_RDONLY) = 4',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The raw read event must NOT have been emitted — it would carry
      // the literal "secret" relative path and bypass policy matchers.
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read';
      });
      expect(reads).toHaveLength(0);
      // The synthetic <UNRESOLVED_PATH> audit_bypass entry must be present.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      // Forensic ident carries kind:path so the auditor can see the attempt.
      expect(raw['prog']).toBe('read:secret');
      // End-to-end through normalize → render: the entry must surface as
      // `<UNRESOLVED_PATH> …` under audit_bypass so findAuditBypass catches it.
      const ev: AttributedEvent = {
        raw: unresolved[0]!['raw'] as AttributedEvent['raw'],
        pkg: events[0]!['pkg'] as string,
        lifecycle: events[0]!['lifecycle'] as AttributedEvent['lifecycle'],
      };
      const ctx: NormalizeContext = {
        roots: { repo: '/work', nodeModules: '/work/node_modules', home: '/root', tmp: '/tmp', cache: '/cache' },
        pkgDirs: new Map([[ev.pkg, '/work/node_modules/orphan-pkg']]),
      };
      const out = normalize([ev], ctx);
      const block = out.get(ev.pkg)!.lifecycle.postinstall!;
      expect(block.audit_bypass.some((e) => e.startsWith('<UNRESOLVED_PATH>'))).toBe(true);
    });

    // Case 4: a numeric dirfd we never observed for a WRITE — same
    // fail-closed behavior as case 3 but ensures the write branch is
    // covered, not just read.
    // Codex adversarial follow-up (high, 2026-05-19): a relative chdir
    // from an untracked-cwd pid must NOT be resolved against the agent
    // process's cwd.  Pre-fix, `path.resolve("subdir")` produced
    // `<agent_cwd>/subdir`, which was then trusted by canonicalizeForEmit
    // and emitted as a normal absolute path — bypassing protected-paths /
    // cross-package matchers on the real target.  Post-fix, the pid is
    // marked cwd-unknown and AT_FDCWD-relative opens from it fail closed.
    it('relative chdir from untracked-cwd pid → AT_FDCWD-relative opens fail closed (codex follow-up)', async () => {
      const proc = mockProcReader({
        910: {
          ppid: 1,
          env: {
            npm_package_name: 'rel-chdir-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Codex follow-up #1 (2026-05-19): burn the install-root-seeded
        // flag with a benign first observation on a different pid so
        // pid 910 reaches the dispatcher genuinely "untracked".
        // Without this, pid 910 would inherit pidCwd=/work via the
        // install-root seeding path, and the relative chdir test
        // would resolve against /work/subdir — bypassing the
        // codex-finding fail-closed branch we are exercising.
        {
          pid: 1,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Relative chdir from a pid with no prior tracked cwd.
        // Kernel cwd moves to parent_cwd/subdir — which we don't know.
        {
          pid: 910,
          line: 'chdir("subdir") = 0',
          source: 'strace',
        },
        // Subsequent AT_FDCWD-relative open: must fail closed.
        {
          pid: 910,
          line: 'openat(AT_FDCWD, "secret", O_RDONLY) = 4',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No plain read event for "secret" must leak through.
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === 'secret';
      });
      expect(reads).toHaveLength(0);
      // And no plain read event with the WRONG resolution (input.cwd
      // joined with "secret") must appear either.
      const wrongReads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === '/work/secret';
      });
      expect(wrongReads).toHaveLength(0);
      // <UNRESOLVED_PATH> audit_bypass entry MUST be present.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe('read:secret');
    });

    // Codex adversarial follow-up (high, 2026-05-19): fchdir to a fd
    // that was never observed being opened (e.g. inherited across an
    // unobserved fork, or strace -ff dropped the openat line).  The
    // kernel cwd has moved to *somewhere* unknown; subsequent
    // AT_FDCWD-relative opens must fail closed.  Pre-fix, the fchdir
    // branch was a silent no-op and canonicalizeForEmit would have
    // fallen back to input.cwd, certifying a wrong absolute path.
    it('fchdir to unknown fd marks pid cwd-unknown → subsequent AT_FDCWD-relative opens fail closed (codex follow-up)', async () => {
      const proc = mockProcReader({
        911: {
          ppid: 1,
          env: {
            npm_package_name: 'fchdir-unknown-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // fd 42 was never opened on this pid — fchdir to unknown fd.
        {
          pid: 911,
          line: 'fchdir(42) = 0',
          source: 'strace',
        },
        // AT_FDCWD-relative open after the state mutation.
        {
          pid: 911,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No plain read event for the wrong absolute path (/work/.ssh/id_rsa)
      // must leak through — that would bypass the $HOME/.ssh/** matcher.
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read';
      });
      expect(reads).toHaveLength(0);
      // <UNRESOLVED_PATH> audit_bypass entry MUST be present.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe('read:.ssh/id_rsa');
    });

    // An ABSOLUTE chdir RE-ESTABLISHES confidence after a prior
    // unresolvable mutation — the new cwd is known, so AT_FDCWD-relative
    // opens after it resolve normally.
    it('absolute chdir after unresolvable mutation re-establishes cwd → relative opens resolve again', async () => {
      const proc = mockProcReader({
        912: {
          ppid: 1,
          env: {
            npm_package_name: 're-establish-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // First: an unresolvable fchdir.
        {
          pid: 912,
          line: 'fchdir(99) = 0',
          source: 'strace',
        },
        // Then: an absolute chdir re-establishes confidence.
        {
          pid: 912,
          line: 'chdir("/tmp/known") = 0',
          source: 'strace',
        },
        // Now AT_FDCWD-relative resolves against /tmp/known.
        {
          pid: 912,
          line: 'openat(AT_FDCWD, "data.txt", O_RDONLY) = 4',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read';
      });
      expect(reads).toHaveLength(1);
      const raw = reads[0]!['raw'] as Record<string, unknown>;
      expect(raw['path']).toBe('/tmp/known/data.txt');
      // The earlier unresolvable fchdir is forgotten — no
      // <UNRESOLVED_PATH> entry from THIS pid (it had no relative
      // opens between the fchdir and the absolute chdir).
      const unresolvedFromThisPid = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 912;
      });
      expect(unresolvedFromThisPid).toHaveLength(0);
    });

    it('numeric dirfd never observed (write) → raw event dropped, <UNRESOLVED_PATH> audit_bypass surfaced', async () => {
      const proc = mockProcReader({
        904: {
          ppid: 1,
          env: {
            npm_package_name: 'orphan-write-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // fd 77 was never opened on this pid; openat with it = dirfd miss.
        {
          pid: 904,
          line: 'openat(77, "evil", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 8',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No plain write event should leak through carrying "evil".
      const writes = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'write';
      });
      expect(writes).toHaveLength(0);
      // <UNRESOLVED_PATH> must be surfaced with the write kind in its ident.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe('write:evil');
    });

    // ===================================================================
    // Codex audit findings #1 + #2 (high, 2026-05-19) — fork/clone cwd
    // and fd inheritance propagation + dup/close fd-table mutation
    // + removal of the `input.cwd` fallback in canonicalizeForEmit.
    // ===================================================================

    // Codex finding #1: a parent that chdir'd then forked produces a
    // child whose AT_FDCWD-relative open MUST resolve against the
    // parent's cwd at fork time, not against `input.cwd`.  Pre-fix
    // (with the input.cwd fallback) a child that `openat(AT_FDCWD,
    // ".ssh/id_rsa", O_RDONLY) = -1 ENOENT` would resolve to
    // `/work/.ssh/id_rsa`, miss the `$HOME/.ssh/**` matcher, and be
    // dropped as an unprotected ENOENT.  Post-fix, the clone
    // propagator copies parent's cwd to the child so the resolved
    // path is `/root/.ssh/id_rsa` and the matcher fires.
    it('clone propagates parent cwd → child resolves AT_FDCWD-relative correctly (codex finding #1)', async () => {
      const proc = mockProcReader({
        2001: {
          ppid: 1,
          env: {
            npm_package_name: 'fork-parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        2002: {
          ppid: 2001,
          env: {
            npm_package_name: 'fork-parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent (pid 2001) chdirs to $HOME.
        {
          pid: 2001,
          line: 'chdir("/root") = 0',
          source: 'strace',
        },
        // Parent clones — child pid 2002 inherits cwd /root.
        {
          pid: 2001,
          line: 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f...) = 2002',
          source: 'strace',
        },
        // Child probes $HOME/.ssh/id_rsa — kernel resolves through
        // its inherited cwd /root, sees ENOENT.  Our dispatcher must
        // resolve to /root/.ssh/id_rsa so the matcher catches it.
        {
          pid: 2002,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The child's probe must surface as a read with the absolute
      // path and hidden=true (matched the protected pattern).
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read';
      });
      expect(reads).toHaveLength(1);
      const raw = reads[0]!['raw'] as Record<string, unknown>;
      expect(raw['path']).toBe('/root/.ssh/id_rsa');
      expect(raw['hidden']).toBe(true);
      // No <UNRESOLVED_PATH> for the child — clone propagated cwd.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex finding #1: a parent's fd-table is copied to the child at
    // fork.  The child can use an INHERITED dirfd in subsequent
    // openat(<fd>, "relative", …) calls; the dispatcher must
    // resolve via the propagated dirfdTable entry.
    it('clone propagates parent dirfdTable → child openat(<inherited-fd>, ...) resolves (codex finding #1)', async () => {
      const proc = mockProcReader({
        2101: {
          ppid: 1,
          env: {
            npm_package_name: 'fork-fd-parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        2102: {
          ppid: 2101,
          env: {
            npm_package_name: 'fork-fd-parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const SOME_DIR = '/var/lib/secrets';
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /var/lib/secrets → fd 7.
        {
          pid: 2101,
          line: `openat(AT_FDCWD, "${SOME_DIR}", O_RDONLY|O_DIRECTORY) = 7`,
          source: 'strace',
        },
        // Parent clones — child pid 2102 inherits fd 7 → SOME_DIR.
        {
          pid: 2101,
          line: 'clone(child_stack=NULL, flags=SIGCHLD) = 2102',
          source: 'strace',
        },
        // Child uses inherited fd 7 for a relative open.
        {
          pid: 2102,
          line: 'openat(7, "passwords.txt", O_RDONLY) = 8',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The child's read MUST resolve to /var/lib/secrets/passwords.txt
      // — the inherited dirfd's directory + the relative basename.
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === `${SOME_DIR}/passwords.txt`;
      });
      expect(reads).toHaveLength(1);
      // And no <UNRESOLVED_PATH> for the child.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 2102;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex finding #2: dup2 over a tracked dirfd MUST propagate the
    // dirfd mapping from the source fd.  Without dup2 tracing, the
    // dirfdTable still maps the original fd to the original directory,
    // so a later openat(<dup'd-fd>, "relative", ...) resolves through
    // the WRONG directory.  This test pins that dup2 replaces the
    // mapping correctly so the openat resolves against /root, matching
    // the kernel's behaviour after the dup2.
    it('dup2 over tracked dirfd → openat resolves through the new directory (codex finding #2)', async () => {
      const proc = mockProcReader({
        2201: {
          ppid: 1,
          env: {
            npm_package_name: 'dup2-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg → fd 7.
        {
          pid: 2201,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Open /root → fd 8.
        {
          pid: 2201,
          line: 'openat(AT_FDCWD, "/root", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // dup2(8, 7): fd 7 now aliases /root.
        {
          pid: 2201,
          line: 'dup2(8, 7) = 7',
          source: 'strace',
        },
        // openat(7, ...): kernel resolves through /root.
        {
          pid: 2201,
          line: 'openat(7, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === '/root/.ssh/id_rsa';
      });
      expect(reads).toHaveLength(1);
      const raw = reads[0]!['raw'] as Record<string, unknown>;
      expect(raw['hidden']).toBe(true);
      // And NO read with the stale /pkg resolution.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/.ssh/id_rsa';
      });
      expect(stale).toHaveLength(0);
    });

    // Codex finding #2: close(fd) invalidates the dirfdTable entry.  A
    // subsequent openat(<closed-fd>, ...) must fail closed — without
    // close tracing the table would still map the fd to its old
    // directory.
    it('close invalidates dirfdTable → subsequent openat(<closed-fd>, ...) fails closed (codex finding #2)', async () => {
      const proc = mockProcReader({
        2301: {
          ppid: 1,
          env: {
            npm_package_name: 'close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 2301,
          line: 'openat(AT_FDCWD, "/some/dir", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 2301,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // openat through the (now stale) fd — kernel would either
        // return EBADF or, if another fd was opened in the meantime,
        // resolve through that.  We can't know without further
        // tracing, so fail closed.
        {
          pid: 2301,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No plain read with /some/dir/file (the stale resolution).
      const stale = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === '/some/dir/file';
      });
      expect(stale).toHaveLength(0);
      // <UNRESOLVED_PATH> entry MUST be surfaced.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe('read:file');
    });

    // Codex finding #2: close_range(first, last, flags) invalidates a
    // range of fds.  We must iterate over existing table entries
    // rather than the full numeric range (last can be UINT_MAX, the
    // common "close everything above first" idiom).
    it('close_range invalidates dirfds in range → openat fails closed (codex finding #2)', async () => {
      const proc = mockProcReader({
        2401: {
          ppid: 1,
          env: {
            npm_package_name: 'close-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 2401,
          line: 'openat(AT_FDCWD, "/dir-a", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 2401,
          line: 'openat(AT_FDCWD, "/dir-b", O_RDONLY|O_DIRECTORY) = 9',
          source: 'strace',
        },
        // close_range(3, UINT_MAX, 0): close all fds >= 3 — wipes
        // fds 7 and 9 from our table.
        {
          pid: 2401,
          line: 'close_range(3, 4294967295, 0) = 0',
          source: 'strace',
        },
        // openat through fd 7 (no longer tracked).
        {
          pid: 2401,
          line: 'openat(7, "secret-a", O_RDONLY) = 8',
          source: 'strace',
        },
        // openat through fd 9 (also no longer tracked).
        {
          pid: 2401,
          line: 'openat(9, "secret-b", O_RDONLY) = 10',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No stale reads for either secret.
      const stale = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return (
          raw['kind'] === 'read' &&
          (raw['path'] === '/dir-a/secret-a' || raw['path'] === '/dir-b/secret-b')
        );
      });
      expect(stale).toHaveLength(0);
      // Two <UNRESOLVED_PATH> entries — one per stale openat.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(2);
    });

    // Codex finding #1: a pid that emerges with NO observed chdir and
    // NO observed clone parent (e.g. a strace -ff line that arrived
    // out-of-order) must fail closed for AT_FDCWD-relative opens.
    // The pre-fix `input.cwd` fallback would have silently produced
    // a wrong absolute path.
    it('untracked pid with no observed parent → AT_FDCWD-relative opens fail closed (codex finding #1)', async () => {
      const proc = mockProcReader({
        2501: {
          ppid: 1,
          env: {
            npm_package_name: 'orphan-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Burn the install-root-seeded flag with a benign event on
        // the simulated install root (pid 1) so pid 2501 is NOT the
        // first observed and DOES NOT get the input.cwd seed.
        {
          pid: 1,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Pid 2501 has no observed chdir, no observed clone parent.
        // Its AT_FDCWD-relative open MUST fail closed.
        {
          pid: 2501,
          line: 'openat(AT_FDCWD, "leak.txt", O_RDONLY) = 4',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No plain read for leak.txt under input.cwd.
      const stale = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === '/work/leak.txt';
      });
      expect(stale).toHaveLength(0);
      // <UNRESOLVED_PATH> MUST be surfaced — pid 2501 is genuinely
      // unrooted in our trace.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 2501;
      });
      expect(unresolved).toHaveLength(1);
      const raw = unresolved[0]!['raw'] as Record<string, unknown>;
      expect(raw['prog']).toBe('read:leak.txt');
    });

    // Codex finding #1, exception path: the install root pid (the FIRST
    // observed pid in the dispatcher) IS seeded with `input.cwd`, since
    // it has no observable clone parent in our trace (it was spawned
    // by the agent directly).  This test pins that the install root
    // resolves its own AT_FDCWD-relative opens correctly.
    it('install root pid resolves AT_FDCWD-relative against input.cwd (codex finding #1, root exception)', async () => {
      const proc = mockProcReader({
        2601: {
          ppid: 1,
          env: {
            npm_package_name: 'root-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Pid 2601 IS the first observed pid → install root → gets
        // pidCwd seeded to /work via the installRootSeeded path.
        {
          pid: 2601,
          line: 'openat(AT_FDCWD, "package.json", O_RDONLY) = 4',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records),
        attribution: new Attribution(proc),
        emitter,
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The install root resolves package.json against /work.
      const reads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return raw['kind'] === 'read' && raw['path'] === '/work/package.json';
      });
      expect(reads).toHaveLength(1);
      // No <UNRESOLVED_PATH> for the install root.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(0);
    });

    // ===================================================================
    // Bug-fix regression tests (high, 2026-05-19):
    //   #1 — root pid plumbing (runner-reported, not "first observed")
    //   #2 — CLONE_FS shared cwd group (parent ↔ child cwd is shared)
    //   #3 — CLONE_FILES shared fd-table group (dup/close affects both)
    // ===================================================================

    // Bug #1: pre-fix the dispatcher seeded `pidCwd[<first-yielded-pid>]
    // = input.cwd` on the FIRST yielded event.  The production
    // `StraceTailer` watches per-pid files via readdir + fs.watch; the
    // watcher may report a forked child's file BEFORE the parent's, in
    // which case the child (whose real cwd is whatever the parent
    // chdir'd to) silently gets the WRONG cwd seed and AT_FDCWD-
    // relative opens leak past protected-paths.  Post-fix: only the
    // runner-reported root pid is ever seeded.
    it('child-first event arrival does NOT seed child cwd with input.cwd (bug #1)', async () => {
      const proc = mockProcReader({
        9001: {
          ppid: 1,
          env: {
            npm_package_name: 'parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9002: {
          ppid: 9001,
          env: {
            npm_package_name: 'parent-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Simulate the race: the CHILD's strace per-pid file is drained
        // first by the watcher.  Pre-fix this would set pidCwd[9002] =
        // '/work', so a subsequent openat for ".ssh/id_rsa" from pid
        // 9002 would resolve to /work/.ssh/id_rsa — wrong (the kernel
        // resolves through the parent's chdir'd cwd which we don't yet
        // know) and unprotected.
        {
          pid: 9002,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        // Runner reports pid 9001 as the install root — but pid 9001 is
        // never yielded.  The dispatcher MUST NOT seed pid 9002 with
        // input.cwd just because it's the first observed pid.
        strace: cannedStraceRunner(records, 0, { rootPid: 9001 }),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The probe must NOT have been silently certified as /work/.ssh/id_rsa.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/.ssh/id_rsa';
      });
      expect(stale).toHaveLength(0);
      // A <UNRESOLVED_PATH> entry MUST be surfaced — pid 9002 had no
      // observable parent clone and the runner's root pid is 9001.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 9002;
      });
      expect(unresolved).toHaveLength(1);
    });

    // Bug #2: CLONE_FS makes parent and child share `struct fs` (cwd).
    // A chdir in EITHER pid mutates the shared cwd; subsequent
    // AT_FDCWD-relative opens in the OTHER pid resolve through the
    // new cwd.  Pre-fix, copy-on-clone snapshotted parent's cwd into
    // child's INDEPENDENT entry; a child chdir then mutated only the
    // child's cwd, and a parent openat resolved against the parent's
    // stale snapshot — leaking past protected-paths.
    it('clone with CLONE_FS unions cwd group: child chdir affects parent openat (bug #2)', async () => {
      const proc = mockProcReader({
        9101: {
          ppid: 1,
          env: {
            npm_package_name: 'clone-fs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9102: {
          ppid: 9101,
          env: {
            npm_package_name: 'clone-fs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Seed the install-root path with a no-op event from pid 9101
        // so it gets the input.cwd seed.
        {
          pid: 9101,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with CLONE_FS → parent and child share cwd.
        {
          pid: 9101,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tidptr=0x7f...) = 9102',
          source: 'strace',
        },
        // CHILD chdirs to $HOME — kernel mutates the SHARED fs struct,
        // so the parent's effective cwd is now /root too.
        {
          pid: 9102,
          line: 'chdir("/root") = 0',
          source: 'strace',
        },
        // PARENT issues AT_FDCWD-relative openat.  Kernel resolves
        // through /root because cwd is shared.  Post-fix the matcher
        // sees /root/.ssh/id_rsa.
        {
          pid: 9101,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9101 }),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The parent's probe MUST surface as /root/.ssh/id_rsa with
      // hidden=true (matched the protected pattern) — proving the
      // child's chdir mutated the shared cwd.
      const protectedReads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return (
          raw['kind'] === 'read' &&
          raw['path'] === '/root/.ssh/id_rsa' &&
          raw['pid'] === 9101 &&
          raw['hidden'] === true
        );
      });
      expect(protectedReads).toHaveLength(1);
      // The pre-fix (independent cwd snapshot) would have resolved to
      // /work/.ssh/id_rsa and dropped it as unprotected ENOENT.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/.ssh/id_rsa';
      });
      expect(stale).toHaveLength(0);
    });

    // Bug #3: CLONE_FILES makes parent and child share the fd table.
    // A dup2 in EITHER pid mutates the shared fd table; subsequent
    // openat(<fd>, "relative", ...) in the OTHER pid resolves through
    // the new fd's directory.  Pre-fix, copy-on-clone snapshotted
    // parent's dirfdTable into child's INDEPENDENT keys; a child
    // dup2 then mutated only the child's table, and a parent
    // openat(<dup'd-fd>, ...) resolved against the parent's stale
    // entry — missing the protected-paths match.
    it('clone with CLONE_FILES unions fd-table group: child dup2 affects parent openat (bug #3)', async () => {
      const proc = mockProcReader({
        9201: {
          ppid: 1,
          env: {
            npm_package_name: 'clone-files-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9202: {
          ppid: 9201,
          env: {
            npm_package_name: 'clone-files-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /pkg → fd 7.
        {
          pid: 9201,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent opens /root → fd 8.
        {
          pid: 9201,
          line: 'openat(AT_FDCWD, "/root", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → fd table is shared.
        {
          pid: 9201,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS, child_tidptr=0x7f...) = 9202',
          source: 'strace',
        },
        // CHILD dup2(8, 7): fd 7 now aliases /root in the SHARED table.
        {
          pid: 9202,
          line: 'dup2(8, 7) = 7',
          source: 'strace',
        },
        // PARENT openat(7, ...): kernel resolves through /root because
        // the fd table is shared and fd 7 now points at /root.
        {
          pid: 9201,
          line: 'openat(7, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];

      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9201 }),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });

      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The parent's openat MUST resolve through /root (the new dirfd
      // target) — proving the child's dup2 mutated the shared fd
      // table.  The protected pattern matches → hidden=true.
      const protectedReads = events.filter((e) => {
        const raw = e['raw'] as Record<string, unknown>;
        return (
          raw['kind'] === 'read' &&
          raw['path'] === '/root/.ssh/id_rsa' &&
          raw['pid'] === 9201 &&
          raw['hidden'] === true
        );
      });
      expect(protectedReads).toHaveLength(1);
      // The pre-fix (independent fd-table snapshot) would have
      // resolved through the parent's stale fd 7 → /pkg → /pkg/.ssh/
      // id_rsa.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/.ssh/id_rsa';
      });
      expect(stale).toHaveLength(0);
    });
  });

  // ===================================================================
  // Codex follow-up regression tests (high, 2026-05-19):
  //   #1 — root pid race: child's first event arrives before parent's
  //   #2 — union reconciles pre-existing per-group state
  //   #3 — close_range honours CLOSE_RANGE_UNSHARE
  // ===================================================================
  describe('codex follow-up #1/#2/#3 regression', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Bug #1 — race revisited at the dispatcher layer (not the
    // /proc/<strace_pid>/task/.../children layer, which is exercised in
    // the runner unit tests).  The dispatcher's contract is that ONLY
    // the runner-reported root pid receives the input.cwd seed; a child
    // whose event arrives BEFORE the parent's MUST NOT be silently
    // certified.
    it('root-pid race: child event before parent does NOT mis-seed child cwd (bug #1, dispatcher contract)', async () => {
      const proc = mockProcReader({
        7001: {
          ppid: 1,
          env: {
            npm_package_name: 'race-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7002: {
          ppid: 7001,
          env: {
            npm_package_name: 'race-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      // Runner reports pid 7001 as the root; child 7002 emits FIRST.
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child's relative openat lands before parent's strace lines.
        // Pre-fix the "first observed pid wins" heuristic would seed
        // pidCwd[7002] = /work, resolving to /work/.ssh/id_rsa.  Post-
        // fix the child gets no seed (the runner says 7001 is root,
        // and 7002 has no observed clone parent yet) and the openat
        // fails closed.
        {
          pid: 7002,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
        // Parent's first event arrives later.  The seed lands on 7001.
        {
          pid: 7001,
          line: 'openat(AT_FDCWD, "package.json", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7001 }),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child's probe was NOT silently certified as /work/.ssh/id_rsa.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/.ssh/id_rsa' && r['pid'] === 7002;
      });
      expect(stale).toHaveLength(0);
      // Parent's relative open resolved against input.cwd → /work/package.json.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/package.json' && r['pid'] === 7001;
      });
      expect(parentRead).toHaveLength(1);
      // Child's openat surfaced as <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7002;
      });
      expect(unresolved).toHaveLength(1);
    });

    // Bug #2 — union reconciliation:
    //  (a) child chdir before parent's clone — child's cwd MUST be
    //      adopted into the merged group rather than orphaned.  The
    //      parent here is NOT the install root (rootPid=7100, never
    //      yielded) so it carries no input.cwd seed; this isolates the
    //      "child-only state pre-union" case the codex spec calls out.
    it('union reconciles: child chdir before parent clone(CLONE_FS) keeps child cwd (bug #2.a)', async () => {
      const proc = mockProcReader({
        7101: {
          ppid: 7100,
          env: {
            npm_package_name: 'union-recon-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7102: {
          ppid: 7101,
          env: {
            npm_package_name: 'union-recon-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child chdir BEFORE the clone line is observed.  Pre-fix this
        // landed under pidCwd[<child-pre-union-root>] and was orphaned
        // when the parent's clone CLONE_FS arrived.  Post-fix the
        // union reconciles the child's cwd into the merged group.
        {
          pid: 7102,
          line: 'chdir("/root") = 0',
          source: 'strace',
        },
        // Parent's CLONE_FS clone is observed AFTER the child's chdir.
        {
          pid: 7101,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, child_tidptr=0x7f...) = 7102',
          source: 'strace',
        },
        // Parent's AT_FDCWD-relative openat MUST resolve through /root
        // (shared cwd group adopted the child's /root cwd).
        {
          pid: 7101,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        // rootPid 7100 is never yielded, so neither 7101 nor 7102
        // receives the input.cwd seed — we isolate the union state
        // reconciliation logic.
        strace: cannedStraceRunner(records, 0, { rootPid: 7100 }),
        attribution: new Attribution(proc),
        emitter,
        protectedPaths: new ProtectedPathsMatcher({
          patterns: ['$HOME/.ssh/**'],
          roots: {
            repo: '/work',
            nodeModules: '/work/node_modules',
            home: '/root',
            tmp: '/tmp',
            cache: '/root/.cache/pnpm',
          },
        }),
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's probe MUST resolve to /root/.ssh/id_rsa with hidden=true.
      const hits = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' &&
          r['path'] === '/root/.ssh/id_rsa' &&
          r['pid'] === 7101 &&
          r['hidden'] === true
        );
      });
      expect(hits).toHaveLength(1);
      // Pre-fix the orphaned child cwd would have left the parent with
      // NO tracked cwd — relative openat would have failed closed.
      // Post-fix the union adopted /root → parent resolves correctly.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/.ssh/id_rsa';
      });
      expect(stale).toHaveLength(0);
    });

    //  (b) differing cwds on both sides → merged group is cwdUnknown,
    //      subsequent relative open fails closed.
    it('union reconciles: differing parent/child cwds before clone(CLONE_FS) → cwdUnknown (bug #2.b)', async () => {
      const proc = mockProcReader({
        7201: {
          ppid: 1,
          env: {
            npm_package_name: 'union-ambig-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7202: {
          ppid: 7201,
          env: {
            npm_package_name: 'union-ambig-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 7201,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Both pids chdir to DIFFERENT absolute paths BEFORE the clone
        // CLONE_FS line.  Post-union the merged group is cwdUnknown.
        {
          pid: 7201,
          line: 'chdir("/B") = 0',
          source: 'strace',
        },
        {
          pid: 7202,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        {
          pid: 7201,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES, child_tidptr=0x7f...) = 7202',
          source: 'strace',
        },
        // Parent's AT_FDCWD-relative openat now fails closed
        // (cwdUnknown → canonicalizeForEmit returns null).
        {
          pid: 7201,
          line: 'openat(AT_FDCWD, "secret.key", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7201 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Relative open MUST NOT be certified against either /A or /B or /work.
      const certified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' &&
          (r['path'] === '/A/secret.key' || r['path'] === '/B/secret.key' || r['path'] === '/work/secret.key')
        );
      });
      expect(certified).toHaveLength(0);
      // <UNRESOLVED_PATH> is surfaced via the exec audit_bypass synth.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7201;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    //  (c) fd-table union — child opens fd 7→/A, parent opens fd 8→/B,
    //      then clone(CLONE_FILES).  Merged group has BOTH entries.
    it('union reconciles fd table: child fd7→/A + parent fd8→/B + clone(CLONE_FILES) → both keys live (bug #2 fd)', async () => {
      const proc = mockProcReader({
        7301: {
          ppid: 1,
          env: {
            npm_package_name: 'fd-union-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7302: {
          ppid: 7301,
          env: {
            npm_package_name: 'fd-union-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child opens /A as fd 7 BEFORE clone is observed.
        {
          pid: 7302,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent opens /B as fd 8.
        {
          pid: 7301,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Clone with CLONE_FILES merges the fd tables.
        {
          pid: 7301,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, child_tidptr=0x7f...) = 7302',
          source: 'strace',
        },
        // Parent reads via fd 7 (child's entry) — resolves to /A.
        {
          pid: 7301,
          line: 'openat(7, "leaf-a", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child reads via fd 8 (parent's entry) — resolves to /B.
        {
          pid: 7302,
          line: 'openat(8, "leaf-b", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7301 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const aHit = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/leaf-a' && r['pid'] === 7301;
      });
      expect(aHit).toHaveLength(1);
      const bHit = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/leaf-b' && r['pid'] === 7302;
      });
      expect(bHit).toHaveLength(1);
    });

    //  (d) fd conflict — both sides have fd 7 mapped to different
    //      paths.  Merged entry is dropped → openat(7, ...) fails
    //      closed.
    it('union reconciles fd table: same fd / different paths → entry dropped (bug #2 fd-conflict)', async () => {
      const proc = mockProcReader({
        7401: {
          ppid: 1,
          env: {
            npm_package_name: 'fd-conflict-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7402: {
          ppid: 7401,
          env: {
            npm_package_name: 'fd-conflict-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child opens /A as fd 7.
        {
          pid: 7402,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent opens /B as fd 7 (same fd, different dir) — only
        // possible because the two pids are NOT yet in a shared fd
        // group; once we observe the clone CLONE_FILES line we have
        // a conflict.
        {
          pid: 7401,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Clone with CLONE_FILES — union encounters conflicting fd 7.
        {
          pid: 7401,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 7402',
          source: 'strace',
        },
        // Parent's openat(7, ...) MUST fail closed post-union.
        {
          pid: 7401,
          line: 'openat(7, "leaf", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7401 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const certified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && (r['path'] === '/A/leaf' || r['path'] === '/B/leaf');
      });
      expect(certified).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7401;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #3 — CLOSE_RANGE_UNSHARE:
    //  parent + child share fd table; child close_range(... UNSHARE).
    //  Parent retains its fd; child loses it.
    it('close_range(... CLOSE_RANGE_UNSHARE) detaches caller — parent fd survives, child fd dies (bug #3)', async () => {
      const proc = mockProcReader({
        7501: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7502: {
          ppid: 7501,
          env: {
            npm_package_name: 'unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /pkg as fd 7.
        {
          pid: 7501,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → child shares fd table.
        {
          pid: 7501,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 7502',
          source: 'strace',
        },
        // Child detaches via close_range(3, INT_MAX, CLOSE_RANGE_UNSHARE).
        {
          pid: 7502,
          line: 'close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Parent's openat(7, ...) MUST still resolve to /pkg.
        {
          pid: 7501,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child's openat(7, ...) MUST fail closed.
        {
          pid: 7502,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7501 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 7501;
      });
      expect(parentRead).toHaveLength(1);
      // Child's openat(7, ...) was dropped; <UNRESOLVED_PATH> surfaced.
      const childCertified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 7502;
      });
      expect(childCertified).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7502;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #3 — close_range WITHOUT UNSHARE on a shared fd group: BOTH
    // sides lose the fd.
    it('close_range(... 0) on shared group: BOTH parent and child lose fd (bug #3 sanity)', async () => {
      const proc = mockProcReader({
        7601: {
          ppid: 1,
          env: {
            npm_package_name: 'no-unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7602: {
          ppid: 7601,
          env: {
            npm_package_name: 'no-unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 7601,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 7601,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 7602',
          source: 'strace',
        },
        // close_range without UNSHARE — both sides lose fd 7.
        {
          pid: 7602,
          line: 'close_range(3, 4294967295, 0) = 0',
          source: 'strace',
        },
        {
          pid: 7601,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        {
          pid: 7602,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7601 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const certified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file';
      });
      expect(certified).toHaveLength(0);
      // Both pids surface <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'exec' &&
          r['unresolved_path'] === true &&
          (r['pid'] === 7601 || r['pid'] === 7602)
        );
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(2);
    });
  });

  // =====================================================================
  // codex follow-up #4 regression (2026-05-19):
  //   #1 — CLOSE_RANGE_UNSHARE caller IS the group representative.
  //        The detach must still re-root the group and seed a private
  //        copy for the caller; pre-fix this branch was a no-op so
  //        siblings observed deletions from the caller's close_range.
  //   #2 — cwdUnknown dominates canonicalizers.  After unionCwd merges
  //        a child cwd-unknown group into a parent cwd-known group, the
  //        parent's adopted value MUST NOT certify subsequent
  //        AT_FDCWD-relative opens — the unknown bit fails closed.
  //   #3 — tri-state rootPid resolution (LinuxStraceRunner side).
  //        When the /proc resolution path was attempted but produced
  //        no pid, the per-pid-file fallback MUST be suppressed.  See
  //        agent.test.ts for the runner-side test; we still capture
  //        the dispatcher's null-rootPid contract here.
  //   #4 — clone3 return-value parsing.  Struct fields like
  //        `stack_size=0` MUST NOT shadow the trailing rc.  Pre-fix
  //        the rc regex matched the first `=N` token in the line.
  // =====================================================================
  describe('codex follow-up #4 regression', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Bug #1 (round 2) — caller IS the group representative.
    //  parent (group root) opens fd 7→/A, parent clones with CLONE_FILES
    //  → child joins parent's group, parent (NOT child) calls
    //  close_range(3, INT_MAX, CLOSE_RANGE_UNSHARE).  The remaining
    //  sibling (the child) must keep resolving fd 7→/A through whichever
    //  representative the implementation chose.  Pre-fix the parent's
    //  detach was a silent no-op and the close range mutated the SHARED
    //  group's entries — the child's openat(7, "file") would have
    //  failed closed.
    it('CLOSE_RANGE_UNSHARE when caller IS the group root: sibling fd state preserved (bug #1)', async () => {
      const proc = mockProcReader({
        8001: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-root-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        8002: {
          ppid: 8001,
          env: {
            npm_package_name: 'unshare-root-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A as fd 7.
        {
          pid: 8001,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → child joins parent's group.
        // Parent is the group root (rootedFd(parent) === parent because
        // unionFd points the CHILD's root at the parent's root).
        {
          pid: 8001,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 8002',
          source: 'strace',
        },
        // PARENT (the group root) detaches via CLOSE_RANGE_UNSHARE.
        {
          pid: 8001,
          line: 'close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Child's openat(7, "file") MUST still resolve to /A/file
        // (the sibling state was preserved because the implementation
        // re-rooted the group to the child before detaching the parent).
        {
          pid: 8002,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Parent's openat(7, "file") MUST fail closed (caller detached
        // AND closed fd 7 in its new private group).
        {
          pid: 8001,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 8001 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child's read resolved to /A/file — sibling fd table survived.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 8002;
      });
      expect(childRead).toHaveLength(1);
      // Parent's read MUST NOT have resolved to /A/file (its private
      // group lost fd 7 to the close range).
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 8001;
      });
      expect(parentRead).toHaveLength(0);
      // Parent's openat surfaces as <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 8001;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #1 sanity — caller IS the group root AND is the only member
    // (singleton group).  Nothing to detach against; close_range applies
    // to the caller's private state directly.  No siblings to preserve.
    it('CLOSE_RANGE_UNSHARE on a singleton group: close applies to caller directly (bug #1 sanity)', async () => {
      const proc = mockProcReader({
        8101: {
          ppid: 1,
          env: {
            npm_package_name: 'singleton-unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Pid 8101 opens /A as fd 7 — singleton group.
        {
          pid: 8101,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // CLOSE_RANGE_UNSHARE on a singleton: no other members to
        // re-root; the close range applies to pid 8101's own entries.
        {
          pid: 8101,
          line: 'close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Pid 8101's openat(7, "file") MUST fail closed (its fd 7 was
        // closed in the singleton's group).
        {
          pid: 8101,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 8101 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const certified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file';
      });
      expect(certified).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 8101;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 — cwdUnknown dominance.
    //  parent has cwd=/A (seeded as install root); child has
    //  cwdUnknown=true (a chdir to a relative path with no prior cwd
    //  marked it unknown).  CLONE_FS clone unions them.  After the
    //  union the merged group inherits the unknown bit AND the
    //  parent's old /A value (unionCwd only deletes the merged-group
    //  pidCwd entry when BOTH sides had values that DIFFERED).  ANY
    //  AT_FDCWD-relative open from either pid MUST fail closed.
    it('cwdUnknown dominates canonicalizer: child cwdUnknown + parent cwd=/A + CLONE_FS → opens fail closed (bug #2)', async () => {
      const proc = mockProcReader({
        8201: {
          ppid: 1,
          env: {
            npm_package_name: 'unknown-dominates-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        8202: {
          ppid: 8201,
          env: {
            npm_package_name: 'unknown-dominates-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent (install root) gets seeded with /A via the explicit
        // cwd seed below.  We do an absolute chdir to make it explicit.
        {
          pid: 8201,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Child performs a RELATIVE chdir with NO prior cwd — this
        // sets cwdUnknown on the child's group (per the chdirRe
        // handler in phase-install.ts).
        {
          pid: 8202,
          line: 'chdir("subdir") = 0',
          source: 'strace',
        },
        // Now the parent observes a CLONE_FS clone of the child.  The
        // union reconciles: parent has cwd=/A, child has cwdUnknown.
        // Per unionCwd, the merged group keeps /A as the pidCwd value
        // (no conflict because child had no value) AND inherits the
        // unknown bit.  Pre-fix the canonicalizer called cwdGet first
        // and returned /A — certifying every subsequent relative open.
        // Post-fix the unknown bit dominates: returns null.
        {
          pid: 8201,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES, child_tidptr=0x7f...) = 8202',
          source: 'strace',
        },
        // Parent's AT_FDCWD-relative openat MUST fail closed.
        {
          pid: 8201,
          line: 'openat(AT_FDCWD, "secret.key", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child's AT_FDCWD-relative openat MUST also fail closed.
        {
          pid: 8202,
          line: 'openat(AT_FDCWD, "other.key", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/A',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 8201 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No relative open should have been resolved to /A/* — the
      // unknown bit dominates after the union.
      const certified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' &&
          (r['path'] === '/A/secret.key' || r['path'] === '/A/other.key')
        );
      });
      expect(certified).toHaveLength(0);
      // Both pids surface <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'exec' &&
          r['unresolved_path'] === true &&
          (r['pid'] === 8201 || r['pid'] === 8202)
        );
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(2);
    });

    // Bug #3 (dispatcher-side contract) — null rootPid disables seeding.
    //  When the runner returns null from getRootPid(), the dispatcher
    //  MUST NOT seed any pid's cwd from input.cwd.  First-observed-pid
    //  fallback (the pre-fix race) is gone.  This test exercises the
    //  dispatcher contract; agent.test.ts covers the runner-side
    //  /proc-failure path that produces null in the first place.
    it('rootPid=null leaves all pids unseeded; first-observed AT_FDCWD-relative open fails closed (bug #3)', async () => {
      const proc = mockProcReader({
        8301: {
          ppid: 1,
          env: {
            npm_package_name: 'null-rootpid-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // First-observed pid does an AT_FDCWD-relative openat without
        // any prior chdir.  Pre-fix the "first observed pid wins"
        // fallback would have seeded pidCwd[8301] = input.cwd → /work
        // → certified open to /work/secret.key.  Post-fix (rootPid
        // null) no seeding happens → fails closed.
        {
          pid: 8301,
          line: 'openat(AT_FDCWD, "secret.key", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        // rootPid explicitly null — mirrors the runner-side decision
        // that /proc resolution failed and the per-pid-file fallback
        // was suppressed (bug #3 tri-state).
        strace: cannedStraceRunner(records, 0, { rootPid: null }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/secret.key' && r['pid'] === 8301;
      });
      expect(stale).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 8301;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #4 — clone3 return-value parsing anchored on the closing `)`.
    //  Real-shape clone3 lines contain numeric struct fields BEFORE the
    //  trailing rc (`stack_size=0`, `exit_signal=17`).  Pre-fix the rc
    //  regex was `/=\s*(\d+)\b/` — greedy across the line — and
    //  matched the first `=0`, making `childPid` parse to 0 and the
    //  propagation branch silently skip.  Post-fix the regex anchors
    //  on `)\s*=\s*` and picks up the real rc.  We then verify
    //  propagation happened: the child does an AT_FDCWD-relative open
    //  and resolves against the parent's cwd (which was seeded as
    //  input.cwd).
    it('clone3 with numeric struct fields propagates state to child (bug #4)', async () => {
      const proc = mockProcReader({
        8401: {
          ppid: 1,
          env: {
            npm_package_name: 'clone3-rc-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9999: {
          ppid: 8401,
          env: {
            npm_package_name: 'clone3-rc-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Real-shape clone3 line with `stack_size=0` (and other `=N`
        // tokens) BEFORE the trailing `= 9999`.  Pre-fix the rc parse
        // matched `=0` → childPid=0 → propagation skipped.
        {
          pid: 8401,
          line: 'clone3({flags=CLONE_VM|CLONE_FS, stack_size=0, child_tidptr=0x7f8c0000, exit_signal=17}, 88) = 9999',
          source: 'strace',
        },
        // Child does an AT_FDCWD-relative open.  Post-fix the
        // CLONE_FS-flagged clone3 unions the cwd group, so the child
        // resolves through the parent's cwd (seeded from input.cwd =
        // /work as the install root).
        {
          pid: 9999,
          line: 'openat(AT_FDCWD, "package.json", O_RDONLY) = 4',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 8401 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child's open resolved to /work/package.json (propagation
      // succeeded).  Pre-fix this open would have failed closed.
      const hit = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/package.json' && r['pid'] === 9999;
      });
      expect(hit).toHaveLength(1);
      // No <UNRESOLVED_PATH> for pid 9999.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 9999;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Bug #4 negative case — pre-fix regression sentinel.  Without the
    // anchored regex the dispatcher would have parsed childPid=0 from
    // the leading `stack_size=0` and skipped propagation entirely; the
    // child's openat would then have failed closed (no cwd seed).  We
    // assert the POSITIVE outcome to prevent re-introduction.
    it('clone3 rc anchored on closing `)` works with `=N` struct fields preceding the rc (bug #4)', async () => {
      // Sanity check the regex at the source level — we extract a
      // copy via a small inline parser that mirrors phase-install's
      // intent.  This is a behavioural assertion of the anchor.
      const line =
        'clone3({flags=CLONE_VM|CLONE_FS, stack_size=0, exit_signal=17}, 88) = 12345';
      // Pre-fix regex.
      const pre = line.match(/=\s*(\d+)\b/);
      expect(pre?.[1]).toBe('0'); // pre-fix matched the wrong token.
      // Post-fix anchored regex.
      const post = line.match(/\)\s*=\s*(-?\d+)\b/);
      expect(post?.[1]).toBe('12345');
    });
  });

  // =====================================================================
  // codex follow-up #5 (2026-05-19) — close_range decimal flag parsing
  // and CLOEXEC fd tracking across execve.
  //
  // Two bugs:
  //   #1 — close_range flags rendered as a DECIMAL bitmask (`2`, `3`,
  //        `6`) were silently treated as the non-UNSHARE branch.
  //        Pre-fix the parser only recognised the symbolic identifier
  //        list (`CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC`) and the
  //        `0x`-prefixed hex form; a decimal token like `2` slipped
  //        past both checks.  The result was that, on kernels/strace
  //        builds rendering flags numerically, `close_range(3, ~0,
  //        CLOSE_RANGE_UNSHARE) = 0` would render as
  //        `close_range(3, 4294967295, 2) = 0` and the dispatcher
  //        deleted from the SHARED group's dirfdTable instead of
  //        detaching the caller.
  //
  //   #2 — dirfdTable entries opened with O_CLOEXEC survived execve.
  //        The kernel auto-closes FD_CLOEXEC fds on successful exec,
  //        but our model kept them.  A subsequent
  //        openat(<stale-fd>, "../../root/.ssh/id_rsa", ...) resolved
  //        through the dirfdTable to the package's directory, missing
  //        the protected-paths match.  Also: fcntl(2) was completely
  //        untraced, so F_DUPFD / F_DUPFD_CLOEXEC / F_SETFD changes
  //        were invisible.
  // =====================================================================
  describe('codex follow-up #5 regression', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Bug #1 — decimal CLOSE_RANGE_UNSHARE (`2`).  Parent + child share
    // an fd group; child issues close_range(3, INT_MAX, 2) (decimal).
    // The bit value 2 IS CLOSE_RANGE_UNSHARE, so the child must detach
    // BEFORE closing.  The parent's fd 7→/A entry must survive.
    it('close_range with decimal UNSHARE flag (`2`) detaches caller; sibling fd survives (bug #1)', async () => {
      const proc = mockProcReader({
        7001: {
          ppid: 1,
          env: {
            npm_package_name: 'decimal-unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        7002: {
          ppid: 7001,
          env: {
            npm_package_name: 'decimal-unshare-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7.
        {
          pid: 7001,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent CLONE_FILES with child — they share the fd group.
        {
          pid: 7001,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 7002',
          source: 'strace',
        },
        // Child detaches via decimal CLOSE_RANGE_UNSHARE (bit 2 in the
        // flags arg, rendered as the bare decimal `2` by some strace
        // builds).  Pre-fix this was ignored and the dispatcher
        // deleted the SHARED group's fd entries.
        {
          pid: 7002,
          line: 'close_range(3, 4294967295, 2) = 0',
          source: 'strace',
        },
        // Parent's fd 7 MUST still resolve through /A (the unshare
        // copied the table into the child's private group, then
        // closed; the parent's group is untouched).
        {
          pid: 7001,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child's fd 7 MUST be closed (in its private group).
        {
          pid: 7002,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7001 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 7001;
      });
      expect(parentRead).toHaveLength(1);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 7002;
      });
      expect(childRead).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7002;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 — openat with O_CLOEXEC is dropped from the dirfdTable on
    // execve.  A subsequent openat(<closed-fd>, ...) MUST fail closed.
    it('O_CLOEXEC dirfd is swept on execve → post-exec openat fails closed (bug #2)', async () => {
      const proc = mockProcReader({
        7101: {
          ppid: 1,
          env: {
            npm_package_name: 'cloexec-sweep-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg with O_CLOEXEC → fd 7.
        {
          pid: 7101,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 7',
          source: 'strace',
        },
        // Successful execve replaces the address space.  Kernel
        // auto-closes fd 7 (FD_CLOEXEC).  Our dirfdTable must too.
        {
          pid: 7101,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec openat(7, ...) MUST NOT resolve to /pkg/file.
        {
          pid: 7101,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7101 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file';
      });
      expect(stale).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7101;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 control — open WITHOUT O_CLOEXEC survives execve.  Asserts
    // the sweep doesn't over-delete.
    it('non-CLOEXEC dirfd survives execve → post-exec openat resolves (bug #2 control)', async () => {
      const proc = mockProcReader({
        7201: {
          ppid: 1,
          env: {
            npm_package_name: 'no-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg WITHOUT O_CLOEXEC → fd 7.
        {
          pid: 7201,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Successful execve.  Kernel keeps fd 7 (not CLOEXEC).
        {
          pid: 7201,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec openat(7, "file") MUST resolve to /pkg/file.
        {
          pid: 7201,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7201 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const reads = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 7201;
      });
      expect(reads).toHaveLength(1);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7201;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Bug #2 — fcntl(F_SETFD, FD_CLOEXEC) sets cloexec on an existing
    // non-CLOEXEC fd; the next execve sweeps it.
    it('fcntl(F_SETFD FD_CLOEXEC) sets cloexec → exec sweeps fd → post-exec open fails closed (bug #2)', async () => {
      const proc = mockProcReader({
        7301: {
          ppid: 1,
          env: {
            npm_package_name: 'fcntl-setfd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg WITHOUT O_CLOEXEC → fd 7.
        {
          pid: 7301,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Set FD_CLOEXEC via fcntl.
        {
          pid: 7301,
          line: 'fcntl(7, F_SETFD, FD_CLOEXEC) = 0',
          source: 'strace',
        },
        // Exec — kernel closes fd 7.
        {
          pid: 7301,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec openat(7, ...) MUST fail closed.
        {
          pid: 7301,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7301 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file';
      });
      expect(stale).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7301;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 — fcntl(F_DUPFD_CLOEXEC) creates a CLOEXEC duplicate; the
    // next execve sweeps the duplicate; the source fd may also be
    // cloexec/not depending on its prior bit (here it isn't).
    it('fcntl(F_DUPFD_CLOEXEC) duplicate is CLOEXEC → swept on exec (bug #2)', async () => {
      const proc = mockProcReader({
        7401: {
          ppid: 1,
          env: {
            npm_package_name: 'fcntl-dupfd-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg → fd 7 (non-CLOEXEC).
        {
          pid: 7401,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Duplicate fd 7 with CLOEXEC → fd 12 (cloexec=true).
        {
          pid: 7401,
          line: 'fcntl(7, F_DUPFD_CLOEXEC, 10) = 12',
          source: 'strace',
        },
        // Exec — kernel closes fd 12 (CLOEXEC) and keeps fd 7 (no CLOEXEC).
        {
          pid: 7401,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec openat(12, ...) MUST fail closed.
        {
          pid: 7401,
          line: 'openat(12, "secret", O_RDONLY) = 8',
          source: 'strace',
        },
        // Post-exec openat(7, ...) MUST resolve (fd 7 was not CLOEXEC).
        {
          pid: 7401,
          line: 'openat(7, "file", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7401 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // fd 12 → /pkg/secret stale resolution MUST NOT occur.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/secret';
      });
      expect(stale).toHaveLength(0);
      // fd 7 → /pkg/file MUST resolve.
      const live = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 7401;
      });
      expect(live).toHaveLength(1);
      // <UNRESOLVED_PATH> for the fd-12 open.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7401;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 — close_range CLOSE_RANGE_CLOEXEC marks (does not delete).
    // Before exec, the fd still resolves; after exec, it doesn't.
    it('close_range with CLOSE_RANGE_CLOEXEC (flag 4) marks not deletes; swept on exec (bug #2)', async () => {
      const proc = mockProcReader({
        7501: {
          ppid: 1,
          env: {
            npm_package_name: 'close-range-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg → fd 7 (non-CLOEXEC).
        {
          pid: 7501,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // close_range(3, INT_MAX, 4) — CLOSE_RANGE_CLOEXEC alone (no
        // UNSHARE).  Mark fd 7's entry cloexec=true; the fd itself
        // remains open until exec.
        {
          pid: 7501,
          line: 'close_range(3, 4294967295, 4) = 0',
          source: 'strace',
        },
        // Before exec: openat(7, ...) MUST resolve to /pkg/file (fd
        // still open, just FD_CLOEXEC).
        {
          pid: 7501,
          line: 'openat(7, "file", O_RDONLY) = 9',
          source: 'strace',
        },
        // Exec — kernel closes fd 7 (CLOEXEC was set by close_range).
        {
          pid: 7501,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec: openat(7, ...) MUST fail closed.
        {
          pid: 7501,
          line: 'openat(7, "other", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7501 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The pre-exec /pkg/file read MUST appear (fd still open).
      const preExecRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 7501;
      });
      expect(preExecRead).toHaveLength(1);
      // The post-exec /pkg/other read MUST NOT appear (fd swept).
      const postStale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/other';
      });
      expect(postStale).toHaveLength(0);
      // <UNRESOLVED_PATH> for the post-exec attempt.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7501;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Bug #2 — dup3 with O_CLOEXEC creates a CLOEXEC duplicate; the
    // next execve sweeps it.
    it('dup3 with O_CLOEXEC marks newfd cloexec → swept on exec (bug #2)', async () => {
      const proc = mockProcReader({
        7601: {
          ppid: 1,
          env: {
            npm_package_name: 'dup3-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Open /pkg → fd 7 (non-CLOEXEC).
        {
          pid: 7601,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // dup3(7, 9, O_CLOEXEC) → fd 9 with cloexec=true.
        {
          pid: 7601,
          line: 'dup3(7, 9, O_CLOEXEC) = 9',
          source: 'strace',
        },
        // Exec — kernel closes fd 9 (CLOEXEC); fd 7 survives.
        {
          pid: 7601,
          line: 'execve("/usr/bin/sh", ["sh", "-c", "x"], 0x7ffd...) = 0',
          source: 'strace',
        },
        // Post-exec openat(9, ...) MUST fail closed.
        {
          pid: 7601,
          line: 'openat(9, "secret", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 7601 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // fd 9 → /pkg/secret stale MUST NOT occur.
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/secret';
      });
      expect(stale).toHaveLength(0);
      // <UNRESOLVED_PATH> for the fd-9 open.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 7601;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
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

  // =====================================================================
  // Codex follow-up regression tests (high, 2026-05-19):
  //
  //   #1 — execve detaches the caller from a shared CLONE_FILES fd group
  //        BEFORE the kernel sweeps CLOEXEC.  Sibling fd mutations after
  //        the exec must NOT bleed into the exec'd image's modeled state.
  //   #2 — execve still sweeps CLOEXEC in the now-private fd group
  //        without disturbing the sibling's view of the SHARED group.
  //   #3 — unshare(CLONE_FILES) detaches the caller from a shared
  //        CLONE_FILES group.  Subsequent dup/close in the caller must
  //        NOT mutate the sibling's modeled fd table.
  //   #4 — unshare(CLONE_FS) detaches the caller from a shared CLONE_FS
  //        cwd group.  Subsequent chdir in the caller must NOT mutate
  //        the sibling's modeled cwd.
  //   #5 — unshare flags parser accepts decimal and hex numeric forms
  //        (CLONE_FILES = 0x400 = 1024) so kernels / libc combos that
  //        emit numeric flags still trigger the detach.
  //   #6 — unshare with flag bits we don't model (CLONE_NEWUTS, etc) is
  //        ignored — no spurious detach.
  // =====================================================================
  describe('execve detaches CLONE_FILES + unshare(2) modeling (codex follow-up)', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Test #1 — execve detaches CLONE_FILES: parent + child share fd
    // table; child execve's; AFTER the exec, parent dup2(8→7) where 8
    // was opened to /B BEFORE the clone.  Assert:
    //   - child's modeled fd 7 still maps to /A (the exec snapshot).
    //   - parent's modeled fd 7 maps to /B (post-detach mutation in the
    //     parent's group only).
    // Pre-fix the parent's dup2 mutated the shared dirfdTable, so the
    // child's post-exec openat(7, ...) would also resolve through /B.
    it('execve detaches caller from shared fd group: parent dup2 after exec does not affect child (bug #1)', async () => {
      const proc = mockProcReader({
        9301: {
          ppid: 1,
          env: {
            npm_package_name: 'exec-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9302: {
          ppid: 9301,
          env: {
            npm_package_name: 'exec-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 (without O_CLOEXEC so it survives exec).
        {
          pid: 9301,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent opens /B → fd 8 BEFORE the clone (so the snapshot
        // entering the child includes fd 8 too).
        {
          pid: 9301,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → child shares fd table.
        {
          pid: 9301,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 9302',
          source: 'strace',
        },
        // Child execve's → kernel calls unshare_files_struct.  Our
        // model must detach the child's fd group from the parent's.
        {
          pid: 9302,
          line: 'execve("/usr/bin/cat", ["cat"], 0x7f...) = 0',
          source: 'strace',
        },
        // Parent dup2(8, 7) — in the parent's group only.  Post-fix
        // this MUST NOT affect the child's modeled fd 7.
        {
          pid: 9301,
          line: 'dup2(8, 7) = 7',
          source: 'strace',
        },
        // Parent openat(7, "file") — resolves through /B (the new
        // mapping in the parent's private group).
        {
          pid: 9301,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child openat(7, "file") — must resolve through /A (the
        // exec'd image's snapshot, unchanged by the parent's dup2).
        {
          pid: 9302,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9301 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat(7, ...) MUST resolve to /B/file (post-dup2 path).
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file' && r['pid'] === 9301;
      });
      expect(parentRead).toHaveLength(1);
      // Child's openat(7, ...) MUST resolve to /A/file (exec snapshot,
      // not the parent's post-detach /B).
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 9302;
      });
      expect(childRead).toHaveLength(1);
      // Sanity: child MUST NOT see /B/file (parent's mutation leaked).
      const bleed = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file' && r['pid'] === 9302;
      });
      expect(bleed).toHaveLength(0);
    });

    // Test #2 — execve sweeps CLOEXEC in the now-private group only.
    // Parent opens fd 7→/pkg with O_CLOEXEC; clone(CLONE_FILES); child
    // execs.  Post-fix: child's modeled fd 7 is cleared (kernel closed
    // CLOEXEC), parent's modeled fd 7 still resolves to /pkg.
    it('execve sweeps CLOEXEC in private group only: parent fd survives, child fd dies (bug #1)', async () => {
      const proc = mockProcReader({
        9401: {
          ppid: 1,
          env: {
            npm_package_name: 'exec-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9402: {
          ppid: 9401,
          env: {
            npm_package_name: 'exec-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /pkg with O_CLOEXEC → fd 7 (cloexec=true).
        {
          pid: 9401,
          line: 'openat(AT_FDCWD, "/pkg", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 7',
          source: 'strace',
        },
        // Parent clones CLONE_FILES → child shares fd table.
        {
          pid: 9401,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 9402',
          source: 'strace',
        },
        // Child execve's → kernel sweeps CLOEXEC in the child's
        // private fd table.  Our model must:
        //   1. Detach the child from the shared group.
        //   2. Sweep cloexec=true entries in the child's private group.
        //   3. Leave the parent's (formerly shared, now solo) group
        //      with fd 7 → /pkg intact.
        {
          pid: 9402,
          line: 'execve("/usr/bin/cat", ["cat"], 0x7f...) = 0',
          source: 'strace',
        },
        // Parent openat(7, ...) — must still resolve through /pkg.
        {
          pid: 9401,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child openat(7, ...) — must fail closed (CLOEXEC swept).
        {
          pid: 9402,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9401 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's read certified through /pkg.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 9401;
      });
      expect(parentRead).toHaveLength(1);
      // Child's read MUST NOT certify through /pkg — fd was swept.
      const childCertified = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/pkg/file' && r['pid'] === 9402;
      });
      expect(childCertified).toHaveLength(0);
      // Child's openat fails closed → surfaced as <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 9402;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Test #3 — unshare(CLONE_FILES) detaches.  Parent + child share fd
    // table; parent opens /A → fd 7; child unshare(CLONE_FILES); child
    // opens /B → fd 8 then dup2(8, 7).  Post-fix: parent fd 7 still
    // /A, child fd 7 → /B.
    it('unshare(CLONE_FILES) detaches caller: child dup2 does not affect parent (bug #2)', async () => {
      const proc = mockProcReader({
        9501: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-files-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9502: {
          ppid: 9501,
          env: {
            npm_package_name: 'unshare-files-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7.
        {
          pid: 9501,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → child shares fd table.
        {
          pid: 9501,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 9502',
          source: 'strace',
        },
        // Child explicitly detaches via unshare(CLONE_FILES).
        {
          pid: 9502,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child opens /B → fd 8 in its NEW private group.
        {
          pid: 9502,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Child dup2(8, 7) — fd 7 now aliases /B in the CHILD's private
        // group only.  Pre-fix this mutated the shared dirfdTable and
        // the parent's openat(7) below would resolve through /B.
        {
          pid: 9502,
          line: 'dup2(8, 7) = 7',
          source: 'strace',
        },
        // Parent openat(7, "file") — MUST still resolve through /A.
        {
          pid: 9501,
          line: 'openat(7, "file", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child openat(7, "file") — resolves through /B (post-dup2).
        {
          pid: 9502,
          line: 'openat(7, "file", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9501 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 9501;
      });
      expect(parentRead).toHaveLength(1);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file' && r['pid'] === 9502;
      });
      expect(childRead).toHaveLength(1);
      // Sanity: parent MUST NOT see /B/file (child mutation leaked).
      const bleed = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file' && r['pid'] === 9501;
      });
      expect(bleed).toHaveLength(0);
    });

    // Test #4 — unshare(CLONE_FS) detaches cwd.  Parent + child share
    // `struct fs` via clone(CLONE_FS); parent chdir(/A); child
    // unshare(CLONE_FS); child chdir(/B).  Post-fix: parent's cwd is
    // /A, child's cwd is /B (proven by an AT_FDCWD-relative openat
    // resolving against the per-pid cwd).
    it('unshare(CLONE_FS) detaches caller: child chdir does not affect parent (bug #2)', async () => {
      const proc = mockProcReader({
        9601: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-fs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9602: {
          ppid: 9601,
          env: {
            npm_package_name: 'unshare-fs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Seed pid 9601 with a known cwd state.
        {
          pid: 9601,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with CLONE_FS → cwd is shared.
        {
          pid: 9601,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 9602',
          source: 'strace',
        },
        // Parent chdirs to /A — under shared CLONE_FS this would also
        // be the child's cwd.
        {
          pid: 9601,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Child detaches its cwd group via unshare(CLONE_FS).
        {
          pid: 9602,
          line: 'unshare(CLONE_FS) = 0',
          source: 'strace',
        },
        // Child chdirs to /B — kernel mutates ONLY the child's now-
        // private fs struct.  Pre-fix this would also rebind the
        // parent's cwd (shared group).
        {
          pid: 9602,
          line: 'chdir("/B") = 0',
          source: 'strace',
        },
        // Parent AT_FDCWD-relative openat — must resolve through /A.
        {
          pid: 9601,
          line: 'openat(AT_FDCWD, "file.parent", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child AT_FDCWD-relative openat — must resolve through /B.
        {
          pid: 9602,
          line: 'openat(AT_FDCWD, "file.child", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9601 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file.parent' && r['pid'] === 9601;
      });
      expect(parentRead).toHaveLength(1);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.child' && r['pid'] === 9602;
      });
      expect(childRead).toHaveLength(1);
      // Sanity: parent MUST NOT see /B (child mutation leaked).
      const bleed = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.parent' && r['pid'] === 9601;
      });
      expect(bleed).toHaveLength(0);
    });

    // Test #5 — unshare with numeric flags.  Strace (or a libc on a
    // kernel without symbolic flag knowledge) may render the flag as
    // hex (`0x400`) or decimal (`1024`).  Both forms MUST trigger the
    // CLONE_FILES detach.
    it('unshare(2) accepts numeric (hex + decimal) CLONE_FILES flags (bug #2)', async () => {
      // ---------- hex form (0x400) ----------
      const procHex = mockProcReader({
        9701: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-hex-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9702: {
          ppid: 9701,
          env: {
            npm_package_name: 'unshare-hex-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const hexRecords: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 9701,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 9701,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 9702',
          source: 'strace',
        },
        // Hex-encoded CLONE_FILES.
        { pid: 9702, line: 'unshare(0x400) = 0', source: 'strace' },
        {
          pid: 9702,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        { pid: 9702, line: 'dup2(8, 7) = 7', source: 'strace' },
        { pid: 9701, line: 'openat(7, "file", O_RDONLY) = 4', source: 'strace' },
      ];
      const hexEmit = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(hexRecords, 0, { rootPid: 9701 }),
        attribution: new Attribution(procHex),
        emitter: hexEmit.emitter,
      });
      const hexEvents = hexEmit.lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Detach happened → parent's fd 7 still /A.
      const hexParentRead = hexEvents.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 9701;
      });
      expect(hexParentRead).toHaveLength(1);

      // ---------- decimal form (1024) ----------
      const procDec = mockProcReader({
        9801: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-dec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9802: {
          ppid: 9801,
          env: {
            npm_package_name: 'unshare-dec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const decRecords: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 9801,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 9801,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 9802',
          source: 'strace',
        },
        // Decimal-encoded CLONE_FILES (= 0x400 = 1024).
        { pid: 9802, line: 'unshare(1024) = 0', source: 'strace' },
        {
          pid: 9802,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        { pid: 9802, line: 'dup2(8, 7) = 7', source: 'strace' },
        { pid: 9801, line: 'openat(7, "file", O_RDONLY) = 4', source: 'strace' },
      ];
      const decEmit = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(decRecords, 0, { rootPid: 9801 }),
        attribution: new Attribution(procDec),
        emitter: decEmit.emitter,
      });
      const decEvents = decEmit.lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const decParentRead = decEvents.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 9801;
      });
      expect(decParentRead).toHaveLength(1);
    });

    // Test #6 — unshare with flag bits we don't model (e.g. a namespace
    // bit like CLONE_NEWUTS = 0x4000000) MUST be ignored.  The fd
    // group stays shared; a subsequent dup2 in the caller still
    // mutates the sibling's view.
    it('unshare(2) with unknown flag bits is a no-op (bug #2)', async () => {
      const proc = mockProcReader({
        9901: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-noop-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        9902: {
          ppid: 9901,
          env: {
            npm_package_name: 'unshare-noop-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 9901,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 9901,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES, child_tidptr=0x7f...) = 9902',
          source: 'strace',
        },
        // Unknown bit (0x4000000 = CLONE_NEWUTS).  Our model does NOT
        // track namespace separations — the fd group should remain
        // shared and the dup2 below should mutate the sibling's view.
        { pid: 9902, line: 'unshare(0x4000000) = 0', source: 'strace' },
        {
          pid: 9902,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // dup2 in the (still-shared) group — both pids' fd 7 now aliases /B.
        { pid: 9902, line: 'dup2(8, 7) = 7', source: 'strace' },
        // Parent openat(7) — resolves through /B (proves no detach).
        { pid: 9901, line: 'openat(7, "file", O_RDONLY) = 4', source: 'strace' },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 9901 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat(7) resolves through /B → /B/file: detach
      // didn't happen, fd group stayed shared.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file' && r['pid'] === 9901;
      });
      expect(parentRead).toHaveLength(1);
      // Sanity: there's no read of /A/file (which would indicate a
      // bogus detach kept the parent's pre-dup view).
      const stale = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 9901;
      });
      expect(stale).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19): unshare(2) kernel-implied
    // detaches.  unshare(CLONE_NEWNS) makes the kernel implicitly call
    // unshare_fs for the caller (the new mount namespace must own a
    // private fs_struct).  unshare(CLONE_NEWUSER) implicitly unshares
    // BOTH fs_struct and files_struct on Linux 3.8+ — the new user
    // namespace needs private caches.  Pre-fix the unshare flag parser
    // only honored the literal CLONE_FS / CLONE_FILES bits, so a
    // `clone(CLONE_FS); unshare(CLONE_NEWNS)` chain stayed modeled as
    // shared-cwd and subsequent chdirs leaked across the (kernel-
    // detached) cwd group.

    // Test #7 — clone(CLONE_FS) + unshare(CLONE_NEWNS).  Parent + child
    // share cwd via clone(CLONE_FS).  Child unshare(CLONE_NEWNS) →
    // kernel implies CLONE_FS detach.  Child chdir(/B), parent
    // chdir(/A).  Post-fix: AT_FDCWD-relative openat resolves through
    // each pid's private cwd.
    it('unshare(CLONE_NEWNS) implies CLONE_FS detach (kernel-implied)', async () => {
      const proc = mockProcReader({
        10001: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-newns-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        10002: {
          ppid: 10001,
          env: {
            npm_package_name: 'unshare-newns-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Seed pid 10001 with a known cwd state.
        {
          pid: 10001,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with CLONE_FS → cwd shared.
        {
          pid: 10001,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 10002',
          source: 'strace',
        },
        // Child unshare(CLONE_NEWNS) — kernel implies CLONE_FS detach.
        {
          pid: 10002,
          line: 'unshare(CLONE_NEWNS) = 0',
          source: 'strace',
        },
        // Child chdirs to /B — MUST NOT leak into the parent.
        {
          pid: 10002,
          line: 'chdir("/B") = 0',
          source: 'strace',
        },
        // Parent chdirs to /A — MUST NOT leak into the child.
        {
          pid: 10001,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Parent AT_FDCWD-relative openat — must resolve through /A.
        {
          pid: 10001,
          line: 'openat(AT_FDCWD, "file.parent", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child AT_FDCWD-relative openat — must resolve through /B.
        {
          pid: 10002,
          line: 'openat(AT_FDCWD, "file.child", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 10001 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file.parent' && r['pid'] === 10001;
      });
      expect(parentRead).toHaveLength(1);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.child' && r['pid'] === 10002;
      });
      expect(childRead).toHaveLength(1);
      // Sanity: parent MUST NOT see /B (child chdir leaked).
      const bleed = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.parent' && r['pid'] === 10001;
      });
      expect(bleed).toHaveLength(0);
    });

    // Test #8 — clone(CLONE_FS|CLONE_FILES) + unshare(CLONE_NEWUSER).
    // Parent + child share both cwd and fd table.  Child
    // unshare(CLONE_NEWUSER) → kernel implies CLONE_FS detach ONLY
    // (NOT CLONE_FILES — `ksys_unshare` in kernel/fork.c only calls
    // `unshare_fd` when CLONE_FILES is explicitly set; CLONE_NEWUSER
    // implies CLONE_THREAD|CLONE_FS, not CLONE_FILES).  Post-fix:
    //   - cwd groups detach   → parent chdir(/A), child chdir(/B) do
    //     not leak across the (now-private) fs_structs;
    //   - fd table stays shared → child dup2 into parent's fd 8 still
    //     mutates the parent's modeled fd table.
    it('unshare(CLONE_NEWUSER) implies CLONE_FS detach only (NOT CLONE_FILES)', async () => {
      const proc = mockProcReader({
        10101: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-newuser-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        10102: {
          ppid: 10101,
          env: {
            npm_package_name: 'unshare-newuser-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Seed pid 10101 with a known cwd state.
        {
          pid: 10101,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with CLONE_FS|CLONE_FILES → cwd + fd table shared.
        {
          pid: 10101,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 10102',
          source: 'strace',
        },
        // Parent opens /A → fd 8 in the SHARED fd group BEFORE the
        // unshare(CLONE_NEWUSER).  This entry must remain visible to
        // the child after the unshare, because CLONE_NEWUSER does not
        // detach the fd table.
        {
          pid: 10101,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Child unshare(CLONE_NEWUSER) — kernel implies CLONE_FS
        // detach only.  fd table stays shared.
        {
          pid: 10102,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        // Cwd MUST detach: child chdirs to /B, parent chdirs to /A,
        // and neither leaks into the other's AT_FDCWD resolution.
        { pid: 10102, line: 'chdir("/B") = 0', source: 'strace' },
        { pid: 10101, line: 'chdir("/A") = 0', source: 'strace' },
        // Parent AT_FDCWD-relative openat — must resolve through /A.
        {
          pid: 10101,
          line: 'openat(AT_FDCWD, "file.parent", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child AT_FDCWD-relative openat — must resolve through /B.
        {
          pid: 10102,
          line: 'openat(AT_FDCWD, "file.child", O_RDONLY) = 5',
          source: 'strace',
        },
        // fd table MUST stay shared: child uses parent-opened fd 8 to
        // resolve a relative path — this must produce /A/c, proving
        // the shared fd-group survived the unshare.
        {
          pid: 10102,
          line: 'openat(8, "c", O_RDONLY) = 9',
          source: 'strace',
        },
        // Parent's own fd 8 still resolves too.
        {
          pid: 10101,
          line: 'openat(8, "p", O_RDONLY) = 6',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 10101 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Cwd-group detach: parent's AT_FDCWD opens resolve through /A.
      const parentReadCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file.parent' && r['pid'] === 10101;
      });
      expect(parentReadCwd).toHaveLength(1);
      // Cwd-group detach: child's AT_FDCWD opens resolve through /B.
      const childReadCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.child' && r['pid'] === 10102;
      });
      expect(childReadCwd).toHaveLength(1);
      // Sanity: cwds didn't leak across the (correctly-detached) fs group.
      const bleedCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' &&
          ((r['path'] === '/B/file.parent' && r['pid'] === 10101) ||
            (r['path'] === '/A/file.child' && r['pid'] === 10102))
        );
      });
      expect(bleedCwd).toHaveLength(0);
      // fd-group STAYS shared after CLONE_NEWUSER: child's openat(8, "c")
      // must resolve through fd 8 = /A → /A/c.  This is the regression
      // gate against the prior over-detach.
      const childReadFd8 = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/c' && r['pid'] === 10102;
      });
      expect(childReadFd8).toHaveLength(1);
      // Parent's fd 8 still resolves to /A/p.
      const parentReadFd8 = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/p' && r['pid'] === 10101;
      });
      expect(parentReadFd8).toHaveLength(1);
    });

    // Test #8b — regression gate against the previous over-detach.
    // `clone(CLONE_FILES) + unshare(CLONE_NEWUSER)` must NOT detach
    // the fd group: per kernel/fork.c::ksys_unshare, CLONE_NEWUSER
    // implies CLONE_THREAD|CLONE_FS, not CLONE_FILES.  Subsequent
    // child fd-table mutations (dup2/close) must still propagate to
    // the parent's modeled state.
    it('clone(CLONE_FILES) + unshare(CLONE_NEWUSER) does NOT detach fd group (regression)', async () => {
      const proc = mockProcReader({
        10501: {
          ppid: 1,
          env: {
            npm_package_name: 'newuser-no-fd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        10502: {
          ppid: 10501,
          env: {
            npm_package_name: 'newuser-no-fd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Seed pid 10501.
        {
          pid: 10501,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with CLONE_FILES → fd table is shared.
        {
          pid: 10501,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 10502',
          source: 'strace',
        },
        // Parent opens /A → fd 7 in the shared group.
        {
          pid: 10501,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_NEWUSER) — kernel does NOT detach the
        // fd table (no CLONE_FILES in the unshare flags).
        {
          pid: 10502,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        // Child opens /B → fd 8 in the (still shared) group.
        {
          pid: 10502,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Parent uses child-opened fd 8 — must resolve through /B
        // because the fd table is still shared.
        {
          pid: 10501,
          line: 'openat(8, "p", O_RDONLY) = 4',
          source: 'strace',
        },
        // Child uses parent-opened fd 7 — must resolve through /A
        // because the fd table is still shared.
        {
          pid: 10502,
          line: 'openat(7, "c", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 10501 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent reads via child-opened fd 8 → /B/p (proves fd group
      // is still shared).
      const parentCrossFd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/p' && r['pid'] === 10501;
      });
      expect(parentCrossFd).toHaveLength(1);
      // Child reads via parent-opened fd 7 → /A/c (proves fd group
      // is still shared in the other direction too).
      const childCrossFd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/c' && r['pid'] === 10502;
      });
      expect(childCrossFd).toHaveLength(1);
    });

    // Test #9 — unshare(CLONE_NEWNS) in hex form (0x20000).  The numeric
    // path of the flag parser must recognise the bit and trigger the
    // implicit CLONE_FS detach.
    it('unshare(0x20000 = CLONE_NEWNS) implies CLONE_FS detach via numeric parse', async () => {
      const proc = mockProcReader({
        10201: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-newns-hex-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        10202: {
          ppid: 10201,
          env: {
            npm_package_name: 'unshare-newns-hex-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 10201,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        {
          pid: 10201,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 10202',
          source: 'strace',
        },
        // Hex-encoded CLONE_NEWNS (= 0x20000).
        { pid: 10202, line: 'unshare(0x20000) = 0', source: 'strace' },
        { pid: 10202, line: 'chdir("/B") = 0', source: 'strace' },
        { pid: 10201, line: 'chdir("/A") = 0', source: 'strace' },
        {
          pid: 10201,
          line: 'openat(AT_FDCWD, "file.parent", O_RDONLY) = 4',
          source: 'strace',
        },
        {
          pid: 10202,
          line: 'openat(AT_FDCWD, "file.child", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 10201 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file.parent' && r['pid'] === 10201;
      });
      expect(parentRead).toHaveLength(1);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.child' && r['pid'] === 10202;
      });
      expect(childRead).toHaveLength(1);
      const bleed = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/file.parent' && r['pid'] === 10201;
      });
      expect(bleed).toHaveLength(0);
    });

    // Test #10 — unshare(CLONE_NEWUSER) in decimal form (268435456).
    // The numeric path must recognise the bit and trigger the
    // implicit CLONE_FS detach.  CLONE_NEWUSER does NOT imply
    // CLONE_FILES (see ksys_unshare in kernel/fork.c) — the fd table
    // must remain shared.
    it('unshare(268435456 = CLONE_NEWUSER) implies CLONE_FS detach only via decimal parse', async () => {
      const proc = mockProcReader({
        10301: {
          ppid: 1,
          env: {
            npm_package_name: 'unshare-newuser-dec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        10302: {
          ppid: 10301,
          env: {
            npm_package_name: 'unshare-newuser-dec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 10301,
          line: 'openat(AT_FDCWD, "/usr/bin/node", O_RDONLY|O_CLOEXEC) = 3',
          source: 'strace',
        },
        // Parent clones with both CLONE_FS and CLONE_FILES → shared.
        {
          pid: 10301,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 10302',
          source: 'strace',
        },
        // Parent opens /A → fd 7 in the shared fd group BEFORE the
        // unshare.  This entry must survive in the modeled fd table
        // (decimal CLONE_NEWUSER does not detach fds).
        {
          pid: 10301,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Decimal-encoded CLONE_NEWUSER (= 0x10000000 = 268435456).
        { pid: 10302, line: 'unshare(268435456) = 0', source: 'strace' },
        // Cwd group MUST detach: child chdir(/B), parent chdir(/A).
        { pid: 10302, line: 'chdir("/B") = 0', source: 'strace' },
        { pid: 10301, line: 'chdir("/A") = 0', source: 'strace' },
        // Parent AT_FDCWD-relative opens through /A.
        {
          pid: 10301,
          line: 'openat(AT_FDCWD, "p", O_RDONLY) = 6',
          source: 'strace',
        },
        // Child AT_FDCWD-relative opens through /B.
        {
          pid: 10302,
          line: 'openat(AT_FDCWD, "c", O_RDONLY) = 9',
          source: 'strace',
        },
        // fd group MUST stay shared: child uses parent-opened fd 7 →
        // /A/x.
        {
          pid: 10302,
          line: 'openat(7, "x", O_RDONLY) = 11',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 10301 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Cwd detach: parent AT_FDCWD opens /A/p, child AT_FDCWD opens /B/c.
      const parentCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/p' && r['pid'] === 10301;
      });
      expect(parentCwd).toHaveLength(1);
      const childCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/c' && r['pid'] === 10302;
      });
      expect(childCwd).toHaveLength(1);
      // fd group stays shared: child reads via parent-opened fd 7 → /A/x.
      const childCrossFd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 10302;
      });
      expect(childCrossFd).toHaveLength(1);
      // Sanity: no cwd cross-leak.
      const bleedCwd = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' &&
          ((r['path'] === '/B/p' && r['pid'] === 10301) ||
            (r['path'] === '/A/c' && r['pid'] === 10302))
        );
      });
      expect(bleedCwd).toHaveLength(0);
    });
  });

  // Codex follow-up (high, 2026-05-19; refined medium, 2026-05-19):
  // out-of-order unshare BEFORE clone reconciliation.  strace `-ff`
  // writes per-pid files separately and the production tailer drains
  // them in arbitrary order, so a child's
  // `unshare(CLONE_NEWUSER|CLONE_FILES|...)` line CAN reach the
  // dispatcher BEFORE the parent's `clone(... CLONE_FS|CLONE_FILES ...)
  // = <child>` line that pairs them.
  //
  // Pre-fix wire-order:
  //   1. Child unshare line arrives.  Child is still a singleton group
  //      (its own pid) so the immediate detach is a no-op.
  //   2. Parent clone line arrives.  Reconciliation unions parent and
  //      child into the SAME cwd/fd group — re-merging the kernel-
  //      detached child back into the parent's state.
  //
  // Initial fix (commit 69006d2): clone reconciliation SKIPS the
  // union when a pending-detach marker is present.  That stopped the
  // re-merge bug but introduced a new false-positive: the child's
  // group ended up EMPTY (no cwd, no fd entries), so legitimate child
  // code that uses INHERITED paths emitted `<UNRESOLVED_PATH>`
  // audit_bypass entries.
  //
  // Refined fix (medium, 2026-05-19): clone reconciliation takes the
  // COPY branch when the marker is present — parent's cwd/fd state is
  // snapshotted into the child's PRIVATE group.  This emulates the
  // real kernel order (clone → child inherits → unshare → kernel
  // detaches into a private copy whose initial value equals the
  // pre-unshare shared state).  Future mutations on either side stay
  // private to their own group.
  describe('pending unshare-detach honored by delayed clone reconciliation', () => {
    const EVENTS_FILE = '/tmp/script-jail-events/events.jsonl';

    // Test 1: child unshare(CLONE_NEWUSER) is observed BEFORE the
    // parent's clone(CLONE_FS) line.  Post-refined-fix the parent's
    // pre-clone cwd MUST be copied into the child's private group
    // (kernel clone+private-copy semantic).  Parent's LATER chdir
    // must not affect the child's inherited cwd.
    it('child unshare(CLONE_NEWUSER) before parent clone(CLONE_FS) → inherited cwd copied to child, parent mutation does not leak', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'pending-cwd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'pending-cwd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Out-of-order: child's unshare(CLONE_NEWUSER) reaches the
        // dispatcher FIRST.  CLONE_NEWUSER kernel-implies CLONE_FS
        // detach.  Child is still a singleton group at this point so
        // the immediate detach is a no-op — the pending marker is the
        // only state that matters here.
        {
          pid: 1001,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        // Parent's clone(CLONE_FS) line arrives LATER.  Pre-fix this
        // would `unionCwd(parent, child)`; initial-fix would SKIP the
        // union (leaving child with no cwd → false positives).  The
        // refined fix copies parent's cwd (= input.cwd seed = /work)
        // into the child's private group.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent chdirs to /A.  This mutates ONLY parent's group;
        // child's private cwd remains /work (kernel detach semantic).
        {
          pid: 1000,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Child AT_FDCWD-relative openat.  Resolves through the
        // child's inherited cwd (/work), NOT the parent's post-clone
        // cwd (/A).
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // The child's openat MUST NOT resolve to /A/x — that would be
      // the union bug (parent's post-clone chdir leaking into the
      // detached child).
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(leaked).toHaveLength(0);
      // Child's openat MUST resolve to /work/x via the inherited cwd.
      const inherited = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/work/x' && r['pid'] === 1001;
      });
      expect(inherited).toHaveLength(1);
      // No <UNRESOLVED_PATH> for the child — copy succeeded.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Test 2: child unshare(CLONE_FILES) is observed BEFORE the parent's
    // clone(CLONE_FILES) line.  Post-fix the fd-group union is skipped.
    // The parent's later-opened fd 7 must NOT be visible to the child.
    it('child unshare(CLONE_FILES) before parent clone(CLONE_FILES) → fd union skipped, child openat(fd) fails closed', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'pending-fd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'pending-fd-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Out-of-order: child's unshare(CLONE_FILES) reaches the
        // dispatcher FIRST.  No-op detach at this moment (child is
        // its own singleton), but the pending marker is recorded.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Parent's clone(CLONE_FILES) arrives LATER.  Pre-fix this
        // would `unionFd(parent, child)` and re-merge the kernel-
        // detached child back into the parent's fd group.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent opens /A → fd 7 in its (post-skip) private fd group.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child openat(7, ...).  Pre-fix the union would have made
        // fd 7 visible to the child via the shared root, certifying
        // the read to /A/file.  Post-fix fd 7 is NOT in the child's
        // group → dirfdTable miss → fail closed.
        {
          pid: 1001,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Pre-fix the child would have certified a read to /A/file.
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/file' && r['pid'] === 1001;
      });
      expect(leaked).toHaveLength(0);
      // <UNRESOLVED_PATH> audit_bypass surfaced for the child.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Test 3: regression — normal clone(CLONE_FS) WITHOUT a pending
    // marker still unions correctly.  The pending-detach guard must
    // not break the happy path.
    it('normal clone(CLONE_FS) without pending marker still unions cwd group', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'no-pending-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'no-pending-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent clones with CLONE_FS — no prior unshare on either side.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent chdirs to /A — shared cwd group, so child's AT_FDCWD
        // resolves through /A too.
        {
          pid: 1000,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Child AT_FDCWD-relative openat — MUST resolve to /A/x via
        // the union'd cwd group.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child's openat must resolve to /A/x (union happened).
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> for the child — union succeeded.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Regression test 1 (medium, 2026-05-19): inherited cwd survives a
    // child-first unshare.  Parent chdirs to /A FIRST, then we observe
    // the child's unshare out-of-order, then the parent's clone(CLONE_FS).
    // Post-refined-fix: child inherits /A (kernel clone+private-copy
    // semantic — child's private fs_struct starts as a copy of the
    // shared state at unshare time, which equals parent's cwd at clone
    // time since the parent didn't chdir between clone and unshare).
    it('inherited cwd survives child-first unshare: parent chdir before clone copies to child private group', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'inherit-cwd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'inherit-cwd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A) BEFORE the clone.  At kernel time, the
        // child clone will inherit /A; the later unshare detaches
        // child's fs_struct into a private copy that ALSO starts at
        // /A.
        {
          pid: 1000,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Out-of-order: child unshare(CLONE_NEWUSER) arrives before
        // the parent clone line.  Pending marker recorded.
        {
          pid: 1001,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        // Parent clone(CLONE_FS) — reconciliation consumes the pending
        // marker and takes the COPY branch (parent's cwd /A → child).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(AT_FDCWD, "x") — resolves through inherited /A.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Regression test 2 (medium, 2026-05-19): inherited dirfd entries
    // survive a child-first unshare(CLONE_FILES).  Parent opens fd 7 →
    // /somedir BEFORE the clone; child unshare arrives out-of-order;
    // parent clone(CLONE_FILES) reconciles.  Post-refined-fix: child's
    // private fd table starts as a copy of the shared fd table; child
    // openat(7, "file") MUST resolve through the inherited entry.
    it('inherited dirfd survives child-first unshare: parent fd opened before clone copies to child private group', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'inherit-fd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'inherit-fd-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /somedir as fd 7 BEFORE the clone.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/somedir", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Out-of-order: child unshare(CLONE_FILES) before clone.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Parent clone(CLONE_FILES) — reconciliation consumes the
        // pending fd-detach marker, takes the COPY branch, snapshots
        // parent's dirfd table (fd 7 → /somedir) into child's private
        // group.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "file") — resolves through inherited fd 7.
        {
          pid: 1001,
          line: 'openat(7, "file", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/somedir/file' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Regression test 3 (medium, 2026-05-19): parent's post-unshare
    // mutation does NOT propagate to the child (detach semantic).
    // After the pending-detach copy: parent chdirs to /B and observes
    // its own openat resolving to /B/x; a SECOND child openat(y) still
    // resolves through the child's inherited /A cwd, NOT /B.
    it('post-unshare parent mutation does not affect child: groups are private after copy', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-detach-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        {
          pid: 1000,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        {
          pid: 1001,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent chdir(/B) AFTER the child has its own private group.
        {
          pid: 1000,
          line: 'chdir("/B") = 0',
          source: 'strace',
        },
        // Parent open(x) resolves through /B.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
        // Child open(y) STILL resolves through /A (its inherited cwd
        // at clone-time — parent's later chdir does not propagate).
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "y", O_RDONLY) = 6',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat resolves to /B/x.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child's openat resolves to /A/y (NOT /B/y).
      const childAReads = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/y' && r['pid'] === 1001;
      });
      expect(childAReads).toHaveLength(1);
      const childBLeaks = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/y' && r['pid'] === 1001;
      });
      expect(childBLeaks).toHaveLength(0);
    });

    // Regression test 4 (medium, 2026-05-19): conflicting child state
    // BEFORE the clone reconciliation triggers conservative fail-closed.
    // Parent chdir(/A), child chdir(/B) (raced ahead with its own
    // syscall), child unshare, parent clone(CLONE_FS) — the copy
    // branch sees parent=/A and child=/B disagreeing.  Fail closed:
    // mark child cwdUnknown; subsequent openat surfaces
    // <UNRESOLVED_PATH>.
    it('conflicting child state before pending-detach copy → cwdUnknown, openat fails closed', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'conflict-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'conflict-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A) FIRST.
        {
          pid: 1000,
          line: 'chdir("/A") = 0',
          source: 'strace',
        },
        // Child has already chdir'd to /B independently.
        {
          pid: 1001,
          line: 'chdir("/B") = 0',
          source: 'strace',
        },
        // Child unshare arrives out-of-order before clone.
        {
          pid: 1001,
          line: 'unshare(CLONE_NEWUSER) = 0',
          source: 'strace',
        },
        // Parent clone(CLONE_FS) — copy branch reconciles parent=/A
        // vs child=/B.  Conflict → mark child cwdUnknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat — cwdUnknown dominates → fail closed.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // No certified read at /A/x or /B/x for the child.
      const aRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(aRead).toHaveLength(0);
      const bRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(bRead).toHaveLength(0);
      // <UNRESOLVED_PATH> surfaced for the child.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19): pending-detach cwd conflict
    // must taint BOTH parent and child.  The real kernel order is
    //   1. parent chdir(/A)             — parent cwd = /A
    //   2. clone(CLONE_FS)              — child shares the fs_struct
    //   3. child chdir(/root)           — SHARED mutation: both
    //                                     parent AND child now see /root
    //   4. child unshare(CLONE_NEWUSER) — kernel detaches; both retain
    //                                     /root, but now independent.
    // If strace surfaces steps 3+4 before step 2's clone line and we
    // reconcile at step 2 with parent=/A vs child=/root, the post-step-3
    // shared value (/root) is unrecoverable from the model.  Fail closed
    // on BOTH sides: parent's stale modeled /A must not be trusted for
    // its own AT_FDCWD-relative opens either.
    it('pending-cwd-detach conflict taints BOTH parent and child (bug #1)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'cwd-taint-both-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'cwd-taint-both-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A) at the start: parent cwd = /A.
        { pid: 1000, line: 'chdir("/A") = 0', source: 'strace' },
        // Child chdir(/root) — at strace-wire time this was the SHARED
        // group, so the kernel mutated BOTH.  In our model, child is
        // still a singleton (we haven't seen the clone) so this just
        // sets child cwd = /root.
        { pid: 1001, line: 'chdir("/root") = 0', source: 'strace' },
        // Child unshare — pending marker.
        { pid: 1001, line: 'unshare(CLONE_NEWUSER) = 0', source: 'strace' },
        // Parent clone(CLONE_FS) — reconcile: parent=/A vs child=/root
        // disagree under a pending marker → taint both.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent AT_FDCWD openat — must fail closed (parent cwd was
        // tainted).  Pre-fix this resolved through /A and could miss
        // an out-of-tree protected-paths match like /root/.ssh/id_rsa.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat MUST NOT resolve to /A/.ssh/id_rsa — that's
      // the stale-modeled-cwd bug.
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/.ssh/id_rsa' && r['pid'] === 1000;
      });
      expect(leaked).toHaveLength(0);
      // <UNRESOLVED_PATH> surfaced for the parent — parent's cwd was
      // tainted by the pending-detach conflict.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19): pending-detach fd conflict
    // must drop BOTH parent and child fd entries.  The real kernel
    // order is
    //   1. parent openat → fd 7 = /safe
    //   2. child openat → fd 99 = /root
    //   3. child dup2(99, 7) — SHARED mutation: fd 7 now points at
    //      /root for BOTH sides
    //   4. child unshare(CLONE_FILES) — kernel detaches.
    // If strace surfaces 2+3+4 before the parent's clone, reconciling
    // sees parent fd 7 → /safe vs child fd 7 → /root.  The actual
    // shared post-step-3 state was /root.  Without tainting parent,
    // parent's openat(7, ...) would still resolve through /safe and
    // miss protected-paths in /root.
    it('pending-fd-detach conflict drops BOTH parent and child fd entries (bug #2)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'fd-taint-both-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'fd-taint-both-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /safe as fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/safe", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child opens /root as fd 99.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/root", O_RDONLY|O_DIRECTORY) = 99',
          source: 'strace',
        },
        // Child dup2(99, 7) — in the kernel this mutated the shared
        // table.  In our model child is still a singleton, so this
        // sets child fd 7 → /root locally.
        { pid: 1001, line: 'dup2(99, 7) = 7', source: 'strace' },
        // Child unshare(CLONE_FILES) — pending fd-detach marker.
        { pid: 1001, line: 'unshare(CLONE_FILES) = 0', source: 'strace' },
        // Parent clone(CLONE_FILES) — reconcile: parent fd 7 → /safe
        // vs child fd 7 → /root.  Conflict + pending marker → drop
        // BOTH fd-7 entries and mark both groups fd-unknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, ".ssh/id_rsa") — MUST fail closed (stale
        // fd 7 entry was dropped by the conflict).
        {
          pid: 1000,
          line: 'openat(7, ".ssh/id_rsa", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat MUST NOT resolve to /safe/.ssh/id_rsa — that's
      // the stale-fd-entry bug.
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' && r['path'] === '/safe/.ssh/id_rsa' && r['pid'] === 1000
        );
      });
      expect(leaked).toHaveLength(0);
      // <UNRESOLVED_PATH> surfaced for the parent — parent's fd 7
      // entry was dropped by the pending-detach conflict.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19): regression preservation —
    // when there's NO prior child state to conflict with, the copy
    // branch still inherits parent's cwd into the child's private
    // group.  Same shape as bug #1 minus the child's pre-clone chdir.
    it('pending-cwd-detach without conflict still copies parent cwd to child (no regression)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'no-conflict-copy-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'no-conflict-copy-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A).
        { pid: 1000, line: 'chdir("/A") = 0', source: 'strace' },
        // Child unshare — pending marker.  No prior child chdir, so
        // child has no cwd state of its own.
        { pid: 1001, line: 'unshare(CLONE_NEWUSER) = 0', source: 'strace' },
        // Parent clone(CLONE_FS) — copy branch installs parent's /A
        // into child's private group (no conflict path triggered).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(AT_FDCWD, "x") — resolves to /A/x via inherited
        // cwd.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child's openat resolves to /A/x — inherited cwd preserved
      // when no conflict.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> for child — copy succeeded with no
      // conflict.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19, bug #1): pending CWD detach
    // reconciliation must taint the PARENT too when the child carries
    // `cwdUnknown` (e.g. from a relative chdir off an untracked cwd).
    // Pre-fix the parent-taint branch only fired on known-vs-known
    // cwd mismatches; in the kernel-real syscall order, the cwd
    // mutation that made the child unknown happened under shared
    // fs_struct, so the parent's cwd is just as stale.
    //
    // Sequence (kernel-real):
    //   1. parent chdir(/A)                  — fs.cwd = /A (parent's struct)
    //   2. clone(CLONE_FS)                   — child shares fs_struct
    //   3. child chdir(<relative-from-X>)    — kernel updates the SHARED
    //                                          struct to fs.cwd = X
    //                                          (whatever the relative
    //                                          resolves to in the kernel)
    //   4. child unshare(CLONE_NEWUSER)      — kernel splits the struct;
    //                                          both sides retain X.
    //
    // In our model, the child's chdir(<relative>) from an untracked
    // cwd lands it in `cwdUnknownHas(childPid) === true`.  The parent's
    // pre-clone modeled value (/A) is stale because the SHARED mutation
    // at step (3) moved cwd to <somewhere we don't know>.  Reconciling
    // a delayed clone(CLONE_FS) with childCwdUnknown=true MUST taint
    // the parent's cwd too.
    it('pending-cwd-detach with child-cwdUnknown taints BOTH parent and child (bug #1)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'cwd-unknown-taint-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'cwd-unknown-taint-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A) — parent cwd = /A.  Pid 1000 is rootPid;
        // the dispatcher seeds it with input.cwd before this chdir
        // lands, then the absolute chdir overwrites it to /A.
        { pid: 1000, line: 'chdir("/A") = 0', source: 'strace' },
        // Child relative chdir from an untracked cwd — marks pid 1001
        // as cwdUnknown.  Pre-fix the reconciliation only inspected
        // the known-vs-known mismatch branch, so this branch leaked.
        { pid: 1001, line: 'chdir("subdir") = 0', source: 'strace' },
        // Child unshare — sets pendingCwdDetach.
        { pid: 1001, line: 'unshare(CLONE_NEWUSER) = 0', source: 'strace' },
        // Delayed parent clone(CLONE_FS) — reconciliation must see
        // child cwdUnknown + pendingDetachShared → taint both.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent AT_FDCWD openat — MUST fail closed.  Pre-fix this
        // resolved to /A/.ssh/id_rsa (stale modeled cwd) and missed
        // the protected-paths match in the kernel-real cwd.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, ".ssh/id_rsa", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent must NOT certify a read against the stale /A.
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/.ssh/id_rsa' && r['pid'] === 1000;
      });
      expect(leaked).toHaveLength(0);
      // <UNRESOLVED_PATH> for the parent — parent was tainted by
      // the pending-detach reconciliation under child cwdUnknown.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #2): pending FD detach
    // reconciliation must catch untracked-source dup conflicts.
    //
    // Sequence (kernel-real):
    //   1. parent: openat → fd 7 = /safe
    //   2. clone(CLONE_FILES) — child shares files_struct
    //   3. child: dup2(<untracked>, 7) — kernel rewrites shared fd 7
    //      to point at the untracked target.  Pre-fix the dispatcher
    //      noticed the missing source-fd entry and just deleted
    //      child's fd-7 modeled entry without marking anything
    //      unknown.
    //   4. child: unshare(CLONE_FILES) — pending fd-detach marker.
    //   5. (out-of-order) parent clone(CLONE_FILES) reconciliation.
    //
    // Pre-fix, step (5)'s copy loop saw no parent-vs-child fd
    // conflict (child had no modeled fd 7 entry), so parent's
    // /safe entry survived.  Parent's subsequent openat(7, ...)
    // certified through /safe and missed the protected-paths match
    // in the kernel-real target.
    //
    // Post-fix:
    //   - Step (3) now marks the child's fd-group as fd-state-unknown.
    //   - Step (5)'s reconciliation propagates fd-state-unknown to
    //     the parent and drops parent's fd entries.
    it('pending-fd-detach + child untracked-dup taints BOTH parent and child fd groups (bug #2)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'fd-untracked-dup-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'fd-untracked-dup-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /safe → fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/safe", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child dup2(99, 7) — fd 99 is untracked (never opened in our
        // trace).  Post-fix this marks the child group fd-state-unknown.
        { pid: 1001, line: 'dup2(99, 7) = 7', source: 'strace' },
        // Child unshare(CLONE_FILES) — pendingFdDetach marker.
        { pid: 1001, line: 'unshare(CLONE_FILES) = 0', source: 'strace' },
        // Delayed parent clone(CLONE_FILES) — reconciliation sees
        // child fd-state-unknown + pendingDetachShared → drop parent
        // fd entries + mark both groups fd-unknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, ".ssh/id_rsa") — MUST fail closed.
        {
          pid: 1000,
          line: 'openat(7, ".ssh/id_rsa", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat MUST NOT certify against the stale /safe.
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/safe/.ssh/id_rsa' && r['pid'] === 1000;
      });
      expect(leaked).toHaveLength(0);
      // <UNRESOLVED_PATH> surfaced for parent — fd-group tainted.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #3): pending CWD
    // detach without CLONE_FS in the clone must NOT taint the parent.
    // A clone() without CLONE_FS gives the child its own private
    // fs_struct at kernel level — there was no shared state for an
    // unshare to detach from, so parent's modeled cwd is trustworthy
    // regardless of the pending marker.
    //
    // Pre-fix: childHadPendingCwdDetach was the only gate on the
    // parent-side taint; this branch tainted parent's /A even when
    // the clone never shared.  That over-failed clean installs where
    // the lifecycle script fork()'d without CLONE_FS before unshare.
    it('pending-cwd-detach but clone without CLONE_FS does NOT taint parent (bug #3)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'cwd-no-cloneFs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'cwd-no-cloneFs-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A) — parent cwd = /A.
        { pid: 1000, line: 'chdir("/A") = 0', source: 'strace' },
        // Child chdir(/root) — absolute, sets child cwd = /root.
        { pid: 1001, line: 'chdir("/root") = 0', source: 'strace' },
        // Child unshare(CLONE_NEWUSER) — pendingCwdDetach.  At kernel
        // level this is a no-op for fs_struct because the clone below
        // didn't share.
        { pid: 1001, line: 'unshare(CLONE_NEWUSER) = 0', source: 'strace' },
        // Delayed clone WITHOUT CLONE_FS — child had its own
        // fs_struct from the start; no shared-state mutation could
        // possibly have leaked to the parent.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent AT_FDCWD openat — MUST resolve to /A/x (parent NOT
        // tainted by the pending marker since the clone was non-
        // shared).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's open resolves cleanly to /A/x — pre-fix this was
      // <UNRESOLVED_PATH> because the parent had been tainted.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> for parent (parent's cwd is intact).
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #3): pending FD detach
    // without CLONE_FILES in the clone must NOT taint the parent.
    // Mirror of bug-#3 cwd test for the fd group.  Parent opens fd
    // 7 → /safe; child does a conflicting dup2; child unshare
    // (CLONE_FILES); delayed parent clone() WITHOUT CLONE_FILES.
    // Parent's fd 7 → /safe must survive because the clone never
    // shared the files_struct.
    it('pending-fd-detach but clone without CLONE_FILES does NOT taint parent fd (bug #3)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'fd-no-cloneFiles-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'fd-no-cloneFiles-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /safe → fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/safe", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child opens /root → fd 99 (we want a known-vs-known
        // conflict path in the non-shared reconciliation).
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/root", O_RDONLY|O_DIRECTORY) = 99',
          source: 'strace',
        },
        // Child dup2(99, 7) — child's modeled fd 7 = /root.
        { pid: 1001, line: 'dup2(99, 7) = 7', source: 'strace' },
        // Child unshare(CLONE_FILES) — pendingFdDetach marker.
        { pid: 1001, line: 'unshare(CLONE_FILES) = 0', source: 'strace' },
        // Delayed clone WITHOUT CLONE_FILES — non-shared at kernel
        // level.  Parent's fd 7 → /safe must survive even though
        // a known-vs-known conflict exists with child's fd 7 → /root.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "manifest.json") — must resolve to
        // /safe/manifest.json (parent fd 7 retained /safe).
        {
          pid: 1000,
          line: 'openat(7, "manifest.json", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent's openat resolves to /safe/manifest.json.  Pre-fix
      // the parent was tainted by the pending-detach conflict and
      // this read was dropped → <UNRESOLVED_PATH>.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return (
          r['kind'] === 'read' && r['path'] === '/safe/manifest.json' && r['pid'] === 1000
        );
      });
      expect(parentRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> for parent (parent fd 7 entry survived).
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19, bug #1 fcntl): fcntl with
    // F_DUPFD / F_DUPFD_CLOEXEC from an untracked source fd must mark
    // the pid's fd-group state-unknown, mirroring the dup/dup2/dup3
    // untracked-source path.  Without this, the
    // pending-detach-AND-CLONE_FILES reconciliation can't propagate
    // the unknown bit to the parent and a stale parent fd entry
    // certifies through the wrong directory.
    //
    // Sequence:
    //   1. parent: openat → fd 7 = /safe
    //   2. child:  fcntl(99, F_DUPFD, 7) = 7  — oldfd 99 untracked,
    //              new fd 7 must mark child fd-state-unknown.
    //   3. child:  unshare(CLONE_FILES) — pending fd-detach marker.
    //   4. (out-of-order) parent clone(CLONE_FILES) reconciliation.
    //   5. parent: openat(7, ".ssh/id_rsa") — MUST fail closed.
    it('pending-fd-detach + child fcntl(F_DUPFD) from untracked source taints BOTH (bug #1)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'fcntl-untracked-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'fcntl-untracked-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /safe → fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/safe", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child fcntl(99, F_DUPFD, 7) = 7 — fd 99 untracked.  Post-fix
        // marks the child group fd-state-unknown.
        { pid: 1001, line: 'fcntl(99, F_DUPFD, 7) = 7', source: 'strace' },
        // Child unshare(CLONE_FILES) — pendingFdDetach.
        { pid: 1001, line: 'unshare(CLONE_FILES) = 0', source: 'strace' },
        // Delayed parent clone(CLONE_FILES) — propagate unknown bit
        // through the snapshot, drop parent fd entries, mark both
        // groups unknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, ".ssh/id_rsa") — MUST fail closed.
        {
          pid: 1000,
          line: 'openat(7, ".ssh/id_rsa", O_RDONLY) = 5',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const leaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/safe/.ssh/id_rsa' && r['pid'] === 1000;
      });
      expect(leaked).toHaveLength(0);
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(unresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 snapshot): the
    // pending CWD detach marker captures the child's state AT
    // UNSHARE TIME; post-unshare child mutations stay private to the
    // child's group and MUST NOT taint the parent at clone
    // reconciliation.
    //
    // Sequence:
    //   1. parent: chdir(/A) — parent cwd = /A.
    //   2. child:  unshare(CLONE_NEWUSER) — snapshot is empty (child
    //              had no prior cwd state).
    //   3. child:  chdir(/B) — POST-unshare mutation, private to
    //              child's group.  In our model child now has cwd /B.
    //   4. (out-of-order) parent clone(CLONE_FS) reconciliation.
    //
    // Pre-fix (without snapshot): the reconciler read the CHILD's
    // current cwd (/B) at reconcile time and treated parent=/A vs
    // child=/B as a conflict under pendingDetachShared → tainted
    // BOTH.  Parent's subsequent openat(AT_FDCWD, ...) failed closed
    // even though parent's modeled cwd /A was correct.
    //
    // Post-fix (with snapshot): the reconciler reads snapshot.cwd =
    // undefined (child had no cwd at unshare time).  No conflict
    // against parent's /A → parent stays trustworthy.  Child's /B
    // (its post-detach private mutation) is preserved.
    it('post-unshare child chdir does not taint parent (bug #2 snapshot)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-unshare-chdir-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-unshare-chdir-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent chdir(/A).
        { pid: 1000, line: 'chdir("/A") = 0', source: 'strace' },
        // Child unshare(CLONE_NEWUSER) — snapshot child state (empty)
        // at this moment.  CLONE_NEWUSER implies CLONE_FS detach.
        { pid: 1001, line: 'unshare(CLONE_NEWUSER) = 0', source: 'strace' },
        // Child chdir(/B) — POST-unshare mutation.  In a snapshot-
        // less world this would have been read at reconcile time and
        // mistaken for a pre-unshare shared-state mutation.
        { pid: 1001, line: 'chdir("/B") = 0', source: 'strace' },
        // Delayed parent clone(CLONE_FS).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent AT_FDCWD openat — must resolve to /A/x (parent
        // cwd NOT tainted because snapshot showed no child mutation
        // at unshare time).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "x", O_RDONLY) = 5',
          source: 'strace',
        },
        // Child AT_FDCWD openat — should resolve to /B/y (child's
        // private post-unshare chdir is preserved).
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "y", O_RDONLY) = 6',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: /B/y certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/y' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // Parent must NOT have <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #3 close_range
    // UNSHARE): a singleton child that calls close_range(...,
    // CLOSE_RANGE_UNSHARE) MUST record a pending marker so that a
    // delayed parent clone(CLONE_FILES) reconciliation:
    //   (a) does not re-merge child into parent's group,
    //   (b) copies parent fds into child's private group,
    //   (c) replays the close_range action onto the child copy.
    //
    // Result: child fd 7 → fails closed (kernel close_range honored).
    //         parent fd 7 → resolves through /A (parent retains table).
    it('close_range UNSHARE before delayed clone honors private close (bug #3 close_range)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'close-range-singleton-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'close-range-singleton-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 BEFORE any clone reconciliation.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close_range(3, INT_MAX, CLOSE_RANGE_UNSHARE) at
        // singleton time.  Pre-fix: detach no-op, range applied to
        // empty singleton table — no effect.  Then delayed parent
        // clone(CLONE_FILES) unions child back into parent's group,
        // and child fd 7 (= /A) is "alive" again.  Post-fix: pending
        // marker with replay action records the close_range; clone
        // reconciliation copies parent's fd 7 into child group then
        // replays the close → child's fd 7 dropped.
        {
          pid: 1001,
          line: 'close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed (close_range
        // dropped fd 7 in child's private group).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x (parent
        // retains its own fd 7 entry; close_range was private to
        // child).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified (its fd 7 was closed by the replay).
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // Child: <UNRESOLVED_PATH> for the failing openat.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #3 execve): a
    // singleton child that execve()s with a CLOEXEC fd inherited
    // from the parent MUST record a pending marker so that the
    // delayed parent clone(CLONE_FILES) reconciliation:
    //   (a) does not re-merge child into parent's group,
    //   (b) copies parent fds into child's private group,
    //   (c) replays the CLOEXEC sweep onto the child copy.
    //
    // Result: child fd 7 → fails closed (CLOEXEC swept).
    //         parent fd 7 → resolves through /A (parent didn't execve).
    it('execve before delayed clone sweeps CLOEXEC on child only (bug #3 execve)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'execve-singleton-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'execve-singleton-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 with O_CLOEXEC.  At kernel time
        // this fd is shared with the (yet-to-be-cloned) child;
        // execve from the child triggers a CLOEXEC sweep on the
        // child's private copy only.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 7',
          source: 'strace',
        },
        // Child execve at singleton.  Snapshot captures pre-detach
        // state with replay action = execveCloexec.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed (CLOEXEC swept fd
        // 7 in child's private group).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x (parent did
        // not execve; CLOEXEC sweep is private to child).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified.
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // Child: <UNRESOLVED_PATH> for the failing openat.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #1 — ordered replay):
    // close_range UNSHARE FOLLOWED by execve on a singleton child
    // before the delayed parent clone arrives.  Pre-fix the execve's
    // execveCloexec action overwrote the close_range action in the
    // pending marker, so the reconciler only replayed the CLOEXEC
    // sweep and the close_range-closed fds came back to life in the
    // child group.  Post-fix the actions list is ORDERED and both
    // replay in sequence: close_range removes the range first, then
    // the CLOEXEC sweep runs on what remains.
    it('close_range UNSHARE then execve before delayed clone: ordered replay (bug #1)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'ordered-replay-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'ordered-replay-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (non-CLOEXEC) and fd 8 → /B (CLOEXEC).
        // At kernel time these are shared with the (yet-to-be-cloned)
        // child via CLONE_FILES.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 8',
          source: 'strace',
        },
        // Child close_range(3, INT_MAX, CLOSE_RANGE_UNSHARE) at
        // singleton time — pending action 1: closeRange [3, UINT_MAX].
        {
          pid: 1001,
          line: 'close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Child execve at singleton — pending action 2: execveCloexec.
        // Pre-fix this OVERWROTE action 1.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler:
        // (a) skip union (marker present),
        // (b) copy parent fds 7/8 into child group,
        // (c) replay [closeRange, execveCloexec] in order:
        //     close_range drops fd 7 AND fd 8 from child,
        //     execve sweep is a no-op (table already empty).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed (close_range
        // dropped fd 7 in child group).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
        // Child openat(8, "x") — MUST fail closed (close_range
        // dropped fd 8 too; CLOEXEC didn't get a chance to fire
        // because the close_range removed it first).
        {
          pid: 1001,
          line: 'openat(8, "x", O_RDONLY) = 10',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x (parent
        // retains its own fd 7 — close_range was private to child).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 11',
          source: 'strace',
        },
        // Parent openat(8, "x") — MUST resolve to /B/x (parent
        // didn't execve, so its fd 8's CLOEXEC bit didn't fire).
        {
          pid: 1000,
          line: 'openat(8, "x", O_RDONLY) = 12',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x and /B/x certified.
      const parentA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentA).toHaveLength(1);
      const parentB = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1000;
      });
      expect(parentB).toHaveLength(1);
      // Child: NEITHER /A/x NOR /B/x certified.
      const childLeakedA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeakedA).toHaveLength(0);
      const childLeakedB = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childLeakedB).toHaveLength(0);
      // Child: at least two <UNRESOLVED_PATH> (one per failing openat).
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(2);
    });

    // Codex follow-up (high, 2026-05-19, bug #2 — fcntl tombstone):
    // child fcntl(7, F_SETFD, FD_CLOEXEC) on an UNTRACKED fd before
    // the delayed parent clone arrives.  Without the tombstone, the
    // reconciler would copy parent's non-CLOEXEC fd 7 into the child
    // and the execveCloexec sweep wouldn't fire.  With the tombstone,
    // the copied entry is flipped to cloexec=true and the subsequent
    // execve sweep drops it.
    it('fcntl(F_SETFD, FD_CLOEXEC) on untracked-inherited-fd before delayed clone (bug #2 cloexec tombstone)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'cloexec-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'cloexec-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (non-CLOEXEC).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child fcntl(7, F_SETFD, FD_CLOEXEC) — child's dirfdTable
        // has no entry for fd 7 (parent's clone hasn't reconciled
        // yet), so record a 'cloexec' tombstone.
        {
          pid: 1001,
          line: 'fcntl(7, F_SETFD, FD_CLOEXEC) = 0',
          source: 'strace',
        },
        // Child execve at singleton — creates marker; tombstone is
        // absorbed into the marker at snapshotFd time.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler copies
        // parent's fd 7 into child group, applies tombstone (flips
        // cloexec=true), then replays execveCloexec sweep (drops
        // child fd 7).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x.  The fcntl
        // happened in the child's private (post-detach) table; the
        // shared-state propagation is a residual concern but the
        // tombstone path tags BOTH groups fd-unknown only for the
        // 'close' kind.  For 'cloexec' we only flip the child's
        // copied entry; parent's fd 7 stays /A.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified (cloexec tombstone + execve sweep).
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #2 — close tombstone):
    // child close(7) on an UNTRACKED fd before the delayed parent
    // clone arrives.  The kernel really closed the shared slot; the
    // mutation propagates to all CLONE_FILES siblings.  Without the
    // tombstone, the reconciler would copy parent's fd 7 → /A into
    // the child group; both groups would then certify reads through
    // a kernel-closed fd.  With the tombstone (kind: close), the
    // reconciler drops fd 7 from BOTH groups and marks them
    // fd-unknown for any numeric-dirfd open through fd 7.
    it('close on untracked-inherited-fd before delayed clone (bug #2 close tombstone)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'close-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'close-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close(7) — child's dirfdTable has no entry for fd 7,
        // record 'close' tombstone.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  snapshotFd
        // absorbs the tombstone bucket into the pending marker.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler:
        //   (a) skip union,
        //   (b) copy parent fd 7 into child group,
        //   (c) apply tombstone: drop child fd 7, drop parent fd 7,
        //       mark BOTH fd-unknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST also fail closed; the shared
        // close propagated, parent's modeled fd 7 is gone and the
        // group is fd-unknown.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Neither side resolves /A/x.
      const parentLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeaked).toHaveLength(0);
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // BOTH sides surface <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #1 follow-up — cloexec
    // tombstone PROPAGATES TO PARENT under shared CLONE_FILES):
    // when a pre-detach cloexec tombstone is replayed, the kernel
    // mutation hit the shared files_struct so the parent's fd
    // ALSO gets FD_CLOEXEC set.  A subsequent parent execve must
    // sweep that bit and drop the entry; openat(<fd>, ...) on the
    // parent then fails closed.  Pre-fix only the child's copied
    // entry was flipped; the parent retained cloexec=false and a
    // parent execve found nothing to sweep, so fd survived in
    // the parent's modeled state — kernel-real parent fd was
    // actually swept and post-exec parent openat(<fd>, ...)
    // landed on whatever new fd allocation took its place.
    it('parent execve after child untracked F_SETFD FD_CLOEXEC sweeps parent fd 7 (bug #1 cloexec parent propagation)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'cloexec-parent-prop-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'cloexec-parent-prop-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (non-CLOEXEC).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child fcntl(7, F_SETFD, FD_CLOEXEC) — child's dirfdTable
        // has no entry for fd 7 (parent's clone hasn't reconciled
        // yet) AND no marker yet, so this is a PRE-detach cloexec
        // tombstone for fd 7.
        {
          pid: 1001,
          line: 'fcntl(7, F_SETFD, FD_CLOEXEC) = 0',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  snapshotFd
        // creates the marker; preDetachTombstones absorbs the
        // cloexec tombstone.  Action = 'none'.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler:
        //   (a) copy parent fd 7 → child fd 7,
        //   (b) apply preDetach cloexec tombstone with toParent=true:
        //       flip BOTH parent fd 7 and child fd 7 to cloexec=true,
        //   (c) apply action 'none' — no replay.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent execve — sweeps cloexec entries in parent's group;
        // fd 7 (now cloexec=true thanks to the tombstone propagation)
        // is dropped.
        {
          pid: 1000,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST fail closed (parent fd 7 was
        // cloexec-marked by the tombstone replay, then swept by
        // the parent execve above).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: NO /A/x certified.
      const parentLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeaked).toHaveLength(0);
      // Parent: surfaces <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #2 follow-up — RANGE
    // tombstone for close_range on untracked inherited fds):
    // a non-UNSHARE close_range from a singleton pid with no
    // marker mutates the SHARED files_struct.  In delayed-clone
    // order, the inherited parent fds aren't yet copied to the
    // child group, so the immediate iteration finds nothing.
    // Pre-fix the mutation was dropped entirely; reconciliation
    // then copied parent's fds back as if nothing happened, and
    // both groups certified reads through kernel-closed slots.
    // Fix: record a RANGE tombstone so the reconciler replays the
    // range close against the copied entries (and the parent's
    // matching entries under shared CLONE_FILES).
    it('singleton close_range on untracked inherited fds before later marker (bug #2 close_range range tombstone)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'close-range-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'close-range-tombstone-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (non-CLOEXEC).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close_range(3, 10, 0) — singleton, NO marker yet,
        // dirfdTable has no entries under child's prefix in [3,10].
        // Pre-fix: nothing recorded; reconciliation would copy
        // parent fd 7 back into the child group untouched.
        // Post-fix: record a RANGE close tombstone covering [3, 10]
        // in the pre-detach bucket.
        {
          pid: 1001,
          line: 'close_range(3, 10, 0) = 0',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  snapshotFd
        // absorbs the bucket → preDetachTombstones = [closeRange(3,10)].
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler:
        //   (a) copy parent fd 7 → child fd 7,
        //   (b) apply preDetach closeRange tombstone with toParent=true:
        //       drop child fd 7 (in range), drop parent fd 7 (in
        //       range), mark BOTH fd-unknown.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST fail closed (range tombstone
        // propagated to parent under shared CLONE_FILES).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Neither side resolves /A/x.
      const parentLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeaked).toHaveLength(0);
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // BOTH sides surface <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #3 follow-up — POST-detach
    // tombstones MUST NOT taint the parent):
    // sequence: child execve [action 1: execveCloexec queued], then
    // child close(7) on UNTRACKED fd, then delayed parent clone.
    // Pre-fix, recordFdTombstone folded the close into the snapshot
    // `tombstones` map and reconciliation applied ALL tombstones
    // BEFORE actions — but the close happened POST-detach (the
    // kernel had already unshared via execve) so it was private.
    // Yet the close tombstone replay tainted the parent's fd 7
    // (drop + fd-unknown).  Fix: split tombstones into pre-detach
    // (applied to BOTH parent + child) and post-detach (applied to
    // child only).  Parent fd 7 must survive untouched.
    it('execve then close on untracked fd before delayed clone keeps parent fd 7 (bug #3 post-detach private)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-detach-private-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-detach-private-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child execve at singleton — creates marker with
        // actions=[execveCloexec].  NO tombstones recorded yet.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Child close(7) on UNTRACKED fd — marker exists, so
        // recordFdTombstone appends to POST-detach bucket.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler:
        //   (a) copy parent fd 7 → child fd 7,
        //   (b) preDetachTombstones: empty,
        //   (c) actions: execveCloexec sweep on child group — fd 7
        //       cloexec=false, survives,
        //   (d) postDetachTombstones: drop child fd 7 ONLY.  Parent
        //       fd 7 stays /A.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x (the close
        // was private post-detach; parent's fd 7 was never tainted).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified.
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // Child: surfaces <UNRESOLVED_PATH>.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #1 final): interleaved
    // post-detach replay log.  The child's post-detach mutations
    // arrive as a sequence: F_SETFD CLOEXEC (tombstone), then execve
    // (action: execveCloexec).  Pre-fix the reconciler walked
    // actions then tombstones in separate phases, so the CLOEXEC
    // mark applied AFTER the sweep — entry survived.  Post-fix the
    // single interleaved log replays in observed order: mark
    // CLOEXEC, then sweep drops it.  Test asserts child fd 7
    // resolves to <UNRESOLVED_PATH>; parent fd 7 keeps /A/x because
    // BOTH mutations were post-detach (private to the child).
    it('post-detach CLOEXEC tombstone before execve sweep replays in order (bug #1 interleaving)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-detach-interleave-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-detach-interleave-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (non-CLOEXEC).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) at singleton time — snapshot
        // captures `entries=[]` (child has no own fds yet), seeds
        // postDetachLog with action(none).
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child fcntl(7, F_SETFD, FD_CLOEXEC) on UNTRACKED fd —
        // marker exists → tombstone is POST-detach.  Pushed onto
        // postDetachLog at position N (after the unshare action).
        {
          pid: 1001,
          line: 'fcntl(7, F_SETFD, FD_CLOEXEC) = 0',
          source: 'strace',
        },
        // Child execve at singleton — pushes action(execveCloexec)
        // onto postDetachLog at position N+1.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler:
        //   (a) copy parent fd 7 → child fd 7 (path=/A,
        //       cloexec=false),
        //   (b) postDetachLog walk in order:
        //         action(none)      — no-op
        //         tombstone(cloexec, fd=7) — mark child fd 7
        //                          cloexec=true, parent untouched
        //         action(execveCloexec) — sweep cloexec=true in
        //                          child group, fd 7 deleted.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed (entry swept by
        // execveCloexec after CLOEXEC mark applied first).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x.  BOTH the
        // CLOEXEC mark AND the sweep were post-detach mutations
        // private to the child; parent's fd 7 was never tainted.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified — interleaved replay marked
      // CLOEXEC first, then execve sweep dropped the entry.
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // Child: surfaces <UNRESOLVED_PATH>.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #2 final): marker-less
    // standalone tombstone consumption.  child close_range(3, 10, 0)
    // mutates the SHARED files_struct (CLONE_FILES) but no
    // subsequent unshare/execve marker was created.  Pre-fix the
    // pre-marker tombstone bucket was silently deleted at clone
    // reconciliation; the kernel-shared close didn't propagate to
    // the parent's modeled state, so the parent's openat(7, "x")
    // resolved through the stale entry.  Post-fix the standalone
    // tombstone is applied to the now-unified group with
    // shared-kernel propagation: fd 7 dropped both sides,
    // fd-unknown marked both sides.
    it('marker-less singleton close_range tombstone propagates to parent under shared CLONE_FILES (bug #2 standalone)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'standalone-close-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'standalone-close-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A (shared with the child via the
        // delayed CLONE_FILES that will surface last).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close_range(3, 10, 0) — singleton, NO marker yet.
        // Pre-marker range tombstone recorded; the kernel's shared
        // close hit BOTH sides.
        {
          pid: 1001,
          line: 'close_range(3, 10, 0) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) — NO unshare/execve
        // marker on the child.  Reconciler enters the union branch
        // (cloneFiles && no marker), then applies the standalone
        // tombstone to the unified group: drop fd 7 (in [3,10]),
        // mark fd-unknown both sides.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST fail closed.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Neither side resolves /A/x.
      const parentLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeaked).toHaveLength(0);
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // BOTH sides surface <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #2 final): non-shared
    // clone with pre-marker tombstone.  The clone has NO CLONE_FILES,
    // so the kernel did NOT share files_struct at clone time — the
    // child's close(7) was private to its own pre-clone fd table.
    // Standalone tombstone applies to child's copied entry only;
    // parent is untainted.
    it('marker-less close tombstone with non-shared clone applies to child only (bug #2 standalone non-shared)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'standalone-private-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'standalone-private-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens fd 7 → /A.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close(7) — singleton, NO marker.  Pre-marker close
        // tombstone recorded.  Because the eventual clone has NO
        // CLONE_FILES, the kernel-shared semantic does not apply;
        // the tombstone applies to the child's copied entry only.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Delayed parent clone WITHOUT CLONE_FILES.  Reconciler
        // enters the copy branch (no CLONE_FILES); the copy pass
        // copies fd 7 → child group, then the standalone tombstone
        // drops the child's copy.  Parent fd 7 untouched.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified.
      const childLeaked = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeaked).toHaveLength(0);
      // Child: surfaces <UNRESOLVED_PATH>.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — stale-tombstone-
    // on-reopen, no marker): the singleton child close(7) records a
    // pre-marker `close` tombstone for the (untracked) inherited fd
    // 7.  The child then opens /B as fd 7, which (post-fix) cancels
    // the stale tombstone.  When the delayed parent clone(CLONE_FILES)
    // arrives WITHOUT any intervening detach marker, the union
    // branch's standalone-tombstone replay finds an empty bucket →
    // nothing to apply.  unionFd brings the child's fd 7 → /B into
    // the unified group; subsequent openat(7, ...) on either pid
    // resolves through /B.
    //
    // Pre-fix bug: the standalone replay applied the stale close
    // tombstone AFTER unionFd, dropping the merged /B mapping and
    // tainting both groups fd-unknown.  Post-fix: parent + child
    // openat(7, "x") both resolve to /B/x.
    it('close-then-reopen-before-delayed-clone cancels stale tombstone, no marker (bug #2 stale-tombstone-on-reopen)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'tombstone-cancel-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'tombstone-cancel-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child close(7) — singleton, no parent fd 7 entry tracked
        // (untracked inherited).  Pre-marker `close` tombstone
        // recorded for fd 7.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Child opens /B as fd 7 — cancels the stale tombstone
        // (post-fix) and installs the child-group entry.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler enters the
        // union branch; unionFd merges child's fd 7 → /B into the
        // parent group.  Standalone tombstone replay finds an empty
        // bucket → nothing to apply (post-fix).  fd 7 → /B survives.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /B/x.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /B/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: /B/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // Neither side fails closed via <UNRESOLVED_PATH> for the openat.
      const unresolvedFromOpen = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolvedFromOpen).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — stale-tombstone-
    // on-reopen, with subsequent unshare):
    //   1. child close(7) [pre-marker close tombstone for fd 7]
    //   2. child opens /B as fd 7 [cancels pre-marker tombstone]
    //   3. child unshare(CLONE_FILES) [snapshot captures fd 7 → /B;
    //      preDetachTombstones empty post-cancel]
    //   4. delayed parent clone(CLONE_FILES) = child
    // Reconciler: copy branch (childHadPendingFdDetach=true).  Snapshot
    // entries: fd 7 → /B.  preDetachTombstones empty.  No parent
    // entry for fd 7 → no snapshot conflict.  Copy pass leaves the
    // child's current /B entry in place.  Both sides openat(7) →
    // /B/x.
    //
    // Pre-fix: the absorbed pre-detach close tombstone for fd 7
    // would have replayed at reconciliation, dropping the child's
    // /B entry from its post-detach group (and tainting parent
    // under shared CLONE_FILES); both sides would fail closed
    // through fd-unknown.  Post-fix: tombstone cancelled at reopen
    // → /B/x certified.
    it('close-then-reopen-with-unshare cancels pre-marker tombstone (bug #2 stale-tombstone-on-reopen with marker)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'tombstone-cancel-marker-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'tombstone-cancel-marker-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child close(7) — singleton with no parent fd 7 entry
        // (untracked inherited).  Pre-marker `close` tombstone
        // recorded for fd 7.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Child opens /B as fd 7 — cancels the pre-marker tombstone
        // (post-fix).  Child-rooted entry: fd 7 → /B.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  snapshotFd
        // captures fd 7 → /B; absorbPendingTombstones sees an empty
        // bucket → preDetachTombstones is empty.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Copy branch.  Parent
        // has no fd 7 entry, so no snapshot conflict.  Child's
        // current fd 7 → /B is preserved.  Pre-fix: stale close
        // tombstone in preDetachTombstones would now fire,
        // dropping fd 7 and tainting fd-unknown both sides.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /B/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> surfaced from the openat(7, ...) above.
      const unresolvedFromOpen = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolvedFromOpen).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — range-tombstone
    // surgery): child close_range(3, 10, 0) records a pre-marker
    // range tombstone covering [3, 10].  Child then opens /B as fd
    // 7 (in range).  Post-fix the cancel helper splits the range
    // into [3, 6] and [8, 10], leaving fd 7's reopen intact while
    // tombstones for fds 3-6 and 8-10 continue to apply.
    //
    // The test exercises BOTH paths: parent fd 7 (reopen, NOT
    // tombstoned) resolves to /B/x; parent fd 8 (in remaining
    // [8, 10] range, still tombstoned) fails closed under
    // fd-unknown.
    it('close_range-then-reopen-in-range splits range tombstone (bug #2 range surgery)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'tombstone-range-cancel-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'tombstone-range-cancel-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A as fd 7 AND /C as fd 8 (both in [3,10]).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/C", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Child close_range(3, 10, 0) — pre-marker range tombstone
        // covering [3, 10].
        {
          pid: 1001,
          line: 'close_range(3, 10, 0) = 0',
          source: 'strace',
        },
        // Child opens /B as fd 7 — splits the range tombstone into
        // [3, 6] and [8, 10].  fd 7 NOT tombstoned.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).  Reconciler enters the
        // union branch (no marker); standalone tombstone replay
        // applies the SPLIT ranges to the unified group: drop entries
        // in [3, 6] (none tracked — no-op) and [8, 10] (drops fd 8).
        // fd 7 → /B survives because it isn't covered.  Both groups
        // marked fd-unknown because at least one closeRange touched
        // (fd 8).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — surfaced under fd-unknown fail-
        // closed even though fd 7 itself wasn't tombstoned: any
        // touched range tombstone taints the whole group's
        // fd-unknown bit.  Acceptable conservative behaviour; the
        // important property is /A/x is NOT certified.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 11',
          source: 'strace',
        },
        // Parent openat(8, "x") — fd 8 was in the [8, 10] surviving
        // range; entry dropped and group fd-unknown.  MUST fail
        // closed.
        {
          pid: 1000,
          line: 'openat(8, "x", O_RDONLY) = 12',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Critical property: /A/x is NEVER certified (fd 7 was
      // /A in parent's table before child reopened to /B — the
      // reopen overwrites the entry in the shared group AND any
      // stale /A mapping is gone).
      const parentLeakedA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeakedA).toHaveLength(0);
      // /C/x (fd 8's parent path) must also NOT be certified — fd
      // 8 was in the surviving [8, 10] sub-range and got dropped.
      const parentLeakedC = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/C/x' && r['pid'] === 1000;
      });
      expect(parentLeakedC).toHaveLength(0);
      // Parent's fd 8 surfaces <UNRESOLVED_PATH>.
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — postDetachLog
    // stale-tombstone cancellation): once a child has an active
    // pending-fd-detach marker (e.g. from CLOSE_RANGE_UNSHARE), any
    // subsequent close/cloexec/close_range observations queue onto
    // the marker's `postDetachLog[]` in observed order.  A later
    // openat / dup / F_DUPFD that REUSES the same fd number must
    // excise the stale entry from the log; otherwise the delayed-
    // clone reconciler replays the log and the freshly-reopened fd
    // gets dropped from the child's private copy.
    //
    // The three regression tests below stage post-marker scenarios
    // that ONLY trip the postDetachLog bug being fixed.  Parent
    // does not pre-open fd 7 — that orthogonal interaction would
    // expose the dispatcher's copy-pass "fork conflict" path,
    // which is a separate (pre-existing) concern from this fix.
    // Restricting the scenarios isolates the postDetachLog stale-
    // entry pathway: the bug visibly drops the child's freshly-
    // reopened mapping at log replay, and the fix preserves it.
    //
    // Scenario 1 — close_range UNSHARE creates a closeRange action
    // entry in postDetachLog; child reopens the just-closed fd
    // before delayed parent clone arrives.
    //   1. child close_range(7, 7, CLOSE_RANGE_UNSHARE) →
    //      snapshot taken; postDetachLog seeded with the
    //      closeRange [7,7] action
    //   2. child openat(...) = 7 → /B → post-fix: my cancel
    //      helper splits the closeRange action's range around
    //      fd 7 (single-fd range collapses to empty → dropped
    //      from postDetachLog)
    //   3. delayed parent clone(CLONE_FILES) = child → log
    //      replay sees an empty postDetachLog → /B mapping
    //      survives in child's group
    //   4. child openat(7, "x") → /B/x certified
    //
    // Pre-fix: log replay applied the stale closeRange [7,7],
    // deleting fd 7 from the child's private group; child
    // openat(7) failed closed.
    it('close_range UNSHARE marker then reopen in range cancels postDetachLog action entry (bug #2 postDetachLog action)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-log-cancel-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-log-cancel-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child close_range(7, 7, CLOSE_RANGE_UNSHARE) at
        // singleton time.  Creates pendingFdDetach marker with
        // snapshot.entries=[] (child has no rooted fds yet);
        // postDetachLog seeded with closeRange [7,7] action.
        {
          pid: 1001,
          line: 'close_range(7, 7, CLOSE_RANGE_UNSHARE) = 0',
          source: 'strace',
        },
        // Child openat → fd 7 = /B in child's rooted group.
        // Post-fix: cancelPendingTombstonesForFd walks
        // postDetachLog and excises fd 7 from the closeRange
        // [7,7] action — the only-fd-in-range case fully
        // cancels the action, leaving an empty postDetachLog.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // enters the copy branch.  Parent has no fd 7 entries to
        // copy → no copy-pass conflict.  preDetachTombstones
        // empty; postDetachLog empty after surgery → child's /B
        // entry survives.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x.  Pre-fix
        // this failed closed (closeRange [7,7] replay dropped
        // fd 7).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 8',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /B/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH> from the openat — the reopened /B
      // mapping survived the reconciler.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — postDetachLog
    // stale-tombstone, post-marker close):
    //   1. child unshare(CLONE_FILES) → snapshot.entries=[],
    //      postDetachLog=[{action: none}]
    //   2. child close(7) — fd 7 is UNTRACKED in child's rooted
    //      table → recordFdTombstone appends a {tombstone, close
    //      fd 7} entry to postDetachLog (marker already exists)
    //   3. child openat(...) = 7 → /C — post-fix: cancel helper
    //      walks postDetachLog and drops the close tombstone for
    //      fd 7
    //   4. delayed parent clone(CLONE_FILES) = child
    //
    // Reconciler: copy branch.  postDetachLog after surgery is
    // [{action: none}]; the close tombstone is gone.  Child's
    // current fd 7 → /C survives; parent (no fd 7) untouched.
    //
    // Pre-fix: the close tombstone for fd 7 lived in
    // postDetachLog through reconciliation; the replay deleted
    // fd 7 from the child's group → child openat(7) failed
    // closed.
    it('post-marker close then reopen cancels postDetachLog close tombstone (bug #2 postDetachLog tombstone)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-log-cancel-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-log-cancel-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child unshare(CLONE_FILES) — singleton detach.
        // snapshotFd captures empty entries; marker created with
        // postDetachLog=[{action: none}].
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child close(7) — fd 7 untracked in child's rooted
        // table; recordFdTombstone appends a close tombstone for
        // fd 7 onto postDetachLog (marker exists → post-marker
        // path).
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Child opens /C as fd 7 — Post-fix: cancel helper walks
        // postDetachLog and drops the close tombstone for fd 7.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/C", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Copy
        // branch: parent has no fd 7 → no copy-pass conflict;
        // preDetachTombstones empty; postDetachLog replay sees
        // only the `none` action → /C survives.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /C/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /C/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/C/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex follow-up (medium, 2026-05-19, bug #2 — postDetachLog
    // stale-tombstone, post-marker cloexec):
    //   1. child unshare(CLONE_FILES) → snapshot, postDetachLog
    //      seeded with {action: none}
    //   2. child fcntl(7, F_SETFD, FD_CLOEXEC) — fd 7 untracked
    //      → post-marker cloexec tombstone appended to
    //      postDetachLog
    //   3. child openat(...) = 7 → /B (no O_CLOEXEC) — Post-fix:
    //      cancels the cloexec tombstone in postDetachLog
    //   4. child execve — appends {action: execveCloexec} to
    //      postDetachLog
    //   5. delayed parent clone(CLONE_FILES) = child
    //
    // Reconciler: copy branch.  postDetachLog replay:
    //   - none — no-op
    //   - cloexec tombstone for fd 7 — CANCELLED at step 3 →
    //     gone
    //   - execveCloexec — sweeps entries with cloexec=true.  /B
    //     was opened without O_CLOEXEC (cloexec=false) → not
    //     swept.
    //
    // Result: child fd 7 → /B/x.
    //
    // Pre-fix: the cloexec tombstone for fd 7 lived in
    // postDetachLog through reconciliation; the replay marked
    // fd 7 (/B) cloexec=true; the subsequent execveCloexec sweep
    // dropped /B.  Child openat(7) failed closed.
    it('post-marker cloexec then reopen cancels postDetachLog cloexec tombstone before execve sweep (bug #2 postDetachLog cloexec)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'post-log-cancel-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'post-log-cancel-cloexec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Child unshare(CLONE_FILES) — singleton detach.  Snapshot
        // entries empty.  Marker created.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child fcntl(7, F_SETFD, FD_CLOEXEC) — fd 7 untracked in
        // child's rooted table; recorded as POST-marker cloexec
        // tombstone for fd 7 in postDetachLog.
        {
          pid: 1001,
          line: 'fcntl(7, F_SETFD, FD_CLOEXEC) = 0',
          source: 'strace',
        },
        // Child opens /B as fd 7 (no O_CLOEXEC).  Post-fix:
        // cancels the post-marker cloexec tombstone in
        // postDetachLog.  /B installed with cloexec=false.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child execve — post-marker execveCloexec action queued
        // onto postDetachLog.  Sweep only affects entries marked
        // cloexec=true.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Copy branch:
        // parent has no fd 7 → no copy-pass conflict.
        // postDetachLog replay: cloexec tombstone gone;
        // execveCloexec sees /B with cloexec=false → /B not
        // swept.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /B/x certified (cloexec cancelled before sweep).
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // No <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19, bug #3 — post-marker fd
    // reuse exclusion against pre-detach close tombstone):
    //   1. parent opens fd 7 → /A (shared with child via CLONE_FILES)
    //   2. child close(7) [pre-marker close tombstone for fd 7;
    //      kernel mutates SHARED files_struct, propagates to parent]
    //   3. child unshare(CLONE_FILES) [snapshot includes the close
    //      tombstone in preDetachTombstones]
    //   4. child openat(...) = 7 → /B [POST-marker private reopen;
    //      kernel installs fd 7 in child's now-private group only]
    //   5. delayed parent clone(CLONE_FILES) = child
    // Expected: parent fd 7 fails closed (kernel-shared close
    // propagated to parent's fd 7); child fd 7 resolves to /B/x
    // (post-marker private reopen survives — the pre-detach
    // tombstone must NOT apply to the child copy for this fd).
    //
    // Pre-fix: the pre-detach close tombstone applied to BOTH
    // parent and child at reconciliation, clobbering the child's
    // freshly-reopened fd 7 → /B entry alongside the parent fd 7
    // taint.  Post-fix: child-side replay excludes fd 7 because
    // it's in postMarkerFdReuses[childPid].
    it('post-marker fd reuse excluded from child-side pre-detach close tombstone (bug #3 point)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'postmarker-reuse-point-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'postmarker-reuse-point-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7.  At kernel time this fd is shared
        // with the (yet-to-be-cloned) child via CLONE_FILES.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close(7) on UNTRACKED fd (child group is empty;
        // singleton).  Pre-marker close tombstone recorded for fd 7.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  Snapshot
        // absorbs the pre-marker tombstone into preDetachTombstones.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // POST-marker child openat → fd 7 = /B (private reopen).
        // Should add fd 7 to postMarkerFdReuses[1001].
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST fail closed (kernel-shared
        // close propagated to parent's fd 7 via preDetachTombstone).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x (post-marker
        // private reopen excluded from child-side tombstone).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /B/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // Parent: NO /A/x certified (kernel-shared close means
      // parent's fd 7 entry was dropped at reconcile).
      const parentLeak = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeak).toHaveLength(0);
      // Parent: <UNRESOLVED_PATH> on the failing openat(7, "x").
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #3 — range tombstone
    // surgery for post-marker reuses):
    //   1. parent opens /A → fd 7 (shared via CLONE_FILES)
    //   2. child close_range(3, 10, 0) [pre-marker range tombstone
    //      [3,10]; kernel closes the shared files_struct range,
    //      propagates to parent]
    //   3. child unshare(CLONE_FILES) [snapshot includes the range]
    //   4. child openat(...) = 7 → /B [post-marker reopen in range]
    //   5. child openat(...) = 5 → /C [another post-marker reopen
    //      in range]
    //   6. delayed parent clone(CLONE_FILES) = child
    // Expected: parent fd 7 fails closed (range applied);
    //           child fd 7 resolves to /B/x (excluded);
    //           child fd 5 resolves to /C/x (excluded).
    it('post-marker fd reuses excluded from child-side pre-detach close_range (bug #3 range)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'postmarker-reuse-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'postmarker-reuse-range-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 (shared with child via CLONE_FILES).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child close_range(3, 10, 0) at singleton.  Pre-marker
        // range tombstone [3, 10] recorded; mutates shared
        // files_struct.
        {
          pid: 1001,
          line: 'close_range(3, 10, 0) = 0',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach.  Snapshot
        // absorbs the range tombstone into preDetachTombstones.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // POST-marker openats — fd 7 → /B and fd 5 → /C.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/C", O_RDONLY|O_DIRECTORY) = 5',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST fail closed (range applied).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 11',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /B/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 12',
          source: 'strace',
        },
        // Child openat(5, "x") — MUST resolve to /C/x.
        {
          pid: 1001,
          line: 'openat(5, "x", O_RDONLY) = 13',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /B/x and /C/x certified.
      const childB = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childB).toHaveLength(1);
      const childC = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/C/x' && r['pid'] === 1001;
      });
      expect(childC).toHaveLength(1);
      // Parent: NO /A/x certified.
      const parentLeak = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentLeak).toHaveLength(0);
      // Parent: <UNRESOLVED_PATH> on the failing openat(7, "x").
      const parentUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1000;
      });
      expect(parentUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #5 — post-marker close
    // of a previously-reused fd):
    //   1. parent opens fd 7 → /A (shared with child via CLONE_FILES)
    //   2. child unshare(CLONE_FILES) [marker; child group empty]
    //   3. child openat(...) = 7 → /B [post-marker reuse, lifecycle
    //      'open']
    //   4. child close(7) [post-marker close — lifecycle 'closed';
    //      kernel removes fd 7 from the child's PRIVATE group only]
    //   5. delayed parent clone(CLONE_FILES) = child
    // Expected: child fd 7 fails closed (kernel-closed; lifecycle
    //           'closed' tells the reconciler to skip the parent
    //           copy);
    //           parent fd 7 resolves to /A/x (parent's table is
    //           unaffected — the post-marker close happened in the
    //           child's PRIVATE group post-unshare).
    //
    // Pre-fix (bug #5): the post-marker close deleted the child's
    // /B entry but the per-pid reuse Set still listed fd 7.  The
    // reconciler's copy-pass saw `existing === undefined` and
    // copied parent's fd 7 → /A back into the child group;
    // subsequent child openat(7, "x") resolved to /A/x even though
    // the kernel returned EBADF.
    it('post-marker reopen then post-marker close — parent fd not copied back into child (bug #5 close)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'postmarker-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'postmarker-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — singleton detach, marker
        // seeded with action `none`.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // POST-marker child openat → fd 7 = /B (lifecycle 'open').
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // POST-marker child close(7) — lifecycle 'open' → 'closed'.
        // Child's dirfdTable entry for fd 7 is deleted.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // copy-pass MUST skip parent's fd 7 → /A because fd 7 is
        // in the child's closed-lifecycle set.
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed (kernel-closed).
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x (parent's
        // table is untouched by the child's private post-unshare
        // close).
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 10',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // Child: NO /A/x certified (the bug-#5 resurrection); also
      // NO /B/x certified (the kernel closed fd 7 — child fd is
      // gone, no path resolves through it).
      const childLeakA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeakA).toHaveLength(0);
      const childLeakB = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childLeakB).toHaveLength(0);
      // Child: <UNRESOLVED_PATH> on the failing openat(7, "x").
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });

    // Codex follow-up (high, 2026-05-19, bug #5 — post-marker
    // close-then-reopen cycle, lifecycle 'closed' → 'open' again):
    //   1. parent opens fd 7 → /A
    //   2. child unshare(CLONE_FILES) [marker]
    //   3. child openat(...) = 7 → /B [lifecycle 'open']
    //   4. child close(7) [lifecycle 'closed']
    //   5. child openat(...) = 7 → /C [lifecycle 'closed' → 'open'
    //      with new path /C]
    //   6. delayed parent clone(CLONE_FILES) = child
    // Expected: child openat(7, "x") resolves to /C/x (the second
    // post-marker reopen wins; reconciler treats fd 7 as a live
    // reuse, not a closed one).
    //
    // Pre-fix: even if we'd added 'closed' tracking but failed to
    // transition back to 'open' on reopen, the child copy-pass
    // would still skip the parent → child copy.  But the child's
    // /C entry was set directly by the openat handler, so this
    // path is governed by `existing.path === val.path` vs.
    // `existing.path !== val.path` branches.  Verifying it
    // explicitly catches a transition regression where 'closed'
    // doesn't migrate back to 'open'.
    it('post-marker reopen, close, reopen — child sees the second reopen path (bug #5 reopen cycle)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'postmarker-cycle-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'postmarker-cycle-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — marker seeded.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // POST-marker child openat → fd 7 = /B (lifecycle 'open').
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // POST-marker child close(7) — lifecycle 'closed'.
        {
          pid: 1001,
          line: 'close(7) = 0',
          source: 'strace',
        },
        // POST-marker child openat → fd 7 = /C (lifecycle
        // 'closed' → 'open' with the new path /C).
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/C", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // sees lifecycle 'open' for fd 7 → keeps child's /C entry,
        // skips parent's /A copy (path conflict on the
        // reusedPostMarker branch).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST resolve to /C/x.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 9',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /C/x certified.
      const childC = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/C/x' && r['pid'] === 1001;
      });
      expect(childC).toHaveLength(1);
      // Child: NO /A/x or /B/x certified.
      const childLeakA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1001;
      });
      expect(childLeakA).toHaveLength(0);
      const childLeakB = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/B/x' && r['pid'] === 1001;
      });
      expect(childLeakB).toHaveLength(0);
      // No <UNRESOLVED_PATH> for the child openat.
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19, bug #5 — post-marker
    // close_range over previously-reused fds, range form):
    //   1. parent opens fd 7 → /A and fd 8 → /A2
    //   2. child unshare(CLONE_FILES) [marker]
    //   3. child openat(...) = 7 → /B [lifecycle 'open']
    //   4. child openat(...) = 8 → /C [lifecycle 'open']
    //   5. child close_range(3, 10, 0) [post-marker range close —
    //      both fds transition 'open' → 'closed']
    //   6. delayed parent clone(CLONE_FILES) = child
    // Expected: child fd 7 and fd 8 BOTH fail closed (lifecycle
    //           'closed' → reconciler skips parent copy);
    //           parent fd 7 → /A/x and parent fd 8 → /A2/x still
    //           resolve (private to child).
    it('post-marker close_range covers reused fds — child fds fail closed (bug #5 range)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'postmarker-range-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'postmarker-range-close-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 and /A2 → fd 8.
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A2", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) — marker seeded.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // POST-marker child openat → fd 7 = /B (lifecycle 'open').
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/B", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // POST-marker child openat → fd 8 = /C (lifecycle 'open').
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/C", O_RDONLY|O_DIRECTORY) = 8',
          source: 'strace',
        },
        // POST-marker child close_range(3, 10, 0) — both fd 7 and
        // fd 8 lifecycle 'open' → 'closed'.  Child's dirfdTable
        // entries for /B and /C are deleted in-place.
        {
          pid: 1001,
          line: 'close_range(3, 10, 0) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // copy-pass MUST skip parent's fd 7 → /A AND fd 8 → /A2
        // (both fds in childPostMarkerFdClosed).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(7, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(7, "x", O_RDONLY) = 11',
          source: 'strace',
        },
        // Child openat(8, "x") — MUST fail closed.
        {
          pid: 1001,
          line: 'openat(8, "x", O_RDONLY) = 12',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 13',
          source: 'strace',
        },
        // Parent openat(8, "x") — MUST resolve to /A2/x.
        {
          pid: 1000,
          line: 'openat(8, "x", O_RDONLY) = 14',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Parent: /A/x and /A2/x certified.
      const parentA = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentA).toHaveLength(1);
      const parentA2 = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A2/x' && r['pid'] === 1000;
      });
      expect(parentA2).toHaveLength(1);
      // Child: NO /A/x, /A2/x, /B/x, /C/x — every fd in [3, 10]
      // post-marker reused got transitioned to 'closed'.
      const childAnyResolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        if (r['pid'] !== 1001 || r['kind'] !== 'read') return false;
        const p = r['path'];
        return p === '/A/x' || p === '/A2/x' || p === '/B/x' || p === '/C/x';
      });
      expect(childAnyResolved).toHaveLength(0);
      // Child: at least two <UNRESOLVED_PATH> (one per failing
      // openat).
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(2);
    });

    // Codex follow-up (high, 2026-05-19, bug #4 — generation-aware
    // execveCloexec, single exec preserves post-exec O_CLOEXEC fd):
    //   1. parent opens fd 7 → /A (non-CLOEXEC; shared via
    //      CLONE_FILES)
    //   2. child unshare(CLONE_FILES) [snapshot; fd 7 untracked in
    //      child's group, no cloexec entries]
    //   3. child execve [postDetachLog: execveCloexec with empty
    //      excludeFds]
    //   4. child openat(AT_FDCWD, "/D", O_CLOEXEC) = 9 [post-exec
    //      O_CLOEXEC open; recordPostMarkerFdReuse adds 9 to the
    //      pending execveCloexec action's excludeFds]
    //   5. delayed parent clone(CLONE_FILES) = child
    // Expected: child fd 9 resolves to /D/x (NOT swept by exec1
    //           because 9 in excludeFds);
    //           parent fd 7 resolves to /A/x (parent didn't execve).
    //
    // Pre-fix: execveCloexec replay unconditionally swept all
    // cloexec entries in child copy, including fd 9 → /D → fd 9
    // openat fails closed even though kernel never closed it.
    it('post-exec O_CLOEXEC open survives single execveCloexec replay (bug #4 exclude)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'exec-cloexec-exclude-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'exec-cloexec-exclude-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 (non-CLOEXEC; shared via
        // CLONE_FILES).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) at singleton.  Snapshot fd 7
        // untracked in child group (parent's clone hasn't surfaced
        // yet).
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child execve at singleton.  Appends execveCloexec to
        // postDetachLog; excludeFds starts empty.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // POST-exec child openat with O_CLOEXEC → fd 9.  Adds 9 to
        // the queued execveCloexec action's excludeFds.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/D", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 9',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // copies parent's fd 7 (non-cloexec) into child group;
        // execveCloexec replay sweeps cloexec entries EXCEPT fd 9 →
        // fd 9 → /D survives, fd 7 → /A survives (non-cloexec).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(9, "x") — MUST resolve to /D/x (post-exec
        // reopen excluded from sweep).
        {
          pid: 1001,
          line: 'openat(9, "x", O_RDONLY) = 12',
          source: 'strace',
        },
        // Parent openat(7, "x") — MUST resolve to /A/x.
        {
          pid: 1000,
          line: 'openat(7, "x", O_RDONLY) = 13',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: /D/x certified.
      const childRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/D/x' && r['pid'] === 1001;
      });
      expect(childRead).toHaveLength(1);
      // Parent: /A/x certified.
      const parentRead = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/A/x' && r['pid'] === 1000;
      });
      expect(parentRead).toHaveLength(1);
      // No <UNRESOLVED_PATH>.
      const unresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true;
      });
      expect(unresolved).toHaveLength(0);
    });

    // Codex follow-up (high, 2026-05-19, bug #4 — second execveCloexec
    // sweeps post-first-exec cloexec fds): a SECOND exec sweeps the
    // post-first-exec O_CLOEXEC fd because that fd existed at
    // exec2-time (it was NOT post-exec2-opened):
    //   1. parent opens fd 7 → /A (non-CLOEXEC)
    //   2. child unshare(CLONE_FILES)
    //   3. child execve #1 [exec1 excludeFds={}]
    //   4. child openat(AT_FDCWD, "/D", O_CLOEXEC) = 9 → add 9 to
    //      exec1's excludeFds (exec1's snapshot)
    //   5. child execve #2 [exec2 excludeFds={} — fd 9 EXISTED at
    //      this exec's instant, so it's NOT excluded.  The
    //      immediate inline sweep at execve handler already removed
    //      fd 9 from dirfdTable since it had cloexec=true.]
    //   6. delayed parent clone(CLONE_FILES) = child
    // Expected: child fd 9 fails closed (exec2 in-line sweep
    // dropped it AND/OR the exec2 execveCloexec replay's sweep
    // confirms it).
    it('second execveCloexec sweeps post-first-exec cloexec fd (bug #4 second exec)', async () => {
      const proc = mockProcReader({
        1000: {
          ppid: 1,
          env: {
            npm_package_name: 'exec-cloexec-second-exec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
        1001: {
          ppid: 1000,
          env: {
            npm_package_name: 'exec-cloexec-second-exec-pkg',
            npm_package_version: '1.0.0',
            npm_lifecycle_event: 'postinstall',
          },
        },
      });
      const records: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [
        // Parent opens /A → fd 7 (non-CLOEXEC; shared via
        // CLONE_FILES).
        {
          pid: 1000,
          line: 'openat(AT_FDCWD, "/A", O_RDONLY|O_DIRECTORY) = 7',
          source: 'strace',
        },
        // Child unshare(CLONE_FILES) at singleton.
        {
          pid: 1001,
          line: 'unshare(CLONE_FILES) = 0',
          source: 'strace',
        },
        // Child execve #1 at singleton.
        {
          pid: 1001,
          line: 'execve("/bin/sh", ["/bin/sh"], 0x7f...) = 0',
          source: 'strace',
        },
        // POST-exec1 openat with O_CLOEXEC → fd 9.  Adds 9 to
        // exec1's excludeFds.
        {
          pid: 1001,
          line: 'openat(AT_FDCWD, "/D", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 9',
          source: 'strace',
        },
        // Child execve #2 at singleton.  In-line sweep at execve
        // handler drops fd 9 from dirfdTable (it had cloexec=true).
        // exec2's excludeFds starts empty (fd 9 EXISTED at this
        // exec's instant — but it's already gone from dirfdTable
        // post-sweep).
        {
          pid: 1001,
          line: 'execve("/bin/ls", ["/bin/ls"], 0x7f...) = 0',
          source: 'strace',
        },
        // Delayed parent clone(CLONE_FILES) = child.  Reconciler
        // copies parent's fd 7 (non-cloexec) into child group;
        // replays exec1+exec2 in order.  At replay, child group
        // contains fd 7 (non-cloexec) only — fd 9 was dropped
        // in-line at exec2.  Both execveCloexec replays no-op on
        // fd 7 (not cloexec).
        {
          pid: 1000,
          line: 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND, child_tidptr=0x7f...) = 1001',
          source: 'strace',
        },
        // Child openat(9, "x") — MUST fail closed (exec2 swept it).
        {
          pid: 1001,
          line: 'openat(9, "x", O_RDONLY) = 12',
          source: 'strace',
        },
      ];
      const { emitter, lines } = makeEmitter();
      await runInstallPhase({
        manager: 'npm',
        cwd: '/work',
        env: { ...BASE_ENV, SCRIPT_JAIL_LOG_FILE: EVENTS_FILE },
        strace: cannedStraceRunner(records, 0, { rootPid: 1000 }),
        attribution: new Attribution(proc),
        emitter,
      });
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      // Child: NO /D/x certified (exec2 swept fd 9).
      const childLeak = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'read' && r['path'] === '/D/x' && r['pid'] === 1001;
      });
      expect(childLeak).toHaveLength(0);
      // Child: <UNRESOLVED_PATH> on the failing openat(9, "x").
      const childUnresolved = events.filter((e) => {
        const r = e['raw'] as Record<string, unknown>;
        return r['kind'] === 'exec' && r['unresolved_path'] === true && r['pid'] === 1001;
      });
      expect(childUnresolved.length).toBeGreaterThanOrEqual(1);
    });
  });
});

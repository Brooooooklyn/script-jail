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

    it('events_file_forgery renders to <EVENTS_FILE_FORGERY> in audit_bypass via normalize', async () => {
      const ev: AttributedEvent = {
        raw: {
          kind: 'exec',
          prog: EVENTS_FILE,
          argv0: EVENTS_FILE,
          envp_alloc_failed: false,
          syscall_bypass: false,
          events_file_forgery: true,
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

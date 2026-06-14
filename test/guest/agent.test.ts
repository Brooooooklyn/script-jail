// Tests for src/guest/agent.ts
// Wires all mocks together; uses a MemoryConnection and fake config file.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PassThrough } from 'node:stream';
import { writeFileSync, mkdirSync, rmSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stringify } from 'yaml';

import { createConnection } from 'node:net';

import { LinuxVsockConnection, LinuxStraceRunner, main, MemoryConnection, runStraceTailer, attachStdoutTailCollector, PHASE_B_STDOUT_TAIL_BYTES, PHASE_B_STDOUT_PENDING_MAX_BYTES, redactSensitive } from '../../src/guest/agent.js';
import type { DnsLookupFn, SpawnResult, EventsFile, SpawnImpl } from '../../src/guest/agent.js';
import { MacOSInstallRunner } from '../../src/guest/macos-install-runner.js';
import type { Spawner } from '../../src/guest/phase-fetch.js';
import type { StraceRunner } from '../../src/guest/phase-install.js';

// Default DNS lookup fake: simulates an offline VM (ENOTFOUND).  Every
// agent main() call in the test suite injects this so tests don't depend on
// the host machine actually resolving registry.npmjs.org.
const offlineLookup: DnsLookupFn = (_hostname, callback) => {
  // Schedule a microtask-ish callback so we exercise the async path.
  setImmediate(() => {
    const err = new Error('getaddrinfo ENOTFOUND') as NodeJS.ErrnoException;
    err.code = 'ENOTFOUND';
    callback(err);
  });
};

const onlineLookup: DnsLookupFn = (_hostname, callback) => {
  setImmediate(() => { callback(null); });
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let testDir: string;

beforeEach(() => {
  testDir = join(tmpdir(), `script-jail-agent-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function writeConfig(dir: string, extra: Record<string, unknown> = {}): string {
  const config = {
    protected: { files: [], env: [] },
    spoof: { platform: 'linux', arch: 'x64' },
    node_version: '20.0.0',
    work_dir: dir,
    log_fd: 3,
    pkg_dirs: {},
    manager: 'npm',
    ...extra,
  };
  const path = join(dir, 'config.yml');
  writeFileSync(path, stringify(config), 'utf8');
  return path;
}

/** Make a MemoryConnection where:
 *  - `readable` is a PassThrough we can push data into (simulating host → guest)
 *  - `writable` is a PassThrough we can read from (guest → host output)
 */
function makeConn(): {
  conn: MemoryConnection;
  hostSend: (data: string) => void;
  getOutput: () => string;
} {
  const toGuest = new PassThrough();   // host writes here, guest reads
  const fromGuest = new PassThrough(); // guest writes here, host reads
  const conn = new MemoryConnection(toGuest, fromGuest);
  let output = '';
  fromGuest.on('data', (c: Buffer) => { output += c.toString(); });
  return {
    conn,
    hostSend: (data) => toGuest.push(data),
    getOutput: () => output,
  };
}

/** A mock Spawner for Phase A (fetch) that tracks calls and always succeeds. */
function mockSpawner(exitCode = 0): { spawner: Spawner; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    spawner: {
      async spawn(cmd, args) {
        calls.push(`${cmd} ${args.join(' ')}`);
        return { exitCode, stdout: '', stderr: '' };
      },
    },
  };
}

/**
 * A StraceRunner that emits no records and reports exitCode 0.
 * Used as Phase B mock — it owns the install process.
 */
function emptyStrace(exitCode = 0): StraceRunner {
  return {
    async *run(cmd, _args) {
      // Record what command was invoked so tests can assert it.
      void cmd;
    },
    getExitCode() { return exitCode; },
    // Finding D: tamper reporting is part of the StraceRunner contract.
    // Test fakes that don't audit a shared events file return null.
    getTamperReason() { return null; },
    recordTamper(_reason: string) { /* no-op for test fakes */ },
    getRootPid() { return null; },
  };
}

/**
 * Like {@link emptyStrace} (zero events, supplied exit code) but ALSO exposes a
 * captured install-stdout tail via the optional `getStdoutTail()` contract.
 * Exercises the Phase-B fail-closed diagnostic: yarn Berry writes its setup
 * errors to stdout, and `main()` must surface a REDACTED tail on the fatal
 * frame so the real cause isn't invisible.
 */
function emptyStraceWithStdout(exitCode: number, stdoutTail: string): StraceRunner {
  return {
    async *run() { /* zero events */ },
    getExitCode() { return exitCode; },
    getTamperReason() { return null; },
    recordTamper(_reason: string) { /* no-op for test fakes */ },
    getRootPid() { return null; },
    getStdoutTail() { return stdoutTail; },
  };
}

/**
 * A StraceRunner that yields ONE event-producing strace line — so
 * `runInstallPhase` reports `eventCount > 0` — and exits with the supplied
 * code.  Used to exercise the "Phase B failed but the audit DID observe a
 * lifecycle script" path, which must stay non-fatal (unlike a zero-event
 * failure, which fails closed).
 */
function eventEmittingStrace(exitCode: number): StraceRunner {
  return {
    async *run() {
      // A strace execve with no paired shim exec is recorded as an exec
      // event (audit_bypass) — exec events emit even when attribution
      // cannot resolve a package, so this reliably yields eventCount > 0
      // without needing a /proc-backed Attribution.
      yield {
        pid: 5555,
        line: 'execve("/usr/bin/node", ["node", "install.js"], 0x7ffd /* 12 vars */) = 0',
        source: 'strace' as const,
      };
    },
    getExitCode() { return exitCode; },
    getTamperReason() { return null; },
    recordTamper(_reason: string) { /* no-op for test fakes */ },
    getRootPid() { return 5555; },
  };
}

/**
 * A LinuxStraceRunner subclass that emits no records, succeeds with the
 * supplied exit code, and reports a fixed tamper reason.  Historically this
 * existed because the agent's fail-closed gate dispatched on
 * `instanceof LinuxStraceRunner` — Finding D moved that gate onto the
 * `StraceRunner` interface contract, so a plain object literal works too
 * (see `tamperingPlainStrace` below).  Keep the subclass variant around
 * to exercise the inheritance path for any future LinuxStraceRunner
 * decorator subclasses that ride on it.
 */
class TamperingStraceRunner extends LinuxStraceRunner {
  private readonly _reason: string;
  private readonly _stubExitCode: number;
  constructor(reason: string, exitCode = 0) {
    super(undefined, null);
    this._reason = reason;
    this._stubExitCode = exitCode;
  }
  override async *run(_cmd: string, _args: string[]): AsyncIterable<{ pid: number; line: string; source: 'shim' | 'strace' }> {
    void _cmd; void _args;
  }
  override getExitCode(): number {
    return this._stubExitCode;
  }
  override getTamperReason(): string | null {
    return this._reason;
  }
}

/**
 * A plain object-literal `StraceRunner` (NOT a `LinuxStraceRunner`
 * subclass) that reports a fixed tamper reason.  Used to verify Finding D:
 * the agent's tamper gate must dispatch on the interface contract, not on
 * class identity, so any contract-conforming runner can force fail-closed.
 */
function tamperingPlainStrace(reason: string, exitCode = 0): StraceRunner {
  let currentReason = reason;
  return {
    async *run() { /* yield nothing */ },
    getExitCode() { return exitCode; },
    getTamperReason() { return currentReason; },
    recordTamper(r: string) {
      // First-writer-wins parity with LinuxStraceRunner.
      if (currentReason === '' || currentReason === null) currentReason = r;
    },
    getRootPid() { return null; },
  };
}

/**
 * A StraceRunner that also tracks which cmd was run.
 */
function trackingStrace(exitCode = 0): { strace: StraceRunner; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    strace: {
      async *run(cmd, args) {
        calls.push(`${cmd} ${args.join(' ')}`);
      },
      getExitCode() { return exitCode; },
      // Finding D: tamper reporting is part of the StraceRunner contract.
      getTamperReason() { return null; },
      recordTamper(_reason: string) { /* no-op for test fakes */ },
      getRootPid() { return null; },
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('agent main()', () => {
  it('calls fetch (spawner) then install (strace) in order', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner, calls: fetchCalls } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir);

    // Send the host "go" signal after a tiny delay
    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });

    // Phase A: npm ci --ignore-scripts
    expect(fetchCalls.length).toBeGreaterThanOrEqual(1);
    expect(fetchCalls[0]).toContain('npm ci');

    // Phase B: npm rebuild --foreground-scripts (via strace)
    expect(installCalls.length).toBeGreaterThanOrEqual(1);
    expect(installCalls[0]).toContain('npm rebuild');

    // Both handshakes emitted
    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const handshakes = frames.filter((f) => f['kind'] === 'handshake');
    const phases = handshakes.map((h) => h['phase']);
    expect(phases).toContain('fetch_done');
    expect(phases).toContain('install_done');
  });

  it('emits fetch_done before install_done', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner: mockSpawner().spawner, strace: emptyStrace(), dnsLookup: offlineLookup });

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const handshakes = frames.filter((f) => f['kind'] === 'handshake');
    expect(handshakes[0]?.['phase']).toBe('fetch_done');
    expect(handshakes[1]?.['phase']).toBe('install_done');
  });

  it('emits a final lockfile frame with kind=final', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner: mockSpawner().spawner, strace: emptyStrace(), dnsLookup: offlineLookup });

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const finals = frames.filter((f) => f['kind'] === 'final');
    expect(finals).toHaveLength(1);
    expect(typeof finals[0]?.['yaml']).toBe('string');
    expect((finals[0]?.['yaml'] as string)).toContain('schema_version: 1');
  });

  it('emits node_version sourced from the running Node (no leading v)', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    // The config sets node_version: '20.0.0' but the agent should ignore it
    // and use the running Node's version (Task #12).
    const configPath = writeConfig(testDir, { node_version: '99.99.99' });

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: emptyStrace(),
      nodeVersion: 'v22.4.1',
      dnsLookup: offlineLookup,
    });

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const finals = frames.filter((f) => f['kind'] === 'final');
    expect(finals).toHaveLength(1);
    const yaml = finals[0]?.['yaml'] as string;
    // Should contain the injected version *without* the leading "v" and
    // NOT the value from config.
    expect(yaml).toMatch(/^node_version: 22\.4\.1$/m);
    expect(yaml).not.toMatch(/^node_version: 99\.99\.99$/m);
  });

  it('falls back to process.version when nodeVersion is not injected', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: emptyStrace(),
      dnsLookup: offlineLookup,
    });

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const finals = frames.filter((f) => f['kind'] === 'final');
    const yaml = finals[0]?.['yaml'] as string;
    const expectedVersion = process.version.replace(/^v/, '');
    expect(yaml).toMatch(new RegExp(`^node_version: ${expectedVersion.replace(/\./g, '\\.')}$`, 'm'));
  });

  it('waits for host go signal before starting phase B', async () => {
    const { conn, hostSend } = makeConn();
    const configPath = writeConfig(testDir);
    const { spawner } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();

    let phaseADone = false;
    const instrumentedSpawner: Spawner = {
      async spawn(cmd, args, opts) {
        const result = await spawner.spawn(cmd, args, opts);
        if (cmd === 'npm' && args.includes('ci')) phaseADone = true;
        return result;
      },
    };

    // Don't send "go" until after fetch completes
    const goDelay = new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(phaseADone).toBe(true);
        expect(installCalls).toHaveLength(0); // phase B not started yet
        hostSend('go\n');
        resolve();
      }, 50);
    });

    await Promise.all([
      main({ configPath, connection: conn, spawner: instrumentedSpawner, strace, dnsLookup: offlineLookup }),
      goDelay,
    ]);

    expect(installCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('rejects non-"go" control signals', async () => {
    const { conn, hostSend } = makeConn();
    const configPath = writeConfig(testDir);

    // Send a wrong signal
    setTimeout(() => hostSend('start\n'), 10);

    // main() should handle the rejection internally (emit error + exit)
    // Since process.exit would be called, we catch it via the error path.
    // In test, process.exit doesn't terminate — we just verify it doesn't hang.
    let exited = false;
    const origExit = process.exit.bind(process);
    const exitSpy = (code?: number | string) => { exited = true; void code; };
    // @ts-expect-error — patching process.exit for test
    process.exit = exitSpy;

    try {
      await main({ configPath, connection: conn, spawner: mockSpawner().spawner, strace: emptyStrace(), dnsLookup: offlineLookup });
      // flushAndExit() defers `exitFn()` until the writable's `end()`
      // callback fires (next tick on PassThrough), so we need one
      // micro/macro-task hop after `await main(...)` before asserting on
      // the stub.  Without this, the stub is checked while the end()
      // callback is still queued.
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    // Either main rejected or it exited
    expect(exited).toBe(true);
  });

  it('builds correct child env with LD_PRELOAD and NODE_OPTIONS', async () => {
    const { conn, hostSend } = makeConn();
    const configPath = writeConfig(testDir, { spoof: { platform: 'darwin', arch: 'arm64' } });

    const capturedEnvs: Array<NodeJS.ProcessEnv> = [];
    const spawner: Spawner = {
      async spawn(_cmd, _args, opts) {
        capturedEnvs.push(opts.env);
        return { exitCode: 0, stdout: '', stderr: '' };
      },
    };

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner, strace: emptyStrace(), dnsLookup: offlineLookup });

    expect(capturedEnvs.length).toBeGreaterThan(0);
    const env = capturedEnvs[0]!;
    expect(env['LD_PRELOAD']).toBe('/lib/libscriptjail.so');
    expect(env['SCRIPT_JAIL_SPOOF_PLATFORM']).toBe('darwin');
    expect(env['SCRIPT_JAIL_SPOOF_ARCH']).toBe('arm64');
    expect(env['NODE_OPTIONS']).not.toContain('dlopen-block.cjs');
    expect(env['NODE_OPTIONS']).toContain('platform-spoof.cjs');
    expect(env['NODE_OPTIONS']).toContain('env-spy.cjs');
    expect(env['SCRIPT_JAIL_LOG_FD']).toBe('3');
    // Native addons and child_process internals stay enabled; the audit
    // envelope observes their syscalls instead of disabling the Node runtime.
    expect(env['NODE_OPTIONS']).not.toContain('--no-addons');
    expect(env['SCRIPT_JAIL_NODE_OPTIONS']).not.toContain('--no-addons');
    expect(env['SCRIPT_JAIL_NODE_OPTIONS']).toContain('platform-spoof.cjs');
    expect(env['SCRIPT_JAIL_NODE_OPTIONS']).toContain('env-spy.cjs');
  });

  it('macos-bare keeps native file/connect auditing off in Phase A and on in Phase B', async () => {
    const { conn, hostSend } = makeConn();
    const configPath = writeConfig(testDir, { spoof: { platform: 'darwin', arch: 'arm64' } });
    const oldBackend = process.env['SCRIPT_JAIL_BACKEND'];
    const oldAuditOps = process.env['SCRIPT_JAIL_MACOS_AUDIT_OPS'];
    process.env['SCRIPT_JAIL_BACKEND'] = 'macos-bare';
    process.env['SCRIPT_JAIL_MACOS_AUDIT_OPS'] = '1';

    const fetchEnvs: Array<NodeJS.ProcessEnv> = [];
    const installEnvs: Array<NodeJS.ProcessEnv> = [];
    const spawner: Spawner = {
      async spawn(_cmd, _args, opts) {
        fetchEnvs.push(opts.env);
        return { exitCode: 0, stdout: '', stderr: '' };
      },
    };
    const strace: StraceRunner = {
      async *run(_cmd, _args, opts) {
        installEnvs.push(opts.env);
      },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper(_reason: string) { /* no-op for this env-split test */ },
      getRootPid() { return null; },
    };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });
    } finally {
      if (oldBackend === undefined) delete process.env['SCRIPT_JAIL_BACKEND'];
      else process.env['SCRIPT_JAIL_BACKEND'] = oldBackend;
      if (oldAuditOps === undefined) delete process.env['SCRIPT_JAIL_MACOS_AUDIT_OPS'];
      else process.env['SCRIPT_JAIL_MACOS_AUDIT_OPS'] = oldAuditOps;
    }

    expect(fetchEnvs).toHaveLength(1);
    expect(installEnvs).toHaveLength(1);
    expect(fetchEnvs[0]!['DYLD_INSERT_LIBRARIES']).toBe('/lib/libscriptjail.so');
    expect(fetchEnvs[0]!['SCRIPT_JAIL_MACOS_AUDIT_OPS']).toBeUndefined();
    expect(installEnvs[0]!['SCRIPT_JAIL_MACOS_AUDIT_OPS']).toBe('1');
  });

  it('throws when config file does not exist', async () => {
    const { conn } = makeConn();
    await expect(
      main({ configPath: '/nonexistent/config.yml', connection: conn }),
    ).rejects.toThrow(/failed to read config/);
  });

  it('handles pnpm manager config', async () => {
    const { conn, hostSend } = makeConn();
    const { spawner, calls: fetchCalls } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir, { manager: 'pnpm' });

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });

    expect(fetchCalls[0]).toContain('pnpm install --frozen-lockfile --ignore-scripts');
    expect(installCalls[0]).toContain('pnpm rebuild');
  });

  it('handles yarn manager config', async () => {
    const { conn, hostSend } = makeConn();
    const { spawner, calls: fetchCalls } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir, { manager: 'yarn' });

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });

    expect(fetchCalls[0]).toContain('yarn install');
    expect(installCalls[0]).toContain('yarn install --immutable');
  });

  it('fails closed when Phase B exits non-zero with no audit events', async () => {
    // A non-zero Phase B exit with ZERO collected events means the install
    // machinery itself failed before any lifecycle script ran under audit.
    // Emitting a lockfile then would publish a deceptively-clean artifact —
    // fail closed: no install_done, no final, a fatal error frame instead.
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    const origExit = process.exit.bind(process);
    // @ts-expect-error — patching process.exit for test
    process.exit = () => { /* no-op */ };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: emptyStrace(1), // Phase B non-zero, zero events
        dnsLookup: offlineLookup,
      });
    } finally {
      process.exit = origExit;
    }

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const kinds = frames.map((f) => f['kind']);

    const installDoneFrames = frames.filter((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done');
    expect(installDoneFrames).toHaveLength(0);
    expect(kinds).not.toContain('final');

    const errFrame = frames.find((f) => f['kind'] === 'error');
    expect(errFrame?.['fatal']).toBe(true);
  });

  it('Phase B zero-event fail-closed surfaces a REDACTED install-stdout tail', async () => {
    // yarn Berry writes setup errors (Usage Errors, YN0028, resolution
    // failures) to STDOUT, not stderr.  When Phase B fails before any
    // lifecycle script runs (zero events) the fatal frame MUST include a tail
    // of that stdout so the cause is diagnosable — but with credential shapes
    // masked (it is raw, repo-controlled text).  Regression guard for the
    // `--offline` class of failures that previously surfaced as a useless
    // "produced no audit events" with no cause.
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    // A realistic yarn-stdout failure mixed with a credential SHAPE (layer-2
    // redaction fires without needing a process.env value).
    const secret = 'npm_' + 'A'.repeat(36);
    const stdoutTail =
      'Unknown Syntax Error: Unsupported option name ("--offline").\n' +
      `  resolving from //registry.example.com/:_authToken=${secret}\n`;

    const origExit = process.exit.bind(process);
    // @ts-expect-error — patching process.exit for test
    process.exit = () => { /* no-op */ };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: emptyStraceWithStdout(1, stdoutTail),
        dnsLookup: offlineLookup,
      });
    } finally {
      process.exit = origExit;
    }

    const frames = getOutput()
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    const errFrame = frames.find((f) => f['kind'] === 'error');
    expect(errFrame?.['fatal']).toBe(true);
    const msg = String(errFrame?.['message'] ?? '');
    // The real cause is now visible…
    expect(msg).toContain('install stdout (tail)');
    expect(msg).toContain('Unknown Syntax Error');
    // …but the credential shape is masked, not leaked verbatim.
    expect(msg).not.toContain(secret);
    // …and no final lockfile / install_done was emitted (still fail-closed).
    expect(frames.map((f) => f['kind'])).not.toContain('final');
  });

  // ---------------------------------------------------------------------------
  // Phase-A FAILURE redaction — developer install `args` value masking.
  //
  // adversarial-review round-7 [high]: the drop-in install threads developer
  // `args` into the SANDBOX Phase-A fetch via the pm-flags `user_install_args`
  // channel.  On the fetch-FAILURE path the agent redacts the PM stderr/stdout
  // with `redactSensitive` (protected-ENV values + credential SHAPES) ONLY —
  // which does NOT mask a user-arg value like `SECRET_TOKEN` echoed by
  // `npm warn invalid config registry="SECRET_TOKEN"`.  That value matched no
  // shape and no protected env, so it leaked to the public Actions log via BOTH
  // sinks (serial-console `process.stderr.write` + the fatal vsock error frame).
  // The fix masks the known exact user-arg values FIRST.
  // ---------------------------------------------------------------------------
  describe('Phase-A fetch-failure redacts developer install args', () => {
    /** Fail-spawner: Phase A fetch exits non-zero with a chosen stderr/stdout. */
    function failingFetchSpawner(stderr: string, stdout = ''): Spawner {
      return {
        async spawn() {
          return { exitCode: 1, stdout, stderr };
        },
      };
    }

    /**
     * Drive main() to the Phase-A failure site with `userArgs` staged in a
     * pm-flags.json (npm consumes user_install_args).  Captures BOTH sinks:
     * the fatal error frame's message and everything written to process.stderr.
     */
    async function runPhaseAFailure(
      userArgs: string[],
      stderr: string,
      stdout = '',
    ): Promise<{ frameMsg: string; serial: string }> {
      const { conn, getOutput } = makeConn();
      const configPath = writeConfig(testDir);

      // Stage user_install_args; the agent points runFetchPhase at this copy
      // via SCRIPT_JAIL_PM_FLAGS_PATH (the non-Firecracker staged-copy path).
      const pmFlagsPath = join(testDir, 'pm-flags.json');
      writeFileSync(
        pmFlagsPath,
        JSON.stringify({ extra_install_args: [], user_install_args: userArgs }),
      );

      const oldPmFlags = process.env['SCRIPT_JAIL_PM_FLAGS_PATH'];
      process.env['SCRIPT_JAIL_PM_FLAGS_PATH'] = pmFlagsPath;

      // Capture the serial-console sink (process.stderr.write).
      let serial = '';
      const origWrite = process.stderr.write.bind(process.stderr);
      const stderrSpy = (chunk: string | Uint8Array): boolean => {
        serial += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString();
        return true;
      };
      process.stderr.write = stderrSpy as typeof process.stderr.write;

      const origExit = process.exit.bind(process);
      // @ts-expect-error — patching process.exit for test
      process.exit = () => { /* no-op */ };

      try {
        await main({
          configPath,
          connection: conn,
          spawner: failingFetchSpawner(stderr, stdout),
          strace: emptyStrace(), // never reached — Phase A fails first
          dnsLookup: offlineLookup,
        });
      } finally {
        process.exit = origExit;
        process.stderr.write = origWrite;
        if (oldPmFlags === undefined) delete process.env['SCRIPT_JAIL_PM_FLAGS_PATH'];
        else process.env['SCRIPT_JAIL_PM_FLAGS_PATH'] = oldPmFlags;
      }

      const frames = getOutput()
        .split('\n')
        .filter((l) => l.trim())
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      const errFrame = frames.find((f) => f['kind'] === 'error' && f['fatal'] === true);
      return { frameMsg: String(errFrame?.['message'] ?? ''), serial };
    }

    it('masks an `--registry=SECRET_TOKEN` value echoed by the PM (=-form)', async () => {
      const { frameMsg, serial } = await runPhaseAFailure(
        ['--registry=SECRET_TOKEN'],
        'npm warn invalid config registry="SECRET_TOKEN" set in command line options\n',
      );
      // BOTH sinks must be scrubbed and BOTH must carry the mask token.
      expect(frameMsg).not.toContain('SECRET_TOKEN');
      expect(serial).not.toContain('SECRET_TOKEN');
      expect(frameMsg).toContain('<REDACTED:USER-ARG>');
      expect(serial).toContain('<REDACTED:USER-ARG>');
    });

    it('masks a split-pair `--registry SECRET_TOKEN` value (whole-token, len>=4)', async () => {
      const { frameMsg, serial } = await runPhaseAFailure(
        ['--registry', 'SECRET_TOKEN'],
        'npm error could not resolve registry SECRET_TOKEN offline\n',
      );
      expect(frameMsg).not.toContain('SECRET_TOKEN');
      expect(serial).not.toContain('SECRET_TOKEN');
      expect(frameMsg).toContain('<REDACTED:USER-ARG>');
      expect(serial).toContain('<REDACTED:USER-ARG>');
    });

    it('leaves a no-user-args Phase-A failure byte-identical (deriveSensitiveValues([]) is identity)', async () => {
      const stderr = '➤ YN0001: │ Error: ENOSPC: no space left on device, write\n';
      const { frameMsg, serial } = await runPhaseAFailure([], stderr);
      // No mask token injected; the (trimmed) PM error survives verbatim.
      expect(frameMsg).not.toContain('<REDACTED:USER-ARG>');
      expect(serial).not.toContain('<REDACTED:USER-ARG>');
      expect(frameMsg).toContain('ENOSPC: no space left on device');
      expect(serial).toContain('ENOSPC: no space left on device');
    });
  });

  it('still emits install_done and the final lockfile when Phase B exits non-zero but audited scripts', async () => {
    // A non-zero Phase B exit WITH collected events means a dependency
    // lifecycle script ran and failed under audit (e.g. an offline
    // postinstall).  That is audit data, not a fatal error — the lockfile
    // must still be emitted, accompanied by a NON-fatal error frame.
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    const origExit = process.exit.bind(process);
    // @ts-expect-error — patching process.exit for test
    process.exit = () => { /* no-op */ };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: eventEmittingStrace(1), // Phase B non-zero, but events observed
        dnsLookup: offlineLookup,
      });
    } finally {
      process.exit = origExit;
    }

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const kinds = frames.map((f) => f['kind']);

    // install_done IS emitted — the audit observed scripts, so non-zero is non-fatal.
    const installDoneFrames = frames.filter((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done');
    expect(installDoneFrames).toHaveLength(1);

    // The final lockfile IS emitted.
    expect(kinds).toContain('final');

    // A NON-fatal error frame surfaces the non-zero exit for host visibility.
    const errFrame = frames.find((f) => f['kind'] === 'error');
    expect(errFrame).toBeDefined();
    expect(errFrame?.['fatal']).toBe(false);
  });

  it('proceeds to Phase B when verifyOffline reports the lookup failed (offline)', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner, calls: fetchCalls } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir);

    const lookupCalls: string[] = [];
    const recordingLookup: DnsLookupFn = (hostname, callback) => {
      lookupCalls.push(hostname);
      setImmediate(() => {
        const err = new Error('getaddrinfo ENOTFOUND') as NodeJS.ErrnoException;
        err.code = 'ENOTFOUND';
        callback(err);
      });
    };

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner,
      strace,
      dnsLookup: recordingLookup,
    });

    // verifyOffline should have asked about the registry hostname between
    // fetch and install.
    expect(lookupCalls).toEqual(['registry.npmjs.org']);

    // Both phases ran.
    expect(fetchCalls.length).toBeGreaterThanOrEqual(1);
    expect(installCalls.length).toBeGreaterThanOrEqual(1);

    // The final lockfile was emitted (no fatal abort).
    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(frames.some((f) => f['kind'] === 'final')).toBe(true);
  });

  it('aborts fatally with an error frame when DNS still resolves after go', async () => {
    // Stronger failure signal now: dropEth0 succeeded AND DNS still resolved
    // within the timeout, which means the in-guest interface drop did not
    // take effect (or was bypassed entirely).
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir);

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner,
        strace,
        dropEth0: async () => { /* pretend the drop succeeded */ },
        dnsLookup: onlineLookup, // resolver still works → interface drop ineffective
      });
      // See the comment in 'rejects non-"go"' for why we need this hop:
      // flushAndExit() invokes the captured exit function from the
      // writable's `end()` callback, which is one tick away on a
      // PassThrough.  Without this await the assertion races the callback.
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    // Phase B must NOT have started.
    expect(installCalls).toHaveLength(0);

    // The agent should have called process.exit(1) and emitted a fatal error
    // frame that names the offline check.
    expect(exitedWith).toBe(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const errors = frames.filter((f) => f['kind'] === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0]!['fatal']).toBe(true);
    expect(String(errors[0]!['message'])).toMatch(/DNS still resolves/);

    // And no install_done / final after the abort.
    const kinds = frames.map((f) => f['kind']);
    expect(kinds).not.toContain('final');
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done'),
    ).toBe(false);
  });

  it('calls dropEth0 before the DNS verifyOffline lookup', async () => {
    const { conn, hostSend } = makeConn();
    const { spawner } = mockSpawner();
    const { strace } = trackingStrace();
    const configPath = writeConfig(testDir);

    const order: string[] = [];
    const dropEth0 = async (): Promise<void> => {
      order.push('dropEth0');
    };
    const lookup: DnsLookupFn = (_h, cb) => {
      order.push('lookup');
      setImmediate(() => {
        const err = new Error('ENOTFOUND') as NodeJS.ErrnoException;
        err.code = 'ENOTFOUND';
        cb(err);
      });
    };

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner,
      strace,
      dropEth0,
      dnsLookup: lookup,
    });

    expect(order).toEqual(['dropEth0', 'lookup']);
  });

  it('emits a non-fatal error frame and continues when dropEth0 fails', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir);

    const dropEth0 = async (): Promise<void> => {
      throw new Error('no such device');
    };

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner,
      strace,
      dropEth0,
      dnsLookup: offlineLookup,
    });

    // Phase B still ran — the DNS probe is the final gate.
    expect(installCalls.length).toBeGreaterThanOrEqual(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const errors = frames.filter((f) => f['kind'] === 'error');
    // Exactly one non-fatal error frame from the dropEth0 failure.
    expect(errors).toHaveLength(1);
    expect(errors[0]!['fatal']).toBe(false);
    expect(String(errors[0]!['message'])).toMatch(/drop eth0/);

    // Install_done and final were still emitted.
    const kinds = frames.map((f) => f['kind']);
    expect(kinds).toContain('final');
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done'),
    ).toBe(true);
  });

  // ── Finding A: agent fails closed when the events file was tampered ─────
  //
  // The tailer records a tamper reason whenever the events file disappears,
  // is replaced, or shrinks.  main() must convert that into a fatal error
  // frame and refuse to emit a final lockfile — otherwise a hostile
  // lifecycle script that `rm`s the events file (erasing audit_bypass
  // evidence) could pair its evasion with a clean YAML diff.
  it('aborts fatally with an error frame when the strace runner reports events-file tampering', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const configPath = writeConfig(testDir);

    // LinuxStraceRunner subclass — exercises the inheritance path.  The
    // Finding-D refactor moved the gate onto the contract so a plain
    // object literal works too (see the test immediately below).
    const strace = new TamperingStraceRunner('events file disappeared: /tmp/events.jsonl');

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });
      // flushAndExit's callback fires one tick later.
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    expect(exitedWith).toBe(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // The fatal error must name the tamper reason verbatim, so the host's
    // log surfaces what happened.
    const errors = frames.filter((f) => f['kind'] === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0]!['fatal']).toBe(true);
    expect(String(errors[0]!['message'])).toMatch(/tampered/);
    expect(String(errors[0]!['message'])).toMatch(/events file disappeared/);

    // Critically: NO `install_done` handshake and NO `final` lockfile.
    // Without this, the host's check mode would diff a possibly-clean
    // YAML and pass on tampered audit data.
    const kinds = frames.map((f) => f['kind']);
    expect(kinds).not.toContain('final');
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done'),
    ).toBe(false);
  });

  // ── Finding E: agent fails closed when createEventsFile throws ──────────
  //
  // The previous code wrapped createEventsFile() in a try/catch and fell
  // back to SCRIPT_JAIL_LOG_FILE="".  npm spawns lifecycle children with
  // `stdio: 'inherit'` which only propagates fds 0–2 — so the SCRIPT_JAIL_
  // LOG_FD=3 channel does NOT survive past the first child.  Descendants
  // (the actual node processes inside lifecycle scripts) lose their audit
  // sink entirely: env_read / dlopen / exec / env_tamper events go into
  // the void.  A transient /tmp blip would silently produce a clean
  // lockfile with missing audit signals.  The fix: bail with a fatal
  // error frame before Phase A starts; never emit a final lockfile.
  it('aborts fatally with an error frame when createEventsFile throws', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const { strace } = trackingStrace();
    const configPath = writeConfig(testDir);

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    // The host go signal is irrelevant — the agent must bail before
    // Phase A. We send one anyway so a regression that lets the agent
    // proceed doesn't deadlock the test waiting for it.
    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner,
        strace,
        dnsLookup: offlineLookup,
        createEventsFile: () => {
          const err = new Error('EACCES: /tmp is read-only') as NodeJS.ErrnoException;
          err.code = 'EACCES';
          throw err;
        },
      });
      // flushAndExit's callback fires one tick later.
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    expect(exitedWith).toBe(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // Exactly one fatal error frame, naming the underlying failure.
    const errors = frames.filter((f) => f['kind'] === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0]!['fatal']).toBe(true);
    expect(String(errors[0]!['message'])).toMatch(/failed to create audit-events file/);
    expect(String(errors[0]!['message'])).toMatch(/EACCES/);

    // Critically: NO `install_done` handshake, NO `fetch_done` handshake
    // (the bail happens before Phase A), and NO final lockfile.
    const kinds = frames.map((f) => f['kind']);
    expect(kinds).not.toContain('final');
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done'),
    ).toBe(false);
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'fetch_done'),
    ).toBe(false);
  });

  // ── Finding D: tamper gate dispatches on contract, not class identity ───
  //
  // The previous gate was `straceRunner instanceof LinuxStraceRunner`, which
  // silently skipped the tamper check for ANY runner that wasn't a direct
  // subclass — wrappers, decorators, alternative production implementations,
  // or test fakes that carried a legitimate tamper reason were all ignored.
  // Finding D moved tamper reporting onto the StraceRunner interface so the
  // gate is now `straceRunner.getTamperReason()`.  A plain object literal
  // that conforms to the contract MUST trigger fail-closed.
  it('honors getTamperReason() from a plain-object StraceRunner (no LinuxStraceRunner subclass)', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const configPath = writeConfig(testDir);

    // Plain object literal — NOT an instance of LinuxStraceRunner.  Under
    // the old `instanceof` gate this would have been silently ignored and
    // the agent would have emitted a clean final lockfile.
    const strace = tamperingPlainStrace('events file inode mismatch: dev=42 ino=99');

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    expect(exitedWith).toBe(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    const errors = frames.filter((f) => f['kind'] === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0]!['fatal']).toBe(true);
    expect(String(errors[0]!['message'])).toMatch(/tampered/);
    expect(String(errors[0]!['message'])).toMatch(/inode mismatch/);

    const kinds = frames.map((f) => f['kind']);
    expect(kinds).not.toContain('final');
    expect(
      frames.some((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done'),
    ).toBe(false);
  });

  it('treats a hung DNS lookup as offline once the verify timeout fires', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const { spawner } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir);

    // A lookup that never invokes its callback — simulates the resolver
    // hanging after we drop eth0.  The timeout must rescue us.
    const hangingLookup: DnsLookupFn = () => { /* never calls back */ };

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner,
      strace,
      dropEth0: async () => { /* succeed silently */ },
      dnsLookup: hangingLookup,
      verifyOfflineTimeoutMs: 25,
    });

    // Phase B ran (hung lookup treated as offline).
    expect(installCalls.length).toBeGreaterThanOrEqual(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const kinds = frames.map((f) => f['kind']);
    expect(kinds).toContain('final');
    // No fatal error from the verify step.
    const fatalErrors = frames.filter((f) => f['kind'] === 'error' && f['fatal'] === true);
    expect(fatalErrors).toHaveLength(0);
  });

  it('order: fetch_done then events then install_done then final', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir);

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: emptyStrace(),
      dnsLookup: offlineLookup,
    });

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const kinds = lines.map((l) => (JSON.parse(l) as Record<string, unknown>)['kind']);

    // fetch_done is first handshake
    const fetchIdx = kinds.indexOf('handshake');
    // install_done is second handshake
    const installDoneIdx = kinds.lastIndexOf('handshake');
    const finalIdx = kinds.lastIndexOf('final');

    expect(fetchIdx).toBeLessThan(installDoneIdx);
    expect(installDoneIdx).toBeLessThan(finalIdx);
  });
});

describe('agent main() root-prepare second pass', () => {
  // A StraceRunner that yields ONE strace execve line with no paired shim exec
  // → recorded as a `<SYSCALL_EXEC_BYPASS>` event, which emits even without
  // /proc attribution (lands under `<unattributed>`).  So the pass reports
  // eventCount>0, AND we record the (cmd,args) it was asked to run.  The
  // DISTINCT argv[0] basename (rendered verbatim by the bypass synthesis) lets
  // us tell the main pass's event apart from the prepare pass's in the lock.
  function recordingEventStrace(progName: string): {
    runner: StraceRunner;
    calls: Array<{ cmd: string; args: string[] }>;
  } {
    const calls: Array<{ cmd: string; args: string[] }> = [];
    const runner: StraceRunner = {
      async *run(cmd: string, args: string[]) {
        calls.push({ cmd, args });
        const pid = 7000 + calls.length;
        yield {
          pid,
          line: `execve("/usr/bin/${progName}", ["${progName}"], 0x7ffd /* 12 vars */) = 0`,
          source: 'strace' as const,
        };
      },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper(_reason: string) { /* no-op */ },
      getRootPid() { return 7001; },
    };
    return { runner, calls };
  }

  it('runs the prepare pass (npm) when prepareStrace is injected; merges its events', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    const prep = recordingEventStrace('PREPPROG');
    const diagMsgs: string[] = [];

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: main_.runner,
      prepareStrace: prep.runner,
      dnsLookup: offlineLookup,
      diag: (m) => diagMsgs.push(m),
    });

    // The prepare runner WAS invoked, with the npm prepare command (NOT rebuild).
    expect(prep.calls).toHaveLength(1);
    expect(prep.calls[0]!.cmd).toBe('npm');
    expect(prep.calls[0]!.args).toEqual(['run', 'prepare', '--if-present', '--foreground-scripts']);
    // The main install runner ran the install command.
    expect(main_.calls).toHaveLength(1);
    expect(main_.calls[0]!.args).toEqual(['rebuild', '--foreground-scripts']);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // A final lockfile is emitted and contains BOTH passes' events (merged into
    // the same collectingEmitter → collectedEvents → lockfile).
    const finalFrame = frames.find((f) => f['kind'] === 'final');
    expect(finalFrame).toBeDefined();
    const yaml = String(finalFrame!['yaml'] ?? finalFrame!['lockfile'] ?? '');
    expect(yaml).toContain('MAINPROG');
    expect(yaml).toContain('PREPPROG');

    // A diag breadcrumb confirms the prepare pass fired.
    expect(diagMsgs.some((m) => m.includes('prepare pass'))).toBe(true);
  });

  it('SKIPS the prepare pass when only strace is injected (no prepareStrace)', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    const diagMsgs: string[] = [];

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: main_.runner,
      // prepareStrace intentionally omitted → test seam skips the pass.
      dnsLookup: offlineLookup,
      diag: (m) => diagMsgs.push(m),
    });

    // Only the main install ran.
    expect(main_.calls).toHaveLength(1);

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const finalFrame = frames.find((f) => f['kind'] === 'final');
    expect(finalFrame).toBeDefined();
    const yaml = String(finalFrame!['yaml'] ?? finalFrame!['lockfile'] ?? '');
    expect(yaml).toContain('MAINPROG');
    expect(yaml).not.toContain('PREPPROG');

    // No prepare-pass breadcrumb.
    expect(diagMsgs.some((m) => m.includes('prepare pass'))).toBe(false);
  });

  it('SKIPS the prepare pass for pnpm even with prepareStrace (resolver returns null)', async () => {
    const { conn, hostSend } = makeConn();
    // pnpm config — root prepare already covered by `pnpm rebuild --pending`.
    const configPath = writeConfig(testDir, { manager: 'pnpm' });

    const main_ = recordingEventStrace('MAINPROG');
    const prep = recordingEventStrace('PREPPROG');

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: main_.runner,
      prepareStrace: prep.runner,
      dnsLookup: offlineLookup,
    });

    // resolvePrepareCommand('pnpm', …) → null, so the prepare runner is never
    // invoked even though it was injected.
    expect(prep.calls).toHaveLength(0);
    expect(main_.calls).toHaveLength(1);
  });

  it('merges a prepare-pass tamper reason → fails closed at the tamper gate', async () => {
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    // Prepare runner yields a POISONED shim-channel line (unparseable JSONL on
    // the trusted channel). The prepare dispatcher's `setPhaseTamper` fires and
    // surfaces the reason via `prepareResult.tamperReason`, which the agent
    // MERGES into installResult.tamperReason → the 11b tamper gate fails closed.
    // (A test fake's `getTamperReason()` would NOT flow through the merge — only
    // the dispatcher-owned reason does — so we drive the real dispatcher path.)
    const prepTamper: StraceRunner = {
      async *run() {
        yield { pid: 9001, line: 'not-json-at-all{', source: 'shim' as const };
      },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper(_r: string) { /* no-op */ },
      getRootPid() { return 9001; },
    };

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: main_.runner,
        prepareStrace: prepTamper,
        dnsLookup: offlineLookup,
      });
      // flushAndExit's callback fires one tick later.
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // Fatal error frame, no final lockfile.
    const fatal = frames.find((f) => f['kind'] === 'error' && f['fatal'] === true);
    expect(fatal).toBeDefined();
    expect(String(fatal!['message'])).toContain('audit pipeline tampered with');
    expect(frames.some((f) => f['kind'] === 'final')).toBe(false);
    expect(exitedWith).toBe(1);
  });

  it('fails closed on a prepare-RUNNER file-tamper surfaced via getTamperReason()', async () => {
    // The PRODUCTION events-file tamper signal (unlink / inode-swap / mtime
    // regression) is reported by the runner's `getTamperReason()`, NOT by the
    // dispatcher's owned reason — and runInstallPhase's PhaseInstallResult only
    // carries the dispatcher-owned reason.  The 11b gate consults the MAIN
    // runner's getTamperReason(), but the PREPARE runner's is only reachable
    // through the merge.  This asserts that merge folds it in (regression guard
    // for the gap a clean lockfile would otherwise hide on a prepare-pass
    // events-file tamper).
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    const prepFileTamper: StraceRunner = {
      async *run() { /* zero dispatcher events; tamper is file-level */ },
      getExitCode() { return 0; },
      // Dispatcher-owned reason stays null; the file-tamper rides here.
      getTamperReason() { return '<EVENTS_FILE_UNLINKED> prepare'; },
      recordTamper(_r: string) { /* no-op */ },
      getRootPid() { return null; },
    };

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: main_.runner,
        prepareStrace: prepFileTamper,
        dnsLookup: offlineLookup,
      });
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    const fatal = frames.find((f) => f['kind'] === 'error' && f['fatal'] === true);
    expect(fatal).toBeDefined();
    expect(String(fatal!['message'])).toContain('audit pipeline tampered with');
    expect(String(fatal!['message'])).toContain('<EVENTS_FILE_UNLINKED>');
    expect(frames.some((f) => f['kind'] === 'final')).toBe(false);
    expect(exitedWith).toBe(1);
  });

  it('FAILS CLOSED (no lockfile) when the prepare events-file cannot be created (review #2)', async () => {
    // The prepare pass must NEVER silently skip: skipping would render a final
    // lock with the root `prepare` UNAUDITED while `check` mode could still
    // return trusted.  `forcePreparePass` drives the production "build my own
    // runner / events file" branch with an injected MAIN runner; the 2nd
    // createEventsFile call (the prepare events file) throws → fatal, no lock.
    const { createEventsFile } = await import('../../src/guest/agent.js');
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });
    const main_ = recordingEventStrace('MAINPROG');

    let calls = 0;
    const createEventsFileCounting = () => {
      calls += 1;
      if (calls === 1) return createEventsFile(); // main events file — real, so the main pass works
      const err = new Error('ENOSPC: scratch full') as NodeJS.ErrnoException;
      err.code = 'ENOSPC';
      throw err; // prepare events file — fail
    };

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);
    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: main_.runner,
        forcePreparePass: true, // drive the build-own-runner branch with an injected main runner
        createEventsFile: createEventsFileCounting,
        dnsLookup: offlineLookup,
      });
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    const fatal = frames.find((f) => f['kind'] === 'error' && f['fatal'] === true);
    expect(fatal).toBeDefined();
    expect(String(fatal!['message'])).toMatch(/root-prepare pass/);
    expect(String(fatal!['message'])).toMatch(/Refusing to emit a lockfile/);
    // The main install ran, but NO final lockfile ships (fail closed).
    expect(main_.calls).toHaveLength(1);
    expect(frames.some((f) => f['kind'] === 'final')).toBe(false);
    expect(exitedWith).toBe(1);
  });

  it('FAILS CLOSED (no lockfile) when prepare exits nonzero with ZERO events (untraced-prepare audit-bypass)', async () => {
    // The prepare pass is KNOWN to exist (prepareCommand !== null), so a
    // traced run must produce events.  Zero events + nonzero exit = strace
    // couldn't attach or the PM aborted before spawning the prepare script —
    // the root `prepare` ran UNAUDITED.  A clean diff against the resulting
    // lockfile would pass silently.  The gate must fail closed.
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    // Prepare runner yields ZERO events and exits nonzero — simulates
    // strace failing to attach or PM aborting before the prepare script runs.
    const prepZeroEvents: StraceRunner = {
      async *run() { /* no events */ },
      getExitCode() { return 1; },
      getTamperReason() { return null; },
      recordTamper(_r: string) { /* no-op */ },
      getRootPid() { return null; },
    };

    const origExit = process.exit.bind(process);
    let exitedWith: number | string | undefined;
    // @ts-expect-error — patching process.exit for test
    process.exit = (code?: number | string) => { exitedWith = code; };

    setTimeout(() => hostSend('go\n'), 10);

    try {
      await main({
        configPath,
        connection: conn,
        spawner: mockSpawner().spawner,
        strace: main_.runner,
        prepareStrace: prepZeroEvents,
        dnsLookup: offlineLookup,
      });
      await new Promise<void>((r) => setImmediate(r));
    } finally {
      process.exit = origExit;
    }

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // Fatal error frame (fatal: true) mentioning the untraced prepare.
    const fatal = frames.find((f) => f['kind'] === 'error' && f['fatal'] === true);
    expect(fatal).toBeDefined();
    expect(String(fatal!['message'])).toMatch(/prepare pass/);
    expect(String(fatal!['message'])).toMatch(/no audit events/);
    expect(String(fatal!['message'])).toMatch(/Refusing to emit a lockfile/);
    // No final lockfile frame must be emitted.
    expect(frames.some((f) => f['kind'] === 'final')).toBe(false);
    expect(exitedWith).toBe(1);
  });

  it('does NOT fail closed when prepare exits nonzero WITH events (traced failure is fine)', async () => {
    // Counter-test: a prepare that fails offline but was traced produces audit
    // data.  The fix must NOT over-fail this case — the lock is still emitted.
    const { conn, hostSend, getOutput } = makeConn();
    const configPath = writeConfig(testDir, { manager: 'npm' });

    const main_ = recordingEventStrace('MAINPROG');
    // Prepare runner yields ONE event (traced run) but exits nonzero.
    const prepNonzeroWithEvents: StraceRunner = {
      async *run(cmd: string, args: string[]) {
        void cmd; void args;
        yield {
          pid: 8001,
          line: 'execve("/usr/bin/PREPPROG", ["PREPPROG"], 0x7ffd /* 12 vars */) = 0',
          source: 'strace' as const,
        };
      },
      getExitCode() { return 1; },
      getTamperReason() { return null; },
      recordTamper(_r: string) { /* no-op */ },
      getRootPid() { return 8001; },
    };

    setTimeout(() => hostSend('go\n'), 10);

    await main({
      configPath,
      connection: conn,
      spawner: mockSpawner().spawner,
      strace: main_.runner,
      prepareStrace: prepNonzeroWithEvents,
      dnsLookup: offlineLookup,
    });

    const lines = getOutput().split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    // A final lockfile is still emitted (not fail-closed).
    const finalFrame = frames.find((f) => f['kind'] === 'final');
    expect(finalFrame).toBeDefined();
    // A non-fatal error frame is emitted for the prepare failure.
    const nonFatalError = frames.find((f) => f['kind'] === 'error' && f['fatal'] === false);
    expect(nonFatalError).toBeDefined();
    expect(String(nonFatalError!['message'])).toMatch(/prepare pass.*exited non-zero/);
    // No fatal error — the run is not blocked.
    expect(frames.some((f) => f['kind'] === 'error' && f['fatal'] === true)).toBe(false);
  });
});

describe('buildChildEnv protected-env-names length gate', () => {
  // Audit-trust Finding 2 (2026-05-18): the Rust shim's `capture_canon`
  // copies SCRIPT_JAIL_PROTECTED_ENV_NAMES into a fixed-size CanonBuf
  // (CANON_BUF_LEN = 1024 bytes including NUL).  A long list silently
  // truncates inside the shim — the dropped names are NOT registered as
  // protected, and those env-var values would leak through env-spy / shim
  // getenv unannotated for every audited child.  The fix rejects the
  // config at buildChildEnv-time (on the trusted host side, before any
  // audit begins) so the misconfiguration surfaces immediately rather than
  // producing a deceptively-clean lockfile.
  //
  // We import buildChildEnv and CANON_PROTECTED_ENV_NAMES_MAX_LEN from
  // their respective module paths.  buildChildEnv is exported solely for
  // this test surface; the production caller is `main()`.

  function makeConfig(protectedEnv: string[]): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: protectedEnv },
      spoof: { platform: 'linux', arch: 'x64' },
      node_version: '20.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: '/work',
      log_fd: 3,
      pkg_dirs: {},
    };
  }

  it('strips ambient macOS-only SCRIPT_JAIL_MACOS_AUDIT_OPS (and unknown SCRIPT_JAIL_*) from the Linux child env', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const env = buildChildEnv(
      { SCRIPT_JAIL_MACOS_AUDIT_OPS: '1', SCRIPT_JAIL_BOGUS: 'x', PATH: '/usr/bin:/bin' },
      makeConfig([]),
      '/tmp/events.jsonl',
    );
    // Regression (Codex adversarial review): the macOS audit-ops gate must NOT
    // be allow-listed in the shared lifecycle sanitizer.  On a Linux runner the
    // ELF shim has no audit-ops gate, so an ambient SCRIPT_JAIL_MACOS_AUDIT_OPS
    // must be STRIPPED from the audited child env — never ride through (which
    // would break the "strip unknown SCRIPT_JAIL_*" invariant and risk a
    // spurious env_read perturbing the byte-stable lock).
    expect(env['SCRIPT_JAIL_MACOS_AUDIT_OPS']).toBeUndefined();
    expect(env['SCRIPT_JAIL_BOGUS']).toBeUndefined();
  });

  it('accepts a protect list that fits within the CanonBuf payload (<= 1023 bytes)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { CANON_PROTECTED_ENV_NAMES_MAX_LEN, MAX_PROTECTED_ENV_NAMES } =
      await import('../../src/shim/canon-buf-len.js');

    // Build a list that approaches the byte cap from below WITHOUT
    // exceeding the entry-count cap (Finding 3, MAX_PROTECTED_ENV_NAMES =
    // 64).  64 × 15-byte names + 63 commas = 960 + 63 = 1023 bytes
    // (exactly the inclusive cap).  Each name is 15 bytes ASCII.
    const names: string[] = [];
    for (let i = 0; i < MAX_PROTECTED_ENV_NAMES; i++) {
      names.push(`PROT_NM_${String(i).padStart(2, '0')}_X`); // 15 bytes
    }
    const joined = names.join(',');
    expect(names.length).toBe(MAX_PROTECTED_ENV_NAMES);
    expect(Buffer.byteLength(joined, 'utf8')).toBeLessThanOrEqual(CANON_PROTECTED_ENV_NAMES_MAX_LEN);

    const env = buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl');
    expect(env['SCRIPT_JAIL_PROTECTED_ENV_NAMES']).toBe(joined);
  });

  it('rejects a protect list that would silently truncate inside the shim (> 1023 bytes)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { CANON_PROTECTED_ENV_NAMES_MAX_LEN, MAX_PROTECTED_ENV_NAMES } =
      await import('../../src/shim/canon-buf-len.js');

    // To exercise SOLELY the byte-length gate (Finding 2), keep the entry
    // count at or below MAX_PROTECTED_ENV_NAMES (64) but make individual
    // entries long enough that the joined byte length exceeds 1023.
    // 64 × 17-byte entries + 63 commas = 1088 + 63 = 1151 bytes.
    const names: string[] = [];
    for (let i = 0; i < MAX_PROTECTED_ENV_NAMES; i++) {
      names.push(`PROT_NAME_NO_${String(i).padStart(3, '0')}`); // 17 bytes ASCII
    }
    const joined = names.join(',');
    expect(names.length).toBe(MAX_PROTECTED_ENV_NAMES);
    expect(Buffer.byteLength(joined, 'utf8')).toBeGreaterThan(CANON_PROTECTED_ENV_NAMES_MAX_LEN);

    expect(() => buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl')).toThrow(
      /SCRIPT_JAIL_PROTECTED_ENV_NAMES is \d+ bytes/,
    );
    expect(() => buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl')).toThrow(
      /silently truncating/,
    );
  });

  it('error message references the configured entry count and the canon-buf cap', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { MAX_PROTECTED_ENV_NAMES } = await import('../../src/shim/canon-buf-len.js');

    // Stay at or below MAX_PROTECTED_ENV_NAMES so the entry-count gate
    // doesn't pre-empt the byte-length gate.  Build entries large enough
    // that the joined string is just over 1023 bytes.
    const names: string[] = [];
    let bytes = 0;
    // 64 × 17-byte entries → 64 entries (cap), 1151 bytes joined (over cap)
    for (let i = 0; i < MAX_PROTECTED_ENV_NAMES; i++) {
      const name = `PROT_NAME_NO_${String(i).padStart(3, '0')}`; // 17 bytes
      names.push(name);
      bytes += name.length + (i === 0 ? 0 : 1);
    }
    expect(bytes).toBeGreaterThanOrEqual(1024);
    expect(Buffer.byteLength(names.join(','), 'utf8')).toBeGreaterThanOrEqual(1024);

    let caught: Error | undefined;
    try {
      buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl');
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeDefined();
    expect(caught!.message).toContain(`${names.length} entries`);
    expect(caught!.message).toContain('1023 bytes');
  });
});

describe('buildChildEnv protect-list entry-count and per-entry-length gates', () => {
  // Audit-trust Finding 3 (2026-05-18): the shim's static protect-list
  // table holds `MAX_PROTECTED = 64` entries of at most `NAME_MAX_LEN - 1
  // = 255` bytes each.  The byte-length check from Finding 2 covers the
  // total CanonBuf size but NOT the structural caps inside
  // `load_protect_list_from_bytes`, so a configuration of many short
  // names (or a single very long name) could silently truncate inside
  // the shim despite passing the byte-length gate.  These tests pin the
  // boundary behaviour.

  function makeConfig(protectedEnv: string[]): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: protectedEnv },
      spoof: { platform: 'linux', arch: 'x64' },
      node_version: '20.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: '/work',
      log_fd: 3,
      pkg_dirs: {},
    };
  }

  it('accepts exactly MAX_PROTECTED_ENV_NAMES entries (boundary, must accept)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { MAX_PROTECTED_ENV_NAMES } = await import('../../src/shim/canon-buf-len.js');

    // Each entry "A" = 1 byte, total joined = 64 + 63 = 127 bytes (well
    // under the 1023-byte CanonBuf cap, so the entry-count check is the
    // only gate that could fire).
    const names = Array.from({ length: MAX_PROTECTED_ENV_NAMES }, (_, i) => `N${i}`);
    expect(names.length).toBe(MAX_PROTECTED_ENV_NAMES);

    const env = buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl');
    expect(env['SCRIPT_JAIL_PROTECTED_ENV_NAMES']).toBe(names.join(','));
  });

  it('rejects MAX_PROTECTED_ENV_NAMES + 1 entries with a precise error', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { MAX_PROTECTED_ENV_NAMES } = await import('../../src/shim/canon-buf-len.js');

    const names = Array.from(
      { length: MAX_PROTECTED_ENV_NAMES + 1 },
      (_, i) => `N${i}`,
    );
    // Joined "N0,N1,..." comfortably under the 1023-byte byte-length cap
    // (so the entry-count gate is the one that must fire).
    expect(Buffer.byteLength(names.join(','), 'utf8')).toBeLessThan(1023);

    expect(() => buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl')).toThrow(
      new RegExp(`SCRIPT_JAIL_PROTECTED_ENV_NAMES has ${MAX_PROTECTED_ENV_NAMES + 1} entries`),
    );
    expect(() => buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl')).toThrow(
      new RegExp(`at most ${MAX_PROTECTED_ENV_NAMES} entries`),
    );
  });

  it('accepts an entry of exactly PROTECTED_NAME_MAX_LEN bytes (boundary, must accept)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { PROTECTED_NAME_MAX_LEN } = await import('../../src/shim/canon-buf-len.js');

    // 255 ASCII bytes — exactly the cap.
    const name = 'A'.repeat(PROTECTED_NAME_MAX_LEN);
    expect(Buffer.byteLength(name, 'utf8')).toBe(PROTECTED_NAME_MAX_LEN);

    const env = buildChildEnv({}, makeConfig([name]), '/tmp/events.jsonl');
    expect(env['SCRIPT_JAIL_PROTECTED_ENV_NAMES']).toBe(name);
  });

  it('rejects an entry of PROTECTED_NAME_MAX_LEN + 1 bytes with a precise error', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { PROTECTED_NAME_MAX_LEN } = await import('../../src/shim/canon-buf-len.js');

    const tooLong = 'B'.repeat(PROTECTED_NAME_MAX_LEN + 1);
    // Single entry, well under the joined-byte-length cap, so the per-
    // entry gate is the one that must fire.
    expect(Buffer.byteLength(tooLong, 'utf8')).toBeLessThan(1023);

    expect(() => buildChildEnv({}, makeConfig([tooLong]), '/tmp/events.jsonl')).toThrow(
      new RegExp(`SCRIPT_JAIL_PROTECTED_ENV_NAMES entry \\[0\\] is ${PROTECTED_NAME_MAX_LEN + 1} bytes`),
    );
    expect(() => buildChildEnv({}, makeConfig([tooLong]), '/tmp/events.jsonl')).toThrow(
      new RegExp(`at most ${PROTECTED_NAME_MAX_LEN} bytes`),
    );
  });

  it('per-entry check reports the offending index when the bad entry is not first', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { PROTECTED_NAME_MAX_LEN } = await import('../../src/shim/canon-buf-len.js');

    const names = ['OK_ONE', 'OK_TWO', 'C'.repeat(PROTECTED_NAME_MAX_LEN + 1), 'OK_THREE'];
    expect(() => buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl')).toThrow(
      /entry \[2\] is \d+ bytes/,
    );
  });

  it('entry-count gate fires before the byte-length gate on multi-violation configs', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { MAX_PROTECTED_ENV_NAMES, CANON_PROTECTED_ENV_NAMES_MAX_LEN } =
      await import('../../src/shim/canon-buf-len.js');

    // 80 × 16-byte entries: 80 × 16 + 79 = 1359 bytes (both > 1023 AND >
    // 64 entries).  The entry-count error is the more actionable signal
    // (it points at the structural cap, not the byte cap), so we assert
    // it surfaces first.
    const names = Array.from(
      { length: 80 },
      (_, i) => `PROTECTED_NAME${String(i).padStart(2, '0')}`,
    );
    expect(names.length).toBeGreaterThan(MAX_PROTECTED_ENV_NAMES);
    expect(Buffer.byteLength(names.join(','), 'utf8')).toBeGreaterThan(
      CANON_PROTECTED_ENV_NAMES_MAX_LEN,
    );

    let caught: Error | undefined;
    try {
      buildChildEnv({}, makeConfig(names), '/tmp/events.jsonl');
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeDefined();
    expect(caught!.message).toMatch(/has \d+ entries/);
    expect(caught!.message).not.toMatch(/is \d+ bytes \(comma-joined/);
  });
});

describe('buildChildEnv protect-list strict env-var name gate (Finding 5)', () => {
  // Audit-trust Finding 5 (medium, 2026-05-18): the prior count cap
  // validated `config.protected.env.length` (YAML array length), but the
  // shim and env-spy parsers split the wire format on ',' and '\n' at
  // runtime.  A single YAML entry `"FOO,BAR,...,A65"` containing 65
  // names would pass the entry-count gate (1 entry) yet trigger
  // silent truncation inside the shim's `load_protect_list_from_bytes`.
  //
  // The fix rejects any YAML entry whose value does not match the
  // strict env-var name grammar `[A-Za-z_][A-Za-z0-9_]*`.  These tests
  // pin the gate so the audit chain cannot be defeated by smuggling
  // separators into individual entries.

  function makeConfig(protectedEnv: string[]): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: protectedEnv },
      spoof: { platform: 'linux', arch: 'x64' },
      node_version: '20.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: '/work',
      log_fd: 3,
      pkg_dirs: {},
    };
  }

  it('rejects an entry containing a comma (the wire separator)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    expect(() => buildChildEnv({}, makeConfig(['FOO,BAR']), '/tmp/events.jsonl')).toThrow(
      /entry \[0\] \("FOO,BAR"\) must not contain a comma/,
    );
  });

  it('rejects an entry containing a newline (the alternate wire separator)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    expect(() => buildChildEnv({}, makeConfig(['FOO\nBAR']), '/tmp/events.jsonl')).toThrow(
      /must not contain a newline/,
    );
  });

  it('rejects a single entry that smuggles 65 comma-joined names past the entry-count cap', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const { MAX_PROTECTED_ENV_NAMES } = await import('../../src/shim/canon-buf-len.js');
    // A single YAML entry composed of MAX+1 valid env-var names joined
    // by commas.  The OLD count check would see 1 entry (passes) but
    // the shim parser would split it into 65 names at runtime, then
    // silently truncate the 65th.  The strict gate rejects this at
    // configuration time.
    const smuggled = Array.from(
      { length: MAX_PROTECTED_ENV_NAMES + 1 },
      (_, i) => `N${i}`,
    ).join(',');
    expect(() => buildChildEnv({}, makeConfig([smuggled]), '/tmp/events.jsonl')).toThrow(
      /must not contain a comma/,
    );
  });

  it('rejects an entry with leading whitespace', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    expect(() => buildChildEnv({}, makeConfig([' FOO']), '/tmp/events.jsonl')).toThrow(
      /must match \^\[A-Za-z_\]\[A-Za-z0-9_\]\*\$/,
    );
  });

  it('rejects an entry starting with #', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    // The shim parser skips '#'-prefixed entries entirely — accepting
    // them in YAML would silently drop the secret the operator meant
    // to protect.
    expect(() => buildChildEnv({}, makeConfig(['#FOO']), '/tmp/events.jsonl')).toThrow(
      /must match \^\[A-Za-z_\]\[A-Za-z0-9_\]\*\$/,
    );
  });

  it('rejects an empty string entry', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    expect(() => buildChildEnv({}, makeConfig(['']), '/tmp/events.jsonl')).toThrow(
      /is empty or not a string/,
    );
  });

  it('rejects an entry starting with a digit (POSIX env-var name grammar)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    expect(() => buildChildEnv({}, makeConfig(['1FOO']), '/tmp/events.jsonl')).toThrow(
      /must match \^\[A-Za-z_\]\[A-Za-z0-9_\]\*\$/,
    );
  });

  it('accepts plain ASCII env-var names', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    // Sanity check: the strict gate must not break legitimate configs.
    const env = buildChildEnv(
      {},
      makeConfig(['NPM_TOKEN', 'GITHUB_TOKEN', '_PRIVATE']),
      '/tmp/events.jsonl',
    );
    expect(env['SCRIPT_JAIL_PROTECTED_ENV_NAMES']).toBe('NPM_TOKEN,GITHUB_TOKEN,_PRIVATE');
  });
});

describe('buildChildEnv lifecycle env sanitization', () => {
  function makeConfig(protectedEnv: string[]): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: protectedEnv },
      spoof: { platform: 'linux', arch: 'x64' },
      node_version: '20.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: '/work',
      log_fd: 3,
      pkg_dirs: {},
    };
  }

  it('drops agent-control and host-noise env before lifecycle scripts inherit it', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');

    const env = buildChildEnv(
      {
        PATH: '/usr/bin',
        NODE_OPTIONS: '--max-old-space-size=64',
        HOSTNAME: 'docker-container',
        TERM: 'linux',
        COLS: '80',
        LINES: '24',
        POSIXLY_CORRECT: '1',
        SCRIPT_JAIL_CONNECTION: 'stdio',
        SCRIPT_JAIL_CONFIG_PATH: '/etc/script-jail/config.yml',
        SCRIPT_JAIL_NATIVE_PRELOAD_PATH: '/tmp/native.so',
        SCRIPT_JAIL_PLATFORM_PRELOAD_PATH: '/tmp/platform.cjs',
        SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH: '/tmp/env-spy.cjs',
        SCRIPT_JAIL_PHASE_B_UNSHARE_NET: '1',
        SCRIPT_JAIL_E2E_SELF_TEST: '1',
        SCRIPT_JAIL_REPO_DIR: '/work',
        SCRIPT_JAIL_LOG_FILE: '/stale/events.jsonl',
      },
      makeConfig(['NPM_TOKEN']),
      '/tmp/events.jsonl',
    );

    expect(env['PATH']).toBe('/usr/bin');
    expect(env['NODE_OPTIONS']).toContain('--max-old-space-size=64');
    expect(env['SCRIPT_JAIL_LOG_FILE']).toBe('/tmp/events.jsonl');
    expect(env['SCRIPT_JAIL_LOG_FD']).toBe('3');
    expect(env['SCRIPT_JAIL_PROTECTED_ENV_NAMES']).toBe('NPM_TOKEN');

    for (const name of [
      'HOSTNAME',
      'TERM',
      'COLS',
      'LINES',
      'POSIXLY_CORRECT',
      'SCRIPT_JAIL_CONNECTION',
      'SCRIPT_JAIL_CONFIG_PATH',
      'SCRIPT_JAIL_NATIVE_PRELOAD_PATH',
      'SCRIPT_JAIL_PLATFORM_PRELOAD_PATH',
      'SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH',
      'SCRIPT_JAIL_PHASE_B_UNSHARE_NET',
      'SCRIPT_JAIL_E2E_SELF_TEST',
      'SCRIPT_JAIL_REPO_DIR',
    ]) {
      expect(env).not.toHaveProperty(name);
    }
  });
});

describe('redactSensitive (Phase A failure dump)', () => {
  it('masks protected env values read from the agent env', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const env = { NPM_TOKEN: 'super-secret-token-value', GITHUB_TOKEN: 'ghp_abcd1234efgh' };
    const out = redactSensitive(
      'login failed for super-secret-token-value using ghp_abcd1234efgh',
      ['NPM_TOKEN', 'GITHUB_TOKEN'],
      env,
    );
    expect(out).toBe('login failed for <REDACTED:NPM_TOKEN> using <REDACTED:GITHUB_TOKEN>');
    expect(out).not.toContain('super-secret-token-value');
  });

  it('skips short/empty protected values so it cannot blank out an ENOSPC trace', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const out = redactSensitive('ENOSPC: no space left on device', ['CI'], { CI: '1' });
    expect(out).toBe('ENOSPC: no space left on device');
  });

  it('redacts credential SHAPES not in the protected list', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const out = redactSensitive(
      [
        'fetch https://alice:hunter2@npm.example.com/foo',
        '//registry.npmjs.org/:_authToken=npmtok123abc',
        'Authorization: Bearer eyJhbGciOi.payload.sig',
        'token npm_0123456789012345678901234567890123456789',
      ].join('\n'),
      [],
      {},
    );
    expect(out).not.toContain('hunter2');
    expect(out).toContain('https://<REDACTED:URL-CREDENTIALS>@npm.example.com/foo');
    expect(out).toContain('_authToken=<REDACTED>');
    expect(out).toContain('Bearer <REDACTED>');
    expect(out).toContain('<REDACTED:NPM-TOKEN>');
    expect(out).not.toContain('npm_0123456789012345678901234567890123456789');
  });

  it('leaves benign output untouched', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const msg = '➤ YN0001: │ Error: ENOSPC: no space left on device, write';
    expect(redactSensitive(msg, ['NPM_TOKEN'], { NPM_TOKEN: 'x'.repeat(20) })).toBe(msg);
  });

  it('redacts GitHub + AWS key shapes (defense-in-depth, not in protected list)', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const out = redactSensitive(
      'ghp_0123456789abcdefghijklmnopqrstuvwxyzAB and AKIAIOSFODNN7EXAMPLE',
      [],
      {},
    );
    expect(out).toContain('<REDACTED:GH-TOKEN>');
    expect(out).toContain('<REDACTED:AWS-KEY>');
    expect(out).not.toContain('ghp_0123456789');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  // Codex round-2 [high]: a secret must be masked when redaction runs on the
  // FULL output, so a later tail-cap that starts inside the (now-masked) region
  // cannot leak a suffix.  The agent slices stdoutRedacted (post-redact), never
  // the raw stdout — this asserts the value is gone from the full redaction.
  it('masks a secret surrounded by padding longer than the tail cap', async () => {
    const { redactSensitive } = await import('../../src/guest/agent.js');
    const secret = 'tok_' + 'Z'.repeat(40);
    const padded = 'A'.repeat(5000) + secret + 'B'.repeat(50);
    const out = redactSensitive(padded, ['NPM_TOKEN'], { NPM_TOKEN: secret });
    expect(out).not.toContain(secret);
    expect(out.slice(-4000)).not.toContain('ZZZZ');
  });
});

describe('buildChildEnv package-manager cache/store redirects', () => {
  // ENOSPC on large repos (found auditing a ~1000-package yarn-4 monorepo):
  // yarn berry's global folder defaults under $HOME (/root, a 16 MB tmpfs in
  // the microVM) and npm's cache lands at ~/.npm on the same tmpfs.  All
  // package-manager bulk caches must be pinned onto the repo disk
  // (config.work_dir, ~4 GB) the same way the pnpm store already is.
  function makeConfig(
    workDir: string,
    manager?: 'npm' | 'pnpm' | 'yarn',
  ): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: [] },
      spoof: { platform: 'linux', arch: 'x64' },
      node_version: '20.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: workDir,
      log_fd: 3,
      pkg_dirs: {},
      ...(manager !== undefined ? { manager } : {}),
    };
  }

  // The bulk cache/store redirect is INJECTED ONLY for the detected manager:
  // setting a foreign manager's knob is a no-op for the install but env-spy
  // records any enumerated key, so an unconditional YARN_* would pollute a
  // pnpm/npm lockfile and break cross-backend parity for a fixture of another
  // manager.  Each manager therefore carries EXACTLY its own redirect.
  it('pnpm: pins only npm_config_store_dir under work_dir; no yarn/npm knobs', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const env = buildChildEnv({}, makeConfig('/work', 'pnpm'), '/tmp/events.jsonl');

    expect(env['npm_config_store_dir']).toBe('/work/.pnpm-store');
    expect(env['YARN_GLOBAL_FOLDER']).toBeUndefined();
    expect(env['YARN_CACHE_FOLDER']).toBeUndefined();
    expect(env['npm_config_cache']).toBeUndefined();
  });

  it('yarn: pins only YARN_GLOBAL_FOLDER + YARN_CACHE_FOLDER; no pnpm/npm knobs', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const env = buildChildEnv({}, makeConfig('/work', 'yarn'), '/tmp/events.jsonl');

    // berry: enableGlobalCache=true → ${globalFolder}/cache regardless of
    // cacheFolder; YARN_CACHE_FOLDER also covers classic 1.x / enableGlobalCache=false.
    expect(env['YARN_GLOBAL_FOLDER']).toBe('/work/.yarn-global');
    expect(env['YARN_CACHE_FOLDER']).toBe('/work/.yarn-cache');
    expect(env['npm_config_store_dir']).toBeUndefined();
    expect(env['npm_config_cache']).toBeUndefined();
  });

  it('npm: pins only npm_config_cache; no pnpm/yarn knobs', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const env = buildChildEnv({}, makeConfig('/work', 'npm'), '/tmp/events.jsonl');

    expect(env['npm_config_cache']).toBe('/work/.npm-cache');
    expect(env['npm_config_store_dir']).toBeUndefined();
    expect(env['YARN_GLOBAL_FOLDER']).toBeUndefined();
    expect(env['YARN_CACHE_FOLDER']).toBeUndefined();
  });

  it('keeps the redirect relative to a non-default work_dir (yarn)', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    const env = buildChildEnv({}, makeConfig('/staged/repo', 'yarn'), '/tmp/events.jsonl');

    expect(env['YARN_GLOBAL_FOLDER']).toBe('/staged/repo/.yarn-global');
    expect(env['YARN_CACHE_FOLDER']).toBe('/staged/repo/.yarn-cache');
  });

  it('falls back to npm_config_cache when no manager is set and no lockfile is present', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    // makeConfig omits `manager`; /work has no lockfile, so detectManager → 'npm'.
    const env = buildChildEnv({}, makeConfig('/work'), '/tmp/events.jsonl');

    expect(env['npm_config_cache']).toBe('/work/.npm-cache');
    expect(env['npm_config_store_dir']).toBeUndefined();
    expect(env['YARN_GLOBAL_FOLDER']).toBeUndefined();
  });

  it('macOS child env carries the same manager-conditional redirect (parity: $REPO/... tokens)', async () => {
    const { buildChildEnvMacos } = await import('../../src/guest/agent.js');
    const env = buildChildEnvMacos({}, makeConfig('/work', 'yarn'), '/tmp/events.jsonl');

    expect(env['YARN_GLOBAL_FOLDER']).toBe('/work/.yarn-global');
    expect(env['YARN_CACHE_FOLDER']).toBe('/work/.yarn-cache');
    expect(env['npm_config_store_dir']).toBeUndefined();
    expect(env['npm_config_cache']).toBeUndefined();
  });

  it('strips an ambient SCRIPT_JAIL_SCRATCH_DIR from the lifecycle child env', async () => {
    const { buildChildEnv } = await import('../../src/guest/agent.js');
    // init.sh exports SCRIPT_JAIL_SCRATCH_DIR for the AGENT only — it is an
    // internal artifact-placement knob, deliberately not allow-listed in
    // LIFECYCLE_ALLOWED_SCRIPT_JAIL_ENV_NAMES, so backends with and without
    // the scratch disk present byte-identical child environments.
    const env = buildChildEnv(
      { SCRIPT_JAIL_SCRATCH_DIR: '/scratch', PATH: '/usr/bin' },
      makeConfig('/work'),
      '/tmp/events.jsonl',
    );
    expect(env).not.toHaveProperty('SCRIPT_JAIL_SCRATCH_DIR');
  });
});

describe('scratchBaseDir + scratch-disk artifact placement', () => {
  // The VM backends attach a `scratch`-labelled 4 GiB disk that init.sh
  // mounts at /scratch (exporting SCRIPT_JAIL_SCRATCH_DIR) so the per-pid
  // strace logs and the events JSONL stop overflowing the 64 MB /tmp tmpfs.
  // Docker/bare/macOS never set the var → everything stays under /tmp.

  const ENV_NAME = 'SCRIPT_JAIL_SCRATCH_DIR';
  let savedEnv: string | undefined;

  beforeEach(() => {
    savedEnv = process.env[ENV_NAME];
    delete process.env[ENV_NAME];
  });

  afterEach(() => {
    if (savedEnv === undefined) delete process.env[ENV_NAME];
    else process.env[ENV_NAME] = savedEnv;
  });

  it('scratchBaseDir falls back to /tmp when the env var is unset', async () => {
    const { scratchBaseDir } = await import('../../src/guest/agent.js');
    expect(scratchBaseDir({})).toBe('/tmp');
  });

  it('scratchBaseDir treats an empty value as unset (no relative artifact paths)', async () => {
    const { scratchBaseDir } = await import('../../src/guest/agent.js');
    expect(scratchBaseDir({ [ENV_NAME]: '' })).toBe('/tmp');
  });

  it('scratchBaseDir returns the env-provided directory when set', async () => {
    const { scratchBaseDir } = await import('../../src/guest/agent.js');
    expect(scratchBaseDir({ [ENV_NAME]: '/scratch' })).toBe('/scratch');
  });

  it('scratchBaseDir reads process.env by default, at call time', async () => {
    const { scratchBaseDir } = await import('../../src/guest/agent.js');
    expect(scratchBaseDir()).toBe('/tmp');
    process.env[ENV_NAME] = '/scratch';
    expect(scratchBaseDir()).toBe('/scratch');
  });

  it('createEventsFile creates the events dir under SCRIPT_JAIL_SCRATCH_DIR when set', async () => {
    const { createEventsFile } = await import('../../src/guest/agent.js');
    // testDir stands in for the mounted /scratch — created by the
    // file-level beforeEach, removed by its afterEach.
    process.env[ENV_NAME] = testDir;

    const eventsFile = createEventsFile();
    expect(eventsFile.dirPath.startsWith(join(testDir, 'script-jail-events-'))).toBe(true);
    expect(eventsFile.path.startsWith(eventsFile.dirPath)).toBe(true);
    // The handle contract is unchanged: fresh inode baseline captured.
    expect(eventsFile.baseline.ino).toBeGreaterThan(0n);
  });

  it('createEventsFile falls back to /tmp when the env var is unset', async () => {
    const { createEventsFile } = await import('../../src/guest/agent.js');

    const eventsFile = createEventsFile();
    try {
      expect(eventsFile.dirPath.startsWith('/tmp/script-jail-events-')).toBe(true);
    } finally {
      rmSync(eventsFile.dirPath, { recursive: true, force: true });
    }
  });

  it('an explicit parentDir argument still wins over the env var (test seam)', async () => {
    const { createEventsFile } = await import('../../src/guest/agent.js');
    process.env[ENV_NAME] = '/nonexistent-scratch-mount';

    const eventsFile = createEventsFile(testDir);
    expect(eventsFile.dirPath.startsWith(join(testDir, 'script-jail-events-'))).toBe(true);
  });

  it('main() points the strace runner basePath at the scratch dir when set, /tmp when not', async () => {
    // Capture opts.basePath from a contract-conforming fake runner — the
    // same seam trackingStrace uses, extended with the third run() arg.
    function basePathCapturingStrace(): { strace: StraceRunner; basePaths: string[] } {
      const basePaths: string[] = [];
      return {
        basePaths,
        strace: {
          async *run(_cmd, _args, opts) {
            basePaths.push(opts.basePath);
          },
          getExitCode() { return 0; },
          getTamperReason() { return null; },
          recordTamper(_reason: string) { /* no-op for test fakes */ },
          getRootPid() { return null; },
        },
      };
    }

    // Unset → the historical /tmp path (Docker/bare backends).
    {
      const { conn, hostSend } = makeConn();
      const configPath = writeConfig(testDir);
      const { strace, basePaths } = basePathCapturingStrace();
      setTimeout(() => hostSend('go\n'), 10);
      await main({ configPath, connection: conn, spawner: mockSpawner().spawner, strace, dnsLookup: offlineLookup });
      expect(basePaths).toEqual(['/tmp/script-jail-strace/strace.out']);
    }

    // Set → the scratch-disk path (Firecracker/VZ with the scratch drive).
    // testDir stands in for the mounted /scratch: main() also creates the
    // events file under the scratch base, so the dir must really exist or
    // createEventsFile fails closed before Phase B ever runs.
    {
      process.env[ENV_NAME] = testDir;
      const { conn, hostSend } = makeConn();
      const configPath = writeConfig(testDir);
      const { strace, basePaths } = basePathCapturingStrace();
      setTimeout(() => hostSend('go\n'), 10);
      await main({ configPath, connection: conn, spawner: mockSpawner().spawner, strace, dnsLookup: offlineLookup });
      expect(basePaths).toEqual([`${testDir}/script-jail-strace/strace.out`]);
    }
  });
});

describe('buildChildEnvMacos macOS sticky env contract', () => {
  function makeConfig(workDir: string): import('../../src/guest/agent.js').AgentConfig {
    return {
      protected: { files: [], env: [] },
      spoof: { platform: 'darwin', arch: 'arm64' },
      node_version: '24.0.0',
      manager_lockfile_sha256: '',
      lockfile_path: '',
      work_dir: workDir,
      log_fd: 3,
      pkg_dirs: {},
    };
  }

  it('sets SCRIPT_JAIL_WORK_DIR to config.work_dir so the shim keeps node_modules/.bin audited', async () => {
    const { buildChildEnvMacos } = await import('../../src/guest/agent.js');

    const env = buildChildEnvMacos(
      { PATH: '/usr/bin:/bin', SCRIPT_JAIL_SHELL_SHIM_DIR: '/fake/shims' },
      makeConfig('/staged/repo/work'),
      '/tmp/events.jsonl',
    );

    // Mirrors the SCRIPT_JAIL_SHELL_SHIM_DIR contract: the shim captures this at
    // ctor into CANON_WORK_DIR (keep-root #6) so a top-level node_modules/.bin
    // helper stays audited after a lifecycle chdir (the false-strip class).
    expect(env['SCRIPT_JAIL_WORK_DIR']).toBe('/staged/repo/work');
    expect(env['SCRIPT_JAIL_SHELL_SHIM_DIR']).toBe('/fake/shims');
  });

  it('keeps SCRIPT_JAIL_WORK_DIR on a lifecycle child (allow-listed, not sanitized away)', async () => {
    const { buildChildEnvMacos } = await import('../../src/guest/agent.js');

    // baseEnv carries an AMBIENT SCRIPT_JAIL_WORK_DIR; it must survive
    // sanitizeLifecycleBaseEnv (allow-listed) and be re-asserted to config.work_dir.
    const env = buildChildEnvMacos(
      {
        PATH: '/usr/bin:/bin',
        SCRIPT_JAIL_WORK_DIR: '/ambient/work',
        SCRIPT_JAIL_UNKNOWN_VAR: 'stripped',
      },
      makeConfig('/staged/repo/work'),
      '/tmp/events.jsonl',
    );

    expect(env['SCRIPT_JAIL_WORK_DIR']).toBe('/staged/repo/work');
    // Unknown SCRIPT_JAIL_* vars are still stripped (allow-list invariant intact).
    expect(env).not.toHaveProperty('SCRIPT_JAIL_UNKNOWN_VAR');
  });
});

describe('MemoryConnection', () => {
  it('readable and writable are the passed streams', () => {
    const r = new PassThrough();
    const w = new PassThrough();
    const conn = new MemoryConnection(r, w);
    expect(conn.readable).toBe(r);
    expect(conn.writable).toBe(w);
  });

  it('close() does not throw', () => {
    const r = new PassThrough();
    const w = new PassThrough();
    const conn = new MemoryConnection(r, w);
    expect(() => conn.close()).not.toThrow();
  });
});

describe('LinuxVsockConnection', () => {
  // Use a fixed high port that's very unlikely to clash with anything else on
  // the dev machine.  vitest gives each describe-block its own process, but
  // tests within the block run sequentially anyway because each one binds
  // and tears down the same listener.
  const TEST_PORT = 24317;

  it('listen() resolves when a client connects', async () => {
    const connPromise = LinuxVsockConnection.listen(TEST_PORT);

    // Connect from a "client" (simulating the in-VM socat bridge).
    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
    await new Promise<void>((resolve, reject) => {
      client.once('connect', () => { resolve(); });
      client.once('error', reject);
    });

    const conn = await connPromise;
    expect(conn).toBeDefined();
    expect(conn.readable).toBeDefined();
    expect(conn.writable).toBeDefined();

    conn.close();
    client.destroy();
  });

  it('forwards bytes through the accepted connection', async () => {
    const connPromise = LinuxVsockConnection.listen(TEST_PORT);

    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
    await new Promise<void>((resolve, reject) => {
      client.once('connect', () => { resolve(); });
      client.once('error', reject);
    });

    const conn = await connPromise;

    // Client (host side) -> agent (readable).
    const received = new Promise<string>((resolve) => {
      conn.readable.once('data', (chunk: Buffer) => { resolve(chunk.toString()); });
    });
    client.write('hello\n');
    expect(await received).toBe('hello\n');

    // Agent (writable) -> client (host side).
    const echoed = new Promise<string>((resolve) => {
      client.once('data', (chunk: Buffer) => { resolve(chunk.toString()); });
    });
    conn.writable.write('world\n');
    expect(await echoed).toBe('world\n');

    conn.close();
    client.destroy();
  });

  it('close() destroys the accepted socket', async () => {
    const connPromise = LinuxVsockConnection.listen(TEST_PORT);

    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
    await new Promise<void>((resolve, reject) => {
      client.once('connect', () => { resolve(); });
      client.once('error', reject);
    });

    const conn = await connPromise;

    // Client should see the socket close after conn.close().
    const closed = new Promise<void>((resolve) => {
      client.once('close', () => { resolve(); });
    });
    conn.close();
    await closed;

    client.destroy();
  });

  it('after accepting, the listener is closed (port can be re-bound)', async () => {
    const connPromise = LinuxVsockConnection.listen(TEST_PORT);

    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
    await new Promise<void>((resolve, reject) => {
      client.once('connect', () => { resolve(); });
      client.once('error', reject);
    });

    const conn = await connPromise;

    // The listener has been closed inside listen() after accepting; rebinding
    // on the same port must succeed.  Use a fresh listen() call as the probe.
    const probePromise = LinuxVsockConnection.listen(TEST_PORT);
    const probeClient = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
    await new Promise<void>((resolve, reject) => {
      probeClient.once('connect', () => { resolve(); });
      probeClient.once('error', reject);
    });
    const probeConn = await probePromise;

    probeConn.close();
    probeClient.destroy();
    conn.close();
    client.destroy();
  });
});

// ---------------------------------------------------------------------------
// runStraceTailer unit tests
// ---------------------------------------------------------------------------

describe('runStraceTailer', () => {
  let tailerDir: string;

  beforeEach(() => {
    tailerDir = join(tmpdir(), `strace-tailer-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tailerDir, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(tailerDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /** Collect all items from an async iterable with a timeout guard. */
  async function collect(
    iter: AsyncIterable<{ pid: number; line: string; source: 'shim' | 'strace' }>,
    timeoutMs = 3000,
  ): Promise<Array<{ pid: number; line: string; source: 'shim' | 'strace' }>> {
    const results: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
    await Promise.race([
      (async () => {
        for await (const item of iter) {
          results.push(item);
        }
      })(),
      new Promise<void>((_, reject) =>
        setTimeout(() => reject(new Error('collect() timed out')), timeoutMs),
      ),
    ]);
    return results;
  }

  it('yields lines from a pre-written per-pid strace file', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // Write the per-pid file before the tailer starts.
    writeFileSync(`${basePath}.1234`, 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\nexecve("/bin/sh", ["sh"], ...) = 0\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Resolve exit immediately so the tailer drains and finishes.
    resolveExit();

    const items = await collect(tailer);
    expect(items.length).toBe(2);
    expect(items[0]).toEqual({ pid: 1234, line: 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3', source: 'strace' });
    expect(items[1]).toEqual({ pid: 1234, line: 'execve("/bin/sh", ["sh"], ...) = 0', source: 'strace' });
  });

  it('drains the shim events file before per-pid strace files (shim-first ordering)', async () => {
    // For any given exec the shim's `emit_exec` write lands in the events file
    // BEFORE strace logs the execve (the shim writes in-process, before
    // real_execve).  The tailer must therefore yield the shim `exec` record
    // ahead of the matching strace `spawn` for the same pid, so the dispatcher
    // has seeded that pid's attribution from the shim's in-process npm env
    // before it processes the spawn.  Both files are present before start, so
    // this asserts the invariant deterministically via the settle drain.
    const basePath = join(tailerDir, 'strace.out');
    const eventsFile = join(tailerDir, 'events.jsonl');
    const shimExec = JSON.stringify({
      kind: 'exec', prog: '/usr/bin/dirname', argv0: 'dirname', pid: 502,
      ts: 10, envp_alloc_failed: false, result: 'ok',
      npm_package_name: 'unrs-resolver', npm_package_version: '1.11.1',
      npm_lifecycle_event: 'postinstall',
    });
    writeFileSync(eventsFile, shimExec + '\n', 'utf8');
    writeFileSync(`${basePath}.502`, 'execve("/usr/bin/dirname", ["dirname", "/x"], ...) = 0\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsFile,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    const shimIdx = items.findIndex((i) => i.source === 'shim' && i.line.includes('"kind":"exec"'));
    const straceIdx = items.findIndex((i) => i.source === 'strace' && i.pid === 502);
    expect(shimIdx).toBeGreaterThanOrEqual(0);
    expect(straceIdx).toBeGreaterThanOrEqual(0);
    expect(shimIdx).toBeLessThan(straceIdx);
  });

  it('the watchDir callback drains the events file before the strace spawn it fires on', async () => {
    // Regression guard for the per-pid directory watcher's shim-first ordering
    // (2026-06-03).  The directory watcher is a SEPARATE fs.watch from the
    // events-file watcher and can fire first.  If its callback enqueued the
    // strace spawn before the shim `exec` record (which seeds attribution) was
    // drained, the dispatcher would process the spawn with no seed and drop a
    // reaped-helper spawn.
    //
    // The test must isolate the WATCHER callback as the first drain — not the
    // exit settle loop (which also drains shim-first and would mask a
    // regression) nor the periodic poll.  So: the shim line is already in the
    // events file (a pre-existing file does NOT trigger the events-file inotify
    // watch); the poll interval is far longer than the assertion window (the
    // poll never fires here); and `exitPromise` is left UNRESOLVED while we
    // assert, so the settle loop cannot run.  The strace file is written after
    // iteration begins, so the directory watcher fires on it and is the ONLY
    // possible first drain.  We assert the FIRST yielded item is the shim line:
    // with the pollDir-only bug the watcher enqueues the strace spawn first, so
    // the first item would be the strace line.  Teardown resolves exit and
    // drains to completion (guarded) so the generator clears its own timers.
    const basePath = join(tailerDir, 'strace.out');
    const eventsFile = join(tailerDir, 'events.jsonl');
    const shimExec = JSON.stringify({
      kind: 'exec', prog: '/usr/bin/dirname', argv0: 'dirname', pid: 777,
      ts: 5, envp_alloc_failed: false, result: 'ok',
      npm_package_name: 'pkg', npm_package_version: '2.0.0',
      npm_lifecycle_event: 'install',
    });
    writeFileSync(eventsFile, shimExec + '\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsFile,
      exitPromise,
      // The watcher callback fires within ~ms of the strace write; the first
      // poll tick is 1000ms out, so the periodic poll cannot be the first drain
      // (it only serves to wake the generator for teardown in the failure path
      // where the watcher never fires).
      pollIntervalMs: 1000,
      drainMs: 20,
    });
    const iterator = tailer[Symbol.asyncIterator]();
    // CRITICAL: `runStraceTailer` is an async generator — its body (which
    // installs the fs.watch handlers) does NOT run until the first next().  Pull
    // the first item BEFORE creating the strace file so the watchers are
    // installed first and the directory watcher genuinely fires on the new file.
    // A file created before next() would be seen only by a poll/settle drain.
    const nextPromise = iterator.next();
    // exitPromise is intentionally never resolved: the settle loop must not run
    // (it would drain shim-first and mask a watcher regression).  Teardown is
    // via iterator.return(), which runs the generator's finally and clears its
    // own poll timer + watchers.
    void resolveExit;

    try {
      // Give the generator body a tick to run to its wake await and install the
      // watchers, THEN create the strace file so the directory watcher fires on
      // it.  With the pollDir-only bug the watcher enqueues the strace line
      // first, so the first yielded item is the strace spawn (fast assertion
      // failure); with the shim-first fix it is the shim `exec` record.
      await new Promise<void>((r) => setTimeout(r, 40));
      writeFileSync(`${basePath}.777`, 'execve("/usr/bin/dirname", ["dirname"], ...) = 0\n', 'utf8');

      const first = await Promise.race([
        nextPromise,
        new Promise<IteratorResult<{ pid: number; line: string; source: 'shim' | 'strace' }>>(
          (_, reject) => setTimeout(() => reject(new Error('next() timed out — watcher did not drain')), 4000),
        ),
      ]);
      expect(first.done).toBe(false);
      expect(first.value.source).toBe('shim');
      expect(first.value.line).toContain('"pid":777');
    } finally {
      // After a single yielded item the generator is parked at its `yield`, so
      // return() resumes it there and runs the finally promptly (no settle loop,
      // no leaked timer).  Guarded for the failure path where the generator is
      // parked on its wake await — the 1000ms poll tick wakes it and lets the
      // pending return complete.
      await Promise.race([
        Promise.resolve(iterator.return?.(undefined)),
        new Promise<void>((r) => setTimeout(r, 4000)),
      ]);
    }
  });

  it('yields lines from multiple per-pid files with correct pids', async () => {
    const basePath = join(tailerDir, 'strace.out');
    writeFileSync(`${basePath}.100`, 'openat(AT_FDCWD, "/a", O_RDONLY) = 3\n', 'utf8');
    writeFileSync(`${basePath}.200`, 'openat(AT_FDCWD, "/b", O_RDONLY) = 4\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    expect(items).toHaveLength(2);

    const pid100 = items.find((i) => i.pid === 100);
    const pid200 = items.find((i) => i.pid === 200);
    expect(pid100?.line).toContain('/a');
    expect(pid200?.line).toContain('/b');
  });

  it('picks up per-pid files written after the tailer starts', async () => {
    const basePath = join(tailerDir, 'strace.out');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Write the file after a short delay (simulates strace writing during run).
    setTimeout(() => {
      writeFileSync(`${basePath}.9999`, 'openat(AT_FDCWD, "/late", O_RDONLY) = 5\n', 'utf8');
      setTimeout(resolveExit, 30);
    }, 40);

    const items = await collect(tailer);
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual({ pid: 9999, line: 'openat(AT_FDCWD, "/late", O_RDONLY) = 5', source: 'strace' });
  });

  it('yields JSONL lines from fd3Stream with pid=0', async () => {
    const fd3 = new PassThrough();

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: fd3,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    const shimLine = JSON.stringify({ kind: 'env_read', name: 'HOME', pid: 42, ts: 1000, hidden: false });
    fd3.push(shimLine + '\n');
    fd3.push(null); // EOF

    resolveExit();

    const items = await collect(tailer);
    const fd3Items = items.filter((i) => i.pid === 0);
    expect(fd3Items).toHaveLength(1);
    expect(fd3Items[0]!.line).toBe(shimLine);
  });

  it('yields both per-pid strace lines and fd3 JSONL in a single run', async () => {
    const basePath = join(tailerDir, 'strace.out');
    writeFileSync(`${basePath}.555`, 'openat(AT_FDCWD, "/x", O_RDONLY) = 3\n', 'utf8');

    const fd3 = new PassThrough();
    const shimLine = JSON.stringify({ kind: 'dlopen', filename: '/tmp/foo.node', result: 'blocked', pid: 555, ts: 2000 });
    fd3.push(shimLine + '\n');
    fd3.push(null);

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: fd3,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    expect(items.length).toBe(2);
    expect(items.some((i) => i.pid === 555 && i.line.includes('openat'))).toBe(true);
    expect(items.some((i) => i.pid === 0 && i.line.includes('dlopen'))).toBe(true);
  });

  it('completes cleanly when there are no strace files and fd3 is null', async () => {
    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    expect(items).toHaveLength(0);
  });

  it('does not yield lines from files that do not match the base prefix', async () => {
    // Write a file with a wrong prefix — should be ignored.
    writeFileSync(join(tailerDir, 'other.out.1111'), 'should-not-appear\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    expect(items).toHaveLength(0);
  });

  it('handles incremental file growth: yields new lines appended after initial read', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // Write first line before tailer starts.
    writeFileSync(`${basePath}.777`, 'openat(AT_FDCWD, "/first", O_RDONLY) = 3\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 80,
    });

    // Append second line after a short delay.
    setTimeout(() => {
      appendFileSync(`${basePath}.777`, 'openat(AT_FDCWD, "/second", O_RDONLY) = 4\n');
      setTimeout(resolveExit, 60);
    }, 40);

    const items = await collect(tailer, 4000);
    const lines = items.map((i) => i.line);
    expect(lines).toContain('openat(AT_FDCWD, "/first", O_RDONLY) = 3');
    expect(lines).toContain('openat(AT_FDCWD, "/second", O_RDONLY) = 4');
    // Order within one file must be preserved.
    const firstIdx = lines.indexOf('openat(AT_FDCWD, "/first", O_RDONLY) = 3');
    const secondIdx = lines.indexOf('openat(AT_FDCWD, "/second", O_RDONLY) = 4');
    expect(firstIdx).toBeLessThan(secondIdx);
  });

  // -------------------------------------------------------------------------
  // Post-exit settle-loop completeness (capture-race regression, parity fix)
  //
  // strace `-ff` writes one file per traced pid; sub-millisecond cmd-shim
  // helpers (dirname/sed/uname) each leave a tiny per-pid file that a single
  // terminal `readdirSync` can miss or read short. The old tailer did ONE
  // final poll after a blind drainMs and dropped anything not listed then,
  // producing a capture that diverged from the macOS backend. The fix gates
  // on strace's own exit (all per-pid files already flushed) and re-scans in
  // a bounded settle loop until two passes see no new file and no new bytes.
  // -------------------------------------------------------------------------

  it('captures short-lived per-pid files that appear after the initial drain (re-enumerates until quiescent)', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // The install-root pid file exists throughout, as in a real run.
    writeFileSync(`${basePath}.1000`, 'execve("/usr/bin/node", ["node"], ...) = 0\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 10,
      settleQuietPasses: 2,
      settleHardCapMs: 4000,
    });

    resolveExit();

    // Keep the root file growing so the settle loop stays non-quiescent, and
    // partway through materialize three sub-millisecond cmd-shim helper files
    // (dirname/sed/uname analogues). They appear well AFTER the old single
    // drainMs sweep, so the old single-shot terminal poll dropped them; the
    // settle loop must re-enumerate and pick all three up. Then stop the
    // keep-alive so the loop quiesces. The keep-alive window (~100ms) is wide
    // relative to scheduling jitter, so the helper writes land deterministically
    // before quiescence without a tight timing assumption.
    let ticks = 0;
    const keepalive = setInterval(() => {
      ticks += 1;
      try {
        appendFileSync(`${basePath}.1000`, `read(${ticks}) = 0\n`);
        if (ticks === 3) {
          writeFileSync(`${basePath}.1001`, 'execve("/usr/bin/dirname", ["dirname"], ...) = 0\n', 'utf8');
          writeFileSync(`${basePath}.1002`, 'execve("/usr/bin/sed", ["sed"], ...) = 0\n', 'utf8');
          writeFileSync(`${basePath}.1003`, 'execve("/usr/bin/uname", ["uname"], ...) = 0\n', 'utf8');
        }
      } catch { /* dir may be torn down once the tailer finishes */ }
      if (ticks >= 5) { clearInterval(keepalive); }
    }, 20);

    const items = await collect(tailer, 4000);
    clearInterval(keepalive);

    const helperPids = items
      .map((i) => i.pid)
      .filter((p) => p >= 1001 && p <= 1003)
      .sort((a, b) => a - b);
    expect(helperPids).toEqual([1001, 1002, 1003]);
    // The root file's execve is captured too.
    expect(items.some((i) => i.pid === 1000 && i.line.includes('node'))).toBe(true);
  });

  it('completes a per-pid line that was only partially written at exit time', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // A partial line (no trailing newline) is present when the child exits;
    // the remainder + newline arrives a few ms into the settle window. The
    // settle loop must read the file to EOF across passes and emit the full
    // line — not a torn fragment.
    writeFileSync(`${basePath}.2002`, 'execve("/usr/bin/uname", ["unam', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 10,
      settleQuietPasses: 2,
      settleHardCapMs: 4000,
    });

    resolveExit();
    setTimeout(() => {
      try { appendFileSync(`${basePath}.2002`, 'e"], ...) = 0\n'); } catch { /* ignore */ }
    }, 25);

    const items = await collect(tailer, 4000);
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual({
      pid: 2002,
      line: 'execve("/usr/bin/uname", ["uname"], ...) = 0',
      source: 'strace',
    });
  });

  it('terminates promptly once the capture is quiescent (does not run to the hard cap)', async () => {
    const basePath = join(tailerDir, 'strace.out');
    writeFileSync(`${basePath}.3003`, 'execve("/bin/true", ["true"], ...) = 0\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      pollIntervalMs: 10,
      drainMs: 10,
      settleQuietPasses: 2,
      settleHardCapMs: 5000, // generous; must finish far sooner via quiescence
    });

    resolveExit();
    const start = Date.now();
    const items = await collect(tailer, 4000);
    const elapsed = Date.now() - start;

    expect(items).toHaveLength(1);
    // drainMs(10) + ~2 quiet passes * pollInterval(10) ≈ 30ms; assert it is
    // nowhere near the 5000ms hard cap (generous slack for CI scheduling).
    expect(elapsed).toBeLessThan(1000);
  });

  it('fails closed (records tamper) and terminates when the capture never quiesces by the hard cap', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // Fail-closed contract: a capture the tailer could not confirm complete
    // must NOT pass as a clean lockfile. The cap-hit records tamper through
    // tamperRef, which runInstallPhase/main read via getTamperReason() to
    // refuse emitting a final lockfile.
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      exitPromise,
      tamperRef,
      pollIntervalMs: 20,
      drainMs: 10,
      settleQuietPasses: 2,
      settleHardCapMs: 150, // small cap so the no-hang guarantee is fast to test
    });

    resolveExit();
    // Create a new per-pid file faster than the poll interval so every settle
    // pass sees fresh progress and the quiet target can never be met — only
    // the hard cap can stop the loop. The cap must NOT kill strace (there is
    // none here); it only stops tailing.
    let n = 0;
    const spawner = setInterval(() => {
      n += 1;
      try {
        writeFileSync(`${basePath}.${5000 + n}`, `execve("/bin/x${n}", ["x"], ...) = 0\n`, 'utf8');
      } catch { /* ignore */ }
    }, 5);

    const start = Date.now();
    const items = await collect(tailer, 4000);
    const elapsed = Date.now() - start;
    clearInterval(spawner);

    // It terminated (no hang) — bounded by the 150ms cap plus a final flush +
    // scheduling slack, far below collect()'s 4000ms timeout — and yielded
    // what it had seen.
    expect(elapsed).toBeLessThan(2000);
    expect(items.length).toBeGreaterThan(0);
    // …and it fails closed: the incomplete capture is recorded as tamper so it
    // can never be emitted as a clean lockfile.
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/did not quiesce|capture may be incomplete/);
  });

  // -------------------------------------------------------------------------
  // Events-file tail tests (the production channel for shim + JS preloads)
  // -------------------------------------------------------------------------

  it('yields JSONL lines from a pre-written events file as pid=0', async () => {
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    writeFileSync(
      eventsPath,
      '{"kind":"env_read","name":"NPM_TOKEN","pid":1001,"ts":0,"hidden":true}\n' +
      '{"kind":"dlopen","filename":"/work/node_modules/x/evil.node","pid":1002,"ts":1,"result":"blocked"}\n',
      'utf8',
    );

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out', // no per-pid files exist; only the events file
      fd3Stream: null,
      eventsFilePath: eventsPath,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    resolveExit();

    const items = await collect(tailer);
    expect(items).toHaveLength(2);
    // Both lines carry the same synthetic pid=0 the fd3Stream uses; the
    // real per-event pid is inside the JSON payload.
    expect(items[0]).toEqual({
      pid: 0,
      line: '{"kind":"env_read","name":"NPM_TOKEN","pid":1001,"ts":0,"hidden":true}',
      source: 'shim',
    });
    expect(items[1]).toEqual({
      pid: 0,
      line: '{"kind":"dlopen","filename":"/work/node_modules/x/evil.node","pid":1002,"ts":1,"result":"blocked"}',
      source: 'shim',
    });
  });

  it('picks up events-file lines appended after the tailer starts', async () => {
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    writeFileSync(eventsPath, '', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Append after a brief delay (after the tailer has started polling).
    setTimeout(() => {
      writeFileSync(
        eventsPath,
        '{"kind":"env_read","name":"GITHUB_TOKEN","pid":2001,"ts":5,"hidden":true}\n',
        { encoding: 'utf8', flag: 'a' },
      );
      setTimeout(resolveExit, 80);
    }, 40);

    const items = await collect(tailer, 4000);
    expect(items.length).toBe(1);
    expect(items[0]?.line).toContain('GITHUB_TOKEN');
    expect(items[0]?.pid).toBe(0);
  });

  it('reads the events file incrementally without re-reading prior content', async () => {
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    writeFileSync(eventsPath, '{"kind":"env_read","name":"A","pid":1,"ts":0,"hidden":false}\n', 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Append a second line after the initial drain.
    setTimeout(() => {
      writeFileSync(
        eventsPath,
        '{"kind":"env_read","name":"B","pid":2,"ts":1,"hidden":false}\n',
        { encoding: 'utf8', flag: 'a' },
      );
      setTimeout(resolveExit, 80);
    }, 40);

    const items = await collect(tailer, 4000);
    const names = items.map((i) => {
      try { return (JSON.parse(i.line) as { name?: string }).name; } catch { return undefined; }
    });
    // Each name should appear exactly once — no duplicate reads from
    // re-scanning the file.
    expect(names.filter((n) => n === 'A')).toHaveLength(1);
    expect(names.filter((n) => n === 'B')).toHaveLength(1);
  });

  // ── Finding A: events-file tamper detection ─────────────────────────────
  //
  // The tailer baseline-stats SCRIPT_JAIL_LOG_FILE at startup (passed in via
  // eventsBaseline) and re-checks {dev, ino} on every drain cycle.  Any
  // mismatch — unlink, replace, truncate, EACCES — must record a tamper
  // reason into tamperRef so the agent fails closed at install-end.

  it('records a tamper reason when the events file is unlinked mid-run', async () => {
    const { statSync, openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, unlinkSync, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    // Create file with O_EXCL like the production agent does.
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Unlink the events file mid-run.  The polling loop must observe this
    // and record a tamper reason.
    setTimeout(() => {
      unlinkSync(eventsPath);
      setTimeout(resolveExit, 100);
    }, 40);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/events file (disappeared|became unreadable|inode mismatch)/);
    // Defensive: also reference statSync to keep the (linter-suppressed) import warm.
    expect(typeof statSync).toBe('function');
  });

  it('records a tamper reason when the events file is replaced with a different inode', async () => {
    const { openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, writeFileSync: writeSyncFn, renameSync, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Replace the file with a fresh one at the same path — new inode.
    // On Linux, `unlink` immediately followed by `writeFile` of the same
    // path can reuse the just-freed inode number (the kernel's inode
    // allocator picks the lowest free slot), which leaves the baseline
    // {ino,dev} check passing.  Force a guaranteed-different inode by
    // writing the replacement at a sibling path first, then atomically
    // renaming over the target: the renamed file's inode was allocated
    // BEFORE the unlink and so cannot collide.
    // Then deterministically wait for the tailer to observe the tamper
    // (rather than racing a fixed 100ms timer that's flaky on slow CI
    // runners where the polling loop hasn't drained between the
    // unlink+rewrite and the resolveExit).
    setTimeout(() => {
      const tmpPath = `${eventsPath}.replacement`;
      writeSyncFn(tmpPath, '{"kind":"env_read","name":"INJECTED","pid":1,"ts":0,"hidden":false}\n', 'utf8');
      renameSync(tmpPath, eventsPath);
      // Poll tamperRef.reason every 10ms (≤ pollIntervalMs of 20ms) up to
      // a generous 2s cap, then resolveExit.  The cap is large enough
      // that even a heavily-contended CI runner has many poll cycles to
      // notice the inode swap; the fall-through still triggers
      // resolveExit so the test can fail fast if tamper genuinely never
      // fires (rather than hanging until the 4s collect timeout).
      const start = Date.now();
      const waitForTamper = (): void => {
        if (tamperRef.reason !== null || Date.now() - start > 2000) {
          resolveExit();
          return;
        }
        setTimeout(waitForTamper, 10);
      };
      waitForTamper();
    }, 40);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/inode mismatch|disappeared/);
  });

  it('does NOT record tamper when the events file is untouched (happy path)', async () => {
    const { openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, appendFileSync: appendSyncFn, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    setTimeout(() => {
      // Legitimate append — same inode, growing size.
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"OK","pid":1,"ts":0,"hidden":false}\n', 'utf8');
      setTimeout(resolveExit, 100);
    }, 40);

    const items = await collect(tailer, 4000);
    expect(tamperRef.reason).toBeNull();
    // The legitimate appended line must still be yielded.
    expect(items.some((i) => i.line.includes('"name":"OK"'))).toBe(true);
  });

  // 2026-06-11 regression: end-of-audit lazy ctime-finalize must NOT trip.
  //
  // Reproduces the CI parity-test false positive.  After the last legitimate
  // append is consumed (eventsPos === size), the Ubuntu-22.04 microVM kernel
  // finalizes the file's ctime a few hundred microseconds later with mtime and
  // size UNCHANGED.  Once writes stop, that state (`ctime > lastConsumed &&
  // size === eventsPos`) is PERMANENT and accumulates the 3-poll gate into a
  // false "ctime advanced without new bytes" tamper.  A `chmod` bumps ctime only
  // (mtime + size unchanged), faithfully simulating the finalize.
  //
  // The fix freezes the meta-advance gates once the traced tree has exited
  // (childExited), so a finalize observed POST-exit is ignored.  Here the bump
  // lands AFTER resolveExit and is then seen by several post-exit polls: the
  // pre-fix code trips the ctime gate on them (red), the freeze ignores them
  // (green).  The gate stays STRICT during the active phase — the utimes-restore
  // and append-truncate tests below trip pre-exit — so in-model detection is
  // unchanged.
  it('does NOT record tamper on the end-of-audit lazy ctime-finalize (post-exit chmod, mtime+size flat)', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      // Clean strace exit (code 0, no signal): the runner publishes this and the
      // tailer engages the post-exit meta-gate freeze.  Without it the freeze
      // stays OFF (fail-closed default) and this benign finalize would trip.
      exitStatusRef: { code: 0, signal: null },
      pollIntervalMs: 20,
      drainMs: 30,
      // Keep the post-exit settle loop polling long enough that several polls
      // observe the permanent benign state (>> 3 × 20ms) before the tailer
      // stops — so the pre-fix code has a clear window to (wrongly) trip.
      settleQuietPasses: 8,
      settleHardCapMs: 600,
    });

    // t=40: last legitimate event — consumed by an active-phase drain.
    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    // t=120: traced tree exits (childExited).  t=140: bump ctime ONLY (mtime +
    // size flat) AFTER exit, so the permanent finalize state is observed only by
    // post-exit polls — which the freeze must ignore.
    setTimeout(() => { resolveExit(); }, 120);
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 140);

    const items = await collect(tailer, 4000);
    expect(tamperRef.reason).toBeNull();
    // The legitimate appended line must still be yielded.
    expect(items.some((i) => i.line.includes('"name":"LAST"'))).toBe(true);
  });

  // 2026-06-12: PRE-NOTIFICATION RACE — the docker parity job's deterministic
  // false positive.  `strace -ff` exits only after the WHOLE traced tree exits;
  // on a large repo many children finish WITHOUT writing events, so strace
  // lingers >> 3 × pollIntervalMs after the LAST events byte was consumed.  The
  // kernel finalizes that write's ctime immediately, so {ctime advanced, size
  // === eventsPos} is PERMANENT and the gate accumulates its full strike count
  // BEFORE exitPromise resolves and flips `childExited` — the freeze loses the
  // race.  A value window was tried and rejected as attacker-forgeable; the fix
  // records the suspicion PROVISIONALLY and lets the CLEAN exit disposition VOID
  // it.  Here the ctime-only bump (chmod; mtime + size flat) lands at t=120
  // while the tracer is still "running", strikes fire at t≈180, and the clean
  // exit arrives only at t=320 — so the strikes are accumulated, the
  // provisional verdict is set, and the clean disposition must retroactively
  // VOID it.  (Contrast the end-of-audit chmod test above, where the bump lands
  // AFTER the clean exit, so `childExited` is already set and the gate never
  // accumulates — a different path.)
  //
  // NOTE (2026-06-12): an inotify-fire-driven immediate-tamper path was tried
  // here to close the round-4 [high] (a clean exit voiding a real end-of-audit
  // tamper).  It FALSE-POSITIVED on the real CI kernels (docker 24.04 host AND
  // firecracker 22.04 microVM): the lazy ctime finalize is NOT inotify-silent
  // there — a benign write's watcher fire re-stats AFTER the finalize and sees
  // ctime > the pre-finalize lastConsumedCtime with size === eventsPos, which is
  // indistinguishable from a truncate/utimes tamper.  Reverted.  The clean-exit
  // void residual (end-of-audit in-place substitution on a clean exit, winning
  // the sub-ms race vs the inotify+poll drain) is an ACCEPTED irreducible
  // residual — see docs/divergence.md and the agent.ts disposition gate.
  it('voids a ctime finalize whose strikes accumulated BEFORE the clean exit disposition (pre-notification race)', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });
    // Disposition is published in strace's `close` handler BEFORE exitPromise
    // resolves — a CLEAN whole-tree exit (code 0, no signal).
    const exitStatusRef: { code: number | null; signal: NodeJS.Signals | null } = { code: 0, signal: null };

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      exitStatusRef,
      pollIntervalMs: 20,
      drainMs: 30,
      settleQuietPasses: 2,
      settleHardCapMs: 400,
    });

    // t=40: a legitimate event — consumed by an active-phase drain, which sets
    // lastConsumedCtime from the consume-time stat.
    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    // t=120: MID-RUN ctime-only bump (mtime + size flat) — the finalize shape.
    // The tracer is still "running" (childExited false), so the gate ACCUMULATES
    // strikes and sets the provisional verdict at t≈180.
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 120);
    // t=320: the CLEAN whole-tree exit finally lands — long after the strikes
    // fired.  It must retroactively VOID the provisional verdict.
    setTimeout(() => { resolveExit(); }, 320);

    const items = await collect(tailer, 4000);
    expect(tamperRef.reason).toBeNull();
    expect(items.some((i) => i.line.includes('"name":"LAST"'))).toBe(true);
  });

  // Companion: the provisional verdict is VOIDED only by a CLEAN exit.  Same
  // pre-exit-accumulated finalize shape, but the tracer dies ABNORMALLY (a
  // killed tracer can leave a detached survivor), so the suspicion is PROMOTED
  // to a real tamper — never silently dropped.
  it('promotes a pre-exit ctime finalize to tamper when the exit is abnormal', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });
    const exitStatusRef: { code: number | null; signal: NodeJS.Signals | null } = { code: null, signal: null };

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      exitStatusRef,
      pollIntervalMs: 20,
      drainMs: 30,
      settleQuietPasses: 2,
      settleHardCapMs: 400,
    });

    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 120);
    // t=320: ABNORMAL termination (SIGKILL) — publish the abnormal disposition,
    // then resolve.  The provisional ctime verdict must NOT be voided.
    setTimeout(() => {
      exitStatusRef.code = null;
      exitStatusRef.signal = 'SIGKILL';
      resolveExit();
    }, 320);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/ctime advanced without new bytes|terminated abnormally|SIGKILL|killed or crashed tracer/);
  });

  // 2026-06-12 SECURITY (Codex finding 1): the post-exit meta-gate freeze must
  // engage ONLY on a CLEAN strace exit.  exitPromise resolves on ANY strace
  // close — including a tracee (same UID) SIGKILLing its own tracer to detach
  // and keep running.  If the freeze engaged on that, the survivor could
  // append->truncate->utimes-restore (size===eventsPos, mtime pinned) entirely
  // unobserved.  So an ABNORMAL strace termination (signal set, or non-zero
  // code) is itself a fatal tamper — a killed/crashed tracer means the capture
  // can no longer be trusted.  Here strace "exits" via SIGKILL with the events
  // file left completely benign (only one legitimately-consumed line): the
  // killed tracer ALONE must refuse the lockfile.
  it('records a tamper reason when strace exits abnormally (killed tracer), even with a benign events file', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });
    // The runner mutates this ref in strace's `close` handler BEFORE resolving
    // exitPromise.  A tracee-driven SIGKILL surfaces as code=null, signal set.
    const exitStatusRef: { code: number | null; signal: NodeJS.Signals | null } = { code: null, signal: null };

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      exitStatusRef,
      pollIntervalMs: 20,
      drainMs: 30,
      settleQuietPasses: 2,
      settleHardCapMs: 400,
    });

    // t=40: one legitimate event, consumed during the active phase — proves the
    // file itself is untouched; ONLY the tracer's death drives the tamper.
    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    // t=120: strace is SIGKILLed — publish the abnormal disposition, then resolve.
    setTimeout(() => {
      exitStatusRef.code = null;
      exitStatusRef.signal = 'SIGKILL';
      resolveExit();
    }, 120);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/terminated abnormally|SIGKILL|killed or crashed tracer/);
  });

  // 2026-06-12 SECURITY (Codex finding 1, corollary): a NON-ZERO strace exit
  // with NO signal is a legitimately-failing-but-audited install — `strace -f`
  // propagates the tracee's exit code, and the whole tree still exited, so the
  // freeze MUST engage and the benign end-of-audit ctime finalize must NOT trip.
  // Treating a non-zero code as tamper would refuse a lockfile for every offline
  // postinstall (see main()'s non-zero-Phase-B leniency at agent main() tests).
  it('does NOT record tamper on a NORMAL non-zero strace exit + benign post-exit ctime finalize', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      // Normal exit, non-zero code (a failing install), NO signal → freeze engages.
      exitStatusRef: { code: 1, signal: null },
      pollIntervalMs: 20,
      drainMs: 30,
      settleQuietPasses: 8,
      settleHardCapMs: 600,
    });

    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    setTimeout(() => { resolveExit(); }, 120);
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 140);

    const items = await collect(tailer, 4000);
    expect(tamperRef.reason).toBeNull();
    expect(items.some((i) => i.line.includes('"name":"LAST"'))).toBe(true);
  });

  // 2026-06-12 SECURITY (Codex round-2 finding 1): the macOS bare runner spawns
  // the install DIRECTLY (no `strace -ff` whole-tree wait), so it must NOT enable
  // the freeze — it withholds exitStatusRef.  This pins the fail-closed default
  // the macOS path relies on: with NO disposition the meta gates stay ARMED
  // post-exit, so the benign end-of-audit ctime finalize that a clean Linux exit
  // suppresses is instead CAUGHT (on macOS a daemonized survivor could be the
  // cause, and we have no whole-tree-exit proof to rule that out).
  it('keeps the meta gates ARMED post-exit when no exit disposition is supplied (macOS fail-closed default)', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      // NO exitStatusRef → freeze must stay OFF (the macOS direct-spawn default).
      pollIntervalMs: 20,
      drainMs: 30,
      settleQuietPasses: 8,
      settleHardCapMs: 600,
    });

    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    setTimeout(() => { resolveExit(); }, 120);
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 140);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/ctime advanced|without new bytes/);
  });

  it('records a tamper reason when the events file is truncated below the read position', async () => {
    const { openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, truncateSync, writeFileSync: writeSyncFn, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    // Pre-populate with a line so the tailer advances eventsPos > 0.
    writeSyncFn(
      eventsPath,
      '{"kind":"env_read","name":"FIRST","pid":1,"ts":0,"hidden":false}\n',
      { encoding: 'utf8', flag: 'a' },
    );

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      pollIntervalMs: 20,
      drainMs: 50,
    });

    // Wait for first drain to advance eventsPos, then truncate to 0.
    setTimeout(() => {
      truncateSync(eventsPath, 0);
      setTimeout(resolveExit, 120);
    }, 80);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(/shrank|inode mismatch/);
  });

  // Finding A: append-then-truncate-to-same-size cycle.
  //
  // An attacker who knows the polling interval can race the tailer:
  //   1. Read the file's current size (== eventsPos after the last drain).
  //   2. Append a sensitive event line, growing the file.
  //   3. Truncate the file back to the size from step 1, BEFORE the next
  //      poll observes the growth.
  // A naive size-shrink check (`size < eventsPos`) misses this because the
  // size has been restored.  The fix uses mtime monotonicity (every write,
  // including truncate, advances mtime) plus max-seen-size monotonicity
  // (any poll that observes a smaller size than a prior poll is tamper)
  // plus an inotify watch on the file inode that triggers an immediate
  // drain on every kernel-reported modification.
  it('records a tamper reason on an append-then-truncate-to-same-size cycle', async () => {
    const { openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, truncateSync, writeFileSync: writeSyncFn, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    // Pre-populate with one line so eventsPos advances on first drain.
    const firstLine = '{"kind":"env_read","name":"FIRST","pid":1,"ts":0,"hidden":false}\n';
    writeSyncFn(eventsPath, firstLine, { encoding: 'utf8', flag: 'a' });
    const baselineSize = Buffer.byteLength(firstLine, 'utf8');

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      // Slightly longer poll interval — we want there to be a real polling
      // window even on a slow CI runner.  The mtime + maxSeenSize checks
      // still fire even when the polling races losing the intermediate
      // growth observation.
      pollIntervalMs: 30,
      drainMs: 80,
    });

    // After eventsPos advances past the first line, append a "sensitive"
    // line and immediately truncate back to baselineSize.  Sleep briefly
    // between operations so the kernel definitely bumps mtime.
    setTimeout(() => {
      writeSyncFn(
        eventsPath,
        '{"kind":"audit_bypass","name":"NPM_TOKEN","pid":99,"ts":1,"hidden":false}\n',
        { encoding: 'utf8', flag: 'a' },
      );
      // Tight loop, then truncate — replicates the racing-attacker scenario.
      setTimeout(() => {
        truncateSync(eventsPath, baselineSize);
        setTimeout(resolveExit, 200);
      }, 5);
    }, 120);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    // Either signal is acceptable: a poll caught the intermediate grow (→
    // max-seen mismatch), or it landed on the post-truncate state (→ mtime
    // advanced without new bytes), or the inotify watch forced a drain that
    // observed the larger size.
    expect(tamperRef.reason).toMatch(
      /shrank below max-seen|mtime advanced without new bytes|shrank/,
    );
  });

  // Finding B: parent-directory rename watch.
  //
  // The transient-rename attack: rename the events file aside, drop a
  // decoy at the same path, let a child open the decoy, then rename the
  // original back.  The inode baseline is restored before the next drain
  // so the existing dev/ino check passes — but the child's writes never
  // reach the file the tailer reads from.  Inotify on the parent dir
  // catches the IN_MOVED_FROM / IN_MOVED_TO / IN_CREATE events even when
  // the polling loop misses the window.
  it('records a tamper reason when the events file is renamed away in its parent directory', async () => {
    const { renameSync, openSync: openSyncFn, fstatSync: fstatSyncFn, closeSync: closeSyncFn, constants: fsConstants } = await import('node:fs');
    const eventsPath = join(tailerDir, 'events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      // Finding-B inputs: watch the parent directory for renames affecting
      // the events file's basename.
      eventsDirPath: tailerDir,
      eventsFileBasename: 'events.jsonl',
      tamperRef,
      exitPromise,
      pollIntervalMs: 30,
      drainMs: 80,
    });

    // Rename the events file aside.  The parent-dir watcher should fire a
    // 'rename' event with filename='events.jsonl' and record tamper, even
    // if the polling loop happens to miss the gap before exit.
    setTimeout(() => {
      renameSync(eventsPath, join(tailerDir, 'events.bak'));
      setTimeout(resolveExit, 200);
    }, 60);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    expect(tamperRef.reason).toMatch(
      /parent directory rename|events file disappeared|inode mismatch/,
    );
  });

  // Audit-trust 2026-05-18: append-truncate-utimes_restore bypass.
  //
  // Same-UID attacker:
  //   1. stat() the events file, record current mtime.
  //   2. Append a corrupting/malicious JSONL line — mtime + ctime + size
  //      all advance.
  //   3. ftruncate() back to the original size — mtime + ctime advance
  //      again, size returns to baseline.
  //   4. utimesSync(path, atime, oldMtime) — mtime is restored to the
  //      pre-attack value.  ctime, however, ADVANCES one more time (the
  //      kernel updates ctime on any metadata change, including utimes
  //      itself) and cannot be set back.
  // After the sequence, size === eventsPos AND mtime === lastObservedMtime,
  // so the legacy "mtime advanced without new bytes" gate stays quiet.
  // ctime, however, is strictly greater than the ctime observed at the
  // last successful drain (which is the baseline ctime if no drains have
  // happened yet) — flagging tamper.
  it('records a tamper reason on append-truncate-utimes_restore (ctime-based detection)', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      truncateSync,
      writeFileSync: writeSyncFn,
      utimesSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(tailerDir, 'events.jsonl');
    // Create with O_EXCL so we own the inode (matches createEventsFile in
    // production).  Capture {ino, dev, mtimeNs, ctimeNs} at creation —
    // ctimeNs is the load-bearing baseline for this test.
    const fd = openSyncFn(
      eventsPath,
      // eslint-disable-next-line no-bitwise -- POSIX flag composition
      fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL,
      0o600,
    );
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const baseline = {
      ino: stat.ino,
      dev: stat.dev,
      mtimeNs: stat.mtimeNs,
      ctimeNs: stat.ctimeNs,
    };
    const tamperRef: { reason: string | null } = { reason: null };

    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });

    const tailer = runStraceTailer({
      watchDir: tailerDir,
      basePrefix: 'strace.out',
      fd3Stream: null,
      eventsFilePath: eventsPath,
      eventsBaseline: baseline,
      tamperRef,
      exitPromise,
      pollIntervalMs: 30,
      drainMs: 80,
    });

    // Record the pre-attack mtime — we'll restore it at the end of the
    // tamper sequence to defeat the pure mtime-advanced gate.  Use the
    // baseline-captured mtime so we know the exact value to pin to (a
    // re-stat here would race with any background activity).
    const preAttackAtimeNs = stat.atimeNs;
    const preAttackMtimeNs = stat.mtimeNs;

    setTimeout(() => {
      // Step 1: append a malicious line.  This advances mtime, ctime, size.
      writeSyncFn(
        eventsPath,
        '{"kind":"audit_bypass","name":"NPM_TOKEN","pid":99,"ts":1,"hidden":false}\n',
        { encoding: 'utf8', flag: 'a' },
      );
      // Step 2: truncate back to original size (0).  mtime and ctime
      // advance again; size returns to baseline.
      truncateSync(eventsPath, 0);
      // Step 3: utimes — restore mtime to its pre-attack value.  ctime
      // advances one more time (kernel rule), atime is restored too (the
      // test pins both fields so atime monotonicity does not factor in).
      //
      // node:fs.utimesSync takes seconds or Date.  Convert ns → s (number)
      // with floor; precision loss only affects atime/mtime, which is the
      // attacker-favorable case (any precision loss makes the attack
      // STRONGER, not weaker, so the test remains a valid lower bound).
      const atimeSec = Number(preAttackAtimeNs) / 1e9;
      const mtimeSec = Number(preAttackMtimeNs) / 1e9;
      utimesSync(eventsPath, atimeSec, mtimeSec);
      // Resolve so the tailer drains and exits.  Give a longer window so
      // the polling loop and inotify watcher both have a chance to fire.
      setTimeout(resolveExit, 250);
    }, 80);

    await collect(tailer, 4000);
    expect(tamperRef.reason).not.toBeNull();
    // The ctime-based detection is the load-bearing signal: even when
    // mtime is utimes-restored and size is back to eventsPos, ctime is
    // strictly greater than the baseline ctime.  Accept any of the
    // ctime-flavoured reasons; "shrank below max-seen" is also acceptable
    // if a poll happened to land between the append and the truncate
    // (defense-in-depth).
    expect(tamperRef.reason).toMatch(
      /ctime advanced without new bytes|shrank below max-seen|mtime regressed/,
    );
  });
});

// ---------------------------------------------------------------------------
// LinuxStraceRunner stderr forwarding tests
// ---------------------------------------------------------------------------

describe('LinuxStraceRunner stderr forwarding', () => {
  let tailerDir: string;

  beforeEach(() => {
    tailerDir = join(tmpdir(), `strace-runner-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tailerDir, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(tailerDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('forwards strace stderr lines to process.stderr with [strace] prefix and does not yield them in the iterator', async () => {
    // Build a synthetic ChildProcess-shaped object that exposes stderr (a
    // PassThrough), a stdio[3] pipe for fd-3 JSONL, and an on('close') emitter.
    // This is injected via the spawnImpl DI seam so LinuxStraceRunner.run() is
    // exercised end-to-end without needing a real strace binary.
    const fakeStderr = new PassThrough();
    const fakeFd3 = new PassThrough();

    let closeListener: ((code: number | null) => void) | undefined;
    let errorListener: ((err: Error) => void) | undefined;

    const fakeChild: SpawnResult = {
      stderr: fakeStderr,
      stdio: [null, null, fakeStderr, fakeFd3],
      // bug #1 (2026-05-19): SpawnResult now exposes pid so the runner
      // can read /proc/<pid>/task/<pid>/children to identify strace's
      // direct child.  undefined here keeps the runner on the fallback
      // path (the per-pid file observation heuristic).
      pid: undefined,
      on(event: string, listener: unknown) {
        if (event === 'close') closeListener = listener as (code: number | null) => void;
        if (event === 'error') errorListener = listener as (err: Error) => void;
        return this;
      },
    };
    void errorListener; // suppress unused warning

    const runner = new LinuxStraceRunner(() => fakeChild);

    // Spy on process.stderr.write to capture forwarded lines.
    const capturedStderr: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    const stderrSpy = (chunk: string | Uint8Array, ...args: unknown[]): boolean => {
      const str = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString();
      capturedStderr.push(str);
      return origWrite(chunk as Parameters<typeof origWrite>[0], ...(args as Parameters<typeof origWrite>[1][]));
    };
    process.stderr.write = stderrSpy as typeof process.stderr.write;

    try {
      const basePath = `${tailerDir}/strace.out`;
      const runIter = runner.run('npm', ['rebuild'], {
        env: {},
        cwd: tailerDir,
        basePath,
      });

      // Collect items from the iterator in background while we push data.
      const itemsPromise: Promise<Array<{ pid: number; line: string; source: 'shim' | 'strace' }>> = (async () => {
        const collected: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
        for await (const item of runIter) {
          collected.push(item);
        }
        return collected;
      })();

      // Emit two synthetic strace stderr lines.
      fakeStderr.push('strace: exec failed: No such file or directory\n');
      fakeStderr.push('ptrace: Operation not permitted\n');
      fakeStderr.push(null); // EOF so readline closes

      // Emit one fd3 JSONL line (should yield through iterator with pid=0).
      const shimLine = JSON.stringify({ kind: 'env_read', name: 'HOME', pid: 1, ts: 1000, hidden: false });
      fakeFd3.push(shimLine + '\n');
      fakeFd3.push(null);

      // Signal child exit so the tailer drains and finishes.
      setTimeout(() => { closeListener?.(0); }, 30);

      const items = await itemsPromise;

      // The stderr lines must NOT appear in the yielded iterator items.
      const allLines = items.map((i) => i.line);
      expect(allLines.some((l) => l.includes('exec failed'))).toBe(false);
      expect(allLines.some((l) => l.includes('ptrace'))).toBe(false);

      // The fd3 JSONL line must still come through.
      expect(items.some((i) => i.pid === 0 && i.line.includes('env_read'))).toBe(true);

      // The two strace stderr lines must have been forwarded to process.stderr
      // with the [strace] prefix.
      const forwardedLines = capturedStderr.join('');
      expect(forwardedLines).toContain('[strace] strace: exec failed: No such file or directory');
      expect(forwardedLines).toContain('[strace] ptrace: Operation not permitted');
    } finally {
      process.stderr.write = origWrite;
    }
  });

  // Codex follow-up (bug #3, high, 2026-05-19): tri-state rootPid resolution.
  // When `child.pid` is defined AND readStraceChildPid returns null (timeout,
  // ambiguous, /proc unavailable), the per-pid-file fallback MUST be suppressed.
  // Pre-fix the fallback ran unconditionally — a per-pid file's pid would have
  // seeded `_rootPid` and re-introduced the race the deterministic /proc
  // resolution was added to eliminate.
  it('rootPid: /proc failure with defined child.pid leaves rootPid null and DISABLES per-pid-file fallback (bug #3)', async () => {
    const fakeStderr = new PassThrough();
    const fakeFd3 = new PassThrough();
    let closeListener: ((code: number | null) => void) | undefined;

    // child.pid = 0 makes readStraceChildPid throw on every readFileSync
    // (`/proc/0/task/0/children` doesn't exist) so it returns null AFTER
    // the deadline.  Crucially, pid IS DEFINED (typeof === 'number'),
    // which selects the deterministic-resolution code path — once that
    // path is taken, the per-pid-file fallback MUST be suppressed even
    // when readStraceChildPid returns null.
    const fakeChild: SpawnResult = {
      stderr: fakeStderr,
      stdio: [null, null, fakeStderr, fakeFd3],
      pid: 0,
      on(event: string, listener: unknown) {
        if (event === 'close') closeListener = listener as (code: number | null) => void;
        return this;
      },
    };

    const runner = new LinuxStraceRunner(() => fakeChild);
    const basePath = `${tailerDir}/strace.out`;
    // Pre-create a per-pid file so the tailer's discovery path would
    // otherwise fire recordRootPid(<pid>) with this synthetic pid.
    writeFileSync(`${basePath}.4242`, 'openat(AT_FDCWD, "/x", O_RDONLY) = 3\n', 'utf8');

    const runIter = runner.run('npm', ['rebuild'], {
      env: {},
      cwd: tailerDir,
      basePath,
    });
    const itemsPromise: Promise<Array<{ pid: number; line: string; source: 'shim' | 'strace' }>> = (async () => {
      const collected: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
      for await (const item of runIter) {
        collected.push(item);
      }
      return collected;
    })();
    fakeStderr.push(null);
    fakeFd3.push(null);
    // Allow the tailer one poll cycle to drain the pre-created file
    // BEFORE we signal exit, so the recordRootPid suppression is the
    // ONLY reason _rootPid stays null (rather than the iterator exiting
    // before the tailer ever discovered the file).
    setTimeout(() => { closeListener?.(0); }, 200);
    await itemsPromise;

    // CRITICAL ASSERTION: getRootPid() is null even though a per-pid
    // file with pid 4242 was visible the entire run.  The suppression
    // is what bug #3's fix introduces.
    expect(runner.getRootPid()).toBeNull();
  });

  // Bug #3 sanity — the test-fake fallback path still works.  When
  // child.pid is UNDEFINED (catastrophic spawn or test stub), the
  // per-pid-file fallback MUST still seed _rootPid for the convenience
  // of older test fakes that rely on it.
  it('rootPid: undefined child.pid keeps the per-pid-file fallback enabled (bug #3 sanity)', async () => {
    const fakeStderr = new PassThrough();
    const fakeFd3 = new PassThrough();
    let closeListener: ((code: number | null) => void) | undefined;

    const fakeChild: SpawnResult = {
      stderr: fakeStderr,
      stdio: [null, null, fakeStderr, fakeFd3],
      pid: undefined,
      on(event: string, listener: unknown) {
        if (event === 'close') closeListener = listener as (code: number | null) => void;
        return this;
      },
    };

    const runner = new LinuxStraceRunner(() => fakeChild);
    const basePath = `${tailerDir}/strace.out`;
    writeFileSync(`${basePath}.5151`, 'openat(AT_FDCWD, "/x", O_RDONLY) = 3\n', 'utf8');

    const runIter = runner.run('npm', ['rebuild'], {
      env: {},
      cwd: tailerDir,
      basePath,
    });
    const itemsPromise: Promise<Array<{ pid: number; line: string; source: 'shim' | 'strace' }>> = (async () => {
      const collected: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
      for await (const item of runIter) {
        collected.push(item);
      }
      return collected;
    })();
    fakeStderr.push(null);
    fakeFd3.push(null);
    setTimeout(() => { closeListener?.(0); }, 200);
    await itemsPromise;

    // Fallback enabled → pid 5151 was observed and seeded _rootPid.
    expect(runner.getRootPid()).toBe(5151);
  });
});

// ---------------------------------------------------------------------------
// runStraceTailer cleanup (try/finally) on consumer break
// ---------------------------------------------------------------------------

describe('runStraceTailer cleanup on early break', () => {
  let tailerDir: string;

  beforeEach(() => {
    tailerDir = join(tmpdir(), `strace-tailer-break-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tailerDir, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(tailerDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('clears the poll interval when the consumer breaks out of for-await early', async () => {
    const basePath = join(tailerDir, 'strace.out');
    // Write one line so the tailer has something to yield before we break.
    writeFileSync(`${basePath}.1`, 'openat(AT_FDCWD, "/first", O_RDONLY) = 3\n', 'utf8');

    // Capture clearInterval calls so we can assert cleanup fired.
    const clearedIds: Array<ReturnType<typeof setInterval>> = [];
    const realClearInterval = clearInterval;
    const clearIntervalSpy = (id: ReturnType<typeof setInterval> | string | number | undefined): void => {
      if (id !== undefined) clearedIds.push(id as ReturnType<typeof setInterval>);
      realClearInterval(id as ReturnType<typeof setInterval>);
    };
    // Patch the global so runStraceTailer's finally block calls our spy.
    (globalThis as Record<string, unknown>)['clearInterval'] = clearIntervalSpy;

    try {
      // exitPromise that never resolves — only the consumer break should stop the loop.
      const exitPromise = new Promise<void>(() => { /* never */ });

      const tailer = runStraceTailer({
        watchDir: tailerDir,
        basePrefix: 'strace.out',
        fd3Stream: null,
        exitPromise,
        pollIntervalMs: 50,
        drainMs: 50,
      });

      // Read exactly one item then break.
      const collected: Array<{ pid: number; line: string; source: 'shim' | 'strace' }> = [];
      for await (const item of tailer) {
        collected.push(item);
        break; // triggers the try/finally in runStraceTailer
      }

      // We got the first line.
      expect(collected).toHaveLength(1);
      expect(collected[0]!.line).toContain('/first');

      // The finally block must have called clearInterval at least once.
      expect(clearedIds.length).toBeGreaterThanOrEqual(1);
    } finally {
      (globalThis as Record<string, unknown>)['clearInterval'] = realClearInterval;
    }
  });
});

// ---------------------------------------------------------------------------
// Codex follow-up (bug #1, 2026-05-19): readStraceChildPid — deterministic
// resolution of strace's direct child pid via /proc/<pid>/task/<pid>/children
// ---------------------------------------------------------------------------

describe('readStraceChildPid', () => {
  it('returns null when /proc is unavailable for the given pid', async () => {
    // Pid 0 is not a real process on Linux; /proc/0 does not exist, so
    // every readFileSync attempt will throw and the loop will exit
    // after the deadline.  Set a short deadline to keep the test fast.
    const { readStraceChildPid } = await import('../../src/guest/agent.js');
    const result = readStraceChildPid(0, 15);
    expect(result).toBeNull();
  });

  it('returns null when the deadline expires (very short deadline)', async () => {
    // Pass a pid that almost certainly has no children (process.pid
    // itself is the test runner; the children file may be non-empty
    // BUT we use a 0ms deadline so the loop exits on the first
    // Date.now() check without reading anything).
    const { readStraceChildPid } = await import('../../src/guest/agent.js');
    const result = readStraceChildPid(process.pid, 0);
    expect(result).toBeNull();
  });
});

describe('MacOSInstallRunner post-exit freeze omission (Codex round-2 finding 1)', () => {
  let macDir: string;

  beforeEach(() => {
    macDir = join(tmpdir(), `macos-runner-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(macDir, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(macDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  // The macOS bare runner spawns the install command DIRECTLY (no `strace -ff`
  // whole-tree wait), so a normal child exit does NOT prove a daemonized
  // descendant has exited.  It therefore MUST NOT pass exitStatusRef to
  // runStraceTailer — leaving the post-exit ctime/mtime meta gates ARMED.  This
  // is a SECURITY invariant (Codex round-2 finding 1): if a maintainer "fixed"
  // the runner to pass a normal-exit disposition, the freeze would engage and a
  // post-parent-exit survivor could tamper undetected.  This test fails if that
  // regression is introduced: a benign post-exit ctime finalize MUST still be
  // caught (gates armed), exactly because the runner withholds exitStatusRef.
  it('does NOT freeze the meta gates post-exit (keeps them armed) on a normal child exit', async () => {
    const {
      openSync: openSyncFn,
      fstatSync: fstatSyncFn,
      closeSync: closeSyncFn,
      appendFileSync: appendSyncFn,
      chmodSync,
      constants: fsConstants,
    } = await import('node:fs');
    const eventsPath = join(macDir, 'script-jail-events.jsonl');
    const fd = openSyncFn(eventsPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const stat = fstatSyncFn(fd, { bigint: true });
    closeSyncFn(fd);
    const eventsFile: EventsFile = {
      path: eventsPath,
      dirPath: macDir,
      baseline: { ino: stat.ino, dev: stat.dev, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs },
    };

    // Fake child whose `close` we fire manually with a NORMAL (code 0, no signal)
    // exit — the disposition that WOULD freeze the gates on the Linux runner.
    let fireClose: ((code: number | null, signal: NodeJS.Signals | null) => void) | null = null;
    const fakeChild = {
      stderr: null as NodeJS.ReadableStream | null,
      stdio: [null, null, null, null] as Array<NodeJS.ReadableStream | null | undefined>,
      pid: undefined as number | undefined,
      on(event: 'close' | 'error', listener: (...a: never[]) => void) {
        if (event === 'close') fireClose = listener as unknown as typeof fireClose;
        return this;
      },
    };
    const fakeSpawn = (() => fakeChild) as unknown as SpawnImpl;

    const runner = new MacOSInstallRunner(fakeSpawn, eventsFile);

    // t=40: one legitimate event consumed during the active phase.
    setTimeout(() => {
      appendSyncFn(eventsPath, '{"kind":"env_read","name":"LAST","pid":1,"ts":0,"hidden":false}\n', 'utf8');
    }, 40);
    // t=120: child exits NORMALLY (code 0).  t=140: benign ctime finalize.
    setTimeout(() => { fireClose?.(0, null); }, 120);
    setTimeout(() => { chmodSync(eventsPath, 0o600); }, 140);

    // Consume the runner's async iterable with a timeout guard.
    await Promise.race([
      (async () => {
        for await (const _ of runner.run('node', [], {
          env: {},
          cwd: macDir,
          basePath: join(macDir, 'strace.out'),
        })) {
          // drain
        }
      })(),
      new Promise<void>((_, reject) => setTimeout(() => reject(new Error('macOS runner timed out')), 4000)),
    ]);

    // Gates stayed ARMED → the post-exit ctime bump is caught.  If the runner
    // ever (wrongly) passed a normal-exit exitStatusRef, the freeze would engage
    // and this would be null.
    expect(runner.getTamperReason()).not.toBeNull();
    expect(runner.getTamperReason()).toMatch(/ctime advanced|without new bytes/);
  });
});

describe('Phase B stdout capture (in-memory tail)', () => {
  // Drain a PassThrough through the collector, then end it and let the
  // 'data'/'end' listeners flush on the next tick before reading the tail.
  async function feed(
    chunks: Array<string | Buffer>,
    redact: ((s: string) => string) | undefined,
    capBytes?: number,
    pendingMaxBytes?: number,
  ): Promise<string> {
    const stream = new PassThrough();
    const getTail = attachStdoutTailCollector(stream, redact, capBytes, pendingMaxBytes);
    for (const c of chunks) stream.write(c);
    stream.end();
    await new Promise<void>((r) => stream.on('end', () => r()));
    await new Promise<void>((r) => setImmediate(r));
    return getTail();
  }

  // Feed Buffer chunks as SEPARATE 'data' events (a setImmediate between writes)
  // so a multibyte codepoint split across chunk boundaries actually exercises
  // the stateful decoder (PassThrough may otherwise coalesce back-to-back writes).
  async function feedBuffersSeparated(
    buffers: Array<Buffer>,
    redact: ((s: string) => string) | undefined,
    capBytes?: number,
  ): Promise<string> {
    const stream = new PassThrough();
    const getTail = attachStdoutTailCollector(stream, redact, capBytes);
    for (const b of buffers) {
      stream.write(b);
      await new Promise<void>((r) => setImmediate(r));
    }
    stream.end();
    await new Promise<void>((r) => stream.on('end', () => r()));
    await new Promise<void>((r) => setImmediate(r));
    return getTail();
  }

  it('returns "" when no stream is supplied (test stubs / no fd1)', () => {
    expect(attachStdoutTailCollector(null, undefined)()).toBe('');
    expect(attachStdoutTailCollector(undefined, (s) => s)()).toBe('');
  });

  it('keeps the whole output when under the byte cap', async () => {
    expect(await feed(['hello ', 'world'], undefined, 16384)).toBe('hello world');
  });

  it('drains a verbose stream without deadlock and keeps the tail bounded', async () => {
    const chunks = Array.from({ length: 200 }, (_, i) => `line ${i}\n`.repeat(50));
    const tail = await feed(chunks, undefined, 1024);
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(1024);
    expect(tail).toContain('line 199'); // most-recent output survives
  });

  // ── LEAK GATE ────────────────────────────────────────────────────────────
  // O9 invariant: a line is redacted only once COMPLETE (its '\n' arrived), so
  // the whole token is present; shapes are LINE-LOCAL so per-line redaction is
  // complete; a complete line is safe to retain at any length (redaction masks
  // every secret BEFORE the front-drop). The r5..r8 "overflow split" leak is
  // structurally impossible: a REAL credential on a (re-assembled) complete line
  // is masked whole; the only drop is an unterminated >pendingMax line (poison).
  it('LEAK GATE: a real Bearer token whose token chars exceed the cap is masked whole', async () => {
    const cap = 4096;
    const redact = (s: string) => redactSensitive(s, []); // shape-only
    // One complete line, token >cap — kept (not poisoned) and masked whole.
    const tail = await feed(['Authorization: Bearer ' + 'A'.repeat(cap + 1000) + '\n'], redact, cap);
    expect(tail).not.toMatch(/A{50}/); // the token is gone
    expect(tail).toContain('<REDACTED');
  });

  const realShape: Array<{ name: string; line: string; secretRe: RegExp }> = [
    { name: 'Bearer', line: 'Authorization: Bearer ABCDEFGH01234567890123456789\n', secretRe: /ABCDEFGH0123/ },
    { name: '_authToken', line: '//registry/:_authToken=npmTokenABCDEFGH01234567\n', secretRe: /npmTokenABCDEF/ },
    { name: 'url user:pass@', line: 'proxy=https://user:PASSWORDABCDEFGH@host:8080\n', secretRe: /PASSWORDABCDEF/ },
  ];
  for (const { name, line, secretRe } of realShape) {
    it(`LEAK GATE: real ${name} credential split ACROSS CHUNKS reunites on its line and is masked`, async () => {
      const redact = (s: string) => redactSensitive(s, []);
      const mid = Math.floor(line.length / 2);
      // Push the cap first with newline-terminated noise, then split the
      // credential line across two chunks (no delimiter between).
      const tail = await feed(
        ['noise\n'.repeat(2000), line.slice(0, mid), line.slice(mid)],
        redact,
        PHASE_B_STDOUT_TAIL_BYTES,
      );
      expect(tail).not.toMatch(secretRe);
      expect(tail).toContain('<REDACTED');
    });
  }

  it('LEAK GATE: a layer-1 exact value is masked wherever it lands on a complete line (after huge prefix + CR)', async () => {
    const cap = 4096;
    const redact = (s: string) => redactSensitive(s, ['TOK'], { TOK: 'SECRETVAL1234567890' });
    // The value sits after a >cap prefix and a bare CR, all on ONE complete line.
    const tail = await feed(['junk ' + 'Q'.repeat(cap + 1000) + '\rSECRETVAL1234567890\n'], redact, cap);
    expect(tail).not.toContain('SECRETVAL1234567890');
  });

  it('LEAK GATE: a layer-1 value split ACROSS CHUNKS within a line is masked', async () => {
    const redact = (s: string) => redactSensitive(s, ['TOK'], { TOK: 'SECRETVAL123' });
    const tail = await feed(['env: secret=SECRET', 'VAL123 done\n'], redact, 4096);
    expect(tail).not.toContain('SECRETVAL123');
    expect(tail).toContain('<REDACTED');
  });

  // ── FINDING 1: line-local shape contract (Codex round-9 [high] #1) ─────────
  it('line-local contract: a same-line shape is masked; a shape spanning a newline is NOT (documented)', async () => {
    const redact = (s: string) => redactSensitive(s, []);
    expect(await feed(['Authorization: Bearer TOKEN0123456789\n'], redact, 4096)).toContain('<REDACTED');
    // Bearer marker and token on SEPARATE lines: by the line-local contract this
    // is not a credential, so the token is not shape-masked.
    const cross = await feed(['Authorization: Bearer\n', 'TOKEN0123456789\n'], redact, 4096);
    expect(cross).toContain('TOKEN0123456789');
  });

  it('line-local contract: a real protected VALUE on the token line is still masked even when the shape spans a newline', async () => {
    // Defense in depth: even if a shape regex would not span the newline, a
    // registered env value on the second line is caught by layer-1.
    const redact = (s: string) => redactSensitive(s, ['TOK'], { TOK: 'TOKEN0123456789' });
    const tail = await feed(['Authorization: Bearer\n', 'TOKEN0123456789\n'], redact, 4096);
    expect(tail).not.toContain('TOKEN0123456789');
  });

  // ── FINDING 2: stateful UTF-8 decode across chunk boundaries (round-9 #2) ───
  it('multibyte protected value split mid-codepoint across chunks is still masked', async () => {
    const VALUE = 'tokéSECRETTAIL1234'; // é = 0xC3 0xA9
    const redact = (s: string) => redactSensitive(s, ['V'], { V: VALUE });
    const full = Buffer.from('value=' + VALUE + '\n', 'utf8');
    const splitAt = Buffer.byteLength('value=tok', 'utf8') + 1; // AFTER the first byte of é
    const tail = await feedBuffersSeparated(
      [full.subarray(0, splitAt), full.subarray(splitAt)],
      redact,
      4096,
    );
    expect(tail).not.toContain('SECRETTAIL1234'); // value reassembled then masked
    expect(tail).toContain('<REDACTED');
  });

  // ── FINDING 3: keep long-but-complete diagnostic lines (round-9 [medium]) ───
  it('keeps a long (>cap) COMPLETE line and the YN0028 error that follows', async () => {
    const cap = 4096;
    const longLine = 'lockfile descriptor ' + 'D'.repeat(19000) + '\n'; // ~19 KB, like real Yarn
    const tail = await feed(
      [longLine, 'YN0028: The lockfile would have been modified by this install.\n'],
      undefined,
      cap,
    );
    expect(tail).toContain('YN0028: The lockfile would have been modified'); // NOT dropped
    expect(tail).not.toContain('stdout capture stopped'); // no poison for a complete line
  });

  // ── POISON: only an unterminated line over pendingMax ──────────────────────
  it('poisons (sticky) only an UNTERMINATED line exceeding pendingMax; drops nothing before it', async () => {
    const cap = 1024;
    const pendingMax = 4096;
    const tail = await feed(
      ['real error line\n', 'Z'.repeat(pendingMax + 100) /* no newline, > pendingMax */, 'later\n'],
      undefined,
      cap,
      pendingMax,
    );
    expect(tail).toContain('real error line'); // pre-overflow retained
    expect(tail).toContain('stdout capture stopped'); // marker
    expect(tail).not.toContain('later'); // sticky: post-overflow dropped
    expect((tail.match(/stdout capture stopped/g) || []).length).toBe(1); // exactly one marker
  });

  // Byte-at-a-time UNTERMINATED stream: exercises the O(1) incremental
  // pendingBytes counter (no per-event O(pending) re-measure / newline scan).
  // Under pendingMax it is retained whole; over it, it poisons — same outcome
  // as a single big chunk, but reached one byte per 'data' event.
  it('byte-at-a-time unterminated input: retained under pendingMax, poisoned over it', async () => {
    // effective pendingMax = max(pendingMaxArg, capBytes); keep cap below it.
    const cap = 2048;
    const pendingMax = 3000;
    const under = 'a'.repeat(2000); // < pendingMax and < cap → fully retained
    const kept = await feed(under.split(''), undefined, cap, pendingMax);
    expect(kept).toBe(under); // every single-byte chunk accumulated, none lost

    const over = 'b'.repeat(4000); // > pendingMax, no newline
    const poisoned = await feed(over.split(''), undefined, cap, pendingMax);
    expect(poisoned).toContain('stdout capture stopped');
    expect((poisoned.match(/stdout capture stopped/g) || []).length).toBe(1);
  });

  // ── CORRECTNESS / EDGES ──────────────────────────────────────────────────
  it('front-drop never strands a secret across many redacted lines', async () => {
    const cap = 2048;
    const redact = (s: string) => redactSensitive(s, []);
    const lines: Array<string> = [];
    for (let i = 0; i < 200; i++) lines.push(`//r${i}/:_authToken=npm_${'A'.repeat(36)}${i}\n`);
    const tail = await feed(lines, redact, cap);
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(cap);
    expect(tail).not.toMatch(/_authToken=npm_A/); // every token masked, none stranded
    expect(tail).toContain('<REDACTED');
  });

  it('multibyte complete line under cap kept on a char boundary', async () => {
    const tail = await feed(['€'.repeat(3) + '\n'], undefined, 16);
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(16);
    expect(tail).toContain('€');
  });

  it('idempotent getter: repeated calls are stable', async () => {
    const stream = new PassThrough();
    const get = attachStdoutTailCollector(stream, undefined, 4096);
    stream.write('hi\n');
    stream.end();
    await new Promise<void>((r) => stream.on('end', () => r()));
    await new Promise<void>((r) => setImmediate(r));
    expect(get()).toBe(get());
    expect(get()).toBe('hi\n');
  });

  it('exposes sane default byte caps', () => {
    expect(PHASE_B_STDOUT_TAIL_BYTES).toBeGreaterThanOrEqual(16384);
    expect(PHASE_B_STDOUT_PENDING_MAX_BYTES).toBeGreaterThan(PHASE_B_STDOUT_TAIL_BYTES);
  });
});

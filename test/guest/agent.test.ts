// Tests for src/guest/agent.ts
// Wires all mocks together; uses a MemoryConnection and fake config file.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PassThrough } from 'node:stream';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stringify } from 'yaml';

import { createConnection } from 'node:net';

import { LinuxVsockConnection, main, MemoryConnection, runStraceTailer } from '../../src/guest/agent.js';
import type { DnsLookupFn } from '../../src/guest/agent.js';
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
    expect(env['NODE_OPTIONS']).toContain('dlopen-block.cjs');
    expect(env['NODE_OPTIONS']).toContain('platform-spoof.cjs');
    expect(env['SCRIPT_JAIL_LOG_FD']).toBe('3');
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

    expect(fetchCalls[0]).toContain('pnpm fetch');
    expect(installCalls[0]).toContain('pnpm install');
  });

  it('handles yarn manager config', async () => {
    const { conn, hostSend } = makeConn();
    const { spawner, calls: fetchCalls } = mockSpawner();
    const { strace, calls: installCalls } = trackingStrace();
    const configPath = writeConfig(testDir, { manager: 'yarn' });

    setTimeout(() => hostSend('go\n'), 10);

    await main({ configPath, connection: conn, spawner, strace, dnsLookup: offlineLookup });

    expect(fetchCalls[0]).toContain('yarn install');
    expect(installCalls[0]).toContain('yarn install --immutable --offline');
  });

  it('does NOT emit install_done or final lockfile when install fails', async () => {
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
        strace: emptyStrace(1), // Phase B fails
        dnsLookup: offlineLookup,
      });
    } finally {
      process.exit = origExit;
    }

    const output = getOutput();
    const lines = output.split('\n').filter((l) => l.trim());
    const frames = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const kinds = frames.map((f) => f['kind']);

    // install_done should NOT be emitted on failure
    const installDoneFrames = frames.filter((f) => f['kind'] === 'handshake' && f['phase'] === 'install_done');
    expect(installDoneFrames).toHaveLength(0);

    // final should NOT be emitted on failure
    expect(kinds).not.toContain('final');

    // An error frame should be emitted instead
    expect(kinds).toContain('error');
    const errFrame = frames.find((f) => f['kind'] === 'error');
    expect(errFrame?.['fatal']).toBe(true);
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
    iter: AsyncIterable<{ pid: number; line: string }>,
    timeoutMs = 3000,
  ): Promise<Array<{ pid: number; line: string }>> {
    const results: Array<{ pid: number; line: string }> = [];
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
    expect(items[0]).toEqual({ pid: 1234, line: 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3' });
    expect(items[1]).toEqual({ pid: 1234, line: 'execve("/bin/sh", ["sh"], ...) = 0' });
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
    expect(items[0]).toEqual({ pid: 9999, line: 'openat(AT_FDCWD, "/late", O_RDONLY) = 5' });
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
      const { appendFileSync } = require('node:fs');
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
});

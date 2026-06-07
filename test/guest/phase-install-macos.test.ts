// script-jail — test/guest/phase-install-macos.test.ts
//
// Unit tests for the macOS-bare Phase B dispatcher (`runInstallPhaseMacos`).
// The Mach-O shim is the SOLE event source on macOS, so this dispatcher reads
// a SINGLE in-order shim JSONL channel (no strace text channel, no /proc).
//
// These tests inject a canned StraceRunner (the same test-impl seam the Linux
// `runInstallPhase` tests use) that yields hand-written shim JSONL lines, ALL
// tagged `source:'shim'`.  No real install is spawned.  We assert the dispatcher:
//   - PARSES the `read` / `write` / `connect` JSONL kinds the Mach-O shim emits
//     (these are NOT handled by the shared `parseShimLine` — on Linux they come
//     from strace — so the macOS dispatcher uses its own `read`/`write`/`connect`
//     parse and fails closed on anything else),
//   - seeds attribution from a shim `exec` carrying npm lifecycle env,
//   - synthesizes a `spawn` for a successful `exec`,
//   - records `connect` faithfully (the host result, no offline rewrite),
//   - surfaces a hidden env_read,
//   - FAILS CLOSED (tamper) on an unparseable shim line.

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';

import { runInstallPhaseMacos } from '../../src/guest/phase-install-macos.js';
import type { StraceRunner, LineSource } from '../../src/guest/phase-install.js';
import { Emitter } from '../../src/guest/emit.js';
import { Attribution } from '../../src/guest/attribution.js';
import type { ProcReader } from '../../src/guest/attribution.js';
import type { AttributedEvent } from '../../src/lock/schema.js';

const PID = 100;

// macOS contract: /proc is absent, so every ProcReader lookup returns null and
// attribution flows entirely through the shim event seed.
const NULL_PROC_READER: ProcReader = {
  readPpid() { return null; },
  readEnviron() { return null; },
};

/**
 * A StraceRunner that replays pre-canned shim JSONL lines, all tagged
 * `source:'shim'` (the only source the macOS dispatcher ever sees).  Mirrors
 * `cannedStraceRunner` in test/guest/phase-install.ts.
 */
function cannedShimRunner(
  lines: string[],
): StraceRunner & { tamper(): string | null } {
  let tamper: string | null = null;
  return {
    async *run(): AsyncIterable<{ pid: number; line: string; source: LineSource }> {
      for (const line of lines) {
        let pid = PID;
        try { pid = (JSON.parse(line) as { pid?: number }).pid ?? PID; } catch { /* keep default */ }
        yield { pid, line, source: 'shim' };
      }
    },
    getExitCode() { return 0; },
    getTamperReason() { return tamper; },
    recordTamper(reason: string) { if (tamper === null) tamper = reason; },
    getRootPid() { return null; },
    tamper() { return tamper; },
  };
}

/** Drive runInstallPhaseMacos and collect the emitted AttributedEvents. */
async function drive(
  lines: string[],
): Promise<{ events: AttributedEvent[]; result: Awaited<ReturnType<typeof runInstallPhaseMacos>> }> {
  const events: AttributedEvent[] = [];
  const pt = new PassThrough();
  pt.on('data', (chunk: Buffer) => {
    for (const l of chunk.toString().split('\n')) {
      if (!l.trim()) continue;
      const parsed = JSON.parse(l) as Record<string, unknown>;
      if (parsed['kind'] === 'event') {
        events.push({
          raw: parsed['raw'] as AttributedEvent['raw'],
          pkg: parsed['pkg'] as string,
          lifecycle: parsed['lifecycle'] as AttributedEvent['lifecycle'],
        });
      }
    }
  });
  const runner = cannedShimRunner(lines);
  const result = await runInstallPhaseMacos({
    manager: 'pnpm',
    cwd: '/work',
    env: { PATH: '/usr/bin' },
    strace: runner,
    attribution: new Attribution(NULL_PROC_READER),
    emitter: new Emitter(pt),
  });
  return { events, result };
}

// A shim `exec` carrying the in-process npm lifecycle env seeds attribution for
// the pid.  Using a NON-node basename begins a bootstrap *candidate* (vs the
// node-bootstrap window), so post-exec events flush rather than being dropped
// as Node's own bootstrap noise.
function execLine(opts: { basename: string; pid?: number } = { basename: 'install.sh' }): string {
  return JSON.stringify({
    kind: 'exec',
    prog: `/work/node_modules/evil-pkg/${opts.basename}`,
    argv0: opts.basename,
    envp_alloc_failed: false,
    pid: opts.pid ?? PID,
    ts: 1,
    npm_package_name: 'evil-pkg',
    npm_package_version: '1.0.0',
    npm_lifecycle_event: 'postinstall',
  });
}

describe('runInstallPhaseMacos — shim-only dispatch', () => {
  it('runs pnpm rebuild via <re-signed node> <corepack-cli> (DYLD-preserving launch)', async () => {
    const calls: Array<{ cmd: string; args: string[] }> = [];
    const strace: StraceRunner = {
      async *run(cmd, args) { calls.push({ cmd, args }); },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper() { /* no-op */ },
      getRootPid() { return null; },
    };
    await runInstallPhaseMacos({
      manager: 'pnpm',
      cwd: '/work',
      env: { PATH: '/usr/bin' },
      strace,
      attribution: new Attribution(NULL_PROC_READER),
      emitter: new Emitter(new PassThrough()),
    });
    expect(calls).toHaveLength(1);
    // The manager MUST be launched as `<node> <manager-cli.js> …`, never the
    // bare `pnpm` shim: a shebang shim routes the first exec through the SIP
    // binary /usr/bin/env, which strips DYLD_INSERT_LIBRARIES before node starts
    // (so the Mach-O shim never loads).  The orchestrator runs under the
    // re-signed node, so cmd === process.execPath.
    expect(calls[0]!.cmd).toBe(process.execPath);
    expect(calls[0]!.args[0]).toMatch(/corepack\.js$/);
    expect(calls[0]!.args).toContain('pnpm');
    expect(calls[0]!.args).toContain('rebuild');
    // The store-dir is pinned to the cwd (parity with the fetch phase).
    expect(calls[0]!.args.some((a) => a.startsWith('--store-dir='))).toBe(true);
  });

  it('runs npm rebuild via <re-signed node> <npm-cli.js> (DYLD-preserving launch)', async () => {
    const calls: Array<{ cmd: string; args: string[] }> = [];
    const strace: StraceRunner = {
      async *run(cmd, args) { calls.push({ cmd, args }); },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper() { /* no-op */ },
      getRootPid() { return null; },
    };
    await runInstallPhaseMacos({
      manager: 'npm',
      cwd: '/work',
      env: { PATH: '/usr/bin' },
      strace,
      attribution: new Attribution(NULL_PROC_READER),
      emitter: new Emitter(new PassThrough()),
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.cmd).toBe(process.execPath);
    expect(calls[0]!.args[0]).toMatch(/npm-cli\.js$/);
    expect(calls[0]!.args).toContain('rebuild');
  });

  it('parses a shim `write` JSONL line and attributes it to the exec-seeded package', async () => {
    // REGRESSION: the shared parseShimLine does NOT handle `write` (on Linux it
    // comes from strace), so without the macOS-specific parse this line would
    // fail closed.  Here it must surface as a real write event.
    const { events, result } = await drive([
      execLine(),
      JSON.stringify({ kind: 'write', path: '/work/escaped.txt', pid: PID, ts: 2, hidden: false }),
    ]);
    expect(result.tamperReason).toBeNull();
    const write = events.find((e) => e.raw.kind === 'write');
    expect(write).toBeDefined();
    expect(write!.pkg).toBe('evil-pkg@1.0.0');
    expect(write!.lifecycle).toBe('postinstall');
    expect((write!.raw as { path: string }).path).toBe('/work/escaped.txt');
  });

  it('parses a shim `read` JSONL line', async () => {
    const { events, result } = await drive([
      execLine(),
      JSON.stringify({ kind: 'read', path: '/work/data.json', pid: PID, ts: 2, hidden: false }),
    ]);
    expect(result.tamperReason).toBeNull();
    const read = events.find((e) => e.raw.kind === 'read');
    expect(read).toBeDefined();
    expect((read!.raw as { path: string }).path).toBe('/work/data.json');
  });

  it('parses a shim `connect` JSONL line and records the host result FAITHFULLY (online → ok)', async () => {
    // macOS bare is observe-only and stays online, so the shim records the
    // actual connect result (`ok`).  normalize/parity-diff reconcile this with
    // the Linux side's offline `<BLOCKED>` at diff time, NOT here.
    const { events, result } = await drive([
      execLine(),
      JSON.stringify({ kind: 'connect', host: '198.51.100.7', port: 443, result: 'ok', pid: PID, ts: 2 }),
    ]);
    expect(result.tamperReason).toBeNull();
    const conn = events.find((e) => e.raw.kind === 'connect');
    expect(conn).toBeDefined();
    expect((conn!.raw as { result: string; host: string; port: number }).result).toBe('ok');
    expect((conn!.raw as { host: string }).host).toBe('198.51.100.7');
  });

  it('surfaces a hidden env_read (protected env var)', async () => {
    const { events } = await drive([
      execLine(),
      JSON.stringify({ kind: 'env_read', name: 'NPM_TOKEN', pid: PID, ts: 2, hidden: true }),
    ]);
    const envRead = events.find((e) => e.raw.kind === 'env_read');
    expect(envRead).toBeDefined();
    expect((envRead!.raw as { name: string; hidden: boolean }).name).toBe('NPM_TOKEN');
    expect((envRead!.raw as { hidden: boolean }).hidden).toBe(true);
  });

  it('synthesizes a spawn for a successful exec (argv0 ?? prog), attributed to the seeded package', async () => {
    const { events } = await drive([execLine({ basename: 'install.sh' })]);
    const spawn = events.find((e) => e.raw.kind === 'spawn');
    expect(spawn).toBeDefined();
    expect(spawn!.pkg).toBe('evil-pkg@1.0.0');
    expect((spawn!.raw as { argv: string[] }).argv).toEqual(['install.sh']);
    expect((spawn!.raw as { result: string }).result).toBe('ok');
  });

  it('carries the shim audit_blind flag onto the synthesized spawn (un-instrumented SIP exec)', async () => {
    // The shim could not redirect /usr/bin/find (not a uutils applet / shell), so
    // the real arm64e binary ran with DYLD stripped and the shim tagged the exec
    // audit_blind. The dispatcher must carry that onto the spawn so normalize.ts
    // surfaces it as `<AUDIT_BLIND>` in spawn_attempts.
    const blindExec = JSON.stringify({
      kind: 'exec',
      prog: '/usr/bin/find',
      argv0: '/usr/bin/find',
      envp_alloc_failed: false,
      result: 'ok',
      audit_blind: true,
      pid: PID,
      ts: 1,
      npm_package_name: 'evil-pkg',
      npm_package_version: '1.0.0',
      npm_lifecycle_event: 'postinstall',
    });
    const { events } = await drive([blindExec]);
    const spawn = events.find((e) => e.raw.kind === 'spawn');
    expect(spawn).toBeDefined();
    expect((spawn!.raw as { audit_blind?: boolean }).audit_blind).toBe(true);
  });

  it('leaves audit_blind unset on the spawn for an ordinary (redirected/non-SIP) exec', async () => {
    const { events } = await drive([execLine({ basename: 'install.sh' })]);
    const spawn = events.find((e) => e.raw.kind === 'spawn');
    expect(spawn).toBeDefined();
    expect((spawn!.raw as { audit_blind?: boolean }).audit_blind).toBeUndefined();
  });

  it('FAILS CLOSED (tamper) on an unparseable shim line', async () => {
    // The trusted shim channel must never fall through to a best-effort drop.
    const { result } = await drive([
      execLine(),
      '{ this is not valid json',
    ]);
    expect(result.tamperReason).not.toBeNull();
    expect(result.tamperReason).toMatch(/unparseable JSONL/);
  });

  it('FAILS CLOSED on a structurally-invalid (schema-rejected) connect line', async () => {
    // A `connect` line missing `port` is schema-rejected → parse returns null →
    // the macOS dispatcher fails closed, same as a malformed JSON line.
    const { result } = await drive([
      execLine(),
      JSON.stringify({ kind: 'connect', host: '198.51.100.7', result: 'ok', pid: PID, ts: 2 }),
    ]);
    expect(result.tamperReason).not.toBeNull();
  });

  it('FAILS CLOSED on an unexpected non-shim LineSource', async () => {
    // The Mach-O shim is the sole source; a 'strace' line is an audit-pipeline
    // contract breach on macOS.
    const events: AttributedEvent[] = [];
    const runner: StraceRunner = {
      async *run(): AsyncIterable<{ pid: number; line: string; source: LineSource }> {
        yield { pid: PID, line: execLine(), source: 'strace' };
      },
      getExitCode() { return 0; },
      getTamperReason() { return null; },
      recordTamper() { /* no-op */ },
      getRootPid() { return null; },
    };
    const result = await runInstallPhaseMacos({
      manager: 'pnpm',
      cwd: '/work',
      env: { PATH: '/usr/bin' },
      strace: runner,
      attribution: new Attribution(NULL_PROC_READER),
      emitter: new Emitter(new PassThrough()),
    });
    expect(result.tamperReason).toMatch(/unexpected LineSource/);
    expect(events).toHaveLength(0);
  });
});

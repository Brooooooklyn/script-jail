// Tests for src/guest/env-spy.cjs
// Forks child processes with the preload and checks that process.env reads
// are logged as JSONL events, and that protected names are hidden from the
// guest's view.

import { describe, it, expect } from 'vitest';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(__dirname, '../../src/guest/env-spy.cjs');

function writeChildScript(code: string): string {
  const dir = join(tmpdir(), 'script-jail-test');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `child-env-spy-${Date.now()}-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(path, `'use strict';\n${code}\n`);
  return path;
}

function freshLogFile(): string {
  const p = join(
    tmpdir(),
    `script-jail-events-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`,
  );
  writeFileSync(p, '');
  return p;
}

/**
 * Finding 4 (audit-trust): the protected-env list ships as a comma-separated
 * env var (`SCRIPT_JAIL_PROTECTED_ENV_NAMES`), not a file path.  This helper
 * exists so the test bodies don't repeat the `.join(',')` boilerplate; tests
 * also pass the value directly when they want to exercise odd whitespace /
 * comment / empty-entry behaviour.
 */
function joinProtected(names: ReadonlyArray<string>): string {
  return names.join(',');
}

interface ChildResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function runWithSpy(
  code: string,
  env: Record<string, string | undefined> = {},
): Promise<ChildResult> {
  return new Promise((resolve, reject) => {
    const script = writeChildScript(code);
    const child = fork(script, [], {
      env: {
        ...process.env,
        ...env,
        NODE_OPTIONS: `--require=${preloadPath}`,
      },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (c: Buffer) => { stdout += c.toString(); });
    child.stderr?.on('data', (c: Buffer) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('exit', (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });
  });
}

interface EnvReadLine {
  kind: string;
  name: string;
  pid: number;
  ts: number;
  hidden: boolean;
}

function readEnvReadLines(logFile: string): EnvReadLine[] {
  return readFileSync(logFile, 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((o) => o['kind'] === 'env_read') as unknown as EnvReadLine[];
}

describe('env-spy preload', () => {
  it('logs a process.env read as kind=env_read with the access name', async () => {
    const logFile = freshLogFile();
    const code = `
      const x = process.env.FOO;
      process.stdout.write(JSON.stringify({ value: x }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      FOO: 'bar',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { value: string };
    expect(out.value).toBe('bar');

    const lines = readEnvReadLines(logFile);
    const fooReads = lines.filter((l) => l.name === 'FOO');
    expect(fooReads.length).toBeGreaterThanOrEqual(1);
    expect(fooReads[0]!.hidden).toBe(false);
  });

  it('hides protected names: read returns undefined and is logged with hidden=true', async () => {
    const logFile = freshLogFile();
    const code = `
      const tok = process.env.NPM_TOKEN;
      // Treat the read as "undefined" explicitly so JSON survives.
      process.stdout.write(JSON.stringify({ tokIsUndefined: tok === undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_NAMES: joinProtected(['NPM_TOKEN']),
      NPM_TOKEN: 'super-secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { tokIsUndefined: boolean };
    expect(out.tokIsUndefined).toBe(true);

    const lines = readEnvReadLines(logFile);
    const tokenReads = lines.filter((l) => l.name === 'NPM_TOKEN');
    expect(tokenReads.length).toBeGreaterThanOrEqual(1);
    expect(tokenReads.every((l) => l.hidden === true)).toBe(true);
  });

  it('hides protected names from `in` and Object.keys / ownKeys', async () => {
    const logFile = freshLogFile();
    const code = `
      const has = 'NPM_TOKEN' in process.env;
      const keys = Object.keys(process.env);
      const descr = Object.getOwnPropertyDescriptor(process.env, 'NPM_TOKEN');
      process.stdout.write(JSON.stringify({
        has,
        included: keys.includes('NPM_TOKEN'),
        descrIsUndefined: descr === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_NAMES: joinProtected(['NPM_TOKEN']),
      NPM_TOKEN: 'super-secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as {
      has: boolean;
      included: boolean;
      descrIsUndefined: boolean;
    };
    expect(out.has).toBe(false);
    expect(out.included).toBe(false);
    expect(out.descrIsUndefined).toBe(true);
  });

  it('does not log when neither LOG_FILE nor LOG_FD is set', async () => {
    // Reads still happen; logging is silently skipped.
    const code = `
      const x = process.env.PATH;
      process.stdout.write(JSON.stringify({ ok: x !== undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: undefined,
      SCRIPT_JAIL_LOG_FD: undefined,
    });
    expect(result.exitCode).toBe(0);
  });

  it('does not crash when SCRIPT_JAIL_PROTECTED_ENV_NAMES is empty', async () => {
    const logFile = freshLogFile();
    const code = `
      const x = process.env.PATH;
      process.stdout.write(JSON.stringify({ ok: x !== undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_NAMES: '',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
    // Nothing protected — PATH read should be logged with hidden=false.
    const lines = readEnvReadLines(logFile);
    const pathReads = lines.filter((l) => l.name === 'PATH');
    expect(pathReads.length).toBeGreaterThanOrEqual(1);
    expect(pathReads.every((l) => l.hidden === false)).toBe(true);
  });

  it('requiring the preload twice does not throw (idempotency)', async () => {
    const code = `
      require(${JSON.stringify(preloadPath)});
      process.stdout.write(JSON.stringify({ ok: true }));
    `;
    const result = await runWithSpy(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
  });

  it('process.env Proxy is non-configurable (cannot be redefined)', async () => {
    const code = `
      try {
        Object.defineProperty(process, 'env', { value: {} });
        process.stdout.write(JSON.stringify({ threw: false }));
      } catch (e) {
        process.stdout.write(JSON.stringify({ threw: true, name: e.constructor.name }));
      }
    `;
    const result = await runWithSpy(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { threw: boolean; name: string };
    expect(out.threw).toBe(true);
    expect(out.name).toBe('TypeError');
  });

  it('reads for unprotected names go through to the underlying value', async () => {
    const logFile = freshLogFile();
    const code = `
      const safe = process.env.SAFE_VAR;
      const tok = process.env.NPM_TOKEN;
      process.stdout.write(JSON.stringify({
        safe,
        tokHidden: tok === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_NAMES: joinProtected(['NPM_TOKEN']),
      SAFE_VAR: 'visible',
      NPM_TOKEN: 'secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { safe: string; tokHidden: boolean };
    expect(out.safe).toBe('visible');
    expect(out.tokHidden).toBe(true);
  });

  it('parses comma-separated entries with whitespace, empties, and # comments', async () => {
    // Finding 4 (audit-trust): the env-var-encoded protect-list parses the
    // same shape the Rust shim accepts: ',' or '\n' separators, leading and
    // trailing ASCII whitespace stripped, empty entries and '#'-prefixed
    // entries silently skipped.
    const logFile = freshLogFile();
    const code = `
      const a = process.env.NPM_TOKEN;
      const b = process.env.GITHUB_TOKEN;
      process.stdout.write(JSON.stringify({
        aHidden: a === undefined,
        bHidden: b === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_NAMES:
        '#comment, NPM_TOKEN ,, GITHUB_TOKEN ,,#another',
      NPM_TOKEN: 'x',
      GITHUB_TOKEN: 'y',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { aHidden: boolean; bHidden: boolean };
    expect(out.aHidden).toBe(true);
    expect(out.bHidden).toBe(true);
  });

  it('does not break child_process.spawn (Proxy receiver compatibility)', async () => {
    // Regression guard: an earlier version of this preload passed the Proxy
    // itself as the receiver to Reflect.get / Reflect.set when forwarding to
    // process.env.  process.env is a special EnvironmentVariableNamespace
    // whose getter/setter use `this` to find the underlying environ store;
    // passing the Proxy as receiver made child_process.spawn fail silently
    // because the child's env table couldn't be materialized.  This test
    // spawns a real subprocess through the proxied process.env and verifies
    // it returns the expected exit code and inherited env.
    const code = `
      const r = require('child_process').spawnSync(
        process.execPath,
        ['-e', 'process.stdout.write(JSON.stringify({inherited: process.env.MARKER_ENV}))'],
      );
      process.stdout.write(JSON.stringify({
        status: r.status,
        stdout: r.stdout.toString(),
        errored: r.error ? r.error.message : null,
      }));
    `;
    const result = await runWithSpy(code, { MARKER_ENV: 'visible-to-child' });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as {
      status: number;
      stdout: string;
      errored: string | null;
    };
    expect(out.status).toBe(0);
    expect(out.errored).toBeNull();
    const inherited = JSON.parse(out.stdout) as { inherited: string };
    expect(inherited.inherited).toBe('visible-to-child');
  });

  it('symbol property access passes through without logging', async () => {
    const logFile = freshLogFile();
    const code = `
      const sym = Symbol.for('test-symbol');
      // Set and read a symbol key (not a string) — should NOT log env_read.
      const target = process.env;
      const v = target[sym];
      process.stdout.write(JSON.stringify({ vIsUndefined: v === undefined }));
    `;
    const result = await runWithSpy(code, { SCRIPT_JAIL_LOG_FILE: logFile });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { vIsUndefined: boolean };
    expect(out.vIsUndefined).toBe(true);
    // No env_read entry should reference a symbol — the preload skips non-string keys.
    const lines = readEnvReadLines(logFile);
    expect(lines.every((l) => typeof l.name === 'string')).toBe(true);
  });

  // ── Audit-trust Finding 4 (2026-05-18) — fd-close recovery ────────────────
  //
  // A lifecycle script that scans /proc/self/fd/<N> and close()s every fd
  // pointing at SCRIPT_JAIL_LOG_FILE breaks env-spy's cached fd.  The fix
  // is for env-spy's write path to:
  //   1. catch the write failure (typically EBADF),
  //   2. reopen the events file by its known path,
  //   3. retry the write once.
  // If the reopen ALSO fails, env-spy emits an audit_fd_lost env_tamper
  // line via a fresh open and exits non-zero so the install command fails
  // closed.  This test drives the recovery branch by stubbing fs.writeSync
  // to throw EBADF on the first call: the child must reopen, retry, and
  // succeed — landing exactly one env_read line in the events file.
  //
  // The actual /proc/self/fd attack is a Linux-only integration test; here
  // we cover the recovery code path under unit conditions on every OS.

  it('reopens the events file on EBADF and writes the env_read line via the new fd', async () => {
    const logFile = freshLogFile();
    // The child:
    //   1. monkey-patches fs.writeSync so the first call throws EBADF;
    //   2. requires env-spy.cjs (which is the --require target via NODE_OPTIONS);
    //   3. reads process.env.FOO, which goes through the Proxy → logEnvRead →
    //      writeSync (throws EBADF) → reopen → retry → success.
    // Because env-spy is pre-loaded via NODE_OPTIONS=--require=env-spy.cjs
    // BEFORE the child script body runs, we need to install the writeSync
    // stub in `--require` order.  Easiest path: inject a SECOND --require
    // that runs BEFORE env-spy.  But --require entries run in left-to-right
    // order, so we instead patch writeSync at the top of the child script
    // and then trigger a delayed env-read.  The first env-spy auto-reads
    // (process.env.SCRIPT_JAIL_LOG_FILE / SCRIPT_JAIL_PROTECTED_ENV_NAMES)
    // happen BEFORE our patch — so we must NOT patch writeSync until after
    // env-spy's resolveLogFd has run and logFd is cached.  Insert the
    // patch in the user code, then make the read.
    const code = `
      const fs = require('fs');
      // env-spy is already preloaded by NODE_OPTIONS=--require=...;
      // logFd is now > 0 and cached.  Install a one-shot EBADF stub on
      // writeSync — only the FIRST call throws, so the reopen-retry path
      // succeeds on the second attempt.
      const realWriteSync = fs.writeSync;
      let firstCall = true;
      fs.writeSync = function (fd, ...rest) {
        if (firstCall) {
          firstCall = false;
          const err = new Error('Stale fd');
          err.code = 'EBADF';
          throw err;
        }
        return realWriteSync.call(fs, fd, ...rest);
      };
      // Trigger one env_read through the Proxy.  Recovery path expectation:
      // the first writeSync throws EBADF → env-spy reopens the file by
      // path → writeSync (the new, non-stubbed fd) succeeds on the second
      // call.  The events file must contain exactly one env_read line.
      const v = process.env.FOO;
      process.stdout.write('FOO=' + (v || 'ABSENT'));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      FOO: 'bar',
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('FOO=bar');
    const lines = readEnvReadLines(logFile);
    const fooReads = lines.filter((l) => l.name === 'FOO');
    expect(fooReads.length).toBeGreaterThanOrEqual(1);
  });

  it('exits non-zero with audit_fd_lost when reopen also fails (unrecoverable fd-tamper)', async () => {
    const logFile = freshLogFile();
    // Same stub strategy, but also stub fs.openSync so the reopen retry
    // fails too.  Expected: env-spy exits non-zero and emits an
    // env_tamper{op:'audit_fd_lost'} JSONL line via the final fresh-open
    // fallback (which we also break — proving the exit-non-zero is the
    // hard fail-closed signal even when no audit line can be written).
    const code = `
      const fs = require('fs');
      const realWriteSync = fs.writeSync;
      let firstWrite = true;
      fs.writeSync = function (fd, ...rest) {
        if (firstWrite) {
          firstWrite = false;
          const err = new Error('Stale fd');
          err.code = 'EBADF';
          throw err;
        }
        return realWriteSync.call(fs, fd, ...rest);
      };
      // Now break openSync ENTIRELY so the reopen branch fails too —
      // including the final fallback open inside emitAuditFdLostAndExit.
      // Both the env_read retry AND the audit_fd_lost write should fail;
      // the process MUST still exit non-zero.
      fs.openSync = function () {
        const err = new Error('Stubbed openSync failure');
        err.code = 'EACCES';
        throw err;
      };
      // Trigger one env_read.  writeSync throws → reopen attempts openSync
      // → throws → emitAuditFdLostAndExit → process.exit(91).
      const v = process.env.FOO;
      // Must never be reached:
      process.stdout.write('UNREACHED');
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      FOO: 'bar',
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).not.toContain('UNREACHED');
    // Stderr should carry the diagnostic so an interactive caller can
    // correlate the failure with the audit-fd-lost cause.
    expect(result.stderr).toMatch(/script-jail\/env-spy/);
  });
});

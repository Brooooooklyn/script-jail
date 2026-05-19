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
    // Audit-trust Finding 4 (high, 2026-05-18): the preload captures fs
    // function references at module load time, so monkeypatching
    // `fs.writeSync` no longer reaches the preload's writes.  To exercise
    // the EBADF recovery path we therefore have to invalidate the
    // underlying fd directly — by closing every fd in /proc/self/fd that
    // points at the events file.  That's the actual production threat
    // (a lifecycle script scanning /proc/self/fd/ and calling
    // `close(n)` on descriptors it doesn't own).
    //
    // Linux-only: /proc/self/fd is not present on macOS, so we skip this
    // test on Darwin.  CI runs Linux for the guest test suite.
    if (process.platform !== 'linux') return;
    const code = `
      const fs = require('node:fs');
      // Find any fd in /proc/self/fd whose readlink resolves to the
      // events file path and close it via the host fd table.  Calling
      // closeSync(n) on someone else's fd is the same primitive a
      // hostile lifecycle script would use — the kernel doesn't track
      // ownership at this layer.
      //
      // IMPORTANT (fd-slot reuse race): on Linux, close(fd) frees the
      // fd-table slot, and the kernel's next open(2) returns the LOWEST
      // free fd — which is exactly the slot we just freed.  env-spy's
      // recovery path then races itself: it opens a new fd (gets the
      // recycled slot N), then close()s the "stale" cached logFd (still
      // numerically N) — which closes the JUST-OPENED new fd.  The
      // immediately-following writeSync(N) then fails with EBADF a
      // SECOND time, env-spy hits emitAuditFdLostAndExit, and the
      // process exits 91.
      //
      // To exercise the recovery path WITHOUT triggering that production
      // race, occupy the freed slot ourselves with a read-only /dev/null
      // descriptor right after the close.  Two effects:
      //   1. writeSync on the cached logFd still EBADFs (the new
      //      occupant is RDONLY → write fails the same way).
      //   2. env-spy's recovery openSync allocates the NEXT-lowest free
      //      slot (a different fd number), so its subsequent
      //      closeSync(<old logFd>) closes our /dev/null placeholder
      //      instead of the freshly-opened logFile fd.
      const logFile = ${JSON.stringify(logFile)};
      try {
        const fds = fs.readdirSync('/proc/self/fd');
        for (const name of fds) {
          const fd = Number(name);
          if (!Number.isInteger(fd)) continue;
          let target;
          try { target = fs.readlinkSync('/proc/self/fd/' + name); } catch { continue; }
          if (target === logFile) {
            try { fs.closeSync(fd); } catch { /* ignored */ }
            // Re-occupy the freed slot with a RDONLY decoy so env-spy's
            // recovery openSync lands on a different fd number.  The
            // RDONLY mode preserves the EBADF behaviour on writeSync —
            // a write to a read-only fd fails with EBADF on Linux.
            try { fs.openSync('/dev/null', 'r'); } catch { /* ignored */ }
          }
        }
      } catch { /* ignored */ }
      // Trigger one env_read through the Proxy.  Recovery path:
      // writeSync on the stale fd throws EBADF → env-spy reopens the
      // file by path → writeSync (the new fd) succeeds.
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
    // Audit-trust Finding 4: monkeypatching fs.openSync no longer affects
    // the preload (it captured _openSync at module load).  To force a
    // reopen failure we make the events-file PATH itself fail to open by
    // pointing at a directory that we then chmod 0 underneath the
    // running child.  Linux-specific, and racy in principle — but the
    // child closes the cached fd FIRST (driving the EBADF) and the
    // chmod is applied before that close so the reopen sees the broken
    // permissions deterministically.
    if (process.platform !== 'linux') return;
    const logFile = freshLogFile();
    const code = `
      const fs = require('node:fs');
      const logFile = ${JSON.stringify(logFile)};
      // Break the path so reopen fails: rename the file, which means the
      // path no longer resolves.  EACCES on a missing parent dir is more
      // robust than the chmod approach.
      const brokenDir = logFile + '.dir';
      try {
        // Move the file out of the way, then put a path-eating dir in
        // its place with no read permissions.  openSync('a') will fail
        // with EACCES.
        fs.renameSync(logFile, logFile + '.moved');
        fs.mkdirSync(brokenDir, { mode: 0o000 });
        fs.renameSync(brokenDir, logFile);
      } catch { /* ignored */ }
      // Now close every fd that points at the moved file so the cached
      // fd in env-spy goes stale and the next writeSync throws EBADF.
      try {
        const fds = fs.readdirSync('/proc/self/fd');
        for (const name of fds) {
          const fd = Number(name);
          if (!Number.isInteger(fd)) continue;
          let target;
          try { target = fs.readlinkSync('/proc/self/fd/' + name); } catch { continue; }
          if (target === logFile + '.moved' || target === logFile + '.moved (deleted)') {
            try { fs.closeSync(fd); } catch { /* ignored */ }
          }
        }
      } catch { /* ignored */ }
      // Trigger one env_read.  writeSync throws EBADF → reopen attempts
      // openSync(logFile) → fails → emitAuditFdLostAndExit → exit(91).
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

  // Audit-trust Finding 4 (high, 2026-05-18) — monkeypatch resistance.
  //
  // Lifecycle JS that runs INSIDE the audited process can (before
  // triggering a sensitive env read) overwrite `fs.writeSync` /
  // `fs.openSync` / `process.exit` to neutralise the audit chain.  The
  // preload captures these references at module load time (before any
  // user code runs), so the monkeypatch only affects the public slots,
  // not the captured references.  These tests pin that contract.
  describe('Finding 4 — monkeypatch resistance', () => {
    it('monkeypatched fs.writeSync after preload load does NOT silence env_read audit', async () => {
      const logFile = freshLogFile();
      const code = `
        const fs = require('node:fs');
        // Monkeypatch AFTER the preload has loaded (the preload runs as
        // --require BEFORE the child body).  If the preload were
        // reading fs.writeSync through the mutable slot on every call,
        // this stub would suppress every env_read line.
        fs.writeSync = function () { /* silent black hole */ };
        // Also monkeypatch process.exit so a fail-closed exit can't
        // accidentally hide the bug.
        process.exit = function () { /* swallow */ };
        const v = process.env.NPM_TOKEN;
        process.stdout.write('TOKEN=' + (v === undefined ? 'HIDDEN' : 'LEAKED'));
      `;
      const result = await runWithSpy(code, {
        SCRIPT_JAIL_LOG_FILE: logFile,
        SCRIPT_JAIL_PROTECTED_ENV_NAMES: 'NPM_TOKEN',
        NPM_TOKEN: 'super-secret',
      });
      expect(result.exitCode).toBe(0);
      // Value must be hidden (protected list still enforced).
      expect(result.stdout).toContain('TOKEN=HIDDEN');
      // The audit line must exist despite the monkeypatched writeSync.
      const lines = readEnvReadLines(logFile);
      const tokenReads = lines.filter((l) => l.name === 'NPM_TOKEN');
      expect(tokenReads.length).toBeGreaterThanOrEqual(1);
      expect(tokenReads[0]!.hidden).toBe(true);
    });

    it('monkeypatched process.exit does NOT prevent fail-closed exit on unrecoverable audit-fd loss', async () => {
      // Combine the unrecoverable-fd-tamper attack with a process.exit
      // override.  The preload captured `_processExit` at load time, so
      // the user's override only affects the public slot and the exit
      // still fires.
      if (process.platform !== 'linux') return;
      const logFile = freshLogFile();
      const code = `
        const fs = require('node:fs');
        // Monkeypatch process.exit BEFORE triggering the audit-loss
        // event.  The captured _processExit reference must still fire.
        process.exit = function () { /* swallow */ };
        const logFile = ${JSON.stringify(logFile)};
        try {
          fs.renameSync(logFile, logFile + '.moved');
          fs.mkdirSync(logFile, { mode: 0o000 });
        } catch { /* ignored */ }
        try {
          const fds = fs.readdirSync('/proc/self/fd');
          for (const name of fds) {
            const fd = Number(name);
            if (!Number.isInteger(fd)) continue;
            let target;
            try { target = fs.readlinkSync('/proc/self/fd/' + name); } catch { continue; }
            if (target === logFile + '.moved' || target === logFile + '.moved (deleted)') {
              try { fs.closeSync(fd); } catch { /* ignored */ }
            }
          }
        } catch { /* ignored */ }
        const v = process.env.FOO;
        process.stdout.write('UNREACHED');
      `;
      const result = await runWithSpy(code, {
        SCRIPT_JAIL_LOG_FILE: logFile,
        FOO: 'bar',
      });
      // Must exit non-zero despite the monkeypatched process.exit.
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).not.toContain('UNREACHED');
    });

    // Audit-trust Finding 5 (high, 2026-05-19) — env-mutation redirect.
    //
    // Companion test to the same finding in dlopen-block.cjs.  env-spy has
    // captured `logFilePath` at module load since commit b56b9975 (Finding
    // 4); this test pins that contract so any future regression that re-
    // reads `process.env.SCRIPT_JAIL_LOG_FILE` in `logEnvRead` is caught.
    it('mutating process.env.SCRIPT_JAIL_LOG_FILE after preload does NOT redirect env_read audit', async () => {
      const realLog = freshLogFile();
      const decoy = freshLogFile();
      const code = `
        // Redirect (or delete) SCRIPT_JAIL_LOG_FILE BEFORE triggering an
        // env read.  The audit line must still land in the original path
        // captured at preload load time.
        process.env.SCRIPT_JAIL_LOG_FILE = ${JSON.stringify(decoy)};
        delete process.env.SCRIPT_JAIL_LOG_FD;
        const v = process.env.NPM_TOKEN;
        process.stdout.write('TOKEN=' + (v === undefined ? 'HIDDEN' : 'LEAKED'));
      `;
      const result = await runWithSpy(code, {
        SCRIPT_JAIL_LOG_FILE: realLog,
        SCRIPT_JAIL_PROTECTED_ENV_NAMES: 'NPM_TOKEN',
        NPM_TOKEN: 'super-secret',
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('TOKEN=HIDDEN');

      const realReads = readEnvReadLines(realLog).filter((l) => l.name === 'NPM_TOKEN');
      const decoyReads = readEnvReadLines(decoy).filter((l) => l.name === 'NPM_TOKEN');
      expect(realReads.length).toBeGreaterThanOrEqual(1);
      expect(realReads[0]!.hidden).toBe(true);
      expect(decoyReads.length).toBe(0);
    });
  });
});

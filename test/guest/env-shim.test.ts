// Tests for src/shim/src/lib.rs
// Uses vitest project: "guest" (see vitest.config.ts)
//
// Skipped entirely on non-Linux: LD_PRELOAD semantics differ significantly on
// macOS (DYLD_INSERT_LIBRARIES + SIP restrictions) and are not supported here.

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, unlinkSync, existsSync, statSync, rmSync, readFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const isLinux = process.platform === 'linux';

// Paths relative to the repo root (resolved from __dirname = test/guest/).
// __dirname is undefined in ESM; use import.meta.url instead.
const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const shimSo        = join(repoRoot, 'images/libscriptjail.so');
const cargoManifest = join(repoRoot, 'src/shim/Cargo.toml');
const libRs         = join(repoRoot, 'src/shim/src/lib.rs');

// Temp files created during tests; cleaned up in afterEach.
const tempFiles: string[] = [];

function makeTempFile(content: string, suffix = ''): string {
  const dir  = mkdtempSync(join(tmpdir(), 'script-jail-shim-'));
  const path = join(dir, `tmp${suffix}`);
  writeFileSync(path, content, 'utf8');
  tempFiles.push(path);
  tempFiles.push(dir); // mark dir for cleanup too
  return path;
}

afterEach(() => {
  for (const p of tempFiles) {
    try {
      if (existsSync(p)) {
        const stat = statSync(p);
        if (stat.isDirectory()) rmSync(p, { recursive: true, force: true });
        else unlinkSync(p);
      }
    } catch { /* ignore */ }
  }
  tempFiles.length = 0;
});

// ── Build helper ─────────────────────────────────────────────────────────────

/**
 * Returns true if the .so is up-to-date (exists and newer than the Rust crate
 * manifest and the library source file).
 */
function soIsUpToDate(): boolean {
  if (!existsSync(shimSo) || !existsSync(cargoManifest) || !existsSync(libRs)) return false;
  const soMtime    = statSync(shimSo).mtimeMs;
  const cargoMtime = statSync(cargoManifest).mtimeMs;
  const libMtime   = statSync(libRs).mtimeMs;
  return soMtime >= cargoMtime && soMtime >= libMtime;
}

// ── Suite ─────────────────────────────────────────────────────────────────────

describe.skipIf(!isLinux)('env-shim LD_PRELOAD', () => {

  // shimAvailable tracks whether the .so was successfully built/found.
  // Tests skip dynamically (via ctx.skip()) when the shim is unavailable,
  // producing a visible SKIP in the test report rather than a vacuous pass.
  let shimAvailable = false;

  // ── beforeAll: compile .so if stale ─────────────────────────────────────
  //
  // On Linux we treat a build failure as a hard error so that CI cannot go
  // green without actually exercising the shim.  Only an unavailable Rust
  // toolchain is treated as a skip condition.

  beforeAll(() => {
    // Check that the Rust toolchain (cargo) is available.
    const cargo = spawnSync('cargo', ['--version'], { encoding: 'utf8' });
    if (cargo.status !== 0 || cargo.error) {
      // No cargo — leave shimAvailable = false so all tests are skipped.
      return;
    }

    if (soIsUpToDate()) {
      shimAvailable = true;
      return;
    }

    const result = spawnSync(
      'cargo',
      ['build', '--release', '--manifest-path', cargoManifest],
      { encoding: 'utf8', cwd: repoRoot },
    );

    if (result.status !== 0) {
      throw new Error(`cargo build failed:\n${result.stderr}\n${result.stdout}`);
    }

    // Stage the freshly built cdylib into images/ so the rest of the suite
    // (and any downstream consumer of images/libscriptjail.so) finds it at
    // the canonical path.
    mkdirSync(join(repoRoot, 'images'), { recursive: true });
    copyFileSync(
      join(repoRoot, 'src/shim/target/release/libscriptjail.so'),
      shimSo,
    );

    shimAvailable = true;

    // Sanity-check: the wrapper symbols must be visible in .dynsym so that
    // ld-linux.so can intercept them via LD_PRELOAD.  readelf is optional
    // (skip if absent rather than failing).
    const readelf = spawnSync('readelf', ['-Ws', '--dyn-syms', shimSo], { encoding: 'utf8' });
    if (readelf.status === 0 && !readelf.error) {
      const requiredSymbols = [
        'getenv',
        'secure_getenv',
        'execve',
        'execv',
        'execvp',
        'execvpe',
        'execveat',
        'fexecve',
        'posix_spawn',
        'posix_spawnp',
        'setenv',
        'unsetenv',
        'putenv',
        'clearenv',
      ];
      const missing = requiredSymbols.filter((sym) => !new RegExp(`\\b${sym}\\b`).test(readelf.stdout));
      if (missing.length > 0) {
        throw new Error(
          `libscriptjail.so is missing dynamic symbols: ${missing.join(', ')} — check the \`#[no_mangle] pub extern "C"\` exports and the Rust cdylib default-hidden-visibility behavior`,
        );
      }
    }
    // readelf unavailable: skip the assertion (don't fail)
  });

  // ── helper: run a command with the shim preloaded ────────────────────────

  interface ShimResult {
    exitCode:  number | null;
    logLines:  string[];  // JSONL lines captured from log fd
    stdout:    string;    // combined stdout of the spawned process
  }

  /**
   * Spawns `cmd` (via `/bin/sh -c`) with:
   *  - LD_PRELOAD=shimSo
   *  - SCRIPT_JAIL_LOG_FD=3
   *  - any additional `env` entries merged in
   *
   * FD 3 is captured via a temporary file (spawnSync can't redirect arbitrary fds,
   * so we wrap the invocation in an sh one-liner that opens the file on fd 3).
   */
  function runWithShim(opts: {
    cmd:         string;
    env?:        Record<string, string>;
    /**
     * Finding 4 (audit-trust): the protected-env list now ships inline as a
     * comma-separated env var (`SCRIPT_JAIL_PROTECTED_ENV_NAMES`) — no more
     * `/tmp/script-jail-protected.txt`.  Tests pass `protectNames` as a list
     * of bare env-var names; the helper joins them with ',' and forwards to
     * the shim through the new env var.  The legacy `protectFile` option
     * is intentionally absent: there is no longer a file path to point at.
     */
    protectNames?: ReadonlyArray<string>;
  }): ShimResult {
    const logFile = makeTempFile('', '.jsonl');

    const extraEnv: Record<string, string> = {
      LD_PRELOAD:       shimSo,
      SCRIPT_JAIL_LOG_FD:   '3',
      ...opts.env,
    };
    if (opts.protectNames !== undefined) {
      extraEnv['SCRIPT_JAIL_PROTECTED_ENV_NAMES'] = opts.protectNames.join(',');
    }

    // Build env string for sh: "KEY=VAL KEY2=VAL2 ..."
    // We pass env via process env to avoid shell-quoting issues.
    const fullEnv: Record<string, string> = {
      // minimal base env so programs work
      PATH: process.env['PATH'] ?? '/usr/bin:/bin',
      HOME: process.env['HOME'] ?? '/root',
      ...extraEnv,
    };

    // Wrap command so that fd 3 is redirected to the log file.
    const wrapped = `exec 3>>"${logFile}"; ${opts.cmd}`;

    const result = spawnSync('/bin/sh', ['-c', wrapped], {
      env: fullEnv,
      encoding: 'utf8',
      timeout: 10_000,
    });

    // Parse JSONL log.
    const logContent = existsSync(logFile) ? readFileSync(logFile, 'utf8') : '';
    const logLines = logContent
      .split('\n')
      .filter((l: string) => l.trim().length > 0);

    return {
      exitCode: result.status,
      logLines,
      stdout: result.stdout ?? '',
    };
  }

  // ── Test 1: getenv calls are logged to FD 3 ──────────────────────────────

  it('getenv calls are logged as env_read JSONL lines', (ctx) => {
    if (!shimAvailable) ctx.skip(); // cc was unavailable; skip visibly

    // Use `node -e` rather than env(1)/printenv(1): modern GNU coreutils
    // iterate `environ[]` directly and never call libc getenv, so they
    // bypass the LD_PRELOAD shim. Node's libuv invokes getenv on startup
    // and for every process.env.<X> access — guaranteed shim coverage.
    const res = runWithShim({ cmd: `node -e 'void process.env.PATH'` });

    // Assert at least one valid JSONL line was emitted.
    expect(res.logLines.length).toBeGreaterThan(0);

    const first = res.logLines[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      const parsed = JSON.parse(first) as Record<string, unknown>;
      expect(parsed['kind']).toBe('env_read');
      expect(typeof parsed['name']).toBe('string');
      expect(typeof parsed['pid']).toBe('number');
      expect(typeof parsed['ts']).toBe('number');
      expect(typeof parsed['hidden']).toBe('boolean');
    }
  });

  it('a known env var (PATH) appears in log', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // printenv(1) iterates environ[] directly on modern Ubuntu and so
    // bypasses the LD_PRELOAD shim; route through Node, whose libuv goes
    // through libc getenv.
    const res = runWithShim({ cmd: `node -e 'void process.env.PATH'` });

    const pathLines = res.logLines.filter((l: string) => {
      try {
        const obj = JSON.parse(l) as Record<string, unknown>;
        return obj['name'] === 'PATH';
      } catch { return false; }
    });
    expect(pathLines.length).toBeGreaterThan(0);

    // Also verify the hidden field is false for PATH (not protected).
    const parsed = JSON.parse(pathLines[0]!) as Record<string, unknown>;
    expect(parsed['hidden']).toBe(false);
  });

  // ── Test 2: protected names return NULL ──────────────────────────────────

  it('protected env var is hidden and logged with hidden:true', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // node: exit 0 if NPM_TOKEN is undefined, exit 1 if it is defined.
    const res = runWithShim({
      cmd: `node -e 'process.exit(process.env.NPM_TOKEN === undefined ? 0 : 1)'`,
      env: { NPM_TOKEN: 'super-secret' },
      protectNames: ['NPM_TOKEN'],
    });

    // The node process should see NPM_TOKEN as undefined (getenv returns NULL).
    expect(res.exitCode).toBe(0);

    // And the log should record it as hidden.
    const hiddenLines = res.logLines.filter((l: string) => {
      try {
        const obj = JSON.parse(l) as Record<string, unknown>;
        return obj['name'] === 'NPM_TOKEN' && obj['hidden'] === true;
      } catch { return false; }
    });
    expect(hiddenLines.length).toBeGreaterThan(0);
  });

  // ── Test 3: JSON escape correctness (v2 follow-up for special chars) ──────

  // TODO(v2): Test that names containing `"`, `\`, and control characters are
  // properly JSON-escaped in the JSONL output.  This requires invoking getenv()
  // directly from a small compiled C program (to pass such a name), which is
  // too costly for the v1 test suite.  The escaping logic in src/shim/src/lib.rs
  // is unit-testable in isolation.

  // ── Test 4: comma-separated protect-list with whitespace/empty entries ───
  //
  // Finding 4 (audit-trust): the protect-list now arrives as a comma-
  // separated env var.  Defensive parser behaviour we want to keep working:
  //   * leading / trailing ASCII whitespace per entry is stripped
  //   * empty entries are silently ignored
  //   * entries starting with '#' are skipped (allows future templating)
  // This test exercises all three at once.
  it('protect-list parses comma-separated names with whitespace + empty entries', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // Both NPM_TOKEN and GITHUB_TOKEN should be hidden.
    // node exits 0 iff both are undefined.
    const script = [
      'const hidden = process.env.NPM_TOKEN === undefined && process.env.GITHUB_TOKEN === undefined;',
      'process.exit(hidden ? 0 : 1);',
    ].join(' ');

    const res = runWithShim({
      cmd: `node -e '${script}'`,
      env: {
        NPM_TOKEN:    'secret1',
        GITHUB_TOKEN: 'secret2',
      },
      // Mix in:
      //   - leading + trailing space around entries (stripped)
      //   - empty entries from doubled commas (skipped)
      //   - a leading-'#' entry (skipped)
      protectNames: ['NPM_TOKEN', '', '  GITHUB_TOKEN  ', '#comment'],
    });

    expect(res.exitCode).toBe(0);

    // Verify both appear in log as hidden.
    const names = new Set<string>();
    for (const l of res.logLines) {
      try {
        const obj = JSON.parse(l) as Record<string, unknown>;
        if (obj['hidden'] === true && typeof obj['name'] === 'string')
          names.add(obj['name'] as string);
      } catch { /* ignore */ }
    }
    expect(names.has('NPM_TOKEN')).toBe(true);
    expect(names.has('GITHUB_TOKEN')).toBe(true);
  });

  // ── Test 5: unprotected env var still visible ─────────────────────────────

  it('non-protected env var value is passed through unchanged', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // MY_VAR is not in the protect list — it should be visible.
    const res = runWithShim({
      cmd: `node -e 'process.exit(process.env.MY_VAR === "hello" ? 0 : 1)'`,
      env: {
        MY_VAR:     'hello',
        HIDDEN_VAR: 'secret',
      },
      protectNames: ['HIDDEN_VAR'],
    });

    expect(res.exitCode).toBe(0);
  });

  // ── Test 6: shim is silent when SCRIPT_JAIL_LOG_FD is unset ──────────────────

  it('shim does not crash when SCRIPT_JAIL_LOG_FD is unset', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // Run without SCRIPT_JAIL_LOG_FD; the shim should be silent (no log output)
    // and not crash the child process.
    const result = spawnSync('/bin/sh', ['-c', 'printenv PATH'], {
      env: {
        PATH:       process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // SCRIPT_JAIL_LOG_FD intentionally omitted
      },
      encoding: 'utf8',
      timeout: 5_000,
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe(''); // shim must not write to stderr
  });

  // ── Test 7: LD_PRELOAD re-injection on cleared envp ───────────────────────

  it('LD_PRELOAD is re-injected when child is spawned with a cleared envp', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // Outer process has LD_PRELOAD set.  The Node script spawns a child with
    // env: { PATH } only.  The shim's posix_spawn wrapper should re-inject the
    // canonical LD_PRELOAD value back into the child's envp so the child also
    // runs under audit.  We verify two things:
    //   1. The child's stdout contains the shim path (not "MISSING").
    //   2. The audit log contains at least one exec event from posix_spawn.
    const res = runWithShim({
      cmd: `node -e 'const cp = require("node:child_process");
                     const r = cp.spawnSync("node",
                       ["-e", "process.stdout.write(process.env.LD_PRELOAD || \\"MISSING\\")"],
                       { env: { PATH: process.env.PATH || "/usr/bin:/bin" } });
                     process.stdout.write(r.stdout.toString());'`,
      env: {
        SCRIPT_JAIL_PRELOAD_PATH: shimSo, // canonical preload path the shim re-injects
      },
    });

    // The child's stdout should contain the shim path (i.e. not "MISSING").
    expect(res.stdout).toContain(shimSo);

    // The audit log should also contain at least one exec event from posix_spawn.
    const execEvents = res.logLines.filter((l) => {
      try { return (JSON.parse(l) as Record<string, unknown>)['kind'] === 'exec'; }
      catch { return false; }
    });
    expect(execEvents.length).toBeGreaterThan(0);
  });

  // ── Test 8: setenv on protected name is refused + audited ─────────────────

  it('setenv("LD_PRELOAD", "evil") is refused and audited', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // Node's `process.env.X = value` assignment compiles to a libc setenv()
    // call, so we can exercise the shim's setenv guard directly from Node.
    const res = runWithShim({
      cmd: `node -e 'process.env.LD_PRELOAD = "/evil/path";
                     console.log("LDP=" + process.env.LD_PRELOAD);'`,
    });

    // Audit event for the refused setenv.
    const tamperEvents = res.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> => e !== null && e['kind'] === 'env_tamper');

    // At least one tamper event for LD_PRELOAD.
    const ldpTamper = tamperEvents.filter((e) => e['name'] === 'LD_PRELOAD');
    expect(ldpTamper.length).toBeGreaterThan(0);

    // op should be setenv (Node's `process.env.X = ...` uses setenv).
    expect(ldpTamper[0]?.['op']).toBe('setenv');
    expect(ldpTamper[0]?.['refused']).toBe(true);
  });

  // ── Test 9: unsetenv on protected name is refused + audited ──────────────

  it('delete process.env.LD_PRELOAD (unsetenv) is refused and audited', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const res = runWithShim({
      cmd: `node -e 'delete process.env.LD_PRELOAD;
                     console.log("LDP=" + (process.env.LD_PRELOAD || "GONE"));'`,
    });

    const tamperEvents = res.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> =>
        e !== null && e['kind'] === 'env_tamper' && e['op'] === 'unsetenv' && e['name'] === 'LD_PRELOAD',
      );

    expect(tamperEvents.length).toBeGreaterThan(0);
    expect(tamperEvents[0]?.['refused']).toBe(true);
  });

  // ── Test 10: non-protected setenv is forwarded normally ───────────────────

  it('setenv on a non-protected name is forwarded without an env_tamper event', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const res = runWithShim({
      cmd: `node -e 'process.env.MY_HARMLESS_VAR = "hello";
                     console.log("V=" + process.env.MY_HARMLESS_VAR);'`,
    });

    // No env_tamper event for MY_HARMLESS_VAR.
    const tamperEvents = res.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> =>
        e !== null && e['kind'] === 'env_tamper' && e['name'] === 'MY_HARMLESS_VAR',
      );

    expect(tamperEvents.length).toBe(0);
  });

  // ── Test 11 (Finding A): caller-supplied sticky var is REMOVED when canon empty ─
  //
  // The parent runs the shim with SCRIPT_JAIL_LOG_FD only.  No
  // SCRIPT_JAIL_LOG_FILE is set, so the canonical snapshot for that var is
  // empty.  A Node script then spawns a child whose envp explicitly
  // contains `SCRIPT_JAIL_LOG_FILE=/tmp/evil` — an attacker poison
  // attempt.  The rewrite_envp loop MUST delete the caller's entry rather
  // than skip; otherwise the child shim would honor /tmp/evil and the
  // audit log would be redirected.
  //
  // We verify by inspecting the child's actual env (printed via
  // node -e 'process.stdout.write(process.env.SCRIPT_JAIL_LOG_FILE || "ABSENT")').
  it('caller-supplied SCRIPT_JAIL_LOG_FILE is removed when canon is empty (Finding A)', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const res = runWithShim({
      cmd: `node -e 'const cp = require("node:child_process");
                     const r = cp.spawnSync("node",
                       ["-e", "process.stdout.write(process.env.SCRIPT_JAIL_LOG_FILE || \\"ABSENT\\")"],
                       { env: { PATH: process.env.PATH || "/usr/bin:/bin",
                                SCRIPT_JAIL_LOG_FILE: "/tmp/evil" } });
                     process.stdout.write(r.stdout.toString());'`,
      // Deliberately do NOT set SCRIPT_JAIL_LOG_FILE here — parent's
      // canon will be empty for that sticky var.  SCRIPT_JAIL_LOG_FD is
      // injected by runWithShim itself.
    });

    // The child must report ABSENT — the attacker entry was stripped.
    // If the bug were present, the child would print "/tmp/evil".
    expect(res.stdout).toContain('ABSENT');
    expect(res.stdout).not.toContain('/tmp/evil');
  });

  // ── Test 12 (Finding C): putenv tamper emits bare NAME, not NAME=VALUE ────
  //
  // The Node-side `process.env.X = "value"` path uses setenv() and is
  // already covered by Test 8.  putenv() is harder to invoke from Node, so
  // we drive it via a small C compile via `cc -x c -`.  If `cc` is not
  // available, skip — the test is informational on Linux runners that
  // lack a C toolchain.
  it('putenv("NODE_OPTIONS=<long value>") emits env_tamper with name="NODE_OPTIONS" (Finding C)', (ctx) => {
    if (!shimAvailable) ctx.skip();

    // Probe for cc.
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    // Build a tiny binary that calls putenv() then exits.  The string is
    // intentionally long + contains a recognizable secret-shape so we can
    // assert it does NOT appear in the audit event's name field.
    const dir = mkdtempSync(join(tmpdir(), 'script-jail-putenv-'));
    tempFiles.push(dir);
    const bin = join(dir, 'putenv_attack');
    const src = `
      #include <stdlib.h>
      int main(void) {
        /* The argument MUST be retained for putenv's lifetime — use a
           static buffer.  Glibc keeps a pointer into this string. */
        static char poison[] =
          "NODE_OPTIONS=--require=/tmp/evil.js SECRET_LEAK_abcdef_NOT_IN_LOG";
        putenv(poison);
        return 0;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) {
      // Compiler errored — treat as environment-skip, not a test failure.
      ctx.skip();
    }

    const res = runWithShim({ cmd: bin });

    const putenvEvents = res.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> =>
        e !== null && e['kind'] === 'env_tamper' && e['op'] === 'putenv',
      );

    expect(putenvEvents.length).toBeGreaterThan(0);
    // Name must be the bare protected identifier.
    expect(putenvEvents[0]?.['name']).toBe('NODE_OPTIONS');
    // Critically: the attacker-controlled VALUE must NOT leak into the
    // event payload.
    for (const ev of putenvEvents) {
      const name = ev['name'];
      if (typeof name === 'string') {
        expect(name).not.toContain('SECRET_LEAK');
        expect(name).not.toContain('=');
      }
    }
    // And the full log line must also not carry the secret as the name field.
    for (const l of res.logLines) {
      // Allow the secret to appear elsewhere (it shouldn't anywhere, but
      // pin the audited claim: the *name* field is not the full string).
      // A simpler guarantee: the full poison string is not present.
      expect(l).not.toContain('SECRET_LEAK_abcdef_NOT_IN_LOG');
    }
  });

  // ── Test 13 (Finding B): duplicate sticky envp entries are exhaustively cleaned ─
  //
  // A raw envp passed via execve() can contain multiple `NAME=…` entries —
  // there is no libc-level dedupe.  An attacker that controls a child's
  // envp (e.g. a native addon calling execve directly) could pass two
  // `SCRIPT_JAIL_LOG_FILE=…` entries to slip past the shim's sticky-var
  // re-injection: if envbuf_remove / overwrite_env stopped at the first
  // match, the second attacker-supplied entry would survive into the
  // grandchild and redirect its audit log.
  //
  // We exercise both arms of the sticky-var loop:
  //   * empty-canon case  → envbuf_remove path must delete EVERY duplicate.
  //   * non-empty-canon   → overwrite_env path must collapse to a single
  //                          canonical entry, with NO attacker copy left.
  //
  // The harness uses a small C binary (compiled via `cc -x c -`) that
  // builds a raw envp[] with two SCRIPT_JAIL_LOG_FILE entries, then
  // execve()s `node -e ...` which prints back what it sees for that var
  // and the total count of matching entries in its own environ.
  it('duplicate SCRIPT_JAIL_LOG_FILE entries are exhaustively removed when canon is empty (Finding B)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-dup-envp-empty-'));
    tempFiles.push(dir);
    const bin = join(dir, 'dup_envp_empty');
    // We embed shimSo's path so the child can find it.  The C program calls
    // execve with a raw envp array containing TWO SCRIPT_JAIL_LOG_FILE
    // entries.  The parent of execve runs WITHOUT shim_init having
    // captured SCRIPT_JAIL_LOG_FILE (canon empty); we don't preload here
    // for that reason — let it be a regular execve and rely on the
    // shim-as-LD_PRELOAD inside the child to do the rewrite work.  Both
    // duplicate entries must be stripped because canon for that var is
    // empty in the parent.
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "let n=0;"
          "for (const k of Object.keys(process.env)) if (k === 'SCRIPT_JAIL_LOG_FILE') n++;"
          "process.stdout.write('count='+n+'/value='+(process.env.SCRIPT_JAIL_LOG_FILE||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "SCRIPT_JAIL_LOG_FILE=/tmp/evil-one",
          "SCRIPT_JAIL_LOG_FILE=/tmp/evil-two",
          "LD_PRELOAD=${shimSo}",
          /* SCRIPT_JAIL_LOG_FD intentionally absent → canon for LOG_FILE empty */
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    // No LD_PRELOAD on the OUTER process: this binary directly execve()s
    // node with the duplicate-envp poison.  The shim only loads inside the
    // execve()'d child where it captures canon at shim_init from the
    // (poisoned) envp.  But the shim resolves canon from real_getenv on
    // the FIRST entry it sees, which is whichever the kernel hands back.
    // For the empty-canon arm we instead let the outer C binary BE the
    // shim-loaded process and the inner node child receive the rewritten
    // envp via execve interception.
    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // SCRIPT_JAIL_LOG_FD only — no SCRIPT_JAIL_LOG_FILE.  So canon for
        // SCRIPT_JAIL_LOG_FILE inside this outer process is empty.
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // The child must see ZERO SCRIPT_JAIL_LOG_FILE entries; both attacker
    // duplicates were stripped by rewrite_envp.
    expect(result.stdout).toContain('count=0');
    expect(result.stdout).toContain('value=ABSENT');
    expect(result.stdout).not.toContain('/tmp/evil-one');
    expect(result.stdout).not.toContain('/tmp/evil-two');
  });

  it('duplicate SCRIPT_JAIL_LOG_FILE entries collapse to a single canonical entry when canon is set (Finding B)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-dup-envp-set-'));
    tempFiles.push(dir);
    const bin = join(dir, 'dup_envp_set');
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "let n=0;"
          "for (const k of Object.keys(process.env)) if (k === 'SCRIPT_JAIL_LOG_FILE') n++;"
          "process.stdout.write('count='+n+'/value='+(process.env.SCRIPT_JAIL_LOG_FILE||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "SCRIPT_JAIL_LOG_FILE=/tmp/evil-one",
          "SCRIPT_JAIL_LOG_FILE=/tmp/evil-two",
          "LD_PRELOAD=${shimSo}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    // Outer process sets SCRIPT_JAIL_LOG_FILE → canon is non-empty.  The
    // child's TWO attacker duplicates must be replaced with EXACTLY one
    // canonical entry whose value matches the parent's setting.
    const canonical = '/tmp/script-jail-canonical-log';
    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_LOG_FILE: canonical,
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // EXACTLY one entry — Node's process.env hides Linux-level duplicates
    // (it dedupes on read) so the harness counts keys in Object.keys() and
    // also checks the single resolved value.  process.env is built from
    // environ[] left-to-right with LATER entries winning in glibc; we
    // assert the canonical value is what survived, not /tmp/evil-two.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${canonical}`);
    expect(result.stdout).not.toContain('/tmp/evil-one');
    expect(result.stdout).not.toContain('/tmp/evil-two');
  });

  // ── Finding (high): duplicate LD_PRELOAD survives the idempotent branch ──
  //
  // Even when the FIRST LD_PRELOAD entry is already canonical (matches the
  // sticky SCRIPT_JAIL_PRELOAD_PATH), a SECOND attacker-controlled
  // LD_PRELOAD entry in the raw envp must also be stripped.  Previously
  // append_path_env returned early on the idempotent prefix match, leaving
  // the duplicate live for ld.so to honor.
  it('duplicate LD_PRELOAD entries collapse to one canonical entry when first is already canonical', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-dup-ldp-'));
    tempFiles.push(dir);
    const bin = join(dir, 'dup_ldp');
    // The child Node script counts how many LD_PRELOAD entries the kernel
    // handed it (via /proc/self/environ — process.env dedupes on read, so
    // we cannot use it for the count) and prints the resolved value.
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "process.stdout.write('count='+ldp.length+'/value='+(process.env.LD_PRELOAD||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* FIRST entry: already canonical — exactly the SCRIPT_JAIL_PRELOAD_PATH
             value the parent will set below.  The idempotency check will fire. */
          "LD_PRELOAD=${shimSo}",
          /* SECOND entry: attacker-controlled.  Must be stripped. */
          "LD_PRELOAD=/tmp/evil-ldp.so",
          "SCRIPT_JAIL_PRELOAD_PATH=${shimSo}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Exactly one LD_PRELOAD entry in the child's environ.  The canonical
    // shim path survives; the attacker's /tmp/evil-ldp.so is gone.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${shimSo}`);
    expect(result.stdout).not.toContain('/tmp/evil-ldp.so');
  });

  // ── Finding (high): duplicate NODE_OPTIONS survives the idempotent branch ─
  it('duplicate NODE_OPTIONS entries collapse to one canonical entry when first is already canonical', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-dup-nodeopts-'));
    tempFiles.push(dir);
    const bin = join(dir, 'dup_nodeopts');
    // Pick a NODE_OPTIONS value Node accepts without spawning a preload
    // module (which would have to exist on disk).  --no-warnings is a
    // built-in, no file required.  This is the value the parent passes
    // via SCRIPT_JAIL_NODE_OPTIONS so the shim's append_path_env sees
    // the first entry as already canonical.
    const canonNodeOpts = '--no-warnings';
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const opt = entries.filter(e => e.startsWith('NODE_OPTIONS='));"
          "process.stdout.write('count='+opt.length+'/value='+(process.env.NODE_OPTIONS||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "LD_PRELOAD=${shimSo}",
          /* FIRST: already canonical (matches SCRIPT_JAIL_NODE_OPTIONS). */
          "NODE_OPTIONS=${canonNodeOpts}",
          /* SECOND: attacker --require= pointing at a nonexistent file.
             Must be stripped.  If it survived Node would fail to start. */
          "NODE_OPTIONS=--require=/tmp/evil-nodeopt.js",
          "SCRIPT_JAIL_NODE_OPTIONS=${canonNodeOpts}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_NODE_OPTIONS: canonNodeOpts,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Exactly one NODE_OPTIONS entry — only canonical --no-warnings remains.
    // The attacker --require=/tmp/evil-nodeopt.js must be gone.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${canonNodeOpts}`);
    expect(result.stdout).not.toContain('/tmp/evil-nodeopt.js');
    expect(result.stdout).not.toContain('--require=');
  });

  // ── Critical: attacker LD_PRELOAD is overwritten, not merged ───────────────
  //
  // The previous implementation prepended canonical to caller-supplied
  // (result: `canonical:attacker_value`) so our wrappers' symbols would
  // shadow at runtime — but ld.so still ran the attacker .so's ELF
  // constructor before any of our wrappers initialised.  rewrite_envp now
  // uses overwrite_env for LD_PRELOAD: the attacker's path must NOT
  // appear anywhere in the child's effective LD_PRELOAD.
  it('caller-supplied LD_PRELOAD is overwritten (attacker .so never loads)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldp-overwrite-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldp_overwrite');
    // Single attacker LD_PRELOAD entry (NOT a duplicate of canonical).  If
    // the shim still merged we'd see "LD_PRELOAD=<shimSo>:/tmp/evil.so";
    // with overwrite_env the attacker path is completely gone.
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "process.stdout.write('count='+ldp.length+'/value='+(process.env.LD_PRELOAD||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* Pure attacker payload — not a duplicate, not canonical. */
          "LD_PRELOAD=/tmp/evil.so",
          "SCRIPT_JAIL_PRELOAD_PATH=${shimSo}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Effective LD_PRELOAD is EXACTLY the canonical shim path — no
    // suffix/prefix from the attacker's value.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${shimSo}`);
    expect(result.stdout).not.toContain('/tmp/evil.so');
    // Specifically guard against the old prepend-merge format.
    expect(result.stdout).not.toContain(`${shimSo}:/tmp/evil.so`);
    expect(result.stdout).not.toContain(`/tmp/evil.so:${shimSo}`);
  });

  // ── Critical: attacker NODE_OPTIONS is overwritten, not merged ─────────────
  //
  // Same reasoning as LD_PRELOAD: caller-supplied --require=/tmp/evil.js
  // would still load (just after ours) under the old prepend-merge code.
  // The legitimate --max-old-space-size=1024 is dropped too — the audit
  // envelope owns NODE_OPTIONS end-to-end.
  it('caller-supplied NODE_OPTIONS is overwritten (attacker --require never runs)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-nodeopts-overwrite-'));
    tempFiles.push(dir);
    const bin = join(dir, 'nodeopts_overwrite');
    const canonNodeOpts = '--no-warnings';
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const opt = entries.filter(e => e.startsWith('NODE_OPTIONS='));"
          "process.stdout.write('count='+opt.length+'/value='+(process.env.NODE_OPTIONS||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "LD_PRELOAD=${shimSo}",
          /* Pure attacker payload: --require points at a non-existent
             file (so if it survived, Node would fail to start with a
             MODULE_NOT_FOUND error) plus a legitimate-looking flag.
             Both must be stripped. */
          "NODE_OPTIONS=--require=/tmp/evil.js --max-old-space-size=1024",
          "SCRIPT_JAIL_NODE_OPTIONS=${canonNodeOpts}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // Set BOTH canons so rewrite_envp exercises overwrite_env for
        // each: without SCRIPT_JAIL_PRELOAD_PATH, LD_PRELOAD canon would
        // be empty and the test would silently accept the caller's
        // LD_PRELOAD=shimSo passthrough instead of asserting overwrite.
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_NODE_OPTIONS: canonNodeOpts,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Effective NODE_OPTIONS is EXACTLY canonical — no attacker payload
    // anywhere, and the legitimate --max-old-space-size is also dropped.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${canonNodeOpts}`);
    expect(result.stdout).not.toContain('--require=');
    expect(result.stdout).not.toContain('/tmp/evil.js');
    expect(result.stdout).not.toContain('--max-old-space-size');
  });

  // ── Critical: both LD_PRELOAD and NODE_OPTIONS overwritten together ────────
  //
  // Cross-check: a single execve with attacker entries for BOTH names
  // must scrub both.  The two overwrite_env calls in rewrite_envp are
  // independent — assert they compose correctly.
  it('caller-supplied LD_PRELOAD and NODE_OPTIONS are both overwritten', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-both-overwrite-'));
    tempFiles.push(dir);
    const bin = join(dir, 'both_overwrite');
    const canonNodeOpts = '--no-warnings';
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "const opt = entries.filter(e => e.startsWith('NODE_OPTIONS='));"
          "process.stdout.write("
          "  'ldp_count='+ldp.length+"
          "  '/ldp_value='+(process.env.LD_PRELOAD||'ABSENT')+"
          "  '/opt_count='+opt.length+"
          "  '/opt_value='+(process.env.NODE_OPTIONS||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "LD_PRELOAD=/tmp/evil.so",
          "NODE_OPTIONS=--require=/tmp/evil.js",
          "SCRIPT_JAIL_PRELOAD_PATH=${shimSo}",
          "SCRIPT_JAIL_NODE_OPTIONS=${canonNodeOpts}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_NODE_OPTIONS: canonNodeOpts,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Both vars: exactly one entry, exactly the canonical value, no
    // attacker payload anywhere in the child's environ.
    expect(result.stdout).toContain('ldp_count=1');
    expect(result.stdout).toContain(`ldp_value=${shimSo}`);
    expect(result.stdout).toContain('opt_count=1');
    expect(result.stdout).toContain(`opt_value=${canonNodeOpts}`);
    expect(result.stdout).not.toContain('/tmp/evil.so');
    expect(result.stdout).not.toContain('/tmp/evil.js');
    expect(result.stdout).not.toContain('--require=');
  });

  // ── Critical: init-time fallback canon enforces overwrite on LD_PRELOAD ────
  //
  // When the parent does NOT set SCRIPT_JAIL_PRELOAD_PATH but DOES load
  // the shim via LD_PRELOAD, shim_init captures the parent's LD_PRELOAD
  // value as the fallback canonical (CANON_PRELOAD_PATH).  rewrite_envp
  // then overwrites any caller-supplied LD_PRELOAD with that fallback —
  // so a pure attacker payload `LD_PRELOAD=/tmp/evil.so` must NOT survive
  // into the child.  Before this fix the empty-SCRIPT_JAIL_PRELOAD_PATH
  // branch passed caller envp through verbatim.
  it('caller-supplied LD_PRELOAD is overwritten with init-time canonical when SCRIPT_JAIL_PRELOAD_PATH is unset', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldp-initcanon-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldp_initcanon');
    // The C launcher execve()s with a pure attacker LD_PRELOAD value
    // (no shim path).  Without the init-time fallback canon the shim
    // would preserve this verbatim — letting /tmp/evil.so survive into
    // the child's environ.  With the fix the parent's LD_PRELOAD=<shimSo>
    // becomes the fallback canonical and overwrites the attacker entry.
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "process.stdout.write('count='+ldp.length+'/value='+(process.env.LD_PRELOAD||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* Pure attacker payload — NO shim path. */
          "LD_PRELOAD=/tmp/evil.so",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // Deliberately NO SCRIPT_JAIL_PRELOAD_PATH → init-time
        // LD_PRELOAD=<shimSo> becomes CANON_PRELOAD_PATH.
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Effective LD_PRELOAD is EXACTLY the init-time shim path — attacker
    // value completely scrubbed.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${shimSo}`);
    expect(result.stdout).not.toContain('/tmp/evil.so');
  });

  // ── Critical: attacker SUFFIX on canonical LD_PRELOAD is stripped ──────────
  //
  // Caller passes `LD_PRELOAD=<shimSo>:/tmp/evil.so` — looks legitimate at
  // a glance (the shim is in there!) but the attacker .so is loaded by
  // ld.so right after the shim and its ELF constructor runs.  With the
  // init-time fallback canon, overwrite_env replaces the whole entry with
  // just `<shimSo>` — the colon-separated suffix is gone.
  it('caller-supplied LD_PRELOAD=/lib/libscriptjail.so:/tmp/evil.so is overwritten to just /lib/libscriptjail.so when SCRIPT_JAIL_PRELOAD_PATH is unset', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldp-suffix-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldp_suffix');
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "process.stdout.write('count='+ldp.length+'/value='+(process.env.LD_PRELOAD||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* Canonical shim path PLUS an attacker suffix.  ld.so loads
             both .so files; the attacker's ELF ctor runs.  Must be
             stripped down to just the canonical entry. */
          "LD_PRELOAD=${shimSo}:/tmp/evil.so",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // No SCRIPT_JAIL_PRELOAD_PATH → init-time LD_PRELOAD=<shimSo>
        // is the fallback canon.
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Exactly one LD_PRELOAD entry, exactly the canonical shim path,
    // no /tmp/evil.so suffix anywhere.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${shimSo}`);
    expect(result.stdout).not.toContain('/tmp/evil.so');
    expect(result.stdout).not.toContain(`${shimSo}:/tmp/evil.so`);
  });

  // ── Critical: empty NODE_OPTIONS canon → caller entry exhaustively removed
  //
  // Neither SCRIPT_JAIL_NODE_OPTIONS nor a parent NODE_OPTIONS is set,
  // so CANON_NODE_OPTIONS is empty even after the init-time fallback.
  // overwrite_env's empty-value path must exhaustively strip any
  // attacker NODE_OPTIONS entry from caller envp — the child must see
  // NO NODE_OPTIONS at all (Node would otherwise --require=/tmp/evil.js).
  it('caller-supplied NODE_OPTIONS with --require=/tmp/evil.js is removed when both canonicals are empty', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-nodeopt-empty-'));
    tempFiles.push(dir);
    const bin = join(dir, 'nodeopt_empty');
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const opt = entries.filter(e => e.startsWith('NODE_OPTIONS='));"
          "process.stdout.write('count='+opt.length+'/value='+(process.env.NODE_OPTIONS||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* Keep shim in the chain so the child can still emit audit. */
          "LD_PRELOAD=${shimSo}",
          /* Pure attacker NODE_OPTIONS — parent never set one and never
             set SCRIPT_JAIL_NODE_OPTIONS either, so both canonicals are
             empty and this must be exhaustively removed. */
          "NODE_OPTIONS=--require=/tmp/evil.js",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // Neither SCRIPT_JAIL_NODE_OPTIONS nor NODE_OPTIONS on the
        // parent → CANON_NODE_OPTIONS stays empty after init.
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // No NODE_OPTIONS entry survives into the child.
    expect(result.stdout).toContain('count=0');
    expect(result.stdout).toContain('value=ABSENT');
    expect(result.stdout).not.toContain('--require=');
    expect(result.stdout).not.toContain('/tmp/evil.js');
  });

  // ── Regression: empty-canon LD_PRELOAD must NOT be stripped ────────────────
  //
  // When the parent never set SCRIPT_JAIL_PRELOAD_PATH the canon for
  // LD_PRELOAD is captured from the parent's init-time LD_PRELOAD value
  // as a fallback (see capture_canon in shim_init).  That fallback
  // ensures rewrite_envp overwrites caller-supplied entries with the
  // shim path, preserving the audit chain at every exec.
  it('caller-supplied LD_PRELOAD is preserved when canon is empty (audit chain)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldp-empty-canon-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldp_empty_canon');
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const ldp = entries.filter(e => e.startsWith('LD_PRELOAD='));"
          "process.stdout.write('count='+ldp.length+'/value='+(process.env.LD_PRELOAD||'ABSENT'));",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          /* Caller passes LD_PRELOAD=shimSo so the child stays under
             audit.  No SCRIPT_JAIL_PRELOAD_PATH on the parent so canon
             is empty.  Rewrite must leave this entry alone. */
          "LD_PRELOAD=${shimSo}",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        // Deliberately NO SCRIPT_JAIL_PRELOAD_PATH → CANON_PRELOAD_PATH empty.
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // LD_PRELOAD survives intact — shim chain still propagates.
    expect(result.stdout).toContain('count=1');
    expect(result.stdout).toContain(`value=${shimSo}`);
  });

  // ── Audit-trust Finding 2 (2026-05-18) — LD_AUDIT / LD_LIBRARY_PATH ────────
  //
  // glibc honors LD_AUDIT and LD_LIBRARY_PATH at process startup independently
  // of LD_PRELOAD.  LD_AUDIT loads an attacker-supplied DSO via the rtld-audit
  // API BEFORE any LD_PRELOAD module's constructor runs, and LD_LIBRARY_PATH
  // diverts ld.so's library search to attacker-controlled directories.
  // rewrite_envp must strip both names from every exec'd child's envp; the
  // setenv/unsetenv/putenv wrappers must refuse to set them in-process so a
  // descendant cannot restore them between the strip and the next exec.

  it('caller-supplied LD_AUDIT is stripped from the child env (Finding 2)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldaudit-strip-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldaudit_strip');
    // Native execve()s into `env node` with LD_AUDIT in the envp; the Node
    // child reads /proc/self/environ to count LD_AUDIT entries the kernel
    // actually delivered.  Expectation: zero.
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const aud = entries.filter(e => e.startsWith('LD_AUDIT='));"
          "process.stdout.write('count='+aud.length);",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "LD_PRELOAD=${shimSo}",
          "SCRIPT_JAIL_PRELOAD_PATH=${shimSo}",
          /* Attacker-controlled audit DSO. */
          "LD_AUDIT=/tmp/evil-audit.so",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    // Child sees zero LD_AUDIT entries — the attacker payload never reaches
    // ld.so's audit hook.
    expect(result.stdout).toContain('count=0');
    expect(result.stdout).not.toContain('/tmp/evil-audit.so');
  });

  it('caller-supplied LD_LIBRARY_PATH is stripped from the child env (Finding 2)', (ctx) => {
    if (!shimAvailable) ctx.skip();
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) ctx.skip();

    const dir = mkdtempSync(join(tmpdir(), 'script-jail-ldlibpath-strip-'));
    tempFiles.push(dir);
    const bin = join(dir, 'ldlibpath_strip');
    const src = `
      #include <unistd.h>
      extern char **environ;
      int main(void) {
        char *argv[] = {
          "env",
          "node",
          "-e",
          "const fs = require('fs');"
          "const buf = fs.readFileSync('/proc/self/environ');"
          "const entries = buf.toString('utf8').split('\\\\0').filter(s => s.length > 0);"
          "const lp = entries.filter(e => e.startsWith('LD_LIBRARY_PATH='));"
          "process.stdout.write('count='+lp.length);",
          0,
        };
        char *envp[] = {
          "PATH=/usr/bin:/bin",
          "LD_PRELOAD=${shimSo}",
          "SCRIPT_JAIL_PRELOAD_PATH=${shimSo}",
          /* Attacker-controlled library search path. */
          "LD_LIBRARY_PATH=/tmp/attacker_libs:",
          0,
        };
        execve("/usr/bin/env", argv, envp);
        return 1;
      }
    `;
    const compile = spawnSync(
      'cc', ['-x', 'c', '-o', bin, '-'],
      { input: src, encoding: 'utf8' },
    );
    if (compile.status !== 0) ctx.skip();

    const result = spawnSync(bin, [], {
      env: {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        LD_PRELOAD: shimSo,
        SCRIPT_JAIL_PRELOAD_PATH: shimSo,
        SCRIPT_JAIL_LOG_FD: '1',
      },
      encoding: 'utf8',
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('count=0');
    expect(result.stdout).not.toContain('/tmp/attacker_libs');
  });

  it('setenv("LD_AUDIT", "/tmp/evil.so") is refused and audited (Finding 2)', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const result = runWithShim({
      cmd: `node -e 'process.env.LD_AUDIT = "/tmp/evil-audit.so";
                     console.log("LDA=" + (process.env.LD_AUDIT || "GONE"));'`,
    });

    expect(result.exitCode).toBe(0);
    // setenv was refused inside libc, but the JS Proxy's `set` trap (which
    // doesn't go through the shim) still updates the in-Node env Map; what
    // matters here is that the shim emitted env_tamper and refused the libc
    // call.  Other tests assert the env_shim wrappers themselves; here we
    // only check the audit event was emitted.
    const tamperEvents = result.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> => e !== null && e['kind'] === 'env_tamper');
    const lda = tamperEvents.filter((e) => e['name'] === 'LD_AUDIT');
    expect(lda.length).toBeGreaterThanOrEqual(1);
    expect(lda.every((e) => e['refused'] === true)).toBe(true);
  });

  it('setenv("LD_LIBRARY_PATH", "/tmp/evil") is refused and audited (Finding 2)', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const result = runWithShim({
      cmd: `node -e 'process.env.LD_LIBRARY_PATH = "/tmp/attacker_libs";
                     console.log("LLP=" + (process.env.LD_LIBRARY_PATH || "GONE"));'`,
    });

    expect(result.exitCode).toBe(0);
    const tamperEvents = result.logLines
      .map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter((e): e is Record<string, unknown> => e !== null && e['kind'] === 'env_tamper');
    const llp = tamperEvents.filter((e) => e['name'] === 'LD_LIBRARY_PATH');
    expect(llp.length).toBeGreaterThanOrEqual(1);
    expect(llp.every((e) => e['refused'] === true)).toBe(true);
  });
});

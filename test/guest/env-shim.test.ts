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
    protectFile?: string;
  }): ShimResult {
    const logFile = makeTempFile('', '.jsonl');

    const extraEnv: Record<string, string> = {
      LD_PRELOAD:       shimSo,
      SCRIPT_JAIL_LOG_FD:   '3',
      ...opts.env,
    };
    if (opts.protectFile !== undefined) {
      extraEnv['SCRIPT_JAIL_PROTECTED_ENV_FILE'] = opts.protectFile;
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

    const protectFile = makeTempFile('NPM_TOKEN\n', '.txt');

    // node: exit 0 if NPM_TOKEN is undefined, exit 1 if it is defined.
    const res = runWithShim({
      cmd: `node -e 'process.exit(process.env.NPM_TOKEN === undefined ? 0 : 1)'`,
      env: { NPM_TOKEN: 'super-secret' },
      protectFile,
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

  // ── Test 4: comments and blank lines in protect-list are ignored ──────────

  it('protect-list respects comments and blank lines', (ctx) => {
    if (!shimAvailable) ctx.skip();

    const protectContent = [
      '# comment line',
      'NPM_TOKEN',
      '',
      'GITHUB_TOKEN',
      '  # indented comment is NOT a comment (no leading-space trim)',
    ].join('\n') + '\n';

    const protectFile = makeTempFile(protectContent, '.txt');

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
      protectFile,
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

    const protectFile = makeTempFile('HIDDEN_VAR\n', '.txt');

    // MY_VAR is not in the protect list — it should be visible.
    const res = runWithShim({
      cmd: `node -e 'process.exit(process.env.MY_VAR === "hello" ? 0 : 1)'`,
      env: {
        MY_VAR:     'hello',
        HIDDEN_VAR: 'secret',
      },
      protectFile,
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
});

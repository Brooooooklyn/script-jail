// Tests for src/shim/env-shim.c
// Uses vitest project: "guest" (see vitest.config.ts)
//
// Skipped entirely on non-Linux: LD_PRELOAD semantics differ significantly on
// macOS (DYLD_INSERT_LIBRARIES + SIP restrictions) and are not supported here.

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, unlinkSync, existsSync, statSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const isLinux = process.platform === 'linux';

// Paths relative to the repo root (resolved from __dirname = test/guest/).
// __dirname is undefined in ESM; use import.meta.url instead.
const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const shimSrc  = join(repoRoot, 'src/shim/env-shim.c');
const shimSo   = join(repoRoot, 'images/libscriptjail.so');
const buildSh  = join(repoRoot, 'src/shim/build.sh');

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
 * Returns true if the .so is up-to-date (exists and newer than the source and
 * the build script).
 */
function soIsUpToDate(): boolean {
  if (!existsSync(shimSo) || !existsSync(shimSrc) || !existsSync(buildSh)) return false;
  const soMtime  = statSync(shimSo).mtimeMs;
  const srcMtime = statSync(shimSrc).mtimeMs;
  const shMtime  = statSync(buildSh).mtimeMs;
  return soMtime >= srcMtime && soMtime >= shMtime;
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
  // green without actually exercising the shim.  Only an unavailable C
  // compiler is treated as a skip condition.

  beforeAll(() => {
    // Check that a C compiler is available.
    const cc = spawnSync('cc', ['--version'], { encoding: 'utf8' });
    if (cc.status !== 0 || cc.error) {
      // No C compiler — leave shimAvailable = false so all tests are skipped.
      return;
    }

    if (soIsUpToDate()) {
      shimAvailable = true;
      return;
    }

    const result = spawnSync('sh', [buildSh], {
      encoding: 'utf8',
      cwd: repoRoot,
    });

    if (result.status !== 0) {
      throw new Error(`build.sh failed:\n${result.stderr}\n${result.stdout}`);
    }

    shimAvailable = true;

    // Sanity-check: the wrapper symbols must be visible in .dynsym so that
    // ld-linux.so can intercept them via LD_PRELOAD.  readelf is optional
    // (skip if absent rather than failing).
    const readelf = spawnSync('readelf', ['-Ws', '--dyn-syms', shimSo], { encoding: 'utf8' });
    if (readelf.status === 0 && !readelf.error) {
      if (!/\bgetenv\b/.test(readelf.stdout)) {
        throw new Error('libscriptjail.so does not export getenv as a dynamic symbol — check -fvisibility=hidden and __attribute__((visibility("default")))');
      }
    }
    // readelf unavailable: skip the assertion (don't fail)
  });

  // ── helper: run a command with the shim preloaded ────────────────────────

  interface ShimResult {
    exitCode:  number | null;
    logLines:  string[];  // JSONL lines captured from log fd
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
  // too costly for the v1 test suite.  The escaping logic in env-shim.c is
  // unit-testable in isolation.

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
});

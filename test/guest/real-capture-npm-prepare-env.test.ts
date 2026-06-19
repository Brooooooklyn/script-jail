// Empirical (real-npm) test for realCaptureNpmPrepareEnv (src/guest/agent.ts).
//
// "Seeing is believing": this drives the ACTUAL round-20 capture — a forced-shell
// `npm exec --script-shell=/bin/sh ... -c '<dump env>'` + `npm config get
// script-shell` — against the node-bundled npm, asserting the security-critical
// properties verified during design:
//   - the repo's custom `.npmrc` config key IS projected into npm_config_* (npm
//     does this whenever a root package.json exists — which the audited repo always
//     has) → the prepare sees a faithful config;
//   - a registry credential (`//host/:_authToken`) is NOT leaked into the env;
//   - `config get` reports the repo's REAL `script-shell`, while the captured
//     npm_config_script_shell (forced /bin/sh — un-hijackable dump) is DROPPED;
//   - the exec-specific `npm_config_call` (holds the random dump path) is DROPPED.
//
// Gated on the node-bundled npm-cli.js existing at the derived path (always true on
// CI / a normal node install); skipped otherwise so the suite never hard-depends on
// a particular npm layout.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { realCaptureNpmPrepareEnv, npmCliEntryPath } from '../../src/guest/agent.js';

const NPM_CLI = npmCliEntryPath(process.execPath);
const HAVE_NPM = existsSync(NPM_CLI);

let repo: string;

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), 'sj-realcap-'));
});
afterEach(() => {
  try { rmSync(repo, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe.skipIf(!HAVE_NPM)('realCaptureNpmPrepareEnv (real npm)', () => {
  it('captures custom npm_config_* + repo script-shell; excludes credentials/call/script_shell', () => {
    // A root package.json is REQUIRED for npm to project project-.npmrc config into
    // npm_config_* (verified during design).
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    writeFileSync(
      join(repo, '.npmrc'),
      [
        'sj-custom-key=ROOTVAL',
        'script-shell=/usr/bin/repo-shell',
        '//registry.npmjs.org/:_authToken=SHOULD_NOT_LEAK',
        '',
      ].join('\n'),
      'utf8',
    );

    const cap = realCaptureNpmPrepareEnv({
      node: process.execPath,
      npmCli: NPM_CLI,
      cwd: repo,
      env: process.env,
    });
    expect(cap).not.toBeNull();
    const { npmConfig, scriptShell } = cap!;

    // Custom .npmrc key projected into npm_config_* (faithful config for the prepare).
    expect(npmConfig['npm_config_sj_custom_key']).toBe('ROOTVAL');
    // `config get` reports the repo's REAL script-shell (NOT the forced /bin/sh).
    expect(scriptShell).toBe('/usr/bin/repo-shell');
    // The forced /bin/sh + the exec-specific dump command are NOT in the captured set.
    expect(npmConfig['npm_config_script_shell']).toBeUndefined();
    expect(npmConfig['npm_config_call']).toBeUndefined();
    // NO registry credential leaked — neither as a key nor as a value.
    for (const k of Object.keys(npmConfig)) {
      expect(k.toLowerCase()).not.toContain('authtoken');
    }
    expect(Object.values(npmConfig).join('\n')).not.toContain('SHOULD_NOT_LEAK');
    // The dump captured a non-trivial config set (npm's runtime keys at minimum).
    expect(Object.keys(npmConfig).length).toBeGreaterThan(0);
  });

  it('reports scriptShell=null when the repo .npmrc sets no script-shell', () => {
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    writeFileSync(join(repo, '.npmrc'), 'foo=bar\n', 'utf8');
    const cap = realCaptureNpmPrepareEnv({
      node: process.execPath,
      npmCli: NPM_CLI,
      cwd: repo,
      env: process.env,
    });
    expect(cap).not.toBeNull();
    expect(cap!.scriptShell).toBeNull();
  });

  // adversarial-review round-20 [critical]: the dump child runs with the agent's
  // REAL env (which holds protected secrets), but it must NOT spill a non-config
  // secret to disk where the later untrusted prepare (same UID, same tmpdir) could
  // read it via a plain file read (invisible to the env-read audit).  Two layers:
  // the dump emits ONLY npm_config_*, and the whole dump dir is removed in a finally.
  it('never spills a non-config secret (NPM_TOKEN) to disk, and cleans up its dump dir', () => {
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    writeFileSync(join(repo, '.npmrc'), 'sj-custom-key=KEEPVAL\n', 'utf8');

    // This file is the ONLY caller of realCaptureNpmPrepareEnv, and tests within a
    // file run sequentially → any sj-prep-cap dir appearing across the call is OURS.
    const before = new Set(readdirSync(tmpdir()).filter((n) => n.startsWith('sj-prep-cap-')));
    const SECRET = 'SJ_SPILL_CANARY_9f3a2b1c';

    const cap = realCaptureNpmPrepareEnv({
      node: process.execPath,
      npmCli: NPM_CLI,
      cwd: repo,
      // Inject a non-config protected-shaped secret into the dump env (the agent's
      // real env holds exactly this kind of value in production).
      env: { ...process.env, NPM_TOKEN: SECRET, GITHUB_TOKEN: SECRET },
    });
    expect(cap).not.toBeNull();

    // The faithful custom config key still rides through (no faithfulness regression).
    expect(cap!.npmConfig['npm_config_sj_custom_key']).toBe('KEEPVAL');
    // The secret never reaches the returned config (it is not an npm_config_ key).
    expect(Object.values(cap!.npmConfig).join('\n')).not.toContain(SECRET);

    // CLEANUP: the call left NO new sj-prep-cap dir behind — nothing for the later
    // prepare to enumerate and read.
    const after = readdirSync(tmpdir()).filter((n) => n.startsWith('sj-prep-cap-'));
    const leftBehind = after.filter((n) => !before.has(n));
    expect(leftBehind).toEqual([]);

    // Belt-and-suspenders: even scanning EVERY surviving sj-prep-cap dir (e.g. a
    // stale one from a crashed run) finds the canary nowhere on disk.
    for (const d of after) {
      const dir = join(tmpdir(), d);
      let names: string[] = [];
      try { names = statSync(dir).isDirectory() ? readdirSync(dir) : []; } catch { names = []; }
      for (const f of names) {
        let body = '';
        try { body = readFileSync(join(dir, f), 'utf8'); } catch { body = ''; }
        expect(body).not.toContain(SECRET);
      }
    }
  });

  // adversarial-review round-21 [high]: the forced-shell dump `-c` body is parsed by
  // /bin/sh.  The node + dump-script paths (derived from os.tmpdir(), and on macOS
  // process.execPath may sit under an env-selected provision path) MUST ride in env
  // and be referenced as double-quoted `"$X"` expansions — interpolating them into the
  // command string lets a TMPDIR with shell metacharacters inject commands that run
  // with the agent's REAL env (secrets) BEFORE the npm_config_-only dump or cleanup.
  it('is immune to shell injection via a TMPDIR containing shell metacharacters', () => {
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    const pwn = join(repo, 'PWNED.txt');
    // A tmp dir whose NAME embeds an injection: if the `-c` body interpolated the path
    // unquoted, /bin/sh would run `node -e <write the canary token to PWN_OUT>`.
    const evilTmp = join(
      repo,
      'x; node -e "require(\'fs\').writeFileSync(process.env.PWN_OUT, process.env.NPM_TOKEN)" ; #',
    );
    mkdirSync(evilTmp, { recursive: true });

    const savedTmp = process.env.TMPDIR;
    process.env.TMPDIR = evilTmp; // os.tmpdir() reads this fresh → the dump dir lands here.
    try {
      realCaptureNpmPrepareEnv({
        node: process.execPath,
        npmCli: NPM_CLI,
        cwd: repo,
        env: { ...process.env, NPM_TOKEN: 'SJ_INJECT_CANARY_b41f', PWN_OUT: pwn },
      });
    } finally {
      if (savedTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = savedTmp;
    }
    // No injected command ran → the canary file was never written.
    expect(existsSync(pwn)).toBe(false);
  });

  // adversarial-review round-22 [high]: shell-quoting the dump path is not enough — the
  // value is still passed as node's first ARGV.  A RELATIVE TMPDIR that starts with a
  // node option (e.g. `--eval=<code>` / `--import=data:...`) makes dumpScriptPath start
  // with `--`, so without a `--` end-of-options terminator node parses it as a CLI
  // OPTION and runs the attacker code with the agent's real env BEFORE dump.cjs.  The
  // fix is `node -- <dump>`; this pins that the option never executes.
  it('is immune to node ARGV option-injection via a relative TMPDIR starting with --', () => {
    const pwn = join(repo, 'PWNED.txt');
    // Slash-free, single-component relative dir name that, as `--eval=<code>`, would
    // run writeFileSync(PWN_OUT) BEFORE the trailing path text is parsed (left-to-right
    // eval; the writeFileSync executes, then `undefined / .../dump.cjs` is harmless NaN).
    const evilRelTmp = "--eval=require('fs').writeFileSync(process.env.PWN_OUT,'OPTINJECT')";
    // mkdtemp resolves a relative tmpdir against process.cwd(); chdir to a throwaway
    // sandbox so the weird dir never touches the repo working tree.
    const sandbox = mkdtempSync(join(tmpdir(), 'sj-optinj-'));
    writeFileSync(join(sandbox, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    mkdirSync(join(sandbox, evilRelTmp), { recursive: true });

    const cwdSaved = process.cwd();
    const savedTmp = process.env.TMPDIR;
    process.chdir(sandbox);
    process.env.TMPDIR = evilRelTmp; // relative → dump dir + dump.cjs land under sandbox.
    try {
      realCaptureNpmPrepareEnv({
        node: process.execPath,
        npmCli: NPM_CLI,
        cwd: sandbox,
        env: { ...process.env, NPM_TOKEN: 'SJ_OPTINJECT_CANARY', PWN_OUT: pwn },
      });
    } finally {
      process.chdir(cwdSaved);
      if (savedTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = savedTmp;
      try { rmSync(sandbox, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    // The `--eval` option never executed → the canary file was never written.
    expect(existsSync(pwn)).toBe(false);
  });

  it('returns null when the npm-cli path does not exist (dump cannot run → fail closed)', () => {
    writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'r', version: '1.0.0' }), 'utf8');
    const cap = realCaptureNpmPrepareEnv({
      node: process.execPath,
      npmCli: join(repo, 'no-such-npm-cli.js'),
      cwd: repo,
      env: process.env,
    });
    expect(cap).toBeNull();
  });
});

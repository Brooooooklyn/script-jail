// Tests for NPM_PREPARE_RUNNER_SOURCE (src/guest/agent.ts).
//
// The #44 fix runs the ROOT project's prepare lifecycle through this runner,
// DIRECT-LAUNCHED by the guest as `node <runner> <npmCli> <scriptShell>` (round-20
// — NOT via `npm exec`).  The runner resolves `@npmcli/run-script` (npm's OWN
// lifecycle runner) relative to the npm-cli.js path in argv[2] and calls it once
// per present prepare-class event, forwarding the repo's resolved `script-shell`
// (argv[3]) as run-script's `scriptShell` option.  Both ride in ARGV (not env) so
// the runner emits NO env_reads of its own under env-spy.
//
// What these tests pin (the adversarial-review concerns):
//   - Finding A (NO wrapper recursion): the runner only ever drives the fixed
//     triplet preprepare/prepare/postprepare via run-script — which itself adds
//     NO automatic pre/post — so a real install's run-order is reproduced and a
//     `prepreprepare`-style wrapper can never be invoked.
//   - It runs ONLY those three (never `build`/`postinstall`/etc.), in order.
//   - Absent / empty scripts and a missing package.json are clean exit-0 no-ops.
//   - A failing prepare script propagates as a nonzero exit (fail-loud).
//   - It FORWARDS the repo's script-shell as run-script's `scriptShell` option
//     (round-20) — empty/'null'/absent → undefined (run-script default).
//
// `@npmcli/run-script` is STUBBED (a recorder) so the test pins the RUNNER's
// behavior, not npm's; the real run-script's no-pre/post contract is npm's.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NPM_PREPARE_RUNNER_SOURCE } from '../../src/guest/agent.js';

let dir: string;
let projDir: string;
let runnerPath: string;
let recordFile: string;
let npmExecPath: string;

// A stub `@npmcli/run-script`: appends `<event>\t<scriptShell>` per call to
// SJ_RECORD (so the test can assert both run-order AND scriptShell forwarding),
// and throws when SJ_FAIL names that event (to drive the fail path).
const RUN_SCRIPT_STUB = [
  "'use strict';",
  "const fs = require('fs');",
  'module.exports = async function runScript(opts) {',
  "  const shell = Object.prototype.hasOwnProperty.call(opts, 'scriptShell') ? String(opts.scriptShell) : '<absent>';",
  "  fs.appendFileSync(process.env.SJ_RECORD, opts.event + '\\t' + shell + '\\n');",
  '  if (process.env.SJ_FAIL && process.env.SJ_FAIL === opts.event) {',
  "    throw new Error('stub run-script forced failure for ' + opts.event);",
  '  }',
  '};',
  '',
].join('\n');

beforeEach(() => {
  dir = join(tmpdir(), `sj-prep-runner-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  projDir = join(dir, 'proj');
  mkdirSync(projDir, { recursive: true });

  // Fake npm layout so the runner can resolve @npmcli/run-script from
  // dirname(npm_execpath): npm_execpath = <fakenpm>/bin/npm-cli.js, and
  // run-script lives at <fakenpm>/node_modules/@npmcli/run-script (the
  // require.resolve `paths` option walks the node_modules hierarchy up from
  // the given dir — exactly how the real bundled npm is laid out).
  const rsDir = join(dir, 'fakenpm', 'node_modules', '@npmcli', 'run-script');
  mkdirSync(rsDir, { recursive: true });
  mkdirSync(join(dir, 'fakenpm', 'bin'), { recursive: true });
  writeFileSync(join(dir, 'fakenpm', 'bin', 'npm-cli.js'), '// fake npm-cli\n', 'utf8');
  writeFileSync(
    join(rsDir, 'package.json'),
    JSON.stringify({ name: '@npmcli/run-script', version: '1.0.0', main: 'index.js' }),
    'utf8',
  );
  writeFileSync(join(rsDir, 'index.js'), RUN_SCRIPT_STUB, 'utf8');
  npmExecPath = join(dir, 'fakenpm', 'bin', 'npm-cli.js');

  runnerPath = join(dir, 'sj-prepare-runner.cjs');
  writeFileSync(runnerPath, NPM_PREPARE_RUNNER_SOURCE, 'utf8');
  recordFile = join(dir, 'record.txt');
});

afterEach(() => {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function writeProjPkg(scripts: Record<string, unknown> | undefined): void {
  const pkg = scripts === undefined
    ? { name: 'root', version: '1.0.0' }
    : { name: 'root', version: '1.0.0', scripts };
  writeFileSync(join(projDir, 'package.json'), JSON.stringify(pkg), 'utf8');
}

interface RunRecord {
  event: string;
  shell: string;
}

// Run the runner with cwd=projDir; returns {status, records}.  When the runner
// exits nonzero, execFileSync throws — we capture status from the thrown error.
// round-20: npmCli is argv[2] (defaults to the fake npm-cli.js), scriptShell is
// argv[3] (omitted unless provided).  The runner reads BOTH from argv, not env, so
// it emits no env_reads of its own under env-spy.
function runRunner(
  opts: { npmCli?: string; scriptShell?: string; extraEnv?: Record<string, string> } = {},
): { status: number; records: RunRecord[] } {
  const argv = [runnerPath, opts.npmCli ?? npmExecPath];
  if (opts.scriptShell !== undefined) argv.push(opts.scriptShell);
  let status = 0;
  try {
    execFileSync(process.execPath, argv, {
      cwd: projDir,
      env: { ...process.env, SJ_RECORD: recordFile, ...(opts.extraEnv ?? {}) },
      stdio: 'pipe',
    });
  } catch (err) {
    status = (err as { status?: number }).status ?? 1;
  }
  const records = existsSync(recordFile)
    ? readFileSync(recordFile, 'utf8')
        .split('\n')
        .filter((l) => l.length > 0)
        .map((l) => {
          const [event, shell] = l.split('\t');
          return { event: event as string, shell: shell as string };
        })
    : [];
  return { status, records };
}

describe('NPM_PREPARE_RUNNER_SOURCE', () => {
  it('is syntactically valid JS', () => {
    // `node --check` parses without executing.
    expect(() => execFileSync(process.execPath, ['--check', runnerPath], { stdio: 'pipe' }))
      .not.toThrow();
  });

  it('runs preprepare → prepare → postprepare in order, and NOTHING else (no recursion, Finding A)', () => {
    // `prepreprepare`/`postprepare`-of-wrappers and unrelated scripts must NEVER
    // be invoked: a real `npm install` runs exactly preprepare/prepare/postprepare.
    writeProjPkg({
      preprepare: "node -e ''",
      prepare: "node -e ''",
      postprepare: "node -e ''",
      prepreprepare: "node -e ''", // a wrapper-of-wrapper — must NOT run
      postpreprepare: "node -e ''", // ditto
      build: "node -e ''", // unrelated — must NOT run
      postinstall: "node -e ''", // unrelated — must NOT run
    });
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records.map((r) => r.event)).toEqual(['preprepare', 'prepare', 'postprepare']);
  });

  it('runs only the present subset, preserving order (prepare + postprepare, no preprepare)', () => {
    writeProjPkg({ prepare: "node -e ''", postprepare: "node -e ''" });
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records.map((r) => r.event)).toEqual(['prepare', 'postprepare']);
  });

  it('skips empty-string and non-string scripts', () => {
    writeProjPkg({ preprepare: '', prepare: 42, postprepare: "node -e ''" });
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records.map((r) => r.event)).toEqual(['postprepare']);
  });

  it('exits 0 with no events when there is no scripts block', () => {
    writeProjPkg(undefined);
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records).toEqual([]);
  });

  it('exits 0 with no events when there is no package.json (nothing to audit)', () => {
    // projDir intentionally has no package.json.
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records).toEqual([]);
  });

  it('exits nonzero (fail-loud) when a prepare-class script fails', () => {
    writeProjPkg({ preprepare: "node -e ''", prepare: "node -e ''" });
    const { status, records } = runRunner({ extraEnv: { SJ_FAIL: 'prepare' } });
    expect(status).not.toBe(0);
    // preprepare ran (recorded) before prepare failed.
    expect(records.map((r) => r.event)).toEqual(['preprepare', 'prepare']);
  });

  it('exits 3 when @npmcli/run-script cannot be resolved', () => {
    // Point npm_execpath at a dir with no resolvable run-script (and the bare
    // `require` fallback also fails from the runner's /tmp location) → exit 3.
    // The orchestrator treats a nonzero exit with zero events as fail-closed, so
    // an unresolvable run-script can never silently ship.
    writeProjPkg({ prepare: "node -e ''" });
    const badCli = join(dir, 'no-such-npm', 'bin', 'npm-cli.js');
    const { status, records } = runRunner({ npmCli: badCli });
    expect(status).toBe(3);
    expect(records).toEqual([]);
  });

  // round-20: scriptShell forwarding.  @npmcli/run-script reads `scriptShell` from
  // its OPTIONS (NOT npm_config_script_shell env); npm's CLI passes the resolved
  // `script-shell` config the same way.  The runner reads the repo value from ARGV
  // (process.argv[3] — NOT env, so it emits no env_read under env-spy) and forwards
  // it — so a custom (even malicious) repo shell is used for the prepare scripts,
  // exactly as a real install would (and is audited).
  it('forwards the argv[3] script-shell as run-script `scriptShell`', () => {
    writeProjPkg({ prepare: "node -e ''", postprepare: "node -e ''" });
    const { status, records } = runRunner({ scriptShell: '/usr/bin/repo-shell' });
    expect(status).toBe(0);
    expect(records).toEqual([
      { event: 'prepare', shell: '/usr/bin/repo-shell' },
      { event: 'postprepare', shell: '/usr/bin/repo-shell' },
    ]);
  });

  it.each(['', 'null'])(
    'passes scriptShell=undefined (run-script default) when argv[3] is %j',
    (val) => {
      writeProjPkg({ prepare: "node -e ''" });
      const { status, records } = runRunner({ scriptShell: val });
      expect(status).toBe(0);
      // `scriptShell: undefined` is an OWN property of the opts object, so the
      // stub stringifies it to 'undefined' (NOT '<absent>').
      expect(records).toEqual([{ event: 'prepare', shell: 'undefined' }]);
    },
  );

  it('passes scriptShell=undefined when argv[3] is absent', () => {
    writeProjPkg({ prepare: "node -e ''" });
    const { status, records } = runRunner();
    expect(status).toBe(0);
    expect(records).toEqual([{ event: 'prepare', shell: 'undefined' }]);
  });
});

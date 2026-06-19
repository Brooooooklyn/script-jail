// Tests for NPM_PREPARE_RUNNER_SOURCE (src/guest/agent.ts).
//
// The #44 fix runs the ROOT project's prepare lifecycle through this runner,
// launched as `npm exec --offline --node-options= -c '<node> <runner>'`.  The
// runner resolves `@npmcli/run-script` (npm's OWN lifecycle runner) relative to
// `npm_execpath` and calls it once per present prepare-class event.
//
// What these tests pin (the adversarial-review concerns):
//   - Finding A (NO wrapper recursion): the runner only ever drives the fixed
//     triplet preprepare/prepare/postprepare via run-script — which itself adds
//     NO automatic pre/post — so a real install's run-order is reproduced and a
//     `prepreprepare`-style wrapper can never be invoked.
//   - It runs ONLY those three (never `build`/`postinstall`/etc.), in order.
//   - Absent / empty scripts and a missing package.json are clean exit-0 no-ops.
//   - A failing prepare script propagates as a nonzero exit (fail-loud).
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
let markerPath: string;

// A stub `@npmcli/run-script`: appends the event it was asked to run to
// SJ_RECORD, and throws when SJ_FAIL names that event (to drive the fail path).
const RUN_SCRIPT_STUB = [
  "'use strict';",
  "const fs = require('fs');",
  'module.exports = async function runScript(opts) {',
  "  fs.appendFileSync(process.env.SJ_RECORD, opts.event + '\\n');",
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
  // The runner writes its ground-truth execution sentinel at __dirname/ran.marker
  // (round-18b).  runnerPath lives directly in `dir`, so the marker lands there.
  markerPath = join(dir, 'ran.marker');
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

// Run the runner with cwd=projDir; returns {status, events}.  When the runner
// exits nonzero, execFileSync throws — we capture status from the thrown error.
function runRunner(
  extraEnv: Record<string, string> = {},
): { status: number; events: string[]; marker: boolean } {
  let status = 0;
  try {
    execFileSync(process.execPath, [runnerPath], {
      cwd: projDir,
      env: { ...process.env, npm_execpath: npmExecPath, SJ_RECORD: recordFile, ...extraEnv },
      stdio: 'pipe',
    });
  } catch (err) {
    status = (err as { status?: number }).status ?? 1;
  }
  const events = existsSync(recordFile)
    ? readFileSync(recordFile, 'utf8').split('\n').filter((l) => l.length > 0)
    : [];
  return { status, events, marker: existsSync(markerPath) };
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
    const { status, events, marker } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual(['preprepare', 'prepare', 'postprepare']);
    // Ground-truth sentinel written (the runner ran at the repo root) — round-18b.
    expect(marker).toBe(true);
  });

  it('runs only the present subset, preserving order (prepare + postprepare, no preprepare)', () => {
    writeProjPkg({ prepare: "node -e ''", postprepare: "node -e ''" });
    const { status, events } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual(['prepare', 'postprepare']);
  });

  it('skips empty-string and non-string scripts', () => {
    writeProjPkg({ preprepare: '', prepare: 42, postprepare: "node -e ''" });
    const { status, events } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual(['postprepare']);
  });

  it('exits 0 with no events when there is no scripts block', () => {
    writeProjPkg(undefined);
    const { status, events } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual([]);
  });

  it('exits 0 with no events when there is no package.json (nothing to audit)', () => {
    // projDir intentionally has no package.json.
    const { status, events, marker } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual([]);
    // No root package.json → exit BEFORE the sentinel write → marker absent (the
    // orchestrator then fails closed; the repo root always HAS a package.json, so
    // this is an anomaly, not the benign no-prepare case below).
    expect(marker).toBe(false);
  });

  it('writes the sentinel even with NO prepare scripts (benign no-op) — marker present, exit 0', () => {
    // The benign case: a parseable root package.json with no prepare-class script.
    // The runner reaches "about to run the lifecycle" (pkg read OK) → writes the
    // marker → finds nothing → exits 0.  Distinguishes "ran, nothing to do" (marker
    // present, NOT fail-closed) from "never ran" (marker absent, fail-closed).
    writeProjPkg({ build: "node -e ''" });
    const { status, events, marker } = runRunner();
    expect(status).toBe(0);
    expect(events).toEqual([]);
    expect(marker).toBe(true);
  });

  it('exits nonzero (fail-loud) when a prepare-class script fails — sentinel still present', () => {
    writeProjPkg({ preprepare: "node -e ''", prepare: "node -e ''" });
    const { status, events, marker } = runRunner({ SJ_FAIL: 'prepare' });
    expect(status).not.toBe(0);
    // preprepare ran (recorded) before prepare failed.
    expect(events).toEqual(['preprepare', 'prepare']);
    // The marker is written BEFORE the lifecycle loop, so a failing prepare is a
    // recorded (non-fatal) run, NOT a "runner never executed" fail-closed.
    expect(marker).toBe(true);
  });

  it('exits 3 with NO sentinel when @npmcli/run-script cannot be resolved', () => {
    // Point npm_execpath at a dir with no resolvable run-script (and the bare
    // `require` fallback also fails from the runner's /tmp location) → exit 3,
    // BEFORE the pkg read + sentinel write.  The orchestrator treats the absent
    // marker as fail-closed, so an unresolvable run-script can never silently ship.
    writeProjPkg({ prepare: "node -e ''" });
    const badCli = join(dir, 'no-such-npm', 'bin', 'npm-cli.js');
    const { status, events, marker } = runRunner({ npm_execpath: badCli });
    expect(status).toBe(3);
    expect(events).toEqual([]);
    expect(marker).toBe(false);
  });
});

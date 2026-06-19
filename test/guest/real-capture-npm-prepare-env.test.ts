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
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
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

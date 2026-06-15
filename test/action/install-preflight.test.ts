// script-jail — test/action/install-preflight.test.ts
//
// Unit tests for the `install: true` pre-trust config-exec detector.  Each
// vector was empirically reproduced against pnpm 10.34/11.1 and yarn Berry 4.16
// (see the module header); these tests pin the static detection that refuses
// install before any of that code can run on the runner.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { detectPreTrustConfigExec } from '../../src/action/install-preflight.js';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sj-preflight-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const write = (rel: string, content: string): void => {
  const full = join(dir, rel);
  mkdirSync(join(full, '..'), { recursive: true });
  writeFileSync(full, content);
};

describe('detectPreTrustConfigExec — npm', () => {
  it('returns null even with a .pnpmfile.cjs / .yarnrc.yml present (npm ignores both)', () => {
    write('.pnpmfile.cjs', 'module.exports = {}');
    write('.yarnrc.yml', 'yarnPath: ./x.cjs\n');
    // npm has no pnpmfile/yarnrc surface; its only pre-trust config exec (the git
    // binary) is handled by the npm_config_git pin, not here.
    expect(detectPreTrustConfigExec(dir, 'npm')).toBeNull();
  });
});

describe('detectPreTrustConfigExec — pnpm', () => {
  it('blocks a default .pnpmfile.cjs', () => {
    write('.pnpmfile.cjs', 'console.log("hi")');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/\.pnpmfile\.cjs/);
  });

  it('does NOT block a dot-less pnpmfile.cjs (not a pnpm default)', () => {
    write('pnpmfile.cjs', 'console.log("hi")');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a .npmrc pnpmfile= relocation', () => {
    write('.npmrc', 'pnpmfile=./evil.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpmfile/);
  });

  it('blocks a .npmrc global-pnpmfile= relocation (case/space tolerant)', () => {
    write('.npmrc', '  Global-Pnpmfile = ./evil.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/global-pnpmfile/i);
  });

  it('ignores a commented-out pnpmfile= line', () => {
    write('.npmrc', '; pnpmfile=./evil.cjs\n# global-pnpmfile=./x\nregistry=https://r/\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a pnpm-workspace.yaml pnpmfile: key', () => {
    write('pnpm-workspace.yaml', 'pnpmfile: ./evil.cjs\npackages:\n  - "pkgs/*"\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpm-workspace\.yaml/);
  });

  it('blocks a pnpm-workspace.yaml configDependencies: key', () => {
    write('pnpm-workspace.yaml', 'configDependencies:\n  my-cfg: 1.0.0+sha512-x\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpm-workspace\.yaml/);
  });

  it('fails closed on an unparseable pnpm-workspace.yaml', () => {
    write('pnpm-workspace.yaml', 'pnpmfile: : : [unbalanced\n  - {');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/unparseable/);
  });

  it('blocks a package.json pnpm.configDependencies (pnpm 10 fetch/extract vector)', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { configDependencies: { 'my-cfg': '1.0.0+sha512-deadbeef' } } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.json/);
  });

  it('blocks a package.json pnpm.pnpmfile (defense in depth)', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { pnpmfile: './evil.cjs' } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.json/);
  });

  it('fails closed on an unparseable package.json', () => {
    write('package.json', '{ not: valid json ');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/unparseable root .package\.json/);
  });

  it('does NOT block a package.json with a benign pnpm block', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { onlyBuiltDependencies: ['esbuild'] } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('returns null for a clean pnpm repo (lock + plain workspace, no hooks)', () => {
    write('package.json', '{"name":"x"}');
    write('pnpm-workspace.yaml', 'packages:\n  - "pkgs/*"\n');
    write('.npmrc', 'registry=https://registry.npmjs.org/\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });
});

describe('detectPreTrustConfigExec — yarn (Berry)', () => {
  it('blocks .yarnrc.yml yarnPath', () => {
    write('.yarnrc.yml', 'yarnPath: ./.evil-yarn.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/yarnPath/);
  });

  it('blocks .yarnrc.yml plugins (object form)', () => {
    write('.yarnrc.yml', 'plugins:\n  - path: ./p.cjs\n    spec: "@x/y"\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/plugins/);
  });

  it('blocks .yarnrc.yml plugins (string form)', () => {
    write('.yarnrc.yml', 'plugins:\n  - ./p.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/plugins/);
  });

  it('does NOT block an empty plugins array', () => {
    write('.yarnrc.yml', 'plugins: []\nnodeLinker: node-modules\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('blocks enableConstraintsChecks:true WHEN a yarn.config.cjs is present', () => {
    write('.yarnrc.yml', 'enableConstraintsChecks: true\n');
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/enableConstraintsChecks/);
  });

  it('does NOT block enableConstraintsChecks:true without a yarn.config file (hook no-ops)', () => {
    write('.yarnrc.yml', 'enableConstraintsChecks: true\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('does NOT block a yarn.config.cjs when the flag is off (default false)', () => {
    write('.yarnrc.yml', 'nodeLinker: node-modules\n');
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('fails closed on a present-but-unparseable .yarnrc.yml', () => {
    write('.yarnrc.yml', 'yarnPath: : : [unbalanced\n  - {');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/unparseable/);
  });

  it('returns null when there is no .yarnrc.yml (classic .yarnrc is not a Berry vector)', () => {
    write('.yarnrc', 'yarn-path "./x.js"\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('returns null for a clean Berry repo (benign .yarnrc.yml)', () => {
    write('.yarnrc.yml', 'nodeLinker: node-modules\nenableTelemetry: false\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });
});

// script-jail — test/scripts/assert-npm-packlist.test.ts
//
// PKG-2 guard for scripts/assert-npm-packlist.mjs — the per-package publish
// gate. npm silently omits missing `files` entries, so `npm pack --dry-run`
// alone is not a release gate; this script reads the staged package's name,
// looks up its canonical spec via scripts/npm-packages.mjs, expands the spec's
// `files`, and asserts the `npm pack --dry-run --json` output matches exactly —
// plus the VZ-helper exec bit (darwin-arm64 only) and the per-package size cap.
// The main package lists its preloads EXPLICITLY (not a glob) so a dropped
// preload is caught here rather than slipping silently into a release.
//
// These tests drive the script via child_process (it shells out to `npm pack`,
// consistent with check-publish-artifacts.test.ts) over dummy staging dirs
// built from the canonical npm-packages.mjs spec. `npm` must be on PATH.
//
// IMPORTANT (LOW fix WS2 reviewer #3): the only mode assertion is the 0o755
// exec bit on the darwin VZ helper `script-jail-vm`. `npm pack --dry-run
// --json` reports the main package's `dist/cli.cjs` at 0o644 even though it is
// the `bin` target (npm flips the exec bit at install time), so the main
// package's bin must NOT be asserted at 0o755. The "cli reported at 0o644"
// test below pins that expectation so a contributor does not add a wrong check.

import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  chmodSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { npmPackages } from '../../scripts/npm-packages.mjs';
import type { NpmPackageSpec } from '../../scripts/npm-packages.mjs';

const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const SCRIPT = join(repoRoot, 'scripts/assert-npm-packlist.mjs');
const VERSION = '0.1.0';

const tempDirs: string[] = [];

afterAll(() => {
  for (const d of tempDirs) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

function spec(name: string): NpmPackageSpec {
  const pkg = npmPackages(VERSION).find((p) => p.name === name);
  if (!pkg) throw new Error(`expected npm package ${name}`);
  return pkg;
}

function writeFileAt(dir: string, rel: string, bytes: string, mode = 0o644): void {
  const abs = join(dir, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, bytes);
  chmodSync(abs, mode);
}

// Materialize a staging dir for the named package using dummy file content.
// Every `files` entry is an explicit path (the main package enumerates its
// preloads), so each one is written directly.
function stagePackage(name: string): string {
  const pkg = spec(name);
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-packlist-'));
  tempDirs.push(dir);

  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify(pkg.packageJson, null, 2) + '\n',
  );

  for (const file of pkg.packageJson.files as string[]) {
    // The VZ helper ships executable; everything else at 0o644.
    const mode = file === 'script-jail-vm' ? 0o755 : 0o644;
    writeFileAt(dir, file, `dummy:${file}`, mode);
  }

  return dir;
}

function runPacklist(dir: string, args: string[] = [], env: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

describe('assert-npm-packlist.mjs (PKG-2)', () => {
  it('passes a valid darwin-arm64 staging dir (default cwd)', () => {
    const dir = stagePackage('@script-jail/darwin-arm64');
    const result = runPacklist(dir);
    expect(`${result.stdout}${result.stderr}`).toBeTruthy();
    expect(result.status).toBe(0);
  });

  it('fails when the VZ helper is not executable (mode 0o644)', () => {
    const dir = stagePackage('@script-jail/darwin-arm64');
    chmodSync(join(dir, 'script-jail-vm'), 0o644);
    const result = runPacklist(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(/executable|0755|0o755/i);
  });

  it('fails with a file-list mismatch when a required artifact is missing', () => {
    const dir = stagePackage('@script-jail/darwin-arm64');
    rmSync(join(dir, 'libscriptjail-arm64.so'));
    const result = runPacklist(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(/file list mismatch/i);
  });

  it('passes the main package with all three preloads (explicit list)', () => {
    const dir = stagePackage('script-jail');
    // npm pack reports 7 files: README, cli.cjs, guest-agent.cjs, 3 preloads,
    // package.json — the main spec enumerates the three preloads explicitly.
    const pack = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: dir,
      encoding: 'utf8',
    });
    const paths = (JSON.parse(pack.stdout)[0].files as Array<{ path: string }>).map(
      (f) => f.path,
    );
    expect(paths).toContain('dist/preloads/env-spy.cjs');
    expect(paths).toContain('dist/preloads/platform-spoof.cjs');
    expect(paths).toContain('dist/preloads/dlopen-block.cjs');
    // And the script accepts the package.
    expect(runPacklist(dir).status).toBe(0);
  });

  it('fails the main package when a required preload is missing', () => {
    // Preloads are listed explicitly in the spec, so a dropped preload is a
    // file-list mismatch (npm pack omits the missing file; the expected list
    // still requires it). This is the regression guard for the glob bug.
    const dir = stagePackage('script-jail');
    rmSync(join(dir, 'dist/preloads/platform-spoof.cjs'));
    const result = runPacklist(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(/file list mismatch/i);
  });

  it('fails the main package when an explicit JS bundle is missing', () => {
    const dir = stagePackage('script-jail');
    rmSync(join(dir, 'dist/guest-agent.cjs'));
    const result = runPacklist(dir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(/file list mismatch/i);
  });

  it('reports the main package bin (dist/cli.cjs) at mode 0o644, not 0o755', () => {
    // npm pack --dry-run --json reports dist/cli.cjs at 0o644 even though it is
    // the `bin` target (npm sets the exec bit at install time). The script must
    // NOT over-assert 0o755 on main — the only 0o755 check is script-jail-vm.
    const dir = stagePackage('script-jail');
    const pack = spawnSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: dir,
      encoding: 'utf8',
    });
    expect(pack.status).toBe(0);
    const files = JSON.parse(pack.stdout)[0].files as Array<{
      path: string;
      mode: number;
    }>;
    const cli = files.find((f) => f.path === 'dist/cli.cjs');
    expect(cli?.mode).toBe(0o644);
    // And the script accepts it (does not fail on the bin's non-exec mode).
    expect(runPacklist(dir).status).toBe(0);
  });

  it('fails when the packed size exceeds SCRIPT_JAIL_NPM_MAX_PACK_BYTES', () => {
    const dir = stagePackage('@script-jail/linux-x64');
    const result = runPacklist(dir, [], {
      SCRIPT_JAIL_NPM_MAX_PACK_BYTES: '10',
    });
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(/exceeds limit|exceeds/i);
  });

  it('--all loops over every staged package in a staging root', () => {
    const root = mkdtempSync(join(tmpdir(), 'script-jail-staging-'));
    tempDirs.push(root);
    for (const pkg of npmPackages(VERSION)) {
      stageInto(join(root, pkg.dir), pkg);
    }
    const result = runPacklist(root, ['--all', root]);
    expect(result.status).toBe(0);
  });

  it('--all fails when any single package is invalid', () => {
    const root = mkdtempSync(join(tmpdir(), 'script-jail-staging-'));
    tempDirs.push(root);
    for (const pkg of npmPackages(VERSION)) {
      stageInto(join(root, pkg.dir), pkg);
    }
    // Break the darwin VZ helper exec bit in one of the staged packages.
    chmodSync(join(root, 'script-jail-darwin-arm64', 'script-jail-vm'), 0o644);
    const result = runPacklist(root, ['--all', root]);
    expect(result.status).not.toBe(0);
  });

  it('--all fails when a canonical package dir is missing (no silent partial publish)', () => {
    // An incomplete staging would otherwise pass the gate and cause a
    // non-rerunnable partial npm publish. Stage only 3 of the 4 canonical dirs.
    const root = mkdtempSync(join(tmpdir(), 'script-jail-staging-'));
    tempDirs.push(root);
    for (const pkg of npmPackages(VERSION)) {
      if (pkg.name === 'script-jail') continue; // omit the main package dir
      stageInto(join(root, pkg.dir), pkg);
    }
    const result = runPacklist(root, ['--all', root]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(
      /do not match the canonical set[\s\S]*missing:\s+script-jail\b/i,
    );
  });

  it('--all fails on an unexpected extra dir under the staging root', () => {
    const root = mkdtempSync(join(tmpdir(), 'script-jail-staging-'));
    tempDirs.push(root);
    for (const pkg of npmPackages(VERSION)) {
      stageInto(join(root, pkg.dir), pkg);
    }
    mkdirSync(join(root, 'script-jail-bogus-extra'), { recursive: true });
    const result = runPacklist(root, ['--all', root]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(
      /unexpected:\s+script-jail-bogus-extra/i,
    );
  });
});

// Stage a package directly into an arbitrary directory (for the --all root).
function stageInto(dir: string, pkg: NpmPackageSpec): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify(pkg.packageJson, null, 2) + '\n',
  );
  for (const file of pkg.packageJson.files as string[]) {
    const mode = file === 'script-jail-vm' ? 0o755 : 0o644;
    writeFileAt(dir, file, `dummy:${file}`, mode);
  }
}

// script-jail — test/scripts/assemble-npm-packages.test.ts
//
// PKG-3 guard for scripts/assemble-npm-packages.mjs — the release-time stager
// that turns the CI build artifacts into four ready-to-publish package dirs.
//
// For each package in the canonical spec (scripts/npm-packages.mjs) the script:
//   - writes a clean published `package.json` (2-space indent + trailing
//     newline) into <stagingRoot>/<sanitizedDir>/,
//   - for the main package, derives the manifest from the repo-root
//     package.json (overwriting `files`/`optionalDependencies`, dropping
//     devDependencies/scripts/packageManager) and copies the committed JS
//     bundles from <artifacts>/dist/... plus the repo README,
//   - for the platform packages, gzips (zlib, fixed level — run-to-run
//     deterministic, NOT byte-identical to GNU `gzip -n`) or copies each
//     artifact from <artifacts>/<src> into the staged dir, applying the
//     spec mode (0o755 for the VZ helper, else 0o644).
//
// These tests drive the script via child_process over a FAKE artifacts dir of
// dummy bytes, consistent with the other scripts/* tests.

import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  statSync,
  rmSync,
} from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { npmPackages } from '../../scripts/npm-packages.mjs';

const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const SCRIPT = join(repoRoot, 'scripts/assemble-npm-packages.mjs');
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

function mkTmp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeAt(dir: string, rel: string, bytes: string): void {
  const abs = join(dir, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, bytes);
}

// Materialize a fake CI artifacts dir matching the release-job layout:
//   artifacts/dist/{cli,guest-agent}.cjs, artifacts/dist/preloads/*.cjs
//   artifacts/images/<rootfs ext4 | *.so | vmlinux-vz-arm64>
//   artifacts/script-jail-vm-arm64-darwin   (root, from build-mac-bin)
// Returns { dir, sources } where sources maps each platform artifact `src`
// (relative to the artifacts dir) to the dummy bytes written.
function makeArtifacts(): { dir: string; sources: Map<string, string> } {
  const dir = mkTmp('script-jail-assemble-art-');
  const sources = new Map<string, string>();

  // Main package JS bundles.
  writeAt(dir, 'dist/cli.cjs', 'cli-bundle');
  writeAt(dir, 'dist/guest-agent.cjs', 'guest-agent-bundle');
  writeAt(dir, 'dist/preloads/env-spy.cjs', 'env-spy');
  writeAt(dir, 'dist/preloads/platform-spoof.cjs', 'platform-spoof');
  writeAt(dir, 'dist/preloads/dlopen-block.cjs', 'dlopen-block');

  // Every platform-artifact source across all packages.
  for (const pkg of npmPackages(VERSION)) {
    for (const art of pkg.artifacts) {
      if (sources.has(art.src)) continue;
      const bytes = `dummy-bytes-for:${art.src}`;
      writeAt(dir, art.src, bytes);
      sources.set(art.src, bytes);
    }
  }

  return { dir, sources };
}

function runAssemble(args: string[]) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8',
    env: { ...process.env },
  });
}

function assemble(out: string, artifactsDir: string) {
  return runAssemble([
    '--artifacts',
    artifactsDir,
    '--out',
    out,
    '--version',
    VERSION,
  ]);
}

describe('assemble-npm-packages.mjs (PKG-3)', () => {
  it('stages all four package dirs from the canonical spec', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    const result = assemble(out, artifactsDir);
    expect(`${result.stdout}${result.stderr}`).toBeTruthy();
    expect(result.status).toBe(0);

    for (const pkg of npmPackages(VERSION)) {
      const pkgDir = join(out, pkg.dir);
      expect(existsSync(pkgDir), `${pkg.dir} should exist`).toBe(true);
      expect(existsSync(join(pkgDir, 'package.json'))).toBe(true);
    }
  });

  it('writes each package.json with correct name/version/os/cpu/files/optionalDeps', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    expect(assemble(out, artifactsDir).status).toBe(0);

    for (const pkg of npmPackages(VERSION)) {
      const raw = readFileSync(join(out, pkg.dir, 'package.json'), 'utf8');
      // 2-space indent + trailing newline.
      expect(raw.endsWith('\n')).toBe(true);
      expect(raw).toContain('\n  "');
      const manifest = JSON.parse(raw);
      expect(manifest.name).toBe(pkg.name);
      expect(manifest.version).toBe(VERSION);
      expect(manifest.files).toEqual(pkg.packageJson.files);

      if (pkg.name === 'script-jail') {
        // Main: no os/cpu; optionalDependencies all pinned to the version.
        expect(manifest.os).toBeUndefined();
        expect(manifest.cpu).toBeUndefined();
        expect(manifest.optionalDependencies).toEqual({
          '@script-jail/darwin-arm64': VERSION,
          '@script-jail/linux-x64': VERSION,
          '@script-jail/linux-arm64': VERSION,
        });
        // Clean published manifest: dev-only fields dropped.
        expect(manifest.devDependencies).toBeUndefined();
        expect(manifest.scripts).toBeUndefined();
        expect(manifest.packageManager).toBeUndefined();
        // Kept fields.
        expect(manifest.bin).toEqual({ 'script-jail': 'dist/cli.cjs' });
      } else {
        // Platform packages carry os/cpu and no optionalDependencies.
        expect(manifest.os).toEqual(pkg.packageJson.os);
        expect(manifest.cpu).toEqual(pkg.packageJson.cpu);
        expect(manifest.optionalDependencies).toBeUndefined();
      }
    }
  });

  it('makes the darwin VZ helper executable (mode & 0o755)', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    expect(assemble(out, artifactsDir).status).toBe(0);

    const helper = join(out, 'script-jail-darwin-arm64', 'script-jail-vm');
    expect(existsSync(helper)).toBe(true);
    expect(statSync(helper).mode & 0o755).toBe(0o755);
  });

  it('gzips every rootfs into a *.ext4.gz with gzip magic that gunzips back', () => {
    const { dir: artifactsDir, sources } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    expect(assemble(out, artifactsDir).status).toBe(0);

    for (const pkg of npmPackages(VERSION)) {
      for (const art of pkg.artifacts) {
        const dest = join(out, pkg.dir, art.dest);
        expect(existsSync(dest), `${pkg.dir}/${art.dest}`).toBe(true);
        const bytes = readFileSync(dest);
        if (art.gzip) {
          expect(art.dest.endsWith('.ext4.gz')).toBe(true);
          // gzip magic 0x1f 0x8b.
          expect(bytes[0]).toBe(0x1f);
          expect(bytes[1]).toBe(0x8b);
          const expected = sources.get(art.src)!;
          expect(gunzipSync(bytes).toString('utf8')).toBe(expected);
        } else {
          // Plain copy.
          expect(bytes.toString('utf8')).toBe(sources.get(art.src));
        }
      }
    }
  });

  it('stages the main package with JS bundles + README and no images/', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    expect(assemble(out, artifactsDir).status).toBe(0);

    const mainDir = join(out, 'script-jail');
    expect(existsSync(join(mainDir, 'dist/cli.cjs'))).toBe(true);
    expect(existsSync(join(mainDir, 'dist/guest-agent.cjs'))).toBe(true);
    expect(existsSync(join(mainDir, 'dist/preloads/env-spy.cjs'))).toBe(true);
    expect(existsSync(join(mainDir, 'dist/preloads/platform-spoof.cjs'))).toBe(
      true,
    );
    expect(existsSync(join(mainDir, 'dist/preloads/dlopen-block.cjs'))).toBe(
      true,
    );
    expect(existsSync(join(mainDir, 'README.md'))).toBe(true);
    // No runtime images leaked into main.
    expect(existsSync(join(mainDir, 'images'))).toBe(false);
  });

  it('produces byte-identical gz across two runs (deterministic gzip)', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const outA = mkTmp('script-jail-assemble-a-');
    const outB = mkTmp('script-jail-assemble-b-');
    expect(assemble(outA, artifactsDir).status).toBe(0);
    expect(assemble(outB, artifactsDir).status).toBe(0);

    const gz = join(
      'script-jail-linux-x64',
      'rootfs-ubuntu-24.04.ext4.gz',
    );
    const a = readFileSync(join(outA, gz));
    const b = readFileSync(join(outB, gz));
    expect(a.equals(b)).toBe(true);
  });

  it('fails naming a missing artifact', () => {
    const { dir: artifactsDir } = makeArtifacts();
    rmSync(join(artifactsDir, 'images/libscriptjail.so'));
    const out = mkTmp('script-jail-assemble-out-');
    const result = assemble(out, artifactsDir);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toMatch(
      /images\/libscriptjail\.so/,
    );
  });

  it('produces dirs that pass assert-npm-packlist.mjs (end-to-end)', () => {
    const { dir: artifactsDir } = makeArtifacts();
    const out = mkTmp('script-jail-assemble-out-');
    expect(assemble(out, artifactsDir).status).toBe(0);

    const packlist = join(repoRoot, 'scripts/assert-npm-packlist.mjs');
    for (const pkg of npmPackages(VERSION)) {
      const result = spawnSync(process.execPath, [packlist, join(out, pkg.dir)], {
        encoding: 'utf8',
        env: { ...process.env },
      });
      expect(
        result.status,
        `assert-npm-packlist for ${pkg.name}: ${result.stdout}${result.stderr}`,
      ).toBe(0);
    }
  });
});

// script-jail — test/scripts/check-publish-artifacts.test.ts
//
// Unit tests for scripts/check-publish-artifacts.sh — the publish-job gate
// that verifies the downloaded build artifacts' SHA-256 digests against the
// tagged source's `src/action/artifact-manifest.ts` (and, for dist/main.js,
// the tagged source's dist/main.js itself).
//
// The script is shell, not TS, because the release workflow's publish job
// deliberately runs WITHOUT `pnpm install` — see the file header in
// scripts/check-publish-artifacts.sh.  These tests drive the script via
// child_process so we exercise the same code path the workflow does.
//
// Each test sets up an isolated temp directory with:
//   - a synthetic manifest file (subset of the real artifact-manifest.ts schema),
//   - dummy artifact files under images/ and dist/,
//   - optionally a dist-source file to compare dist/main.js against.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Resolve the script path from the repo root.
const repoRoot = new URL('../../', import.meta.url).pathname.replace(
  /\/$/,
  '',
);
const SCRIPT = join(repoRoot, 'scripts/check-publish-artifacts.sh');

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

function makeWorkspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-checkpub-'));
  tempDirs.push(dir);
  mkdirSync(join(dir, 'src/action'), { recursive: true });
  mkdirSync(join(dir, 'art/images'), { recursive: true });
  mkdirSync(join(dir, 'art/dist'), { recursive: true });
  return dir;
}

function sha256(bytes: string | Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

interface ManifestEntries {
  rootfs22: string;
  rootfs24: string;
  libso: string;
}

function writeManifest(workspace: string, entries: ManifestEntries): string {
  const path = join(workspace, 'src/action/artifact-manifest.ts');
  // Match the real file's exact layout (single-quoted keys + values) so the
  // shell regex parser exercises the same surface area as in production.
  const contents = [
    "import type { ArtifactManifest } from './pre-fetch-artifacts.js';",
    '',
    'export const PINNED_MANIFEST: ArtifactManifest = {',
    "  repo: 'brooklyn/script-jail',",
    "  tag: 'v0.0.0',",
    '  expected: {',
    `    'rootfs-ubuntu-22.04.ext4': '${entries.rootfs22}',`,
    `    'rootfs-ubuntu-24.04.ext4': '${entries.rootfs24}',`,
    `    'libscriptjail.so':              '${entries.libso}',`,
    '  },',
    '};',
    '',
  ].join('\n');
  writeFileSync(path, contents, 'utf8');
  return path;
}

interface ArtifactBytes {
  rootfs22: string;
  rootfs24: string;
  libso: string;
  dist: string;
}

function writeArtifacts(workspace: string, bytes: ArtifactBytes): {
  dir: string;
  shas: ArtifactBytes;
} {
  const dir = join(workspace, 'art');
  writeFileSync(join(dir, 'images/rootfs-ubuntu-22.04.ext4'), bytes.rootfs22);
  writeFileSync(join(dir, 'images/rootfs-ubuntu-24.04.ext4'), bytes.rootfs24);
  writeFileSync(join(dir, 'images/libscriptjail.so'), bytes.libso);
  writeFileSync(join(dir, 'dist/main.js'), bytes.dist);
  return {
    dir,
    shas: {
      rootfs22: sha256(bytes.rootfs22),
      rootfs24: sha256(bytes.rootfs24),
      libso: sha256(bytes.libso),
      dist: sha256(bytes.dist),
    },
  };
}

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runScript(args: string[]): RunResult {
  const result = spawnSync('bash', [SCRIPT, ...args], {
    encoding: 'utf8',
    timeout: 10_000,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

// Sanity check: the script and a sha256sum binary must be available.  All
// real CI runners (and our dev hosts via coreutils) ship sha256sum.
beforeAll(() => {
  const probe = spawnSync('sha256sum', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    throw new Error(
      'sha256sum is required to run these tests; install GNU coreutils.',
    );
  }
});

describe('scripts/check-publish-artifacts.sh', () => {
  it('exits 0 with a warning when the manifest is all placeholders (bootstrap)', () => {
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, {
      rootfs22: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
      rootfs24: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_24_04',
      libso: 'PLACEHOLDER_SHA256_LIBSCRIPTJAIL_SO',
    });
    const { dir } = writeArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    });

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(0);
    // The warning is emitted on stdout (GitHub Actions ::warning:: syntax).
    expect(r.stdout).toMatch(/::warning::/);
    expect(r.stdout).toMatch(/bootstrap path/);
  });

  it('exits 0 when every artifact SHA matches the manifest', () => {
    const ws = makeWorkspace();
    const bytes: ArtifactBytes = {
      rootfs22: 'rootfs22-bytes',
      rootfs24: 'rootfs24-bytes',
      libso: 'libscriptjail-bytes',
      dist: 'dist-main-bytes',
    };
    const { dir, shas } = writeArtifacts(ws, bytes);
    const manifestPath = writeManifest(ws, {
      rootfs22: shas.rootfs22,
      rootfs24: shas.rootfs24,
      libso: shas.libso,
    });

    // Provide a dist-source whose contents match the artifact so dist/main.js
    // verification also passes.
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, bytes.dist);

    const r = runScript([
      '--manifest',
      manifestPath,
      '--dir',
      dir,
      '--dist-source',
      distSource,
    ]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
  });

  it('exits 1 and names the offending artifact when a SHA mismatches', () => {
    const ws = makeWorkspace();
    const bytes: ArtifactBytes = {
      rootfs22: 'actual-22-bytes',
      rootfs24: 'rootfs24-bytes',
      libso: 'libscriptjail-bytes',
      dist: 'dist-main-bytes',
    };
    const { dir, shas } = writeArtifacts(ws, bytes);
    // Lie about the 22.04 rootfs SHA — pretend it's all-a's instead.
    const wrong = 'a'.repeat(64);
    const manifestPath = writeManifest(ws, {
      rootfs22: wrong,
      rootfs24: shas.rootfs24,
      libso: shas.libso,
    });

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/SHA mismatch/);
    expect(r.stderr).toMatch(/rootfs-ubuntu-22\.04\.ext4/);
    expect(r.stderr).toMatch(new RegExp(`expected=${wrong}`));
    expect(r.stderr).toMatch(new RegExp(`computed=${shas.rootfs22}`));
  });

  it('exits 1 when the manifest mixes placeholders with real SHAs (packaging bug)', () => {
    const ws = makeWorkspace();
    const bytes: ArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeArtifacts(ws, bytes);
    // One placeholder + one real-but-mismatching real SHA (and one real-matching).
    const wrong = 'b'.repeat(64);
    const manifestPath = writeManifest(ws, {
      rootfs22: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
      rootfs24: wrong, // real-looking but wrong
      libso: shas.libso, // real, matching
    });

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/mixed with/);
    // It must NOT be the bootstrap branch — no GitHub warning should appear
    // on stdout, and no comparison should run.
    expect(r.stdout).not.toMatch(/::warning::/);
  });

  it('verifies dist/main.js even in bootstrap mode (mismatch hard-fails)', () => {
    // Regression test for adversarial-review finding: a build-job
    // compromise could swap dist/main.js while the manifest is in bootstrap
    // mode.  The fresh-checkout dist/main.js is an independent reference,
    // so this comparison must run regardless of manifest-placeholder state.
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, {
      rootfs22: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
      rootfs24: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_24_04',
      libso: 'PLACEHOLDER_SHA256_LIBSCRIPTJAIL_SO',
    });
    const { dir } = writeArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'tampered-dist-bytes', // pretend the build job's dist was swapped
    });
    // The fresh-checkout dist/main.js holds the trusted bytes.
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, 'trusted-dist-bytes');

    const r = runScript([
      '--manifest',
      manifestPath,
      '--dir',
      dir,
      '--dist-source',
      distSource,
    ]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/dist\/main\.js mismatch/);
    expect(r.stderr).toMatch(/refusing to publish/);
  });

  it('verifies dist/main.js in bootstrap mode (match exits 0 with warning)', () => {
    // Companion to the test above: bootstrap mode + matching dist should
    // still succeed (otherwise the bootstrap loop is broken).
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, {
      rootfs22: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
      rootfs24: 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_24_04',
      libso: 'PLACEHOLDER_SHA256_LIBSCRIPTJAIL_SO',
    });
    const distBytes = 'trusted-dist-bytes';
    const { dir } = writeArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: distBytes,
    });
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, distBytes);

    const r = runScript([
      '--manifest',
      manifestPath,
      '--dir',
      dir,
      '--dist-source',
      distSource,
    ]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/::warning::/);
  });

  it('rejects a manifest with a duplicate key in the expected block', () => {
    // Regression test for adversarial-review finding: a duplicated entry
    // (e.g. from a bad merge) MUST fail the parser instead of silently
    // picking one value.  Otherwise an attacker who can land a second
    // poisoned line wins.
    const ws = makeWorkspace();
    const bytes: ArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeArtifacts(ws, bytes);
    // Hand-write a manifest with `rootfs-ubuntu-22.04.ext4` appearing twice.
    const manifestPath = join(ws, 'src/action/artifact-manifest.ts');
    const contents = [
      'export const PINNED_MANIFEST: ArtifactManifest = {',
      "  repo: 'brooklyn/script-jail',",
      "  tag: 'v0.0.0',",
      '  expected: {',
      `    'rootfs-ubuntu-22.04.ext4': '${shas.rootfs22}',`,
      `    'rootfs-ubuntu-22.04.ext4': '${'f'.repeat(64)}',`, // duplicate
      `    'rootfs-ubuntu-24.04.ext4': '${shas.rootfs24}',`,
      `    'libscriptjail.so':              '${shas.libso}',`,
      '  },',
      '};',
      '',
    ].join('\n');
    writeFileSync(manifestPath, contents, 'utf8');

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(
      /manifest key 'rootfs-ubuntu-22\.04\.ext4' appears 2 times/,
    );
  });

  it('ignores commented-out example entries outside the expected block', () => {
    // Regression test for adversarial-review finding: the parser must
    // scope to PINNED_MANIFEST.expected and not pick up stray lines from
    // comments or unrelated maps elsewhere in the source.  We construct a
    // manifest where a comment ABOVE the block carries a placeholder-like
    // entry — the real entry inside the block must still win.
    const ws = makeWorkspace();
    const bytes: ArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeArtifacts(ws, bytes);

    const manifestPath = join(ws, 'src/action/artifact-manifest.ts');
    const contents = [
      '// Example (do not remove):',
      "//   'rootfs-ubuntu-22.04.ext4': 'PLACEHOLDER_SHA256_DECOY',",
      '',
      'export const PINNED_MANIFEST: ArtifactManifest = {',
      "  repo: 'brooklyn/script-jail',",
      "  tag: 'v0.0.0',",
      '  expected: {',
      `    'rootfs-ubuntu-22.04.ext4': '${shas.rootfs22}',`,
      `    'rootfs-ubuntu-24.04.ext4': '${shas.rootfs24}',`,
      `    'libscriptjail.so':              '${shas.libso}',`,
      '  },',
      '};',
      '',
    ].join('\n');
    writeFileSync(manifestPath, contents, 'utf8');

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    // Real entries are valid SHAs; the comment must NOT have poisoned the
    // parser into bootstrap mode or into a mismatch.
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
    expect(r.stdout).not.toMatch(/::warning::/);
  });

  it('exits 1 when a required artifact file is missing', () => {
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, {
      rootfs22: 'c'.repeat(64),
      rootfs24: 'd'.repeat(64),
      libso: 'e'.repeat(64),
    });
    // Do NOT call writeArtifacts — the art/ tree is empty but the dirs exist.
    const dir = join(ws, 'art');

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/required artifact\(s\) missing/);
  });
});

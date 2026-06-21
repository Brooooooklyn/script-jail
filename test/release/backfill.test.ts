// script-jail — test/release/backfill.test.ts
//
// Unit tests for the release-backfill core (src/release/backfill.ts).  No
// network: synthetic staged trees built with mkdtemp + tiny byte strings, the
// committed trimmed buildx-push log fixture, and the byte-oracle codegen
// round-trip against the committed manifest at git commit 2140b6d.

import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import {
  assertOfflineInputsConsistent,
  assertRepo,
  assertRunId,
  bumpVersion,
  computeManifestExpected,
  parseDockerDigestsFromLog,
  prepareCleanStagingDir,
  renderArtifactManifestTs,
  selectBuildJobId,
} from '../../src/release/backfill.js';
import type { ArtifactManifest } from '../../src/action/pre-fetch-artifacts.js';
import { canonicalRootfsHash } from '../../src/rootfs/repro-hash.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, 'fixtures');

const tmpDirs: string[] = [];
function freshTmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'sj-backfill-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

const HEX64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// Synthetic staged-tree builder
// ---------------------------------------------------------------------------
//
// The 12 file artifacts in the manifest, with where each lands in the staged
// tree.  We write a tiny distinct byte string per file (keyed by name so the
// content — and therefore the digest — is unique per artifact).

const STAGED_ARTIFACTS: ReadonlyArray<{
  key: string;
  under: 'images' | 'root';
  ext4: boolean;
}> = [
  { key: 'rootfs-ubuntu-22.04.ext4', under: 'images', ext4: true },
  { key: 'rootfs-ubuntu-24.04.ext4', under: 'images', ext4: true },
  { key: 'libscriptjail.so', under: 'images', ext4: false },
  { key: 'rootfs-ubuntu-22.04-arm64.ext4', under: 'images', ext4: true },
  { key: 'rootfs-ubuntu-24.04-arm64.ext4', under: 'images', ext4: true },
  { key: 'libscriptjail-arm64.so', under: 'images', ext4: false },
  { key: 'libscriptjail-arm64.dylib', under: 'root', ext4: false },
  { key: 'coreutils-arm64', under: 'root', ext4: false },
  { key: 'bash-arm64', under: 'root', ext4: false },
  { key: 'vmlinux-vz-x86_64', under: 'images', ext4: false },
  { key: 'vmlinux-vz-arm64', under: 'images', ext4: false },
  { key: 'script-jail-vm-arm64-darwin', under: 'root', ext4: false },
];

/** A small fixed-byte buffer for an artifact (distinct per key). */
function fixtureBytes(key: string): Buffer {
  // 8 KiB of repeated, key-derived bytes so ext4 files are large enough that
  // `ext4VolatileByteRanges` finds the primary superblock (offset 1024) inside
  // the image — proving the canonical path actually masks something.
  const seed = createHash('sha256').update(key).digest();
  const buf = Buffer.alloc(8192);
  for (let i = 0; i < buf.length; i++) buf[i] = seed[i % seed.length]!;
  return buf;
}

function buildStagedDir(opts: { omit?: string } = {}): string {
  const dir = freshTmp();
  mkdirSync(join(dir, 'images'), { recursive: true });
  for (const art of STAGED_ARTIFACTS) {
    if (opts.omit === art.key) continue;
    const path =
      art.under === 'images' ? join(dir, 'images', art.key) : join(dir, art.key);
    writeFileSync(path, fixtureBytes(art.key));
  }
  return dir;
}

function plainSha(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

// ---------------------------------------------------------------------------
// The v0.2.5 manifest struct — the 16 values read from `git show 2140b6d`.
// ---------------------------------------------------------------------------

const V025_MANIFEST: ArtifactManifest = {
  repo: 'Brooooooklyn/script-jail',
  tag: 'v0.2.5',
  expected: {
    linux: {
      'rootfs-ubuntu-22.04.ext4':
        '9135bc1fb3228add3a647567ca6658fb042d1ce93ac21d56ecc84dec06c07750',
      'rootfs-ubuntu-24.04.ext4':
        '7f3e916aa6e2e974ee8d2cf4e25d2813cd2b2bc63e9728f84e9207d336252f13',
      'libscriptjail.so':
        '00ad21620189c80228d46ecf50009350906660ee0fd68e0f695108fdccd48251',
    },
    darwin: {
      'rootfs-ubuntu-22.04-arm64.ext4':
        'a6d6a716f4a60b6d5fc80d314f30441819f7cc8cf355b02efdf87141d4906d3a',
      'rootfs-ubuntu-24.04-arm64.ext4':
        '3460b2c2626e23da5d9efd405c48fdc09195dde2f88d3a06bff58a6d4aa8212f',
      'libscriptjail-arm64.so':
        '865379b96a5b5b79af3d2e0c5125ee71a14340fadbba34fdcc318e2f734e9911',
      'libscriptjail-arm64.dylib':
        '8f7276bc5d9148a93a5ef32d48fd80aafdf9179eb2f02a2941f4608ccd2dad95',
      'coreutils-arm64':
        '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21',
      'bash-arm64':
        'b067972c856c90d3147b179b4269db57bb78fc65f0e92c9b6f66efd505cec722',
      'vmlinux-vz-x86_64':
        'f873d0e941b6da652b0f420a21fe86e2616c9d1183a12f19699f6701a7628b2c',
      'vmlinux-vz-arm64':
        'e641300b5ab1f613c2929eb95cb4ed2e0bb34f0fb42ed3399f98b6d3277d3e79',
      'script-jail-vm-arm64-darwin':
        '6a14ab8d03874e189216b4bdd5d9f5ea1a5bdc7c3ed9cdb20350b818ee91c13d',
    },
  },
  dockerImages: {
    x64: {
      'ubuntu-22.04':
        'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c',
      'ubuntu-24.04':
        'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:f02c7a0820a24d316246abdbcfae2606e8923a760ac620d3bdb10125fb4629ce',
    },
    arm64: {
      'ubuntu-22.04':
        'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04-arm64@sha256:6f5452e5f38d28f1a21b03130acb8d58348876adbf0d4c5f03a58cb709ab05d6',
      'ubuntu-24.04':
        'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:4f7197d1867d230fe4c8b055816a016af370a6a7bb422be9ce69d6ff519d58f8',
    },
  },
};

// ---------------------------------------------------------------------------
// Case 1: computeManifestExpected
// ---------------------------------------------------------------------------

describe('computeManifestExpected', () => {
  it('produces 12 correct keys (3 linux + 9 darwin), ext4 via canonical, rest via sha256', async () => {
    const dir = buildStagedDir();
    const expected = await computeManifestExpected(dir);

    expect(Object.keys(expected.linux).sort()).toEqual(
      ['libscriptjail.so', 'rootfs-ubuntu-22.04.ext4', 'rootfs-ubuntu-24.04.ext4'].sort(),
    );
    expect(Object.keys(expected.darwin)).toHaveLength(9);

    // All 12 digests are 64-char lowercase hex.
    for (const section of [expected.linux, expected.darwin]) {
      for (const v of Object.values(section)) {
        expect(v).toMatch(HEX64);
      }
    }

    // ext4 keys route through the CANONICAL (time-masked) hash, not plain sha256.
    // Prove it by computing both on the same fixture and asserting the manifest
    // value equals the canonical one and DIFFERS from the plain sha256 (the
    // masking zeroes the s_wtime/s_checksum region in our 8 KiB fixture).
    const ext4Path = join(dir, 'images', 'rootfs-ubuntu-22.04.ext4');
    const canonical = await canonicalRootfsHash(ext4Path);
    const plain = plainSha(fixtureBytes('rootfs-ubuntu-22.04.ext4'));
    expect(expected.linux['rootfs-ubuntu-22.04.ext4']).toBe(canonical);
    expect(canonical).not.toBe(plain); // masking actually changed bytes

    // Non-ext4 keys are plain sha256.
    expect(expected.linux['libscriptjail.so']).toBe(plainSha(fixtureBytes('libscriptjail.so')));
    expect(expected.darwin['coreutils-arm64']).toBe(plainSha(fixtureBytes('coreutils-arm64')));
    expect(expected.darwin['script-jail-vm-arm64-darwin']).toBe(
      plainSha(fixtureBytes('script-jail-vm-arm64-darwin')),
    );
  });

  // Case 7: reject missing artifact (omit one of the 12) → throws.
  it('throws a clear error when an artifact is missing', async () => {
    const dir = buildStagedDir({ omit: 'vmlinux-vz-arm64' });
    await expect(computeManifestExpected(dir)).rejects.toThrow(/missing artifact 'vmlinux-vz-arm64'/);
  });
});

// ---------------------------------------------------------------------------
// Case 2: parseDockerDigestsFromLog over the committed buildx-log fixture
// ---------------------------------------------------------------------------

describe('parseDockerDigestsFromLog', () => {
  const log = readFileSync(join(FIXTURES, 'buildx-push-v0.2.5.log'), 'utf8');

  it('extracts exactly the 4 floating refs (dropping -v dups + decoys)', () => {
    const docker = parseDockerDigestsFromLog(log, {
      repo: 'Brooooooklyn/script-jail',
      tag: 'v0.2.5',
    });
    expect(docker).toEqual(V025_MANIFEST.dockerImages);
  });

  // Case 4: reject <4 digests (drop a floating-tag line) → throws.
  it('throws when fewer than 4 floating tags are present', () => {
    const trimmed = log
      .split('\n')
      .filter((l) => !l.includes('script-jail-rootfs:ubuntu-24.04-arm64@'))
      .join('\n');
    expect(() =>
      parseDockerDigestsFromLog(trimmed, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/no GHCR push for floating tag 'ubuntu-24.04-arm64'/);
  });

  // Case 5a: reject too-SHORT (63 hex) digest → line no longer matches → tag missing.
  it('throws on a too-short (63-hex) digest (line no longer matches)', () => {
    const corrupted = log.replace(
      'ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c',
      'ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586', // 63 chars
    );
    expect(() =>
      parseDockerDigestsFromLog(corrupted, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/no GHCR push for floating tag 'ubuntu-22.04'/);
  });

  // Case 5b: a too-LONG (65-hex) digest must be REJECTED, not silently truncated
  // to 64 (the `(?![0-9a-f])` boundary).  Only the floating 22.04 ref is made
  // 65-hex; its line then fails to match → that tag is missing → throws.
  it('rejects an over-long (65-hex) digest instead of truncating it', () => {
    const corrupted = log.replace(
      'ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c done',
      'ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586cd done', // 65 chars
    );
    expect(() =>
      parseDockerDigestsFromLog(corrupted, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/no GHCR push for floating tag 'ubuntu-22.04'/);
  });

  // Owner anchoring: requesting a DIFFERENT owner finds none of the upstream refs.
  it('is owner-anchored — a mismatched repo owner matches nothing', () => {
    expect(() =>
      parseDockerDigestsFromLog(log, { repo: 'SomeoneElse/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/no GHCR push for floating tag/);
  });

  // Provenance: the version-suffixed dup must be present (binds digest to the tag).
  it('throws when a version-suffixed dup is missing (provenance unbound)', () => {
    const noSuffixed = log
      .split('\n')
      .filter((l) => !l.includes('-v0.2.5@'))
      .join('\n');
    expect(() =>
      parseDockerDigestsFromLog(noSuffixed, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/missing version-suffixed GHCR push 'ubuntu-22.04-v0\.2\.5'/);
  });

  // Provenance: the floating + version-suffixed digests must AGREE.
  it('throws when the floating and version-suffixed digests disagree', () => {
    const mismatched = log.replace(
      'ubuntu-22.04-v0.2.5@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c',
      'ubuntu-22.04-v0.2.5@sha256:0000000000000000000000000000000000000000000000000000000000000000',
    );
    expect(() =>
      parseDockerDigestsFromLog(mismatched, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/does not match its version-suffixed dup/);
  });

  // Case 6: reject conflicting digest for same tag → throws.
  it('throws when the same tag carries conflicting digests', () => {
    const conflicting =
      log +
      '\n#99 pushing manifest for ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04@sha256:0000000000000000000000000000000000000000000000000000000000000000 done\n';
    expect(() =>
      parseDockerDigestsFromLog(conflicting, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
    ).toThrow(/conflicting digests for tag 'ubuntu-22.04'/);
  });

  // Boundary: ANY digest/tag-token char glued after 64 hex must NOT be accepted
  // by pinning the 64-char prefix — the `(?![0-9A-Za-z._-])` boundary rejects
  // alphanumeric continuation (lowercase non-hex `g`, uppercase `A`, digit) AND
  // the `.`/`_`/`-` separators that can glue garbage onto an OCI tag token
  // (`...586c_bad`, `...586c.bad`, `...586c-bad`).  Only a real terminator
  // (whitespace / quote / EOL) may follow the digest.
  it.each([['g'], ['A'], ['z'], ['_bad'], ['.bad'], ['-bad']])(
    'rejects a 64-hex digest with a glued %s instead of truncating',
    (suffix) => {
      const corrupted = log.replace(
        'ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c done',
        `ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c${suffix} done`,
      );
      expect(() =>
        parseDockerDigestsFromLog(corrupted, { repo: 'Brooooooklyn/script-jail', tag: 'v0.2.5' }),
      ).toThrow(/no GHCR push for floating tag 'ubuntu-22.04'/);
    },
  );
});

// ---------------------------------------------------------------------------
// assertRepo — reject path-traversal / dot-only segments
// ---------------------------------------------------------------------------

describe('assertRepo', () => {
  it.each(['Brooooooklyn/script-jail', 'fork-owner/my.repo_name', 'a/b'])(
    'accepts a valid owner/name: %s',
    (repo) => {
      expect(() => assertRepo(repo)).not.toThrow();
    },
  );

  it.each(['../evil', 'owner/..', './evil', 'owner/.', '..', 'a/b/c', 'noslash', "owner/x'y"])(
    'rejects an invalid / traversal repo: %s',
    (repo) => {
      expect(() => assertRepo(repo)).toThrow(/repo must be 'owner\/name'/);
    },
  );
});

// ---------------------------------------------------------------------------
// assertRunId — numeric run id only (it becomes a staging-dir path component)
// ---------------------------------------------------------------------------

describe('assertRunId', () => {
  it.each(['1', '27868987817', '999999999999'])('accepts a numeric run id: %s', (run) => {
    expect(() => assertRunId(run)).not.toThrow();
  });

  // Path-separator / traversal / metachar / leading-zero / empty must all throw
  // so a hostile --run can never escape `.release-backfill/<tag>-<run>`.
  it.each([
    '',
    '0',
    '01',
    '12a',
    '1.2',
    '../../etc',
    'a/b',
    '12/..',
    './1',
    '1 2',
    '-1',
    '+1',
    '1e3',
  ])('rejects a non-numeric / unsafe run id: %s', (run) => {
    expect(() => assertRunId(run)).toThrow(/must be a numeric GitHub run id/);
  });
});

// ---------------------------------------------------------------------------
// prepareCleanStagingDir — fresh per-run dir, fail-closed on symlink escape
// ---------------------------------------------------------------------------

describe('prepareCleanStagingDir', () => {
  it('creates a fresh per-run dir and WIPES stale contents', () => {
    const root = join(freshTmp(), '.release-backfill');
    const child = 'v0.2.6-111';
    // Seed a stale file from a "previous run" at the same child name.
    mkdirSync(join(root, child), { recursive: true });
    writeFileSync(join(root, child, 'stale.txt'), 'leftover');

    const dir = prepareCleanStagingDir(root, child);
    expect(dir).toBe(join(root, child));
    expect(existsSync(dir)).toBe(true);
    // The stale leftover is gone — the dir is fresh.
    expect(existsSync(join(dir, 'stale.txt'))).toBe(false);
  });

  // The exact escape the 6th-pass review reproduced: a symlinked staging ROOT
  // would make the recursive wipe delete a tree OUTSIDE the repo.  Must throw
  // BEFORE deleting anything, and the outside target must be untouched.
  it('refuses a symlinked staging root and does NOT delete its target', () => {
    const base = freshTmp();
    const outside = join(base, 'outside');
    mkdirSync(join(outside, 'v0.2.6-222'), { recursive: true });
    writeFileSync(join(outside, 'v0.2.6-222', 'precious.txt'), 'do not delete');

    const root = join(base, '.release-backfill');
    symlinkSync(outside, root); // .release-backfill -> outside

    expect(() => prepareCleanStagingDir(root, 'v0.2.6-222')).toThrow(/staging root .* is a symlink/);
    // The outside tree the symlink pointed at is intact.
    expect(existsSync(join(outside, 'v0.2.6-222', 'precious.txt'))).toBe(true);
  });

  it('refuses when the per-run child is itself a pre-existing symlink', () => {
    const base = freshTmp();
    const outside = join(base, 'outside');
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(outside, 'precious.txt'), 'do not delete');

    const root = join(base, '.release-backfill');
    mkdirSync(root, { recursive: true });
    symlinkSync(outside, join(root, 'v0.2.6-333')); // child -> outside

    expect(() => prepareCleanStagingDir(root, 'v0.2.6-333')).toThrow(/is a symlink; refusing to wipe/);
    expect(existsSync(join(outside, 'precious.txt'))).toBe(true);
  });

  it('refuses when the staging root exists as a non-directory', () => {
    const base = freshTmp();
    const root = join(base, '.release-backfill');
    writeFileSync(root, 'i am a file');
    expect(() => prepareCleanStagingDir(root, 'v0.2.6-444')).toThrow(/is not a directory/);
  });

  it.each(['', '.', '..', 'a/b', 'a\\b', '../escape'])(
    'refuses an unsafe child name: %s',
    (child) => {
      const root = join(freshTmp(), '.release-backfill');
      expect(() => prepareCleanStagingDir(root, child)).toThrow(/unsafe staging child name/);
    },
  );
});

// ---------------------------------------------------------------------------
// selectBuildJobId — bind --build-job to the requested run
// ---------------------------------------------------------------------------

describe('selectBuildJobId', () => {
  const jobs = [
    { databaseId: 111, name: 'build-mac-bin' },
    { databaseId: 222, name: 'build' },
  ];

  it('returns the `build` job id when no override is given', () => {
    expect(selectBuildJobId(jobs)).toBe('222');
  });

  it('returns the override when it IS a job of the run', () => {
    expect(selectBuildJobId(jobs, '111')).toBe('111');
  });

  it('throws when the override is NOT a job of the run (cross-run binding)', () => {
    expect(() => selectBuildJobId(jobs, '999')).toThrow(/not a job of the requested run/);
  });

  it('throws when there is no `build` job and no override', () => {
    expect(() => selectBuildJobId([{ databaseId: 1, name: 'lint' }])).toThrow(
      /no job named 'build'/,
    );
  });
});

// ---------------------------------------------------------------------------
// assertOfflineInputsConsistent — --dir + --log are all-or-nothing
// ---------------------------------------------------------------------------

describe('assertOfflineInputsConsistent', () => {
  it('returns false (online, bound) when neither --dir nor --log is given', () => {
    expect(assertOfflineInputsConsistent({})).toBe(false);
  });

  it('returns true (offline) when BOTH --dir and --log are given', () => {
    expect(assertOfflineInputsConsistent({ dir: '/tmp/tree', log: '/tmp/log.txt' })).toBe(true);
  });

  it('throws when only --dir is given (would mix local artifacts + fetched log)', () => {
    expect(() => assertOfflineInputsConsistent({ dir: '/tmp/tree' })).toThrow(
      /must be used TOGETHER/,
    );
  });

  it('throws when only --log is given (would mix fetched artifacts + local log)', () => {
    expect(() => assertOfflineInputsConsistent({ log: '/tmp/log.txt' })).toThrow(
      /must be used TOGETHER/,
    );
  });
});

// ---------------------------------------------------------------------------
// Case 3: codegen round-trip — BYTE-equals the frozen v0.2.5 manifest.
//
// The oracle is a COMMITTED fixture snapshot of `src/action/artifact-manifest.ts`
// as released at v0.2.5 (commit 2140b6d), regenerated with:
//   git show 2140b6d:src/action/artifact-manifest.ts \
//     > test/release/fixtures/artifact-manifest-v0.2.5.ts.txt
// It is read from disk (NOT `git show`) so the test is self-contained: CI uses a
// shallow checkout that may not contain 2140b6d, and freezing the bytes here keeps
// the oracle stable even after a future release regenerates the live manifest.
// ---------------------------------------------------------------------------

describe('renderArtifactManifestTs', () => {
  it('byte-equals the frozen v0.2.5 manifest fixture', () => {
    const rendered = renderArtifactManifestTs(V025_MANIFEST);
    const oracle = readFileSync(join(FIXTURES, 'artifact-manifest-v0.2.5.ts.txt'), 'utf8');
    expect(rendered).toBe(oracle);
  });

  it('emits value lines matching the parser-required shape', () => {
    const rendered = renderArtifactManifestTs(V025_MANIFEST);
    const valueLines = rendered
      .split('\n')
      .filter((l) => /^\s+'[^']+':\s*'[^']+',\s*$/.test(l));
    // 12 file SHAs + 4 docker refs + tag/repo are NOT value-lines (tag/repo are
    // unquoted-key or trailing-comment), so we just assert the 16 quoted entries
    // all match the strict shape.
    expect(valueLines.length).toBe(16);
    for (const l of valueLines) {
      expect(l).toMatch(/^\s*'[^']+':\s*'[^']+',\s*$/);
    }
  });
});

// ---------------------------------------------------------------------------
// Case 8: bumpVersion
// ---------------------------------------------------------------------------

describe('bumpVersion', () => {
  it('writes the bare version, preserving 2-space indent + trailing newline, leaving rest intact', () => {
    const dir = freshTmp();
    const pkgPath = join(dir, 'package.json');
    const original = {
      name: 'script-jail',
      version: '0.2.4',
      scripts: { build: 'oxnode scripts/build.ts' },
    };
    writeFileSync(pkgPath, JSON.stringify(original, null, 2) + '\n');

    bumpVersion(pkgPath, '0.2.5');

    const raw = readFileSync(pkgPath, 'utf8');
    expect(raw.endsWith('\n')).toBe(true);
    expect(raw).toContain('  "version": "0.2.5"'); // 2-space indent, bare version
    const parsed = JSON.parse(raw) as typeof original;
    expect(parsed.version).toBe('0.2.5');
    expect(parsed.name).toBe('script-jail'); // rest intact
    expect(parsed.scripts.build).toBe('oxnode scripts/build.ts');
  });

  it('rejects a version with a leading v', () => {
    const dir = freshTmp();
    const pkgPath = join(dir, 'package.json');
    writeFileSync(pkgPath, JSON.stringify({ name: 'x', version: '0.0.0' }, null, 2) + '\n');
    expect(() => bumpVersion(pkgPath, 'v0.2.5')).toThrow(/bare semver/);
  });

  it('rejects an injection-shaped version (no TS metacharacters reach codegen)', () => {
    const dir = freshTmp();
    const pkgPath = join(dir, 'package.json');
    writeFileSync(pkgPath, JSON.stringify({ name: 'x', version: '0.0.0' }, null, 2) + '\n');
    // A version that would break out of a single-quoted TS literal in the manifest.
    expect(() =>
      bumpVersion(pkgPath, "0.2.6', injected: process.exit(1), x: '"),
    ).toThrow(/bare semver/);
  });
});

// ---------------------------------------------------------------------------
// Codegen injection / --repo honored
// ---------------------------------------------------------------------------

describe('renderArtifactManifestTs — input hardening', () => {
  it('rejects a tag carrying TS-literal-breakout metacharacters', () => {
    const evil: ArtifactManifest = {
      ...V025_MANIFEST,
      tag: "v0.2.6', injected: process.exit(1), x: '",
    };
    expect(() => renderArtifactManifestTs(evil)).toThrow(/manifest tag must be/);
  });

  it('rejects a repo carrying metacharacters', () => {
    const evil: ArtifactManifest = {
      ...V025_MANIFEST,
      repo: "Owner/name', evil: '1",
    };
    expect(() => renderArtifactManifestTs(evil)).toThrow(/repo must be/);
  });

  it('rejects a malformed (non-digest-pinned) GHCR ref', () => {
    const evil: ArtifactManifest = {
      ...V025_MANIFEST,
      dockerImages: {
        ...V025_MANIFEST.dockerImages!,
        x64: {
          ...V025_MANIFEST.dockerImages!.x64,
          'ubuntu-22.04': 'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-22.04', // no @sha256:
        },
      },
    };
    expect(() => renderArtifactManifestTs(evil)).toThrow(/not a valid .*GHCR ref/);
  });

  it('honors a non-default repo (renders manifest.repo, no upstream comment)', () => {
    const forkRefs = {
      x64: {
        'ubuntu-22.04':
          'ghcr.io/forkowner/script-jail-rootfs:ubuntu-22.04@sha256:f5b9b3062398a449553ecc566a4827f05cbbf301b45617ee9cd287cda110586c',
        'ubuntu-24.04':
          'ghcr.io/forkowner/script-jail-rootfs:ubuntu-24.04@sha256:f02c7a0820a24d316246abdbcfae2606e8923a760ac620d3bdb10125fb4629ce',
      },
      arm64: {
        'ubuntu-22.04':
          'ghcr.io/forkowner/script-jail-rootfs:ubuntu-22.04-arm64@sha256:6f5452e5f38d28f1a21b03130acb8d58348876adbf0d4c5f03a58cb709ab05d6',
        'ubuntu-24.04':
          'ghcr.io/forkowner/script-jail-rootfs:ubuntu-24.04-arm64@sha256:4f7197d1867d230fe4c8b055816a016af370a6a7bb422be9ce69d6ff519d58f8',
      },
    };
    const fork: ArtifactManifest = {
      ...V025_MANIFEST,
      repo: 'ForkOwner/script-jail',
      dockerImages: forkRefs,
    };
    const rendered = renderArtifactManifestTs(fork);
    expect(rendered).toContain("  repo: 'ForkOwner/script-jail',");
    expect(rendered).not.toContain('renamed from scriptjail'); // upstream-only comment
  });
});

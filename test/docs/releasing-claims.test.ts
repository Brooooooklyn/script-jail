// script-jail — test/docs/releasing-claims.test.ts
//
// Doc-claim cross-check for `docs/releasing.md` (the release runbook).
//
// `docs/releasing.md` documents the build-once / download-forever single-tag
// release flow. It hard-codes facts that live in source (the pinned-manifest
// artifact COUNTS, the repo slug, the `release.yml` publish-job step names, the
// producer→backfill→download-and-verify invariants, and the load-bearing
// CLI-skips-manifest / Action-gates-on-manifest asymmetry). When the source of
// truth drifts, this test fails in the cheap `unit` vitest project instead of
// silently leaving the runbook wrong for the one person who follows it once.
//
// This file lives under `test/docs/**`. The `unit` vitest project includes
// `test/**/*.test.ts` and excludes only `integration|guest|e2e`
// (vitest.config.ts:9-10), so `test/docs/**` IS picked up with no relocation.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { describe, it, expect } from 'vitest';

import { PINNED_MANIFEST } from '../../src/action/artifact-manifest.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const releasingPath = join(repoRoot, 'docs', 'releasing.md');
const developmentPath = join(repoRoot, 'docs', 'development.md');
const readmePath = join(repoRoot, 'README.md');
const cliIndexPath = join(repoRoot, 'src', 'cli', 'index.ts');
const mainPath = join(repoRoot, 'src', 'main.ts');
const checkPublishPath = join(
  repoRoot,
  'scripts',
  'check-publish-artifacts.sh',
);

function readReleasing(): string {
  return readFileSync(releasingPath, 'utf8');
}

describe('docs/releasing.md claims', () => {
  // Claim: the runbook exists and is non-empty (fails until Task 5.2 writes it).
  it('exists and is non-empty', () => {
    expect(existsSync(releasingPath)).toBe(true);
    expect(readReleasing().trim().length).toBeGreaterThan(0);
  });

  // Claim: the runbook names the release repo slug, describes the SINGLE-tag
  // release (`vX.Y.Z`, no two-tag bootstrap loop), and preserves the
  // historically-true note that 0.1.0 was the one-time MANUAL bootstrap publish.
  it('names the repo slug, the single release tag, and the 0.1.0 bootstrap note', () => {
    const doc = readReleasing();
    expect(doc).toContain('Brooooooklyn/scriptjail');
    // Single-tag flow: the runbook templates the tag as vX.Y.Z, not a fixed
    // bootstrap pair.
    expect(doc).toContain('vX.Y.Z');
    // The historical 0.1.0 manual bootstrap exception is preserved.
    expect(doc).toContain('0.1.0');
    // The old two-tag rebuild/backfill narrative must be gone: there is no
    // v0.1.1 "backfill reproduces v0.1.0's SHAs" second tag in this flow.
    expect(doc).not.toContain('v0.1.1');
  });

  // Claim: the runbook describes the build-once / download-forever split — a
  // producer (`release-build.yml`) builds the assets once, and `release.yml`
  // DOWNLOADS + VERIFIES them rather than rebuilding. Guard both halves.
  it('describes the producer build-once / download-and-verify split', () => {
    const doc = readReleasing();
    expect(doc).toContain('release-build.yml');
    expect(doc).toContain('build-once');
    // The release must download + verify, never rebuild.
    expect(doc.toLowerCase()).toContain('never rebuild');
    expect(doc.toLowerCase()).toContain('download');
    // Backfill must come from the LATEST producer run (the release lookup picks
    // newest-first — backfilling from an older run breaks the SHA verify).
    expect(doc).toMatch(/latest[^.\n]*producer run/i);
  });

  // Claim: the runbook states plainly that byte-reproducibility is NO LONGER a
  // release gate (build-once means the exact producer bytes are downloaded and
  // verified), while the canonical (time-masked) rootfs hash is still HOW those
  // assets are verified.
  it('states reproducibility is not a release gate but is the verify mechanism', () => {
    const doc = readReleasing();
    expect(doc.toLowerCase()).toContain('canonical (time-masked) hash');
    // It must NOT re-introduce reproducibility as a release gate.
    expect(doc).not.toContain("reproduces v0.1.0's SHAs");
    expect(doc).not.toMatch(/cross-run reproducibility/i);
  });

  // Claim: the artifact COUNTS the runbook tells the maintainer to backfill
  // (file SHAs + Docker digests) equal what `PINNED_MANIFEST` actually carries.
  // Single-sourced: we extract the numbers the doc PRINTS and compare them to
  // the values computed from the manifest, so the count is never hardcoded
  // twice. If an artifact is added/removed from the manifest, this fails.
  it('states artifact counts that equal the pinned manifest', () => {
    const { expected, dockerImages } = PINNED_MANIFEST;
    const fileCount =
      Object.keys(expected.linux).length + Object.keys(expected.darwin).length;
    const dockerCount =
      Object.keys(dockerImages?.x64 ?? {}).length +
      Object.keys(dockerImages?.arm64 ?? {}).length;

    const doc = readReleasing();

    // The doc prints "<n> file SHAs" and "<n> Docker digests"; pull those
    // numbers back out and compare to the computed values.
    const fileMatch = doc.match(/(\d+)\s+file SHAs/);
    const dockerMatch = doc.match(/(\d+)\s+Docker digests/);
    expect(fileMatch, 'doc must state "<n> file SHAs"').not.toBeNull();
    expect(dockerMatch, 'doc must state "<n> Docker digests"').not.toBeNull();
    expect(Number(fileMatch![1])).toBe(fileCount);
    expect(Number(dockerMatch![1])).toBe(dockerCount);
  });

  // Claim: the all-or-nothing mixed-manifest reject spans ALL pinned entries —
  // the file SHAs AND the Docker digests, not just the files.
  // Single-sourced: the total (9 files + 4 docker = 13) is computed from
  // PINNED_MANIFEST and compared to the count the doc prints, and we confirm
  // the gate the doc attributes it to (check-publish-artifacts.sh) actually
  // folds the 4 Docker refs into the same placeholder/real tally.
  it('states the all-or-nothing reject spans all file + docker entries', () => {
    const { expected, dockerImages } = PINNED_MANIFEST;
    const fileCount =
      Object.keys(expected.linux).length + Object.keys(expected.darwin).length;
    const dockerCount =
      Object.keys(dockerImages?.x64 ?? {}).length +
      Object.keys(dockerImages?.arm64 ?? {}).length;
    const totalCount = fileCount + dockerCount;

    const doc = readReleasing();

    // The doc prints "all <n> pinned entries"; pull it back out and compare to
    // the manifest-derived total so the count is never hardcoded twice.
    const totalMatch = doc.match(/all (\d+) pinned entries/);
    expect(
      totalMatch,
      'doc must state "all <n> pinned entries"',
    ).not.toBeNull();
    expect(Number(totalMatch![1])).toBe(totalCount);

    // The gate the doc names must actually fold the 4 Docker refs into the
    // same all-or-nothing classification (not just the file SHAs).
    const script = readFileSync(checkPublishPath, 'utf8');
    expect(script).toContain(
      'The 4 Docker image refs participate in the SAME all-or-nothing',
    );
  });

  // Claim: the runbook names ONLY the publish-job step names that release.yml
  // is contracted to preserve (renamed in Phase 2). Asserting on these couples
  // the runbook to the real workflow without re-breaking on the pre-WS2 names.
  it('names the preserved release.yml publish-job step names', () => {
    const doc = readReleasing();
    expect(doc).toContain('Stage npm packages');
    expect(doc).toContain('Validate npm packlists');
    expect(doc).toContain('Publish npm packages (platform-first, main last)');
  });

  // Claim: the load-bearing asymmetry the matrix rests on — the CLI never
  // validates the manifest (so macOS-arm64 works day-one) while the Action
  // hard-fails on a placeholder manifest. Guard the source strings the runbook
  // attributes the matrix to.
  it('matches the CLI-skips-manifest / Action-gates-on-manifest invariant', () => {
    const cli = readFileSync(cliIndexPath, 'utf8');
    const main = readFileSync(mainPath, 'utf8');
    expect(cli).not.toContain('validateManifest(');
    expect(main).toContain('doValidateManifest(PINNED_MANIFEST)');
  });

  // Claim: the runbook is linked from README's Docs list and from
  // docs/development.md's Release flow.
  it('is linked from README and docs/development.md', () => {
    const readme = readFileSync(readmePath, 'utf8');
    const development = readFileSync(developmentPath, 'utf8');
    expect(readme).toContain('](./docs/releasing.md)');
    expect(development).toContain('docs/releasing.md');
  });
});

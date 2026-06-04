// script-jail — test/scripts/release-workflow.test.ts
//
// PKG-5: guards the rewired `publish` job in .github/workflows/release.yml.
//
// The publish job must, after staging/verifying the build artifacts:
//   1. assemble the four npm package dirs via scripts/assemble-npm-packages.mjs
//      (--artifacts <downloaded dir> --out <staging root> --version <tag>),
//   2. gate each staged dir's packed file list via
//      scripts/assert-npm-packlist.mjs --all <staging root>,
//   3. publish the three @script-jail/<platform> packages FIRST, then the main
//      `script-jail` package LAST (load-bearing: main's optionalDependencies
//      must resolve at consumer-install time, and npm publish is
//      non-transactional / non-re-runnable for an already-published version).
//
// Publishing uses OIDC trusted publishing (no NODE_AUTH_TOKEN / NPM_TOKEN): the
// publish job grants `id-token: write`, upgrades npm to an OIDC-capable version
// (>= 11.5.1), and every `npm publish` keeps `--access public` (provenance is
// generated automatically, so the `--provenance` flag is gone). The version==tag
// gate is preserved.
//
// We parse the real workflow YAML (not a snapshot) so a textual reshuffle that
// preserves intent stays green, and the platform-first ordering is asserted by
// comparing string offsets in the concatenated publish-step scripts. The
// sanitized package dir names are sourced from scripts/npm-packages.mjs so they
// can never drift from the assembler / publisher.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

// eslint-disable-next-line import/no-unresolved
import { npmPackages } from '../../scripts/npm-packages.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const WORKFLOW_PATH = join(REPO_ROOT, '.github', 'workflows', 'release.yml');

interface WorkflowStep {
  name?: string;
  run?: string;
  uses?: string;
  env?: Record<string, unknown>;
  with?: Record<string, unknown>;
}

interface ParsedJob {
  permissions?: Record<string, string> | string;
  needs?: string | string[];
  steps?: WorkflowStep[];
}

interface ParsedWorkflow {
  jobs: Record<string, ParsedJob>;
}

function loadPublishJob(): ParsedJob {
  const raw = readFileSync(WORKFLOW_PATH, 'utf8');
  const parsed = parseYaml(raw) as ParsedWorkflow;
  const publish = parsed.jobs?.publish;
  expect(publish, 'release.yml must define a `publish` job').toBeDefined();
  expect((publish?.steps ?? []).length).toBeGreaterThan(0);
  return publish!;
}

// The dirs are the single source of truth for what the publish loop iterates.
const PACKAGES = npmPackages('0.1.0');
const MAIN_DIR = PACKAGES.find((p) => p.name === 'script-jail')!.dir;
const PLATFORM_DIRS = PACKAGES.filter((p) => p.name !== 'script-jail').map(
  (p) => p.dir,
);

describe('release.yml publish job (PKG-5)', () => {
  const publishJob = loadPublishJob();
  const steps = publishJob.steps ?? [];
  // All `run:` script bodies concatenated, for offset-based ordering checks.
  const runScripts = steps
    .map((s) => s.run ?? '')
    .filter((s) => s.length > 0);
  const allRun = runScripts.join('\n');

  it('invokes scripts/assemble-npm-packages.mjs with --artifacts and --out', () => {
    const step = runScripts.find((s) =>
      s.includes('assemble-npm-packages.mjs'),
    );
    expect(step, 'a publish step must run assemble-npm-packages.mjs').toBeDefined();
    expect(step).toContain('--artifacts');
    expect(step).toContain('--out');
  });

  it('gates each staged package via scripts/assert-npm-packlist.mjs', () => {
    const step = runScripts.find((s) => s.includes('assert-npm-packlist.mjs'));
    expect(step, 'a publish step must run assert-npm-packlist.mjs').toBeDefined();
  });

  it('publishes the three platform packages before the main package', () => {
    // The platform dirs appear bare in the `for pkg in ...` loop list; the main
    // dir is published last via the literal `publish_if_absent script-jail`
    // call AFTER the loop. We anchor the main offset on that trailing call (the
    // platform loop uses `publish_if_absent "${pkg}"` with a variable, so the
    // bare `publish_if_absent script-jail` literal is unambiguously the main
    // publish — and the platform dir names are not a prefix of it).
    const mainIndex = allRun.lastIndexOf(`publish_if_absent ${MAIN_DIR}`);
    expect(
      mainIndex,
      'main package (publish_if_absent script-jail) publish must appear last',
    ).toBeGreaterThan(-1);
    for (const dir of PLATFORM_DIRS) {
      const platformIndex = allRun.indexOf(dir);
      expect(
        platformIndex,
        `platform package ${dir} must be referenced in a publish step`,
      ).toBeGreaterThan(-1);
      expect(
        platformIndex,
        `platform package ${dir} must publish before main (${MAIN_DIR})`,
      ).toBeLessThan(mainIndex);
    }
  });

  it('every npm publish keeps --access public (provenance is automatic via OIDC)', () => {
    // The publish step batches the three platform packages in a single `for`
    // loop and then publishes main, so there are fewer literal `npm publish`
    // lines than packages. Assert (a) every `npm publish` line carries
    // `--access public` (scoped packages default to restricted otherwise), and
    // (b) all four package dirs are referenced in the publish step. The
    // `--provenance` flag is intentionally gone: trusted publishing generates
    // provenance attestations automatically (asserted separately below).
    const publishLines = allRun
      .split('\n')
      .filter((line) => /\bnpm publish\b/.test(line));
    expect(
      publishLines.length,
      'expected at least one npm publish invocation',
    ).toBeGreaterThanOrEqual(1);
    for (const line of publishLines) {
      expect(line).toContain('--access public');
    }
    for (const dir of [...PLATFORM_DIRS, MAIN_DIR]) {
      expect(
        allRun,
        `package dir ${dir} must be referenced in the publish step`,
      ).toContain(dir);
    }
  });

  it('is idempotent — skips a package whose exact version is already published', () => {
    // The publish step must probe the registry per package and skip an
    // already-published name@version instead of letting a bare `npm publish`
    // 409 abort the `set -euo pipefail` job. This is load-bearing for the
    // v0.1.0 generating-run (whose 0.1.0 packages were bootstrap-published
    // already) and for re-running a partially-failed release (the documented
    // recovery: republish only the still-unpublished packages).
    const step = runScripts.find((s) => /\bnpm view\b/.test(s));
    expect(
      step,
      'the publish step must use a read-only `npm view` existence probe to skip already-published versions',
    ).toBeDefined();
    // The probe must guard the publish (skip path) rather than always publish.
    expect(step).toMatch(/already published/i);
    expect(step).toMatch(/npm view .*version/);
    // The skip-or-publish decision must wrap the actual `npm publish`.
    const viewIdx = step!.search(/\bnpm view\b/);
    const publishIdx = step!.search(/\bnpm publish\b/);
    expect(viewIdx, 'existence probe must precede the npm publish').toBeLessThan(
      publishIdx,
    );
  });

  it('preserves the version==tag gate', () => {
    const step = runScripts.find((s) =>
      s.includes('package.json version'),
    );
    expect(
      step,
      'the version-must-match-tag gate must remain in a publish step',
    ).toBeDefined();
    expect(step).toContain('must match tag');
  });

  it('publishes via OIDC — no NODE_AUTH_TOKEN / NPM_TOKEN anywhere in the job', () => {
    // Trusted publishing replaced the token flow. If a token is present npm
    // prefers it over the OIDC exchange, so the publish job must reference
    // neither NODE_AUTH_TOKEN nor secrets.NPM_TOKEN (in any step env or run).
    const jobJson = JSON.stringify(publishJob);
    expect(jobJson, 'publish job must not set NODE_AUTH_TOKEN').not.toContain(
      'NODE_AUTH_TOKEN',
    );
    expect(jobJson, 'publish job must not reference NPM_TOKEN').not.toContain(
      'NPM_TOKEN',
    );
  });

  it('grants id-token: write for the OIDC token exchange', () => {
    const perms = publishJob.permissions;
    expect(
      typeof perms === 'object' && perms !== null,
      'publish job must declare a permissions map',
    ).toBe(true);
    expect((perms as Record<string, string>)['id-token']).toBe('write');
  });

  it('upgrades npm to an OIDC-capable version (>= 11.5.1) before publishing', () => {
    // OIDC trusted publishing requires npm >= 11.5.1; the npm bundled with the
    // runner's Node can be older, so a publish step must install a newer npm.
    const upgrade = runScripts.find((s) => /npm (?:install|i) -g npm@/.test(s));
    expect(
      upgrade,
      'a publish step must upgrade npm for OIDC trusted publishing',
    ).toBeDefined();
    const m = upgrade!.match(/npm@(\d+)\.(\d+)\.(\d+)/);
    expect(m, 'the npm upgrade must pin an explicit version').not.toBeNull();
    const [maj, min, patch] = [Number(m![1]), Number(m![2]), Number(m![3])];
    const meetsFloor =
      maj > 11 || (maj === 11 && (min > 5 || (min === 5 && patch >= 1)));
    expect(
      meetsFloor,
      `pinned npm@${maj}.${min}.${patch} must be >= 11.5.1 for OIDC`,
    ).toBe(true);
    // The upgrade must precede the first npm publish (else the old npm runs it).
    const upgradeIdx = allRun.indexOf('-g npm@');
    const publishIdx = allRun.search(/\bnpm publish\b/);
    expect(upgradeIdx, 'npm upgrade must appear in a run step').toBeGreaterThan(
      -1,
    );
    expect(
      upgradeIdx,
      'npm must be upgraded before the first npm publish',
    ).toBeLessThan(publishIdx);
  });

  it('verifies real pinned Docker digests resolve in GHCR (backfill gate)', () => {
    // The gate reads the pinned dockerImages from src/action/artifact-manifest.ts
    // and `docker buildx imagetools inspect`s each REAL ref; placeholders (the
    // v0.1.0 bootstrap) are skipped. Docker images are not byte-reproducible, so
    // it asserts EXISTENCE — catching a hand-copy typo / stale digest that would
    // otherwise ship in dist/main.cjs and break Docker-backend consumers.
    const step = runScripts.find(
      (s) =>
        s.includes('artifact-manifest.ts') && s.includes('imagetools inspect'),
    );
    expect(
      step,
      'a publish step must verify pinned Docker digests against GHCR',
    ).toBeDefined();
    expect(step).toContain('PLACEHOLDER_SHA256_');
    expect(step).toMatch(/does not resolve in GHCR/);
    expect(step).toContain('exit 1');
  });

  it('runs the Docker-digest GHCR gate before any npm publish', () => {
    // A bad digest must block the irreversible npm publish, so the gate's
    // `imagetools inspect` must precede the first `npm publish` in step order.
    const gateIdx = allRun.indexOf('imagetools inspect');
    const publishIdx = allRun.search(/\bnpm publish\b/);
    expect(gateIdx, 'GHCR digest gate must be present').toBeGreaterThan(-1);
    expect(publishIdx, 'an npm publish must be present').toBeGreaterThan(-1);
    expect(
      gateIdx,
      'the GHCR digest gate must run before any npm publish',
    ).toBeLessThan(publishIdx);
  });
});

// The `build` job rebuilds each rootfs ext4 in-run and asserts its CANONICAL
// hash (volatile superblock time fields masked) reproduces — for BOTH arches.
// This is load-bearing for the two-tag manifest bootstrap: v0.1.0 publishes
// PLACEHOLDER SHAs and v0.1.1 backfills the REAL canonical hashes, so the
// v0.1.1 build must reproduce v0.1.0's released bytes. A reproducibility
// regression therefore has to FAIL the release build, not surface later as an
// unfixable backfill SHA mismatch (by which point v0.1.0 is immutable on npm).
// arm64 can't share the x64 snapshot (no public ubuntu-ports snapshot) so it
// pins the frozen ports.ubuntu.com release pocket and gets its own gate; this
// block guards that the arm64 gate exists and runs pre-publish.
describe('release.yml build job rootfs reproducibility gates', () => {
  const parsed = parseYaml(readFileSync(WORKFLOW_PATH, 'utf8')) as ParsedWorkflow;
  const buildJob = parsed.jobs?.build;
  const publishJob = parsed.jobs?.publish;
  const steps = buildJob?.steps ?? [];
  const stepNames = steps.map((s) => s.name ?? '');
  const byName = (re: RegExp): WorkflowStep | undefined =>
    steps.find((s) => re.test(s.name ?? ''));

  it('defines a build job with an x64 canonical-reproducibility gate (both majors)', () => {
    const gate = byName(/x64 rootfs ext4s are canonical-reproducible/i);
    expect(gate, 'x64 reproducibility gate step must exist').toBeDefined();
    const run = gate!.run ?? '';
    expect(run, 'gate must compare CANONICAL hashes via repro-hash-cli').toContain(
      'repro-hash-cli.cjs',
    );
    expect(run).toContain('ubuntu-24.04');
    expect(run).toContain('ubuntu-22.04');
    expect(run).toMatch(/is not canonical-reproducible/);
    expect(run).toContain('exit 1');
  });

  it('defines an arm64 canonical-reproducibility gate covering both majors', () => {
    // The review-mandated gate: arm64 reproducibility must be PROVEN in-run
    // before the irreversible v0.1.0 publish, not first tested at the v0.1.1
    // backfill (when v0.1.0's arm64 bytes are already immutable on npm).
    const gate = byName(/arm64 rootfs ext4s are canonical-reproducible/i);
    expect(gate, 'arm64 reproducibility gate step must exist').toBeDefined();
    const run = gate!.run ?? '';
    expect(run, 'gate must compare CANONICAL hashes via repro-hash-cli').toContain(
      'repro-hash-cli.cjs',
    );
    expect(run, 'gate must rebuild the arm64 image').toContain('--arch=arm64');
    expect(run, 'gate must compare the arm64 ext4 artifacts').toMatch(
      /rootfs-\$\{major\}-arm64\.ext4/,
    );
    expect(run).toContain('assert_reproducible_arm64 ubuntu-24.04');
    expect(run).toContain('assert_reproducible_arm64 ubuntu-22.04');
    expect(run).toMatch(/is not canonical-reproducible/);
    expect(run).toContain('exit 1');
  });

  it('runs the arm64 gate after the arm64 builds and before the x64 shim restore', () => {
    // The gate rebuilds the arm64 image, which re-stages the arm64 shim to the
    // single images/libscriptjail.so COPY target — so it must run while that
    // path still holds the arm64 shim, i.e. before "Restore x64 shim artifact".
    const armBuildIdx = stepNames.findIndex((n) =>
      /Build rootfs \(ubuntu-24\.04, arm64\)/.test(n),
    );
    const gateIdx = stepNames.findIndex((n) =>
      /arm64 rootfs ext4s are canonical-reproducible/i.test(n),
    );
    const restoreIdx = stepNames.findIndex((n) => /Restore x64 shim/i.test(n));
    expect(armBuildIdx, 'arm64 build step must exist').toBeGreaterThan(-1);
    expect(gateIdx, 'arm64 gate must exist').toBeGreaterThan(-1);
    expect(restoreIdx, 'x64 shim restore step must exist').toBeGreaterThan(-1);
    expect(
      gateIdx,
      'arm64 gate must run after the arm64 rootfs builds',
    ).toBeGreaterThan(armBuildIdx);
    expect(
      gateIdx,
      'arm64 gate must run before the x64 shim restore (rebuild needs the arm64 shim staged)',
    ).toBeLessThan(restoreIdx);
  });

  it('gates reproducibility before publish (publish depends on build)', () => {
    // The gates live in `build`; the irreversible npm publish lives in
    // `publish`. `publish: needs: build` is what makes the gates block the
    // publish — without it the publish could run on a non-reproducible build.
    const needs = publishJob?.needs;
    const needsArr = Array.isArray(needs) ? needs : needs ? [needs] : [];
    expect(
      needsArr,
      'publish job must `needs: build` so the reproducibility gates run first',
    ).toContain('build');
  });
});

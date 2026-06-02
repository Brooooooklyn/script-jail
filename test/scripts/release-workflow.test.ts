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
    // The platform dirs appear bare in the `for pkg in ...` loop list; the
    // main dir appears as the literal `npm-staging/script-jail` `cd` after the
    // loop. (The loop body itself uses `npm-staging/${pkg}`, so the literal
    // `npm-staging/script-jail` offset is unambiguously the main publish.)
    const mainIndex = allRun.indexOf(`npm-staging/${MAIN_DIR}`);
    expect(
      mainIndex,
      'main package (npm-staging/script-jail) publish must appear',
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

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
// Every `npm publish` keeps `--provenance --access public`; the
// version==tag gate and `NODE_AUTH_TOKEN: secrets.NPM_TOKEN` are preserved.
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

interface ParsedWorkflow {
  jobs: Record<string, { steps?: WorkflowStep[] }>;
}

function loadPublishSteps(): WorkflowStep[] {
  const raw = readFileSync(WORKFLOW_PATH, 'utf8');
  const parsed = parseYaml(raw) as ParsedWorkflow;
  const publish = parsed.jobs?.publish;
  expect(publish, 'release.yml must define a `publish` job').toBeDefined();
  const steps = publish?.steps ?? [];
  expect(steps.length).toBeGreaterThan(0);
  return steps;
}

// The dirs are the single source of truth for what the publish loop iterates.
const PACKAGES = npmPackages('0.1.0');
const MAIN_DIR = PACKAGES.find((p) => p.name === 'script-jail')!.dir;
const PLATFORM_DIRS = PACKAGES.filter((p) => p.name !== 'script-jail').map(
  (p) => p.dir,
);

describe('release.yml publish job (PKG-5)', () => {
  const steps = loadPublishSteps();
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

  it('every npm publish keeps --provenance and --access public', () => {
    // The publish step batches the three platform packages in a single `for`
    // loop and then publishes main, so there are fewer literal `npm publish`
    // lines than packages. Assert (a) every `npm publish` line carries both
    // flags, and (b) all four package dirs are referenced in the publish step.
    const publishLines = allRun
      .split('\n')
      .filter((line) => /\bnpm publish\b/.test(line));
    expect(
      publishLines.length,
      'expected at least one npm publish invocation',
    ).toBeGreaterThanOrEqual(1);
    for (const line of publishLines) {
      expect(line).toContain('--provenance');
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

  it('keeps NODE_AUTH_TOKEN referencing secrets.NPM_TOKEN', () => {
    const tokenStep = steps.find(
      (s) =>
        s.env &&
        Object.prototype.hasOwnProperty.call(s.env, 'NODE_AUTH_TOKEN'),
    );
    expect(
      tokenStep,
      'a publish step must set NODE_AUTH_TOKEN',
    ).toBeDefined();
    expect(String(tokenStep!.env!.NODE_AUTH_TOKEN)).toContain(
      'secrets.NPM_TOKEN',
    );
  });
});

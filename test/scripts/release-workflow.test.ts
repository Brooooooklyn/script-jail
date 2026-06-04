// script-jail — test/scripts/release-workflow.test.ts
//
// PKG-5: guards the build-once / download-forever release contract across the
// producer (.github/workflows/release-build.yml) and the release
// (.github/workflows/release.yml) workflows.
//
// The producer builds every binary image asset ONCE, pushes the 4 GHCR rootfs
// images, and uploads the binaries as TAG-SUFFIXED Actions artifacts
// (`release-assets-<tag>`, `mac-bin-<tag>`). The release run on the tag
// DOWNLOADS those exact artifacts (matched by the tag-suffixed name, since the
// producer ran on a different commit) and NEVER rebuilds them.
//
// The release `publish` job must, after downloading/verifying the producer's
// binary artifacts:
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
const PRODUCER_PATH = join(
  REPO_ROOT,
  '.github',
  'workflows',
  'release-build.yml',
);

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

function loadWorkflow(path: string): ParsedWorkflow {
  return parseYaml(readFileSync(path, 'utf8')) as ParsedWorkflow;
}

function loadPublishJob(): ParsedJob {
  const parsed = loadWorkflow(WORKFLOW_PATH);
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

  it('downloads the producer build artifacts by tag-suffixed name (never rebuilds)', () => {
    // The publish job must locate the release-build.yml producer run and
    // download `release-assets-<tag>` + `mac-bin-<tag>` — matched by the
    // tag-suffixed artifact NAME (the producer ran on a different commit, so a
    // commit-SHA match is impossible). github.ref_name is the tag here.
    const step = runScripts.find(
      (s) => s.includes('release-assets-') && s.includes('gh run download'),
    );
    expect(
      step,
      'a publish step must download the producer release-assets artifact',
    ).toBeDefined();
    // Tag-suffixed artifact names.
    expect(step).toMatch(/release-assets-\$\{TAG\}/);
    expect(step).toMatch(/mac-bin-\$\{TAG\}/);
    // Locates the producer run via the release-build workflow.
    expect(step).toContain('release-build.yml');
    // Clear failure when no producer run carries the artifact.
    expect(step).toMatch(/no release-build run found carrying/);
  });

  it('reads ${TAG} from github.ref_name in the producer-download step', () => {
    const step = steps.find(
      (s) => (s.run ?? '').includes('gh run download'),
    );
    expect(step, 'producer-download step must exist').toBeDefined();
    expect(step!.env, 'producer-download step must set TAG via env').toBeDefined();
    expect(String(step!.env!.TAG)).toContain('github.ref_name');
  });

  it('never rebuilds images: no rootfs/shim/kernel/Mach-O build or GHCR push in publish', () => {
    // Build-once / download-forever: every image asset comes from the producer.
    // The publish job must not contain any of the producer-only build steps.
    expect(allRun, 'publish must not run mkfs/rootfs build').not.toMatch(
      /pnpm build -- --runner-image=/,
    );
    expect(allRun, 'publish must not build the VZ kernel').not.toContain(
      'images/kernel/build.sh',
    );
    expect(allRun, 'publish must not cross-build the arm64 shim').not.toContain(
      '--shim-arm64',
    );
    expect(allRun, 'publish must not push GHCR images').not.toContain(
      'docker buildx build',
    );
    expect(allRun, 'publish must not push GHCR images').not.toContain('--push');
    // No reproducibility gate (moved out of the release entirely).
    expect(allRun).not.toMatch(/is not canonical-reproducible/);
  });

  it('does NOT pass --dist-source/--dist-cli-source to check-publish-artifacts.sh', () => {
    // The producer no longer ships dist/*; the shipped dist comes from the
    // tagged checkout (verified by the verify job + test.yml), so there is
    // nothing downloaded to compare against.
    const step = runScripts.find((s) =>
      s.includes('bash scripts/check-publish-artifacts.sh'),
    );
    expect(step, 'a publish step must run check-publish-artifacts.sh').toBeDefined();
    expect(step).toContain('--manifest');
    expect(step).toContain('--dir');
    expect(step, 'must not compare a downloaded dist/main.cjs').not.toContain(
      '--dist-source',
    );
    expect(step, 'must not compare a downloaded dist/cli.cjs').not.toContain(
      '--dist-cli-source',
    );
  });

  it('does NOT cmp downloaded dist artifacts (producer ships no dist)', () => {
    // The old "Verify Docker runtime JS artifacts" cmp step compared
    // artifacts/dist/* which no longer exists.
    expect(allRun).not.toContain('artifacts/dist/');
  });

  it('invokes scripts/assemble-npm-packages.mjs with --artifacts and --out', () => {
    const step = runScripts.find((s) =>
      s.includes('node scripts/assemble-npm-packages.mjs'),
    );
    expect(step, 'a publish step must run assemble-npm-packages.mjs').toBeDefined();
    expect(step).toContain('--artifacts');
    expect(step).toContain('--out');
  });

  it('gates each staged package via scripts/assert-npm-packlist.mjs', () => {
    const step = runScripts.find((s) =>
      s.includes('node scripts/assert-npm-packlist.mjs'),
    );
    expect(step, 'a publish step must run assert-npm-packlist.mjs').toBeDefined();
  });

  it('uploads dist/main.cjs + dist/cli.cjs from the tagged checkout, not artifacts/', () => {
    // The npm/Action dist bundles must ship from REPO_ROOT (the tagged checkout
    // with the real backfilled manifest), NOT from the producer's pre-backfill
    // artifacts. The release-asset upload lists them by their repo-root path.
    const uploadStep = steps.find((s) => s.uses?.includes('action-gh-release'));
    expect(uploadStep, 'release-asset upload step must exist').toBeDefined();
    const files = String(uploadStep!.with?.files ?? '');
    expect(files).toContain('dist/main.cjs');
    expect(files).toContain('dist/cli.cjs');
    // dist must NOT be sourced from the downloaded artifacts tree.
    expect(files, 'dist bundles must not come from artifacts/').not.toContain(
      'artifacts/dist/main.cjs',
    );
    expect(files).not.toContain('artifacts/dist/cli.cjs');
    // Binary assets DO come from the downloaded artifacts.
    expect(files).toContain('artifacts/images/rootfs-ubuntu-24.04.ext4');
    expect(files).toContain('artifacts/script-jail-vm-arm64-darwin');
  });

  it('publishes the three platform packages before the main package', () => {
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
    const step = runScripts.find((s) => /\bnpm view\b/.test(s));
    expect(
      step,
      'the publish step must use a read-only `npm view` existence probe to skip already-published versions',
    ).toBeDefined();
    expect(step).toMatch(/already published/i);
    expect(step).toMatch(/npm view .*version/);
    const viewIdx = step!.search(/\bnpm view\b/);
    const publishIdx = step!.search(/\bnpm publish\b/);
    expect(viewIdx, 'existence probe must precede the npm publish').toBeLessThan(
      publishIdx,
    );
  });

  it('preserves the version==tag gate', () => {
    const step = runScripts.find((s) => s.includes('package.json version'));
    expect(
      step,
      'the version-must-match-tag gate must remain in a publish step',
    ).toBeDefined();
    expect(step).toContain('must match tag');
  });

  it('publishes via OIDC — no NODE_AUTH_TOKEN / NPM_TOKEN anywhere in the job', () => {
    const jobJson = JSON.stringify(publishJob);
    expect(jobJson, 'publish job must not set NODE_AUTH_TOKEN').not.toContain(
      'NODE_AUTH_TOKEN',
    );
    expect(jobJson, 'publish job must not reference NPM_TOKEN').not.toContain(
      'NPM_TOKEN',
    );
  });

  it('grants id-token: write for OIDC and actions: read for cross-run download', () => {
    const perms = publishJob.permissions;
    expect(
      typeof perms === 'object' && perms !== null,
      'publish job must declare a permissions map',
    ).toBe(true);
    const map = perms as Record<string, string>;
    expect(map['id-token']).toBe('write');
    // Cross-run artifact download from release-build.yml needs actions:read.
    expect(map['actions']).toBe('read');
    expect(map['contents']).toBe('write');
    // The producer pushes GHCR now; publish only reads (login + inspect).
    expect(map['packages']).not.toBe('write');
  });

  it('upgrades npm to an OIDC-capable version (>= 11.5.1) before publishing', () => {
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
    // and `docker buildx imagetools inspect`s each REAL ref. The producer pushed
    // the images; this asserts EXISTENCE — catching a hand-copy typo / stale
    // digest that would otherwise ship in dist/main.cjs and break Docker-backend
    // consumers.
    const step = runScripts.find(
      (s) =>
        s.includes('artifact-manifest.ts') && s.includes('imagetools inspect'),
    );
    expect(
      step,
      'a publish step must verify pinned Docker digests against GHCR',
    ).toBeDefined();
    expect(step).toMatch(/does not resolve in GHCR/);
    expect(step).toContain('exit 1');
  });

  it('runs the Docker-digest GHCR gate before any npm publish', () => {
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

describe('release.yml verify job (no rebuild, manifest gate)', () => {
  const parsed = loadWorkflow(WORKFLOW_PATH);

  it('has no build-mac-bin job (Mach-O built by the producer)', () => {
    expect(parsed.jobs['build-mac-bin']).toBeUndefined();
  });

  it('replaces the heavy build job with a lightweight verify job', () => {
    expect(parsed.jobs.verify, 'release.yml must define a `verify` job').toBeDefined();
    // The old `build` job (image builds) is gone.
    expect(parsed.jobs.build).toBeUndefined();
  });

  it('publish depends on verify (so the gates block the publish)', () => {
    const needs = parsed.jobs.publish?.needs;
    const needsArr = Array.isArray(needs) ? needs : needs ? [needs] : [];
    expect(needsArr).toContain('verify');
  });

  it('verify gates that the committed manifest has NO placeholders', () => {
    const steps = parsed.jobs.verify?.steps ?? [];
    const run = steps.map((s) => s.run ?? '').join('\n');
    expect(
      run,
      'verify must fail when the manifest still carries PLACEHOLDER_SHA256_*',
    ).toContain('PLACEHOLDER_SHA256_');
    expect(run).toContain('exit 1');
  });

  it('verify never builds shipped images (no rootfs/kernel/shim/GHCR)', () => {
    const steps = parsed.jobs.verify?.steps ?? [];
    const run = steps.map((s) => s.run ?? '').join('\n');
    const usesList = steps.map((s) => s.uses ?? '').join('\n');
    expect(run).not.toMatch(/pnpm build -- --runner-image=/);
    expect(run).not.toContain('images/kernel/build.sh');
    expect(run).not.toContain('--shim-arm64');
    expect(run).not.toContain('docker buildx build');
    expect(usesList).not.toContain('docker/login-action');
  });

  it('verify asserts committed dist bundles are fresh (drift gate)', () => {
    const steps = parsed.jobs.verify?.steps ?? [];
    const run = steps.map((s) => s.run ?? '').join('\n');
    expect(run).toContain('git diff --exit-code');
    expect(run).toContain('dist/main.cjs');
    expect(run).toContain('dist/guest-agent.cjs');
  });
});

// The PRODUCER builds + pushes everything once. Guard its contract: it pushes
// the 4 GHCR images and uploads the binary assets under TAG-SUFFIXED artifact
// names (so the release run can find this run's output across commits).
describe('release-build.yml producer contract', () => {
  const parsed = loadWorkflow(PRODUCER_PATH);
  const buildJob = parsed.jobs?.build;
  const buildSteps = buildJob?.steps ?? [];

  it('is a workflow_dispatch producer with a required tag input', () => {
    const raw = readFileSync(PRODUCER_PATH, 'utf8');
    const wf = parseYaml(raw) as Record<string, unknown>;
    const on = wf.on as Record<string, unknown> | undefined;
    const dispatch = on?.workflow_dispatch as
      | { inputs?: Record<string, { required?: boolean }> }
      | undefined;
    expect(dispatch, 'producer must be workflow_dispatch').toBeDefined();
    expect(dispatch!.inputs?.tag?.required).toBe(true);
  });

  it('builds and pushes the 4 GHCR rootfs images', () => {
    const run = buildSteps.map((s) => s.run ?? '').join('\n');
    expect(run, 'producer must build the rootfs images').toMatch(
      /pnpm build -- --runner-image=/,
    );
    expect(run, 'producer must build the VZ kernels').toContain(
      'images/kernel/build.sh',
    );
    expect(run, 'producer must docker buildx --push the GHCR images').toContain(
      'docker buildx build',
    );
    expect(run).toContain('--push');
  });

  it('uploads the binary assets under release-assets-<tag> (tag-suffixed, no dist/*)', () => {
    const upload = buildSteps.find(
      (s) =>
        s.uses?.includes('upload-artifact') &&
        String(s.with?.name ?? '').includes('release-assets'),
    );
    expect(upload, 'producer must upload release-assets').toBeDefined();
    expect(String(upload!.with?.name)).toBe(
      'release-assets-${{ inputs.tag }}',
    );
    const paths = String(upload!.with?.path ?? '');
    // Binary image assets only.
    expect(paths).toContain('images/rootfs-ubuntu-24.04.ext4');
    expect(paths).toContain('images/libscriptjail.so');
    expect(paths).toContain('images/vmlinux-vz-arm64');
    // dist/* MUST NOT be in the producer artifact (it carries the placeholder
    // manifest; the release ships dist from the tagged checkout instead).
    expect(paths, 'producer must not upload dist/main.cjs').not.toContain(
      'dist/main.cjs',
    );
    expect(paths).not.toContain('dist/cli.cjs');
    expect(paths).not.toContain('dist/guest-agent.cjs');
    expect(paths).not.toContain('dist/preloads');
  });

  it('uploads the Mach-O helper under mac-bin-<tag>', () => {
    const macUpload = parsed.jobs?.['build-mac-bin']?.steps?.find(
      (s) =>
        s.uses?.includes('upload-artifact') &&
        String(s.with?.name ?? '').includes('mac-bin'),
    );
    expect(macUpload, 'producer must upload the Mach-O under mac-bin-<tag>').toBeDefined();
    expect(String(macUpload!.with?.name)).toBe('mac-bin-${{ inputs.tag }}');
    // The on-disk filename inside the artifact is unchanged.
    expect(String(macUpload!.with?.path)).toContain(
      'script-jail-vm-arm64-darwin',
    );
  });
});

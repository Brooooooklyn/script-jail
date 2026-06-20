// script-jail — scripts/release-backfill.ts
//
// Release-backfill CLI.  Given a producer GitHub Actions run id + a version,
// it downloads the run's artifacts + build log, recomputes ALL 16 release-
// manifest pins, regenerates src/action/artifact-manifest.ts, bumps
// package.json, rebuilds dist/, runs the fail-closed validators, and PRINTS
// (does not run) the git commit/tag/push block.
//
// This replaces the error-prone manual 16-hash hand-edit done each release.
//
// Usage:
//   pnpm release:backfill --run <id> --version X.Y.Z \
//     [--repo owner/name]      (default Brooooooklyn/script-jail)
//     [--dir <tree> --log <build-log.txt>]   OFFLINE mode — pre-downloaded tree +
//                    build log.  Must be given TOGETHER (operator vouches both
//                    came from the same run); neither = fetch + bind to --run.
//     [--no-build]                    (skip the dist/ rebuild)
//     [--build-job <id>]              (pin the build job id; bound to --run)
//
// The `gh` I/O + orchestration lives HERE; the pure recompute/codegen core
// lives in src/release/backfill.ts (so the unit tests need no network).
//
// Mind the `v` prefix: --version takes the BARE version (0.2.5); the manifest
// tag is `v0.2.5` and package.json version is the bare `0.2.5`.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertBareVersion,
  assertOfflineInputsConsistent,
  assertRepo,
  assertRunId,
  buildManifest,
  bumpVersion,
  prepareCleanStagingDir,
  renderArtifactManifestTs,
  selectBuildJobId,
} from '../src/release/backfill.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const DEFAULT_REPO = 'Brooooooklyn/script-jail';

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

interface CliArgs {
  run: string;
  version: string;
  repo: string;
  dir?: string;
  log?: string;
  noBuild: boolean;
  buildJob?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const out: Partial<CliArgs> = { repo: DEFAULT_REPO, noBuild: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`release-backfill: ${arg} requires a value`);
      return v;
    };
    switch (arg) {
      case '--run':
        out.run = next();
        break;
      case '--version':
        out.version = next();
        break;
      case '--repo':
        out.repo = next();
        break;
      case '--dir':
        out.dir = next();
        break;
      case '--log':
        out.log = next();
        break;
      case '--no-build':
        out.noBuild = true;
        break;
      case '--build-job':
        out.buildJob = next();
        break;
      default:
        throw new Error(`release-backfill: unknown argument: ${arg}`);
    }
  }
  if (out.run === undefined) throw new Error('release-backfill: --run <id> is required');
  if (out.version === undefined) throw new Error('release-backfill: --version X.Y.Z is required');
  // Strict shapes: these flow into generated TS + GHCR refs + (for --run) a
  // staging directory name, so reject anything that isn't a numeric run id / bare
  // semver / 'owner/name' (also rejects a leading 'v' + any injection or path
  // metacharacter).
  assertRunId(out.run);
  assertBareVersion(out.version);
  assertRepo(out.repo ?? DEFAULT_REPO);
  return out as CliArgs;
}

// ---------------------------------------------------------------------------
// gh helpers
// ---------------------------------------------------------------------------

function run(cmd: string, args: string[], opts: { capture?: boolean } = {}): string {
  process.stderr.write(`+ ${cmd} ${args.join(' ')}\n`);
  return execFileSync(cmd, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: opts.capture ? ['ignore', 'pipe', 'inherit'] : ['ignore', 'inherit', 'inherit'],
    maxBuffer: 256 * 1024 * 1024,
  }) as unknown as string;
}

/** Download the producer artifacts into `<dir>/images` and `<dir>` (mac-bin). */
function downloadArtifacts(runId: string, repo: string, version: string, dir: string): void {
  mkdirSync(join(dir, 'images'), { recursive: true });
  run('gh', [
    'run', 'download', runId,
    '--repo', repo,
    '--name', `release-assets-v${version}`,
    '--dir', join(dir, 'images'),
  ]);
  run('gh', [
    'run', 'download', runId,
    '--repo', repo,
    '--name', `mac-bin-v${version}`,
    '--dir', dir,
  ]);
}

/**
 * Resolve the `build` job id of the producer run.  Always lists the jobs of
 * `runId`; a caller `override` (--build-job) is BOUND to this run via
 * {@link selectBuildJobId} so its log can't come from a different run than the
 * artifacts being hashed.
 */
function resolveBuildJobId(runId: string, repo: string, override?: string): string {
  const json = run('gh', ['run', 'view', runId, '--repo', repo, '--json', 'jobs'], {
    capture: true,
  });
  const parsed = JSON.parse(json) as { jobs: Array<{ databaseId: number; name: string }> };
  return selectBuildJobId(parsed.jobs, override);
}

/** Fetch the build job's log text. */
function fetchBuildLog(buildJobId: string, repo: string): string {
  return run('gh', ['run', 'view', '--job', buildJobId, '--repo', repo, '--log'], {
    capture: true,
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const tag = `v${args.version}`;

  // Provenance gate: --dir + --log are an all-or-nothing OFFLINE mode.  Mixing a
  // local input with a fetched one would pair one run's artifacts with another
  // run's digests (see assertOfflineInputsConsistent).
  const offline = assertOfflineInputsConsistent({ dir: args.dir, log: args.log });
  if (offline) {
    process.stderr.write(
      `release-backfill: ⚠ OFFLINE MODE — using operator-provided --dir + --log; their\n` +
        `  provenance is NOT bound to run ${args.run}. You are vouching that BOTH came from\n` +
        `  the same producer run as the artifacts you are pinning.\n`,
    );
  }

  // (1) Resolve the staged tree.
  let stagedDir: string;
  if (args.dir !== undefined) {
    stagedDir = resolve(args.dir);
    process.stderr.write(`release-backfill: using pre-downloaded tree at ${stagedDir}\n`);
  } else {
    // Stage under a per-RUN directory and WIPE it before downloading.  Two
    // different producer runs for the SAME version would otherwise share
    // `.release-backfill/<tag>`, and `gh run download` only overwrites matching
    // files — a file present in an earlier run but absent in this run's artifact
    // set would survive and be hashed as if it came from THIS run (the hasher
    // only existsSync-checks each expected path).  Per-run dir + fresh wipe binds
    // every hashed byte to args.run.  prepareCleanStagingDir fail-closes if the
    // `.release-backfill` root (or the per-run child) is a symlink, so the wipe
    // can never delete a tree outside the repo.  (args.run is asserted numeric.)
    stagedDir = prepareCleanStagingDir(
      join(REPO_ROOT, '.release-backfill'),
      `${tag}-${args.run}`,
    );
    downloadArtifacts(args.run, args.repo, args.version, stagedDir);
  }

  // (2) Resolve the build log.
  let buildLogText: string;
  if (args.log !== undefined) {
    buildLogText = readFileSync(resolve(args.log), 'utf8');
    process.stderr.write(`release-backfill: using build log from ${resolve(args.log)}\n`);
  } else {
    // --build-job is bound to args.run inside resolveBuildJobId (it must be a
    // job of the run the artifacts came from), so a stale/foreign job's log
    // can't be paired with this run's hashed artifacts.
    const buildJobId = resolveBuildJobId(args.run, args.repo, args.buildJob);
    buildLogText = fetchBuildLog(buildJobId, args.repo);
  }

  // (3) Recompute + codegen + version bump.
  const manifest = await buildManifest({
    stagedDir,
    buildLogText,
    repo: args.repo,
    version: args.version,
  });
  const manifestTs = renderArtifactManifestTs(manifest);
  const manifestPath = join(REPO_ROOT, 'src', 'action', 'artifact-manifest.ts');
  writeFileSync(manifestPath, manifestTs);
  process.stderr.write(`release-backfill: wrote ${manifestPath}\n`);

  const pkgPath = join(REPO_ROOT, 'package.json');
  bumpVersion(pkgPath, args.version);
  process.stderr.write(`release-backfill: bumped ${pkgPath} → ${args.version}\n`);

  // (4) Rebuild dist/ (unless --no-build).
  if (!args.noBuild) {
    run('pnpm', ['build:bundle']);
    run('pnpm', ['build:cli']);
    run('pnpm', ['build:guest-agent']);
    run('pnpm', ['build:repro-hash']);
  } else {
    process.stderr.write('release-backfill: --no-build given; skipping dist/ rebuild\n');
  }

  // (5) Fail-closed validators.
  run('pnpm', ['exec', 'oxnode', 'scripts/validate-manifest.ts']);
  run('bash', [
    'scripts/check-publish-artifacts.sh',
    '--manifest', 'src/action/artifact-manifest.ts',
    '--dir', stagedDir,
  ]);

  // (6) Print (do NOT run) the git commit/tag/push block.
  const block = [
    '',
    '============================================================',
    `release-backfill: manifest + version bumped for ${tag}.`,
    'Review the diff, then run the following to cut the release:',
    '============================================================',
    '',
    'git add src/action/artifact-manifest.ts package.json dist/',
    `git commit -m "release: backfill ${tag} artifact manifest + bump version" \\`,
    `  -m "Producer run ${args.run}. All 12 file SHAs recomputed from the producer" \\`,
    '  -m "artifacts (canonical repro-hash for the rootfs ext4s, plain sha256 for" \\',
    '  -m "the rest); the 4 GHCR digests read from the buildx push log."',
    `git tag -s ${tag} -m "${tag}"`,
    'git push origin HEAD',
    `git push origin ${tag}`,
    '',
  ].join('\n');
  process.stdout.write(`${block}\n`);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`release-backfill: ${message}\n`);
  process.exit(1);
});

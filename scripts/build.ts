// script-jail — scripts/build.ts
// Master build coordinator. Invoked via `oxnode scripts/build.ts`.
//
// Steps:
//   1. Compile the action entry: esbuild src/main.ts → dist/main.cjs
//   2. Build the C shim: src/shim/build.sh → images/libscriptjail.so (skip on macOS)
//   3. Build the rootfs(es): src/rootfs/build.ts for the selected runner image.
//
// Flags:
//   --skip-rootfs                                skip rootfs build (e.g., when you
//                                                only need the action bundle)
//   --skip-bundle                                skip the esbuild action-bundle step
//                                                (use when the bundle was already
//                                                built in a prior invocation, e.g.
//                                                a release workflow that builds the
//                                                bundle once then loops over two
//                                                runner images for rootfs builds)
//   --skip-shim                                  skip the C-shim build step (same
//                                                rationale as --skip-bundle)
//   --runner-image=ubuntu-22.04|ubuntu-24.04     which Ubuntu base to build the
//                                                rootfs against
//   --all                                        build BOTH runner-image rootfses
//                                                (overrides --runner-image)
//
// Default: build a single rootfs for whichever runner image we detect (via
// `detectRunnerImage()`); falls back to `ubuntu-24.04` when detection fails
// (e.g. on macOS dev hosts).

import { execSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildRootfs,
  formatBytes,
  imageOutputPath,
  parseRunnerImageArg,
  type BuildInput,
  type RunnerImage,
} from '../src/rootfs/build.js';
import { detectRunnerImage } from '../src/action/runner-image.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

interface ParsedArgs {
  skipRootfs: boolean;
  /** Skip the esbuild action-bundle step. */
  skipBundle: boolean;
  /** Skip the C-shim build step. */
  skipShim: boolean;
  /** When `--all`, build both runner-image rootfses. */
  all: boolean;
  /** Explicit `--runner-image=…` choice; ignored when `--all`. */
  runnerImage: RunnerImage | undefined;
}

function parseArgs(): ParsedArgs {
  const args = process.argv.slice(2);

  const skipRootfs = args.includes('--skip-rootfs');
  const skipBundle = args.includes('--skip-bundle');
  const skipShim = args.includes('--skip-shim');
  const all = args.includes('--all');
  const runnerImage = parseRunnerImageArg(args);

  // Warn about unknown flags so typos don't silently no-op.
  for (const arg of args) {
    if (
      arg === '--skip-rootfs' ||
      arg === '--skip-bundle' ||
      arg === '--skip-shim' ||
      arg === '--all' ||
      /^--runner-image=/.test(arg)
    ) continue;
    console.warn(`[build] Unknown flag: ${arg}`);
  }

  return { skipRootfs, skipBundle, skipShim, all, runnerImage };
}

/**
 * Pick the default runner image when none is explicitly requested.
 *
 * Tries to detect the current host via `detectRunnerImage()`; if that throws
 * (typical on macOS dev hosts where `/etc/os-release` is absent and `ImageOS`
 * is unset), falls back to `ubuntu-24.04`.
 *
 * Both branches log via `console.log` — the detection result is informational,
 * not an error, even when detection fails (we have a sensible fallback).
 */
function defaultRunnerImage(): RunnerImage {
  try {
    const img = detectRunnerImage();
    console.log(
      `[build] No --runner-image flag; detected ${img} from ImageOS/os-release.`,
    );
    return img;
  } catch {
    console.log(
      '[build] No --runner-image flag and detection failed; falling back to ubuntu-24.04.',
    );
    return 'ubuntu-24.04';
  }
}

// ---------------------------------------------------------------------------
// Step 1 — Build action bundle
// ---------------------------------------------------------------------------

function buildActionBundle(): void {
  console.log('[build] Building action bundle: src/main.ts → dist/main.cjs …');
  const esbuildBin = join(REPO_ROOT, 'node_modules', '.bin', 'esbuild');
  const mainSrc = join(REPO_ROOT, 'src', 'main.ts');
  const mainOut = join(REPO_ROOT, 'dist', 'main.js');

  execSync(
    `"${esbuildBin}" "${mainSrc}" ` +
    `--bundle --platform=node --format=cjs --target=node20 ` +
    `--outfile="${mainOut}"`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );
  console.log('[build] dist/main.cjs built.');
}

// ---------------------------------------------------------------------------
// Step 2 — Build C shim
// ---------------------------------------------------------------------------

function buildShim(): void {
  if (process.platform === 'darwin') {
    console.warn(
      '[build] WARNING: Running on macOS — skipping src/shim/build.sh (requires Linux cc).\n' +
      '[build]          The .so is not needed for macOS development; build in CI or Linux.',
    );
    return;
  }

  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail.so');
  if (existsSync(shimOut)) {
    console.log('[build] images/libscriptjail.so already present, skipping shim build.');
    return;
  }

  console.log('[build] Building C shim: src/shim/build.sh …');
  const buildSh = join(REPO_ROOT, 'src', 'shim', 'build.sh');
  execSync(`sh "${buildSh}"`, { stdio: 'inherit', cwd: REPO_ROOT });
  console.log('[build] images/libscriptjail.so built.');
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

interface ArtifactSummary {
  path: string;
  sizeBytes?: number;
}

function collectSummary(artifacts: ArtifactSummary[]): void {
  console.log('\n[build] ========= Build Summary =========');
  for (const art of artifacts) {
    if (existsSync(art.path)) {
      const bytes = statSync(art.path).size;
      console.log(`  ${art.path}  (${formatBytes(bytes)})`);
    } else {
      console.log(`  ${art.path}  [NOT PRODUCED — see warnings above]`);
    }
  }
  console.log('[build] ====================================\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { skipRootfs, skipBundle, skipShim, all, runnerImage } = parseArgs();

  const artifacts: ArtifactSummary[] = [];

  // Step 1: action bundle
  if (skipBundle) {
    console.log('[build] --skip-bundle passed; skipping action-bundle build.');
  } else {
    buildActionBundle();
  }
  artifacts.push({ path: join(REPO_ROOT, 'dist', 'main.js') });

  // Step 2: C shim
  if (skipShim) {
    console.log('[build] --skip-shim passed; skipping C-shim build.');
  } else {
    buildShim();
  }
  artifacts.push({ path: join(REPO_ROOT, 'images', 'libscriptjail.so') });

  // Step 3: rootfs
  if (skipRootfs) {
    console.log('[build] --skip-rootfs passed; skipping rootfs build.');
  } else {
    const targets: ReadonlyArray<RunnerImage> = all
      ? ['ubuntu-22.04', 'ubuntu-24.04']
      : [runnerImage ?? defaultRunnerImage()];

    for (const target of targets) {
      const rootfsInput: BuildInput = {
        runnerImage: target,
        outputDir: join(REPO_ROOT, 'images'),
      };

      await buildRootfs(rootfsInput);
      artifacts.push({ path: imageOutputPath(rootfsInput) });
    }
  }

  // Summary
  collectSummary(artifacts);
}

main().catch((err: unknown) => {
  console.error(String(err instanceof Error ? err.stack ?? err.message : err));
  process.exit(1);
});

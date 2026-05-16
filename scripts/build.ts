// npm-jar — scripts/build.ts
// Master build coordinator. Invoked via `oxnode scripts/build.ts`.
//
// Steps:
//   1. Compile the action entry: esbuild src/main.ts → dist/main.js
//   2. Build the C shim: src/shim/build.sh → images/libnpmjar.so (skip on macOS)
//   3. Build the rootfs(es): src/rootfs/build.ts for the selected runner image.
//
// Flags:
//   --skip-rootfs                                skip rootfs build (e.g., when you
//                                                only need the action bundle)
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
  /** When `--all`, build both runner-image rootfses. */
  all: boolean;
  /** Explicit `--runner-image=…` choice; ignored when `--all`. */
  runnerImage: RunnerImage | undefined;
}

function parseArgs(): ParsedArgs {
  const args = process.argv.slice(2);

  const skipRootfs = args.includes('--skip-rootfs');
  const all = args.includes('--all');
  const runnerImage = parseRunnerImageArg(args);

  // Warn about unknown flags so typos don't silently no-op.
  for (const arg of args) {
    if (
      arg === '--skip-rootfs' ||
      arg === '--all' ||
      /^--runner-image=/.test(arg)
    ) continue;
    console.warn(`[build] Unknown flag: ${arg}`);
  }

  return { skipRootfs, all, runnerImage };
}

/**
 * Pick the default runner image when none is explicitly requested.
 *
 * Tries to detect the current host via `detectRunnerImage()`; if that throws
 * (typical on macOS dev hosts where `/etc/os-release` is absent and `ImageOS`
 * is unset), falls back to `ubuntu-24.04`.
 */
function defaultRunnerImage(): RunnerImage {
  try {
    return detectRunnerImage();
  } catch {
    return 'ubuntu-24.04';
  }
}

// ---------------------------------------------------------------------------
// Step 1 — Build action bundle
// ---------------------------------------------------------------------------

function buildActionBundle(): void {
  console.log('[build] Building action bundle: src/main.ts → dist/main.js …');
  const esbuildBin = join(REPO_ROOT, 'node_modules', '.bin', 'esbuild');
  const mainSrc = join(REPO_ROOT, 'src', 'main.ts');
  const mainOut = join(REPO_ROOT, 'dist', 'main.js');

  execSync(
    `"${esbuildBin}" "${mainSrc}" ` +
    `--bundle --platform=node --format=cjs --target=node20 ` +
    `--outfile="${mainOut}"`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );
  console.log('[build] dist/main.js built.');
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

  const shimOut = join(REPO_ROOT, 'images', 'libnpmjar.so');
  if (existsSync(shimOut)) {
    console.log('[build] images/libnpmjar.so already present, skipping shim build.');
    return;
  }

  console.log('[build] Building C shim: src/shim/build.sh …');
  const buildSh = join(REPO_ROOT, 'src', 'shim', 'build.sh');
  execSync(`sh "${buildSh}"`, { stdio: 'inherit', cwd: REPO_ROOT });
  console.log('[build] images/libnpmjar.so built.');
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
  const { skipRootfs, all, runnerImage } = parseArgs();

  const artifacts: ArtifactSummary[] = [];

  // Step 1: action bundle
  buildActionBundle();
  artifacts.push({ path: join(REPO_ROOT, 'dist', 'main.js') });

  // Step 2: C shim
  buildShim();
  artifacts.push({ path: join(REPO_ROOT, 'images', 'libnpmjar.so') });

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

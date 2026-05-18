// script-jail — scripts/build.ts
// Master build coordinator. Invoked via `oxnode scripts/build.ts`.
//
// Steps:
//   1. Compile the action entry: esbuild src/main.ts → dist/main.cjs
//   2. Build the Rust shim: cargo build src/shim/Cargo.toml → images/libscriptjail.so (skip on macOS)
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
//   --skip-shim                                  skip the Rust-shim build step (same
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
import { copyFileSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
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
  /** Skip the Rust-shim build step. */
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
  // action.yml's `main:` field points at dist/main.cjs, and `pnpm build:bundle`
  // writes there too — so this coordinator MUST also write to .cjs. A prior
  // revision of this file wrote to dist/main.js, which left a stale bundle in
  // the working tree that bypassed gates added to dist/main.cjs (e.g. the
  // audit_bypass hard-fail in commit fe13357). action.yml is the source of
  // truth: keep this aligned with it.
  console.log('[build] Building action bundle: src/main.ts → dist/main.cjs …');
  const esbuildBin = join(REPO_ROOT, 'node_modules', '.bin', 'esbuild');
  const mainSrc = join(REPO_ROOT, 'src', 'main.ts');
  const mainOut = join(REPO_ROOT, 'dist', 'main.cjs');

  execSync(
    `"${esbuildBin}" "${mainSrc}" ` +
    `--bundle --platform=node --format=cjs --target=node20 ` +
    `--outfile="${mainOut}"`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );
  console.log('[build] dist/main.cjs built.');
}

// ---------------------------------------------------------------------------
// Step 2 — Build Rust shim
// ---------------------------------------------------------------------------

/**
 * Files whose mtime gates whether `images/libscriptjail.so` is fresh enough
 * to reuse. Touching any of these makes `buildShim` rebuild from cargo.
 *
 * Kept narrow on purpose: these are the inputs cargo actually consumes for
 * the `script-jail-shim` crate. Adding more (e.g. an entire src/shim tree
 * glob) would be more thorough but would also force a rebuild on unrelated
 * edits — `Cargo.toml` already declares the source layout.
 */
export function shimSourceInputs(repoRoot: string = REPO_ROOT): ReadonlyArray<string> {
  return [
    join(repoRoot, 'src', 'shim', 'Cargo.toml'),
    join(repoRoot, 'src', 'shim', 'Cargo.lock'),
    join(repoRoot, 'src', 'shim', 'rust-toolchain.toml'),
    join(repoRoot, 'src', 'shim', 'src', 'lib.rs'),
  ];
}

/**
 * Pure decision helper for "is the cached `libscriptjail.so` stale?".
 *
 * `artifactMtimeMs` is `null` when the artifact doesn't exist (→ rebuild).
 * `sourceMtimesMs` is the list of mtimes for every shim source input that
 * exists on disk; empty when none are found (→ rebuild defensively).
 *
 * Returns `true` when ANY of:
 *   - the artifact does not exist;
 *   - no shim sources can be found (degenerate / broken checkout);
 *   - any source is newer than the artifact.
 *
 * Pure / no IO — separated from `shimArtifactIsStale` to make it
 * straightforward to unit-test the comparison rules without touching the
 * filesystem.
 */
export function decideShimRebuild(
  artifactMtimeMs: number | null,
  sourceMtimesMs: ReadonlyArray<number>,
): boolean {
  if (artifactMtimeMs === null) return true;
  if (sourceMtimesMs.length === 0) return true;
  const latestSource = Math.max(...sourceMtimesMs);
  return latestSource > artifactMtimeMs;
}

/**
 * Inspect the filesystem and decide whether `libscriptjail.so` needs to be
 * rebuilt. See `decideShimRebuild` for the rule.
 *
 * Missing source files are skipped silently — they cannot have been an input
 * to whatever produced the artifact, so treating them as "ancient" would be
 * misleading.
 */
export function shimArtifactIsStale(
  shimOut: string,
  sources: ReadonlyArray<string> = shimSourceInputs(),
): boolean {
  const artifactMtime = existsSync(shimOut) ? statSync(shimOut).mtimeMs : null;
  const sourceMtimes: number[] = [];
  for (const path of sources) {
    if (!existsSync(path)) continue;
    sourceMtimes.push(statSync(path).mtimeMs);
  }
  return decideShimRebuild(artifactMtime, sourceMtimes);
}

function buildShim(): void {
  if (process.platform === 'darwin') {
    console.warn(
      '[build] WARNING: Running on macOS — skipping shim build (requires Linux toolchain).\n' +
      '[build]          The .so is not needed for macOS development; build in CI or Linux.',
    );
    return;
  }

  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail.so');

  // Freshness check: only reuse `images/libscriptjail.so` when every shim
  // input (Cargo.toml/Cargo.lock/rust-toolchain.toml/src/lib.rs) is older
  // than the artifact. Any source edit forces a rebuild.
  //
  // Defence in depth: the rootfs build also runs `validateShimFile` to catch
  // *malformed* artifacts (wrong arch, truncated header, no PT_DYNAMIC). This
  // mtime check protects against the *silently-stale* case that validation
  // cannot detect — a structurally-valid .so produced from out-of-date source.
  if (!shimArtifactIsStale(shimOut)) {
    console.log(
      '[build] images/libscriptjail.so is up-to-date relative to shim sources; ' +
      'skipping shim build.',
    );
    return;
  }

  if (existsSync(shimOut)) {
    console.log(
      '[build] images/libscriptjail.so is older than shim sources; rebuilding via cargo …',
    );
  } else {
    console.log('[build] Building Rust shim via cargo …');
  }

  const manifest = join(REPO_ROOT, 'src', 'shim', 'Cargo.toml');
  execSync(
    `cargo build --release --manifest-path "${manifest}"`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );

  mkdirSync(join(REPO_ROOT, 'images'), { recursive: true });
  copyFileSync(
    join(REPO_ROOT, 'src', 'shim', 'target', 'release', 'libscriptjail.so'),
    shimOut,
  );
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
  artifacts.push({ path: join(REPO_ROOT, 'dist', 'main.cjs') });

  // Step 2: Rust shim
  if (skipShim) {
    console.log('[build] --skip-shim passed; skipping Rust-shim build.');
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

// Only run main() when this file is the CLI entry point. Tests import the
// exported `decideShimRebuild` / `shimArtifactIsStale` helpers; they must NOT
// trigger a full build at import time.
const isMain =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === __filename;

if (isMain) {
  main().catch((err: unknown) => {
    console.error(String(err instanceof Error ? err.stack ?? err.message : err));
    process.exit(1);
  });
}

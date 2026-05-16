// npm-jar — scripts/build.ts
// Master build coordinator. Invoked via `oxnode scripts/build.ts`.
//
// Steps:
//   1. Compile the action entry: esbuild src/main.ts → dist/main.js
//   2. Build the C shim: src/shim/build.sh → images/libnpmjar.so (skip on macOS)
//   3. Build the rootfs(es): src/rootfs/build.ts for each (nodeMajor, pm) combo
//
// Flags:
//   --skip-rootfs        skip rootfs build (e.g., when you only need the action bundle)
//   --node-major=<N>     override Node.js major version (default: 20)
//   --pm=<pm>            override package manager (default: pnpm)

import { execSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildRootfs, formatBytes, imageOutputPath } from '../src/rootfs/build.js';
import type { BuildInput } from '../src/rootfs/build.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

function parseArgs(): {
  skipRootfs: boolean;
  nodeMajor: number;
  pm: 'npm' | 'pnpm' | 'yarn';
} {
  const args = process.argv.slice(2);

  const skipRootfs = args.includes('--skip-rootfs');

  let nodeMajor = 20;
  let pm: 'npm' | 'pnpm' | 'yarn' = 'pnpm';

  for (const arg of args) {
    const majorMatch = /^--node-major=(\d+)$/.exec(arg);
    if (majorMatch) {
      nodeMajor = parseInt(majorMatch[1] ?? '20', 10);
      continue;
    }

    const pmMatch = /^--pm=(npm|pnpm|yarn)$/.exec(arg);
    if (pmMatch) {
      const parsedPm = pmMatch[1];
      if (parsedPm === 'npm' || parsedPm === 'pnpm' || parsedPm === 'yarn') {
        pm = parsedPm;
      }
      continue;
    }

    if (arg !== '--skip-rootfs') {
      console.warn(`[build] Unknown flag: ${arg}`);
    }
  }

  return { skipRootfs, nodeMajor, pm };
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
  const { skipRootfs, nodeMajor, pm } = parseArgs();

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
    const rootfsInput: BuildInput = {
      nodeMajor,
      pm,
      outputDir: join(REPO_ROOT, 'images'),
    };

    await buildRootfs(rootfsInput);
    artifacts.push({ path: imageOutputPath(rootfsInput) });
  }

  // Summary
  collectSummary(artifacts);
}

main().catch((err: unknown) => {
  console.error(String(err instanceof Error ? err.stack ?? err.message : err));
  process.exit(1);
});

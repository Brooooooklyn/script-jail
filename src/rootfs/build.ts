// script-jail — src/rootfs/build.ts
// Orchestrates building the Firecracker rootfs ext4 image.
//
// In v2 the rootfs is keyed by Ubuntu major (`ubuntu-22.04`, `ubuntu-24.04`)
// rather than by `(node-major, package-manager)`: Node ships into the VM at
// runtime via a third virtio drive packed by the action (see
// `src/action/firecracker/overlay.ts`).  The rootfs therefore only needs to
// be ABI-compatible with whatever the host runner provides.
//
// Steps:
//   1. Bundle src/guest/agent.ts → dist/guest-agent.cjs via esbuild
//   2. Copy the .cjs preloads to dist/preloads/
//   3. Ensure images/libscriptjail.so is present (build if not, skip on macOS)
//   4. docker build → script-jail-rootfs:<runnerImage>
//   5. docker export → tar → directory → ext4 image
//   6. Write images/rootfs-<runnerImage>.ext4
//   7. Report size; warn if > 200 MB

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, statSync, copyFileSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported runner images.  Must stay in sync with `src/action/runner-image.ts`. */
export type RunnerImage = 'ubuntu-22.04' | 'ubuntu-24.04';

export interface BuildInput {
  runnerImage: RunnerImage;
  /** Directory where images/*.ext4 are written. Defaults to <repo root>/images */
  outputDir: string;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
/** Repo root: two levels up from src/rootfs/ */
const REPO_ROOT = join(__dirname, '..', '..');

// ---------------------------------------------------------------------------
// Pure helpers (unit-testable)
// ---------------------------------------------------------------------------

/** Compute the output ext4 image filename. */
export function imageFilename(input: Pick<BuildInput, 'runnerImage'>): string {
  return `rootfs-${input.runnerImage}.ext4`;
}

/** Compute the full output path for the ext4 image. */
export function imageOutputPath(input: BuildInput): string {
  return join(input.outputDir, imageFilename(input));
}

/** Docker image tag for this runner image. */
export function dockerTag(input: Pick<BuildInput, 'runnerImage'>): string {
  return `script-jail-rootfs:${input.runnerImage}`;
}

/** Map a runner image to its `ubuntu:<version>` base tag. */
export function ubuntuBaseTag(input: Pick<BuildInput, 'runnerImage'>): string {
  const versions: Record<RunnerImage, string> = {
    'ubuntu-22.04': '22.04',
    'ubuntu-24.04': '24.04',
  };
  return `ubuntu:${versions[input.runnerImage]}`;
}

/** Extract the bare Ubuntu major version (e.g. `22.04`) from a runner image. */
export function ubuntuMajor(input: Pick<BuildInput, 'runnerImage'>): string {
  // ubuntuBaseTag is `ubuntu:<version>`; strip the prefix.
  return ubuntuBaseTag(input).slice('ubuntu:'.length);
}

/** Return true when the process is running on macOS. */
export function isMacOS(): boolean {
  return process.platform === 'darwin';
}

/** Return true when the process is running on Linux. */
export function isLinux(): boolean {
  return process.platform === 'linux';
}

/** Format bytes as a human-readable string (e.g. "123.4 MB"). */
export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Threshold in bytes above which we warn about image size. */
export const SIZE_WARN_THRESHOLD_BYTES = 200 * 1024 * 1024; // 200 MB

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

function run(cmd: string, opts?: { cwd?: string }): void {
  execSync(cmd, { stdio: 'inherit', cwd: opts?.cwd ?? REPO_ROOT });
}

function runCapture(cmd: string, opts?: { cwd?: string }): string {
  return execSync(cmd, { cwd: opts?.cwd ?? REPO_ROOT }).toString().trim();
}

function commandExists(cmd: string): boolean {
  const result = spawnSync('which', [cmd], { stdio: 'ignore' });
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// Step 1 — Bundle agent
// ---------------------------------------------------------------------------

function bundleAgent(): void {
  const agentSrc = join(REPO_ROOT, 'src', 'guest', 'agent.ts');
  const agentOut = join(REPO_ROOT, 'dist', 'guest-agent.cjs');

  mkdirSync(join(REPO_ROOT, 'dist'), { recursive: true });

  const esbuildBin = join(REPO_ROOT, 'node_modules', '.bin', 'esbuild');
  run(
    `"${esbuildBin}" "${agentSrc}" ` +
    `--bundle --platform=node --format=cjs --target=node20 ` +
    `--outfile="${agentOut}"`,
  );
  console.log(`[rootfs] Bundled agent → dist/guest-agent.cjs`);
}

// ---------------------------------------------------------------------------
// Step 2 — Copy preloads
// ---------------------------------------------------------------------------

function copyPreloads(): void {
  const preloadsDir = join(REPO_ROOT, 'dist', 'preloads');
  mkdirSync(preloadsDir, { recursive: true });

  const files: ReadonlyArray<string> = ['platform-spoof.cjs', 'dlopen-block.cjs', 'env-spy.cjs'];
  for (const file of files) {
    const src = join(REPO_ROOT, 'src', 'guest', file);
    const dst = join(preloadsDir, file);
    copyFileSync(src, dst);
    console.log(`[rootfs] Copied ${file} → dist/preloads/${file}`);
  }
}

// ---------------------------------------------------------------------------
// Step 3 — Ensure libscriptjail.so
// ---------------------------------------------------------------------------

function ensureShim(): boolean {
  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail.so');

  if (existsSync(shimOut)) {
    console.log(`[rootfs] libscriptjail.so already present.`);
    return true;
  }

  if (isMacOS()) {
    console.warn(
      '[rootfs] WARNING: Running on macOS — cannot build libscriptjail.so (requires Linux toolchain).\n' +
      '[rootfs]          Skipping shim build. The docker build step will also be skipped.\n' +
      '[rootfs]          To build the full rootfs, run this script on a Linux host or CI.',
    );
    return false;
  }

  console.log(`[rootfs] Building libscriptjail.so via cargo …`);
  const manifest = join(REPO_ROOT, 'src', 'shim', 'Cargo.toml');
  run(`cargo build --release --manifest-path "${manifest}"`);

  mkdirSync(join(REPO_ROOT, 'images'), { recursive: true });
  copyFileSync(
    join(REPO_ROOT, 'src', 'shim', 'target', 'release', 'libscriptjail.so'),
    shimOut,
  );

  if (!existsSync(shimOut)) {
    throw new Error(`[rootfs] cargo build ran but ${shimOut} was not produced.`);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Step 4 — Docker build
// ---------------------------------------------------------------------------

function dockerBuild(input: BuildInput): void {
  const tag = dockerTag(input);
  const dockerfile = join(REPO_ROOT, 'src', 'rootfs', 'Dockerfile.base');
  run(
    `docker build ` +
    `--build-arg UBUNTU_MAJOR=${ubuntuMajor(input)} ` +
    `-f "${dockerfile}" ` +
    `-t "${tag}" ` +
    `.`,
  );
  console.log(`[rootfs] Built docker image: ${tag}`);
}

// ---------------------------------------------------------------------------
// Step 5+6 — Export container → ext4
// ---------------------------------------------------------------------------

/** On Linux, use native mkfs.ext4 (from e2fsprogs). */
function makeExt4Native(exportDir: string, outImage: string): void {
  // We size at 512 MB to give headroom; the Firecracker VM never writes much.
  run(
    `mkfs.ext4 -d "${exportDir}" ` +
    `-L rootfs -O ^has_journal ` +
    `-m 0 ` +
    `"${outImage}" ` +
    `512M`,
  );
}

/** On macOS (no native mkfs.ext4), use an Alpine container to create the image. */
function makeExt4ViaDocker(exportDir: string, outImage: string): void {
  const outDir = dirname(outImage);
  const imageName = 'rootfs.ext4';
  // Mount exportDir as /work (source) and outDir as /out (destination).
  run(
    `docker run --rm ` +
    `-v "${exportDir}:/work:ro" ` +
    `-v "${outDir}:/out" ` +
    `alpine:latest ` +
    `sh -c ` +
    `"apk add --no-cache e2fsprogs && ` +
    ` mkfs.ext4 -d /work -L rootfs -O ^has_journal -m 0 /out/${imageName} 512M"`,
  );
  // The container writes rootfs.ext4 into outDir; rename to the expected filename.
  const tmpOut = join(outDir, imageName);
  if (tmpOut !== outImage) {
    // Rename the file to the expected target path.
    execSync(`mv "${tmpOut}" "${outImage}"`);
  }
}

function exportAndConvert(input: BuildInput): void {
  const tag = dockerTag(input);
  const outImage = imageOutputPath(input);
  mkdirSync(dirname(outImage), { recursive: true });

  // Create a temp directory to hold the exported filesystem tree.
  const tmpBase = tmpdir();
  const tmpDir = join(tmpBase, `script-jail-rootfs-${randomBytes(6).toString('hex')}`);
  mkdirSync(tmpDir, { recursive: true });

  try {
    // Create a container (not running) so we can export its filesystem.
    const containerId = runCapture(`docker create "${tag}"`);
    console.log(`[rootfs] Created container ${containerId.slice(0, 12)} for export`);

    try {
      // Export container filesystem as a tar stream and extract it.
      run(`docker export "${containerId}" | tar -x -C "${tmpDir}"`);
      console.log(`[rootfs] Exported filesystem to ${tmpDir}`);
    } finally {
      // Always remove the temporary container.
      try { execSync(`docker rm "${containerId}"`, { stdio: 'ignore' }); } catch { /* ignore */ }
    }

    // Verify we got something.
    const exported = readdirSync(tmpDir);
    if (exported.length === 0) {
      throw new Error(`[rootfs] docker export produced an empty directory: ${tmpDir}`);
    }

    // Convert to ext4.
    if (isLinux()) {
      console.log(`[rootfs] Creating ext4 image (native mkfs.ext4) …`);
      makeExt4Native(tmpDir, outImage);
    } else {
      console.log(`[rootfs] Creating ext4 image (via Alpine docker helper) …`);
      makeExt4ViaDocker(tmpDir, outImage);
    }
  } finally {
    // Clean up the temp directory.
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  console.log(`[rootfs] Wrote: ${outImage}`);
}

// ---------------------------------------------------------------------------
// Step 7 — Size check
// ---------------------------------------------------------------------------

function reportSize(input: BuildInput): void {
  const outImage = imageOutputPath(input);
  if (!existsSync(outImage)) return;

  const { size } = statSync(outImage);
  const formatted = formatBytes(size);

  if (size > SIZE_WARN_THRESHOLD_BYTES) {
    console.warn(
      `[rootfs] WARNING: ${imageFilename(input)} is ${formatted}, ` +
      `which exceeds the 200 MB target. Consider stripping more content from the image.`,
    );
  } else {
    console.log(`[rootfs] Image size: ${formatted} ✓`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function buildRootfs(input: BuildInput): Promise<void> {
  console.log(
    `[rootfs] Building rootfs for ${input.runnerImage} → ${imageFilename(input)}`,
  );

  if (!commandExists('docker')) {
    throw new Error(
      '[rootfs] docker is not available. ' +
      'Install Docker Desktop (macOS) or docker-ce (Linux) before running the rootfs build.',
    );
  }

  // Step 1: bundle agent
  bundleAgent();

  // Step 2: copy preloads
  copyPreloads();

  // Step 3: ensure shim
  const shimOk = ensureShim();

  if (!shimOk) {
    // On macOS without the .so we cannot build the docker image because the
    // Dockerfile COPY would fail. Emit a clear warning and return.
    console.warn(
      '[rootfs] Skipping docker build and ext4 conversion (libscriptjail.so not available on macOS).',
    );
    return;
  }

  // Step 4: docker build
  dockerBuild(input);

  // Steps 5+6: export + convert to ext4
  exportAndConvert(input);

  // Step 7: report size
  reportSize(input);

  console.log(`[rootfs] Done.`);
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

// This file may also be imported as a module by scripts/build.ts.
// When run directly (via oxnode src/rootfs/build.ts), build with defaults.
//
// Use an exact resolved-path comparison against import.meta.url so that
// importing this module from scripts/build.ts does NOT trigger a build:
// both files end in "build.ts", but only one of them IS this file.
const isMain =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === __filename;

if (isMain) {
  // CLI: `oxnode src/rootfs/build.ts [--runner-image=ubuntu-22.04|ubuntu-24.04]`
  const runnerImage = parseRunnerImageArg(process.argv.slice(2)) ?? 'ubuntu-24.04';
  const defaultInput: BuildInput = {
    runnerImage,
    outputDir: join(REPO_ROOT, 'images'),
  };

  buildRootfs(defaultInput).catch((err: unknown) => {
    console.error(String(err instanceof Error ? err.stack ?? err.message : err));
    process.exit(1);
  });
}

/**
 * Parse `--runner-image=ubuntu-22.04|ubuntu-24.04` from argv.  Returns
 * `undefined` when the flag is absent so callers can apply their own default.
 * Throws on an unknown value so the user sees a clear error rather than
 * silently getting the default.
 */
export function parseRunnerImageArg(args: ReadonlyArray<string>): RunnerImage | undefined {
  for (const arg of args) {
    const m = /^--runner-image=(.+)$/.exec(arg);
    if (m === null) continue;
    const value = m[1];
    if (value === 'ubuntu-22.04' || value === 'ubuntu-24.04') return value;
    throw new Error(
      `[rootfs] Unknown --runner-image value: ${String(value)}. ` +
      `Expected one of: ubuntu-22.04, ubuntu-24.04.`,
    );
  }
  return undefined;
}

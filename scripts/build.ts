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
//   --arch=x64|arm64                             target rootfs architecture.
//                                                Defaults to 'x64' unless
//                                                --shim-arm64 is also set.
//   --shim-arm64                                 cross-compile libscriptjail.so for
//                                                aarch64-unknown-linux-gnu.
//                                                Linux-only; macOS surfaces a
//                                                clear error pointing at CI.
//
// Default: build a single rootfs for whichever runner image we detect (via
// `detectRunnerImage()`); falls back to `ubuntu-24.04` when detection fails
// (e.g. on macOS dev hosts).

import { execSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  type Dirent,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildRootfs,
  formatBytes,
  imageOutputPath,
  parseArchArg,
  parseRunnerImageArg,
  type BuildArch,
  type BuildInput,
  type RunnerImage,
} from '../src/rootfs/build.js';
import { detectRunnerImage } from '../src/action/runner-image.js';
import {
  decideShimRebuild as decideShimRebuildShared,
  shimArtifactIsStale as shimArtifactIsStaleShared,
  shimSourceInputs as shimSourceInputsShared,
} from '../src/rootfs/shim-freshness.js';
import { sha256File } from '../src/shared/http-download.js';

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
  /**
   * Explicit `--arch=x64|arm64`.  Drives the rootfs build (BuildInput.arch)
   * AND, when 'arm64', triggers the aarch64-unknown-linux-gnu cross-compile
   * for libscriptjail.so.  Defaults to undefined → host arch fallback.
   */
  arch: BuildArch | undefined;
  /**
   * `--shim-arm64` requests the cross-compiled
   * `target/aarch64-unknown-linux-gnu/release/libscriptjail.so` → copied to
   * `images/libscriptjail-arm64.so`. Implies --arch=arm64 for the rootfs
   * step unless --arch is supplied separately. Gated on Linux: on macOS we
   * surface a clear error pointing at CI (cargo on Darwin cannot build a
   * Linux .so from this toolchain).
   */
  shimArm64: boolean;
}

function parseArgs(): ParsedArgs {
  const args = process.argv.slice(2);

  const skipRootfs = args.includes('--skip-rootfs');
  const skipBundle = args.includes('--skip-bundle');
  const skipShim = args.includes('--skip-shim');
  const all = args.includes('--all');
  const shimArm64 = args.includes('--shim-arm64');
  const runnerImage = parseRunnerImageArg(args);
  const arch = parseArchArg(args);

  // Warn about unknown flags so typos don't silently no-op.
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (
      arg === '--skip-rootfs' ||
      arg === '--skip-bundle' ||
      arg === '--skip-shim' ||
      arg === '--all' ||
      arg === '--shim-arm64' ||
      /^--runner-image=/.test(arg) ||
      /^--arch=/.test(arg)
    ) continue;
    // --arch <value> two-token form: skip both this token and the value.
    if (arg === '--arch') { i++; continue; }
    console.warn(`[build] Unknown flag: ${arg}`);
  }

  return { skipRootfs, skipBundle, skipShim, all, runnerImage, arch, shimArm64 };
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

// Freshness helpers now live in src/rootfs/shim-freshness.ts so that both
// scripts/build.ts:buildShim() AND src/rootfs/build.ts:ensureShim() can call
// the exact same logic.  See that module for the rationale (Finding 3).
//
// We re-export them at the same names with the same signatures used by the
// existing tests in test/scripts/build-shim-freshness.test.ts; the
// `shimSourceInputs` default-argument behaviour is preserved.

/** Bound to the shared helper but keeps the `repoRoot = REPO_ROOT` default. */
export function shimSourceInputs(repoRoot: string = REPO_ROOT): ReadonlyArray<string> {
  return shimSourceInputsShared(repoRoot);
}

export const decideShimRebuild = decideShimRebuildShared;

/** Bound to the shared helper but keeps the default sources behaviour. */
export function shimArtifactIsStale(
  shimOut: string,
  sources: ReadonlyArray<string> = shimSourceInputs(),
): boolean {
  return shimArtifactIsStaleShared(shimOut, sources);
}

/**
 * Cross-compile `libscriptjail.so` for aarch64-unknown-linux-gnu and copy it
 * to `images/libscriptjail-arm64.so`.  Gated on Linux: macOS cargo cannot
 * produce a Linux ELF from this toolchain (would yield a Mach-O dylib), so
 * we surface a clear error pointing the user at CI.
 *
 * Cross-compile via cargo-zigbuild + zig.  zigbuild bundles the
 * cross-libc/sysroot lookup and the linker invocation into one tool, so
 * the same `pnpm build --shim-arm64` works on Linux AND macOS dev hosts
 * (and on the release runners) without per-host `gcc-aarch64-linux-gnu`
 * installs or `.cargo/config.toml` linker pinning.
 *
 * Prerequisites (installed by .github/workflows/{release,parity-test}.yml
 * before invoking this; same install also works locally):
 *   - `cargo install cargo-zigbuild`
 *   - zig binary on PATH (`brew install zig` on macOS,
 *     `pip install ziglang` / download tarball on Linux)
 *   - `rustup target add aarch64-unknown-linux-gnu` (for the std rlib)
 */
function buildShimArm64(): void {
  const target = 'aarch64-unknown-linux-gnu';
  const manifest = join(REPO_ROOT, 'src', 'shim', 'Cargo.toml');
  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail-arm64.so');

  console.log(`[build] Building arm64 shim via cargo zigbuild --target ${target} …`);
  execSync(
    `cargo zigbuild --release --manifest-path "${manifest}" --target ${target}`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );

  mkdirSync(join(REPO_ROOT, 'images'), { recursive: true });
  copyFileSync(
    join(REPO_ROOT, 'target', target, 'release', 'libscriptjail.so'),
    shimOut,
  );
  console.log(`[build] images/libscriptjail-arm64.so built.`);
}

/**
 * Build the macOS-native Mach-O shim (`libscriptjail-arm64.dylib`) for the
 * `bare` (no-VM) macOS audit backend.  Unlike the Linux `.so`, macOS cargo
 * CAN produce this natively (it's the host target), so there is no CI-only
 * short-circuit.  Steps:
 *   1. `cargo build --release --target aarch64-apple-darwin`
 *   2. copy `target/aarch64-apple-darwin/release/libscriptjail.dylib`
 *      → `images/libscriptjail-arm64.dylib`
 *   3. ad-hoc codesign (`codesign --force --sign -`) — MANDATORY on Apple
 *      Silicon and required for injection into the re-signed node (Phase 4).
 *   4. `codesign --verify` so a broken signature fails the build.
 */
function buildShimMac(): void {
  const target = 'aarch64-apple-darwin';
  const manifest = join(REPO_ROOT, 'src', 'shim', 'Cargo.toml');
  const shimOut = join(REPO_ROOT, 'images', 'libscriptjail-arm64.dylib');

  // Freshness: reuse the existing dylib only when every shim source input is
  // older than it (same rule as the Linux .so).  shimArtifactIsStale compares
  // the artifact mtime against the shared shimSourceInputs (which now include
  // interpose.rs / fileops.rs / net.rs — see shim-freshness.ts).
  if (!shimArtifactIsStale(shimOut)) {
    console.log(
      '[build] images/libscriptjail-arm64.dylib is up-to-date relative to shim ' +
      'sources; skipping macOS shim build.',
    );
    return;
  }

  console.log(`[build] Building macOS shim via cargo build --target ${target} …`);
  execSync(
    `cargo build --release --manifest-path "${manifest}" --target ${target}`,
    { stdio: 'inherit', cwd: REPO_ROOT },
  );

  mkdirSync(join(REPO_ROOT, 'images'), { recursive: true });
  copyFileSync(
    join(REPO_ROOT, 'target', target, 'release', 'libscriptjail.dylib'),
    shimOut,
  );

  // Ad-hoc sign + verify.  `--force` re-stamps the linker's adhoc+linker-signed
  // signature as a plain adhoc one (the spike's codesignDylibCmd).
  console.log('[build] Ad-hoc signing the dylib (codesign --force --sign -) …');
  execSync(`codesign --force --sign - "${shimOut}"`, { stdio: 'inherit', cwd: REPO_ROOT });
  execSync(`codesign --verify --verbose "${shimOut}"`, { stdio: 'inherit', cwd: REPO_ROOT });
  console.log('[build] images/libscriptjail-arm64.dylib built + signed.');
}

// ---------------------------------------------------------------------------
// Step 2c — macOS audit-shell binaries (coreutils + bash)
// ---------------------------------------------------------------------------
//
// The macOS `bare` backend's SIP redirect (SCRIPT_JAIL_SHELL_SHIM_DIR) points
// at a DIRECTORY holding exactly two files — `bash` and `coreutils` — that the
// shim resolves /bin/sh + /bin/bash → `bash` and any uutils applet under
// /bin or /usr/bin → `coreutils` to (argv[0] is left UNCHANGED for multi-call
// dispatch).  We acquire both here, right after the dylib is built + signed,
// using the same SHA-verified download precedent as fetchVpBinary
// (src/cli/provision-node-mac.ts) — NodeHttpClient.download verifies the
// pinned SHA-256 before moving the file into place and throws on mismatch.

/**
 * uutils coreutils 0.4.0 official aarch64-apple-darwin prebuilt.  Extracted to
 * images/coreutils-arm64.
 *
 * MAC_COREUTILS_SHA256 is the SHA-256 of the EXTRACTED BINARY, not the tarball.
 * Upstream periodically recompresses the `.tar.gz` release asset (its archive
 * SHA drifts — e.g. the 0.4.0 asset was re-published 2025-11-09) while the inner
 * binary bytes are stable, so the binary is the real supply-chain gate (this is
 * also how the fspy reference and uutils' own build pin it).
 */
const MAC_COREUTILS_URL =
  'https://github.com/uutils/coreutils/releases/download/0.4.0/coreutils-0.4.0-aarch64-apple-darwin.tar.gz';
const MAC_COREUTILS_SHA256 =
  '8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21';

/**
 * GNU bash source tarball (built from source for a plain arm64, ad-hoc signed
 * binary).  Pinned SHA-256 of the source tarball (GNU release tarballs are
 * stable), verified by NodeHttpClient.download.
 */
const MAC_BASH_SRC_URL = 'https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz';
const MAC_BASH_SRC_SHA256 =
  '0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba';

/**
 * Download the official uutils coreutils prebuilt, verify its SHA-256, extract
 * the single `coreutils` multi-call binary to images/coreutils-arm64, and
 * chmod 0o755.  Skips the re-download when images/coreutils-arm64 already
 * exists and hashes to the pinned SHA-256.
 */
async function fetchMacCoreutils(): Promise<void> {
  const imagesDir = join(REPO_ROOT, 'images');
  const dest = join(imagesDir, 'coreutils-arm64');

  if (existsSync(dest)) {
    const sha = await sha256File(dest);
    if (sha === MAC_COREUTILS_SHA256) {
      console.log(
        '[build] images/coreutils-arm64 already matches the pinned SHA-256; ' +
        'skipping uutils download.',
      );
      return;
    }
    console.log(
      `[build] images/coreutils-arm64 SHA-256 mismatch (have ${sha}); re-downloading.`,
    );
  }

  mkdirSync(imagesDir, { recursive: true });
  const tmp = mkdtempSync(join(tmpdir(), 'script-jail-coreutils-'));
  try {
    const tgzPath = join(tmp, 'coreutils.tar.gz');
    console.log(`[build] Downloading uutils coreutils prebuilt: ${MAC_COREUTILS_URL} …`);
    // Fetch the tarball, then verify the EXTRACTED BINARY's SHA-256 (not the
    // archive's — upstream recompresses the .tar.gz, so its SHA drifts while
    // the binary is stable; the binary is the supply-chain gate).
    execSync(`curl -fsSL -o "${tgzPath}" "${MAC_COREUTILS_URL}"`, { stdio: 'inherit', cwd: REPO_ROOT });

    const extractDir = join(tmp, 'extract');
    mkdirSync(extractDir, { recursive: true });
    execSync(`tar -xzf "${tgzPath}" -C "${extractDir}"`, { stdio: 'inherit', cwd: REPO_ROOT });

    // The uutils tarball wraps everything under a single
    // `coreutils-0.4.0-aarch64-apple-darwin/` directory; the multi-call binary
    // is named `coreutils` inside it.  Locate it without hardcoding layout.
    const coreutilsBin = findFileNamed(extractDir, 'coreutils');
    if (!coreutilsBin) {
      throw new Error(
        `[build] coreutils binary not found under ${extractDir} after extracting ${MAC_COREUTILS_URL}.`,
      );
    }

    const sha = await sha256File(coreutilsBin);
    if (sha !== MAC_COREUTILS_SHA256) {
      throw new Error(
        `[build] uutils coreutils binary SHA-256 mismatch: expected ` +
        `${MAC_COREUTILS_SHA256}, got ${sha} (from ${MAC_COREUTILS_URL}).`,
      );
    }

    copyFileSync(coreutilsBin, dest);
    chmodSync(dest, 0o755);
    console.log('[build] images/coreutils-arm64 extracted, SHA-256 verified, chmod 0o755.');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Build bash from source for a plain arm64, ad-hoc-signed binary at
 * images/bash-arm64.  Downloads + SHA-verifies the GNU bash source tarball to
 * a temp dir, extracts, then:
 *   1. `./configure --without-bash-malloc CFLAGS="-arch arm64 -Os"`
 *   2. `make -j`
 *   3. `codesign --force --sign -` the resulting bash
 *   4. copy → images/bash-arm64 (chmod 0o755)
 * Skips the rebuild when images/bash-arm64 already exists and is a thin arm64
 * Mach-O.  NOTE: bash is an MH_EXECUTE, not an MH_DYLIB, so it is validated with
 * a `lipo -archs` arch check (not validateMachOShimFile, which is dylib-only).
 */
async function buildMacBash(): Promise<void> {
  const imagesDir = join(REPO_ROOT, 'images');
  const dest = join(imagesDir, 'bash-arm64');

  if (existsSync(dest) && machoArchs(dest) === 'arm64') {
    console.log(
      '[build] images/bash-arm64 already exists and is a thin arm64 Mach-O; ' +
      'skipping bash build.',
    );
    return;
  }

  mkdirSync(imagesDir, { recursive: true });
  const tmp = mkdtempSync(join(tmpdir(), 'script-jail-bash-'));
  try {
    const tgzPath = join(tmp, 'bash.tar.gz');
    console.log(`[build] Downloading bash source: ${MAC_BASH_SRC_URL} …`);
    // curl (not NodeHttpClient): ftp.gnu.org 403s plain GETs that lack a UA /
    // don't follow its mirror redirect.  Verify the pinned source-tarball
    // SHA-256 after download (GNU release tarballs are stable — supply-chain
    // gate for the bash source).
    execSync(`curl -fsSL --retry 3 --retry-delay 2 -o "${tgzPath}" "${MAC_BASH_SRC_URL}"`, {
      stdio: 'inherit',
      cwd: REPO_ROOT,
    });
    const srcSha = await sha256File(tgzPath);
    if (srcSha !== MAC_BASH_SRC_SHA256) {
      throw new Error(
        `[build] bash source tarball SHA-256 mismatch: expected ` +
        `${MAC_BASH_SRC_SHA256}, got ${srcSha} (from ${MAC_BASH_SRC_URL}).`,
      );
    }

    const extractDir = join(tmp, 'extract');
    mkdirSync(extractDir, { recursive: true });
    execSync(`tar -xzf "${tgzPath}" -C "${extractDir}"`, { stdio: 'inherit', cwd: REPO_ROOT });

    // GNU source tarballs unpack into a single `bash-5.3/` directory.
    const entries = readdirSync(extractDir, { withFileTypes: true })
      .filter((e) => e.isDirectory());
    const srcDir = entries.length === 1 ? join(extractDir, entries[0]!.name) : extractDir;

    console.log('[build] Configuring bash (--without-bash-malloc, -arch arm64 -Os) …');
    execSync(
      `./configure --without-bash-malloc CFLAGS="-arch arm64 -Os"`,
      { stdio: 'inherit', cwd: srcDir },
    );
    console.log('[build] Building bash (make -j) …');
    execSync(`make -j`, { stdio: 'inherit', cwd: srcDir });

    const builtBash = join(srcDir, 'bash');
    if (!existsSync(builtBash)) {
      throw new Error(`[build] bash binary not found at ${builtBash} after make.`);
    }

    // Ad-hoc sign so the binary loads under SIP-redirect into the audited shell
    // path on Apple Silicon (same precedent as the dylib codesign above).
    console.log('[build] Ad-hoc signing bash (codesign --force --sign -) …');
    execSync(`codesign --force --sign - "${builtBash}"`, { stdio: 'inherit', cwd: srcDir });

    copyFileSync(builtBash, dest);
    chmodSync(dest, 0o755);

    // Sanity-check the artifact is a THIN arm64 Mach-O (rejects arm64e, fat, or
    // x86_64 — the whole point is no arm64e).
    const archs = machoArchs(dest);
    if (archs !== 'arm64') {
      throw new Error(
        `[build] images/bash-arm64 is not a thin arm64 Mach-O (lipo -archs = ${archs ?? 'unreadable'}).`,
      );
    }
    console.log('[build] images/bash-arm64 built + signed + chmod 0o755.');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Depth-bounded search for a regular file named `name` under `root`.  Used to
 * locate the `coreutils` binary inside the extracted uutils tarball without
 * hardcoding its wrapper-directory layout.
 */
/**
 * The lipo arch list of a Mach-O file (e.g. `"arm64"`, `"arm64e"`,
 * `"arm64 arm64e"`), or null if the file is missing / not a Mach-O.  Used to
 * assert the substitution binaries are THIN arm64 (no arm64e slice).
 */
function machoArchs(path: string): string | null {
  try {
    return execSync(`lipo -archs "${path}"`, {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
  } catch {
    return null;
  }
}

function findFileNamed(root: string, name: string): string | null {
  const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (stack.length > 0) {
    const { dir, depth } = stack.pop()!;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isFile() && entry.name === name) return full;
      if (entry.isDirectory() && depth < 4) stack.push({ dir: full, depth: depth + 1 });
    }
  }
  return null;
}

function buildShim(): void {
  if (process.platform === 'darwin') {
    // macOS produces the native Mach-O shim for the bare backend.  The Linux
    // `.so` cannot be cross-built from this toolchain (cargo would emit a
    // Mach-O); --shim-arm64 (cargo-zigbuild) handles the Linux arm64 .so in CI.
    buildShimMac();
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
    join(REPO_ROOT, 'target', 'release', 'libscriptjail.so'),
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
  const { skipRootfs, skipBundle, skipShim, all, runnerImage, arch, shimArm64 } =
    parseArgs();

  const artifacts: ArtifactSummary[] = [];

  // Step 1: action bundle
  if (skipBundle) {
    console.log('[build] --skip-bundle passed; skipping action-bundle build.');
  } else {
    buildActionBundle();
  }
  artifacts.push({ path: join(REPO_ROOT, 'dist', 'main.cjs') });

  // Step 2: Rust shim(s)
  if (skipShim) {
    console.log('[build] --skip-shim passed; skipping Rust-shim build.');
  } else {
    buildShim();
  }
  // On macOS buildShim produces the Mach-O dylib (bare backend); on Linux the
  // ELF .so.  Report whichever one the host build produced.
  artifacts.push({
    path:
      process.platform === 'darwin'
        ? join(REPO_ROOT, 'images', 'libscriptjail-arm64.dylib')
        : join(REPO_ROOT, 'images', 'libscriptjail.so'),
  });

  // Step 2c: macOS audit-shell binaries (coreutils + bash).  These live next
  // to the dylib in images/ and the SIP redirect's SCRIPT_JAIL_SHELL_SHIM_DIR
  // points at a dir holding exactly these two files.  Acquire them right after
  // the dylib is built + signed (same --skip-shim gate; same host gate).
  if (skipShim) {
    console.log(
      '[build] --skip-shim passed; skipping macOS coreutils/bash acquisition.',
    );
  } else if (process.platform === 'darwin') {
    await fetchMacCoreutils();
    await buildMacBash();
    artifacts.push({ path: join(REPO_ROOT, 'images', 'coreutils-arm64') });
    artifacts.push({ path: join(REPO_ROOT, 'images', 'bash-arm64') });
  }

  // Step 2b: optional arm64 shim cross-compile.  Surfaces a clear error on
  // macOS (where cargo cannot produce a Linux .so) so dev hosts know the
  // build path is CI-only.
  if (shimArm64) {
    buildShimArm64();
    artifacts.push({
      path: join(REPO_ROOT, 'images', 'libscriptjail-arm64.so'),
    });
  }

  // Step 3: rootfs
  if (skipRootfs) {
    console.log('[build] --skip-rootfs passed; skipping rootfs build.');
  } else {
    const targets: ReadonlyArray<RunnerImage> = all
      ? ['ubuntu-22.04', 'ubuntu-24.04']
      : [runnerImage ?? defaultRunnerImage()];

    // When --shim-arm64 is set without an explicit --arch, default the rootfs
    // arch to arm64 too — building the arm64 .so without an arm64 rootfs to
    // pair it with is almost never what the user wants.
    const rootfsArch: BuildArch = arch ?? (shimArm64 ? 'arm64' : 'x64');

    for (const target of targets) {
      const rootfsInput: BuildInput = {
        runnerImage: target,
        outputDir: join(REPO_ROOT, 'images'),
        arch: rootfsArch,
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

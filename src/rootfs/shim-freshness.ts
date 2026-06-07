// script-jail — src/rootfs/shim-freshness.ts
//
// Shared freshness-decision helpers for `images/libscriptjail.so`.
//
// Why a separate module: this logic used to live exclusively in
// `scripts/build.ts:buildShim()` and was only consulted when the top-level
// build script was run.  Anything that bypassed `scripts/build.ts` (e.g. a
// direct `oxnode src/rootfs/build.ts`, a `--skip-shim` toggle, or a future
// caller that orchestrates rootfs assembly differently) skipped the mtime
// gate entirely and could embed a structurally-valid-but-stale `.so` into
// the Firecracker rootfs.  The ELF validator catches malformed bytes — it
// cannot detect "valid ELF, produced from out-of-date Rust source".
//
// Finding 3 (audit-trust) moves the gate to the rootfs packaging boundary
// (`src/rootfs/build.ts:ensureShim`), which every code path that ships a
// VM image must go through.  This module exports the pure decision rule
// and the filesystem-touching wrapper so both `ensureShim` and the
// `scripts/build.ts:buildShim` step can share the exact same logic — no
// chance of the two checks drifting apart.

import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Files whose mtime gates whether `images/libscriptjail.so` is fresh enough
 * to reuse. Touching any of these makes consumers rebuild from cargo.
 *
 * Kept narrow on purpose: these are the inputs cargo actually consumes for
 * the `script-jail-shim` crate. Adding more (e.g. an entire src/shim tree
 * glob) would be more thorough but would also force a rebuild on unrelated
 * edits — `Cargo.toml` already declares the source layout.
 */
export function shimSourceInputs(repoRoot: string): ReadonlyArray<string> {
  return [
    join(repoRoot, 'src', 'shim', 'Cargo.toml'),
    join(repoRoot, 'Cargo.lock'),
    join(repoRoot, 'rust-toolchain.toml'),
    join(repoRoot, 'src', 'shim', 'src', 'lib.rs'),
    // macOS Mach-O port modules (cfg-gated to darwin in lib.rs).  They only
    // affect the dylib, but listing them keeps the freshness gate honest when
    // a macOS-only hook changes without touching lib.rs.
    join(repoRoot, 'src', 'shim', 'src', 'interpose.rs'),
    join(repoRoot, 'src', 'shim', 'src', 'fileops.rs'),
    join(repoRoot, 'src', 'shim', 'src', 'net.rs'),
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
  sources: ReadonlyArray<string>,
): boolean {
  const artifactMtime = existsSync(shimOut) ? statSync(shimOut).mtimeMs : null;
  const sourceMtimes: number[] = [];
  for (const path of sources) {
    if (!existsSync(path)) continue;
    sourceMtimes.push(statSync(path).mtimeMs);
  }
  return decideShimRebuild(artifactMtime, sourceMtimes);
}

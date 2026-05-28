// script-jail — src/shared/detect-pm.ts
//
// Detects the package manager from lockfile presence in the repository root.
//
// Detection rules (first match wins):
//   1. pnpm-lock.yaml      → pnpm
//   2. yarn.lock           → yarn
//   3. package-lock.json   → npm
//   4. npm-shrinkwrap.json → npm
//
// Bun handling: if `bun.lock` or `bun.lockb` is the ONLY lockfile present,
// throw `BunUnsupportedError`.  script-jail v1 only supports npm/pnpm/yarn.
//
// When multiple supported lockfiles are present we log a warning (via the
// shared `warn` helper from ./log.ts so it shows up as a GitHub Actions
// `::warning::` annotation by default) and pick the highest priority.
// This mirrors the behaviour of `corepack` and most CI install actions.
//
// The `fs` and `warn` fields on `DetectInput` are injection seams so tests
// can avoid touching the real filesystem or stdout.  Default writes a
// GitHub Actions ::warning:: annotation; callers such as the host-mac CLI can
// override to log via their own sink.
//
// This function is synchronous: the lockfile read is small and one-shot, so
// async IO buys nothing.  We return `DetectedPm` directly (not a Promise).

import { createHash } from 'node:crypto';
import { existsSync as realExistsSync, readFileSync as realReadFileSync } from 'node:fs';
import { join } from 'node:path';

import { warn as realWarn } from './log.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type PackageManager = 'npm' | 'pnpm' | 'yarn';

export interface DetectedPm {
  manager: PackageManager;
  /** Absolute path to the lockfile that triggered detection. */
  lockfilePath: string;
  /** SHA-256 hex digest over the raw bytes of the lockfile. */
  lockfileSha256: string;
}

export interface DetectInput {
  /** Absolute repo root. */
  repoDir: string;
  /**
   * Optional injection seam for tests.  Defaults to node:fs.  Both methods
   * are synchronous to keep this module trivial — the lockfile is read once
   * and is always small enough that async IO is unjustified.
   */
  fs?: {
    existsSync(p: string): boolean;
    readFileSync(p: string): Buffer;
  } | undefined;
  /**
   * Optional injection seam for the warning sink.  Defaults to the shared
   * `warn` helper which writes a `::warning::` annotation to stdout.
   */
  warn?: ((msg: string) => void) | undefined;
}

// ---------------------------------------------------------------------------
// BunUnsupportedError
// ---------------------------------------------------------------------------

/**
 * Thrown when only a bun lockfile (`bun.lock` or `bun.lockb`) is found and no
 * supported lockfile (npm/pnpm/yarn) is present.
 *
 * script-jail v1 does not support bun because the guest agent only ships strace
 * shims for the npm/pnpm/yarn CLIs.  Tracking issue: v2 will add bun support.
 */
export class BunUnsupportedError extends Error {
  constructor() {
    super('script-jail v1 does not support bun. Use npm/pnpm/yarn, or wait for v2.');
    this.name = 'BunUnsupportedError';
  }
}

// ---------------------------------------------------------------------------
// Lockfile priority table
// ---------------------------------------------------------------------------

/**
 * Ordered list of (filename, manager) pairs.  First match (top-to-bottom) wins.
 * The order matches the public API documented at the top of this file.
 */
const LOCKFILE_PRIORITY: ReadonlyArray<{ readonly name: string; readonly manager: PackageManager }> = [
  { name: 'pnpm-lock.yaml', manager: 'pnpm' },
  { name: 'yarn.lock', manager: 'yarn' },
  { name: 'package-lock.json', manager: 'npm' },
  { name: 'npm-shrinkwrap.json', manager: 'npm' },
];

/** Bun lockfile names.  Detected for diagnostic purposes only. */
const BUN_LOCKFILES: ReadonlyArray<string> = ['bun.lock', 'bun.lockb'];

// ---------------------------------------------------------------------------
// detectPm
// ---------------------------------------------------------------------------

export function detectPm(input: DetectInput): DetectedPm {
  const fs = input.fs ?? {
    existsSync: realExistsSync,
    readFileSync: (p: string): Buffer => realReadFileSync(p),
  };
  const warn = input.warn ?? realWarn;

  // Collect every supported lockfile that exists in the repo root.
  const found = LOCKFILE_PRIORITY.filter((entry) =>
    fs.existsSync(join(input.repoDir, entry.name)),
  );

  if (found.length === 0) {
    // No supported lockfile.  Check bun before erroring so we can surface the
    // clearer "bun not supported" message.
    const hasBun = BUN_LOCKFILES.some((name) =>
      fs.existsSync(join(input.repoDir, name)),
    );
    if (hasBun) throw new BunUnsupportedError();

    throw new Error(
      `script-jail: no lockfile found in ${input.repoDir}. ` +
      `Expected one of: package-lock.json, pnpm-lock.yaml, yarn.lock, npm-shrinkwrap.json.`,
    );
  }

  // Pick the highest-priority lockfile (`found` already preserves priority).
  const chosen = found[0]!; // length checked above
  const others = found.slice(1);
  if (others.length > 0) {
    const otherNames = others.map((o) => o.name).join(', ');
    warn(
      `[detect-pm] multiple lockfiles found; using ${chosen.name} ` +
      `(ignoring: ${otherNames})`,
    );
  }

  const lockfilePath = join(input.repoDir, chosen.name);
  const buf = fs.readFileSync(lockfilePath);
  const lockfileSha256 = createHash('sha256').update(buf).digest('hex');

  return {
    manager: chosen.manager,
    lockfilePath,
    lockfileSha256,
  };
}

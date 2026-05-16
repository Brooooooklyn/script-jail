// npm-jar — src/action/runner-image.ts
//
// Detects which Ubuntu runner image we are running on, so the host can pick
// a rootfs whose glibc/library set matches the host kernel + userland.
//
// Why this exists:
//   Starting in v2, the rootfs is mounted with the host's Node binary
//   bind-mounted in (Task #12).  That means the rootfs no longer needs to
//   carry a Node major version — it only needs to be ABI-compatible with the
//   host's shared libraries.  So we key the rootfs by runner image
//   (`ubuntu-22.04`, `ubuntu-24.04`) instead of `(node-major, package-manager)`.
//
// Resolution order:
//
//   1. `process.env.ImageOS` — set by GitHub-hosted runners.  Values:
//        - `ubuntu22` → ubuntu-22.04
//        - `ubuntu24` → ubuntu-24.04
//        - anything else → fall through to /etc/os-release
//
//   2. `/etc/os-release` — fallback for self-hosted runners.  We require
//      `ID=ubuntu` and `VERSION_ID` to be one of the supported releases.
//
// If neither signal yields a supported image, we throw — the host can't pick
// a rootfs blindly because a glibc mismatch would manifest as opaque dynamic
// linker errors inside the VM.
//
// The `imageOsEnv` and `fs` fields on `DetectRunnerImageInput` are injection
// seams so tests can avoid touching real process.env or filesystem.

import { existsSync as realExistsSync, readFileSync as realReadFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RunnerImage = 'ubuntu-22.04' | 'ubuntu-24.04';

export interface DetectRunnerImageInput {
  /** Optional injection seam for tests.  Defaults to `process.env.ImageOS`. */
  imageOsEnv?: string | undefined;
  /** Optional fs seam for the /etc/os-release fallback.  Defaults to node:fs. */
  fs?: {
    existsSync(p: string): boolean;
    readFileSync(p: string, enc: 'utf8'): string;
  } | undefined;
}

// ---------------------------------------------------------------------------
// UnsupportedRunnerImageError
// ---------------------------------------------------------------------------

/**
 * Thrown when `/etc/os-release` parses cleanly but reports an OS that npm-jar
 * does not (yet) ship a rootfs for.  The error message includes the parsed
 * `ID` and `VERSION_ID` so users can see exactly what was detected.
 */
export class UnsupportedRunnerImageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedRunnerImageError';
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OS_RELEASE_PATH = '/etc/os-release';

const IMAGE_OS_MAP: Readonly<Record<string, RunnerImage>> = {
  ubuntu22: 'ubuntu-22.04',
  ubuntu24: 'ubuntu-24.04',
};

const VERSION_ID_MAP: Readonly<Record<string, RunnerImage>> = {
  '22.04': 'ubuntu-22.04',
  '24.04': 'ubuntu-24.04',
};

// ---------------------------------------------------------------------------
// detectRunnerImage
// ---------------------------------------------------------------------------

export function detectRunnerImage(input?: DetectRunnerImageInput): RunnerImage {
  // We distinguish "key not in input" (use process.env default) from "key
  // present and set to undefined" (test explicitly wants it unset).  This
  // matters because in CI the real `ImageOS` env var would otherwise leak
  // into tests that pass `imageOsEnv: undefined`.
  const imageOsEnv =
    input !== undefined && 'imageOsEnv' in input
      ? input.imageOsEnv
      : process.env['ImageOS'];
  const fs = input?.fs ?? {
    existsSync: realExistsSync,
    readFileSync: (p: string, enc: 'utf8'): string => realReadFileSync(p, enc),
  };

  // ---- 1. ImageOS env (GitHub-hosted runners) ------------------------------
  if (imageOsEnv !== undefined && imageOsEnv !== '') {
    const mapped = IMAGE_OS_MAP[imageOsEnv];
    if (mapped !== undefined) return mapped;
    // Unknown value: fall through to /etc/os-release rather than throw.
    // Self-hosted runners can leak unrelated ImageOS values into the env.
  }

  // ---- 2. /etc/os-release fallback -----------------------------------------
  if (!fs.existsSync(OS_RELEASE_PATH)) {
    throw new Error(
      'npm-jar: cannot detect runner image — ImageOS env not set and /etc/os-release missing/unreadable.',
    );
  }

  let raw: string;
  try {
    raw = fs.readFileSync(OS_RELEASE_PATH, 'utf8');
  } catch {
    throw new Error(
      'npm-jar: cannot detect runner image — ImageOS env not set and /etc/os-release missing/unreadable.',
    );
  }

  const parsed = parseOsRelease(raw);
  const id = parsed['ID'] ?? '';
  const versionId = parsed['VERSION_ID'] ?? '';

  if (id === 'ubuntu') {
    const mapped = VERSION_ID_MAP[versionId];
    if (mapped !== undefined) return mapped;
  }

  throw new UnsupportedRunnerImageError(
    `npm-jar: unsupported runner image (ID=${id}, VERSION_ID=${versionId}). ` +
    'Supported: ubuntu-22.04, ubuntu-24.04.',
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse an /etc/os-release-style key=value file.
 *
 * Lenient on purpose: distros differ slightly, and we only ever look up two
 * keys (`ID`, `VERSION_ID`).  Behaviour:
 *
 *   - Lines are trimmed of surrounding whitespace.
 *   - Empty lines and lines starting with `#` are ignored.
 *   - Lines without `=` are ignored.
 *   - Values may be wrapped in single OR double quotes; the quotes are stripped.
 *   - No shell-style escape handling (the values we care about are plain
 *     identifiers and dotted version numbers, so this is fine).
 */
function parseOsRelease(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (key === '') continue;
    let value = line.slice(eq + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

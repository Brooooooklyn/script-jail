// npm-jar — src/action/inputs.ts
//
// Parses the GitHub Action's inputs into a typed, validated ActionInputs object.
//
// Why not `@actions/core` directly?
//   The `@actions/core` `getInput` API reads from `process.env.INPUT_<NAME>`.
//   We mirror that convention in the default `getInput` so production code
//   "just works" inside a runner, while unit tests inject a plain map for
//   deterministic behaviour.
//
// All path inputs are resolved against `repoDir` (a relative path becomes an
// absolute path).
//
// Note on Node version: as of v2, there is no `node-version` input.  The
// user's `actions/setup-node` step controls which Node is on the host PATH,
// and we bind-mount that Node into the VM (see ./runner-image.ts and
// Task #12).  The rootfs is keyed by runner image, not by Node major.

import { isAbsolute, join, resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type Mode = 'check' | 'update';
export type SpoofPlatform = 'linux' | 'darwin' | 'win32';
export type SpoofArch = 'x64' | 'arm64';

export interface ActionInputs {
  /** Absolute path to the npm-jar config YAML. */
  configPath: string;
  /** Absolute path to the install-lock YAML (existing or to be created). */
  lockPath: string;
  mode: Mode;
  spoofPlatform: SpoofPlatform;
  spoofArch: SpoofArch;
  /** Whether to enable runner caching of the Firecracker bits. */
  cacheFirecracker: boolean;
}

export interface ParseInput {
  /** Absolute repository root used for relative-path resolution. */
  repoDir: string;
  /**
   * Optional injection seam.  Returns the raw string for a given Action input
   * name.  The default implementation reads `process.env.INPUT_<UPPER_SNAKE>`,
   * matching `@actions/core`'s convention.
   */
  getInput?: ((name: string) => string | undefined) | undefined;
  /** Injection seam for filesystem reads (reserved for future inputs). */
  fs?: {
    existsSync(p: string): boolean;
    readFileSync(p: string, enc: 'utf8'): string;
  } | undefined;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_PLATFORMS: ReadonlySet<SpoofPlatform> = new Set<SpoofPlatform>(['linux', 'darwin', 'win32']);
const VALID_ARCHES: ReadonlySet<SpoofArch> = new Set<SpoofArch>(['x64', 'arm64']);
const VALID_MODES: ReadonlySet<Mode> = new Set<Mode>(['check', 'update']);

// ---------------------------------------------------------------------------
// parseInputs
// ---------------------------------------------------------------------------

export function parseInputs(input: ParseInput): ActionInputs {
  const getInput = input.getInput ?? defaultGetInput;
  // The `fs` field on `ParseInput` is currently unused — `parseInputs` no
  // longer reads from disk now that the `node-version` resolution chain has
  // moved to runner-image detection (see ./runner-image.ts).  We keep the
  // seam on the interface for forward compatibility and so existing test
  // callers that pass `fs` continue to typecheck.

  const rawConfig = getInput('config') ?? '';
  const rawLock = getInput('lock') ?? '';
  const rawMode = getInput('mode') ?? '';
  const rawPlatform = getInput('spoof-platform') ?? '';
  const rawArch = getInput('spoof-arch') ?? '';
  const rawCache = getInput('cache-firecracker') ?? '';

  // ---- mode -----------------------------------------------------------------
  const modeStr = rawMode.trim() === '' ? 'check' : rawMode.trim();
  if (!isMode(modeStr)) {
    throw new Error(
      `npm-jar: invalid value for input "mode": "${modeStr}". Expected "check" or "update".`,
    );
  }

  // ---- spoof-platform -------------------------------------------------------
  const platformStr = rawPlatform.trim() === '' ? 'linux' : rawPlatform.trim();
  if (!isSpoofPlatform(platformStr)) {
    throw new Error(
      `npm-jar: invalid value for input "spoof-platform": "${platformStr}". ` +
      `Expected one of: linux, darwin, win32.`,
    );
  }

  // ---- spoof-arch -----------------------------------------------------------
  const archStr = rawArch.trim() === '' ? 'x64' : rawArch.trim();
  if (!isSpoofArch(archStr)) {
    throw new Error(
      `npm-jar: invalid value for input "spoof-arch": "${archStr}". ` +
      `Expected one of: x64, arm64.`,
    );
  }

  // ---- cache-firecracker ----------------------------------------------------
  const cacheStr = rawCache.trim();
  let cacheFirecracker: boolean;
  if (cacheStr === '' || cacheStr === 'true') cacheFirecracker = true;
  else if (cacheStr === 'false') cacheFirecracker = false;
  else {
    throw new Error(
      `npm-jar: invalid value for input "cache-firecracker": "${cacheStr}". ` +
      `Expected "true" or "false".`,
    );
  }

  // ---- path resolution ------------------------------------------------------
  const configRel = rawConfig.trim() === '' ? '.npm-jar.yml' : rawConfig.trim();
  const lockRel = rawLock.trim() === '' ? '.npm-jar.lock.yml' : rawLock.trim();

  return {
    configPath: resolveAgainstRepo(configRel, input.repoDir),
    lockPath: resolveAgainstRepo(lockRel, input.repoDir),
    mode: modeStr,
    spoofPlatform: platformStr,
    spoofArch: archStr,
    cacheFirecracker,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isMode(s: string): s is Mode {
  return VALID_MODES.has(s as Mode);
}

function isSpoofPlatform(s: string): s is SpoofPlatform {
  return VALID_PLATFORMS.has(s as SpoofPlatform);
}

function isSpoofArch(s: string): s is SpoofArch {
  return VALID_ARCHES.has(s as SpoofArch);
}

function resolveAgainstRepo(p: string, repoDir: string): string {
  if (isAbsolute(p)) return p;
  return join(resolve(repoDir), p);
}

/**
 * Default `getInput` — reads from `process.env.INPUT_<UPPER>` with hyphens
 * converted to underscores.  Matches `@actions/core`'s `getInput` convention.
 *
 * Returns `undefined` (not '') when the env var is unset so callers can
 * distinguish "not provided" from "empty string".
 */
function defaultGetInput(name: string): string | undefined {
  const key = `INPUT_${name.replace(/-/g, '_').toUpperCase()}`;
  return process.env[key];
}

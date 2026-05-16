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
// absolute path).  The `nodeVersion` is normalised to its MAJOR component
// (e.g. "20") because the rootfs images are keyed by major version.

import { existsSync as realExistsSync, readFileSync as realReadFileSync } from 'node:fs';
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
  /** Node MAJOR version as a string (e.g. "20"). */
  nodeVersion: string;
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
  /** Injection seam for filesystem reads (for .nvmrc / package.json). */
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

/** Default Node major version when no signal can be found. */
const DEFAULT_NODE_MAJOR = '20';

// ---------------------------------------------------------------------------
// parseInputs
// ---------------------------------------------------------------------------

export function parseInputs(input: ParseInput): ActionInputs {
  const getInput = input.getInput ?? defaultGetInput;
  const fs = input.fs ?? {
    existsSync: realExistsSync,
    readFileSync: (p: string, enc: 'utf8'): string => realReadFileSync(p, enc),
  };

  const rawConfig = getInput('config') ?? '';
  const rawLock = getInput('lock') ?? '';
  const rawMode = getInput('mode') ?? '';
  const rawPlatform = getInput('spoof-platform') ?? '';
  const rawArch = getInput('spoof-arch') ?? '';
  const rawNodeVersion = getInput('node-version') ?? '';
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

  // ---- node-version ---------------------------------------------------------
  const nodeVersion = resolveNodeMajor(rawNodeVersion, input.repoDir, fs);

  // ---- path resolution ------------------------------------------------------
  const configRel = rawConfig.trim() === '' ? '.npm-jar.yml' : rawConfig.trim();
  const lockRel = rawLock.trim() === '' ? '.npm-jar.lock.yml' : rawLock.trim();

  return {
    configPath: resolveAgainstRepo(configRel, input.repoDir),
    lockPath: resolveAgainstRepo(lockRel, input.repoDir),
    mode: modeStr,
    spoofPlatform: platformStr,
    spoofArch: archStr,
    nodeVersion,
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
 * Resolve the Node MAJOR version, in priority order:
 *   1. The literal `node-version` input (if non-empty).
 *   2. `<repoDir>/.nvmrc`.
 *   3. `engines.node` in `<repoDir>/package.json`.
 *   4. Default: "20".
 *
 * The returned string is always just the MAJOR component (e.g. "20"), with any
 * leading "v" or semver operator stripped.
 */
function resolveNodeMajor(
  rawInput: string,
  repoDir: string,
  fs: NonNullable<ParseInput['fs']>,
): string {
  const trimmed = rawInput.trim();
  if (trimmed !== '') return majorOf(trimmed);

  // .nvmrc
  const nvmrcPath = join(repoDir, '.nvmrc');
  if (fs.existsSync(nvmrcPath)) {
    try {
      const content = fs.readFileSync(nvmrcPath, 'utf8').trim();
      if (content !== '') return majorOf(content);
    } catch { /* fall through */ }
  }

  // engines.node
  const pkgPath = join(repoDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const content = fs.readFileSync(pkgPath, 'utf8');
      const parsed: unknown = JSON.parse(content);
      if (typeof parsed === 'object' && parsed !== null) {
        const engines = (parsed as { engines?: unknown }).engines;
        if (typeof engines === 'object' && engines !== null) {
          const node = (engines as { node?: unknown }).node;
          if (typeof node === 'string' && node.trim() !== '') {
            return majorOf(node);
          }
        }
      }
    } catch { /* malformed JSON / read failure → fall through */ }
  }

  return DEFAULT_NODE_MAJOR;
}

/**
 * Extract the MAJOR version from an arbitrary node-version-ish string.
 *
 * Accepts things like: "20", "v20", "20.10.0", ">=20.0.0", "^21.2.3", "~18".
 * Strips any leading non-digit characters (semver operators, "v") and any
 * trailing ".minor.patch".
 *
 * Returns DEFAULT_NODE_MAJOR if no digits are found.
 */
function majorOf(s: string): string {
  const match = s.match(/(\d+)/);
  return match ? match[1]! : DEFAULT_NODE_MAJOR;
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

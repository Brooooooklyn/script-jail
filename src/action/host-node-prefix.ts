// npm-jar — src/action/host-node-prefix.ts
//
// Resolves the user-selected Node installation prefix for the host-Node mount
// feature (Task #12).  The host packs the resolved prefix into a small ext4
// disk attached to the VM at /opt/host-node; the guest mounts it read-only and
// prepends its `bin` to PATH.
//
// Why we resolve via PATH, NOT `process.execPath`:
//   This action is wired in action.yml as `runs.using: node20`, which means
//   GitHub spawns dist/main.js with the *runner's bundled Node20* — and that's
//   what `process.execPath` reports.  But the entire point of this feature is
//   to capture whichever Node the user's workflow set up (typically via
//   `actions/setup-node`).  `actions/setup-node` prepends its toolcache `bin/`
//   directory to PATH, so a PATH-resolved `node` IS the user-selected Node;
//   `process.execPath` is the runner's internal Node and would be wrong.
//
// The two-step API:
//
//   - `resolveHostNodeExecPath` walks PATH and returns the realpath of the
//     first `<segment>/node` that is a regular executable file.  Symlinks
//     are resolved so the derived prefix reflects the install tree, not the
//     shim's parent.  Throws if no usable `node` is on PATH (a clear
//     setup-node-prompting error).
//
//   - `resolveHostNodePrefix` calls `resolveHostNodeExecPath`, derives the
//     prefix via two `dirname` calls, then validates it.  Rules, in order:
//
//       1. REJECT the runner's bundled Node — paths matching
//          `/runner/runners/<ver>/externals/node*/bin/node`.  This catches
//          the case where the user forgot `actions/setup-node` and the only
//          Node on PATH is the runner's internal one.
//
//       2. REJECT (subtree-aware) the system-wide blocklist regardless of
//          any later signal: `/usr`, `/usr/local`, `/opt/homebrew`,
//          `/opt/local`, `/`.  A derived prefix that EQUALS or sits UNDER
//          one of these roots is rejected even if marker files exist.
//          A `RUNNER_TOOL_CACHE` that itself sits inside a blocked root is
//          also ignored — a misconfigured env var cannot unlock /usr/....
//
//       3. ACCEPT paths under `/opt/hostedtoolcache/node/` (setup-node's
//          canonical install location on GH-hosted runners).
//
//       4. ACCEPT paths under `/tmp/`, `os.tmpdir()`, or
//          `process.env.RUNNER_TOOL_CACHE` (tests + self-hosted-runner
//          toolcache override).  Only honoured AFTER the blocklist check.
//
//       5. FALLBACK: anything else is accepted ONLY when it contains BOTH
//          `include/node/node.h` AND `share/doc/node`.  (Either alone has
//          false positives.)
//
// This module runs on Linux GitHub Actions runners only.  We deliberately do
// not handle Windows `.exe`/`.cmd` resolution — Windows runners aren't a
// target.  macOS dev/test goes through the tmp-prefix path.

import {
  existsSync as realExistsSync,
  statSync as realStatSync,
  realpathSync as realRealpathSync,
  accessSync as realAccessSync,
  constants as fsConstants,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface HostNodePrefixFs {
  existsSync(p: string): boolean;
}

/**
 * Strategy that returns the absolute path of a command found in one of the
 * given PATH segments (in order), or `null` if not found.  Injection seam so
 * tests don't need real files on disk.
 */
export type WhichFn = (cmd: string, segments: string[]) => string | null;

export interface ResolveHostNodeExecPathOptions {
  /** Defaults to `process.env.PATH ?? ''`. */
  path?: string | undefined;
  /** Defaults to a built-in fs-backed walk (no `which` dependency). */
  which?: WhichFn | undefined;
  /**
   * Optional fs seam used by the built-in `which` fallback.  Honoured only
   * when `which` is not supplied.
   */
  fs?: HostNodePrefixFs | undefined;
}

export interface ResolveHostNodePrefixOptions extends ResolveHostNodeExecPathOptions {
  /**
   * Defaults to `process.env.RUNNER_TOOL_CACHE`.  When set, any resolved
   * `node` path under this prefix is accepted without requiring marker
   * files.  This lets self-hosted runners point at a non-/opt/hostedtoolcache
   * directory while still bypassing the marker-file check.
   */
  runnerToolCache?: string | undefined;
}

// ---------------------------------------------------------------------------
// Constants — validation rules
// ---------------------------------------------------------------------------

const HOSTED_TOOLCACHE_PREFIX = '/opt/hostedtoolcache/node/';

/**
 * Runner-bundled Node lives under `/runner/runners/<ver>/externals/node*`/bin/node.
 * Be specific so we don't false-positive on toolcache paths (which never
 * contain `externals/node`).
 */
const RUNNER_BUNDLED_NODE_RE = /\/runner\/runners\/[^/]+\/externals\/node[^/]*\/bin\/node$/;

/**
 * Explicit blocklist: prefixes we refuse to pack even if marker files exist.
 * The order matters — `/usr/local` must be tested before `/usr` so the more
 * specific match wins (cosmetic, but the error message is cleaner).
 */
const SYSTEM_BLOCKLIST: ReadonlyArray<string> = [
  '/usr/local',
  '/usr',
  '/opt/homebrew',
  '/opt/local',
  '/',
];

// ---------------------------------------------------------------------------
// resolveHostNodeExecPath
// ---------------------------------------------------------------------------

/**
 * Walk the given PATH and return the absolute path of the first `node` found.
 * Throws a clear, setup-node-prompting error if no `node` is on PATH.
 */
export function resolveHostNodeExecPath(
  opts?: ResolveHostNodeExecPathOptions,
): string {
  // We distinguish "key not in opts" from "key present and undefined" so tests
  // that explicitly pass `path: undefined` cannot accidentally inherit the
  // real process.env.PATH.
  const rawPath =
    opts !== undefined && 'path' in opts ? opts.path : process.env['PATH'];
  const path = rawPath ?? '';
  const segments = path.split(delimiter).filter((s) => s !== '');

  const which: WhichFn =
    opts?.which ?? makeDefaultWhich(opts?.fs ?? { existsSync: realExistsSync });

  const resolved = which('node', segments);
  if (resolved === null) {
    throw new Error(
      'npm-jar: no `node` was found on PATH. Add `actions/setup-node` before ' +
        'this action so the chosen Node version is on PATH.',
    );
  }
  return resolved;
}

/**
 * Default `WhichFn`: walk segments in order, returning the first
 * `<segment>/node` that is a regular file AND has the executable bit set.
 * Symlinks are resolved with `realpathSync` so the derived prefix reflects
 * the underlying install tree, not the shim location.  Linux-only — we
 * deliberately skip Windows `.exe`/`.cmd` extension fallbacks; GH Linux
 * runners are the only target.
 *
 * Note: this function intentionally calls real `fs` APIs beyond
 * `existsSync` (the `HostNodePrefixFs` seam).  The seam is honoured for the
 * cheap existence check; statSync/accessSync/realpathSync are used directly
 * because the cost of widening the seam interface is not worth it for a
 * helper this small.  Tests that need to exercise non-runnable / symlinked
 * paths use real tmp files (see test/action/host-node-prefix.test.ts).
 */
function makeDefaultWhich(fs: HostNodePrefixFs): WhichFn {
  return (cmd, segments) => {
    for (const seg of segments) {
      const candidate = join(seg, cmd);
      if (!fs.existsSync(candidate)) continue;
      // Must be a regular file (not a directory) and executable by the
      // current user.  Skip silently and try the next segment if either
      // check fails — that mirrors how a real shell's `command -v` /
      // `which` walks PATH.
      let st;
      try {
        st = realStatSync(candidate);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      try {
        realAccessSync(candidate, fsConstants.X_OK);
      } catch {
        continue;
      }
      // Resolve symlinks so the derived prefix is the install root, not the
      // shim's parent.  Fall back to the candidate path if realpath fails
      // (the file exists and is executable — losing realpath is non-fatal).
      try {
        return realRealpathSync(candidate);
      } catch {
        return candidate;
      }
    }
    return null;
  };
}

// ---------------------------------------------------------------------------
// resolveHostNodePrefix
// ---------------------------------------------------------------------------

/**
 * Resolve the user-selected Node's install prefix.  Composes
 * `resolveHostNodeExecPath` (PATH-based lookup) with the dirname-twice
 * derivation and the tightened validation rules.  See file-level docs.
 *
 * @throws Error when the resolved path is the runner's bundled Node, when it
 *   matches the system-wide blocklist, or when it lacks the marker files
 *   required for a non-toolcache path.
 */
export function resolveHostNodePrefix(
  opts?: ResolveHostNodePrefixOptions,
): string {
  const fs = opts?.fs ?? { existsSync: realExistsSync };
  const execPath = resolveHostNodeExecPath({
    ...(opts !== undefined && 'path' in opts ? { path: opts.path } : {}),
    ...(opts?.which !== undefined ? { which: opts.which } : {}),
    fs,
  });

  // Reject the runner's bundled Node first.  We do this BEFORE deriving the
  // prefix because the error message should name the binary, not the prefix.
  if (RUNNER_BUNDLED_NODE_RE.test(execPath)) {
    throw new Error(
      "npm-jar: refusing to mount the GitHub Actions runner's bundled Node. " +
        'Add `actions/setup-node` before this action so the chosen Node version is used.',
    );
  }

  // Two dirname calls up: `/opt/.../x64/bin/node` → `/opt/.../x64`.
  const prefix = dirname(dirname(execPath));

  // Resolve the runner-tool-cache override (env var by default).
  const runnerToolCache =
    opts !== undefined && 'runnerToolCache' in opts
      ? opts.runnerToolCache
      : process.env['RUNNER_TOOL_CACHE'];

  // --- Hard blocklist FIRST -------------------------------------------------
  // We check the blocklist before the accept rules so that a misconfigured
  // RUNNER_TOOL_CACHE (e.g. pointed at `/usr`) can't unlock a system-wide
  // install.  The check is SUBTREE-AWARE: we reject `/usr/lib/node` as well
  // as `/usr` itself.  "Regardless of marker files" in the spec is
  // interpreted here as "regardless of any later signal".
  const blockedRoot = findBlockedRoot(prefix);
  if (blockedRoot !== null) {
    throw new Error(
      `npm-jar: refusing to pack ${blockedRoot} — looks like a system-wide ` +
        'install. Use actions/setup-node so Node lives in an isolated ' +
        'toolcache directory.',
    );
  }

  // --- Allowed locations (no marker-file requirement) -----------------------

  if (execPath.startsWith(HOSTED_TOOLCACHE_PREFIX)) return prefix;

  if (isUnder(execPath, '/tmp/')) return prefix;

  // os.tmpdir() may resolve to /var/folders/... on macOS or /tmp on Linux;
  // honour either at runtime.
  const tmp = tmpdir();
  if (tmp !== '' && tmp !== '/' && isUnder(execPath, withTrailingSlash(tmp))) {
    return prefix;
  }

  // RUNNER_TOOL_CACHE is honoured ONLY when it sits OUTSIDE every blocklisted
  // root.  A misconfigured `RUNNER_TOOL_CACHE=/usr` (or `/usr/local/...`) must
  // not unlock a system-wide install; the blocklist always wins.
  if (
    runnerToolCache !== undefined &&
    runnerToolCache !== '' &&
    runnerToolCache !== '/' &&
    findBlockedRoot(runnerToolCache) === null &&
    isUnder(execPath, withTrailingSlash(runnerToolCache))
  ) {
    return prefix;
  }

  // --- Fallback: require BOTH marker files ----------------------------------

  const hasHeader = fs.existsSync(join(prefix, 'include', 'node', 'node.h'));
  const hasDocs = fs.existsSync(join(prefix, 'share', 'doc', 'node'));
  if (hasHeader && hasDocs) return prefix;

  throw new Error(
    `npm-jar: ${execPath} does not appear to be a self-contained Node ` +
      'install (missing include/node/node.h and/or share/doc/node). ' +
      'Use actions/setup-node before calling this action.',
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function withTrailingSlash(p: string): string {
  return p.endsWith('/') ? p : `${p}/`;
}

function isUnder(path: string, prefixWithSlash: string): boolean {
  return path.startsWith(prefixWithSlash);
}

/**
 * Return the blocklisted root that contains (or equals) `path`, or `null` if
 * `path` is not under any blocked root.  Subtree-aware: `/usr/lib/node` is
 * caught under `/usr`.  The `/` entry is handled separately — every absolute
 * path technically starts with `/`, so we treat it as a root match only when
 * `path === '/'` (no real install lives directly under root and only at root,
 * but we also don't want to false-positive on every absolute path).
 */
function findBlockedRoot(path: string): string | null {
  if (path === '/') return '/';
  for (const blocked of SYSTEM_BLOCKLIST) {
    if (blocked === '/') continue; // handled above
    if (path === blocked) return blocked;
    if (isUnder(path, withTrailingSlash(blocked))) return blocked;
  }
  return null;
}

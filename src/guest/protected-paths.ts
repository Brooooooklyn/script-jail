// Protected-paths policy filter.
//
// Sits between attribution and emit in the install-phase pipeline. Decides
// which fs read/write events (carrying an `errno` field from strace-parser)
// should be:
//   - emitted with `hidden: true` (path matches a user-configured pattern)
//   - dropped silently (ENOENT on a non-protected path -- existing noise filter)
//   - emitted as-is (successful syscall, or EACCES on a non-protected path)
//
// Matching is done on the TOKENIZED path (`$HOME/.ssh/id_rsa` not
// `/root/.ssh/id_rsa`) so user patterns like `$HOME/.ssh/**` and
// `$REPO/.env*` match regardless of where the VM mounts $HOME or $REPO.
//
// Pattern normalization:
//   `~`          → `$HOME`              (so `~/.ssh/**` becomes `$HOME/.ssh/**`)
//   `$REPO`/etc. → kept as-is           (already canonical tokens)
//
// Micromatch is invoked with `dot: true` so dotfile segments like `.ssh` and
// `.env` match. The default would silently skip them.

import micromatch from 'micromatch';
import type { AttributedEvent, FsReadEvent, FsWriteEvent } from '../lock/schema.js';
import type { TokenizeRoots } from '../lock/tokenize.js';
import { canonicalizeTokenizeRoots, tokenize } from '../lock/tokenize.js';
import { canonicalizePrivateRealpath } from '../lock/private-realpath.js';

export interface ProtectedPathsMatcherInput {
  /** Patterns from config.protected.files (e.g. ['~/.ssh/**', '$REPO/.env*']). */
  patterns: ReadonlyArray<string>;
  roots: TokenizeRoots;
  /**
   * Host OS the audit runs on.  On 'darwin' the matcher collapses the macOS
   * `/private/{var,tmp,etc}` realpath prefix the Mach-O shim reports BEFORE
   * matching, so it agrees with the non-/private `roots` (and with normalize's
   * own /private canonicalization).  Defaults to 'linux' — a no-op — so the
   * Linux pipeline is byte-identical and a hostile Linux lockfile can never
   * trigger macOS path rewriting.
   */
  os?: 'linux' | 'darwin';
}

export class ProtectedPathsMatcher {
  private readonly tokenizedPatterns: string[];
  private readonly roots: TokenizeRoots;
  private readonly os: 'linux' | 'darwin';

  constructor(input: ProtectedPathsMatcherInput) {
    // Canonicalize the DROP-critical root prefixes (repo / nodeModules) so a
    // trailing-slash root (config.work_dir can arrive with one from
    // SCRIPT_JAIL_REPO_DIR / GITHUB_WORKSPACE) does not defeat the
    // segment-boundary prefix check in tokenize() / isUnderNodeModules() and
    // silently DROP a protected probe (e.g. an ENOENT read of `$REPO/.env` would
    // fail to tokenize, isProtected() would return false, and the policy would
    // drop it as unprotected noise instead of emitting `<HIDDEN> $REPO/.env`).
    // Same shared helper normalize() uses, so the matcher and the lock agree.
    this.roots = canonicalizeTokenizeRoots(input.roots);
    this.tokenizedPatterns = input.patterns.map(normalizePattern);
    this.os = input.os ?? 'linux';
  }

  /**
   * Collapse the macOS /private realpath prefix when auditing on darwin so the
   * raw shim path (/private/var/folders/.../node_modules/...) matches the
   * non-/private `roots`.  No-op on linux.
   */
  private canon(rawPath: string): string {
    return this.os === 'darwin' ? canonicalizePrivateRealpath(rawPath) : rawPath;
  }

  /**
   * Returns true when `rawPath` (an absolute Linux path) matches any
   * configured protected pattern after tokenization. The match is performed
   * on the TOKENIZED path so patterns like `$HOME/.ssh/**` match regardless
   * of which absolute path the VM uses for $HOME.
   *
   * Returns false when the matcher has no patterns -- a no-op matcher always
   * answers "not protected" so downstream filtering behaves like the original
   * pre-hidden-marking pipeline.
   */
  isProtected(rawPath: string): boolean {
    if (this.tokenizedPatterns.length === 0) return false;
    const tokenized = tokenize(this.canon(rawPath), this.roots);
    return micromatch.isMatch(tokenized, this.tokenizedPatterns, { dot: true });
  }

  /**
   * Returns true when `rawPath` is the node_modules root or anything beneath
   * it.  Matched on the RAW absolute path (not tokenized) because the drop
   * decision in {@link applyProtectedPathsPolicy} runs per-event before the
   * package-relative `$PKG` token is known; a sibling-package read and the
   * current package's own read both live under this root and are both meant to
   * be dropped (normalize would drop the `$PKG` ones anyway).
   *
   * Returns false for the no-op matcher (empty `nodeModules` root), so a
   * pipeline constructed without real roots never suppresses reads.
   */
  isUnderNodeModules(rawPath: string): boolean {
    const nm = this.roots.nodeModules;
    if (nm.length === 0) return false;
    const p = this.canon(rawPath);
    return p === nm || p.startsWith(`${nm}/`);
  }
}

/**
 * Apply the protected-paths policy to an AttributedEvent before emission.
 *
 *   - Non-fs events: returned unchanged.
 *   - fs events without `errno` (successful syscalls): transport-only
 *     fields (`dirfd`, `retFd`) are stripped and the event is returned.
 *   - fs events with `errno` whose path is PROTECTED: re-emitted with
 *     `hidden: true` and transport-only fields stripped. The hidden flag is
 *     what lock/normalize.ts turns into `<HIDDEN> $HOME/...`.
 *   - fs events with `errno === 'ENOENT'` whose path is NOT protected:
 *     dropped (`null`). This preserves the original noise filter -- nearly
 *     every install does thousands of ENOENT probes against $PATH lookups,
 *     library search paths, etc.
 *   - fs events with `errno === 'EACCES'` whose path is NOT protected:
 *     emitted with transport-only fields stripped (the attempt is still
 *     useful audit signal).
 *
 * Benign cross-package read suppression (2026-06-04): a lifecycle script
 * READING a file under $NODE_MODULES — a sibling installed package's
 * package.json / .node addon / source, or its own files — is normal install
 * behavior, not an escape, so the read is dropped before emission REGARDLESS of
 * success/ENOENT/EACCES.  The single exception is a path matching a configured
 * protected pattern: that is an explicit auditor opt-in, so it falls through to
 * the logic below and surfaces exactly as any other protected read (plainly on
 * success, `<HIDDEN>` on a failed probe).  This is the matcher-aware home for
 * the policy precisely because `hidden` is NOT set on successful reads, so a
 * normalize-side check could not tell a protected node_modules read from a
 * benign one.  WRITES under $NODE_MODULES are never dropped here — they are
 * tampering and `lock/normalize.ts` tags them `<CROSS_PACKAGE>`.
 *
 * Transport-only fields (`errno`, `dirfd`, `retFd`) are always stripped
 * before the event leaves this function; they must never reach
 * lock/normalize.ts (which doesn't reference them) or lock/render.ts
 * (which would write them into the YAML output).  See Finding 2 in
 * src/lock/schema.ts for the `dirfd`/`retFd` contract.
 */
export function applyProtectedPathsPolicy(
  ev: AttributedEvent,
  matcher: ProtectedPathsMatcher,
): AttributedEvent | null {
  if (ev.raw.kind !== 'read' && ev.raw.kind !== 'write') return ev;

  // Drop benign cross-package reads under $NODE_MODULES (any success/errno),
  // EXCEPT auditor-opted-in protected paths which fall through and surface
  // normally.  Writes are never dropped here — they continue below.
  if (
    ev.raw.kind === 'read' &&
    matcher.isUnderNodeModules(ev.raw.path) &&
    !matcher.isProtected(ev.raw.path)
  ) {
    return null;
  }

  if (ev.raw.errno === undefined) {
    // Successful syscall — no errno-based filtering, but we still must
    // strip the transport-only fd-table fields so they don't leak into
    // the rendered lockfile.  Cheap: most fs events have neither.
    if (ev.raw.dirfd === undefined && ev.raw.retFd === undefined) return ev;
    return { ...ev, raw: stripTransport(ev.raw) };
  }

  const isProtected = matcher.isProtected(ev.raw.path);
  if (isProtected) {
    return { ...ev, raw: stripTransport({ ...ev.raw, hidden: true }) };
  }

  if (ev.raw.errno === 'ENOENT') return null;
  return { ...ev, raw: stripTransport(ev.raw) };
}

/**
 * Return a clone of the fs event without the transport-only properties
 * (`errno`, `dirfd`, `retFd`).  We rely on destructuring rather than
 * `field: undefined` because exactOptionalPropertyTypes treats the latter
 * as "explicitly undefined" rather than absent -- and downstream code
 * reads `field === undefined` as "no value to report".  Stripping cleanly
 * avoids the distinction leaking out.
 */
function stripTransport<T extends FsReadEvent | FsWriteEvent>(ev: T): T {
  const { errno: _errno, dirfd: _dirfd, retFd: _retFd, ...rest } = ev;
  return rest as T;
}

/**
 * Normalize a user-written pattern to the tokenize.ts token form.
 *   `~`           → `$HOME`
 *   `~/foo`       → `$HOME/foo`
 *   `$REPO`/etc.  → kept as-is (already canonical)
 */
function normalizePattern(p: string): string {
  if (p === '~') return '$HOME';
  if (p.startsWith('~/')) return `$HOME/${p.slice(2)}`;
  return p;
}

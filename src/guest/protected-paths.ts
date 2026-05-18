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
import { tokenize } from '../lock/tokenize.js';

export interface ProtectedPathsMatcherInput {
  /** Patterns from config.protected.files (e.g. ['~/.ssh/**', '$REPO/.env*']). */
  patterns: ReadonlyArray<string>;
  roots: TokenizeRoots;
}

export class ProtectedPathsMatcher {
  private readonly tokenizedPatterns: string[];
  private readonly roots: TokenizeRoots;

  constructor(input: ProtectedPathsMatcherInput) {
    this.roots = input.roots;
    this.tokenizedPatterns = input.patterns.map(normalizePattern);
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
    const tokenized = tokenize(rawPath, this.roots);
    return micromatch.isMatch(tokenized, this.tokenizedPatterns, { dot: true });
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

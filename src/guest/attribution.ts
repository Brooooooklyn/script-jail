// pid → lifecycle-package attribution
//
// The Attribution class walks the /proc/<pid>/status PPid chain to find the
// nearest ancestor process whose environment contains:
//   - npm_package_name   (and optionally npm_package_version)
//   - npm_lifecycle_event set to one of the four canonical LifecycleStage values
//
// That ancestor's environment determines the pkg and lifecycle for the
// AttributedEvent. The result is cached per starting pid so subsequent calls
// for the same pid never re-read /proc.
//
// Walk termination rules:
//   - Terminate when we reach ppid 0 or 1 (init / kernel pseudo-process).
//   - Terminate when readPpid() returns null (unreadable or missing status).
//   - When readEnviron() returns null for the current pid but readPpid() is
//     still readable, we continue walking UP the chain (the current process
//     may be short-lived or sandboxed, but its parent may have the npm vars).
//     Only a null from readPpid() terminates the walk.
//   - Terminate (return null) when no ancestor in the entire chain matches.

import type { LifecycleStage } from '../lock/schema.js';
import { LifecycleStage as LifecycleStageSchema } from '../lock/schema.js';

export interface AttributionResult {
  /**
   * Package identity string. Format: `npm_package_name@npm_package_version`
   * when both env vars are present, otherwise just `npm_package_name`.
   * npm, pnpm, and yarn-berry all set both; the fallback handles unusual or
   * synthetic invocations where the version variable is absent.
   */
  pkg: string;
  lifecycle: LifecycleStage;
}

/** Seam to the OS's /proc filesystem. Kept separate so Attribution is 100%
 *  unit-testable with a synthetic in-memory implementation. */
export interface ProcReader {
  /** Read the PPid field from /proc/<pid>/status.
   *  Returns null on ENOENT, EACCES, or any parse failure. Never throws. */
  readPpid(pid: number): number | null;

  /** Read and parse /proc/<pid>/environ (NUL-separated KEY=VALUE pairs).
   *  Returns null on ENOENT or EACCES. Never throws.
   *  Tokens without an '=' are silently skipped.
   *  When '=' appears in the value (e.g. KEY=foo=bar) only the first '='
   *  is used as the delimiter, so the value is 'foo=bar'. */
  readEnviron(pid: number): Map<string, string> | null;
}

/** The four canonical npm lifecycle stages we recognise as attribution roots.
 *  Any other value of npm_lifecycle_event (e.g. "test", "start") is ignored
 *  and the walk continues up to the next ancestor. */
const CANONICAL_STAGES = new Set<string>(LifecycleStageSchema.options);

function isCanonicalStage(s: string): s is LifecycleStage {
  return CANONICAL_STAGES.has(s);
}

/**
 * Build the pkg string from the environment map.
 * Returns `name@version` when both npm_package_name and npm_package_version
 * are present, otherwise just `name`.
 */
function buildPkg(env: Map<string, string>): string {
  const name = env.get('npm_package_name') ?? '';
  const version = env.get('npm_package_version');
  return version !== undefined ? `${name}@${version}` : name;
}

export class Attribution {
  private readonly reader: ProcReader;
  /** Terminal-result cache: keyed by the *starting* pid of each attribute() call. */
  private readonly cache: Map<number, AttributionResult | null> = new Map();

  constructor(reader: ProcReader) {
    this.reader = reader;
  }

  /**
   * Walk pid → ppid → ppid' … until we find a process whose environ has
   * `npm_package_name` AND `npm_lifecycle_event` is one of the four canonical
   * LifecycleStage values. Return that pkg + lifecycle pair.
   *
   * Returns null when:
   *   - The walk reaches pid 0 or 1 without finding a match.
   *   - readPpid() returns null for any pid in the chain.
   *   - No ancestor in the chain has the required env vars.
   *
   * Results are cached per starting pid. A second call with the same pid will
   * return the cached value without any additional /proc reads.
   */
  attribute(pid: number): AttributionResult | null {
    if (this.cache.has(pid)) {
      return this.cache.get(pid) ?? null;
    }

    const result = this._walk(pid);
    this.cache.set(pid, result);
    return result;
  }

  private _walk(startPid: number): AttributionResult | null {
    let current = startPid;

    // Safety bound to prevent infinite loops on malformed /proc data.
    // In practice, process trees are shallow; 1024 levels is far beyond any
    // realistic depth.
    const MAX_DEPTH = 1024;

    for (let depth = 0; depth < MAX_DEPTH; depth++) {
      // pid 0 and pid 1 are the kernel idle process and init respectively.
      // Neither is an npm lifecycle root; terminate here.
      if (current === 0 || current === 1) {
        return null;
      }

      // Check if this pid has the required npm env vars.
      //
      // TODO(v2): Attribution trusts the environment of the *observed* process
      // (and its ancestors) at face value.  A malicious lifecycle script could
      // spawn a child process with forged npm_package_name / npm_lifecycle_event
      // vars, causing that child's events to be recorded under the wrong
      // package.  A hardened implementation would identify trusted lifecycle
      // roots from the package-manager launch context (e.g. by tracking which
      // pids the pm itself forked) and propagate attribution downward from those
      // roots rather than reading unchecked env from arbitrary ancestors.
      const env = this.reader.readEnviron(current);
      if (env !== null) {
        const name = env.get('npm_package_name');
        const event = env.get('npm_lifecycle_event');
        if (name !== undefined && event !== undefined && isCanonicalStage(event)) {
          return { pkg: buildPkg(env), lifecycle: event };
        }
        // npm_package_name is set but event is not canonical (or missing):
        // continue walking up.
      }
      // When env is null: the process's environ is unreadable. We still try to
      // walk up via its ppid — the parent may have the npm vars. Only a null
      // ppid terminates the walk.

      const ppid = this.reader.readPpid(current);
      if (ppid === null) {
        return null;
      }

      current = ppid;
    }

    // Exceeded depth limit — treat as no match.
    return null;
  }
}

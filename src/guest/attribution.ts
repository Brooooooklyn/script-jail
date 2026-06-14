// pid → lifecycle-package attribution
//
// The Attribution class walks the /proc/<pid>/status PPid chain to find the
// process itself or its nearest ancestor whose environment contains:
//   - npm_package_name   (and optionally npm_package_version)
//   - npm_lifecycle_event set to one of the four canonical LifecycleStage values
//
// That process's environment determines the pkg and lifecycle for the
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
 * Build the pkg string from a non-empty name and an optional version.
 * Returns `name@version` when version is present, otherwise just `name`.
 */
function buildPkg(name: string, version: string | undefined): string {
  return version !== undefined ? `${name}@${version}` : name;
}

/**
 * Build the complete set of root-package identity keys from a parsed
 * root `package.json` manifest, and the canonical key to use when
 * force-attributing events to the root.
 *
 * Rules mirror `buildPkg` exactly:
 *   - Bare `name` is ALWAYS added (covers the "version field absent →
 *     npm sets no npm_package_version → attribution yields bare name" case).
 *   - `name@version` is added whenever `version` is a string — INCLUDING
 *     the empty string `''` — because npm/pnpm set `npm_package_version=`
 *     (empty) when `package.json` has `"version": ""`, which makes
 *     `buildPkg` produce `name@` (NOT the bare `name`).  Gating on
 *     `version.length > 0` would diverge from `buildPkg` for that case,
 *     causing a root fs event with `pkg='name@'` to go unrecognised and
 *     `normalize` to throw `pkgDirs missing entry`.
 *
 * Returns `{ keys: Set<string>, canonical: string | null }` where:
 *   - `keys` is the set of all pkg strings that could be emitted by
 *     attribution for a root event.
 *   - `canonical` is the single key used to force-attribute root events
 *     (the most-specific one: `name@version` when version is a string,
 *     else `name`).  `null` only when `name` is missing/invalid.
 *
 * Used by both `src/guest/agent.ts` (guest side) and `src/main.ts`
 * (host side) to avoid duplicating this logic — divergence was the
 * original bug.
 */
export function buildRootPkgKeys(manifest: { name?: unknown; version?: unknown }): {
  keys: Set<string>;
  canonical: string | null;
} {
  const keys = new Set<string>();
  if (typeof manifest.name !== 'string' || manifest.name.length === 0) {
    return { keys, canonical: null };
  }
  const name = manifest.name;
  keys.add(name);
  if (typeof manifest.version === 'string') {
    // version is present (even if empty ''): mirrors buildPkg → `name@version`
    keys.add(`${name}@${manifest.version}`);
    return { keys, canonical: `${name}@${manifest.version}` };
  }
  // version field absent → canonical is bare name
  return { keys, canonical: name };
}

/**
 * Compose an {@link AttributionResult} from raw npm lifecycle env vars, applying
 * the SAME match rules as the /proc walk: `npm_package_name` must be non-empty
 * AND `npm_lifecycle_event` must be one of the canonical {@link LifecycleStage}
 * values. Returns null otherwise.
 *
 * Shared by {@link Attribution._walk} (reading /proc/<pid>/environ) and the
 * phase-install dispatcher's shim-exec fast path (reading the
 * `npm_package_name`/`npm_package_version`/`npm_lifecycle_event` fields the
 * LD_PRELOAD shim stamps into its `exec` record). Centralising it guarantees a
 * shim-sourced attribution renders BYTE-IDENTICALLY to the /proc-sourced one —
 * the invariant the macOS-VZ-vs-Docker parity test depends on.
 *
 * TRUST (audit-trust, 2026-06-03): both inputs are trusted at face value and at
 * the SAME level. The /proc path reads a process's own (script-settable) env
 * (see the {@link Attribution._walk} `TODO(v2)` note); the shim path reads
 * fields the shim stamped from that same env at ctor time, carried over the
 * events-file channel. A malicious lifecycle script can MIS-LABEL a spawn
 * through either path. Reading these fields adds an attribution LABEL to the
 * shim's events-file channel but does not change that channel's integrity: it
 * was already forgeable by an already-shim-loaded pid (the out-of-scope
 * "advanced attack" the phase-install events-file forgery detector documents),
 * and that same forgery can ALSO suppress `<SYSCALL_EXEC_BYPASS>` synthesis
 * (under-capture) — see the trust notes at the phase-install seed site. Do not
 * read this helper as a guarantee that forged attribution can only mislabel
 * and never hide; the bypass-suppression path is the counterexample.
 */
export function attributionFromEnvVars(
  name: string | undefined,
  version: string | undefined,
  event: string | undefined,
): AttributionResult | null {
  if (
    name !== undefined &&
    name.length > 0 &&
    event !== undefined &&
    isCanonicalStage(event)
  ) {
    return { pkg: buildPkg(name, version), lifecycle: event };
  }
  return null;
}

export class Attribution {
  private readonly reader: ProcReader;
  // Terminal-only cache: keyed by starting pid. Intermediate pids are not
  // cached (v1 limitation). Pid recycling is rare but possible — even in the
  // single-install Firecracker environment, a short-lived child can exit and
  // have its pid reassigned within the same install when another sibling
  // forks. The {@link invalidate} method exists so the phase-install
  // dispatcher can drop a dead generation's cached attribution upon observing
  // its `+++ exited +++` line, ensuring the next `attribute(pid)` on the
  // recycled pid re-reads /proc instead of returning the dead generation's
  // result.
  private readonly cache: Map<number, AttributionResult | null> = new Map();

  constructor(reader: ProcReader) {
    this.reader = reader;
  }

  /**
   * Walk pid → ppid → ppid' … until we find the process itself or its nearest
   * ancestor whose environ has `npm_package_name` (non-empty) AND
   * `npm_lifecycle_event` is one of the four canonical LifecycleStage values.
   * Return that pkg + lifecycle pair.
   *
   * Returns null when:
   *   - The walk reaches pid 0 or 1 without finding a match.
   *   - readPpid() returns null for any pid in the chain.
   *   - No process in the chain has the required env vars.
   *
   * Results are cached per starting pid. A second call with the same pid will
   * return the cached value without any additional /proc reads — unless
   * {@link invalidate} has been called for the pid in between.
   */
  attribute(pid: number): AttributionResult | null {
    if (this.cache.has(pid)) {
      return this.cache.get(pid) ?? null;
    }

    const result = this._walk(pid);
    this.cache.set(pid, result);
    return result;
  }

  /**
   * Drop the cached attribution for `pid`. The next call to
   * {@link attribute} for the same pid will walk /proc afresh.
   *
   * Used by the phase-install dispatcher when it observes a process-exit
   * strace line (`+++ exited +++` / `+++ killed by SIG... +++`) so a
   * recycled pid does NOT inherit the dead generation's cached
   * attribution result. Without invalidation, the per-pid `cache` Map
   * here would keep returning the old pkg/lifecycle pair forever (the
   * single-install Firecracker environment runs for the whole install,
   * so the process-level cache is long-lived), and the dispatcher's
   * snapshot machinery would store the stale value as the recycled
   * pid's new generation snapshot.
   */
  invalidate(pid: number): void {
    this.cache.delete(pid);
  }

  private _walk(startPid: number): AttributionResult | null {
    let current = startPid;

    // Safety bound to prevent infinite loops on malformed /proc data.
    // In practice, process trees are shallow; 1024 levels is far beyond any
    // realistic depth. Linux's PID namespace nesting cap is ≤32, so 1024 is
    // a conservative upper bound.
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
        const attrib = attributionFromEnvVars(
          env.get('npm_package_name'),
          env.get('npm_package_version'),
          env.get('npm_lifecycle_event'),
        );
        if (attrib !== null) {
          return attrib;
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

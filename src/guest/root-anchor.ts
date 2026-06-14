// Pure "repo-root anchoring" helper.
//
// script-jail attributes each fs/network event to a package using the
// FORGEABLE npm_* env vars read from /proc/<pid>/environ. The ROOT project is
// treated specially in src/lock/normalize.ts (its events surface as $REPO/...).
// A malicious dependency could spawn a child with a forged
// npm_package_name=<root-project-name> and thereby launder its repo writes into
// the ROOT project's attribution.
//
// To stop that, ROOT identity is decided from a NON-forgeable signal: the
// kernel-observed process tree (clone/fork/vfork edges) plus the cwd each
// process had at its FIRST execve. The package manager sets a lifecycle
// script's cwd to the package dir BEFORE the script can run, so it cannot be
// forged after the fact (a later chdir does not change the snapshotted value).
//
// This module is intentionally PURE: no I/O, no global state, no internal
// cache. The maps it consumes are built elsewhere (a later wiring task).

export interface RepoRootAnchorInput {
  pid: number;
  /** child pid -> parent pid, from kernel-observed clone/fork/vfork. */
  childParent: Map<number, number>;
  /** pid -> resolved cwd snapshotted at the pid's FIRST execve.
   *  - a string  = the cwd at exec time (kernel-observed, PM-set, non-forgeable)
   *  - null      = the pid exec'd but its cwd was unresolvable (fail closed)
   *  - absent    = the pid never exec'd (forked but same program as parent) */
  execCwd: Map<number, string | null>;
  /** returns true iff this pid's cwd is provably unknown; query through the
   *  caller's group-aware accessor. A pid whose cwd became unresolvable is
   *  unprovable, so the walk treats it as a disqualifier (fail closed). */
  cwdUnknown: (pid: number) => boolean;
  /** the resolved repo root (path.resolve of the install cwd). */
  workDir: string;
  /** the traced package-manager root pid (the trusted anchor). */
  rootPid: number;
}

// Safety bound to prevent infinite loops on malformed/cyclic maps. Mirrors the
// bound used in src/guest/attribution.ts; real process trees are far shallower
// (Linux PID-namespace nesting caps at ≤32), so 1024 is a conservative ceiling.
const MAX_DEPTH = 1024;

/**
 * Returns true iff `pid` is "repo-root anchored": walking pid -> parent up to
 * `rootPid`, every process either never exec'd (inherits its parent's identity)
 * or exec'd with cwd === workDir, and we reach `rootPid` without hitting an
 * ancestor whose exec-cwd is a non-root directory, an unknown cwd, or a broken
 * lineage. Fail closed (return false) on any uncertainty.
 */
export function isRepoRootAnchored(input: RepoRootAnchorInput): boolean {
  const { childParent, execCwd, workDir, rootPid } = input;

  let cur = input.pid;

  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    // Reached the trusted PM anchor with no disqualifier along the way.
    if (cur === rootPid) {
      return true;
    }

    // This pid's cwd is unprovable: fail closed. The `cwdUnknown` predicate is
    // group-aware (the caller routes it through its cwd-group accessor) so a pid
    // marked unknown via a CLONE_FS sibling is disqualified even if a stale
    // value lingers in the raw cwd map.
    if (input.cwdUnknown(cur)) {
      return false;
    }

    const ec = execCwd.get(cur);
    if (ec === null) {
      // Exec'd, but its cwd was unresolvable: fail closed.
      return false;
    }
    if (ec !== undefined && ec !== workDir) {
      // A script launched in a non-root dir (e.g. a dependency's
      // node_modules/<dep>). This is the disqualifier we are guarding against,
      // and snapshotting at exec time means a later chdir(workDir) cannot
      // launder it. Fail closed.
      return false;
    }
    // Otherwise: ec === workDir (exec'd at the repo root) or ec === undefined
    // (never exec'd, inherits parent identity). Either way this hop is fine;
    // continue walking up.

    const parent = childParent.get(cur);
    if (parent === undefined) {
      // Unknown lineage: we did not reach rootPid. Fail closed.
      return false;
    }
    cur = parent;
  }

  // Depth bound exceeded (malformed or cyclic map): fail closed.
  return false;
}

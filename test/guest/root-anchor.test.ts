// Tests for src/guest/root-anchor.ts
// Uses vitest project: "guest" (see vitest.config.ts — test/guest/** routes there).
// Pure function: every case builds small synthetic maps by hand and asserts the boolean.

import { describe, it, expect } from 'vitest';
import { isRepoRootAnchored } from '../../src/guest/root-anchor.js';
import type { RepoRootAnchorInput } from '../../src/guest/root-anchor.js';

const WORK = '/work';

// Builder with sane empty defaults so each test only sets what it cares about.
function input(over: Partial<RepoRootAnchorInput>): RepoRootAnchorInput {
  return {
    pid: 0,
    childParent: new Map(),
    execCwd: new Map(),
    cwdUnknown: () => false,
    recycled: () => false,
    workDir: WORK,
    rootPid: 100,
    ...over,
  };
}

describe('isRepoRootAnchored', () => {
  it('returns true when pid IS the rootPid', () => {
    expect(isRepoRootAnchored(input({ pid: 100, rootPid: 100 }))).toBe(true);
  });

  it('returns true for a genuine root-script chain where every exec-cwd is workDir', () => {
    // 100 (PM root) -> 101 (sh, exec at /work) -> 102 (node, exec at /work)
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [102, WORK],
          [101, WORK],
        ]),
      }),
    );
    expect(r).toBe(true);
  });

  it('returns true when an intermediate pid never exec\'d (cwd absent = inherits parent)', () => {
    // 102 forked from 101 without exec'ing (absent from execCwd) -> inherits.
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [101, WORK],
          // 102 absent: forked, never exec'd
        ]),
      }),
    );
    expect(r).toBe(true);
  });

  it('returns true when the leaf pid itself never exec\'d', () => {
    // pid 103 forked directly off rootPid, never exec'd.
    const r = isRepoRootAnchored(
      input({
        pid: 103,
        rootPid: 100,
        childParent: new Map([[103, 100]]),
        execCwd: new Map(), // 103 absent
      }),
    );
    expect(r).toBe(true);
  });

  it('returns false for a dependency-anchored chain (ancestor exec\'d in node_modules)', () => {
    // 100 (PM) -> 101 (dep install script, exec at /work/node_modules/dep)
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, '/work/node_modules/dep']]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false for the chdir-after-exec attack (leaf cwd=workDir but ancestor in node_modules)', () => {
    // Key security property. 100 (PM) -> 101 (dep script, exec'd at
    // /work/node_modules/evil) -> 102 (child that exec'd with cwd /work,
    // e.g. after the parent chdir'd). The snapshotted ancestor cwd betrays it.
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [102, WORK], // leaf looks root-anchored...
          [101, '/work/node_modules/evil'], // ...but its parent does not.
        ]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when the leaf\'s own exec-cwd is a non-root dir', () => {
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, '/work/node_modules/dep/sub']]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when exec-cwd is null (exec\'d but cwd unresolvable)', () => {
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, null]]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when null exec-cwd is on an ancestor, not the leaf', () => {
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [102, WORK],
          [101, null], // ancestor cwd unresolvable
        ]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when the leaf pid is reported unknown by the cwdUnknown predicate', () => {
    const unknown = new Set([101]);
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, WORK]]),
        cwdUnknown: (pid) => unknown.has(pid),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when an ancestor pid is reported unknown by the cwdUnknown predicate', () => {
    const unknown = new Set([101]);
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [102, WORK],
          [101, WORK],
        ]),
        cwdUnknown: (pid) => unknown.has(pid),
      }),
    );
    expect(r).toBe(false);
  });

  it('cwdUnknown predicate disqualifies independently of execCwd: cwd looks anchored (execCwd=workDir) but is provably unknown', () => {
    // Soundness regression guard. The exec-cwd snapshot says this leaf exec'd
    // at the repo root (execCwd=workDir, which alone would pass), but the
    // group-aware cwdUnknown predicate reports its cwd as provably unknown
    // (e.g. a CLONE_FS sibling marked the group unknown while a stale workDir
    // value lingered). The predicate disqualifier MUST fire regardless of the
    // execCwd value, so the pid cannot be laundered into a root-anchored
    // verdict. Pre-fix the helper queried a raw-pid Set and could miss this.
    const unknown = new Set([101]);
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, WORK]]), // exec snapshot looks anchored...
        cwdUnknown: (pid) => unknown.has(pid), // ...but cwd is provably unknown.
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false on broken lineage (a non-root pid with no childParent entry)', () => {
    // 102 -> 101, but 101 has no parent entry and is not rootPid.
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([[102, 101]]), // 101 -> ??? missing
        execCwd: new Map([
          [102, WORK],
          [101, WORK],
        ]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false when the leaf pid has no childParent entry and is not rootPid', () => {
    const r = isRepoRootAnchored(
      input({
        pid: 999,
        rootPid: 100,
        childParent: new Map(),
        execCwd: new Map(),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false on a cycle in childParent (bounded by MAX_DEPTH)', () => {
    // 101 <-> 102 cycle that never reaches rootPid.
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([
          [101, 102],
          [102, 101],
        ]),
        execCwd: new Map([
          [101, WORK],
          [102, WORK],
        ]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns false on a self-cycle that is not rootPid', () => {
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 101]]),
        execCwd: new Map([[101, WORK]]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns true for a deep-but-bounded valid chain (well under MAX_DEPTH)', () => {
    // Build 1 (root) <- 2 <- ... <- 500, all exec at workDir.
    const childParent = new Map<number, number>();
    const execCwd = new Map<number, string | null>();
    for (let p = 2; p <= 500; p++) {
      childParent.set(p, p - 1);
      execCwd.set(p, WORK);
    }
    const r = isRepoRootAnchored(
      input({ pid: 500, rootPid: 1, childParent, execCwd }),
    );
    expect(r).toBe(true);
  });

  it('returns false for an over-deep but otherwise-valid chain (exceeds MAX_DEPTH before reaching rootPid)', () => {
    // The cycle tests cover the cyclic side of the depth bound; this covers the
    // acyclic side: a STRUCTURALLY VALID linear chain (every hop exec'd at
    // workDir, every parent edge present, terminating at rootPid) that is simply
    // TOO LONG. The loop runs depth 0..1023 (MAX_DEPTH=1024); a chain that would
    // only reach rootPid at depth 1024+ falls through the bound and fails closed.
    //
    // Build 1 (root) <- 2 <- ... <- 1100, all exec at workDir, starting at the
    // 1100-deep leaf. Reaching rootPid (1) would require depth 1099, but the
    // last executed iteration is depth 1023 (cur = 1100 - 1023 = 77 != 1), so it
    // exits the loop and returns false despite the chain being entirely honest.
    const childParent = new Map<number, number>();
    const execCwd = new Map<number, string | null>();
    for (let p = 2; p <= 1100; p++) {
      childParent.set(p, p - 1);
      execCwd.set(p, WORK);
    }
    const r = isRepoRootAnchored(
      input({ pid: 1100, rootPid: 1, childParent, execCwd }),
    );
    expect(r).toBe(false);
  });

  it('does NOT special-case workDir as a non-root subdir prefix match', () => {
    // A path that has workDir as a prefix but is a sibling, e.g.
    // '/work-evil', must be treated as a non-root dir (exact match only).
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, '/work-evil']]),
      }),
    );
    expect(r).toBe(false);
  });

  it('returns true when pid === rootPid even with empty maps', () => {
    expect(
      isRepoRootAnchored(input({ pid: 42, rootPid: 42 })),
    ).toBe(true);
  });

  // --- pid-reuse determinism (the `recycled` disqualifier) -----------------
  // A pid NUMBER reused across generations has a LAST-WINS childParent edge in
  // the dispatcher: the surviving edge is whichever clone line drained last,
  // which is strace -ff drain-order-dependent. A pid that ever received >=2
  // distinct parent edges (childParentReused) or exec'd after its own exit
  // (pidRecycled) is reported by the `recycled` predicate, and the walk must
  // fail closed on it so the verdict is REPRODUCIBLE (a deterministic
  // <FORGED_ROOT>) instead of flapping genuine/forged with drain order. This is
  // the napi-rs yarn-berry husky-postinstall flap: a transient launcher whose
  // pid lineage passes through a recycled intermediate.

  it('recycled ancestor on the walk path → false, even though the chain otherwise reaches rootPid at workDir', () => {
    // 102 -> 101 -> 100(root), every exec-cwd is workDir → WOULD anchor true,
    // but the intermediate 101's pid number was reused (its childParent edge is
    // not trustworthy). Fail closed.
    const recycled = new Set([101]);
    const over = {
      pid: 102,
      rootPid: 100,
      childParent: new Map([
        [102, 101],
        [101, 100],
      ]),
      execCwd: new Map([
        [102, WORK],
        [101, WORK],
      ]),
    };
    // Control: WITHOUT the recycle signal this exact chain anchors true. This is
    // what makes the verdict flap when `childParent`'s last-wins edge differs by
    // drain order; the predicate is what pins it to a deterministic false.
    expect(isRepoRootAnchored(input({ ...over }))).toBe(true);
    expect(
      isRepoRootAnchored(input({ ...over, recycled: (p) => recycled.has(p) })),
    ).toBe(false);
  });

  it('recycled leaf pid → false', () => {
    const recycled = new Set([101]);
    const r = isRepoRootAnchored(
      input({
        pid: 101,
        rootPid: 100,
        childParent: new Map([[101, 100]]),
        execCwd: new Map([[101, WORK]]),
        recycled: (p) => recycled.has(p),
      }),
    );
    expect(r).toBe(false);
  });

  it('recycled rootPid number → false (defense-in-depth: a reused root pid number is not blindly trusted)', () => {
    // Security-conservative ordering: the recycle disqualifier is checked BEFORE
    // the rootPid success terminal, so an event whose pid === rootPid still fails
    // closed if that pid number was observed reused. In practice the PM root pid
    // is long-lived and never flagged, so genuine root events are unaffected; a
    // false NEGATIVE (hiding a forged write) is the catastrophic direction, so we
    // prefer the over-surface here.
    const recycled = new Set([100]);
    const r = isRepoRootAnchored(
      input({
        pid: 100,
        rootPid: 100,
        recycled: (p) => recycled.has(p),
      }),
    );
    expect(r).toBe(false);
  });

  it('a clean (non-recycled) chain still anchors true with the predicate wired', () => {
    // The predicate must NOT over-fire: a normal chain where no walked pid is
    // recycled anchors exactly as before.
    const r = isRepoRootAnchored(
      input({
        pid: 102,
        rootPid: 100,
        childParent: new Map([
          [102, 101],
          [101, 100],
        ]),
        execCwd: new Map([
          [102, WORK],
          [101, WORK],
        ]),
        recycled: () => false,
      }),
    );
    expect(r).toBe(true);
  });
});

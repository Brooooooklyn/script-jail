// script-jail — phase-install.ts
// Phase B: network-off audited install under strace.
//
// Per-manager commands:
//   npm:  `npm rebuild --foreground-scripts`
//     Runs lifecycle scripts against the already-fetched node_modules.
//     --foreground-scripts keeps stdout/stderr visible for debugging.
//   pnpm: `pnpm install --frozen-lockfile --offline --config.side-effects-cache=false`
//     Installs from cache without network and without side-effect cache
//     to ensure we always run lifecycle scripts fresh.
//   yarn: `yarn install --immutable --offline`
//     Re-links packages and runs scripts without touching the registry.
//
// ARCHITECTURE: StraceRunner is the *sole* owner of the install child process.
// There is no separate Spawner call in Phase B — doing so would start the
// lifecycle scripts twice (once audited under strace, once not), which is
// both incorrect and a security hole. The StraceRunner emits (pid, line)
// records while the process runs and resolves its async iterable with the
// exit code via the final sentinel record.

import * as fs from 'node:fs';
import * as path from 'node:path';

import type { Emitter } from './emit.js';
import type { Attribution } from './attribution.js';
import { parseStraceLine, unescapeStraceString } from './strace-parser.js';
import { applyProtectedPathsPolicy, ProtectedPathsMatcher } from './protected-paths.js';
import {
  ExecEvent,
  EnvTamperEvent,
  type AttributedEvent,
  type RawEvent,
} from '../lock/schema.js';

/**
 * StraceRunner abstraction. Spawns strace and streams (pid, line) records.
 * It is the sole owner of the audited child process — no separate Spawner is
 * used for Phase B. Production impl tails per-pid files as they grow; test
 * impl emits pre-canned sequences.
 *
 * The iterable completes when the traced process and all its children have
 * exited. Callers obtain the install command exit code via `getExitCode()`
 * after the iterable drains.
 */
/**
 * Source channel of a yielded line.
 *
 *   `'shim'`   — line came from a trusted JSONL writer: the fd-3 pipe (env-spy
 *                / dlopen-block preloads writing directly into the
 *                LinuxStraceRunner-owned pipe) OR the per-VM events file
 *                (SCRIPT_JAIL_LOG_FILE) the Rust LD_PRELOAD shim writes into
 *                with `O_APPEND`.  Only `parseShimLine` is consulted for these
 *                lines.  A parse failure here is fatal: lifecycle scripts can
 *                technically open the events file (the path leaks through the
 *                child env so descendants can find it) and write a
 *                partial-line prefix that, on the next legitimate shim write,
 *                concatenates into garbage and gets dropped silently.  We
 *                fail closed via `recordTamper()` instead.
 *
 *   `'strace'` — line came from strace's per-pid `-ff -o <basePath>.<pid>`
 *                text output.  Only `parseStraceLine` is consulted.  Parse
 *                failures here are best-effort drops — strace's format is
 *                unstable across versions, lines can be split across reads
 *                under load, and the channel is noisy by design (we trace
 *                openat/execve/connect/readlinkat/statx/etc.).  A strict
 *                fail-closed here would block every install.
 */
export type LineSource = 'shim' | 'strace';

export interface StraceRunner {
  /**
   * Spawn `strace -ff -e trace=... -o <basePath> <cmd> <args>` and return an
   * async iterable of {pid, line, source} records. The iterable completes
   * when the traced process and all its children have exited.
   *
   * The `source` discriminator tells the caller whether the line came from
   * the trusted JSONL shim channel (fd-3 pipe or SCRIPT_JAIL_LOG_FILE) or
   * from strace's stdout text format.  See {@link LineSource}.
   *
   * After the iterable is fully consumed, `getExitCode()` returns the exit
   * code of the traced root process.
   */
  run(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string; basePath: string },
  ): AsyncIterable<{ pid: number; line: string; source: LineSource }>;

  /**
   * Returns the exit code of the most recently run process.
   * Only valid after the async iterable from `run()` has been fully consumed.
   */
  getExitCode(): number;

  /**
   * Returns a human-readable tamper reason if the runner observed any
   * integrity violation in the audit pipeline (e.g. events-file unlink,
   * inode swap, mtime regression, parent-directory rename, OR a
   * shim-channel JSONL line that failed to parse), or `null` if
   * everything looked clean.  Only meaningful after the async iterable
   * from `run()` has been fully consumed.
   *
   * Part of the contract — NOT a class-identity check — so wrappers,
   * decorators, and test fakes can opt into fail-closed semantics by
   * carrying a real tamper reason through `main()` without subclassing
   * `LinuxStraceRunner`.  Implementations that don't audit a shared events
   * file should return `null` unconditionally.
   *
   * Finding D (security-review): previously `main()` gated on
   * `straceRunner instanceof LinuxStraceRunner`, which silently skipped
   * the tamper check for any other implementation even when it had a
   * legitimate reason to fail closed.
   */
  getTamperReason(): string | null;

  /**
   * Record a tamper reason from outside the runner — typically from
   * {@link runInstallPhase} when a shim-channel JSONL line fails to parse
   * (malformed JSON, unknown `kind`, or schema-rejected payload).  The
   * runner stores this in the same `tamperRef.reason` slot that the
   * events-file watcher uses, so the agent's `main()` post-install gate
   * (which reads `getTamperReason()`) fails closed regardless of which
   * layer detected the violation.
   *
   * Implementations that don't have a tamper sink may no-op, but in
   * production this is the wire-up between the parse layer in phase-install
   * and the fail-closed gate in agent.main().  First-writer-wins:
   * subsequent calls with a reason already recorded should be ignored so
   * the earliest signal survives.
   */
  recordTamper(reason: string): void;

  /**
   * Returns the pid of the install command — i.e. strace's direct child,
   * the process the audited install command was exec'd into — or `null`
   * if the runner has not yet observed any pid (or strace failed to
   * spawn).
   *
   * Used by {@link runInstallPhase} to seed `pidCwd` for EXACTLY one pid:
   * the install root.  Pre-fix, the dispatcher seeded the cwd of the
   * first pid it observed — a forked child whose strace per-pid file
   * happened to be drained before the parent's would have been seeded
   * with `input.cwd`, silently certifying a wrong cwd.  Pinning the
   * seed to the runner-reported root pid eliminates that race.
   *
   * Implementations that cannot identify the root pid (e.g. a fake
   * runner that emits canned records) MAY return the first pid in
   * their record sequence, or `null` to opt out of seeding entirely.
   * The production `LinuxStraceRunner` records the pid of the first
   * per-pid strace output file it observes — strace writes the
   * install root's file strictly before any of its descendants', so
   * this is the install command's pid.
   */
  getRootPid(): number | null;
}

export interface PhaseInstallInput {
  manager: 'npm' | 'pnpm' | 'yarn';
  cwd: string;
  env: NodeJS.ProcessEnv;
  strace: StraceRunner;
  attribution: Attribution;
  emitter: Emitter;
  /**
   * Base path prefix for strace per-pid output files.
   * e.g. `/tmp/script-jail-strace/strace.out` → strace writes .out.<pid> files.
   */
  straceBasePath?: string;
  /**
   * Optional protected-paths matcher. When provided, fs events carrying an
   * `errno` are filtered: matches are stamped `hidden: true` and emitted,
   * unprotected ENOENTs are dropped, unprotected EACCES are emitted plainly.
   * When omitted, a no-op matcher is used (no patterns) so callers that
   * don't care about hidden-marking still get the existing drop-ENOENT
   * behaviour from the policy filter.
   */
  protectedPaths?: ProtectedPathsMatcher;
}

export interface PhaseInstallResult {
  exitCode: number;
  eventCount: number;
  /**
   * Human-readable tamper reason owned by `runInstallPhase` itself.  Set when
   * the install-phase dispatcher detects an integrity violation in the audit
   * pipeline that the runner-side `recordTamper()` may or may not have
   * surfaced (Finding 2 — runner contract allows no-op implementations).
   *
   * Currently populated by:
   *   - Shim-channel JSONL parse failures (malformed JSON, unknown `kind`,
   *     schema-rejected payload).  Same condition the dispatcher previously
   *     reported ONLY via `strace.recordTamper()`, which the StraceRunner
   *     contract allows to be a no-op.
   *   - Unknown / invalid `LineSource` discriminator values (Finding 1 —
   *     runtime-exhaustive dispatch; any non-'shim'/'strace' value is treated
   *     as an audit-pipeline contract breach).
   *
   * `null` when the install phase completed without observing tamper.  The
   * agent's `main()` post-install gate MUST treat any non-null value as fatal
   * — in addition to the existing `strace.getTamperReason()` check, which
   * covers events-file file-tamper signals (unlink/inode-swap/etc.).  The two
   * checks are defence-in-depth: each may catch tampering the other misses.
   */
  tamperReason: string | null;
}

const INSTALL_CMD: Record<'npm' | 'pnpm' | 'yarn', { cmd: string; args: string[] }> = {
  npm:  { cmd: 'npm',  args: ['rebuild', '--foreground-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['install', '--frozen-lockfile', '--offline', '--config.side-effects-cache=false'] },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--offline'] },
};

/**
 * Parse a JSONL line coming from the LD_PRELOAD shim, the env-spy preload, or
 * the dlopen-block preload. Returns a RawEvent or null if the line is
 * malformed/unrecognised.
 *
 * Expected shapes:
 *   env_read:    {"kind":"env_read","name":"...","pid":N,"ts":N,"hidden":bool}
 *   dlopen:      {"kind":"dlopen","filename":"...","result":"blocked","pid":N,"ts":N}
 *   exec:        {"kind":"exec","prog":"...","argv0":"...|null","envp_alloc_failed":bool,"pid":N,"ts":N}
 *   env_tamper:  {"kind":"env_tamper","op":"setenv|unsetenv|putenv|clearenv",
 *                 "name":"...","refused":true,"pid":N,"ts":N}
 *
 * exec/env_tamper validation goes through the zod schema (rather than the
 * hand-rolled shape checks env_read/dlopen still use) because both shapes
 * carry conditional fields (argv0 nullable; env_tamper name optional for
 * clearenv) that are easier to express declaratively. Existing env_read /
 * dlopen branches are left as-is to keep their tight error paths unchanged.
 */
export function parseShimLine(line: string): RawEvent | null {
  try {
    const obj = JSON.parse(line) as Record<string, unknown>;
    if (obj['kind'] === 'env_read') {
      const name = obj['name'];
      const pid = obj['pid'];
      const ts = obj['ts'];
      const hidden = obj['hidden'];
      if (
        typeof name === 'string' &&
        typeof pid === 'number' &&
        typeof ts === 'number' &&
        typeof hidden === 'boolean'
      ) {
        return { kind: 'env_read', name, pid, ts, hidden };
      }
    } else if (obj['kind'] === 'dlopen') {
      const filename = obj['filename'];
      const pid = obj['pid'];
      const ts = obj['ts'];
      if (
        typeof filename === 'string' &&
        typeof pid === 'number' &&
        typeof ts === 'number'
      ) {
        return { kind: 'dlopen', filename, result: 'blocked', pid, ts };
      }
    } else if (obj['kind'] === 'exec') {
      const parsed = ExecEvent.safeParse(obj);
      if (parsed.success) return parsed.data;
    } else if (obj['kind'] === 'env_tamper') {
      const parsed = EnvTamperEvent.safeParse(obj);
      if (parsed.success) return parsed.data;
    }
    return null;
  } catch {
    return null;
  }
}

export async function runInstallPhase(
  input: PhaseInstallInput,
): Promise<PhaseInstallResult> {
  const { cmd, args } = INSTALL_CMD[input.manager];
  const basePath = input.straceBasePath ?? '/tmp/script-jail-strace/strace.out';

  // No-op matcher when the caller didn't supply one. Its `isProtected()`
  // short-circuits to false, so ENOENT events get dropped exactly like the
  // pre-Task-16 strace-parser behaviour, while EACCES events still flow.
  const matcher = input.protectedPaths ?? new ProtectedPathsMatcher({
    patterns: [],
    roots: { repo: '', nodeModules: '', home: '', tmp: '', cache: '' },
  });

  let eventCount = 0;

  // Tamper reason owned by runInstallPhase itself (Finding 2).  The
  // StraceRunner.recordTamper() contract allows no-op implementations, so the
  // dispatcher must NOT delegate fail-closed decisions to optional runner side
  // state — it has to carry the signal through its own return value.  We keep
  // the runner-side recordTamper() call as defence-in-depth (so a runner that
  // does audit a shared events file still picks up the same reason), but the
  // canonical signal for `main()` is this local variable, exposed through
  // PhaseInstallResult.tamperReason.  First-writer-wins: once set, subsequent
  // failures don't overwrite the earliest reason.
  let phaseTamperReason: string | null = null;
  const setPhaseTamper = (reason: string): void => {
    if (phaseTamperReason === null) phaseTamperReason = reason;
    // Belt-and-braces: also surface through the runner contract for any
    // implementation that wants to consume it via getTamperReason().  No-op
    // runners (most tests, and any wrapper that didn't bother) simply drop
    // the reason on the floor — and that's exactly why we need our own owned
    // slot above.
    input.strace.recordTamper(reason);
  };

  const emit = (ev: AttributedEvent): void => {
    const filtered = applyProtectedPathsPolicy(ev, matcher);
    if (filtered === null) return;
    input.emitter.emitEvent(filtered);
    eventCount++;
  };

  // Audit-trust Finding 1 (2026-05-18): cross-check strace execve against
  // shim exec events to detect raw-syscall bypass.  The shim interposes
  // libc symbols only (execve, execv, execvp, execvpe, execveat, fexecve,
  // posix_spawn, posix_spawnp).  A native lifecycle script that issues
  // `syscall(SYS_execve, …)` directly bypasses every libc wrapper, so the
  // child runs WITHOUT our env envelope (no LD_PRELOAD re-injection, no
  // SCRIPT_JAIL_* re-injection); strace still observes the syscall, but
  // the shim emits no `exec` event because no libc wrapper was entered.
  //
  // Bookkeeping: per pid, count successful execve syscalls seen via strace
  // and successful libc-exec events seen via shim.  Any positive
  // `strace - shim` delta after the iterator drains is a bypass count for
  // that pid.  We emit one synthesised ExecEvent per excess strace execve
  // (with `syscall_bypass: true`) so normalize.ts can fold it into the
  // package's `audit_bypass` array via the existing pipeline — that array
  // is what `findAuditBypass` in src/action/diff.ts scans to hard-fail
  // the lockfile diff.
  //
  // Why per-pid counts (not pid-set membership): pid reuse across the
  // install is possible — a `pnpm install` that spawns many node children
  // can recycle pids after exit — and a single pid can legitimately exec
  // multiple times (sh / busybox / corepack chains).  We match counts so
  // each strace execve has a 1:1 corresponding shim exec event; anything
  // unmatched is a real bypass.
  //
  // We track the most recent strace observation (argv0/prog/ts) per pid so
  // the synthesised audit_bypass entry can carry useful forensic context
  // (the strace-observed argv[0] of the bypassed exec).  Strace can record
  // multiple execs for a pid; we keep a small ring of the trailing entries
  // so the audit_bypass list points at the right ones even if some were
  // matched by shim events out of order.
  interface StraceExecSample {
    argv0: string;
    prog: string;
    pid: number;
    ts: number;
    pkg: string;
    lifecycle: AttributedEvent['lifecycle'];
  }
  const straceExecsByPid = new Map<number, StraceExecSample[]>();
  const shimExecCountByPid = new Map<number, number>();

  // Audit-trust Finding A (high, 2026-05-18): events-file write forgery
  // detection.  A lifecycle script can read `SCRIPT_JAIL_LOG_FILE` from
  // /proc/self/environ, open the file in write mode, and append a forged
  // JSONL line (e.g. a fabricated `{"kind":"exec","result":"ok",…}` to
  // cancel out the post-loop cross-check against a paired raw `execve`
  // syscall bypass).  The trusted-channel parser then accepts the line
  // and the bypass detector goes silent.
  //
  // Trust model: the ONLY processes that should write to the events file
  // are processes that have loaded `/lib/libscriptjail.so` via the dynamic
  // linker (LD_PRELOAD).  Strace's `openat(AT_FDCWD, "/lib/libscriptjail.so",
  // O_RDONLY|O_CLOEXEC) = <fd>` line is the kernel-observed signal that
  // ld.so is mapping the shim into a new process — this is the SAME pid
  // that, microseconds later, the shim's `shim_init` runs in and opens
  // the events file for write.  We build the `shimLoadedPids` set from
  // these openat-read observations (parsed as `RawEvent.kind === 'read'`
  // with `path === SHIM_LIBRARY_PATH`) and treat any openat-write of the
  // events file from a pid NOT in the set as forgery.
  //
  // Why strace and not the file-sourced JSONL?  An attacker can ALSO
  // forge a `{"kind":"shim_init",...}` line, so a trust set built from
  // file-sourced events is also forgeable.  Strace's openat stream comes
  // from the kernel ptrace channel, not user-space writes, so it cannot
  // be lied about by a same-UID attacker.  This is defence-in-depth
  // against the canonical "raw-syscall exec with scrubbed envp" attack:
  // a child spawned that way never has ld.so map libscriptjail.so, so
  // it is never added to `shimLoadedPids`, so any forged write attempt
  // from that pid is caught.
  //
  // Caveat: an attacker inside an already-shim-loaded pid CAN still
  // write to the events file (their pid is trusted), and a same-uid
  // attacker that read SCRIPT_JAIL_LOG_FILE before any libc-exec ran
  // could in principle forge from such a pid.  That is a more advanced
  // attack and out of scope for this fix — the canonical, demonstrated
  // attack pattern (raw-syscall exec + scrubbed envp + forged JSONL)
  // is what we are closing.
  const SHIM_LIBRARY_PATH = '/lib/libscriptjail.so';
  const eventsFilePathRaw = input.env['SCRIPT_JAIL_LOG_FILE'];
  const eventsFilePath: string | null =
    typeof eventsFilePathRaw === 'string' && eventsFilePathRaw.length > 0
      ? eventsFilePathRaw
      : null;

  // Audit-trust Finding 2 (high, 2026-05-18): canonicalize the events-file
  // path ONCE at agent startup so an attacker can't defeat the equality
  // check with a path alias (`/tmp/..././script-jail-events-XXX/events.jsonl`
  // has the same realpath as the canonical form but does not string-equal it).
  //
  // We prefer `fs.realpathSync` because it resolves symlinks AND collapses
  // `.`/`..` segments — but realpath requires the file to exist.  At the
  // time `runInstallPhase` starts the file may already exist (the shim
  // opens it eagerly via shim_init in the agent), but to be safe we fall
  // back to `path.resolve` if realpath throws.  Subsequent realpath calls
  // on attacker-supplied paths are NOT performed — we resolve those with
  // `path.resolve` only.  Otherwise a malicious symlink (e.g.
  // `/tmp/innocent -> /tmp/.../events.jsonl` created by the attacker)
  // would canonicalize TO the events file and we'd flag the wrong
  // syscall.  The trust direction is: anchor on the realpath of our own
  // configured path; canonicalize attacker-supplied paths via
  // `path.resolve` only (which collapses redundant separators and `..`
  // but does NOT follow symlinks).
  const eventsFilePathCanonical: string | null = (() => {
    if (eventsFilePath === null) return null;
    try {
      return fs.realpathSync(eventsFilePath);
    } catch {
      // File doesn't exist yet (or stat permission error) — fall back to
      // a lexical canonicalization that still collapses `.`/`..` segments
      // so a process can't escape via `/tmp/..././events-dir/file.jsonl`.
      return path.resolve(eventsFilePath);
    }
  })();

  // Audit-trust Finding (high, 2026-05-19): basename of the canonical
  // events file, used as a Layer-1 safety net for the cwd-relative
  // openat-forgery attack.  Even when per-pid CWD tracking fails (Layer
  // 2 below — strace dropped the chdir line, fchdir resolved against an
  // unknown fd, etc.), a non-shim-loaded pid that opens ANY file whose
  // basename matches the events file is unambiguously a forgery
  // attempt: the basename is per-run-random (`events-<32-hex>.jsonl`,
  // see `createEventsFile` in `agent.ts`), unguessable by a package's
  // lifecycle script, and unique to this audit channel.  The earlier
  // generic `events.jsonl` basename caused false positives (a package
  // legitimately writing `./events.jsonl` to its own cwd matched the
  // safety net); per-run randomization closes that gap while
  // preserving the detector for actual forgery (an attacker who reads
  // SCRIPT_JAIL_LOG_FILE then chdir's into the events directory).
  const eventsFileBasename: string | null =
    eventsFilePathCanonical !== null
      ? path.basename(eventsFilePathCanonical)
      : null;

  // ===================================================================
  // Codex audit follow-up (high, 2026-05-19): CLONE_FS / CLONE_FILES
  // group modelling via union-find.
  //
  // The kernel's clone(2) flags determine whether the child shares
  // parent state or gets an independent copy:
  //   - CLONE_FS    → parent and child share `struct fs` (cwd, root,
  //                   umask).  A chdir(2) in either pid mutates the
  //                   OTHER pid's effective cwd, since both pids point
  //                   at the same kernel structure.
  //   - CLONE_FILES → parent and child share the file descriptor table.
  //                   A dup/close in either pid mutates the OTHER pid's
  //                   fd table.  (Threads created via pthread_create
  //                   ALWAYS share both, since glibc passes
  //                   CLONE_FS|CLONE_FILES|CLONE_VM.)
  //
  // Without modelling this sharing, copy-on-clone produces silently
  // wrong audits: a CLONE_FS-cloned pair where the CHILD chdir's
  // produces a parent whose effective cwd has ALSO moved, but our
  // pidCwd[parent] still points at the parent's pre-clone cwd.  A
  // subsequent `openat(AT_FDCWD, ".ssh/id_rsa", ...)` in the parent
  // then resolves against the WRONG cwd, slipping past the
  // protected-paths matcher.
  //
  // The fix: model cwd state and fd-table state as PER-GROUP rather
  // than per-pid, with the group represented by a union-find
  // structure.  On every read/write of `pidCwd`, `pidCwdUnknown`,
  // `dirfdTable`, and `dirfdStateUnknown`, we replace the pid key
  // with `findCwdRoot(pid)` / `findFdRoot(pid)` to resolve to the
  // group's canonical representative.  Clone propagation either
  // unions the parent/child into the same group (CLONE_FS /
  // CLONE_FILES set) or creates an independent copy for the child
  // (flag unset, the default for plain fork/clone).
  // ===================================================================

  // Union-find parent-pointer maps for cwd sharing groups and fd-table
  // sharing groups.  A pid not in the map is its own root (lazy init).
  // Path compression is applied during `find` to keep amortized lookup
  // near O(1).
  const cwdParent = new Map<number, number>();
  const fdParent = new Map<number, number>();

  // Codex follow-up (high, 2026-05-19; refined medium, 2026-05-19):
  // pending unshare-detach markers.  strace `-ff` writes per-pid files
  // separately; the production tailer drains them in arbitrary order,
  // so a child's `unshare(...)` line CAN be observed BEFORE the
  // parent's `clone(... CLONE_FS|CLONE_FILES ...) = <child>` line.  In
  // that order the immediate `detachCwdGroup` / `detachFdGroup` calls
  // in the unshare handler are no-ops (child is still a singleton
  // group at that point), and a naive clone reconciliation would
  // `unionCwd` / `unionFd` the kernel-detached child back INTO the
  // parent's group — wrong direction.
  //
  // Fix: when we observe `unshare(...)` we ALSO add the pid to a
  // pending-detach set; the clone reconciliation consults the set and
  // takes the COPY branch (parent → child snapshot) instead of the
  // UNION branch when the marker is present.  That matches the
  // kernel's `clone(... CLONE_FS|CLONE_FILES); unshare(...)` order:
  // the child first inherits the parent's state, then the kernel
  // detaches the child's fs_struct/files_struct into a private copy
  // whose initial value equals the shared state at unshare time.
  // After the copy, future mutations on either side stay private to
  // their own group (no shared mutation propagation).
  //
  // Markers persist across events (we don't track pid exits — stale
  // entries are harmless: the next clone wiring with the same pid
  // would honor an obsolete intent, but pids are recycled
  // monotonically and within a single install run reuse is rare; if
  // it happens, taking the copy branch is conservative).
  //
  // Codex follow-up (medium, 2026-05-19, bug #2): pending markers are
  // SNAPSHOTS of the child's state at unshare/close_range-UNSHARE/execve
  // time — NOT references that read child state at reconcile time.
  // Reading at reconcile time would conflate the child's pre-detach
  // state (visible to the parent under shared CLONE_FS/CLONE_FILES) with
  // its post-detach private mutations (which by definition the kernel
  // hid from the parent).  The reconciler uses the snapshot for parent-
  // taint decisions; the child's current state stays as-is unless
  // there's a snapshot-vs-parent conflict.
  //
  // Codex follow-up (medium, 2026-05-19, bug #3): close_range with
  // CLOSE_RANGE_UNSHARE and successful execve also detach the caller's
  // fd table from any shared CLONE_FILES group at kernel level.  When
  // the caller is a singleton at the moment the line is observed, the
  // immediate detach call is a no-op AND the action that follows
  // (close_range fd-close / execve CLOEXEC-sweep) only mutates the
  // caller's table — under-modeling the kernel's behavior when a
  // delayed parent clone(CLONE_FILES) line arrives later.  We capture
  // the "detach-time action" in the snapshot so the reconciler can
  // replay it onto the child's private group AFTER copying parent
  // state.  The parent's table stays intact (per real-kernel semantics:
  // unshare detaches the caller's struct only).
  interface CwdSnapshot {
    cwd: string | undefined;
    unknown: boolean;
  }
  // FdSnapshot's `entries` field captures the child's modeled fd table
  // (by fd suffix only — fd-group root is implicit) at the moment the
  // marker was FIRST set (the baseline parent-shared state under
  // CLONE_FILES).  `postDetachLog` is an ordered LIST that interleaves
  // detach actions and post-detach tombstones in their observed order;
  // the reconciler replays it in the same order onto the COPIED-from-
  // parent child group.  Detach action kinds:
  //   - 'none'           — plain unshare(CLONE_FILES).  No replay
  //                        action; the kernel only detached, didn't
  //                        otherwise mutate the table.
  //   - 'closeRange'     — close_range applied to caller AFTER the
  //                        kernel-level detach.  Replay: drop entries
  //                        in [first, last] (or mark cloexec if the
  //                        action carried CLOSE_RANGE_CLOEXEC).
  //   - 'execveCloexec'  — successful execve performed a CLOEXEC sweep
  //                        on the caller's private fd table.  Replay:
  //                        drop entries with cloexec=true.
  //
  // Codex follow-up (high, 2026-05-19, bug #1): pre-fix the singleton-
  // pending-fd-detach handlers stored ONE FdDetachAction in the Map
  // entry; a later detach call OVERWROTE the prior action.  Failure
  // mode: child close_range(UNSHARE) → then execve.  execve overwrote
  // the close_range action; reconciliation replayed only the CLOEXEC
  // sweep and the closed fds came back.  Fix: ordered list, append on
  // every detach call (push, don't overwrite), replay in order.  The
  // `entries` baseline stays from the FIRST detach (parent-state-at-
  // first-detach is the right basis for parent-taint).
  //
  // Codex follow-up (high, 2026-05-19, bug #1 final): post-detach
  // tombstones are now ALSO appended to the same ordered log so an
  // interleaved sequence (tombstone, action, tombstone, action, ...)
  // replays in the OBSERVED order.  Pre-fix used a separate
  // `postDetachTombstones[]` list that was replayed AFTER every
  // action, so a CLOEXEC tombstone observed BEFORE a subsequent
  // execveCloexec action ended up applied AFTER the sweep (stale entry
  // survived).
  //
  // Codex follow-up (high, 2026-05-19, bug #2): `tombstones` records
  // fd-specific mutations done on UNTRACKED fds during the singleton
  // pre-detach window.  When the operation targets an fd NOT in
  // `dirfdTable`, the prior fast-path just no-op'd — but in delayed-
  // clone order an absent child entry can mean "inherited from parent
  // who's not yet reconciled".  The child's close / SETFD-CLOEXEC
  // legitimately mutated the shared kernel state; the reconciler must
  // replay the mutation after copying parent's fds into the child
  // group.  Each tombstone is keyed by raw fd number; replay semantics
  // depend on `kind`:
  //   - 'close'   — kernel closed the shared fd.  Drop the entry in
  //                 the child's copied table AND drop the parent's
  //                 matching entry (the shared mutation propagated
  //                 to the parent under CLONE_FILES); mark both
  //                 groups fd-unknown for that fd region.
  //   - 'cloexec' — kernel set FD_CLOEXEC on the shared fd.  Mark the
  //                 child's copied entry cloexec=true so the
  //                 subsequent execveCloexec action in the list (if
  //                 any) sweeps it.
  // Codex follow-up (high, 2026-05-19, bug #4 — execveCloexec
  // generation-aware sweep): `execveCloexec` carries a per-action
  // EXCLUSION set of fds opened AFTER this specific exec (and before
  // any subsequent exec).  Replay sweeps every cloexec entry in the
  // child copy EXCEPT those in this set.  Pre-fix the replay swept
  // every cloexec entry, which incorrectly clobbered fds the child
  // opened with O_CLOEXEC AFTER this exec but BEFORE the delayed
  // clone — the kernel wouldn't close those until the NEXT exec.
  //
  // Why exclusion (option b) instead of an inclusion snapshot
  // (option a): at child-singleton-exec time, the child's group is
  // empty in our model (the parent's clone(CLONE_FILES) line hasn't
  // arrived yet, so we haven't unioned parent fds in).  A snapshot
  // of cloexec fds in the child's group at exec time would be
  // empty even though the kernel's actual files_struct (shared with
  // the parent pre-unshare) contained parent-installed cloexec fds.
  // Reconciliation copies parent fds into the child AFTER this
  // snapshot would have been taken — so the snapshot misses them.
  // Exclusion sweeps after the copy and correctly drops the parent-
  // copied cloexec fds while sparing post-exec child reopens.
  type FdDetachAction =
    | { kind: 'none' }
    | { kind: 'closeRange'; first: number; last: number; cloexec: boolean }
    | { kind: 'execveCloexec'; excludeFds: Set<string> };
  // Codex follow-up (high, 2026-05-19, bug #1 + #2 follow-ups):
  // tombstones now carry an optional RANGE so close_range mutations on
  // untracked fds (the singleton-pre-detach case) can be replayed at
  // delayed-clone reconciliation without enumerating every fd in
  // [first, last] (UINT_MAX-fd loops would blow up).  Point tombstones
  // (single `fd`) retain prior semantics.
  type FdTombstone =
    | { kind: 'close'; fd: number }
    | { kind: 'cloexec'; fd: number }
    | { kind: 'closeRange'; first: number; last: number; cloexec: boolean };
  // Codex follow-up (medium, 2026-05-19, bug #3 follow-up): split
  // tombstones into PRE-detach and POST-detach buckets.  Pre-detach
  // tombstones were recorded BEFORE any detach action queued onto
  // `postDetachLog[]`; under shared CLONE_FILES the kernel mutation hit
  // the SHARED files_struct and propagated to the parent, so the
  // reconciler must flip BOTH parent and child copy.  Post-detach
  // tombstones were recorded AFTER at least one detach action was
  // queued; the kernel had already unshared (or was about to via
  // execve) so the mutation is private and only the child copy
  // reflects it.
  //
  // Codex follow-up (high, 2026-05-19, bug #1 final): the prior
  // bookkeeping kept post-detach tombstones in a SEPARATE list from
  // `actions` and replayed them in two phases — actions first, then
  // tombstones.  That order was wrong: a CLOEXEC tombstone observed
  // BEFORE a subsequent execveCloexec action must apply first (mark
  // fd cloexec) so the sweep can drop the entry.  Two-phase replay
  // applied the CLOEXEC mark POST-sweep, leaving the entry intact.
  // Fix: interleave actions and post-detach tombstones into a SINGLE
  // ordered log; the reconciler walks it in observed order.  Pre-
  // detach tombstones still live in `preDetachTombstones[]` and apply
  // BEFORE the log replay (with shared-kernel propagation to parent
  // under shared CLONE_FILES).
  type FdLogEntry =
    | { kind: 'action'; action: FdDetachAction }
    | { kind: 'tombstone'; tombstone: FdTombstone };
  interface FdSnapshot {
    entries: Array<[string /* fd suffix */, { path: string; cloexec: boolean }]>;
    unknown: boolean;
    // Ordered interleaved log of detach actions and post-detach
    // tombstones.  Always begins with at least one action (snapshotFd
    // seeds the first action; appendFdAction pushes subsequent ones).
    postDetachLog: FdLogEntry[];
    preDetachTombstones: FdTombstone[];
    // Codex pass 47 follow-up (high, 2026-05-19, bug #1 — pre-detach
    // opaque reuse not replayed against the parent).  The set of fd
    // NUMBERS for which the child's PRE-marker activity recorded an
    // opaque-reuse marker on the SHARED fd group.  Frozen at marker
    // creation by `snapshotFd` from `opaqueFdReuses[<currentRoot>]`,
    // then absorbed at delayed-clone reconciliation: under shared
    // CLONE_FILES the kernel-shared files_struct was opaque'd at
    // those fds BEFORE the marker, so the parent's same-numbered
    // entries must be DROPPED (their model state is stale; the
    // kernel slot was rewritten by an opaque source).
    //
    // Distinction vs `opaqueFdReuses` post-marker:
    //   - preDetachOpaque (this set): pre-marker opaque reuses.
    //     Kernel-shared state was opaque at marker time → drop
    //     parent's fd-N entry at reconciliation.
    //   - opaqueFdReuses[currentRoot] (post-marker): only the
    //     CHILD's private fd was opaque'd.  Reconciliation just
    //     skips parent→child copy (already handled today by the
    //     copy branch + unionFd opaque-set merge).
    preDetachOpaque: Set<number>;
  }
  const pendingCwdDetach = new Map<number, CwdSnapshot>();
  const pendingFdDetach = new Map<number, FdSnapshot>();
  // Codex follow-up (high, 2026-05-19, bug #2): pre-marker tombstones.
  // close()/fcntl(F_SETFD,FD_CLOEXEC)/close_range called on UNTRACKED
  // inherited fds BEFORE the singleton pid has any pending-fd-detach
  // marker.  When a marker is eventually created (snapshotFd), it
  // absorbs the entries from this list into `preDetachTombstones`.  No
  // pending-marker, no detach: in that case we leave the dirfdTable
  // delete (close) already-applied as the only effect, and the bucket
  // is discarded at marker creation.
  const pendingFdTombstones = new Map<number, FdTombstone[]>();
  // Codex follow-up (high, 2026-05-19, bug #3 — post-marker fd reuse
  // exclusion): once a singleton pid has a pending-fd-detach marker
  // (i.e., the kernel already unshared/execed and we're waiting for
  // the delayed parent clone(CLONE_FILES) line), the child can
  // legitimately REOPEN an fd whose pre-detach state had a `close` /
  // `cloexec` / `closeRange` tombstone in `preDetachTombstones[]`.
  // The pre-detach tombstone correctly applies to the PARENT (shared-
  // files_struct kernel mutation propagated to the parent's view),
  // but for the CHILD copy the post-marker reopen installed a fresh
  // private fd that the kernel did NOT close — the tombstone must
  // NOT apply to that fd on the child side.
  //
  // Codex follow-up (high, 2026-05-19, bug #5 — post-marker
  // close-of-reuse): a post-marker reuse fd can also be CLOSED
  // post-marker.  The dirfdTable.delete in the close handler drops
  // the child's freshly-reopened entry — but the reconciler's copy-
  // pass sees `existing === undefined` for that child key and copies
  // the parent's stale shared-baseline entry back in, resurrecting
  // a path the kernel has confirmed closed.  Lifecycle the per-pid
  // entry as a state machine instead of a flat Set:
  //
  //   - 'open'   — fd is currently a known post-marker reuse; the
  //                child copy holds a private mapping the
  //                reconciler must preserve (skip parent copy on
  //                conflict, skip tombstone replay).
  //   - 'closed' — fd was a post-marker reuse but the child later
  //                closed it post-marker; the kernel-known state is
  //                "closed" in the child's private group.  The
  //                reconciler must NOT copy the parent's stale
  //                shared-baseline entry into the child copy (would
  //                resurrect a closed fd) AND must skip tombstone
  //                replay (the child already knows it's closed; the
  //                pre-detach tombstone would just over-taint the
  //                child group).
  //
  // Transitions: post-marker open/dup/F_DUPFD → 'open'.  Post-marker
  // close of a fd in 'open' → 'closed'.  Post-marker reopen of a fd
  // in 'closed' → back to 'open'.  Post-marker close_range covering
  // a fd in 'open' → 'closed' for that fd (range-walks the per-pid
  // map; unknown fds in the range are handled by the existing
  // post-detach range tombstone logic).
  //
  // Codex pass 50 follow-up (high, 2026-05-19): keyed by FD-GROUP
  // ROOT (via `rootedFd(pid)`), NOT by the mutating pid.  Pre-fix
  // the map was per-pid, which silently dropped post-marker reuses
  // performed by CLONE_FILES siblings of the marker owner.  Concrete
  // breakage: P opens fd 7=/safe; C does unshare(CLONE_FILES) →
  // marker created on C; C does clone(CLONE_FILES)=G → G joins C's
  // post-detach private fd group via `unionFd(C, G)`; G does
  // openat(AT_FDCWD, "/known", ...)=7 — this is a post-marker reuse
  // of fd 7 in C's group, but `pendingFdDetach.get(G)` is undefined
  // pre-fix, so the lifecycle entry was never recorded.  Then the
  // delayed `P clone(CLONE_FILES)=C` line surfaces; reconciliation
  // reads `postMarkerFdReuses.get(C)` and finds nothing, so the
  // copy-pass treats G's fd 7=/known as an ordinary conflict (drops
  // the child entry) instead of preserving the post-marker private
  // reopen.  G's subsequent `openat(7, "file", …)` resolves to
  // `<UNRESOLVED_PATH>`.
  //
  // Marker-owner invariant: a marker is created right after
  // `detachFdGroup(pid)`, so the owner is always its own root at
  // marker-creation time AND remains its own root for the marker's
  // lifetime (`unionFd(other, owner)` is gated on absence of a
  // pending marker; `unionFd(owner, child)` keeps owner as the
  // parent's root).  Consequently `postMarkerFdReuses[root]` is
  // exactly the lifecycle the reconciliation needs, and `root ===
  // ownerPid` whenever an entry exists.
  const postMarkerFdReuses = new Map<number, Map<number, 'open' | 'closed'>>();
  function recordPostMarkerFdReuse(pid: number, fd: number): void {
    // Only track when a marker is actively pending on the FD-GROUP's
    // marker owner — otherwise there's no future reconciliation
    // that needs the exclusion.  The marker owner is the fd-group
    // root by invariant (see comment block above).
    const root = rootedFd(pid);
    const snap = pendingFdDetach.get(root);
    if (snap === undefined) return;
    let lifecycle = postMarkerFdReuses.get(root);
    if (lifecycle === undefined) {
      lifecycle = new Map();
      postMarkerFdReuses.set(root, lifecycle);
    }
    // Transition: 'open' or absent → 'open'; 'closed' → 'open' (reopen
    // cancels the earlier post-marker close).
    lifecycle.set(fd, 'open');
    // Codex follow-up (high, 2026-05-19, bug #4 — generation-aware
    // execveCloexec): add `fd` to the exclude set of every
    // execveCloexec action ALREADY in this marker's postDetachLog.
    // The kernel sweeps cloexec only at exec-time; a post-marker
    // reopen happens AFTER any execve actions already queued, so
    // those execs did NOT see `fd` and the replay must not sweep it.
    // FUTURE execveCloexec appends start with an empty exclude set
    // (their kernel sweep DOES include this fd because the open
    // happened BEFORE that future exec).
    const fdSuffix = String(fd);
    for (const entry of snap.postDetachLog) {
      if (entry.kind === 'action' && entry.action.kind === 'execveCloexec') {
        entry.action.excludeFds.add(fdSuffix);
      }
    }
  }
  // Codex follow-up (high, 2026-05-19, bug #5 — post-marker close of
  // a reused fd): transition the lifecycle entry for `fd` from
  // 'open' → 'closed'.  Only meaningful when a marker is pending on
  // the fd-group's marker owner AND `fd` was previously recorded as
  // an 'open' reuse — otherwise no entry exists / the close is
  // governed by the existing pre-marker / post-marker untracked-fd
  // tombstone paths.  Keyed by fd-group root (pass 50 follow-up) so
  // CLONE_FILES siblings of the marker owner update the SAME
  // lifecycle map the reconciler consumes.
  function recordPostMarkerFdClose(pid: number, fd: number): void {
    const root = rootedFd(pid);
    if (pendingFdDetach.get(root) === undefined) return;
    const lifecycle = postMarkerFdReuses.get(root);
    if (lifecycle === undefined) return;
    if (lifecycle.get(fd) === 'open') {
      lifecycle.set(fd, 'closed');
    }
  }

  // ===================================================================
  // Codex adversarial pass 46 (high, 2026-05-19, bug #7 — marker-less
  // opaque-fd reuse).  Companion to `postMarkerFdReuses` / bug #6.
  //
  // Failure pattern pre-fix:
  //   1. parent P opens /safe → fd 7
  //   2. child C is created via clone(CLONE_FILES) — DELAYED in strace
  //      output (parent's clone line not yet observed by the dispatcher).
  //   3. child C does openat(99, "dir", O_DIRECTORY) = 7 with fd 99
  //      untracked, so canonicalize returns null.  C did NOT do an
  //      unshare beforehand → `pendingFdDetach` has no marker for C →
  //      `recordPostMarkerFdReuse` short-circuits → NO bookkeeping is
  //      recorded for the kernel-installed fresh fd 7.
  //   4. parent's clone(CLONE_FILES) line surfaces; reconciliation
  //      unions C into P's group.  `unionFd` only inspects parent vs
  //      child dirfdTable entries (and C has none for fd 7 — canonicalize
  //      returned null), so parent's stale fd 7 → /safe survives.
  //   5. child C does openat(7, ".ssh/id_rsa", O_RDONLY) — resolved
  //      against the leaked /safe path.  Same trust-boundary failure
  //      as bug #6 but the marker-less path.
  //
  // Why a per-fd opaque-reuse marker (not `fdUnknownAdd`):
  // `fdUnknownAdd(pid)` taints the WHOLE pid's fd group and breaks
  // legitimate later resolutions through unrelated tracked fds (a
  // singleton pid that did one opaque open would lose access to every
  // other valid fd it has).  Per-fd granularity is the precise signal
  // the reconciler needs.
  //
  // Lifecycle:
  //   - `recordOpaqueFdReuse` is unconditional (does NOT gate on a
  //     pending marker).  It's the marker-less safety net.
  //   - `recordPostMarkerFdReuse` (above) is the marker-aware
  //     optimisation that ALSO records the lifecycle state for the
  //     marker's reconciliation pass.  Both helpers are called at every
  //     post-marker reuse site; they're complementary, not exclusive.
  //   - Cleared on: legitimate close, close_range covering the fd,
  //     successful canonicalized open at the same fd number (a fresh
  //     tracked mapping supersedes the opaque marker).
  //   - NOT auto-cleared on execve: we couldn't canonicalize the open,
  //     so we don't know whether the fd had O_CLOEXEC.  Conservative:
  //     keep the marker until an explicit close.
  //
  // Union-find migration: the map is keyed by fd-group root via
  // `rootedFd(pid)`.  `unionFd` MUST merge the two groups' opaque sets
  // into the parent's root and `detachFdGroup` MUST migrate the opaque
  // set to the new root.  See the corresponding sites for the inline
  // wiring.
  // ===================================================================
  const opaqueFdReuses = new Map<number, Set<number>>();
  function recordOpaqueFdReuse(pid: number, fd: number): void {
    const root = rootedFd(pid);
    let set = opaqueFdReuses.get(root);
    if (set === undefined) {
      set = new Set();
      opaqueFdReuses.set(root, set);
    }
    set.add(fd);
  }
  function clearOpaqueFdReuse(pid: number, fd: number): void {
    const root = rootedFd(pid);
    const set = opaqueFdReuses.get(root);
    if (set === undefined) return;
    set.delete(fd);
    if (set.size === 0) opaqueFdReuses.delete(root);
  }
  function clearOpaqueFdRange(pid: number, first: number, last: number): void {
    const root = rootedFd(pid);
    const set = opaqueFdReuses.get(root);
    if (set === undefined) return;
    for (const fd of [...set]) {
      if (fd >= first && fd <= last) set.delete(fd);
    }
    if (set.size === 0) opaqueFdReuses.delete(root);
  }
  // Codex follow-up (high, 2026-05-19, bug #5 — post-marker
  // close_range over a range that may include reused fds): walk the
  // fd-group lifecycle map and transition every fd in [first, last]
  // currently in 'open' → 'closed'.  Range covers reused fds only;
  // unknown fds in the range are still tracked by the existing
  // post-detach range tombstone logic on `postDetachLog`.  Keyed by
  // fd-group root (pass 50 follow-up).
  function recordPostMarkerFdRangeClose(pid: number, first: number, last: number): void {
    const root = rootedFd(pid);
    if (pendingFdDetach.get(root) === undefined) return;
    const lifecycle = postMarkerFdReuses.get(root);
    if (lifecycle === undefined) return;
    for (const [fd, state] of lifecycle) {
      if (fd >= first && fd <= last && state === 'open') {
        lifecycle.set(fd, 'closed');
      }
    }
  }
  function recordFdTombstone(pid: number, tomb: FdTombstone): void {
    // Codex follow-up (high, 2026-05-19, pass 52 — CLONE_FILES sibling
    // tombstones miss root-owned marker): resolve the fd-group ROOT
    // FIRST.  After C owns a pending fd-detach marker and C `clone(
    // CLONE_FILES) = G` is observed, G is non-singleton and
    // `rootedFd(G) === C`.  G's pre-fix tombstones (close on an
    // inherited fd that hasn't yet been copied into C/G because P→C
    // reconciliation hasn't surfaced, F_SETFD CLOEXEC on the same, or
    // a no-UNSHARE close_range covering one) must append to C's marker
    // log so the delayed-clone reconciliation replays them against the
    // parent-copied entries.  Pre-fix the early `isFdSingleton(pid)`
    // gate returned before the lookup, so G's tombstones were dropped
    // and the reconciler later resurrected stale parent entries / missed
    // CLOEXEC sweeps via the copy pass.
    const root = rootedFd(pid);
    const rootSnap = pendingFdDetach.get(root);
    if (rootSnap !== undefined) {
      // Marker already exists on the fd-group root (which may equal
      // pid OR be the marker-owning sibling).  Tombstone is POST-detach
      // relative to that marker; push into the interleaved postDetachLog
      // so the reconciler replays it in observed order regardless of
      // whether pid is itself a singleton.  This is the critical case
      // for CLONE_FILES sibling visibility: G's mutation under shared
      // fd-table propagates to C's view at kernel level, and the
      // marker replay must see the tombstone before delayed-clone
      // parent-copy.
      rootSnap.postDetachLog.push({ kind: 'tombstone', tombstone: tomb });
      return;
    }
    // No root marker → fall back to pre-marker bucket behaviour, which
    // is singleton-scoped.  Pre-marker buckets are pid-keyed and only
    // make sense for the singleton-window: a non-singleton pid's
    // mutations already hit the shared dirfdTable directly via the
    // standard close/close_range/fcntl handlers, so there is no replay
    // needed.
    if (!isFdSingleton(pid)) return;
    // No marker yet → tombstone is PRE-detach.  Queue in the bucket;
    // `snapshotFd` will absorb the bucket into preDetachTombstones.
    let bucket = pendingFdTombstones.get(pid);
    if (bucket === undefined) {
      bucket = [];
      pendingFdTombstones.set(pid, bucket);
    }
    bucket.push(tomb);
  }
  // Fold any pre-marker tombstones into a fresh marker's preDetach
  // bucket so the reconciler sees them through the marker's
  // `preDetachTombstones` field.
  function absorbPendingTombstones(pid: number, snap: FdSnapshot): void {
    const bucket = pendingFdTombstones.get(pid);
    if (bucket === undefined) return;
    for (const tomb of bucket) snap.preDetachTombstones.push(tomb);
    pendingFdTombstones.delete(pid);
  }
  // Codex follow-up (medium, 2026-05-19, bug #2 — stale-tombstone-on-
  // reopen): cancel any PENDING fd tombstones / range-close actions for
  // `pid` whose target fd matches `newFd`.  Strace ordering can surface
  // a close/cloexec/close_range BEFORE a subsequent open/dup/F_DUPFD
  // that reuses the same fd number — without cancellation, the
  // delayed-clone reconciler would replay the stale tombstone AFTER
  // the unified group has the freshly-reopened mapping, deleting the
  // valid entry on BOTH sides.
  //
  // Two storage locations are visited:
  //
  //   1. The PRE-marker bucket (`pendingFdTombstones`) — point and
  //      range tombstones recorded before any detach marker exists.
  //      Keyed by RAW pid: pre-marker buckets are pid-scoped before
  //      any sharing / detach occurs.
  //   2. The POST-marker interleaved log on an existing fd-detach
  //      marker (`pendingFdDetach[rootedFd(pid)].postDetachLog`) —
  //      once a marker is created, subsequent close/cloexec/
  //      close_range observations queue here.  Stale entries in
  //      this log must ALSO be excised on reopen; otherwise the
  //      marker's reconcile replay re-drops `newFd` from the
  //      child's private copy.  Keyed by FD-GROUP ROOT (pass 51
  //      follow-up): after the pass 50 rekeying, the marker is
  //      stored at the marker owner == fd-group root.  When a
  //      CLONE_FILES sibling G of the marker owner C reopens an
  //      fd, `rootedFd(G) === C`, so the lookup must resolve via
  //      the root to find C's marker — keying by the raw sibling
  //      pid would miss the cancellation and the reconciler would
  //      later replay a stale closeRange that drops G's fresh fd.
  //
  // For point tombstones (`close` / `cloexec`) targeting `newFd` we
  // simply drop them.  For range tombstones (`closeRange`) covering
  // `newFd` — whether stored as a `tombstone` log entry, an `action`
  // log entry, or in the pre-marker bucket — we surgically excise
  // `newFd` from the range, splitting into [first, newFd-1] and
  // [newFd+1, last] when the range had more than one entry.  Empty
  // / inverted sub-ranges are pruned.
  //
  // `action: execveCloexec` log entries are left alone: they sweep
  // only entries already marked cloexec=true.  The freshly-opened
  // `newFd` was installed without O_CLOEXEC (and any prior cloexec
  // tombstone on `newFd` is excised above before the sweep can
  // observe it), so execveCloexec never touches it.
  //
  // The snapshot's `preDetachTombstones[]` is intentionally NOT
  // touched: those describe mutations against the parent-shared
  // baseline observed BEFORE the marker existed, frozen at marker
  // time, and reflect already-propagated shared-kernel state.  The
  // marker's `entries` baseline is similarly left alone (parent-
  // state-at-first-detach, different semantics).
  function cancelTombstonesInBucket(bucket: FdTombstone[], newFd: number): FdTombstone[] {
    const next: FdTombstone[] = [];
    for (const tomb of bucket) {
      if (tomb.kind === 'close' || tomb.kind === 'cloexec') {
        if (tomb.fd === newFd) continue;
        next.push(tomb);
      } else {
        // closeRange — split around newFd if it falls inside.
        if (newFd < tomb.first || newFd > tomb.last) {
          next.push(tomb);
          continue;
        }
        if (tomb.first <= newFd - 1) {
          next.push({
            kind: 'closeRange',
            first: tomb.first,
            last: newFd - 1,
            cloexec: tomb.cloexec,
          });
        }
        if (newFd + 1 <= tomb.last) {
          next.push({
            kind: 'closeRange',
            first: newFd + 1,
            last: tomb.last,
            cloexec: tomb.cloexec,
          });
        }
      }
    }
    return next;
  }
  function cancelPendingTombstonesForFd(pid: number, newFd: number): void {
    // 1. PRE-marker bucket — keyed by raw pid (pre-marker buckets
    //    are pid-scoped before any detach / fd-group sharing).
    const bucket = pendingFdTombstones.get(pid);
    if (bucket !== undefined) {
      const next = cancelTombstonesInBucket(bucket, newFd);
      if (next.length === 0) pendingFdTombstones.delete(pid);
      else pendingFdTombstones.set(pid, next);
    }
    // 2. POST-marker interleaved log on the active fd-detach marker.
    //    Walk in observed order; rewrite each entry whose target fd
    //    matches `newFd`.  `tombstone` entries follow the same drop /
    //    split rules as the pre-marker bucket.  `action` entries of
    //    kind `closeRange` undergo the same range surgery (and are
    //    dropped if both sub-ranges are empty — the close_range had
    //    no surviving fds to act on).  Other action kinds (`none`,
    //    `execveCloexec`) don't reference fd numbers and are passed
    //    through unchanged.
    //
    //    Codex pass 51 follow-up (high, 2026-05-19): resolve via the
    //    fd-group root.  After pass 50 the marker is stored at the
    //    marker owner == rootedFd(owner), and CLONE_FILES siblings
    //    of the owner satisfy `rootedFd(sibling) === owner`.  Keying
    //    this lookup by the raw `pid` would miss the marker for a
    //    sibling reopen, leaving any stale closeRange action / range
    //    tombstone unsplit; the delayed-clone reconciler would then
    //    replay the closeRange against the child copy and drop the
    //    sibling's fresh post-marker fd.
    const root = rootedFd(pid);
    const snap = pendingFdDetach.get(root);
    if (snap === undefined) return;
    const nextLog: FdLogEntry[] = [];
    for (const entry of snap.postDetachLog) {
      if (entry.kind === 'tombstone') {
        const filtered = cancelTombstonesInBucket([entry.tombstone], newFd);
        for (const tomb of filtered) {
          nextLog.push({ kind: 'tombstone', tombstone: tomb });
        }
        continue;
      }
      // entry.kind === 'action'
      const action = entry.action;
      if (action.kind === 'closeRange') {
        if (newFd < action.first || newFd > action.last) {
          nextLog.push(entry);
          continue;
        }
        if (action.first <= newFd - 1) {
          nextLog.push({
            kind: 'action',
            action: {
              kind: 'closeRange',
              first: action.first,
              last: newFd - 1,
              cloexec: action.cloexec,
            },
          });
        }
        if (newFd + 1 <= action.last) {
          nextLog.push({
            kind: 'action',
            action: {
              kind: 'closeRange',
              first: newFd + 1,
              last: action.last,
              cloexec: action.cloexec,
            },
          });
        }
        // If both sub-ranges collapsed (single-fd close_range == newFd
        // only) the action is fully cancelled — drop it.
        continue;
      }
      // Other actions (`none`, `execveCloexec`) don't reference fd
      // numbers from a TOMBSTONE-cancellation perspective.  The
      // `execveCloexec` action's exclude-set is mutated by
      // `recordPostMarkerFdReuse` directly (called alongside this
      // helper at each reopen site).
      nextLog.push(entry);
    }
    snap.postDetachLog = nextLog;
  }

  // Helper: snapshot the child's CURRENT cwd state for a pending marker.
  function snapshotCwd(pid: number): CwdSnapshot {
    return { cwd: cwdGet(pid), unknown: cwdUnknownHas(pid) };
  }
  // Helper: snapshot the child's CURRENT fd-table state + the detach-
  // time replay action.  The returned snapshot's `postDetachLog`
  // contains a SINGLE entry — the caller-provided action — and empty
  // pre-detach tombstones.  Subsequent detach calls on the same pid
  // APPEND to `postDetachLog` via `appendFdAction` (and any post-
  // detach tombstones recorded between actions also append via
  // `recordFdTombstone`) rather than calling `snapshotFd` again — the
  // `entries` baseline must stay frozen at the first-detach moment so
  // the reconciler's parent-taint pass measures against the parent-
  // shared state that existed at first detach, not at the last one.
  function snapshotFd(pid: number, action: FdDetachAction): FdSnapshot {
    const root = rootedFd(pid);
    const prefix = `${root}:`;
    const entries: Array<[string, { path: string; cloexec: boolean }]> = [];
    for (const [key, val] of dirfdTable) {
      if (key.startsWith(prefix)) {
        entries.push([key.slice(prefix.length), val]);
      }
    }
    // Codex pass 47 follow-up (high, 2026-05-19, bug #1 — pre-detach
    // opaque reuse not replayed against the parent): freeze the
    // CURRENT opaque-reuse set into the snapshot.  Anything recorded
    // BEFORE the marker reflects mutations on the (then) kernel-
    // shared fd table, so the parent's same-numbered entries must
    // be dropped at delayed-clone reconciliation under shared
    // CLONE_FILES.  Cloned (not shared) so the live
    // `opaqueFdReuses[root]` set is unaffected by future
    // post-marker mutations; reconciliation uses the snapshot for
    // pre-detach semantics and the live set for post-marker
    // semantics.
    const liveOpaque = opaqueFdReuses.get(root);
    const preDetachOpaque =
      liveOpaque === undefined ? new Set<number>() : new Set<number>(liveOpaque);
    const snap: FdSnapshot = {
      entries,
      unknown: dirfdStateUnknown.has(root),
      postDetachLog: [{ kind: 'action', action }],
      preDetachTombstones: [],
      preDetachOpaque,
    };
    absorbPendingTombstones(pid, snap);
    return snap;
  }
  // Helper: extend an existing pending-fd-detach marker with a new
  // action without disturbing its `entries`/`unknown` baseline.  Used
  // by the close_range UNSHARE and execve handlers when the pid
  // ALREADY has a pending marker — appending preserves ordering for
  // replay (close_range BEFORE execve, etc.).  Returns the snapshot
  // we extended, or `null` if none exists for `pid`.  Also absorbs
  // any pre-marker tombstones recorded since the prior detach.
  function appendFdAction(pid: number, action: FdDetachAction): FdSnapshot | null {
    const snap = pendingFdDetach.get(pid);
    if (snap === undefined) return null;
    snap.postDetachLog.push({ kind: 'action', action });
    absorbPendingTombstones(pid, snap);
    return snap;
  }
  // Helper: is `pid` currently the sole member of its fd group?  Used
  // by close_range/execve to gate the pending-marker recording — when
  // pid is already in a multi-member group, the immediate
  // `detachFdGroup` call really does detach (the parent's clone has
  // already been processed) and no delayed reconciliation is needed.
  function isFdSingleton(pid: number): boolean {
    const root = rootedFd(pid);
    if (root !== pid) return false;
    for (const memberPid of fdParent.keys()) {
      if (memberPid === pid) continue;
      if (findFdRoot(memberPid) === pid) return false;
    }
    return true;
  }

  function findCwdRoot(pid: number): number {
    let cur = pid;
    while (true) {
      const next = cwdParent.get(cur);
      if (next === undefined || next === cur) return cur;
      cur = next;
    }
  }
  function findFdRoot(pid: number): number {
    let cur = pid;
    while (true) {
      const next = fdParent.get(cur);
      if (next === undefined || next === cur) return cur;
      cur = next;
    }
  }
  // Path compression: set `pid`'s parent pointer to the resolved root.
  function compressCwd(pid: number, root: number): void {
    if (pid !== root) cwdParent.set(pid, root);
  }
  function compressFd(pid: number, root: number): void {
    if (pid !== root) fdParent.set(pid, root);
  }
  function rootedCwd(pid: number): number {
    const r = findCwdRoot(pid);
    compressCwd(pid, r);
    return r;
  }
  function rootedFd(pid: number): number {
    const r = findFdRoot(pid);
    compressFd(pid, r);
    return r;
  }
  // Union two pids into the same group.  We always union the CHILD's
  // root onto the PARENT's root so the parent's group remains the
  // canonical representative.
  //
  // Codex follow-up (bug #2, high, 2026-05-19): the original
  // implementations only re-pointed the parent-pointer map.  Per-key
  // state already accumulated under the CHILD's pre-union root was
  // silently orphaned — any pidCwd / pidCwdUnknown / dirfdTable /
  // dirfdStateUnknown entries keyed on the child's old root became
  // unreachable after the union, because every accessor now resolves
  // both pids to the parent's root.
  //
  // Why this matters: strace per-pid files are drained out of order by
  // the production tailer (readdirSync + fs.watch is FS-dependent).  A
  // child can emit `chdir("/root")` BEFORE the parent's
  // `clone(..., CLONE_FS, ...)` line is observed.  Pre-fix we'd:
  //   1. set pidCwd[<child-old-root>] = "/root"
  //   2. later observe the clone, run `cwdParent[<child-old-root>] =
  //      <parent-root>` — the cwd entry under the old key is now
  //      orphaned, and cwdGet(child) returns undefined (or
  //      input.cwd from the parent's seed) → wrong.
  // Post-fix we reconcile per-key state INTO the parent's group at
  // union time.
  //
  // Reconciliation rules:
  //   - cwd: child-only → keep child value; parent-only → keep parent's
  //     (already in place); both & equal → keep; both & differ → set
  //     cwdUnknown (state ambiguity is a fail-closed signal); unknown
  //     on EITHER side propagates to the merged group.
  //   - dirfdTable: union of entries; same fd / same path → keep; same
  //     fd / different paths → drop that fd (downstream openat(<fd>,
  //     ...) fails closed via the missing-entry path); fdUnknown on
  //     EITHER side propagates.
  function unionCwd(parentPid: number, childPid: number): void {
    const pr = rootedCwd(parentPid);
    const cr = rootedCwd(childPid);
    if (pr === cr) return;
    // Snapshot pre-union state on both sides.  `pidCwd`/`pidCwdUnknown`
    // are keyed by group root (the SAME map slot the accessors below
    // resolve to).
    const parentCwd = pidCwd.get(pr);
    const childCwd = pidCwd.get(cr);
    const parentUnknown = pidCwdUnknown.has(pr);
    const childUnknown = pidCwdUnknown.has(cr);
    // Re-point first so subsequent set/delete operations resolve into
    // the merged group (parent's root).
    cwdParent.set(cr, pr);
    // Remove the orphaned child-root entries — they would otherwise
    // remain in the map and waste memory, and become "live" again if a
    // future pid happens to be assigned the same number.
    if (childCwd !== undefined) pidCwd.delete(cr);
    if (childUnknown) pidCwdUnknown.delete(cr);
    // Reconcile cwd value.
    if (childCwd !== undefined && parentCwd === undefined) {
      // Child-only: adopt child's cwd into merged group.
      pidCwd.set(pr, childCwd);
    } else if (childCwd !== undefined && parentCwd !== undefined) {
      if (childCwd !== parentCwd) {
        // Ambiguous (parent and child saw different cwds before the
        // shared-fs declaration).  Fail closed: drop the value and
        // mark unknown.
        pidCwd.delete(pr);
        pidCwdUnknown.add(pr);
      }
      // else: equal → already in place, nothing to do.
    }
    // Unknown bit propagates.
    if (childUnknown || parentUnknown) pidCwdUnknown.add(pr);
  }
  function unionFd(parentPid: number, childPid: number): void {
    const pr = rootedFd(parentPid);
    const cr = rootedFd(childPid);
    if (pr === cr) return;
    // Snapshot pre-union fd-table entries on both sides.  Keys are
    // formatted `<root>:<fd>` — collect by root prefix.
    const parentPrefix = `${pr}:`;
    const childPrefix = `${cr}:`;
    const parentFds = new Map<string, { path: string; cloexec: boolean }>(); // fd-suffix → entry
    const childFds = new Map<string, { path: string; cloexec: boolean }>();
    for (const [key, val] of dirfdTable) {
      if (key.startsWith(parentPrefix)) {
        parentFds.set(key.slice(parentPrefix.length), val);
      } else if (key.startsWith(childPrefix)) {
        childFds.set(key.slice(childPrefix.length), val);
        // Delete child-root entries; they'll be re-keyed under the
        // merged root below.
        dirfdTable.delete(key);
      }
    }
    const childFdUnknown = dirfdStateUnknown.has(cr);
    const parentFdUnknown = dirfdStateUnknown.has(pr);
    // Codex adversarial pass 46 (high, 2026-05-19, bug #7 — marker-
    // less opaque-fd reuse): snapshot both groups' opaque-reuse sets
    // BEFORE re-pointing the parent pointer, then merge into the
    // parent's root afterwards.  An opaque fd on EITHER side means
    // the kernel-shared fd table was replaced through that fd and
    // the parent's same-numbered modeled entry is stale — drop it.
    const childOpaque = opaqueFdReuses.get(cr);
    const parentOpaque = opaqueFdReuses.get(pr);
    // Re-point parent pointer after we've finished iterating the map
    // (so the iteration above sees the pre-union roots).
    fdParent.set(cr, pr);
    // Merge child-only fds into the parent group.
    for (const [fdSuffix, childVal] of childFds) {
      const mergedKey = `${pr}:${fdSuffix}`;
      const parentVal = parentFds.get(fdSuffix);
      if (parentVal === undefined) {
        // Child-only fd → adopt unchanged.
        dirfdTable.set(mergedKey, childVal);
      } else if (parentVal.path === childVal.path && parentVal.cloexec === childVal.cloexec) {
        // Same fd, identical entry on both sides — parent's entry is
        // already in `dirfdTable` under `mergedKey` (parentPrefix ===
        // merged prefix), so nothing to do.
      } else if (parentVal.path === childVal.path) {
        // Same fd, same path — but cloexec bits differ (one side set
        // FD_CLOEXEC via fcntl independently from the other).  Keep
        // the path; OR the cloexec bits so the kernel-observable
        // post-exec sweep is conservative (if either side considered
        // it CLOEXEC, the next exec drops it).
        dirfdTable.set(mergedKey, { path: parentVal.path, cloexec: parentVal.cloexec || childVal.cloexec });
      } else {
        // Same fd, DIFFERENT paths — ambiguous.  Fail closed: drop the
        // entry entirely.  Subsequent openat(<fd>, ...) returns
        // `undefined` from dirfdTable.get and canonicalizes to null,
        // producing a `<UNRESOLVED_PATH>` synth.
        dirfdTable.delete(mergedKey);
      }
    }
    // Codex adversarial pass 46 (high, 2026-05-19, bug #7): apply
    // opaque-fd-reuse drops AFTER the merge.  For any fd in either
    // side's opaque set, the kernel-shared fd table at that fd was
    // replaced through an opaque (untracked) source — the parent's
    // modeled entry at that same fd is stale (the kernel had been
    // sharing the table under CLONE_FILES, so the kernel-real fd is
    // whatever the opaque open installed, not what the parent's
    // model says).  Drop the merged entry and KEEP the opaque marker
    // so a subsequent openat(<fd>, ...) on the merged group fails
    // closed via dirfdTable.get returning undefined.
    if (childOpaque !== undefined || parentOpaque !== undefined) {
      const merged = new Set<number>();
      if (childOpaque !== undefined) for (const fd of childOpaque) merged.add(fd);
      if (parentOpaque !== undefined) for (const fd of parentOpaque) merged.add(fd);
      // Drop any merged dirfdTable entry at an opaque fd — the
      // kernel-shared mapping was opaque'd.
      for (const fd of merged) {
        dirfdTable.delete(`${pr}:${fd}`);
      }
      // Stash the merged opaque set under the new root (the parent's
      // root) and clear the child's slot.
      if (childOpaque !== undefined) opaqueFdReuses.delete(cr);
      opaqueFdReuses.set(pr, merged);
    }
    // dirfdStateUnknown propagation: either side's unknown bit taints
    // the merged group.
    if (childFdUnknown) dirfdStateUnknown.delete(cr);
    if (childFdUnknown || parentFdUnknown) dirfdStateUnknown.add(pr);
  }

  // Codex follow-up (high, 2026-05-19): shared detach helpers used by
  // CLOSE_RANGE_UNSHARE, unshare(CLONE_FILES) / unshare(CLONE_FS), and
  // successful execve.  Each helper detaches the caller pid from any
  // multi-member group it is currently a member of, seeding a private
  // copy of the group's per-pid state into the new singleton group.
  //
  // Semantics shared by both:
  //   - If the pid is the sole member of its group (no other pid
  //     resolves to it via the parent map), no-op: the pid already owns
  //     the group state.
  //   - If the pid is a NON-ROOT member, simply clear its parent pointer
  //     (so it becomes its own root) and copy the shared state into the
  //     new key prefix.  The shared group is unaffected; its remaining
  //     members continue to resolve to the unchanged root.
  //   - If the pid IS the group representative AND there are other
  //     members: promote the smallest-pid remaining member to the new
  //     root, re-point all other members at it, migrate the shared
  //     per-pid state keys, then seed the caller's NEW singleton group
  //     with a copy.
  //
  // The execve path needs the fd-group detach BEFORE its CLOEXEC sweep
  // because the kernel's `unshare_files_struct` runs inside `do_execve`
  // — exec dup's the fd table into a private copy and then closes the
  // CLOEXEC fds.  Without the detach, our post-exec sweep mutates the
  // shared dirfdTable, bleeding state changes into siblings.
  //
  // The unshare(CLONE_FS) path needs the cwd-group detach so a child
  // that calls `unshare(CLONE_FS); chdir(...)` no longer affects the
  // parent's modeled cwd (the kernel breaks CLONE_FS at the unshare).
  function detachFdGroup(pid: number): void {
    const sharedRoot = rootedFd(pid);
    const sharedPrefix = `${sharedRoot}:`;
    const snapshot: Array<[string, { path: string; cloexec: boolean }]> = [];
    for (const [key, val] of dirfdTable) {
      if (key.startsWith(sharedPrefix)) {
        snapshot.push([key.slice(sharedPrefix.length), val]);
      }
    }
    const sharedUnknown = dirfdStateUnknown.has(sharedRoot);
    // Codex adversarial pass 46 (high, 2026-05-19, bug #7 — marker-
    // less opaque-fd reuse): snapshot the shared group's opaque-reuse
    // set BEFORE we mutate fdParent so subsequent rootedFd lookups in
    // this function still resolve to `sharedRoot`.  The opaque set
    // follows union-find migration — see comments at the helpers.
    const sharedOpaque = opaqueFdReuses.get(sharedRoot);
    if (sharedRoot !== pid) {
      // Non-root member detach: clear parent pointer, copy snapshot
      // into private group.  Shared group state stays intact.
      fdParent.delete(pid);
      for (const [fdSuffix, val] of snapshot) {
        dirfdTable.set(`${pid}:${fdSuffix}`, val);
      }
      if (sharedUnknown) dirfdStateUnknown.add(pid);
      // Seed caller's new singleton with a COPY of the shared opaque
      // set; the original stays under sharedRoot for the remaining
      // members.
      if (sharedOpaque !== undefined) {
        opaqueFdReuses.set(pid, new Set(sharedOpaque));
      }
      return;
    }
    // Caller IS the representative.  Find other members.
    const otherMembers: number[] = [];
    for (const memberPid of fdParent.keys()) {
      if (memberPid === pid) continue;
      if (findFdRoot(memberPid) === pid) {
        otherMembers.push(memberPid);
      }
    }
    if (otherMembers.length === 0) {
      // Singleton group — nothing to detach against; state already
      // lives under `pid:<fd>`.
      return;
    }
    // Promote smallest-pid remaining member to new root.
    otherMembers.sort((a, b) => a - b);
    const newRoot = otherMembers[0]!;
    fdParent.delete(newRoot);
    for (const member of otherMembers) {
      if (member === newRoot) continue;
      fdParent.set(member, newRoot);
    }
    const oldPrefix = `${pid}:`;
    for (const [fdSuffix, val] of snapshot) {
      dirfdTable.set(`${newRoot}:${fdSuffix}`, val);
      dirfdTable.delete(`${oldPrefix}${fdSuffix}`);
    }
    if (sharedUnknown) {
      dirfdStateUnknown.delete(pid);
      dirfdStateUnknown.add(newRoot);
    }
    // Migrate the opaque-reuse set: the shared group continues under
    // `newRoot`, so move the set from `pid` → `newRoot`.  Seed
    // caller's NEW singleton group with a copy.
    if (sharedOpaque !== undefined) {
      opaqueFdReuses.delete(pid);
      opaqueFdReuses.set(newRoot, sharedOpaque);
      opaqueFdReuses.set(pid, new Set(sharedOpaque));
    }
    // Seed caller's NEW singleton group from snapshot.
    for (const [fdSuffix, val] of snapshot) {
      dirfdTable.set(`${pid}:${fdSuffix}`, val);
    }
    if (sharedUnknown) dirfdStateUnknown.add(pid);
  }

  function detachCwdGroup(pid: number): void {
    const sharedRoot = rootedCwd(pid);
    const sharedCwd = pidCwd.get(sharedRoot);
    const sharedUnknown = pidCwdUnknown.has(sharedRoot);
    if (sharedRoot !== pid) {
      cwdParent.delete(pid);
      if (sharedCwd !== undefined) pidCwd.set(pid, sharedCwd);
      if (sharedUnknown) pidCwdUnknown.add(pid);
      return;
    }
    // Caller IS the representative.
    const otherMembers: number[] = [];
    for (const memberPid of cwdParent.keys()) {
      if (memberPid === pid) continue;
      if (findCwdRoot(memberPid) === pid) {
        otherMembers.push(memberPid);
      }
    }
    if (otherMembers.length === 0) {
      // Singleton — no-op.
      return;
    }
    otherMembers.sort((a, b) => a - b);
    const newRoot = otherMembers[0]!;
    cwdParent.delete(newRoot);
    for (const member of otherMembers) {
      if (member === newRoot) continue;
      cwdParent.set(member, newRoot);
    }
    if (sharedCwd !== undefined) {
      pidCwd.set(newRoot, sharedCwd);
      pidCwd.delete(pid);
    }
    if (sharedUnknown) {
      pidCwdUnknown.delete(pid);
      pidCwdUnknown.add(newRoot);
    }
    // Seed caller's NEW singleton group.
    if (sharedCwd !== undefined) pidCwd.set(pid, sharedCwd);
    if (sharedUnknown) pidCwdUnknown.add(pid);
  }

  // Per-pid (really per-fd-group) fd table: maps a kernel-assigned file
  // descriptor (from a successful openat) to the canonical absolute path
  // of the directory (or file) it points at.  Used to resolve subsequent
  // `openat(<dirfd>, "relative", ...)` events.  We resolve at INSERT
  // time using `path.resolve` on the openat's path argument — strace
  // gives us the literal path from userspace, which is what we need to
  // anchor the relative resolve to.  We don't bother with realpath on
  // attacker-supplied dirfd paths (see note above).
  //
  // Memory bound: pids that exit aren't pruned explicitly; the install
  // is a single-pass loop and the table is GC'd when the function
  // returns.  In practice the table is small (~hundreds of fds per pid
  // at most for a real install).
  //
  // Keyed by fd-group root (`findFdRoot(pid)`) — see CLONE_FILES
  // discussion above.
  //
  // Audit-trust Finding (high, 2026-05-19, codex follow-up): the value
  // type is `{ path; cloexec }` rather than a bare `string`.  The
  // `cloexec` bit is set by openat/openat2/open if the flags argument
  // includes O_CLOEXEC (= 0o2000000), by `dup3(oldfd, newfd, O_CLOEXEC)`,
  // by `fcntl(fd, F_DUPFD_CLOEXEC, …)`, and by
  // `fcntl(fd, F_SETFD, FD_CLOEXEC)`.  It's CLEARED by
  // `fcntl(fd, F_SETFD, 0)`, by `dup`/`dup2` (which never set FD_CLOEXEC
  // on the duplicate), and by close_range with CLOSE_RANGE_CLOEXEC
  // (which sets it).  On a successful execve we sweep the fd-group's
  // dirfdTable: entries with cloexec=true are deleted (the kernel
  // closed them), entries with cloexec=false survive (the kernel kept
  // them).  Pre-fix we never tracked cloexec, so a script that did
  // `openat(AT_FDCWD, "/pkg", O_RDONLY|O_CLOEXEC) = 7` + exec + a raw
  // `openat(7, "../../root/.ssh/id_rsa", …)` would resolve through the
  // stale `/pkg` mapping (kernel had already closed fd 7 on exec, so
  // the post-exec openat actually got EBADF or aliased an unrelated fd
  // the new image opened — either way our resolution was wrong).
  const dirfdTable = new Map<string, { path: string; cloexec: boolean }>();
  const fdKey = (pid: number, fd: number): string => `${rootedFd(pid)}:${fd}`;

  // Audit-trust Finding (high, 2026-05-19): per-pid CWD table for Layer-2
  // resolution of AT_FDCWD-relative openat targets.  Updated from strace
  // `chdir(...)` and `fchdir(...)` lines parsed BELOW in the dispatcher
  // loop (see the `chdirRe` / `fchdirRe` block).  Without this, a non-
  // shim-loaded attacker pid could:
  //   1. `chdir("/tmp/script-jail-events-XXX")`
  //   2. `openat(AT_FDCWD, "events.jsonl", O_APPEND|O_WRONLY)`
  // and the canonicalizer would resolve the relative target against the
  // AGENT process's cwd (NOT the attacker's), producing a path that
  // does not equal `eventsFilePathCanonical` — silently dropping the
  // forgery signal.  Layer 1 (basename match above) is the safety net;
  // this map is the proper resolution.
  //
  // Keyed by cwd-group root (`findCwdRoot(pid)`) — see CLONE_FS
  // discussion in the union-find section above.  All access goes
  // through `cwdGet` / `cwdSet` / `cwdDelete` helpers below to ensure
  // the key is always a group root.
  const pidCwd = new Map<number, string>();

  // Audit-trust Finding (high, 2026-05-19, codex follow-up): set of pids
  // whose cwd state we OBSERVED a mutation event for but COULD NOT
  // resolve.  Membership in this set is "sticky": once a pid lands
  // here, AT_FDCWD-relative opens from it fail closed via the emit-time
  // canonicalizer until a SUCCESSFUL absolute chdir re-establishes a
  // known cwd.  Two cases populate it:
  //
  //   (a) `chdir("<relative>")` with no prior pidCwd entry.  Resolving
  //       the relative target against the agent process's cwd (or
  //       input.cwd) would produce a NON-NULL absolute path that is
  //       almost certainly wrong (the traced pid's actual cwd at
  //       fork-time is what relative chdir is anchored to).  We mark
  //       cwd unknown and fail closed on subsequent relative opens.
  //
  //   (b) `fchdir(<unknown-fd>) = 0`.  Strace observed a successful
  //       fchdir, but the fd is not in our dirfdTable — could be an
  //       inherited fd, a fork-time dup, or a strace line we missed.
  //       The kernel's cwd has moved to *somewhere*; we don't know
  //       where.  Mark unknown and fail closed.
  //
  // A subsequent `chdir("/absolute")` removes the pid from the set and
  // re-seeds `pidCwd` with the absolute path — confidence is
  // re-established because absolute chdir doesn't depend on prior cwd.
  //
  // Keyed by cwd-group root (CLONE_FS — see union-find section above).
  // All access goes through `cwdUnknownHas` / `cwdUnknownAdd` /
  // `cwdUnknownDelete` helpers below.
  const pidCwdUnknown = new Set<number>();

  // ---- group-aware accessors for cwd state -------------------------
  function cwdGet(pid: number): string | undefined {
    return pidCwd.get(rootedCwd(pid));
  }
  function cwdSet(pid: number, value: string): void {
    pidCwd.set(rootedCwd(pid), value);
  }
  function cwdDelete(pid: number): void {
    pidCwd.delete(rootedCwd(pid));
  }
  function cwdUnknownHas(pid: number): boolean {
    return pidCwdUnknown.has(rootedCwd(pid));
  }
  function cwdUnknownAdd(pid: number): void {
    pidCwdUnknown.add(rootedCwd(pid));
  }
  function cwdUnknownDelete(pid: number): void {
    pidCwdUnknown.delete(rootedCwd(pid));
  }

  // Audit-trust Finding (high, 2026-05-19, codex follow-up #2): set of
  // pids whose fd-table integrity we cannot guarantee.  Membership is
  // sticky: once a pid lands here, any subsequent
  // `openat(<numeric-dirfd>, ...)` from that pid fails closed in
  // `canonicalizeForEmit` / `canonicalizeOpenTarget` and emits a
  // `<UNRESOLVED_PATH>` audit_bypass entry instead of trusting the
  // stale dirfdTable mapping.  The codex attack closed here is:
  //
  //   1. parent: `openat(AT_FDCWD, "/pkg",  O_DIRECTORY) = 7`
  //   2. parent: `openat(AT_FDCWD, "/root", O_DIRECTORY) = 8`
  //   3. parent: <untraced fd mutation, e.g. raw `dup2(8,7)` via
  //              `syscall(SYS_dup2, ...)`>
  //   4. parent: `openat(7, ".ssh/id_rsa", O_RDONLY)`
  //
  // The kernel resolves step (4) through `/root` (fd 7 now points at
  // `/root` after the dup2), but the dirfdTable still says fd 7 → /pkg.
  // Pre-fix, we resolved to `/pkg/.ssh/id_rsa` and missed the
  // protected-paths match.  Post-fix, we trace `dup`/`dup2`/`dup3`,
  // `close`/`close_range`, and `fcntl` so the dirfdTable reflects each
  // mutation directly.  Anything we observe but cannot fully model
  // (e.g. a fcntl subcommand we don't recognise on a successful return)
  // lands in this set so subsequent numeric-dirfd opens fail closed.
  //
  // We DO fully parse `dup`/`dup2`/`dup3`/`close`/`close_range`, plus
  // the F_DUPFD / F_DUPFD_CLOEXEC / F_SETFD subcommands of fcntl below
  // — those propagate / invalidate the dirfdTable directly instead of
  // entering this set.  Only fcntl subcommands we don't recognise and
  // any future state-violating syscall we observe but cannot model
  // populate this set.
  //
  // NOTE: this set is INTENTIONALLY orthogonal to `pidCwdUnknown` —
  // cwd state and fd-table state are corrupted by different syscalls
  // and a pid can be cwd-known + fd-unknown (or vice-versa).
  //
  // Keyed by fd-group root (CLONE_FILES — see union-find section
  // above).  All access goes through `fdUnknownHas` / `fdUnknownAdd`
  // helpers below.
  const dirfdStateUnknown = new Set<number>();

  // ---- group-aware accessors for fd-table-unknown state ------------
  function fdUnknownHas(pid: number): boolean {
    return dirfdStateUnknown.has(rootedFd(pid));
  }
  function fdUnknownAdd(pid: number): void {
    dirfdStateUnknown.add(rootedFd(pid));
  }

  // Audit-trust Finding (high, 2026-05-19, codex follow-up #1) +
  // refinement (high, 2026-05-19, bug #1): the install command's root
  // pid (the process strace exec's into) is the ONE pid in the audit
  // tree that doesn't have an observable clone/fork parent — it was
  // spawned by the agent (not by another traced process) and so
  // inherits its cwd from `input.cwd` directly.  Every OTHER pid we
  // observe is either a strace-traced descendant of the root (whose
  // pidCwd is propagated at clone time, see the clone/clone3
  // pre-parser below) or a victim of an unobservable fork (in which
  // case `canonicalizeForEmit` correctly fails closed via the missing-
  // pidCwd path).
  //
  // Pre-refinement we seeded `pidCwd[<first-yielded-pid>] = input.cwd`
  // on the very first event yielded by the runner.  That was a "first
  // observed pid wins" heuristic.  The production `StraceTailer` polls
  // per-pid strace files via `readdirSync()` + `fs.watch`, and there
  // is NO guarantee that the strace root pid's file is yielded
  // first — a forked child's file might be drained earlier if the
  // watcher reports it sooner.  Pre-fix that would have silently
  // seeded the WRONG pid (a child whose actual cwd was inherited from
  // a chdir'd parent) with `input.cwd`, certifying a wrong cwd and
  // letting subsequent AT_FDCWD-relative opens leak past
  // protected-paths.
  //
  // Refinement: the `StraceRunner` interface now exposes a
  // `getRootPid()` accessor.  The production runner records the pid
  // of the FIRST per-pid strace output file discovered (strace writes
  // its direct child's file before any descendants') and exposes it
  // here.  The dispatcher consults `getRootPid()` on every event and
  // seeds `pidCwd` ONLY for that exact pid number.  Pids that don't
  // have that number get no seed — they must either inherit via
  // clone propagation (CLONE_FS or copy) or fail closed.
  //
  // EDGE CASE: if the runner returns null (strace failed to spawn,
  // or the runner is a test fake that doesn't track root), no seeding
  // happens.  This is the safe default — every pid then falls through
  // to clone-propagation or the fail-closed path.
  let installRootSeeded = false;

  /**
   * Canonicalize the target path of an openat write event for comparison
   * against `eventsFilePathCanonical`.  Returns the canonical absolute
   * path, or `null` if the path cannot be resolved (numeric dirfd whose
   * target wasn't observed earlier — drop the comparison to avoid false
   * positives).
   *
   * Canonicalization is LEXICAL only on the attacker-supplied portion:
   * `path.resolve` collapses `.`/`..` and redundant separators but does
   * NOT follow symlinks.  Symlink-following is intentionally avoided —
   * see comments above on the trust direction.
   */
  const canonicalizeOpenTarget = (
    pid: number,
    targetPath: string,
    dirfd: number | undefined,
  ): string | null => {
    if (dirfd === undefined) {
      // AT_FDCWD opens.  For absolute paths, `path.resolve` collapses
      // `.`/`..` segments and is the answer regardless of CWD.  For
      // RELATIVE paths, we need the attacker's actual CWD — not the
      // agent process's CWD — or we miss the cwd-relative forgery
      // attack:
      //   chdir("/tmp/script-jail-events-XXX") +
      //   openat(AT_FDCWD, "events.jsonl", O_APPEND|O_WRONLY)
      // would otherwise resolve to <agent_cwd>/events.jsonl and not
      // string-equal the canonical events file path.
      //
      // The `pidCwd` map is updated from strace `chdir(...)` and
      // `fchdir(...)` lines in the dispatcher loop below.  When we
      // don't have a tracked CWD for this pid (strace dropped the
      // chdir line, or the pid never chdir'd from its inherited cwd),
      // we return `null` so the equality-check path drops the
      // comparison — the basename safety net (Layer 1) catches the
      // common case at the call site.
      if (path.isAbsolute(targetPath)) {
        return path.resolve(targetPath);
      }
      // Codex follow-up (bug #2, high, 2026-05-19): the cwdUnknown bit
      // DOMINATES the cwdGet lookup.  After `unionCwd` reconciles
      // differing parent/child cwds it marks the merged group
      // cwdUnknown (and may also leave a stale adopted value in
      // pidCwd, depending on reconciliation order).  Pre-fix, this
      // canonicalizer called `cwdGet(pid)` directly — bypassing the
      // unknown signal and happily returning the adopted value, which
      // defeated the fail-closed posture.  Strict fix: consult
      // `cwdUnknownHas` FIRST and return null if the pid's cwd state
      // is unknown, regardless of whether a value happens to be in
      // pidCwd.  The unknown bit is the canonical fail-closed signal.
      if (cwdUnknownHas(pid)) return null;
      const cwd = cwdGet(pid);
      if (cwd === undefined) return null;
      return path.resolve(cwd, targetPath);
    }
    // Codex follow-up (high, 2026-05-19): if the pid's dirfd table
    // integrity is unknown, treat ANY numeric-dirfd lookup as
    // unresolvable so the forgery detector falls through to the
    // Layer-1 basename safety net instead of trusting a possibly
    // stale mapping.
    if (fdUnknownHas(pid)) return null;
    const dirEntry = dirfdTable.get(fdKey(pid, dirfd));
    if (dirEntry === undefined) return null;
    return path.resolve(dirEntry.path, targetPath);
  };

  // Audit-trust Finding (high, 2026-05-19): a separate canonicalizer for
  // the *emit* path (NOT the events-file forgery detector).  Same logic
  // as `canonicalizeOpenTarget`, with one historical difference: pre-
  // codex-follow-up, when a pid had no tracked cwd AND no observed
  // state mutation, we fell back to `input.cwd` to keep the install
  // root's own AT_FDCWD-relative opens resolving without flooding
  // `audit_bypass` with `<UNRESOLVED_PATH>` entries.
  //
  // Codex follow-up #1 (high, 2026-05-19): the `input.cwd` fallback is
  // GONE.  It was the direct cause of codex finding #1: forked
  // children inherit their cwd from the parent, but the cwd map was
  // keyed only by pid and the strace trace set did not include
  // fork/clone propagation.  A parent that `chdir("/root")`'d and
  // then `clone(...) = <child>`'d a child whose `openat(AT_FDCWD,
  // ".ssh/id_rsa", O_RDONLY)` arrived first would resolve through the
  // child's missing pidCwd → `input.cwd`, producing `/work/.ssh/id_rsa`
  // — wrong (the kernel-observed path is `/root/.ssh/id_rsa`) and
  // unprotected by the `$HOME/.ssh/**` matcher.
  //
  // Replacement: clone/clone3/vfork/fork propagation copies the
  // parent's pidCwd/pidCwdUnknown/dirfdTable entries to the child at
  // observation time (see the dispatcher pre-parser below).  Plus, the
  // install root pid itself is seeded with `path.resolve(input.cwd)`
  // on first observation — it's the only pid that doesn't have an
  // observable clone parent in our trace.
  //
  // Codex follow-up #2 (high, 2026-05-19): numeric-dirfd lookups now
  // honour `dirfdStateUnknown` — a pid that observed an fd-mutating
  // syscall we couldn't fully model (fcntl etc.) fails closed on
  // every subsequent numeric dirfd, preventing stale-fd certification.
  //
  // The events-file forgery detector (`canonicalizeOpenTarget`) shares
  // both gates — it has always returned `null` on unknown state and
  // falls back to the Layer-1 basename safety net at the call site.
  const canonicalizeForEmit = (
    pid: number,
    targetPath: string,
    dirfd: number | undefined,
  ): string | null => {
    if (dirfd === undefined) {
      if (path.isAbsolute(targetPath)) {
        return path.resolve(targetPath);
      }
      // Codex follow-up (bug #2, high, 2026-05-19): the cwdUnknown bit
      // DOMINATES.  After `unionCwd` merges a child cwd-unknown group
      // into a parent cwd-known group, the merged group inherits the
      // unknown bit but may also retain the parent's old cwd value
      // (the reconciliation rule only deletes pidCwd[merged] when
      // both sides had values and they differed — see unionCwd).
      // Pre-fix, this canonicalizer called `cwdGet(pid)` directly,
      // returning the stale parent value and certifying a wrong cwd
      // for the merged group's AT_FDCWD-relative opens.  Strict fix:
      // consult `cwdUnknownHas` BEFORE `cwdGet`; if unknown, return
      // null so the open is dropped + a `<UNRESOLVED_PATH>` synth
      // surfaces in the post-loop pass.
      if (cwdUnknownHas(pid)) return null;
      const tracked = cwdGet(pid);
      if (tracked !== undefined) {
        return path.resolve(tracked, targetPath);
      }
      // No tracked cwd → fail closed.  Pre-codex-follow-up this branch
      // fell back to `input.cwd` for the convenience of the install
      // root's children that hadn't chdir'd; that fallback was wrong
      // for cloned children that inherited a parent's chdir (codex
      // finding #1).  After this fix, the install root is seeded
      // explicitly on first observation and cloned children inherit
      // via the clone/clone3 pre-parser; any pid that reaches this
      // branch genuinely has unknown cwd state, so we drop the raw
      // event and surface a `<UNRESOLVED_PATH>` synth in the post-
      // loop pass.
      return null;
    }
    // Codex follow-up #2 (high, 2026-05-19): fail closed on stale fd
    // tables — see comments on `dirfdStateUnknown` above.
    if (fdUnknownHas(pid)) return null;
    const dirEntry = dirfdTable.get(fdKey(pid, dirfd));
    if (dirEntry === undefined) return null;
    return path.resolve(dirEntry.path, targetPath);
  };

  const shimLoadedPids = new Set<number>();
  interface ForgerySample {
    pid: number;
    ts: number;
    path: string;
    pkg: string;
    lifecycle: AttributedEvent['lifecycle'];
  }
  const forgerySamples: ForgerySample[] = [];

  // Audit-trust Finding (high, 2026-05-19): per-event sample of an openat
  // read/write whose dirfd/cwd-relative path we could NOT resolve.
  // Emitting the literal relative path as a normal lockfile event would
  // bypass:
  //   (a) the protected-paths matcher (a `$HOME/.ssh/**` pattern can't
  //       match `".ssh/id_rsa"` — micromatch requires the absolute /
  //       tokenized form), and
  //   (b) the cross-package matcher in normalize.ts (a relative
  //       `"build.log"` doesn't start with the package dir prefix, so a
  //       package's legitimate intra-dir write reads as an escaped
  //       write).
  // We collect samples here and surface one synthetic <UNRESOLVED_PATH>
  // exec event per offending openat in the post-loop synthesis pass.
  // Per-event (rather than phase-level setPhaseTamper) granularity
  // mirrors the existing <EVENTS_FILE_FORGERY> and
  // <SYSCALL_EXEC_BYPASS> patterns: it lets the auditor see WHICH
  // package issued the unresolvable open under WHICH lifecycle stage.
  interface UnresolvedPathSample {
    pid: number;
    ts: number;
    // The literal relative path the script tried to open.  Carried
    // forensically only — never matched against any policy pattern.
    path: string;
    // Kind (read|write) is preserved so the audit_bypass entry can
    // include it for context.
    kind: 'read' | 'write';
    pkg: string;
    lifecycle: AttributedEvent['lifecycle'];
  }
  const unresolvedPathSamples: UnresolvedPathSample[] = [];

  // Audit-trust Finding 3 (high, 2026-05-18): a raw `syscall(SYS_execve, …)`
  // bypass with an attacker-controlled `envp` produces a child whose
  // `/proc/<pid>/environ` is missing the npm_package_name /
  // npm_lifecycle_event vars Attribution depends on.  The pre-fix flow
  // gated bypass counting on attribution succeeding, so the most damaging
  // case (raw exec + scrubbed envp) silently skipped the bypass detector
  // and produced a clean lockfile.
  //
  // The fix has two halves:
  //
  //   (a) Snapshot lifecycle attribution per-pid the FIRST time we see
  //       attribution succeed for that pid (or any event with a known
  //       attribution result).  Strace observes pids in spawn-order, so
  //       the very first event we see for a pid is normally from BEFORE
  //       the child has had a chance to overwrite its own environ.  We
  //       cache that snapshot here and prefer it over re-reading
  //       /proc/<pid>/environ at bypass-count time.
  //
  //   (b) Decouple bypass counting (and synthetic-event emission) from
  //       attribution success.  The strace observation of an execve is
  //       proof-of-bypass when no matching shim event exists, regardless
  //       of whether we can still attribute the pid to a package.  When
  //       the snapshot is empty (attribution NEVER succeeded for this
  //       pid — strange but possible) we fall back to a "<unknown>"
  //       pkg + lifecycle so the audit_bypass entry still surfaces in
  //       the lockfile diff and the `findAuditBypass` scan in
  //       src/action/diff.ts hard-fails the PR.
  //
  // The map is keyed by pid.  Entries are REFRESHED on every successful
  // attribution observation: the sole caller (~line 4482) only invokes
  // `recordAttribution` when `result !== null`, so the helper never
  // receives a worse-quality signal than the snapshot we already have.
  // The refresh is important for same-pid re-exec into a different
  // package context (npm spawns a wrapper that itself execs a
  // package-bin), and is the second half of the snapshot-lifetime fix
  // that goes with the exit-line eviction below — together they prevent
  // a recycled or re-exec'd pid from carrying a stale earlier label
  // into the spawn fallback (Codex audit-trust 2026-05-19).
  const attributionSnapshotByPid: Map<
    number,
    { pkg: string; lifecycle: AttributedEvent['lifecycle'] }
  > = new Map();
  const recordAttribution = (
    pid: number,
    attr: { pkg: string; lifecycle: AttributedEvent['lifecycle'] },
  ): void => {
    attributionSnapshotByPid.set(pid, { pkg: attr.pkg, lifecycle: attr.lifecycle });
  };

  // StraceRunner is the SOLE owner of the install process.
  // We do NOT call a separate spawner here — that would run install twice.
  //
  // Dispatch is keyed on `source`, NOT on a parse-and-fall-through pattern.
  // The previous design — try `parseShimLine`, fall through to `parseStraceLine`
  // on null — masked a critical-severity audit bypass: a lifecycle script that
  // open()s SCRIPT_JAIL_LOG_FILE in append mode can write a JSONL prefix
  // WITHOUT a trailing newline, then trigger a legitimate shim write whose
  // bytes append directly onto the attacker's prefix.  The resulting line
  // fails JSON.parse, falls through to parseStraceLine (which fails too on a
  // mangled-JSON fragment), and gets silently dropped — eliminating the real
  // audit event.  By dispatching on `source` and treating shim-channel parse
  // failures as fatal tamper, we close that gap while keeping strace's
  // best-effort drop for its noisy text format.
  //
  // Finding 1 (audit-trust): the dispatch below is runtime-exhaustive.
  // `LineSource` is only a TypeScript type — `source` is opaque at runtime,
  // so an `else` branch that silently falls into the strace parser is a
  // potential audit bypass (a typo, a renamed channel, or a wrapper that
  // produces `undefined` would route trusted-channel bytes through the
  // best-effort path).  We require an explicit 'shim' or 'strace' value;
  // anything else records tamper.
  for await (const { pid, line, source } of input.strace.run(cmd, args, {
    env: input.env,
    cwd: input.cwd,
    basePath,
  })) {
    // Codex follow-up #1 (high, 2026-05-19) + bug-fix refinement (high,
    // 2026-05-19): seed the install root pid's cwd with `input.cwd`
    // EXACTLY ONCE, for EXACTLY the pid the runner reports as the
    // strace root (the install command's pid — strace's direct
    // child).  See the `installRootSeeded` comment above for why this
    // targets exactly one pid rather than every untracked one.  We
    // deliberately seed BEFORE any per-source dispatch so even a
    // leading shim-channel event (which carries the same pid) seeds
    // the root.
    //
    // Pre-refinement this was a "first observed pid wins" heuristic
    // which silently mis-seeded a forked child whose per-pid strace
    // file was yielded before the parent's.  Now the runner
    // explicitly identifies the root pid; non-root pids never receive
    // an `input.cwd` seed here.  If the runner cannot identify a root
    // (`getRootPid()` returns null — strace failed to spawn, or a
    // test fake opted out), no seeding happens and every pid falls
    // through to clone-propagation or the fail-closed path.
    if (!installRootSeeded) {
      const rootPid = input.strace.getRootPid();
      if (rootPid !== null && pid === rootPid) {
        installRootSeeded = true;
        cwdSet(pid, path.resolve(input.cwd));
      }
    }

    if (source === 'shim') {
      // Trusted JSONL channel — fd-3 pipe or SCRIPT_JAIL_LOG_FILE.  Parse
      // failures here are NEVER strace text and must NEVER fall through to
      // parseStraceLine; they indicate the channel was poisoned by a writer
      // that should not have access (a lifecycle script writing partial
      // lines into the events file), OR a writer producing a payload our
      // schema doesn't recognise (which is itself suspicious — every legit
      // writer is owned by us).  Either way, fail closed: record tamper so
      // the agent's main() post-install gate aborts before emitting a
      // lockfile that would whitelist the bypassed events.
      const shimEvent = parseShimLine(line);
      if (shimEvent === null) {
        // Truncate the offending prefix in the error reason — the line
        // could be partially attacker-controlled and may contain secret-
        // like content (e.g. a partial NPM_TOKEN value picked up by the
        // shim's getenv interceptor).  100 bytes is enough to debug a
        // legitimate format drift without exfiltrating the full payload.
        const MAX_PREFIX = 100;
        const prefix = line.length > MAX_PREFIX
          ? `${line.slice(0, MAX_PREFIX)}…`
          : line;
        setPhaseTamper(
          `shim channel had unparseable JSONL line (pid=${pid}): ${JSON.stringify(prefix)}`,
        );
        continue;
      }
      const result = input.attribution.attribute(shimEvent.pid);
      // Audit-trust Finding 1: track the shim's exec events per pid so
      // the post-loop cross-check can pair each strace execve with a
      // shim exec.  We count regardless of whether attribution succeeded
      // (a shim event without attribution still proves the shim wrapper
      // ran for that pid, which is the invariant we are checking).  We
      // ALSO ignore `envp_alloc_failed` here — that's a different bypass
      // (rewrite_envp ran but allocation failed); it still proves the
      // libc wrapper entered the shim path.
      //
      // Audit-trust Finding (high, 2026-05-18): only `result:'ok'` shim
      // events count toward the strace-pairing denominator; failed
      // attempts are subtracted out so we end up with the NET successful
      // libc-wrapper exec count for this pid.  Before this fix, every
      // shim exec event (including failed wrapped execves) incremented
      // the counter — an attacker could trivially pad the shim count
      // with `execve("/missing", argv, envp)` calls (each shim wrapper
      // emits a pre-call event with the optimistic 'ok' tag, and that
      // event survived even when real_execve returned -1 ENOENT).  Then
      // a raw `syscall(SYS_execve, …)` for the same pid produced a
      // matching successful strace observation; the cross-check delta
      // was 0 and no `<SYSCALL_EXEC_BYPASS>` event was synthesised.
      //
      // The shim now emits a `result:'failed'` event AFTER real_execve
      // returns (which only happens on failure since success replaces
      // the image); for posix_spawn it emits a single event with the
      // correct result.  We count `ok - failed` here to obtain the
      // true successful-libc-exec count.
      if (shimEvent.kind === 'exec') {
        // Audit-trust Finding C (medium, 2026-05-18): saturating
        // subtraction.  A `result:'failed'` event from the shim may
        // be either (a) the post-call counterpart to a prior
        // optimistic 'ok' (where the libc wrapper returned an error
        // — net should be 0), or (b) a STANDALONE failure with no
        // prior 'ok' to cancel (posix_spawn that returned rc != 0
        // before the child was created; envp_alloc_failed wrappers
        // that emit 'failed' without 'ok').  Case (b) does NOT have
        // a paired strace observation, so allowing the counter to
        // go negative incorrectly inflates the strace/shim delta
        // for the NEXT legitimate wrapped exec on the same pid —
        // producing a spurious `<SYSCALL_EXEC_BYPASS>` entry that
        // hard-fails clean installs.
        //
        // Clamping the decrement at zero protects against this: a
        // `failed` event only cancels an outstanding `ok` and is
        // otherwise a no-op.  Equivalent to "only count failures
        // that pair with a prior optimistic ok in the same pid",
        // implemented as saturating subtraction rather than a
        // separate history-tracking pass.
        const current = shimExecCountByPid.get(shimEvent.pid) ?? 0;
        const next =
          shimEvent.result === 'failed'
            ? current > 0
              ? current - 1
              : 0
            : current + 1;
        shimExecCountByPid.set(shimEvent.pid, next);
      }
      if (result !== null) {
        // Finding 3 (audit-trust): snapshot attribution for this pid on
        // every successful observation.  A later raw execve from the
        // same pid with a scrubbed envp would otherwise lose the
        // lifecycle context and slip past the bypass detector.  The
        // refresh semantics (see `recordAttribution` declaration) also
        // keep same-pid re-execs into a new package context current.
        recordAttribution(shimEvent.pid, result);
        emit({ raw: shimEvent, pkg: result.pkg, lifecycle: result.lifecycle });
      }
      continue;
    }

    if (source === 'strace') {
      // Audit-trust Finding (medium, 2026-05-19): pre-parse process-exit
      // lines BEFORE any other per-pid bookkeeping in this branch so
      // that the snapshot map (and other pid-keyed state we want to be
      // lifecycle-bounded) never serves a stale entry for a reused or
      // re-exec'd pid.  Strace's `-ff` per-pid output renders the
      // exit-line literally as:
      //
      //   +++ exited with 0 +++
      //   +++ exited with 127 +++
      //   +++ killed by SIGKILL +++
      //
      // (the per-pid file's lines are already stripped of any pid
      // prefix; the dispatcher receives `pid` separately).  The strace
      // parser drops these lines (see src/guest/strace-parser.ts:300-302
      // — the same `+++ ... +++` shape is also used for kill/SIG-exit
      // notifications) so handling them here is the only place the
      // dispatcher gets to react.  We treat any `+++ ... +++` line as
      // process termination for the named pid and evict its snapshot —
      // that's the only state with a pid-reuse hazard that
      // recordAttribution writes today; other pid-keyed maps
      // (pidCwd / dirfdTable / shimLoadedPids / etc) are governed by
      // exec/clone semantics and are intentionally NOT cleared here.
      if (line.startsWith('+++') && line.endsWith('+++')) {
        attributionSnapshotByPid.delete(pid);
        continue;
      }

      // Audit-trust Finding (high, 2026-05-19): pre-parse `chdir(...)` and
      // `fchdir(...)` lines to maintain the per-pid CWD table.  These
      // syscalls don't produce a RawEvent (they're transport-only state
      // for the events-file forgery detector), so we handle them inline
      // here rather than threading a new event kind through the schema.
      //
      // Strace wire format:
      //   `chdir("/tmp/script-jail-events-XXX") = 0`
      //   `fchdir(5) = 0`
      //
      // We only consume successful calls (`= 0`); failures don't change
      // the kernel's cwd state and so don't update our map.  For
      // `fchdir`, the fd must already be in our `dirfdTable` (otherwise
      // we don't know what directory it points at — strace dropped the
      // earlier openat, or the fd was inherited across exec).  On
      // unknown fds we leave the map untouched, which means the
      // canonicalizer will fall back to the Layer-1 basename safety net
      // for any subsequent AT_FDCWD-relative openat from that pid.
      const chdirMatch = line.match(/^chdir\("((?:[^"\\]|\\.)*)"\)\s*=\s*0\b/);
      if (chdirMatch !== null) {
        const rawTarget = chdirMatch[1] ?? '';
        const decoded = unescapeStraceString(rawTarget);
        if (path.isAbsolute(decoded)) {
          // Absolute chdir: resolve to canonical absolute form,
          // re-establish confidence (remove unknown-state mark).
          // The cwdSet/cwdUnknownDelete helpers route through the
          // cwd-group root, so a CLONE_FS sibling's chdir mutates
          // the shared cwd as the kernel would.
          cwdSet(pid, path.resolve(decoded));
          cwdUnknownDelete(pid);
        } else {
          // Relative chdir.  Codex follow-up (high, 2026-05-19): pre-
          // fix, we computed `path.resolve(current ?? '', decoded)` —
          // when `current` was undefined, `path.resolve` falls back to
          // the AGENT process's cwd (process.cwd()), NOT the traced
          // pid's actual cwd.  That silently certified a wrong
          // absolute path and let subsequent AT_FDCWD-relative opens
          // bypass protected-paths / cross-package matchers.
          //
          // Strict fix: only honour relative chdir when we have a
          // tracked prior cwd.  Otherwise mark the pid's cwd state
          // unknown so the emit canonicalizer fails closed on later
          // relative opens.
          const current = cwdGet(pid);
          if (current !== undefined) {
            cwdSet(pid, path.resolve(current, decoded));
            // Keep pidCwdUnknown unchanged: a relative chdir on top
            // of a known cwd produces a known cwd.
          } else {
            cwdUnknownAdd(pid);
            // Do NOT cwdSet here — leaving the entry absent means
            // canonicalizeForEmit consults pidCwdUnknown and
            // returns null.
          }
        }
        continue;
      }
      const fchdirMatch = line.match(/^fchdir\((-?\d+)\)\s*=\s*0\b/);
      if (fchdirMatch !== null) {
        const fd = parseInt(fchdirMatch[1] ?? '', 10);
        if (Number.isFinite(fd)) {
          const dirEntry = dirfdTable.get(fdKey(pid, fd));
          if (dirEntry !== undefined) {
            cwdSet(pid, dirEntry.path);
            // Successful fchdir to a KNOWN fd: re-establish confidence.
            cwdUnknownDelete(pid);
          } else {
            // Codex follow-up (high, 2026-05-19): successful fchdir to
            // an UNKNOWN fd means the kernel's cwd has moved to
            // *somewhere*, but we don't know where.  Pre-fix this
            // branch was a silent no-op — leaving pidCwd as it was
            // (or absent) and letting canonicalizeForEmit fall back
            // to input.cwd, which is wrong.  Mark cwd unknown so
            // subsequent AT_FDCWD-relative opens fail closed.
            cwdUnknownAdd(pid);
            cwdDelete(pid);
          }
        }
        continue;
      }

      // Codex follow-up #1 (high, 2026-05-19) + refinement (bugs #2 & #3,
      // 2026-05-19): pre-parse fork/clone/vfork/clone3 to propagate
      // per-pid state to the new child pid.  Strace wire formats
      // (modern Linux):
      //
      //   clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|..., parent_tid=..., child_tid=..., tls=...) = 12345
      //   clone3({flags=CLONE_VM|..., child_tid=..., parent_tid=..., exit_signal=SIGCHLD, stack=..., stack_size=...}, 88) = 12345
      //   vfork()                                                                                                     = 12345
      //   fork()                                                                                                       = 12345
      //
      // Failure case (rc < 0, e.g. ENOMEM): does NOT create a child, so we
      // skip propagation.
      //
      // CLONE_FS / CLONE_FILES sharing semantics (bugs #2, #3):
      //   - CLONE_FS    → parent and child share `struct fs` (cwd, root,
      //                   umask).  We UNION the cwd group so a chdir in
      //                   either pid mutates the other's effective cwd.
      //   - CLONE_FILES → parent and child share the file descriptor
      //                   table.  We UNION the fd group so dup/close in
      //                   either pid mutates the other's table.
      //   - Neither flag set (default for plain fork/vfork, but vfork
      //                   does set CLONE_VM): child gets an independent
      //                   COPY of the parent's state at clone time.
      //                   Subsequent chdir/dup/close in either pid
      //                   diverges from the other.  This is our copy-on-
      //                   clone branch.
      //
      // We extract the flags string from `flags=CLONE_VM|CLONE_FS|...`
      // (clone) or `{flags=CLONE_VM|..., ...}` (clone3) and check for
      // the literal identifiers `CLONE_FS` and `CLONE_FILES`.  Plain
      // `fork()` and `vfork()` use NEITHER flag, so the copy branch
      // is taken.
      //
      // What we propagate forward (copy branch):
      //   - pidCwd[parent] → pidCwd[child]  (cwd is inherited per clone(2))
      //   - pidCwdUnknown membership        (so a parent with unknown cwd
      //                                      propagates that uncertainty)
      //   - dirfdTable entries keyed by parent → child  (fd table is
      //                                      inherited per clone(2))
      //   - dirfdStateUnknown membership    (propagate fd-table uncertainty)
      //   - shimLoadedPids membership       (shim mapping is preserved
      //                                      across fork — the executable
      //                                      image is shared)
      //
      // Share branch (CLONE_FS / CLONE_FILES set): a single union(pid,
      // childPid) replaces the per-key copy.  After the union, every
      // cwdGet/cwdSet/fdKey on either pid resolves to the same group
      // root, so the kernel-shared state is modelled with a single
      // backing entry.
      //
      // Race with the child's first event (codex spec note): if the child
      // races ahead and emits a syscall BEFORE we observe the parent's
      // clone line, the child's early events resolve through
      // canonicalizeForEmit's fail-closed branch (no pidCwd entry, not
      // pidCwdUnknown → returns null → `<UNRESOLVED_PATH>`).  Forward
      // propagation alone does NOT retroactively rewrite — that's the
      // conservative outcome the codex spec asked for.
      const cloneMatch = line.match(/^(clone3?|vfork|fork)\b/);
      if (cloneMatch !== null) {
        const syscallName = cloneMatch[1] ?? '';
        // Locate the trailing "= <rc>" and gate on success (positive rc).
        //
        // Codex follow-up (bug #4, high, 2026-05-19): the prior regex was
        // `/=\s*(\d+)\b/` — greedy across the whole line.  A clone3 line
        // like
        //   clone3({flags=CLONE_VM|CLONE_FS, stack_size=0,
        //           exit_signal=17}, 88) = 9999
        // contains numeric struct fields (`stack_size=0`, `exit_signal=17`)
        // BEFORE the trailing `= 9999`.  The greedy regex matched `=0`
        // first, so `childPid` became 0, the success gate `childPid > 0`
        // rejected the line, and propagation was silently skipped — the
        // child inherited NO state and every AT_FDCWD-relative open from
        // it failed closed even when the parent had a known cwd.
        //
        // Strict fix: anchor the return-value match on the closing `)` of
        // the syscall.  Strace always renders syscall return as
        // `<syscall>(<args>) = <rc>[ ERRNO]`, so `\)\s*=\s*(-?\d+)\b`
        // picks up the rc unambiguously, regardless of how many `=N`
        // tokens appear inside the args.  We accept negative rc too —
        // the `childPid > 0` gate below still discards failure cases.
        const rcMatch = line.match(/\)\s*=\s*(-?\d+)\b/);
        if (rcMatch !== null) {
          const childPid = parseInt(rcMatch[1] ?? '', 10);
          if (Number.isFinite(childPid) && childPid > 0) {
            // Extract the clone-flag identifier list.  For `clone(...)`
            // strace renders `flags=CLONE_VM|CLONE_FS|...`; for
            // `clone3({...})` it renders the same `flags=...|...` but
            // INSIDE the struct literal.  A single regex matches both
            // because the leading `flags=` token is the same.  Plain
            // fork/vfork have no flags field.
            let cloneFs = false;
            let cloneFiles = false;
            if (syscallName === 'clone' || syscallName === 'clone3') {
              const flagsMatch = line.match(/flags=([A-Z0-9_|]+)/);
              if (flagsMatch !== null) {
                const flagTokens = (flagsMatch[1] ?? '').split('|');
                for (const tok of flagTokens) {
                  if (tok === 'CLONE_FS') cloneFs = true;
                  else if (tok === 'CLONE_FILES') cloneFiles = true;
                }
              }
            }

            // --- cwd group: union if CLONE_FS, else copy. -----------
            //
            // Codex follow-up (medium, 2026-05-19): when a pending
            // unshare-detach marker is present on the child, we must
            // emulate the kernel's clone+private-copy semantic instead
            // of merely skipping the union.  At the kernel level the
            // syscall order is always:
            //   1. clone(...)            — child created; if CLONE_FS
            //                              is set, child shares the
            //                              parent's fs_struct.
            //   2. unshare(...)          — kernel detaches the child's
            //                              fs_struct into a private
            //                              copy whose initial state
            //                              equals the shared state at
            //                              the moment of unshare.
            // Strace per-pid file ordering may surface these lines in
            // either order to our dispatcher.  When we observe the
            // unshare line first we set a pending marker; when the
            // matching clone reconciliation arrives, we must INSTALL
            // the parent's cwd/fd state into the child's private group
            // (copy semantic) rather than dropping it.  Without the
            // copy, legitimate inherited paths surface as
            // `<UNRESOLVED_PATH>` audit_bypass entries and break
            // installs.
            //
            // Conflict reconciliation: if the child has ALREADY emitted
            // state of its own (e.g. it raced ahead with a `chdir`
            // before we processed the clone+marker), we fail closed on
            // disagreement — different cwd values → mark cwdUnknown;
            // different fd→path values → drop the fd entry.
            // Codex follow-up (medium, 2026-05-19, bug #2): consume the
            // pending markers as SNAPSHOTS of the child's state at
            // detach time, not as boolean flags.  The reconciler uses
            // the snapshot for parent-taint decisions so post-detach
            // child mutations (e.g. a chdir AFTER unshare(CLONE_FS))
            // stay private to the child and don't leak into the
            // parent's modeled state.
            const childCwdSnap = pendingCwdDetach.get(childPid);
            pendingCwdDetach.delete(childPid);
            const childFdSnap = pendingFdDetach.get(childPid);
            pendingFdDetach.delete(childPid);
            // Codex follow-up (high, 2026-05-19, bug #3 — post-marker
            // fd reuse exclusion) + (high, 2026-05-19, bug #5 — post-
            // marker close-of-reuse lifecycle): consume the per-pid
            // lifecycle map alongside the marker.  The reconciler
            // needs two derived views:
            //   - childPostMarkerFdTouched: union of OPEN + CLOSED
            //     fds.  Used as the tombstone exclude set — for
            //     pre-detach tombstones, the child's view of these
            //     fds is established post-marker (open or closed)
            //     and the kernel-shared mutation in the tombstone
            //     was already overlaid by the post-marker activity.
            //   - childPostMarkerFdClosed: only fds in 'closed'
            //     state.  Used by the copy-pass to skip parent
            //     entries that would resurrect a kernel-closed fd
            //     in the child copy.
            // Codex pass 50 follow-up (high, 2026-05-19): post-marker
            // fd reuses are keyed by fd-group ROOT (not by mutating
            // pid), so a CLONE_FILES sibling of the marker owner that
            // reused / closed fds post-marker has its lifecycle stored
            // under the SAME root we look up here.  The marker owner
            // is the fd-group root by invariant (markers are created
            // immediately after `detachFdGroup(pid)`), so at this
            // reconciliation moment `rootedFd(childPid) === childPid`
            // when childPid is the marker owner — but using
            // `rootedFd(childPid)` keeps the lookup symmetric with the
            // record/transition helpers above.
            const childFdRoot = rootedFd(childPid);
            const childPostMarkerLifecycle = postMarkerFdReuses.get(childFdRoot);
            postMarkerFdReuses.delete(childFdRoot);
            const childPostMarkerFdTouched =
              childPostMarkerLifecycle === undefined
                ? undefined
                : new Set(childPostMarkerLifecycle.keys());
            const childPostMarkerFdClosed = (() => {
              if (childPostMarkerLifecycle === undefined) return undefined;
              const closed = new Set<number>();
              for (const [fd, state] of childPostMarkerLifecycle) {
                if (state === 'closed') closed.add(fd);
              }
              return closed;
            })();
            // Pre-marker tombstones for this child.  When a marker
            // already exists, those tombstones have already been
            // folded into `preDetachTombstones[]` by
            // `absorbPendingTombstones` during snapshot creation —
            // the bucket here is stale and gets discarded.
            //
            // Codex follow-up (high, 2026-05-19, bug #2 final): when
            // NO marker exists, we used to silently drop the bucket.
            // That left a hole: a singleton child's pre-marker
            // close/close_range/F_SETFD on UNTRACKED inherited fds
            // mutated the shared files_struct (under CLONE_FILES)
            // BEFORE the parent's clone line surfaced.  Without
            // marker-less consumption, the reconciler copied parent
            // fds in untouched, missing the shared-kernel mutation.
            // The standaloneFdTombstones path below consumes them
            // when no marker exists (singleton close_range / close /
            // SETFD with no subsequent unshare/execve marker).
            const standaloneFdTombstones =
              childFdSnap === undefined ? pendingFdTombstones.get(childPid) : undefined;
            pendingFdTombstones.delete(childPid);
            const childHadPendingCwdDetach = childCwdSnap !== undefined;
            const childHadPendingFdDetach = childFdSnap !== undefined;
            if (cloneFs && !childHadPendingCwdDetach) {
              // Union the two pids into the same cwd group.  Subsequent
              // chdir on either pid mutates the shared state.
              unionCwd(pid, childPid);
              // No need to copy cwd / pidCwdUnknown — they are already
              // visible to the child via the shared root.
            } else {
              // Copy branch: independent fs struct.  Either the parent
              // did NOT set CLONE_FS (fork/vfork/clone without that
              // flag) OR the child later unshared its fs_struct (we
              // observed the unshare line first; pending marker now
              // consumed).  Snapshot the parent's cwd / unknown bit
              // into the child's NEW group, reconciling against any
              // state the child has already accumulated.
              const parentCwd = cwdGet(pid);
              const parentCwdUnknown = cwdUnknownHas(pid);
              // Codex follow-up (medium, 2026-05-19, bug #2): parent-
              // taint decisions use the SNAPSHOT (child state at
              // detach time) — NOT current child state.  Child's
              // post-detach mutations are private to the child's
              // group and didn't propagate to the parent under the
              // kernel's CLONE_FS/CLONE_FILES sharing.  The current
              // child state is still consulted for the COPY step
              // below, but a conflict measured against current state
              // would over-taint the parent.
              //
              // When there's no pending marker we fall back to current
              // child state — same as before (covers the plain
              // fork-without-CLONE_FS conflict case).
              const childCwd = childCwdSnap !== undefined ? childCwdSnap.cwd : cwdGet(childPid);
              const childCwdUnknown =
                childCwdSnap !== undefined ? childCwdSnap.unknown : cwdUnknownHas(childPid);
              const currentChildCwd = cwdGet(childPid);
              // Codex follow-up (high, 2026-05-19, bug #1 + bug #3): the
              // pending-detach parent-taint gate is BOTH:
              //   1. `childHadPendingCwdDetach` — the child observed an
              //      unshare AND we recorded a marker for the delayed
              //      reconciliation;
              //   2. `cloneFs` — the deferred clone actually had
              //      CLONE_FS (parent + child shared the fs_struct at
              //      kernel level pre-unshare).
              // Without (2), the parent was never sharing state with
              // the child; the kernel-level invariant we are modeling
              // (shared-state mutation requires shared state) does not
              // apply, so a model-side conflict is just stale per-side
              // bookkeeping and only the child should be tainted.
              const pendingDetachShared = childHadPendingCwdDetach && cloneFs;
              if (parentCwdUnknown || childCwdUnknown) {
                cwdUnknownAdd(childPid);
                // Codex follow-up (high, 2026-05-19, bug #1): when the
                // parent-cwd state is unknown OR the child-cwd state
                // is unknown AND the clone had CLONE_FS (so the kernel
                // truly shared fs_struct), the shared-time chdir was
                // applied to BOTH sides at kernel level.  Our model
                // can't tell which side mutated; either way, the
                // shared mutation makes the parent's modeled cwd
                // stale.  Drop the parent's modeled value and mark
                // unknown so AT_FDCWD-relative opens on the parent
                // fail closed until it re-establishes cwd via an
                // absolute chdir.
                //
                // The child-cwdUnknown case is the codex-finding gap:
                // a child `chdir(<relative>)` from an untracked cwd
                // marks the child cwdUnknown.  Under shared fs_struct
                // that relative chdir mutated parent's cwd too.  Pre-
                // fix, this branch only tainted the child.
                if (pendingDetachShared) {
                  cwdDelete(childPid);
                  cwdDelete(pid);
                  cwdUnknownAdd(pid);
                }
                // Don't seed pidCwd; cwdUnknown dominates the lookup.
              } else if (parentCwd !== undefined && childCwd !== undefined) {
                if (parentCwd !== childCwd) {
                  // Conflict: child already had its own cwd that
                  // disagrees with the parent's pre-clone cwd.
                  //
                  // Codex follow-up (high, 2026-05-19): in the
                  // pending-detach-AND-CLONE_FS case
                  // (`pendingDetachShared`), the real kernel order was:
                  //
                  //   1. clone(CLONE_FS) — parent + child share fs_struct.
                  //   2. one of them chdir(<...>) — mutation hits the
                  //      shared struct, BOTH observe the new cwd.
                  //   3. child unshare(CLONE_FS|CLONE_NEWUSER|...) —
                  //      kernel splits the struct into two private
                  //      copies whose initial state equals the shared
                  //      state at unshare-time.
                  //
                  // When strace surfaces these lines out of order and
                  // we end up reconciling at step (1) with parent
                  // and child already holding DIFFERENT cwds, we
                  // cannot recover the post-step-2 shared value from
                  // the modeled per-side values: parent's modeled cwd
                  // is whatever it had pre-share, child's is whatever
                  // it had post-share (or vice versa).  The correct
                  // semantic is that BOTH sides should now hold the
                  // SAME value (the shared one at unshare time), but
                  // we don't know what it was.  Taint BOTH groups to
                  // UNKNOWN: fail closed for AT_FDCWD-relative opens
                  // until each side re-establishes its cwd via an
                  // absolute chdir.
                  //
                  // In the non-pending case (plain fork without
                  // CLONE_FS) — or in the pending-detach-but-clone-
                  // WITHOUT-CLONE_FS case (codex bug #3) — parent and
                  // child were never shared at kernel level, so a
                  // disagreement just means the child raced ahead with
                  // its own chdir; only the child needs tainting and
                  // the parent's modeled cwd remains trustworthy.
                  cwdDelete(childPid);
                  cwdUnknownAdd(childPid);
                  if (pendingDetachShared) {
                    cwdDelete(pid);
                    cwdUnknownAdd(pid);
                  }
                }
                // else: equal — leave child's value in place.
              } else if (parentCwd !== undefined && currentChildCwd === undefined) {
                // Child has no cwd of its own (neither at detach time
                // nor now) — seed the child's private group from the
                // parent.  This is the canonical kernel-clone+private-
                // copy semantic.  Note: we guard on CURRENT child cwd
                // (not snapshot) because a child that chdir'd AFTER
                // unshare has its own cwd value we must preserve.
                cwdSet(childPid, parentCwd);
              }
              // else: parent has no known cwd; OR child has its own
              // post-detach cwd that we leave alone (private mutation
              // semantic per kernel detach).
            }

            // --- fd group: union if CLONE_FILES, else copy. ---------
            if (cloneFiles && !childHadPendingFdDetach) {
              unionFd(pid, childPid);
              // No per-key copy needed — fd lookups resolve to the
              // shared group root.
              //
              // Codex follow-up (high, 2026-05-19, bug #2 final):
              // marker-less standalone tombstone replay.  When the
              // child did close/close_range/F_SETFD on UNTRACKED
              // inherited fds BEFORE the parent's clone line surfaced
              // — and never followed up with an unshare/execve marker
              // — the kernel ALREADY mutated the shared files_struct
              // (CLONE_FILES is real at the kernel level).  Pre-fix
              // these tombstones were discarded silently; parent's
              // openat(<fd>, ...) then resolved through a stale
              // inherited entry.  Apply tombstones to the now-unified
              // group with shared-kernel propagation: closes drop
              // entries and mark fd-unknown both sides, cloexec marks
              // the entry cloexec=true on both sides, range close
              // drops in [first,last] on both sides.
              if (standaloneFdTombstones !== undefined && standaloneFdTombstones.length > 0) {
                const mergedRoot = rootedFd(pid);
                const groupPrefix = `${mergedRoot}:`;
                // Codex follow-up (high, 2026-05-19, pass 52 finding 2 —
                // pre-marker sibling tombstones not durable through later
                // P→C reconciliation): if the merged fd-group root holds
                // a pending fd-detach marker (e.g. the marker owner is C
                // and we are unioning a sibling G into C), the standalone
                // tombstones G recorded BEFORE the C clone(=G) line
                // surfaced are kernel-real mutations that happened AFTER
                // C's marker was seeded.  Applying them only against the
                // current dirfdTable is insufficient because the entries
                // they describe may not exist yet — they will be copied
                // in later by the delayed P→C reconciliation walking C's
                // marker.  Push the tombstones into the marker's
                // postDetachLog so the future replay drops the parent-
                // copied entries (close), flips cloexec, or surgically
                // delete/cloexec range entries.  Doing this BEFORE the
                // immediate direct application below preserves both
                // effects: the marker captures the future-replay copy,
                // and the direct application handles fds that already
                // exist in the merged root pre-P→C.
                const mergedSnap = pendingFdDetach.get(mergedRoot);
                if (mergedSnap !== undefined) {
                  for (const tomb of standaloneFdTombstones) {
                    mergedSnap.postDetachLog.push({ kind: 'tombstone', tombstone: tomb });
                  }
                }
                for (const tomb of standaloneFdTombstones) {
                  if (tomb.kind === 'close') {
                    dirfdTable.delete(`${groupPrefix}${tomb.fd}`);
                    fdUnknownAdd(pid);
                    fdUnknownAdd(childPid);
                  } else if (tomb.kind === 'cloexec') {
                    const key = `${groupPrefix}${tomb.fd}`;
                    const cur = dirfdTable.get(key);
                    if (cur !== undefined) {
                      dirfdTable.set(key, { path: cur.path, cloexec: true });
                    }
                  } else {
                    // closeRange tombstone — drop / mark cloexec
                    // entries in [first, last] on the unified group.
                    let touched = false;
                    for (const k of [...dirfdTable.keys()]) {
                      if (!k.startsWith(groupPrefix)) continue;
                      const fdStr = k.slice(groupPrefix.length);
                      const fdNum = parseInt(fdStr, 10);
                      if (
                        Number.isFinite(fdNum) &&
                        fdNum >= tomb.first &&
                        fdNum <= tomb.last
                      ) {
                        if (tomb.cloexec) {
                          const cur = dirfdTable.get(k);
                          if (cur !== undefined) {
                            dirfdTable.set(k, { path: cur.path, cloexec: true });
                          }
                        } else {
                          dirfdTable.delete(k);
                        }
                        touched = true;
                      }
                    }
                    if (touched && !tomb.cloexec) {
                      fdUnknownAdd(pid);
                      fdUnknownAdd(childPid);
                    }
                  }
                }
              }
            } else {
              // Copy branch: independent fd table.  Either the parent
              // did NOT set CLONE_FILES OR the child later unshared
              // its files_struct.  Sweep over the parent's keys and
              // re-key into the child's NEW fd group.  `fdKey(parent,
              // fd)` resolves to `<parentRoot>:<fd>`; `fdKey(child,
              // fd)` resolves to `<childRoot>:<fd>` (the child is its
              // own root pre-sweep because we haven't unioned it).
              //
              // Conflict reconciliation: if the child has already
              // observed its own fd entries (e.g. an out-of-order
              // openat before this clone reconciliation), reconcile
              // per fd:
              //   - parent-only fd → copy.
              //   - same fd, same path → keep child's entry; OR the
              //     cloexec bits so the next exec is conservative.
              //   - same fd, different paths → drop the entry (fail
              //     closed on subsequent openat(<fd>, ...)).
              const parentRoot = rootedFd(pid);
              const childRoot = rootedFd(childPid);
              if (parentRoot !== childRoot) {
                const parentPrefix = `${parentRoot}:`;
                const childPrefix = `${childRoot}:`;
                // Codex follow-up (high, 2026-05-19, bug #3): the
                // pending-detach parent-taint gate is BOTH:
                //   1. `childHadPendingFdDetach` — the child observed
                //      an unshare AND we recorded a marker for the
                //      delayed reconciliation;
                //   2. `cloneFiles` — the deferred clone actually had
                //      CLONE_FILES (parent + child shared the
                //      files_struct at kernel level pre-unshare).
                // Without (2), the parent's fd table was never shared
                // with the child; only the child's per-side state
                // needs reconciling and the parent's modeled fds
                // remain trustworthy.
                const fdPendingDetachShared = childHadPendingFdDetach && cloneFiles;
                // Codex follow-up (medium, 2026-05-19, bug #2): when
                // a snapshot is present, parent-taint decisions use
                // the SNAPSHOT (state at detach time) — NOT the
                // child's current state.  Child mutations that
                // happened AFTER unshare are private to the child's
                // group; they didn't propagate to the parent under
                // shared CLONE_FILES and so cannot taint the parent.
                //
                // Build a map of snapshot entries (fdSuffix → entry)
                // for O(1) snapshot lookup during conflict detection.
                const snapEntries = new Map<string, { path: string; cloexec: boolean }>();
                if (childFdSnap !== undefined) {
                  for (const [k, v] of childFdSnap.entries) snapEntries.set(k, v);
                }
                const snapUnknown =
                  childFdSnap !== undefined ? childFdSnap.unknown : fdUnknownHas(childPid);
                // The "effective child unknown" used for parent-taint
                // is the snapshot bit when present; otherwise the
                // current bit (covers the no-marker copy-branch case
                // — e.g. plain fork without CLONE_FILES).
                const childFdUnknownPre = fdPendingDetachShared
                  ? snapUnknown
                  : fdUnknownHas(childPid);
                // First pass: detect parent-vs-snapshot conflicts (for
                // parent-taint).  We can't compute this from the copy
                // pass below because the copy pass examines the
                // child's CURRENT state, which may include post-detach
                // mutations invisible to the parent at kernel level.
                let snapshotConflict = false;
                if (fdPendingDetachShared) {
                  for (const [fdSuffix, snapVal] of snapEntries) {
                    const parentKey = `${parentPrefix}${fdSuffix}`;
                    const parentVal = dirfdTable.get(parentKey);
                    if (parentVal !== undefined && parentVal.path !== snapVal.path) {
                      snapshotConflict = true;
                      break;
                    }
                  }
                }
                // Copy pass: iterate parent's fds, populate child's
                // group with parent's entries.  Child's CURRENT
                // entries are preserved (post-detach private copies).
                //
                // Conflict resolution per fd between parent and the
                // child's CURRENT entry:
                //   - parent-only fd → copy.
                //   - same fd, same path → keep child's entry; OR
                //     cloexec bits.
                //   - same fd, different paths → drop the child key
                //     (fail closed on subsequent openat(<fd>, ...)
                //     from the child).  Parent's entry is preserved
                //     unless the SNAPSHOT-based taint pass fires.
                // Codex adversarial pass 46 (high, 2026-05-19, bug
                // #7 — marker-less opaque-fd reuse): consult the
                // child group's opaque-reuse set BEFORE the copy
                // pass.  Unlike `childPostMarkerFdTouched` (which is
                // gated on a pending marker), `opaqueFdReuses` is
                // recorded unconditionally at every opaque-open
                // site — covering the no-marker delayed-clone case.
                const childOpaqueSet = opaqueFdReuses.get(childRoot);
                for (const [key, val] of dirfdTable) {
                  if (key.startsWith(parentPrefix)) {
                    const suffix = key.slice(parentPrefix.length);
                    const childKey = `${childPrefix}${suffix}`;
                    const existing = dirfdTable.get(childKey);
                    const fdNum = parseInt(suffix, 10);
                    const closedPostMarker =
                      Number.isFinite(fdNum) &&
                      childPostMarkerFdClosed !== undefined &&
                      childPostMarkerFdClosed.has(fdNum);
                    const opaqueReuse =
                      Number.isFinite(fdNum) &&
                      childOpaqueSet !== undefined &&
                      childOpaqueSet.has(fdNum);
                    if (existing === undefined) {
                      // Codex follow-up (high, 2026-05-19, bug #5 —
                      // post-marker close-of-reuse): if the child
                      // post-marker CLOSED this fd, the kernel's
                      // private group view is "closed".  Copying
                      // parent's stale shared-baseline entry in
                      // would resurrect a closed fd — subsequent
                      // child openat(<fd>, "x") would resolve
                      // through parent's path when the kernel
                      // returns EBADF.  Skip the copy; the child
                      // group key stays absent.
                      if (closedPostMarker) continue;
                      // Codex pass 45 follow-up (high, 2026-05-19,
                      // bug #6 — unresolved post-marker open): if the
                      // child's post-marker activity OPENED this fd
                      // through an unknown source (untracked dirfd or
                      // unknown cwd), there is NO modeled child entry
                      // but the kernel did install a fresh private fd.
                      // Copying parent's stale shared-baseline mapping
                      // would let a later child `openat(<fd>, ...)`
                      // certify through the parent's path — the same
                      // failure mode as the `existing.path !== val.path`
                      // branch below.  Skip the copy; subsequent child
                      // resolves via this fd will fail closed.
                      const reusedPostMarker =
                        Number.isFinite(fdNum) &&
                        childPostMarkerFdTouched !== undefined &&
                        childPostMarkerFdTouched.has(fdNum);
                      if (reusedPostMarker) continue;
                      // Codex adversarial pass 46 (high, 2026-05-19,
                      // bug #7 — marker-less opaque-fd reuse): same
                      // hazard as bug #6 but covers the no-marker
                      // case (child did NOT unshare before its
                      // opaque open).  An opaque-reuse marker
                      // signals the kernel-installed fd at this
                      // number is opaque; the parent's same-numbered
                      // entry must not be copied.
                      if (opaqueReuse) continue;
                      dirfdTable.set(childKey, val);
                    } else if (existing.path === val.path) {
                      // Same fd, same path — keep, OR cloexec bits.
                      if (existing.cloexec !== val.cloexec) {
                        dirfdTable.set(childKey, {
                          path: existing.path,
                          cloexec: existing.cloexec || val.cloexec,
                        });
                      }
                    } else {
                      // Codex follow-up (high, 2026-05-19, bug #3 —
                      // post-marker fd reuse): if the child's fd was
                      // reopened AFTER the unshare/exec marker, the
                      // child's entry reflects a private post-detach
                      // open and is authoritative for the child side.
                      // Keep it; the parent's stale-shared mapping at
                      // the same fd was already dropped (or about to
                      // be) by the pre-detach tombstone replay.
                      const reusedPostMarker =
                        Number.isFinite(fdNum) &&
                        childPostMarkerFdTouched !== undefined &&
                        childPostMarkerFdTouched.has(fdNum);
                      if (reusedPostMarker) {
                        continue;
                      }
                      // Marker-less opaque reuse: same reasoning —
                      // child's modeled entry (if any) supersedes a
                      // conflicting parent path because the kernel
                      // installed a fresh private fd at this number.
                      if (opaqueReuse) continue;
                      // Same fd, different paths — fail closed on the
                      // child side.  This handles plain fork conflicts
                      // (no pending marker — child raced ahead with
                      // its own opens).
                      dirfdTable.delete(childKey);
                    }
                  }
                }
                // Parent-taint: drop parent fd entries that conflict
                // with the SNAPSHOT under pendingDetachShared.  The
                // real-kernel order was clone(CLONE_FILES) → shared
                // mutation → unshare; the shared mutation made
                // parent's modeled value stale.
                if (fdPendingDetachShared && snapshotConflict) {
                  for (const [fdSuffix, snapVal] of snapEntries) {
                    const parentKey = `${parentPrefix}${fdSuffix}`;
                    const parentVal = dirfdTable.get(parentKey);
                    if (parentVal !== undefined && parentVal.path !== snapVal.path) {
                      dirfdTable.delete(parentKey);
                    }
                  }
                  fdUnknownAdd(pid);
                  fdUnknownAdd(childPid);
                }
                // Codex pass 47 follow-up (high, 2026-05-19, bug #1 —
                // pre-detach opaque reuse not replayed against the
                // parent): under shared CLONE_FILES the child's
                // PRE-marker opaque opens mutated the SHARED files_
                // struct, so the parent's same-numbered entries are
                // stale.  Drop them.  This is the symmetric pass to
                // the snapshot-entries conflict drop above — that one
                // handles "child opened a known path that conflicts
                // with parent's", this one handles "child opened an
                // opaque path that we couldn't model but the kernel
                // installed at fd N".
                //
                // Skip when the child has a fresh POST-marker mapping
                // at the same fd: the post-marker open is in the
                // child's private group (already private at that
                // point) and tells us nothing about the parent's
                // pre-detach state.  The pre-detach opaque marker is
                // what matters for the parent's view.
                if (
                  fdPendingDetachShared &&
                  childFdSnap !== undefined &&
                  childFdSnap.preDetachOpaque.size > 0
                ) {
                  for (const fd of childFdSnap.preDetachOpaque) {
                    dirfdTable.delete(`${parentPrefix}${fd}`);
                  }
                }
                if (fdUnknownHas(pid)) {
                  fdUnknownAdd(childPid);
                }
                // Codex follow-up (high, 2026-05-19, bug #2 fix part B):
                // child-group fd-state-unknown taints the parent under
                // the pending-detach-AND-CLONE_FILES gate.  The
                // motivating sequence:
                //
                //   1. parent:   openat → fd 7 = /safe
                //   2. (kernel)  clone(CLONE_FILES) — share files_struct
                //   3. child:    dup2(<untracked>, 7) — kernel rewrites
                //                shared fd 7 to point at <opaque>; our
                //                dup-untracked handler set
                //                `dirfdStateUnknown` on the child group.
                //   4. child:    unshare(CLONE_FILES) — kernel detach.
                //   5. strace surfaces clone line LAST → we reach here.
                //
                // Pre-fix, the copy loop saw no parent-vs-child fd
                // conflict (child had no modeled fd 7 entry — the dup
                // deleted it), so parent's fd 7 → /safe persisted and
                // a subsequent parent openat(7, ".ssh/id_rsa", ...)
                // resolved to /safe/.ssh/id_rsa, missing the
                // protected-paths match in the kernel-real target.
                //
                // Drop parent's fd entries we just copied (so the next
                // openat(<fd>, ...) finds no entry) AND mark BOTH
                // groups fd-unknown so `canonicalize*` returns null
                // for any numeric-dirfd open.
                if (fdPendingDetachShared && childFdUnknownPre) {
                  for (const key of [...dirfdTable.keys()]) {
                    if (key.startsWith(parentPrefix)) dirfdTable.delete(key);
                  }
                  fdUnknownAdd(pid);
                  fdUnknownAdd(childPid);
                }
                // Codex follow-up (medium, 2026-05-19, bug #3) + (high,
                // 2026-05-19, bug #1 + #2): apply tombstones FIRST then
                // replay detach-time actions in order onto the child's
                // private group AFTER the copy.
                //
                // Bug #1: pre-fix the singleton-pending-fd-detach path
                // stored ONE action and a later detach overwrote it.
                // Now we replay the full ordered LIST so a
                // close_range UNSHARE followed by an execve replays
                // both — the closed fds stay closed, and the CLOEXEC
                // sweep runs on what remains.
                //
                // Bug #2: tombstones record close / cloexec mutations
                // done on UNTRACKED fds during the singleton window.
                // After copying parent state in, replay them so the
                // child's copied fds reflect kernel reality.  For
                // 'close' tombstones, we ALSO drop the parent's
                // matching entry (the shared mutation propagated to
                // the parent under CLONE_FILES) and mark BOTH groups
                // fd-unknown for that fd.
                if (childFdSnap !== undefined && childHadPendingFdDetach) {
                  const childGroupPrefix = `${rootedFd(childPid)}:`;
                  // Codex follow-up (medium, 2026-05-19, bug #3 +
                  // high, bug #1 follow-up): tombstones split into
                  // PRE-detach (applied to BOTH parent and child copy
                  // under shared CLONE_FILES — kernel mutation hit the
                  // shared files_struct and propagated to the parent)
                  // and POST-detach (applied to child copy only — the
                  // kernel had already unshared by then so the
                  // mutation is private).
                  //
                  // Replay order:
                  //   1. preDetachTombstones (parent + child copy under
                  //      fdPendingDetachShared, else child-only)
                  //   2. postDetachLog — interleaved actions and post-
                  //      detach tombstones in OBSERVED order (child
                  //      copy only).  Single-pass walk preserves the
                  //      kernel-observed ordering so a CLOEXEC
                  //      tombstone followed by an execveCloexec
                  //      action correctly marks-then-sweeps.
                  // Codex follow-up (high, 2026-05-19, bug #3 — post-
                  // marker fd reuse exclusion): child-side tombstone
                  // replay (whether pre-detach OR post-detach) must
                  // skip fds the child reopened AFTER its
                  // unshare/exec marker was recorded.  Those reopens
                  // installed fresh private fds in the child's
                  // post-detach group; the kernel-shared tombstone
                  // describes a pre-unshare mutation and does NOT
                  // apply to the post-marker private reopen.  Parent-
                  // side replay (shared-files_struct propagation) is
                  // unaffected — the kernel did close/cloexec the
                  // parent's shared view at pre-unshare time, and any
                  // subsequent post-unshare reopen happened in the
                  // CHILD's private group, not the parent's.
                  //
                  // Codex follow-up (high, 2026-05-19, bug #5 —
                  // post-marker close-of-reuse): exclude both
                  // 'open' AND 'closed' post-marker fds from child-
                  // side tombstone replay.  For 'closed' fds, the
                  // child's view is already concretely known (the
                  // post-marker close left the child's dirfdTable
                  // key absent); replaying a pre-detach close would
                  // be a no-op for deletion but `applyPointTombstone`
                  // also taints `childPid`'s fd-group unknown bit,
                  // which would over-taint a child whose view of
                  // the kernel-closed fd is unambiguous.  Same
                  // reasoning for range tombstones.
                  const childReuseExclude = childPostMarkerFdTouched;
                  const applyPointTombstone = (
                    fd: number,
                    kind: 'close' | 'cloexec',
                    toParent: boolean,
                    toChild: boolean,
                  ): void => {
                    const childKey = `${childGroupPrefix}${fd}`;
                    const parentKey = `${parentPrefix}${fd}`;
                    if (kind === 'close') {
                      if (toChild) dirfdTable.delete(childKey);
                      if (toParent) {
                        dirfdTable.delete(parentKey);
                        // Parent group-taint always applies under
                        // shared CLONE_FILES — preserves historic
                        // conservative semantics for inherited fds
                        // we may not have modeled.
                        fdUnknownAdd(pid);
                        // Codex follow-up (high, 2026-05-19, bug #3 —
                        // post-marker fd reuse): when the child has a
                        // KNOWN post-marker reopen for this fd, skip
                        // the CHILD group-wide taint — the kernel-
                        // shared close affected only this specific
                        // fd, and the child has a fresh private
                        // mapping for it.  Tainting the child group-
                        // wide would clobber the very mapping we're
                        // trying to preserve.  Without the post-
                        // marker reuse signal (toChild=true) we keep
                        // the historic conservative child taint.
                        if (toChild) {
                          fdUnknownAdd(childPid);
                        }
                      }
                    } else {
                      // cloexec — flip the child's copied entry; under
                      // shared CLONE_FILES the kernel ALSO set
                      // FD_CLOEXEC on the parent's view of the shared
                      // fd, so flip the parent's entry too.  The
                      // parent's next execve sweep then drops it.
                      if (toChild) {
                        const cur = dirfdTable.get(childKey);
                        if (cur !== undefined) {
                          dirfdTable.set(childKey, { path: cur.path, cloexec: true });
                        }
                      }
                      if (toParent) {
                        const pcur = dirfdTable.get(parentKey);
                        if (pcur !== undefined) {
                          dirfdTable.set(parentKey, { path: pcur.path, cloexec: true });
                        }
                      }
                    }
                  };
                  const applyRangeTombstone = (
                    first: number,
                    last: number,
                    cloexec: boolean,
                    toParent: boolean,
                    toChild: boolean,
                    excludeChildFds: Set<number> | undefined,
                  ): void => {
                    // Iterate copied entries in the child group within
                    // [first, last] — skipping any fd in
                    // `excludeChildFds` (post-marker private reopens).
                    if (toChild) {
                      for (const k of [...dirfdTable.keys()]) {
                        if (!k.startsWith(childGroupPrefix)) continue;
                        const fdStr = k.slice(childGroupPrefix.length);
                        const fdNum = parseInt(fdStr, 10);
                        if (
                          Number.isFinite(fdNum) &&
                          fdNum >= first &&
                          fdNum <= last &&
                          (excludeChildFds === undefined || !excludeChildFds.has(fdNum))
                        ) {
                          if (cloexec) {
                            const cur = dirfdTable.get(k);
                            if (cur !== undefined) {
                              dirfdTable.set(k, { path: cur.path, cloexec: true });
                            }
                          } else {
                            dirfdTable.delete(k);
                          }
                        }
                      }
                    }
                    if (toParent) {
                      let touched = false;
                      let onlyExcludedTouched = true;
                      for (const k of [...dirfdTable.keys()]) {
                        if (!k.startsWith(parentPrefix)) continue;
                        const fdStr = k.slice(parentPrefix.length);
                        const fdNum = parseInt(fdStr, 10);
                        if (
                          Number.isFinite(fdNum) &&
                          fdNum >= first &&
                          fdNum <= last
                        ) {
                          if (cloexec) {
                            const cur = dirfdTable.get(k);
                            if (cur !== undefined) {
                              dirfdTable.set(k, { path: cur.path, cloexec: true });
                            }
                          } else {
                            dirfdTable.delete(k);
                          }
                          touched = true;
                          if (
                            excludeChildFds === undefined ||
                            !excludeChildFds.has(fdNum)
                          ) {
                            onlyExcludedTouched = false;
                          }
                        }
                      }
                      // Codex follow-up (high, 2026-05-19, bug #3 —
                      // post-marker fd reuse): skip the group-wide
                      // child taint when every fd touched by this
                      // range tombstone has a post-marker reopen on
                      // the child side.  The child's view of those
                      // fds is concretely known (the reopen
                      // established a fresh private mapping); the
                      // kernel-shared close affected only those
                      // specific fds, so other fds in the child
                      // group remain trustworthy.  Parent taint is
                      // unchanged (the kernel did mutate parent's
                      // shared view of those fds).
                      if (touched && !cloexec) {
                        fdUnknownAdd(pid);
                        if (!onlyExcludedTouched) {
                          fdUnknownAdd(childPid);
                        }
                      }
                    }
                  };
                  // (1) Pre-detach tombstones.  Parent side gets every
                  // tombstone unconditionally under fdPendingDetach-
                  // Shared (kernel mutated the shared files_struct
                  // pre-unshare).  Child side EXCLUDES fds reopened
                  // post-marker — those are private to the child's
                  // post-detach group and the kernel did not clobber
                  // them at pre-unshare time.
                  for (const tomb of childFdSnap.preDetachTombstones) {
                    if (tomb.kind === 'close' || tomb.kind === 'cloexec') {
                      const childExcluded =
                        childReuseExclude !== undefined &&
                        childReuseExclude.has(tomb.fd);
                      applyPointTombstone(
                        tomb.fd,
                        tomb.kind,
                        fdPendingDetachShared,
                        !childExcluded,
                      );
                    } else {
                      // closeRange tombstone (bug #2 follow-up): range
                      // close / CLOEXEC mark replayed against parent +
                      // child copy under shared CLONE_FILES.  Child
                      // side iterates per-fd and honours the exclude
                      // set inline (bug #3 follow-up).
                      applyRangeTombstone(
                        tomb.first,
                        tomb.last,
                        tomb.cloexec,
                        fdPendingDetachShared,
                        true,
                        childReuseExclude,
                      );
                    }
                  }
                  // (2) Interleaved post-detach log — actions and
                  // post-detach tombstones replayed in OBSERVED order,
                  // child copy only.
                  //
                  // Codex follow-up (high, 2026-05-19, bug #1 final):
                  // pre-fix the reconciler walked actions and post-
                  // detach tombstones in two separate phases (all
                  // actions, then all tombstones).  A CLOEXEC
                  // tombstone observed BEFORE a subsequent execveCloexec
                  // action ended up applied AFTER the sweep, leaving
                  // the entry intact.  Fix: single-pass walk over the
                  // interleaved log preserves the kernel-observed
                  // ordering — CLOEXEC mark applied first, sweep
                  // drops it.
                  //
                  // Post-detach mutations MUST NOT taint the parent
                  // (the kernel had already unshared by then), so
                  // tombstones in this phase pass `toParent=false`.
                  for (const entry of childFdSnap.postDetachLog) {
                    if (entry.kind === 'action') {
                      const action = entry.action;
                      if (action.kind === 'closeRange') {
                        for (const k of [...dirfdTable.keys()]) {
                          if (!k.startsWith(childGroupPrefix)) continue;
                          const fdStr = k.slice(childGroupPrefix.length);
                          const fdNum = parseInt(fdStr, 10);
                          if (
                            Number.isFinite(fdNum) &&
                            fdNum >= action.first &&
                            fdNum <= action.last
                          ) {
                            if (action.cloexec) {
                              const cur = dirfdTable.get(k);
                              if (cur !== undefined) {
                                dirfdTable.set(k, { path: cur.path, cloexec: true });
                              }
                            } else {
                              dirfdTable.delete(k);
                            }
                          }
                        }
                      } else if (action.kind === 'execveCloexec') {
                        // Codex follow-up (high, 2026-05-19, bug #4 —
                        // generation-aware execveCloexec): sweep
                        // every cloexec=true entry in the child copy
                        // EXCEPT those in this action's exclude set.
                        // The exclude set accumulates fds reopened
                        // AFTER this exec via
                        // `recordPostMarkerFdReuse`; the kernel only
                        // sweeps fds that existed at exec-time, so
                        // post-exec reopens must survive.
                        for (const k of [...dirfdTable.keys()]) {
                          if (!k.startsWith(childGroupPrefix)) continue;
                          const fdStr = k.slice(childGroupPrefix.length);
                          if (action.excludeFds.has(fdStr)) continue;
                          const ent = dirfdTable.get(k);
                          if (ent !== undefined && ent.cloexec) {
                            dirfdTable.delete(k);
                          }
                        }
                      }
                      // action.kind === 'none' (plain unshare(CLONE_FILES))
                      // → no replay needed.
                    } else {
                      const tomb = entry.tombstone;
                      // Post-detach tombstones replay against the
                      // CHILD copy only (toParent=false).  Like pre-
                      // detach, post-marker fd reuses must NOT be
                      // clobbered on the child side — a tombstone
                      // queued AFTER the marker followed by a reopen
                      // AFTER the tombstone is already cancelled via
                      // cancelPendingTombstonesForFd at the reopen
                      // site, but range tombstones queued AFTER the
                      // marker AND containing a fd reopened later
                      // also need exclusion.  We funnel everything
                      // through the same exclude set for safety.
                      if (tomb.kind === 'close' || tomb.kind === 'cloexec') {
                        const childExcluded =
                          childReuseExclude !== undefined &&
                          childReuseExclude.has(tomb.fd);
                        applyPointTombstone(tomb.fd, tomb.kind, false, !childExcluded);
                      } else {
                        applyRangeTombstone(
                          tomb.first,
                          tomb.last,
                          tomb.cloexec,
                          false,
                          true,
                          childReuseExclude,
                        );
                      }
                    }
                  }
                }
                // Codex follow-up (high, 2026-05-19, bug #2 final):
                // marker-less standalone tombstones in the COPY branch.
                // The clone had no CLONE_FILES (cloneFiles=false) OR
                // the child had no pending fd detach marker on the
                // copy side — but the child still recorded pre-marker
                // tombstones from singleton close/close_range/F_SETFD
                // on UNTRACKED fds.
                //
                // Because cloneFiles is false here, the kernel did NOT
                // share files_struct at clone time; the child's
                // pre-marker close/close_range happened on its private
                // pre-clone fd table.  Tombstones apply to the child's
                // copied entries only — parent is untainted.
                if (
                  standaloneFdTombstones !== undefined &&
                  standaloneFdTombstones.length > 0
                ) {
                  const childGroupPrefix = `${rootedFd(childPid)}:`;
                  for (const tomb of standaloneFdTombstones) {
                    if (tomb.kind === 'close') {
                      dirfdTable.delete(`${childGroupPrefix}${tomb.fd}`);
                    } else if (tomb.kind === 'cloexec') {
                      const key = `${childGroupPrefix}${tomb.fd}`;
                      const cur = dirfdTable.get(key);
                      if (cur !== undefined) {
                        dirfdTable.set(key, { path: cur.path, cloexec: true });
                      }
                    } else {
                      for (const k of [...dirfdTable.keys()]) {
                        if (!k.startsWith(childGroupPrefix)) continue;
                        const fdStr = k.slice(childGroupPrefix.length);
                        const fdNum = parseInt(fdStr, 10);
                        if (
                          Number.isFinite(fdNum) &&
                          fdNum >= tomb.first &&
                          fdNum <= tomb.last
                        ) {
                          if (tomb.cloexec) {
                            const cur = dirfdTable.get(k);
                            if (cur !== undefined) {
                              dirfdTable.set(k, { path: cur.path, cloexec: true });
                            }
                          } else {
                            dirfdTable.delete(k);
                          }
                        }
                      }
                    }
                  }
                }
              }
            }

            // shim-load propagation — the parent's address-space mapping
            // of /lib/libscriptjail.so is shared with the child until
            // the child execve's (which clears the bit, see the
            // existing post-spawn handler below).  Address-space sharing
            // is governed by CLONE_VM, not CLONE_FS / CLONE_FILES; we
            // intentionally do NOT model CLONE_VM as a union because
            // the shim mapping is established at ld.so time (before any
            // user syscalls run) and our per-pid set is functionally
            // identical for shared and copied address spaces in our
            // use case.  Conservative copy here mirrors the historical
            // behaviour.
            if (shimLoadedPids.has(pid)) {
              shimLoadedPids.add(childPid);
            }

            // Audit-trust Finding (high, 2026-05-19): propagate the parent's
            // attribution snapshot to the child at clone time.  A short-
            // lived posix_spawnp child that execve()s a missing binary
            // (e.g. `gcc` not present in the rootfs) exits 127 within
            // microseconds — by the time the strace tailer processes the
            // `execve(...) = -2 ENOENT` line, the child pid is fully
            // reaped, so /proc/<childpid>/environ and
            // /proc/<childpid>/status both ENOENT and
            // `Attribution.attribute(childPid)` returns null.  Pre-fix the
            // spawn event was dropped at the `if (result === null) continue`
            // gate further down and `spawn_blocked` stayed empty for the
            // parent's package (cf. the spawns-gcc@1.0.0 e2e failure).  By
            // seeding the child's snapshot from the parent at clone time
            // (using the same write-once `recordAttribution` helper as
            // every other attribution-success site) the spawn-event
            // dispatcher's snapshot fallback can recover the parent's
            // pkg / lifecycle label.  Only propagate when the parent
            // actually has a snapshot — clone lines from pids without a
            // tracked attribution (e.g. unshare-detached pseudo-parents)
            // leave the child unattributed.
            //
            // Audit-trust follow-up (high, 2026-05-19): if the parent's
            // FIRST observed traced line is the clone itself (no prior
            // shim event, no prior raw execve), the snapshot map is
            // empty and a naive `attributionSnapshotByPid.get(pid)`
            // returns undefined — leaving the child unseeded.  In that
            // window the parent process is still alive (it must be — it
            // just executed clone successfully), so /proc/<parent>/
            // environ and status are readable and Attribution can walk
            // pid → ppid → env.  We synchronously sample the parent's
            // attribution here exactly the same way the regular
            // dispatch path samples a pid on first observation, record
            // it (so subsequent same-pid events reuse it), and use the
            // freshly-sampled snapshot to seed the child.  This closes
            // the clone-first-ordering hole identified by the Codex
            // audit-trust review of e5af2be: a short-lived ENOENT
            // child of a freshly-observed parent now surfaces in
            // spawn_blocked instead of being silently dropped.
            let parentAttrib = attributionSnapshotByPid.get(pid);
            if (parentAttrib === undefined) {
              const sampled = input.attribution.attribute(pid);
              if (sampled !== null) {
                recordAttribution(pid, sampled);
                parentAttrib = sampled;
              }
            }
            if (parentAttrib !== undefined) {
              recordAttribution(childPid, parentAttrib);
            }
          }
        }
        continue;
      }

      // Codex follow-up #2 (high, 2026-05-19): pre-parse fd-mutation
      // syscalls so the dirfdTable reflects the kernel's actual fd
      // table at the moment of the next openat.
      //
      // Strace wire formats:
      //   dup(oldfd)                     = newfd
      //   dup2(oldfd, newfd)             = newfd
      //   dup3(oldfd, newfd, flags)      = newfd
      //   close(fd)                      = 0       (or -1 EBADF, ignored)
      //   close_range(first, last, flags) = 0
      //
      // dup/dup2/dup3 — copy the dirfdTable entry from oldfd to newfd
      // (replacing any stale entry at newfd).  If oldfd has no entry,
      // we DELETE newfd to invalidate any prior mapping; the kernel
      // would still have a mapping there (fds are content-addressable
      // by the file table), but we don't know its directory target,
      // so the next openat(<newfd>, ...) MUST fail closed instead of
      // trusting a stale entry.
      //
      // close/close_range — delete the affected entries.  close_range
      // with last == UINT_MAX (4294967295) is the "close everything
      // above first" idiom; we iterate over existing entries rather
      // than the full integer range to avoid O(UINT_MAX) blowup.  We
      // also tolerate the EBADF case (rc != 0) for close: the syscall
      // returning EBADF means the fd wasn't open in the kernel, but
      // our dirfdTable might still have a stale entry from a prior
      // unobserved close — deleting on EBADF is no-op-safe.
      const dupMatch = line.match(
        /^(dup3?|dup2)\((-?\d+)(?:\s*,\s*(-?\d+))?(?:\s*,\s*([^)]*))?\)\s*=\s*(-?\d+)\b/,
      );
      if (dupMatch !== null) {
        const op = dupMatch[1] ?? '';
        const rc = parseInt(dupMatch[5] ?? '', 10);
        if (Number.isFinite(rc) && rc >= 0) {
          const oldFd = parseInt(dupMatch[2] ?? '', 10);
          const newFd = op === 'dup' ? rc : parseInt(dupMatch[3] ?? '', 10);
          if (Number.isFinite(oldFd) && Number.isFinite(newFd)) {
            // Codex pass 48 follow-up (high, 2026-05-19, bug #8 — dup2 no-op):
            // Linux dup2(fd, fd) is a no-op: the descriptor stays put with all
            // its flags (including FD_CLOEXEC) preserved.  Treating it as a
            // fresh install would clobber the cloexec bit (the strace line has
            // no flags arg for dup2) and run reuse bookkeeping inappropriately.
            // dup3(fd, fd, ...) returns EINVAL on Linux so the success path
            // cannot hit this case; the failed-syscall branch already handles
            // it correctly.  Special-case op === 'dup2' && oldFd === newFd here
            // so dirfdTable/tombstones/postMarkerFdReuses/opaqueFdReuses are
            // left untouched.
            if (op === 'dup2' && oldFd === newFd) {
              continue;
            }
            const oldKey = fdKey(pid, oldFd);
            const newKey = fdKey(pid, newFd);
            const oldVal = dirfdTable.get(oldKey);
            if (oldVal !== undefined) {
              // Audit-trust Finding (high, 2026-05-19, codex follow-up):
              // determine the new fd's CLOEXEC bit per dup-variant
              // semantics:
              //   - dup(oldfd) = newfd       — newfd cloexec=false
              //                                (POSIX: dup never sets
              //                                FD_CLOEXEC).
              //   - dup2(oldfd, newfd)        — newfd cloexec=false (same).
              //   - dup3(oldfd, newfd, flags) — newfd cloexec=true iff
              //                                flags contains O_CLOEXEC
              //                                (numeric bit 0o2000000 or
              //                                the symbolic token).
              let newCloexec = false;
              if (op === 'dup3') {
                const flagsTok = (dupMatch[4] ?? '').trim();
                if (flagsTok.length > 0) {
                  if (flagsTok.includes('O_CLOEXEC')) newCloexec = true;
                  else {
                    // Numeric form (decimal or hex).  O_CLOEXEC = 0o2000000.
                    const n = flagsTok.startsWith('0x')
                      ? parseInt(flagsTok, 16)
                      : flagsTok.startsWith('0o') || /^0\d/.test(flagsTok)
                        ? parseInt(flagsTok, 8)
                        : parseInt(flagsTok, 10);
                    if (Number.isFinite(n) && (n & 0o2000000) !== 0) newCloexec = true;
                  }
                }
              }
              dirfdTable.set(newKey, { path: oldVal.path, cloexec: newCloexec });
              // Codex follow-up (medium, 2026-05-19, bug #2 — stale-
              // tombstone-on-reopen): newfd now points at a valid
              // mapping; cancel any pre-marker tombstone targeting
              // this fd so the delayed-clone reconciler doesn't
              // delete the entry after unionFd merges it.
              cancelPendingTombstonesForFd(pid, newFd);
              // Codex follow-up (high, 2026-05-19, bug #3 — post-marker
              // fd reuse exclusion): if a marker is already pending,
              // a fresh dup install on `newFd` is a child-private
              // reopen AFTER the kernel-level unshare/exec.  Pre-
              // detach tombstones targeting `newFd` describe the
              // pre-unshare shared mutation; the child's reconciled
              // copy must EXCLUDE `newFd` from those tombstones.
              recordPostMarkerFdReuse(pid, newFd);
              // Codex pass 47 follow-up (high, 2026-05-19, bug #2 —
              // known dup reopens leave stale opaque markers): a
              // known-source dup installs a valid mapping at `newFd`
              // and supersedes any prior opaque-reuse marker (the
              // fd's directory target is now known again).  Mirrors
              // the canonicalized-open path which clears the marker
              // after installing a known mapping — without this,
              // `unionFd` would later DROP the just-installed entry
              // because the stale marker survived.
              clearOpaqueFdReuse(pid, newFd);
            } else {
              // oldfd has no tracked dir mapping → newfd must NOT
              // retain its previous mapping either (it now aliases
              // wherever oldfd actually points, which we don't know).
              dirfdTable.delete(newKey);
              // Codex follow-up (high, 2026-05-19, bug #2 fix part A):
              // mark the pid's fd-group as state-unknown.  The kernel
              // has installed a real fd at `newFd` whose directory
              // target is opaque to us (because the source oldfd was
              // never tracked).  Without this marker:
              //   1. parent: openat → fd 7 = /safe
              //   2. clone(CLONE_FILES) — child shares parent's table
              //   3. child: dup2(<untracked>, 7) — kernel rewrites
              //      shared fd 7 to point at <untracked-target>
              //   4. child: unshare(CLONE_FILES) — detach
              //   5. parent: openat(7, ...) — kernel resolves via
              //      <untracked-target>, model trusts /safe.
              // If strace surfaces (3)+(4) before the clone line in
              // (2), the pending-detach reconciliation needs a signal
              // that the child's fd table is no longer trustworthy —
              // this `fdUnknownAdd` is that signal.  The reconciliation
              // path consumes it to taint the parent's fd group too,
              // so parent's subsequent openat(7, ...) fails closed.
              fdUnknownAdd(pid);
              // Codex pass 47 follow-up (high, 2026-05-19, bug #2 —
              // untracked-source dup symmetry): mirror the
              // unresolved-open path.  The kernel installed a fresh
              // private fd at `newFd` whose directory target is
              // opaque — record the per-fd opaque marker so the
              // marker-less reconciler drops the parent's same-
              // numbered entry instead of trusting it.  Cancel any
              // pending tombstones targeting this fd for the same
              // reason as the known-source branch.
              cancelPendingTombstonesForFd(pid, newFd);
              recordPostMarkerFdReuse(pid, newFd);
              recordOpaqueFdReuse(pid, newFd);
            }
          }
        }
        continue;
      }
      const closeMatch = line.match(/^close\((-?\d+)\)\s*=\s*(-?\d+)\b/);
      if (closeMatch !== null) {
        const fd = parseInt(closeMatch[1] ?? '', 10);
        const rc = parseInt(closeMatch[2] ?? '', 10);
        if (Number.isFinite(fd)) {
          // Codex follow-up (high, 2026-05-19, bug #2): if the fd is
          // NOT in `dirfdTable`, the pid is currently a singleton, and
          // we're in the pre-detach window of an out-of-order delayed
          // clone (parent's clone(CLONE_FILES) line hasn't surfaced),
          // record a 'close' tombstone.  At delayed-clone reconciliation
          // the tombstone fires AFTER copying parent's fd table into
          // the child group, dropping the just-copied fd and tainting
          // both groups' fd-state-unknown for it (the shared-kernel
          // mutation propagates to the parent under CLONE_FILES).
          // Successful close only (rc === 0); EBADF means the fd
          // wasn't valid in the kernel and the inherited mapping
          // (if any) is unchanged.
          if (Number.isFinite(rc) && rc === 0) {
            const key = fdKey(pid, fd);
            if (!dirfdTable.has(key)) {
              recordFdTombstone(pid, { kind: 'close', fd });
            }
            // Codex follow-up (high, 2026-05-19, bug #5 — post-
            // marker close-of-reuse): if a marker is pending AND
            // this fd was a post-marker reuse, transition the
            // lifecycle entry from 'open' → 'closed'.  This signals
            // the reconciler's copy-pass to skip the parent's
            // stale shared-baseline entry instead of resurrecting
            // a kernel-closed fd in the child copy.
            recordPostMarkerFdClose(pid, fd);
            // Codex adversarial pass 46 (high, 2026-05-19, bug #7):
            // legitimate close drops any opaque-reuse marker for
            // this fd — the kernel slot is now empty and a future
            // open at the same fd number will install a fresh
            // (potentially canonicalizable) mapping.
            clearOpaqueFdReuse(pid, fd);
          }
          // Delete unconditionally: even on EBADF, our stale entry (if
          // any) is invalidated — the kernel's reply tells us the fd
          // is no longer valid for openat(<fd>, ...).
          dirfdTable.delete(fdKey(pid, fd));
        }
        continue;
      }
      // Codex follow-up (bug #3, high, 2026-05-19) + follow-up (high,
      // 2026-05-19, decimal-flag fix + CLOEXEC marking):
      // `close_range(2)` (Linux 5.9+) defines:
      //   CLOSE_RANGE_UNSHARE  — detach the caller's fd table from any
      //                          shared group BEFORE closing.
      //   CLOSE_RANGE_CLOEXEC  — set FD_CLOEXEC on the range instead of
      //                          closing.  We DO model this now: matching
      //                          dirfdTable entries are flipped to
      //                          cloexec=true so the next successful
      //                          execve sweeps them.
      // Strace renders the flags as either a `|`-separated identifier
      // list OR a numeric (hex/decimal) bitmask:
      //   close_range(3, 4294967295, CLOSE_RANGE_UNSHARE) = 0
      //   close_range(3, ~0U, CLOSE_RANGE_CLOEXEC|CLOSE_RANGE_UNSHARE) = 0
      //   close_range(3, 4294967295, 0) = 0
      //   close_range(3, 4294967295, 2) = 0        ← decimal UNSHARE
      //   close_range(3, 4294967295, 6) = 0        ← decimal CLOEXEC|UNSHARE
      //   close_range(3, 4294967295, 0x2) = 0      ← hex UNSHARE
      //   close_range(3, 4294967295) = 0           (no flags arg — older kernels)
      const closeRangeMatch = line.match(
        /^close_range\((-?\d+)\s*,\s*(-?\d+|0x[0-9a-fA-F]+|~?\d+U?)(?:\s*,\s*([^)]*))?\)\s*=\s*(-?\d+)\b/,
      );
      if (closeRangeMatch !== null) {
        const rc = parseInt(closeRangeMatch[4] ?? '', 10);
        if (Number.isFinite(rc) && rc === 0) {
          const first = parseInt(closeRangeMatch[1] ?? '', 10);
          const lastRaw = closeRangeMatch[2] ?? '';
          // Accept hex (0x...), decimal, and the strace `~0U` shorthand
          // for UINT_MAX (which some glibc builds emit instead of the
          // raw decimal 4294967295).
          let last: number;
          if (lastRaw.startsWith('0x')) {
            last = parseInt(lastRaw, 16);
          } else if (lastRaw === '~0U' || lastRaw === '~0' || lastRaw === '~0u') {
            last = 0xffffffff;
          } else {
            last = parseInt(lastRaw, 10);
          }
          // Parse flags token.  Three accepted forms (codex bug-fix:
          // decimal numeric was treated as the non-UNSHARE branch
          // pre-fix because the parser only checked the `0x` prefix
          // and the identifier-name set):
          //   1. symbolic list  — `CLOSE_RANGE_UNSHARE`,
          //                       `CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC`
          //   2. hex bitmask    — `0x2`, `0x6`
          //   3. decimal bitmask — `0`, `2`, `3`, `6`
          // In all three forms we compute the bitwise OR over
          //   CLOSE_RANGE_UNSHARE = 1<<1 = 0x2
          //   CLOSE_RANGE_CLOEXEC = 1<<2 = 0x4
          // and gate on each bit independently.
          const flagsStr = (closeRangeMatch[3] ?? '').trim();
          const CLOSE_RANGE_UNSHARE = 0x2;
          const CLOSE_RANGE_CLOEXEC = 0x4;
          let flagsBits = 0;
          if (flagsStr.length > 0) {
            if (/^[A-Z_|\s]+$/.test(flagsStr)) {
              // Identifier form (pure symbolic).
              for (const tok of flagsStr.split('|')) {
                const t = tok.trim();
                if (t === 'CLOSE_RANGE_UNSHARE') flagsBits |= CLOSE_RANGE_UNSHARE;
                else if (t === 'CLOSE_RANGE_CLOEXEC') flagsBits |= CLOSE_RANGE_CLOEXEC;
              }
            } else if (flagsStr.startsWith('0x')) {
              const n = parseInt(flagsStr, 16);
              if (Number.isFinite(n)) flagsBits = n;
            } else if (/^-?\d+$/.test(flagsStr)) {
              // Decimal numeric.  Pre-fix this branch was dead — the
              // identifier-form loop didn't match (`2` isn't a known
              // token) and the `0x`-prefix branch didn't either.  So
              // `close_range(3, 4294967295, 2) = 0` was treated as
              // hasUnshare=false and the dispatcher deleted shared-
              // group entries instead of detaching the caller.
              const n = parseInt(flagsStr, 10);
              if (Number.isFinite(n)) flagsBits = n;
            } else {
              // Mixed form (e.g. `CLOSE_RANGE_UNSHARE|0x4`): try both
              // identifier tokens and any hex/decimal tokens.
              for (const tok of flagsStr.split('|')) {
                const t = tok.trim();
                if (t === 'CLOSE_RANGE_UNSHARE') flagsBits |= CLOSE_RANGE_UNSHARE;
                else if (t === 'CLOSE_RANGE_CLOEXEC') flagsBits |= CLOSE_RANGE_CLOEXEC;
                else if (t.startsWith('0x')) {
                  const n = parseInt(t, 16);
                  if (Number.isFinite(n)) flagsBits |= n;
                } else if (/^-?\d+$/.test(t)) {
                  const n = parseInt(t, 10);
                  if (Number.isFinite(n)) flagsBits |= n;
                }
              }
            }
          }
          const hasUnshare = (flagsBits & CLOSE_RANGE_UNSHARE) !== 0;
          const hasCloexec = (flagsBits & CLOSE_RANGE_CLOEXEC) !== 0;
          if (Number.isFinite(first) && Number.isFinite(last) && first >= 0 && last >= first) {
            if (hasUnshare) {
              // Detach the caller into a private fd group BEFORE
              // closing.  Semantics: the kernel allocates a fresh
              // `struct files_struct` for the calling task, copies the
              // shared group's fd table into it, then performs the
              // close range on the private copy.  The old shared group
              // (now without this pid) keeps its full state intact —
              // siblings can still use any fds that were closed only
              // in the caller's new private group.
              //
              // Shared with unshare(CLONE_FILES) and execve via the
              // `detachFdGroup` helper above.
              //
              // Codex follow-up (medium, 2026-05-19, bug #3): if the
              // pid is a singleton at the moment we observe this line,
              // the immediate detach is a no-op AND the close_range
              // below mutates only the singleton group.  When the
              // parent's clone(CLONE_FILES) = <pid> line arrives later,
              // the reconciliation needs to know to (a) skip union,
              // (b) copy parent state into child, (c) replay this
              // close_range on the child's private group.  Snapshot
              // here so the reconciler can do (c).  If the pid is
              // NOT a singleton (multi-member group), the detach
              // actually does separate the group and no delayed
              // reconciliation is needed — the parent's clone has
              // already been processed.
              const fdSingleton = isFdSingleton(pid);
              const action: FdDetachAction = {
                kind: 'closeRange',
                first,
                last,
                cloexec: hasCloexec,
              };
              // Codex follow-up (high, 2026-05-19, bug #1): if a pending
              // marker already exists for this pid (e.g. a prior
              // unshare(CLONE_FILES) or close_range UNSHARE on the same
              // singleton), APPEND the action instead of overwriting.
              // The reconciler replays the list in order; overwriting
              // would lose the earlier mutation.
              let fdSnap: FdSnapshot | null = null;
              if (fdSingleton) {
                fdSnap = appendFdAction(pid, action);
                if (fdSnap === null) {
                  fdSnap = snapshotFd(pid, action);
                }
              }
              detachFdGroup(pid);
              // Apply the range against the caller's group (which is
              // either the brand-new private group or the original
              // singleton group).  CLOSE_RANGE_CLOEXEC and CLOSE_RANGE
              // (no CLOEXEC) differ in disposition: CLOEXEC marks the
              // fds for sweep at next exec instead of closing them now.
              const groupPrefix = `${rootedFd(pid)}:`;
              for (const key of [...dirfdTable.keys()]) {
                if (!key.startsWith(groupPrefix)) continue;
                const fdStr = key.slice(groupPrefix.length);
                const fd = parseInt(fdStr, 10);
                if (Number.isFinite(fd) && fd >= first && fd <= last) {
                  if (hasCloexec) {
                    // Mark cloexec=true; entry survives until the next
                    // successful execve sweep deletes it.
                    const cur = dirfdTable.get(key);
                    if (cur !== undefined) {
                      dirfdTable.set(key, { path: cur.path, cloexec: true });
                    }
                  } else {
                    dirfdTable.delete(key);
                  }
                }
              }
              if (fdSnap !== null) {
                pendingFdDetach.set(pid, fdSnap);
              }
              // Codex follow-up (high, 2026-05-19, bug #5 — post-
              // marker close-of-reuse, range form): if this
              // close_range is itself a post-marker action (i.e.,
              // `appendFdAction` found an existing marker rather
              // than seeding a fresh one), any post-marker reuse
              // fds in [first, last] just got closed by the kernel.
              // Transition their lifecycle entries 'open' → 'closed'
              // so the reconciler's copy-pass skips the parent's
              // stale entries for those fds.  CLOEXEC variant
              // doesn't close until the next execve; lifecycle
              // stays 'open' until then.
              if (!hasCloexec) {
                recordPostMarkerFdRangeClose(pid, first, last);
                // Codex adversarial pass 46 (high, 2026-05-19, bug
                // #7): legitimate close_range drops opaque-reuse
                // markers in the range — see the point-close site.
                clearOpaqueFdRange(pid, first, last);
              }
            } else {
              // Pre-existing behaviour: close the range on the caller's
              // (possibly shared) group.  Siblings observe the closes
              // (UNSHARE wasn't requested).  Iterate over the MAP
              // entries for this fd-group only — avoid O(last) work
              // when last is UINT_MAX (4294967295), the common "close
              // all fds above first" idiom.  Keys are formatted as
              // `<fdGroupRoot>:<fd>`, so we anchor on the resolved
              // root for this pid.
              //
              // Audit-trust Finding (high, 2026-05-19, codex follow-up):
              // honour CLOSE_RANGE_CLOEXEC even without UNSHARE.  The
              // kernel sets FD_CLOEXEC on each matched fd; we mark our
              // dirfdTable entries cloexec=true so the next successful
              // execve sweep drops them.  Pre-fix, our `0x4` /
              // `CLOSE_RANGE_CLOEXEC` branch was a no-op and the fds
              // survived our model indefinitely.
              const groupPrefix = `${rootedFd(pid)}:`;
              for (const key of [...dirfdTable.keys()]) {
                if (!key.startsWith(groupPrefix)) continue;
                const fdStr = key.slice(groupPrefix.length);
                const fd = parseInt(fdStr, 10);
                if (Number.isFinite(fd) && fd >= first && fd <= last) {
                  if (hasCloexec) {
                    const cur = dirfdTable.get(key);
                    if (cur !== undefined) {
                      dirfdTable.set(key, { path: cur.path, cloexec: true });
                    }
                  } else {
                    dirfdTable.delete(key);
                  }
                }
              }
              // Codex follow-up (high, 2026-05-19, bug #2): when the
              // caller is a singleton at observation time, the
              // dirfdTable iteration above only finds entries already
              // copied into the singleton's root group.  In delayed-
              // clone order (parent's clone(CLONE_FILES) line hasn't
              // arrived yet), inherited parent fds are NOT yet keyed
              // under the child's root — the iteration finds nothing
              // for those fds.  Record a RANGE tombstone so the
              // delayed-clone reconciliation can replay the close /
              // CLOEXEC mark against the parent-copied entries it
              // brings into the child group.  Range form avoids
              // enumerating UINT_MAX fds for the common "close all
              // above first" idiom.
              //
              // Codex follow-up (high, 2026-05-19, pass 52): no outer
              // singleton gate here — `recordFdTombstone` now resolves
              // the fd-group root FIRST and appends to a root-owned
              // marker's postDetachLog regardless of whether `pid` is
              // a singleton.  This is required for the CLONE_FILES
              // sibling scenario: P fd 7 = /safe; P clone(CLONE_FILES)
              // = C DELAYED; C unshare(CLONE_FILES) [marker on C]; C
              // clone(CLONE_FILES) = G; G close_range(7,7,0).  G is
              // non-singleton (G is C's CLONE_FILES sibling), but
              // `rootedFd(G) === C` and C owns the marker — so the
              // tombstone belongs in C's postDetachLog so that the
              // delayed P→C reconciliation does not resurrect the
              // copied P:7 in C/G.  The pre-marker bucket path inside
              // `recordFdTombstone` still preserves its singleton
              // semantic for the no-marker case.
              recordFdTombstone(pid, {
                kind: 'closeRange',
                first,
                last,
                cloexec: hasCloexec,
              });
              // Codex follow-up (high, 2026-05-19, bug #5 — post-
              // marker close-of-reuse, range form, no-UNSHARE
              // branch): mirrors the UNSHARE branch above.  When
              // this close_range is observed after a marker is
              // pending, any post-marker reuse fds in [first, last]
              // are now kernel-closed in the child's view; mark
              // them 'closed' so the reconciler's copy-pass skips
              // resurrecting them from the parent's stale entries.
              if (!hasCloexec) {
                recordPostMarkerFdRangeClose(pid, first, last);
                // Codex adversarial pass 46 (high, 2026-05-19, bug
                // #7): legitimate close_range drops opaque-reuse
                // markers in the range — see the point-close site.
                clearOpaqueFdRange(pid, first, last);
              }
            }
          }
        }
        continue;
      }

      // Codex follow-up (high, 2026-05-19): pre-parse `unshare(2)` so a
      // process can explicitly break its CLONE_FILES / CLONE_FS sharing
      // mid-run.  Pre-fix this syscall was invisible to the model: a
      // child that ran `clone(CLONE_FILES); unshare(CLONE_FILES)` and
      // then called `close(7)` would mutate the shared dirfdTable, so
      // a sibling's subsequent `openat(7, ...)` would fail closed even
      // though the kernel still had fd 7 valid in the sibling's table.
      // Same shape for CLONE_FS / chdir.
      //
      // Strace renders flags as either a `|`-separated identifier list
      // OR a numeric (hex/decimal) bitmask.  Linux defines many CLONE_*
      // bits; we model the explicit CLONE_FILES (0x400) and CLONE_FS
      // (0x200) bits AND the namespace bits that the kernel implicitly
      // unshares fs_struct for:
      //
      //   - CLONE_NEWNS   (0x20000)    → kernel implies CLONE_FS
      //   - CLONE_NEWUSER (0x10000000) → kernel implies CLONE_FS only
      //     (and CLONE_THREAD, which we don't model).  CLONE_NEWUSER
      //     does NOT imply CLONE_FILES — `kernel/fork.c::ksys_unshare`
      //     only calls `unshare_fd` when CLONE_FILES is explicitly set
      //     in the user-supplied flags.  See unshare(2).
      //
      // Pre-fix (earlier in this series) we only honored the literal
      // CLONE_FS / CLONE_FILES bits, so a process that ran
      // `clone(CLONE_FS); unshare(CLONE_NEWNS)` stayed modeled as
      // shared-cwd with the parent and subsequent chdirs on either
      // side leaked across the (kernel-detached) group.  An earlier
      // attempt over-corrected and treated CLONE_NEWUSER as implying
      // CLONE_FILES too; that detached the fd group when the kernel
      // actually keeps it shared, so later child dup/close stopped
      // propagating to the parent's modeled state.  This revision
      // matches the kernel: fd detach iff explicit CLONE_FILES.
      //
      // Wire formats:
      //   unshare(CLONE_FILES) = 0
      //   unshare(CLONE_FS|CLONE_FILES) = 0
      //   unshare(CLONE_NEWNS) = 0                ← implies CLONE_FS
      //   unshare(CLONE_NEWUSER) = 0              ← implies CLONE_FS only
      //   unshare(0x400) = 0                     ← hex CLONE_FILES
      //   unshare(0x20000) = 0                   ← hex CLONE_NEWNS
      //   unshare(1024) = 0                      ← decimal CLONE_FILES
      //   unshare(268435456) = 0                 ← decimal CLONE_NEWUSER
      //   unshare(CLONE_NEWUTS) = 0              ← unmodeled bit (no-op)
      //   unshare(CLONE_FILES) = -1 EINVAL       ← failure (no-op)
      const unshareMatch = line.match(/^unshare\(([^)]*)\)\s*=\s*(-?\d+)\b/);
      if (unshareMatch !== null) {
        const rc = parseInt(unshareMatch[2] ?? '', 10);
        if (Number.isFinite(rc) && rc === 0) {
          const flagsStr = (unshareMatch[1] ?? '').trim();
          const CLONE_FS = 0x200;
          const CLONE_FILES = 0x400;
          const CLONE_NEWNS = 0x20000;
          const CLONE_NEWUSER = 0x10000000;
          const parseSymbol = (t: string): number => {
            if (t === 'CLONE_FILES') return CLONE_FILES;
            if (t === 'CLONE_FS') return CLONE_FS;
            if (t === 'CLONE_NEWNS') return CLONE_NEWNS;
            if (t === 'CLONE_NEWUSER') return CLONE_NEWUSER;
            return 0;
          };
          let flagsBits = 0;
          if (flagsStr.length > 0) {
            if (/^[A-Z_|\s]+$/.test(flagsStr)) {
              // Pure symbolic identifier list.
              for (const tok of flagsStr.split('|')) {
                flagsBits |= parseSymbol(tok.trim());
              }
            } else if (flagsStr.startsWith('0x') || flagsStr.startsWith('0X')) {
              const n = parseInt(flagsStr, 16);
              if (Number.isFinite(n)) flagsBits = n;
            } else if (/^-?\d+$/.test(flagsStr)) {
              const n = parseInt(flagsStr, 10);
              if (Number.isFinite(n)) flagsBits = n;
            } else {
              // Mixed form (e.g. `CLONE_FILES|0x40000000`): OR over each
              // token using the union of identifier / hex / decimal
              // parsers above.
              for (const tok of flagsStr.split('|')) {
                const t = tok.trim();
                const sym = parseSymbol(t);
                if (sym !== 0) {
                  flagsBits |= sym;
                } else if (t.startsWith('0x') || t.startsWith('0X')) {
                  const n = parseInt(t, 16);
                  if (Number.isFinite(n)) flagsBits |= n;
                } else if (/^-?\d+$/.test(t)) {
                  const n = parseInt(t, 10);
                  if (Number.isFinite(n)) flagsBits |= n;
                }
              }
            }
          }
          // Kernel-implied detaches:
          //   CLONE_NEWNS    → implies CLONE_FS
          //   CLONE_NEWUSER  → implies CLONE_FS only (NOT CLONE_FILES;
          //                    see ksys_unshare in kernel/fork.c — fd
          //                    detach requires explicit CLONE_FILES).
          const detachCwd =
            (flagsBits & CLONE_FS) !== 0 ||
            (flagsBits & CLONE_NEWNS) !== 0 ||
            (flagsBits & CLONE_NEWUSER) !== 0;
          const detachFds = (flagsBits & CLONE_FILES) !== 0;
          if (detachFds) {
            // Codex follow-up (medium, 2026-05-19, bug #2): snapshot
            // the child's CURRENT fd state BEFORE detach.  The snapshot
            // captures what was visible to the parent under shared
            // CLONE_FILES at the unshare instant; post-unshare child
            // mutations stay private and don't leak into the reconciler.
            // unshare itself doesn't mutate the fd table (only detaches
            // it), so the replay action is 'none'.
            //
            // Codex follow-up (high, 2026-05-19, bug #1): if a prior
            // pending marker already exists for this pid, APPEND the
            // 'none' action so any later replay still sees the full
            // ordered list of detach mutations.  The first marker's
            // `entries` baseline (parent-shared state at first detach)
            // is preserved.
            const existing = appendFdAction(pid, { kind: 'none' });
            const fdSnap = existing ?? snapshotFd(pid, { kind: 'none' });
            detachFdGroup(pid);
            // Codex follow-up (high, 2026-05-19): record the intent.
            // If a later-arriving `clone(... CLONE_FILES ...) = <this
            // pid>` line is observed (out-of-order tail drain), the
            // clone reconciliation will SKIP `unionFd` instead of
            // re-merging the kernel-detached child back into the
            // parent's group.  The marker is consumed when the clone
            // line is reconciled; if no such clone arrives it stays
            // (harmless: pids aren't reused mid-run in practice).
            pendingFdDetach.set(pid, fdSnap);
          }
          if (detachCwd) {
            // Codex follow-up (medium, 2026-05-19, bug #2): snapshot
            // child's CURRENT cwd state BEFORE detach (parent-taint
            // decisions at reconcile time must use this, NOT the child's
            // post-unshare state).
            const cwdSnap = snapshotCwd(pid);
            detachCwdGroup(pid);
            pendingCwdDetach.set(pid, cwdSnap);
          }
        }
        continue;
      }

      // Audit-trust Finding (high, 2026-05-19, codex follow-up): pre-parse
      // fcntl/fcntl64 so the dirfdTable's CLOEXEC bookkeeping survives
      // FD_CLOEXEC mutations done outside of openat/dup3.  Strace wire
      // formats we recognise:
      //
      //   fcntl(7, F_DUPFD, 10) = 12              (newfd cloexec=false)
      //   fcntl(7, F_DUPFD_CLOEXEC, 10) = 12      (newfd cloexec=true)
      //   fcntl(7, F_SETFD, FD_CLOEXEC) = 0       (set fd 7's cloexec=true)
      //   fcntl(7, F_SETFD, 0) = 0                (clear fd 7's cloexec)
      //   fcntl(7, F_GETFD) = N                   (no state change)
      //   fcntl(7, F_GETFL) = N                   (no state change)
      //   fcntl(7, F_SETFL, ...) = 0              (no fd-table change)
      //
      // Any OTHER successful fcntl subcommand we don't recognise marks
      // the pid's fd-group dirfdStateUnknown — the kernel may have
      // mutated the fd state in a way we can't model.  Failures
      // (rc < 0) are a no-op.  fcntl64 has identical semantics on
      // 32-bit arches and is handled the same way.
      const fcntlMatch = line.match(
        /^(fcntl|fcntl64)\((-?\d+)\s*,\s*([A-Z_0-9]+)(?:\s*,\s*([^)]*))?\)\s*=\s*(-?\d+)\b/,
      );
      if (fcntlMatch !== null) {
        const fd = parseInt(fcntlMatch[2] ?? '', 10);
        const cmd = fcntlMatch[3] ?? '';
        const arg = (fcntlMatch[4] ?? '').trim();
        const rc = parseInt(fcntlMatch[5] ?? '', 10);
        if (Number.isFinite(fd) && Number.isFinite(rc) && rc >= 0) {
          const oldKey = fdKey(pid, fd);
          if (cmd === 'F_DUPFD' || cmd === 'F_DUPFD_CLOEXEC') {
            // Duplicate fd → newfd (`rc`) with explicit CLOEXEC behaviour.
            const oldVal = dirfdTable.get(oldKey);
            const newKey = fdKey(pid, rc);
            if (oldVal !== undefined) {
              dirfdTable.set(newKey, {
                path: oldVal.path,
                cloexec: cmd === 'F_DUPFD_CLOEXEC',
              });
              // Codex follow-up (medium, 2026-05-19, bug #2 — stale-
              // tombstone-on-reopen): cancel any pre-marker tombstone
              // targeting fd `rc` for this pid; mirrors the same fix
              // at the dup-family and openat success sites.
              cancelPendingTombstonesForFd(pid, rc);
              // Codex follow-up (high, 2026-05-19, bug #3 — post-marker
              // fd reuse exclusion): mirrors the dup-family fix.
              recordPostMarkerFdReuse(pid, rc);
              // Codex pass 47 follow-up (high, 2026-05-19, bug #2 —
              // known dup reopens leave stale opaque markers): the
              // valid mapping just installed at fd `rc` supersedes
              // any prior opaque-reuse marker; mirrors the canonical-
              // ized-open and dup-family fixes above.
              clearOpaqueFdReuse(pid, rc);
            } else {
              // Unknown source fd → invalidate any prior mapping at the
              // new fd (mirrors the dup-family behaviour).
              dirfdTable.delete(newKey);
              // Codex follow-up (high, 2026-05-19, bug #1): mark the
              // pid's fd-group as state-unknown.  Mirrors the dup/dup2/
              // dup3 fix at line ~1975: the kernel installed a real fd
              // at `rc` whose directory target is opaque to us (because
              // the source oldfd was never tracked).  Same hazard, same
              // remediation — fail closed on subsequent numeric-dirfd
              // lookups via the fd-unknown bit, and propagate the bit
              // to the parent's group at any pending-detach
              // reconciliation under shared CLONE_FILES.
              fdUnknownAdd(pid);
              // Codex pass 47 follow-up (high, 2026-05-19, bug #2 —
              // untracked-source F_DUPFD symmetry): mirror the
              // unresolved-open path.  The kernel installed a fresh
              // private fd at `rc` whose directory target is opaque;
              // record the per-fd opaque marker so the marker-less
              // reconciler drops the parent's same-numbered entry.
              cancelPendingTombstonesForFd(pid, rc);
              recordPostMarkerFdReuse(pid, rc);
              recordOpaqueFdReuse(pid, rc);
            }
          } else if (cmd === 'F_SETFD') {
            // Mutate fd's FD_CLOEXEC bit per the arg.  Strace renders
            // the arg as `FD_CLOEXEC` (= 1) when set or `0` when not.
            // Numeric forms may appear under -x.  Anything else we
            // don't fully understand → fail closed.
            const cur = dirfdTable.get(oldKey);
            let newCloexec: boolean | null = null;
            if (arg === 'FD_CLOEXEC') newCloexec = true;
            else if (arg === '0') newCloexec = false;
            else if (arg.startsWith('0x')) {
              const n = parseInt(arg, 16);
              if (Number.isFinite(n)) newCloexec = (n & 0x1) !== 0;
            } else if (/^-?\d+$/.test(arg)) {
              const n = parseInt(arg, 10);
              if (Number.isFinite(n)) newCloexec = (n & 0x1) !== 0;
            } else if (arg.length > 0) {
              // Mixed/unknown symbolic form (e.g. `FD_CLOEXEC|<other>`).
              // Tokens we recognise contribute to the OR; if anything
              // looks unknown, fall back to unknown.
              let unrecognised = false;
              let bits = 0;
              for (const tok of arg.split('|')) {
                const t = tok.trim();
                if (t === 'FD_CLOEXEC') bits |= 0x1;
                else if (t === '0') {/* nothing */}
                else if (/^0x[0-9a-fA-F]+$/.test(t)) {
                  const n = parseInt(t, 16);
                  if (Number.isFinite(n)) bits |= n;
                } else if (/^-?\d+$/.test(t)) {
                  const n = parseInt(t, 10);
                  if (Number.isFinite(n)) bits |= n;
                } else {
                  unrecognised = true;
                }
              }
              if (!unrecognised) newCloexec = (bits & 0x1) !== 0;
            }
            if (newCloexec !== null) {
              if (cur !== undefined) {
                dirfdTable.set(oldKey, { path: cur.path, cloexec: newCloexec });
              } else if (newCloexec) {
                // Codex follow-up (high, 2026-05-19, bug #2): cur is
                // undefined so we have no tracked entry to flip, but
                // the kernel may have set FD_CLOEXEC on a real
                // inherited fd whose mapping the parent's pending
                // clone(CLONE_FILES) will later copy into us.  Record
                // a 'cloexec' tombstone so the delayed-clone
                // reconciliation flips the COPIED entry post-copy and
                // any subsequent execveCloexec sweep drops it.  Only
                // record when actually SETTING CLOEXEC; CLEARING
                // CLOEXEC on an untracked fd is deferred (residual
                // gap; rare in practice and would require an inverse
                // tombstone type).
                recordFdTombstone(pid, { kind: 'cloexec', fd });
              }
            } else {
              // Unrecognised SETFD arg — fail closed: mark fd-group
              // unknown so subsequent openat(<fd>, ...) returns null.
              fdUnknownAdd(pid);
            }
          } else if (cmd === 'F_GETFD' || cmd === 'F_GETFL' || cmd === 'F_SETFL') {
            // Read-only or non-fd-table-mutating subcommands.  Ignored.
          } else if (
            cmd === 'F_SETLK' || cmd === 'F_SETLKW' || cmd === 'F_GETLK' ||
            cmd === 'F_SETOWN' || cmd === 'F_GETOWN' ||
            cmd === 'F_SETSIG' || cmd === 'F_GETSIG' ||
            cmd === 'F_SETLEASE' || cmd === 'F_GETLEASE' ||
            cmd === 'F_NOTIFY' || cmd === 'F_SETPIPE_SZ' || cmd === 'F_GETPIPE_SZ' ||
            cmd === 'F_ADD_SEALS' || cmd === 'F_GET_SEALS'
          ) {
            // Other documented subcommands that don't affect the
            // <fd → directory> mapping or the FD_CLOEXEC bit.  No-op.
          } else {
            // Unrecognised subcommand on a successful fcntl call.
            // Fail closed: mark the pid's fd-group unknown so
            // subsequent openat(<fd>, ...) returns null.
            fdUnknownAdd(pid);
          }
        }
        continue;
      }

      // source === 'strace' — best-effort text parse.  Failures here are
      // expected and dropped silently: strace lines can be split across
      // reads, the format varies across versions, and the channel emits
      // many syscall families we don't care to extract events from.  A
      // strict gate here would mean every install hits noise-driven
      // tamper.  The StraceRunner owns the ts counter implicitly via file
      // ordering; we call parseStraceLine with ts=0 and let per-file
      // ordering serve as ts.
      const straceEvents: RawEvent[] | null = parseStraceLine(line, pid, 0);
      if (straceEvents === null) continue;

      for (const rawEvent of straceEvents) {
        // Audit-trust Finding (high, 2026-05-19): clear the shim-trust
        // bit on any successful spawn (execve/execveat) BEFORE doing
        // anything else for this event.  Rationale: a pid gains
        // shim-trust when strace observes an openat of
        // `/lib/libscriptjail.so` from that pid — that proves ld.so
        // mapped the shim into the ORIGINAL process image.  A
        // subsequent successful execve REPLACES the address space; the
        // shim mapping is gone, and unless ld.so re-maps the shim into
        // the new image (which produces its own openat line) the new
        // image is unshimmed.  If we kept the trust bit across exec, a
        // raw `syscall(SYS_execve, argv, scrubbed_envp)` from a
        // pre-trusted pid would land in an unshimmed image but still
        // be exempted from the events-file forgery detector — letting
        // the attacker forge JSONL into the trusted channel and cancel
        // the strace-vs-shim exec delta.
        //
        // Why FIRST in the per-event handler: the dispatcher processes
        // strace lines one at a time, so a later openat-write line
        // arriving from the same pid is processed in a separate
        // iteration anyway — but doing the clear at the top of THIS
        // iteration makes the invariant explicit and robust against
        // future refactors that batch multiple events per line.
        // `pidCwd` is intentionally NOT cleared here: kernel CWD
        // survives execve (per execve(2)), so the attacker's
        // chdir(events-dir) before the exec still applies after.
        if (rawEvent.kind === 'spawn' && rawEvent.result === 'ok') {
          shimLoadedPids.delete(rawEvent.pid);
          // Codex follow-up (high, 2026-05-19): execve detaches the
          // caller from any shared CLONE_FILES fd group BEFORE the
          // kernel sweeps CLOEXEC.  The kernel's `do_execve` path calls
          // `unshare_files_struct` — exec dup's the fd table into a
          // private copy.  Pre-fix we swept CLOEXEC on the SHARED
          // dirfdTable, so any post-exec dup/close in the exec'd image
          // mutated state visible to the surviving sibling members.
          // Post-fix we detach FIRST so the CLOEXEC sweep and all
          // subsequent fd-mutating syscalls from the exec'd image apply
          // only to the caller's now-private group.
          //
          // NOTE on cwd: execve does NOT break CLONE_FS (cwd is
          // preserved across exec and the kernel keeps the shared
          // `struct fs`).  We deliberately do NOT detach the cwd group
          // here — that's the unshare(CLONE_FS) path.
          // Codex follow-up (medium, 2026-05-19, bug #3): if the pid
          // is a singleton at execve time, the immediate detach is a
          // no-op AND the CLOEXEC sweep below mutates only the
          // singleton group.  A delayed parent clone(CLONE_FILES) =
          // <pid> line would then re-merge the kernel-detached child
          // into the parent — wrong direction.  Snapshot the child's
          // pre-detach state with an execve-CLOEXEC replay action so
          // the reconciler can copy parent state into child, then
          // replay the sweep on the child's private group.
          // Codex follow-up (high, 2026-05-19, bug #1): APPEND the
          // execveCloexec action to any existing pending marker rather
          // than overwriting.  Failure mode pre-fix: child
          // close_range(UNSHARE) [pending action 1] → child execve
          // [pending action 2].  The Map.set call overwrote the
          // close_range action; reconciliation then replayed only the
          // CLOEXEC sweep and the close_range-closed fds came back to
          // life.
          const execFdSingleton = isFdSingleton(rawEvent.pid);
          let execFdSnap: FdSnapshot | null = null;
          if (execFdSingleton) {
            // Codex follow-up (high, 2026-05-19, bug #4 — generation-
            // aware execveCloexec): seed the exclusion set empty.
            // Subsequent post-marker fd reuses (open/openat/openat2/
            // creat/dup*/F_DUPFD) add their newFd to THIS action's
            // exclude set so the reconciler doesn't sweep an fd that
            // wasn't open at this exec's instant.  See
            // `recordPostMarkerFdReuse` for the wiring.
            const execAction: FdDetachAction = {
              kind: 'execveCloexec',
              excludeFds: new Set<string>(),
            };
            execFdSnap = appendFdAction(rawEvent.pid, execAction);
            if (execFdSnap === null) {
              execFdSnap = snapshotFd(rawEvent.pid, execAction);
            }
          }
          detachFdGroup(rawEvent.pid);
          // Audit-trust Finding (high, 2026-05-19, codex follow-up): on a
          // successful execve the kernel auto-closes every fd whose
          // FD_CLOEXEC bit is set.  Sweep the (now-private) fd-group's
          // dirfdTable: entries with cloexec=true are deleted (the
          // kernel closed them), entries with cloexec=false survive
          // (the kernel kept them and the post-exec image can
          // openat(<fd>, …) through them).  Pre-fix we never tracked
          // CLOEXEC, so a script that did
          // `openat(AT_FDCWD, "/pkg", O_RDONLY|O_CLOEXEC) = 7`
          // followed by exec + `openat(7, "../../root/.ssh/id_rsa", …)`
          // would resolve through the stale `/pkg` mapping.
          const execRoot = rootedFd(rawEvent.pid);
          const execPrefix = `${execRoot}:`;
          for (const key of [...dirfdTable.keys()]) {
            if (!key.startsWith(execPrefix)) continue;
            const entry = dirfdTable.get(key);
            if (entry !== undefined && entry.cloexec) {
              dirfdTable.delete(key);
              // Codex follow-up (high, 2026-05-19, bug #6 — execve
              // CLOEXEC sweep doesn't transition post-marker
              // lifecycle): the kernel ACTUALLY closes the fd here
              // (this is the one site where FD_CLOEXEC translates
              // into a real close — fcntl(F_SETFD) and
              // close_range(CLOSE_RANGE_CLOEXEC) only SET the bit
              // and defer the close to the next exec).  Transition
              // matching post-marker reuse lifecycle entries from
              // 'open' → 'closed' so the delayed-clone reconciler's
              // copy-pass treats fd as kernel-closed and skips the
              // parent's stale shared-baseline entry.  Without this,
              // a post-marker O_CLOEXEC reopen followed by exec lets
              // the parent's same-numbered fd silently resurrect in
              // the child copy, and subsequent child openat(<fd>, …)
              // resolves through the parent's path even though the
              // kernel returns EBADF.
              const fdSuffix = key.slice(execPrefix.length);
              const fdNum = parseInt(fdSuffix, 10);
              if (Number.isFinite(fdNum)) {
                recordPostMarkerFdClose(rawEvent.pid, fdNum);
              }
            }
          }
          if (execFdSnap !== null) {
            pendingFdDetach.set(rawEvent.pid, execFdSnap);
          }
        }

        const result = input.attribution.attribute(rawEvent.pid);

        // Audit-trust Finding A (high, 2026-05-18): kernel-observed
        // openat trust signals — these run BEFORE the attribution gate
        // (and BEFORE the spawn-bookkeeping below) so we can build the
        // trusted-pid set even for pids the attacker has scrubbed
        // /proc/<pid>/environ on (raw-syscall exec with custom envp).
        //
        //   (a) An openat of `/lib/libscriptjail.so` proves ld.so is
        //       mapping the shim into this pid — i.e. LD_PRELOAD was
        //       honoured and `shim_init` is about to run.  Add the pid
        //       to the trusted-writer set so its subsequent openat of
        //       the events file is not flagged as forgery.  We add on
        //       ANY openat (read or write — ld.so opens RDONLY, but
        //       robustness against future shim load paths is cheap).
        //
        //   (b) An openat-write of the per-VM SCRIPT_JAIL_LOG_FILE path
        //       from a pid NOT in the trusted set is forgery: only the
        //       shim itself (via shim_init) should ever write to this
        //       file path.  We collect a forgery sample per offending
        //       pid so the post-loop synthesis pass emits one
        //       `<EVENTS_FILE_FORGERY>` audit_bypass entry per attempt.
        //       The sample carries the attribution snapshot so the
        //       entry surfaces under the right package even when the
        //       attacker has scrubbed the environ.
        // Audit-trust Finding 2 (high, 2026-05-18): grow the per-pid
        // <fd → canonical path> table from any successful openat (read
        // or write, AT_FDCWD or numeric dirfd).  Subsequent
        // openat-with-numeric-dirfd events on the same pid resolve
        // their relative path against this table.  We resolve the
        // OPENED path lexically (path.resolve) — see comment on the
        // `canonicalizeOpenTarget` helper for why we don't realpath
        // attacker-supplied dirfd paths.
        if (
          (rawEvent.kind === 'read' || rawEvent.kind === 'write') &&
          rawEvent.errno === undefined &&
          rawEvent.retFd !== undefined
        ) {
          const canonicalForFd = canonicalizeOpenTarget(
            rawEvent.pid,
            rawEvent.path,
            rawEvent.dirfd,
          );
          if (canonicalForFd !== null) {
            // Audit-trust Finding (high, 2026-05-19, codex follow-up):
            // detect O_CLOEXEC at openat/openat2/open time so the next
            // successful execve sweep correctly drops kernel-closed fds.
            // creat(2) NEVER sets FD_CLOEXEC on its return fd, so a
            // creat-sourced event must always be cloexec=false.  We
            // distinguish creat from open by leading-token match on the
            // raw line — the strace parser doesn't expose the original
            // syscall name on the RawEvent.  Numeric flag form
            // (`0o2000000` / `0x80000` etc) is not common from strace
            // (which renders symbolic identifiers by default for known
            // flags), but we include a numeric check for defence in
            // depth.
            const isCreat = line.startsWith('creat(');
            let cloexec = false;
            if (!isCreat) {
              // Strip the quoted path string from the line before
              // testing for O_CLOEXEC: if a user opens a file whose
              // path literally contains the bytes `O_CLOEXEC` (exotic
              // but legal), we don't want that to leak into the flag
              // detection.  Strace renders the path as a double-quoted
              // C-style string; we conservatively blank out anything
              // inside the first quoted region.
              const firstQuote = line.indexOf('"');
              let scanLine: string;
              if (firstQuote === -1) {
                scanLine = line;
              } else {
                // Find the matching closing quote, skipping escapes.
                let j = firstQuote + 1;
                while (j < line.length) {
                  if (line[j] === '\\') { j += 2; continue; }
                  if (line[j] === '"') break;
                  j++;
                }
                scanLine = line.slice(0, firstQuote) + line.slice(j + 1);
              }
              if (scanLine.includes('O_CLOEXEC')) {
                cloexec = true;
              }
            }
            dirfdTable.set(fdKey(rawEvent.pid, rawEvent.retFd), {
              path: canonicalForFd,
              cloexec,
            });
            // Codex follow-up (medium, 2026-05-19, bug #2 — stale-
            // tombstone-on-reopen): a fresh open/openat/openat2/creat
            // reusing a fd that earlier had a close/cloexec tombstone
            // queued (pre-marker) supersedes that tombstone.  Cancel
            // it so the delayed-clone reconciler doesn't replay it
            // AFTER unionFd merges this valid mapping into the
            // parent's group.
            cancelPendingTombstonesForFd(rawEvent.pid, rawEvent.retFd);
            // Codex follow-up (high, 2026-05-19, bug #3 — post-marker
            // fd reuse exclusion): mirrors the dup-family + fcntl
            // F_DUPFD fix.  A fresh open AFTER the kernel-level
            // unshare/exec installs a child-private fd; pre-detach
            // tombstones targeting this fd describe the pre-unshare
            // shared mutation and must NOT clobber the child copy.
            recordPostMarkerFdReuse(rawEvent.pid, rawEvent.retFd);
            // Codex adversarial pass 46 (high, 2026-05-19, bug #7):
            // a canonicalized open supersedes any prior opaque marker
            // on the same fd number — the kernel installed a fresh
            // fd whose target we now know, so the opaque-reuse signal
            // is no longer needed.
            clearOpaqueFdReuse(rawEvent.pid, rawEvent.retFd);
          } else {
            // Codex pass 45 follow-up (high, 2026-05-19, bug #6 —
            // unresolved post-marker open) + Codex pass 46 follow-up
            // (high, 2026-05-19, bug #7 — marker-less opaque-fd
            // reuse).  A successful open whose canonicalization
            // returned `null` (untracked dirfd, or AT_FDCWD with an
            // unknown cwd) still installs a fresh private fd at
            // `retFd` in the kernel — we just don't know its target
            // path.  Without bookkeeping here:
            //   1. A stale dirfdTable entry at `retFd` (e.g. from a
            //      pre-marker open that has not yet been swept) can
            //      survive and certify a later `openat(retFd, ...)`
            //      through that stale path.
            //   2. Pending pre-/post-marker tombstones targeting this
            //      fd describe the PRIOR fd at that number; they must
            //      be cancelled since the kernel installed a fresh fd.
            //   3. On out-of-order delayed-clone reconciliation the
            //      reconciler would see no child entry for `retFd` and
            //      copy the parent's same-numbered fd into the child
            //      group, certifying a child `openat(retFd, ...)`
            //      through the parent's stale path.
            //
            // Two complementary mechanisms cover both the marker-aware
            // and marker-less paths:
            //
            //   - `recordPostMarkerFdReuse` (bug #6): marker-aware
            //     lifecycle entry consulted by the snapshot-aware
            //     reconciler.  Short-circuits when no marker is
            //     pending.
            //   - `recordOpaqueFdReuse` (bug #7): marker-LESS per-fd
            //     opaque-reuse marker, ALWAYS recorded.  Consulted by
            //     `unionFd` (drops the merged fd entry on CLONE_FILES)
            //     and by the non-CLONE_FILES copy branch in the clone
            //     reconciler (skips copying parent's entry into child).
            //
            // We deliberately do NOT call `fdUnknownAdd(pid)` here —
            // that would taint the WHOLE pid's fd group and break
            // legitimate later resolutions through unrelated tracked
            // fds (a singleton pid that did `openat(<bad-dirfd>, ...)
            // = 8` would lose access to its other tracked fds).  The
            // per-fd opaque marker is the precise signal the
            // reconciler needs; the dirfdTable-delete handles the
            // stale-mapping case directly.
            dirfdTable.delete(fdKey(rawEvent.pid, rawEvent.retFd));
            cancelPendingTombstonesForFd(rawEvent.pid, rawEvent.retFd);
            recordPostMarkerFdReuse(rawEvent.pid, rawEvent.retFd);
            recordOpaqueFdReuse(rawEvent.pid, rawEvent.retFd);
          }
        }

        if (rawEvent.kind === 'read' && rawEvent.path === SHIM_LIBRARY_PATH) {
          shimLoadedPids.add(rawEvent.pid);
        }
        if (
          eventsFilePathCanonical !== null &&
          eventsFileBasename !== null &&
          rawEvent.kind === 'write' &&
          !shimLoadedPids.has(rawEvent.pid)
        ) {
          // Canonicalize the openat target BEFORE comparing.  This catches:
          //   (a) Path-alias attacks like `/tmp/..././events-dir/events.jsonl`
          //       (path.resolve collapses `..././` to a no-op so the result
          //       string-matches the canonical events file path).
          //   (b) dirfd opens — the canonicalizer joins the dirfd's
          //       directory (from the per-pid fd table) with the
          //       relative path before resolving, so
          //       `openat(<dirfd-of-events-dir>, "events.jsonl", O_WRONLY)`
          //       resolves to the same string as the configured events
          //       file path.
          //   (c) (Layer 2) cwd-relative AT_FDCWD opens — the
          //       canonicalizer resolves a relative target against the
          //       attacker's tracked CWD from `pidCwd` (populated by
          //       the chdir/fchdir pre-parser above), so
          //       `chdir(events-dir) + openat(AT_FDCWD, "events.jsonl",
          //       O_WRONLY)` resolves to the canonical events file
          //       path.
          // If canonicalization fails (numeric dirfd whose source we
          // never observed — could happen if strace -ff missed an
          // earlier line under load), the canonical-equality arm
          // returns false; we fall through to the Layer-1 basename
          // safety net.
          const canonicalTarget = canonicalizeOpenTarget(
            rawEvent.pid,
            rawEvent.path,
            rawEvent.dirfd,
          );

          // Audit-trust Finding (high, 2026-05-19): Layer-1 basename
          // safety net.  Even when canonical resolution fails or
          // disagrees, an openat-write whose basename equals the
          // events file basename from a non-shim-loaded pid in the
          // controlled rootfs is unambiguously a forgery attempt.
          // The basename is per-run-random
          // (`events-<32-hex>.jsonl`, see `createEventsFile`),
          // unguessable by a lifecycle script, and unique to this
          // audit channel — there is no legitimate reason for any
          // package to write to that exact filename.  This catches:
          //   - cwd-relative opens after `chdir(events-dir)` when
          //     strace dropped the chdir line and Layer 2 doesn't
          //     have a cwd entry for this pid.
          //   - dirfd-relative opens where the dirfd's source was
          //     missed by strace.
          //
          // Pre-randomization (when the basename was the generic
          // `events.jsonl`), this layer caused medium-severity false
          // positives: a package writing `./events.jsonl` to its own
          // cwd matched the basename and hard-failed the install.
          // Per-run randomization in `createEventsFile` is what makes
          // this layer safe to enable.
          const targetBasename = path.basename(rawEvent.path);
          const isCanonicalMatch = canonicalTarget === eventsFilePathCanonical;
          const isBasenameMatch = targetBasename === eventsFileBasename;

          if (isCanonicalMatch || isBasenameMatch) {
            const snapshot = attributionSnapshotByPid.get(rawEvent.pid);
            // Forensic path: prefer the canonically-resolved target
            // when we have one (most informative); otherwise fall
            // back to the canonical events file path (the basename
            // match implies the attacker INTENDED that target).
            const forensicPath = canonicalTarget ?? eventsFilePathCanonical;
            forgerySamples.push({
              pid: rawEvent.pid,
              ts: rawEvent.ts,
              // Carry the canonical path in the forensic sample so the
              // synthesised audit_bypass entry shows the resolved
              // target, not a relative basename or aliased form.
              path: forensicPath,
              pkg: result?.pkg ?? snapshot?.pkg ?? '<unattributed>',
              lifecycle: result?.lifecycle ?? snapshot?.lifecycle ?? 'install',
            });
          }
        }

        // Audit-trust Finding 3 (high, 2026-05-18): bypass counting
        // runs BEFORE the attribution gate.  Strace observing a
        // successful execve syscall on a pid is proof the kernel ran
        // it — if no matching shim libc-wrapper event arrives, that
        // is a raw-syscall bypass regardless of whether we can still
        // attribute the pid to a package.  The attacker's most
        // damaging variant (raw `syscall(SYS_execve, ...)` with a
        // scrubbed envp) leaves /proc/<pid>/environ without
        // npm_package_name / npm_lifecycle_event, so attribution
        // returns null and, pre-fix, the bypass counter skipped the
        // sample entirely — eliminating the detector.
        //
        // We snapshot attribution per pid on FIRST success and prefer
        // the snapshot at bypass-emission time so the synthesised
        // audit_bypass entry can still carry a meaningful pkg /
        // lifecycle label.  parseStraceLine emits a `spawn` RawEvent
        // for execve and execveat (Finding 2), with the syscall
        // return classified into ok/enoent/eacces.  Only the 'ok'
        // case counts: a failed execve does NOT replace the process
        // image and the shim wrapper would have observed it too, so
        // unsuccessful execve doesn't tell us anything about the
        // bypass invariant.
        if (result !== null) {
          recordAttribution(rawEvent.pid, result);
        }

        if (rawEvent.kind === 'spawn' && rawEvent.result === 'ok') {
          const argv0 = rawEvent.argv[0] ?? '';
          // For execve(pathname, argv, envp) the syscall path arg IS
          // argv[0] in our parser's output (the parser falls back to
          // the path when argv is empty), so prog/argv0 alias here.
          const prog = argv0;
          // Use the snapshot if attribution failed this call but
          // succeeded earlier on the same pid; otherwise fall through
          // to a "<unattributed>" sentinel so the audit_bypass entry
          // still appears in the lockfile.  We deliberately do NOT
          // drop the sample on attribution failure — the bypass
          // counter MUST run regardless (Finding 3).
          const snapshot = attributionSnapshotByPid.get(rawEvent.pid);
          const pkg =
            result?.pkg ?? snapshot?.pkg ?? '<unattributed>';
          const lifecycle =
            result?.lifecycle ?? snapshot?.lifecycle ?? 'install';
          const samples = straceExecsByPid.get(rawEvent.pid) ?? [];
          samples.push({
            argv0,
            prog,
            pid: rawEvent.pid,
            ts: rawEvent.ts,
            pkg,
            lifecycle,
          });
          straceExecsByPid.set(rawEvent.pid, samples);
        }

        // Regular event emission still requires successful attribution
        // — emitting unattributed openat / connect / etc. would flood
        // the lockfile with noise from system processes that happen to
        // get traced.  The bypass synthesis path above is the deliberate
        // exception: an unattributable raw execve IS the signal.
        //
        // Audit-trust Finding (high, 2026-05-19): one further exception
        // — a `spawn` event whose pid is unattributable via /proc but
        // for whom we DO have a parent-propagated attribution snapshot
        // (recorded at clone time) must still emit.  The motivating
        // case: a posix_spawnp child execve()s a missing rootfs binary
        // (`gcc` in spawns-gcc@1.0.0), exits 127 within microseconds,
        // and is reaped before strace tails the ENOENT line.
        // /proc/<childpid>/{environ,status} both ENOENT, so
        // Attribution.attribute(childPid) → null.  Pre-fix the event
        // was dropped here and `spawn_blocked` stayed `[]`, removing
        // the audit signal from the lockfile.  The bypass-synthesis
        // branch above already uses this same snapshot fallback; we
        // mirror its semantics for the regular spawn-event dispatch.
        //
        // Scope is narrow on purpose: only `kind === 'spawn'`.  An
        // unattributable read/write/dlopen/connect from a system pid
        // would flood the lockfile if we broadened the fallback —
        // that's the floor the existing gate enforces.
        if (result === null) {
          if (rawEvent.kind === 'spawn') {
            const spawnSnapshot = attributionSnapshotByPid.get(rawEvent.pid);
            if (spawnSnapshot !== undefined) {
              emit({
                raw: rawEvent,
                pkg: spawnSnapshot.pkg,
                lifecycle: spawnSnapshot.lifecycle,
              });
            }
          }
          continue;
        }

        // Audit-trust Finding (high, 2026-05-19): canonicalize dirfd /
        // cwd-relative read/write paths BEFORE applyProtectedPathsPolicy
        // and BEFORE emit.  Strace yields the syscall's path argument
        // verbatim — relative when dirfd is non-AT_FDCWD or when the
        // pid opened with AT_FDCWD on a cwd-relative path.  Without
        // canonicalization here, the protected-paths matcher and the
        // cross-package matcher would both see the literal relative
        // path:
        //   * `openat(rootFd, ".ssh/id_rsa", O_RDONLY)` — the
        //     `$HOME/.ssh/**` pattern can't match `".ssh/id_rsa"`
        //     (micromatch requires the absolute/tokenized form), so
        //     the read leaks past the hidden/drop logic.
        //   * `openat(pkgDirFd, "build.log", O_CREAT|O_WRONLY)` — the
        //     cross-package matcher in normalize.ts doesn't see the
        //     pkg dir prefix, so a package's own intra-dir write
        //     surfaces as a false-positive escaped write.
        //
        // Fail-closed posture when resolution is impossible (numeric
        // dirfd we never observed, OR AT_FDCWD-relative from a pid
        // with no tracked cwd): we collect an UnresolvedPathSample
        // and DROP the raw event so the unresolved relative path
        // never reaches the lockfile.  The post-loop synthesiser
        // then surfaces one `<UNRESOLVED_PATH>` audit_bypass entry
        // per drop, matching the existing per-event surfacing of
        // `<EVENTS_FILE_FORGERY>` and `<SYSCALL_EXEC_BYPASS>` (and
        // catchable by `findAuditBypass` in src/action/diff.ts).
        //
        // Successful absolute-path opens (AT_FDCWD + leading '/')
        // still pass through this branch — `canonicalizeOpenTarget`
        // returns `path.resolve(targetPath)` for them, which is the
        // same string with `.` / `..` segments collapsed.  Going
        // through canonicalize for those is intentional: it
        // normalises path-alias forms like `/foo/.././bar` to the
        // unambiguous form before downstream matchers see them.
        if (rawEvent.kind === 'read' || rawEvent.kind === 'write') {
          const canonical = canonicalizeForEmit(
            rawEvent.pid,
            rawEvent.path,
            rawEvent.dirfd,
          );
          if (canonical === null) {
            // Fail closed: record an UnresolvedPathSample for
            // post-loop synthesis and DROP the raw event so a
            // relative path never reaches normalize/tokenize.
            unresolvedPathSamples.push({
              pid: rawEvent.pid,
              ts: rawEvent.ts,
              path: rawEvent.path,
              kind: rawEvent.kind,
              pkg: result.pkg,
              lifecycle: result.lifecycle,
            });
            continue;
          }
          // Replace path with canonical absolute form.  Spread
          // preserves discriminant + all transport fields; TS
          // narrows on the literal `kind` so the spread keeps the
          // read/write discriminated-union shape.
          const resolved: RawEvent =
            rawEvent.kind === 'read'
              ? { ...rawEvent, path: canonical }
              : { ...rawEvent, path: canonical };
          emit({ raw: resolved, pkg: result.pkg, lifecycle: result.lifecycle });
          continue;
        }
        emit({ raw: rawEvent, pkg: result.pkg, lifecycle: result.lifecycle });
      }
      continue;
    }

    // Finding 1: terminal else — unknown `LineSource` discriminator.
    // `source` should be impossible to reach here at the type level, but a
    // runner that yields `undefined`, a typo'd value, or a future channel
    // name (added without updating the dispatcher) would silently fall
    // through to the strace parser under the previous design.  Treat it as
    // an audit-pipeline contract breach: record tamper, drop the line, let
    // main() fail closed.  We deliberately truncate `source` in the reason
    // because it could carry attacker-controlled bytes if the runner ever
    // surfaces them verbatim.
    const sourceStr: string = typeof source === 'string'
      ? source
      : `<${typeof source}>`;
    const MAX_SRC = 40;
    const sourceForReason = sourceStr.length > MAX_SRC
      ? `${sourceStr.slice(0, MAX_SRC)}…`
      : sourceStr;
    setPhaseTamper(
      `unknown LineSource (pid=${pid}, source=${JSON.stringify(sourceForReason)}). ` +
        'Audit-pipeline contract requires source ∈ {"shim","strace"}.',
    );
  }

  // Audit-trust Finding 1 (2026-05-18): post-loop cross-check.  For each
  // pid we count successful strace execve syscalls vs shim libc exec
  // events.  Any positive `strace - shim` delta is unaccounted for and
  // can only be explained by a raw `syscall(SYS_execve, …)` bypass — the
  // child therefore ran without the shim's re-injected env envelope.
  // We synthesise one `exec` event (`syscall_bypass: true`) per excess
  // strace execve so normalize.ts folds it into the package's
  // `audit_bypass` list via the existing pipeline.  The
  // `findAuditBypass` scan in src/action/diff.ts then hard-fails the
  // lockfile diff on the resulting `<SYSCALL_EXEC_BYPASS> …` entry.
  //
  // Selection of which strace samples to surface: we surface the LAST N
  // samples (where N = delta).  Rationale: shim exec events arrive in the
  // same temporal order as their strace counterparts for the matched
  // pairs, so the unmatched tail is the most likely bypass.  This is a
  // best-effort heuristic for the forensic argv0 — the audit-bypass
  // signal itself is correctly populated for ANY non-zero delta.
  for (const [pid, samples] of straceExecsByPid) {
    const straceCount = samples.length;
    // Audit-trust Finding C (medium, 2026-05-18): per-event saturating
    // subtraction in the dispatcher loop guarantees `shimExecCountByPid`
    // is non-negative, so a redundant `max(0, …)` here is defence in
    // depth against any future refactor that re-introduces unbounded
    // decrements.  The invariant being enforced is "did the kernel see
    // more successful execs on this pid than the libc wrapper recorded
    // successful ones?".
    const shimNet = shimExecCountByPid.get(pid) ?? 0;
    const shimCount = shimNet < 0 ? 0 : shimNet;
    if (straceCount <= shimCount) continue;
    const bypassCount = straceCount - shimCount;
    // Take the tail samples (most-recent execve calls on this pid).
    const tail = samples.slice(straceCount - bypassCount);
    for (const sample of tail) {
      const synthetic: RawEvent = {
        kind: 'exec',
        prog: sample.prog,
        argv0: sample.argv0.length > 0 ? sample.argv0 : null,
        envp_alloc_failed: false,
        syscall_bypass: true,
        events_file_forgery: false,
        unresolved_path: false,
        // The synthesised event represents a strace-observed successful
        // execve syscall; tag it `result:'ok'` so it matches the shape
        // of a real successful exec.  This field isn't consumed by
        // normalize.ts for the synth path (which keys on
        // `syscall_bypass`) but the schema requires it.
        result: 'ok',
        pid: sample.pid,
        ts: sample.ts,
      };
      emit({
        raw: synthetic,
        pkg: sample.pkg,
        lifecycle: sample.lifecycle,
      });
    }
  }

  // Audit-trust Finding A (high, 2026-05-18): emit one synthetic exec
  // event per detected events-file forgery attempt.  The
  // `events_file_forgery: true` flag drives normalize.ts to surface the
  // entry as `<EVENTS_FILE_FORGERY> …` under `audit_bypass`, which the
  // host-side `findAuditBypass` scan in src/action/diff.ts hard-fails
  // on.  We use the snapshot's pkg / lifecycle so the entry lands in
  // the right package even when the attacker has scrubbed
  // /proc/<pid>/environ (the strace-observed openat is proof of the
  // forgery even when attribution from /proc fails).
  for (const sample of forgerySamples) {
    const synthetic: RawEvent = {
      kind: 'exec',
      prog: sample.path,
      argv0: sample.path,
      envp_alloc_failed: false,
      syscall_bypass: false,
      events_file_forgery: true,
      unresolved_path: false,
      result: 'ok',
      pid: sample.pid,
      ts: sample.ts,
    };
    emit({
      raw: synthetic,
      pkg: sample.pkg,
      lifecycle: sample.lifecycle,
    });
  }

  // Audit-trust Finding (high, 2026-05-19): emit one synthetic exec event
  // per dropped openat read/write whose dirfd/cwd-relative path we could
  // not resolve.  The `unresolved_path: true` flag drives normalize.ts
  // to surface the entry as `<UNRESOLVED_PATH> …` under `audit_bypass`,
  // which the host-side `findAuditBypass` scan in src/action/diff.ts
  // hard-fails on.  The forensic `prog`/`argv0` carries the literal
  // relative path the script tried to open — never matched against any
  // policy, only shown to the auditor.  The pkg / lifecycle come from
  // the attribution result captured at the drop site (Layer 1: we DO
  // require attribution success here so the drop maps to a concrete
  // package — unattributed reads were already filtered above).
  for (const sample of unresolvedPathSamples) {
    // Prefix the kind so the auditor can distinguish read vs write
    // attempts (e.g. ".ssh/id_rsa probe" vs "build.log write").
    const ident = `${sample.kind}:${sample.path}`;
    const synthetic: RawEvent = {
      kind: 'exec',
      prog: ident,
      argv0: ident,
      envp_alloc_failed: false,
      syscall_bypass: false,
      events_file_forgery: false,
      unresolved_path: true,
      result: 'ok',
      pid: sample.pid,
      ts: sample.ts,
    };
    emit({
      raw: synthetic,
      pkg: sample.pkg,
      lifecycle: sample.lifecycle,
    });
  }

  // Exit code is owned by the StraceRunner (it ran the only install process).
  const exitCode = input.strace.getExitCode();
  return { exitCode, eventCount, tamperReason: phaseTamperReason };
}

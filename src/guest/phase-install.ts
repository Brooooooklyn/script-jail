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
  // Union two pids into the same group.  Caller chooses semantics:
  // for cwd vs fd groups they may differ.  We always union the
  // CHILD's root onto the PARENT's root (so the parent's existing
  // group state is preserved).
  function unionCwd(parentPid: number, childPid: number): void {
    const pr = rootedCwd(parentPid);
    const cr = rootedCwd(childPid);
    if (pr === cr) return;
    cwdParent.set(cr, pr);
  }
  function unionFd(parentPid: number, childPid: number): void {
    const pr = rootedFd(parentPid);
    const cr = rootedFd(childPid);
    if (pr === cr) return;
    fdParent.set(cr, pr);
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
  const dirfdTable = new Map<string, string>();
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
  // protected-paths match.  Post-fix, observing an `fcntl(...)` (the
  // one fd-mutating syscall we can't fully parse subcommands for)
  // marks the pid here, so step (4) returns `null` and the raw event
  // is dropped + a `<UNRESOLVED_PATH>` synth event is surfaced.
  //
  // We DO fully parse `dup`/`dup2`/`dup3`/`close`/`close_range` below
  // — those propagate / invalidate the dirfdTable directly instead of
  // entering this set.  Only `fcntl` (which we may add later) and any
  // future state-violating syscall we observe but cannot model
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
    const dirPath = dirfdTable.get(fdKey(pid, dirfd));
    if (dirPath === undefined) return null;
    return path.resolve(dirPath, targetPath);
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
    const dirPath = dirfdTable.get(fdKey(pid, dirfd));
    if (dirPath === undefined) return null;
    return path.resolve(dirPath, targetPath);
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
  // The map is keyed by pid; entries are written once (first observation)
  // and never overwritten, so a later attribution failure can't tamper
  // with an earlier successful snapshot.
  const attributionSnapshotByPid: Map<
    number,
    { pkg: string; lifecycle: AttributedEvent['lifecycle'] }
  > = new Map();
  const recordAttribution = (
    pid: number,
    attr: { pkg: string; lifecycle: AttributedEvent['lifecycle'] },
  ): void => {
    if (!attributionSnapshotByPid.has(pid)) {
      attributionSnapshotByPid.set(pid, { pkg: attr.pkg, lifecycle: attr.lifecycle });
    }
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
        // Finding 3 (audit-trust): snapshot attribution for this pid the
        // first time we see it.  A later raw execve from the same pid
        // with a scrubbed envp would otherwise lose the lifecycle
        // context and slip past the bypass detector.
        recordAttribution(shimEvent.pid, result);
        emit({ raw: shimEvent, pkg: result.pkg, lifecycle: result.lifecycle });
      }
      continue;
    }

    if (source === 'strace') {
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
          const dirPath = dirfdTable.get(fdKey(pid, fd));
          if (dirPath !== undefined) {
            cwdSet(pid, dirPath);
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
        // We match the rc as a decimal integer; clone/clone3 never return
        // hex or symbolic forms.  Negative rc (e.g. "-1 ENOMEM") fails
        // the regex and the propagation is skipped — correct, since no
        // child pid exists in that case.
        const rcMatch = line.match(/=\s*(\d+)\b/);
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
            if (cloneFs) {
              // Union the two pids into the same cwd group.  Subsequent
              // chdir on either pid mutates the shared state.
              unionCwd(pid, childPid);
              // No need to copy cwd / pidCwdUnknown — they are already
              // visible to the child via the shared root.
            } else {
              // Copy branch: independent fs struct.  Snapshot the
              // parent's cwd / unknown bit into the child's NEW group.
              // We deliberately do NOT pre-union the child — leaving
              // it as its own root means future chdir in the child
              // mutates only the child's pidCwd entry.
              const parentCwd = cwdGet(pid);
              if (parentCwd !== undefined) {
                cwdSet(childPid, parentCwd);
              }
              if (cwdUnknownHas(pid)) {
                cwdUnknownAdd(childPid);
              }
            }

            // --- fd group: union if CLONE_FILES, else copy. ---------
            if (cloneFiles) {
              unionFd(pid, childPid);
              // No per-key copy needed — fd lookups resolve to the
              // shared group root.
            } else {
              // Copy branch: independent fd table.  Sweep over the
              // parent's keys and re-key into the child's NEW fd
              // group.  `fdKey(parent, fd)` resolves to
              // `<parentRoot>:<fd>`; `fdKey(child, fd)` resolves to
              // `<childRoot>:<fd>` (the child is its own root pre-
              // sweep because we haven't unioned it).
              const parentRoot = rootedFd(pid);
              const childRoot = rootedFd(childPid);
              if (parentRoot !== childRoot) {
                const parentPrefix = `${parentRoot}:`;
                for (const [key, val] of dirfdTable) {
                  if (key.startsWith(parentPrefix)) {
                    const suffix = key.slice(parentPrefix.length);
                    dirfdTable.set(`${childRoot}:${suffix}`, val);
                  }
                }
                if (fdUnknownHas(pid)) {
                  fdUnknownAdd(childPid);
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
        /^(dup3?|dup2)\((-?\d+)(?:\s*,\s*(-?\d+))?(?:\s*,[^)]*)?\)\s*=\s*(-?\d+)\b/,
      );
      if (dupMatch !== null) {
        const op = dupMatch[1] ?? '';
        const rc = parseInt(dupMatch[4] ?? '', 10);
        if (Number.isFinite(rc) && rc >= 0) {
          const oldFd = parseInt(dupMatch[2] ?? '', 10);
          const newFd = op === 'dup' ? rc : parseInt(dupMatch[3] ?? '', 10);
          if (Number.isFinite(oldFd) && Number.isFinite(newFd)) {
            const oldKey = fdKey(pid, oldFd);
            const newKey = fdKey(pid, newFd);
            const oldVal = dirfdTable.get(oldKey);
            if (oldVal !== undefined) {
              dirfdTable.set(newKey, oldVal);
            } else {
              // oldfd has no tracked dir mapping → newfd must NOT
              // retain its previous mapping either (it now aliases
              // wherever oldfd actually points, which we don't know).
              dirfdTable.delete(newKey);
            }
          }
        }
        continue;
      }
      const closeMatch = line.match(/^close\((-?\d+)\)\s*=\s*(-?\d+)\b/);
      if (closeMatch !== null) {
        const fd = parseInt(closeMatch[1] ?? '', 10);
        if (Number.isFinite(fd)) {
          // Delete unconditionally: even on EBADF, our stale entry (if
          // any) is invalidated — the kernel's reply tells us the fd
          // is no longer valid for openat(<fd>, ...).
          dirfdTable.delete(fdKey(pid, fd));
        }
        continue;
      }
      const closeRangeMatch = line.match(
        /^close_range\((-?\d+)\s*,\s*(-?\d+|0x[0-9a-fA-F]+)(?:\s*,[^)]*)?\)\s*=\s*(-?\d+)\b/,
      );
      if (closeRangeMatch !== null) {
        const rc = parseInt(closeRangeMatch[3] ?? '', 10);
        if (Number.isFinite(rc) && rc === 0) {
          const first = parseInt(closeRangeMatch[1] ?? '', 10);
          const lastRaw = closeRangeMatch[2] ?? '';
          const last = lastRaw.startsWith('0x')
            ? parseInt(lastRaw, 16)
            : parseInt(lastRaw, 10);
          if (Number.isFinite(first) && Number.isFinite(last) && first >= 0 && last >= first) {
            // Iterate over the MAP entries for this fd-group only —
            // avoid O(last) work when last is UINT_MAX (4294967295),
            // the common "close all fds above first" idiom.  Keys are
            // formatted as `<fdGroupRoot>:<fd>`, so we anchor on the
            // resolved root for this pid.
            const groupPrefix = `${rootedFd(pid)}:`;
            for (const key of dirfdTable.keys()) {
              if (!key.startsWith(groupPrefix)) continue;
              const fdStr = key.slice(groupPrefix.length);
              const fd = parseInt(fdStr, 10);
              if (Number.isFinite(fd) && fd >= first && fd <= last) {
                dirfdTable.delete(key);
              }
            }
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
            dirfdTable.set(fdKey(rawEvent.pid, rawEvent.retFd), canonicalForFd);
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
        if (result === null) continue;

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

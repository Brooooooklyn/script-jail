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
  // basename matches the events file is suspicious in the controlled
  // rootfs.  The basename `events.jsonl` is unique to this audit
  // channel in the microVM; lifecycle scripts have no business writing
  // to a file by that name.  If we ever need to harden this further we
  // can rename the events file to include a per-VM random suffix so
  // the basename itself is unique.
  const eventsFileBasename: string | null =
    eventsFilePathCanonical !== null
      ? path.basename(eventsFilePathCanonical)
      : null;

  // Per-pid fd table: maps a kernel-assigned file descriptor (from a
  // successful openat) to the canonical absolute path of the directory
  // (or file) it points at.  Used to resolve subsequent
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
  const dirfdTable = new Map<string, string>();
  const fdKey = (pid: number, fd: number): string => `${pid}:${fd}`;

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
  const pidCwd = new Map<number, string>();

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
      const cwd = pidCwd.get(pid);
      if (cwd === undefined) return null;
      return path.resolve(cwd, targetPath);
    }
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
        const current = pidCwd.get(pid);
        const resolved = current !== undefined && !path.isAbsolute(decoded)
          ? path.resolve(current, decoded)
          : path.resolve(decoded);
        pidCwd.set(pid, resolved);
        continue;
      }
      const fchdirMatch = line.match(/^fchdir\((-?\d+)\)\s*=\s*0\b/);
      if (fchdirMatch !== null) {
        const fd = parseInt(fchdirMatch[1] ?? '', 10);
        if (Number.isFinite(fd)) {
          const dirPath = dirfdTable.get(fdKey(pid, fd));
          if (dirPath !== undefined) {
            pidCwd.set(pid, dirPath);
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
          // controlled rootfs is suspicious.  The basename
          // `events.jsonl` is unique to this audit channel; lifecycle
          // scripts have no business writing to a file by that name.
          // This catches:
          //   - cwd-relative opens after `chdir(events-dir)` when
          //     strace dropped the chdir line and Layer 2 doesn't
          //     have a cwd entry for this pid.
          //   - dirfd-relative opens where the dirfd's source was
          //     missed by strace.
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

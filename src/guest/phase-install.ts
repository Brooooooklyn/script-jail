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

import type { Emitter } from './emit.js';
import type { Attribution } from './attribution.js';
import { parseStraceLine } from './strace-parser.js';
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
      if (result !== null) {
        emit({ raw: shimEvent, pkg: result.pkg, lifecycle: result.lifecycle });
      }
      continue;
    }

    if (source === 'strace') {
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
        const result = input.attribution.attribute(rawEvent.pid);
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

  // Exit code is owned by the StraceRunner (it ran the only install process).
  const exitCode = input.strace.getExitCode();
  return { exitCode, eventCount, tamperReason: phaseTamperReason };
}

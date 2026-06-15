// Shared event + lockfile schemas. The guest agent emits RawEvent objects
// (JSONL over vsock); the host normalizes them into AttributedEvent records
// and renders the canonical Lock YAML committed to the repo as
// .script-jail.lock.yml.

import { z } from 'zod';

export const LifecycleStage = z.enum(['preinstall', 'install', 'postinstall', 'prepare']);
export type LifecycleStage = z.infer<typeof LifecycleStage>;

// `errno` is a transport-only field carried from strace-parser to the
// protected-paths policy filter (src/guest/protected-paths.ts). It is set on
// failed syscalls (ENOENT / EACCES) so the policy filter can decide whether
// the event should be emitted as `<HIDDEN>` or dropped. The field MUST be
// stripped before the event reaches lock/normalize.ts or lock/render.ts —
// neither renders it, and its presence in the public event stream would
// pollute the JSONL audit. Absence means "syscall succeeded."
//
// With exactOptionalPropertyTypes enabled, we OMIT the field entirely when the
// syscall succeeds (rather than setting it to `undefined`). Downstream code
// reads `errno === undefined` to mean "no failure to report."
//
// Audit-trust Finding 2 (high, 2026-05-18): `dirfd` and `retFd` are
// transport-only fields used by the events-file forgery detector in
// `phase-install.ts` to canonicalize paths before the equality check.
//
//   - `dirfd` is set on openat events where the dirfd argument was NOT
//     AT_FDCWD (i.e. a numeric file descriptor pointing at a directory
//     opened earlier).  The phase-install dispatcher uses its per-pid
//     fd-table (built from prior `retFd` observations) to resolve the
//     relative path against the dirfd's directory.
//
//   - `retFd` is the return value of a successful openat (the new fd).
//     phase-install records `<pid, retFd>` → canonical path so subsequent
//     openat-with-dirfd events on the same pid can be resolved.
//
// Both fields are STRIPPED before the event leaves `runInstallPhase`
// (alongside `errno`).  They never appear in the rendered lockfile or
// vsock JSONL stream — they exist solely for path canonicalization.
// `root_anchored` is set ONLY on fs read/write events that attribute to a
// root-project package key. UNLIKE the transport trio above (errno/dirfd/retFd,
// which `protected-paths.ts` strips at emit), `root_anchored` is a SEMANTIC
// field: it carries the non-forgeable repo-root-anchoring verdict (kernel
// process tree + per-pid exec-cwd, computed in `phase-install.ts`) and is
// intentionally KEPT through emit so `normalize.ts` can tell a genuine root
// event from one forged via `npm_package_name=<root>`. It never reaches the
// rendered lockfile: normalize turns events into string arrays and render
// never reads raw events. It is OMITTED entirely (never set to `false`) on
// non-root events, so existing event frames stay byte-identical.
export const FsReadEvent = z.object({
  kind: z.literal('read'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
  errno: z.enum(['ENOENT', 'EACCES']).optional(),
  dirfd: z.number().optional(),
  retFd: z.number().optional(),
  root_anchored: z.boolean().optional(),
});
export type FsReadEvent = z.infer<typeof FsReadEvent>;

export const FsWriteEvent = z.object({
  kind: z.literal('write'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
  errno: z.enum(['ENOENT', 'EACCES']).optional(),
  dirfd: z.number().optional(),
  retFd: z.number().optional(),
  root_anchored: z.boolean().optional(),
});
export type FsWriteEvent = z.infer<typeof FsWriteEvent>;

export const EnvReadEvent = z.object({
  kind: z.literal('env_read'),
  name: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
  // SEMANTIC, same contract as the read/write `root_anchored` above: the
  // non-forgeable repo-root-anchoring verdict, stamped only on env_read events
  // that attribute to a root-project key, OMITTED (never `false`) otherwise, and
  // NEVER rendered (normalize consumes it to emit a `<FORGED_ROOT>` prefix on a
  // forged/unanchored root-claimed env_read). Closes the unmarked-non-fs gap.
  root_anchored: z.boolean().optional(),
});
export type EnvReadEvent = z.infer<typeof EnvReadEvent>;

export const SpawnEvent = z.object({
  kind: z.literal('spawn'),
  argv: z.array(z.string()).min(1), // argv[0] is the executable; an empty argv is never valid
  // 'ok' = binary present in rootfs, exec succeeded
  // 'enoent' = binary not in rootfs (this is how we "block" native binaries)
  // 'eacces' = found but not executable
  result: z.enum(['ok', 'enoent', 'eacces']),
  pid: z.number(),
  ts: z.number(),
  // macOS bare backend only (omitted on Linux for byte-stability). Carried from
  // the Mach-O shim's exec event: `true` when the exec target resolved to a
  // SIP-protected system binary (under /bin or /usr/bin) that sip_redirect could
  // NOT redirect to a bundled substitute (e.g. find/sed/awk/grep/xargs/which/
  // python3/git/perl/ruby). The real arm64e binary ran with DYLD stripped, so it
  // and its descendants executed OUTSIDE the audit envelope. normalize.ts surfaces
  // it as an `<AUDIT_BLIND>` prefix in spawn_attempts/spawn_blocked so the lock
  // diff exposes the un-audited subtree (it is NOT an audit_bypass hard-fail —
  // benign find/sed use stays green; a reviewer just sees the marker). Omitted
  // (never `false`) so existing/non-blind records stay byte-identical.
  audit_blind: z.boolean().optional(),
  // SEMANTIC, same contract as the read/write `root_anchored` above: the
  // non-forgeable repo-root-anchoring verdict, stamped only on spawn events that
  // attribute to a root-project key, OMITTED (never `false`) otherwise, and
  // NEVER rendered (normalize consumes it to emit a `<FORGED_ROOT>` prefix on a
  // forged/unanchored root-claimed spawn). Closes the unmarked-non-fs gap.
  root_anchored: z.boolean().optional(),
});
export type SpawnEvent = z.infer<typeof SpawnEvent>;

export const DlopenEvent = z.object({
  kind: z.literal('dlopen'),
  filename: z.string(),
  // Legacy quarantine-preload event. The default runtime no longer injects
  // dlopen-block.cjs, so normal native-addon loads are not represented here.
  result: z.literal('blocked'),
  pid: z.number(),
  ts: z.number(),
});
export type DlopenEvent = z.infer<typeof DlopenEvent>;

export const NetworkEvent = z.object({
  kind: z.literal('connect'),
  host: z.string(),
  port: z.number(),
  // 'ok' = phase A (fetch with network on). 'blocked' = phase B (offline).
  result: z.enum(['ok', 'blocked']),
  pid: z.number(),
  ts: z.number(),
  // SEMANTIC, same contract as the read/write `root_anchored` above: the
  // non-forgeable repo-root-anchoring verdict, stamped only on connect events
  // that attribute to a root-project key, OMITTED (never `false`) otherwise, and
  // NEVER rendered (normalize consumes it to emit a `<FORGED_ROOT>` prefix on a
  // forged/unanchored root-claimed connect). Closes the unmarked-non-fs gap and
  // the drop-in-install egress-misclassification (a forged root prepare connect
  // is no longer mistaken for the genuine root's host-safe prepare).
  root_anchored: z.boolean().optional(),
});
export type NetworkEvent = z.infer<typeof NetworkEvent>;

// Emitted by the LD_PRELOAD shim's libc exec wrappers (execve, posix_spawn,
// execvpe, execveat, fexecve). Records the libc-level exec attempt, including
// the original prog/argv0 BEFORE any PATH search or rewrite. Redundant with
// strace-observed execve syscalls at the kernel level, so currently dropped
// in normalize.ts and not surfaced in the rendered lockfile; available in
// the raw audit JSONL for forensic inspection.
//
// Audit-trust Finding 1 (2026-05-18): an additional, synthesized variant is
// produced by `runInstallPhase` (NOT by the shim) when a strace-observed
// `execve` syscall has no matching shim-source `exec` event.  That gap is
// only possible when the lifecycle script bypassed the shim's libc wrappers
// (i.e. issued `syscall(SYS_execve, …)` directly), so the child ran without
// our env envelope.  The `syscall_bypass: true` flag on the synthesized
// event drives `normalize.ts` to emit a `<SYSCALL_EXEC_BYPASS>` entry under
// `audit_bypass`, which the host-side `findAuditBypass` scan hard-fails on.
// `argv0` carries the strace-observed argv[0] for forensic context; the
// other shim-only fields default to neutral values.
export const ExecEvent = z.object({
  kind: z.literal('exec'),
  prog: z.string(),
  argv0: z.string().nullable(),
  envp_alloc_failed: z.boolean(),
  // Default false for shim-sourced events.  Only set true by the
  // synthesized cross-check pass in runInstallPhase (Finding 1).
  syscall_bypass: z.boolean().default(false),
  // Default false for shim-sourced events.  Only set true by the
  // events-file forgery detector in runInstallPhase (Finding A,
  // 2026-05-18): strace observed a `write`-mode openat of the per-VM
  // SCRIPT_JAIL_LOG_FILE path from a pid that never loaded
  // `/lib/libscriptjail.so` (i.e. a lifecycle script that bypassed
  // LD_PRELOAD via raw-syscall exec + scrubbed envp and is now trying
  // to forge shim events into the trusted JSONL channel).  Producing a
  // synthetic exec event with this flag drives normalize.ts to emit
  // `<EVENTS_FILE_FORGERY>` under `audit_bypass`, which the host-side
  // `findAuditBypass` scan hard-fails on.
  events_file_forgery: z.boolean().default(false),
  // Default false for shim-sourced events.  Only set true by the
  // dirfd/cwd-relative path canonicalizer in runInstallPhase (Finding,
  // 2026-05-19): strace observed an openat with a numeric dirfd or an
  // AT_FDCWD-relative path that we COULD NOT resolve (the dirfd's
  // opening was never seen, or the pid never chdir'd from its inherited
  // cwd).  Emitting the unresolved relative path as a normal lockfile
  // event would let a package writing `openat(rootFd, ".ssh/id_rsa",
  // …)` masquerade as a plain relative read and bypass the
  // `$HOME/.ssh/**` protected-paths matcher.  Producing a synthetic
  // exec event with this flag drives normalize.ts to emit
  // `<UNRESOLVED_PATH>` under `audit_bypass`, which the host-side
  // `findAuditBypass` scan hard-fails on.
  unresolved_path: z.boolean().default(false),
  // Audit-trust Finding (high, 2026-05-18): the shim emits one event
  // BEFORE calling real_execve (with result='ok' — optimistic, since
  // successful execs never return) and a SECOND event with
  // result='failed' AFTER real_execve returns (a return at all proves
  // the exec failed).  posix_spawn emits a single event tagged with
  // the actual outcome.  The phase-install cross-check counts
  // `okEvents - failedEvents` per pid so failed-attempt libc wrappers
  // cancel out and only true successful execs contribute to the
  // strace/shim pairing.  Without this, an attacker could pad shim
  // exec count with failed wrapped execves (e.g. `execve("/missing",
  // …)`) and a paired raw-syscall bypass would produce a zero delta
  // — silently disabling the `<SYSCALL_EXEC_BYPASS>` detector.
  //
  // Default 'ok' preserves backwards compatibility with pre-fix shim
  // builds that emit the event without a `result` field (older
  // libscriptjail.so + new agent).  CI verifies the shim and agent
  // are built together but this gives us a safety net.
  result: z.enum(['ok', 'failed']).default('ok'),
  pid: z.number(),
  ts: z.number(),
  // macOS bare backend only (omitted on Linux). Set `true` by the Mach-O shim
  // when `prog` resolved to a SIP-protected system binary under /bin or /usr/bin
  // that sip_redirect left unchanged (no bundled substitute covers it), so the
  // real arm64e image ran with DYLD_INSERT_LIBRARIES stripped — un-audited. The
  // macOS guest dispatcher (phase-install-macos.ts) carries this onto the
  // synthesized spawn event; see SpawnEvent.audit_blind. Optional so Linux/non-
  // blind shim records parse byte-identically (zod would otherwise drop it).
  audit_blind: z.boolean().optional(),
  // macOS bare backend only (omitted on Linux). The FULL argv vector for the
  // exec, serialized by the Mach-O shim's `append_argv_field` (capped/truncated
  // deterministically). The macOS guest dispatcher synthesizes a spawn whose
  // `argv` is this array (vs the single-element `[argv0 ?? prog]` fallback), so
  // the rendered spawn_attempts command line matches Linux's full strace argv
  // (e.g. `node postinstall.js` instead of just `node`). Optional so Linux
  // records (no `argv` field) and pre-change shim builds still parse.
  argv: z.array(z.string()).optional(),
  // macOS bare backend only (omitted on Linux). On a FAILED exec the Mach-O shim
  // records the errno as a short uppercase string (`ENOENT` / `EACCES` — the
  // only two Linux's strace parser would surface). The macOS guest dispatcher
  // maps it onto a `spawn` RawEvent with `result:'enoent'|'eacces'` so normalize
  // renders `<ENOENT> <full argv>` in spawn_blocked (parity with Linux strace).
  // Optional so Linux/successful records parse byte-identically.
  exec_errno: z.string().optional(),
});
export type ExecEvent = z.infer<typeof ExecEvent>;

// Emitted by the LD_PRELOAD shim's env-mutator wrappers when a script tries
// to setenv/unsetenv/putenv/clearenv a protected name (LD_PRELOAD,
// NODE_OPTIONS, SCRIPT_JAIL_*). The call is silently refused (returns 0 to
// the caller) and this event records the attempt.
//
// Audit-trust Finding 4 (2026-05-18): `audit_fd_lost` is emitted by the JS
// preloads (env-spy.cjs / legacy dlopen-block.cjs) when a lifecycle script closes
// the cached events-file fd via /proc/self/fd/<N> and the preload's
// reopen-by-path retry also fails.  The preload then exits the Node process
// non-zero so the install command itself fails — but the JSONL line also
// surfaces in the events file so the host-side `findAuditBypass` scan can
// turn it into an audit_bypass entry in the rendered lockfile.  Unlike the
// libc-wrapper-sourced ops, `audit_fd_lost` has no `name` (it's not a
// per-name refusal).
export const EnvTamperEvent = z.object({
  kind: z.literal('env_tamper'),
  op: z.enum(['setenv', 'unsetenv', 'putenv', 'clearenv', 'audit_fd_lost']),
  // Omitted for clearenv (whole-environ wipe — no single name) and for
  // audit_fd_lost (preload-side fd-tamper signal — no env-var name).
  name: z.string().optional(),
  // Optional human-readable detail for audit_fd_lost (the reason string the
  // preload built — e.g. "reopen of /tmp/.../events.jsonl failed: EBADF").
  reason: z.string().optional(),
  refused: z.literal(true),
  pid: z.number(),
  ts: z.number(),
  // SEMANTIC, same contract as the read/write `root_anchored` above: the
  // non-forgeable repo-root-anchoring verdict, stamped only on env_tamper events
  // that attribute to a root-project key, OMITTED (never `false`) otherwise, and
  // NEVER rendered (normalize consumes it to emit a `<FORGED_ROOT>` prefix on a
  // forged/unanchored root-claimed `<REFUSED>` env_tamper). Closes the last
  // unmarked root-claimable + rendered + deduped kind. Does NOT apply to the
  // `audit_fd_lost` variant — that routes to audit_bypass and is hard-failed
  // independently by findAuditBypass, so dedupe-collapse cannot hide it.
  root_anchored: z.boolean().optional(),
});
export type EnvTamperEvent = z.infer<typeof EnvTamperEvent>;

export const RawEvent = z.discriminatedUnion('kind', [
  FsReadEvent,
  FsWriteEvent,
  EnvReadEvent,
  SpawnEvent,
  DlopenEvent,
  NetworkEvent,
  ExecEvent,
  EnvTamperEvent,
]);
export type RawEvent = z.infer<typeof RawEvent>;

export const AttributedEvent = z.object({
  raw: RawEvent,
  pkg: z.string(),
  lifecycle: LifecycleStage,
});
export type AttributedEvent = z.infer<typeof AttributedEvent>;

export const LifecycleBlock = z.object({
  external_reads: z.array(z.string()).default([]),
  escaped_writes: z.array(z.string()).default([]),
  env_read: z.array(z.string()).default([]),
  spawn_attempts: z.array(z.string()).default([]),
  spawn_blocked: z.array(z.string()).default([]),
  dlopen_attempts: z.array(z.string()).default([]),
  network_attempts: z.array(z.string()).default([]),
  // Populated when the LD_PRELOAD shim's libc-exec wrapper could not allocate
  // a re-injected envp for the child (`exec.envp_alloc_failed=true`). The
  // child therefore ran OUTSIDE the audit envelope — strace sees the execve
  // but no shim is loaded into the child, so getenv/dlopen/etc. inside that
  // process are invisible. Surfacing the bypass into the lockfile is the only
  // way an auditor can tell a clean diff from a silenced one.
  // Format: "<EXEC_FAIL_OPEN> <tokenized_prog>". Rare and intentionally noisy.
  audit_bypass: z.array(z.string()).default([]),
  // Populated by `env_tamper` events: a script attempted to mutate a
  // sticky/protected env var via libc (LD_PRELOAD, NODE_OPTIONS,
  // SCRIPT_JAIL_*). The shim refuses the call so prod state is intact, but
  // the attempt itself is hostile intent worth surfacing.
  // Format: "<REFUSED> <op>[ <name>]". `clearenv` has no name component.
  env_tamper: z.array(z.string()).default([]),
});
export type LifecycleBlock = z.infer<typeof LifecycleBlock>;

// PackageBlock uses a partial record: not every lifecycle stage is present.
// We model this as a plain object type to avoid the `z.record(Enum, ...)` issue
// where zod infers required keys over all enum values.
export interface PackageBlock {
  lifecycle: Partial<Record<LifecycleStage, LifecycleBlock>>;
}

export const Lock = z.object({
  schema_version: z.literal(1),
  manager: z.enum(['npm', 'pnpm', 'yarn']),
  manager_lockfile_sha256: z.string(),
  node_version: z.string(),
  generated_at: z.string(),
  // z.record(z.string(), ...) is intentionally permissive here: we accept any
  // string key for both the package id and lifecycle stage so the schema can
  // round-trip lockfiles produced by older or future schema versions without
  // failing validation on unknown lifecycle stage names.
  packages: z.record(z.string(), z.object({
    lifecycle: z.record(z.string(), LifecycleBlock),
  })),
});
export type Lock = z.infer<typeof Lock>;

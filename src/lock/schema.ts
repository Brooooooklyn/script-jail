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
export const FsReadEvent = z.object({
  kind: z.literal('read'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
  errno: z.enum(['ENOENT', 'EACCES']).optional(),
});
export type FsReadEvent = z.infer<typeof FsReadEvent>;

export const FsWriteEvent = z.object({
  kind: z.literal('write'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
  errno: z.enum(['ENOENT', 'EACCES']).optional(),
});
export type FsWriteEvent = z.infer<typeof FsWriteEvent>;

export const EnvReadEvent = z.object({
  kind: z.literal('env_read'),
  name: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
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
});
export type SpawnEvent = z.infer<typeof SpawnEvent>;

export const DlopenEvent = z.object({
  kind: z.literal('dlopen'),
  filename: z.string(),
  // Always 'blocked' in v1 — the JS preload throws before the syscall.
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
  pid: z.number(),
  ts: z.number(),
});
export type ExecEvent = z.infer<typeof ExecEvent>;

// Emitted by the LD_PRELOAD shim's env-mutator wrappers when a script tries
// to setenv/unsetenv/putenv/clearenv a protected name (LD_PRELOAD,
// NODE_OPTIONS, SCRIPT_JAIL_*). The call is silently refused (returns 0 to
// the caller) and this event records the attempt.
//
// Audit-trust Finding 4 (2026-05-18): `audit_fd_lost` is emitted by the JS
// preloads (env-spy.cjs / dlopen-block.cjs) when a lifecycle script closes
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

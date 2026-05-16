// Shared event + lockfile schemas. The guest agent emits RawEvent objects
// (JSONL over vsock); the host normalizes them into AttributedEvent records
// and renders the canonical Lock YAML committed to the repo as
// .npm-jar.lock.yml.

import { z } from 'zod';

export const LifecycleStage = z.enum(['preinstall', 'install', 'postinstall', 'prepare']);
export type LifecycleStage = z.infer<typeof LifecycleStage>;

export const FsReadEvent = z.object({
  kind: z.literal('read'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
});
export type FsReadEvent = z.infer<typeof FsReadEvent>;

export const FsWriteEvent = z.object({
  kind: z.literal('write'),
  path: z.string(),
  pid: z.number(),
  ts: z.number(),
  hidden: z.boolean(),
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
  argv: z.array(z.string()),
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

export const RawEvent = z.discriminatedUnion('kind', [
  FsReadEvent,
  FsWriteEvent,
  EnvReadEvent,
  SpawnEvent,
  DlopenEvent,
  NetworkEvent,
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
  packages: z.record(z.string(), z.object({
    lifecycle: z.record(z.string(), LifecycleBlock),
  })),
});
export type Lock = z.infer<typeof Lock>;

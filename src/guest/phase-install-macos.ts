// script-jail — phase-install-macos.ts
// Phase B for the macOS-bare backend: an observe-only, online audited install
// driven by the Mach-O shim as the SOLE event source.
//
// Why a separate dispatcher from `runInstallPhase` (Linux):
//   The Linux dispatcher merges TWO channels — strace's per-pid kernel text
//   stream AND the trusted JSONL shim channel — and carries a large amount of
//   strace-only machinery: a union-find CLONE_FS/CLONE_FILES group model, a
//   per-pid dirfd/cwd table, AT_FDCWD/relative-path canonicalization, the
//   strace-vs-shim execve cross-check (<SYSCALL_EXEC_BYPASS>), the events-file
//   forgery detector (<EVENTS_FILE_FORGERY>), and the unresolved-path
//   fail-closed (<UNRESOLVED_PATH>).  NONE of that applies on macOS:
//     - The Mach-O shim emits ABSOLUTE paths (F_GETPATH for dirfds, getcwd for
//       AT_FDCWD) — there is no relative path to resolve, so no dirfd/cwd table.
//     - There is no strace/kernel channel to cross-check the shim against, so
//       the three strace-derived audit_bypass detectors are intentionally
//       ABSENT (documented fidelity gap; Firecracker remains the high-assurance
//       backend).  The fs-based events-file tamper detector (inode/dev
//       baseline, mtime/ctime/size monotonicity, parent-dir rename) still fails
//       closed via the runner's tamperRef.
//
// What IS shared with `runInstallPhase` (imported as-is so a shim-sourced
// attribution renders BYTE-IDENTICALLY to the /proc-walk path):
//   parseShimLine, shimExecAttribution, shimNodeStartupAttribution,
//   classifyShimNodeStartupMarker, attributionFromEnvVars, isNodeBasename,
//   isPackageManagerClientBasename, applyProtectedPathsPolicy.
//
// Shim-channel parse failures stay FAIL-CLOSED (setPhaseTamper) exactly as on
// Linux: the trusted JSONL channel must never fall through to a best-effort
// drop.
//
// Linux behaviour is untouched — this module is only invoked on the
// macOS-bare path (see agent.ts main()).

import { applyProtectedPathsPolicy, ProtectedPathsMatcher } from './protected-paths.js';
import type { AttributionResult } from './attribution.js';
import {
  parseShimLine,
  shimExecAttribution,
  classifyShimNodeStartupMarker,
  isNodeBasename,
  isPackageManagerClientBasename,
  type PhaseInstallInput,
  type PhaseInstallResult,
} from './phase-install.js';
import {
  FsReadEvent,
  FsWriteEvent,
  NetworkEvent,
  type AttributedEvent,
  type RawEvent,
  type SpawnEvent,
} from '../lock/schema.js';

// Parse a single macOS shim JSONL line into a RawEvent / node_startup_done.
//
// Why a macOS-specific parser instead of the shared `parseShimLine`: on Linux
// the shim channel only ever carries env_read / dlopen / exec / env_tamper /
// node_startup_done — file reads/writes and connects come from the STRACE text
// channel, so `parseShimLine` (deliberately) does NOT parse `read`/`write`/
// `connect`.  On macOS there is no strace; the Mach-O shim is the SOLE event
// source and emits the EXACT `FsReadEvent` / `FsWriteEvent` / `NetworkEvent`
// shapes from src/lock/schema.ts (see src/shim/src/{fileops,net}.rs).  This
// wrapper validates those three kinds via their zod schemas FIRST, then
// delegates every other kind to the shared `parseShimLine` so a shim-sourced
// attribution still renders byte-identically to the /proc-walk path.
//
// Linux is untouched: `parseShimLine` keeps its original behaviour and this
// helper is only reached on the macOS-bare path.
type MacosShimLineEvent = ReturnType<typeof parseShimLine>;

function parseMacosShimLine(line: string): MacosShimLineEvent {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return null;
  }
  const kind = obj['kind'];
  if (kind === 'read') {
    const parsed = FsReadEvent.safeParse(obj);
    return parsed.success ? parsed.data : null;
  }
  if (kind === 'write') {
    const parsed = FsWriteEvent.safeParse(obj);
    return parsed.success ? parsed.data : null;
  }
  if (kind === 'connect') {
    const parsed = NetworkEvent.safeParse(obj);
    return parsed.success ? parsed.data : null;
  }
  // env_read / dlopen / exec / env_tamper / node_startup_done: shared path.
  return parseShimLine(line);
}

const INSTALL_CMD: Record<'npm' | 'pnpm' | 'yarn', { cmd: string; args: string[] }> = {
  npm:  { cmd: 'npm',  args: ['rebuild', '--foreground-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['rebuild', '--pending', '--config.side-effects-cache=false'] },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--offline'] },
};

/** Basename of a possibly-NUL-truncated prog/argv path (mirrors phase-install). */
function pathBasename(pathLike: string): string {
  const nul = pathLike.indexOf('\0');
  const value = nul === -1 ? pathLike : pathLike.slice(0, nul);
  const slash = value.lastIndexOf('/');
  return slash === -1 ? value : value.slice(slash + 1);
}

export async function runInstallPhaseMacos(
  input: PhaseInstallInput,
): Promise<PhaseInstallResult> {
  const { cmd, args: baseArgs } = INSTALL_CMD[input.manager];
  // For pnpm: pin the store-dir to the repo cwd — IDENTICAL to the value the
  // fetch phase splices.  Mirrors runInstallPhase so both phases agree.
  const args = input.manager === 'pnpm'
    ? [...baseArgs, `--store-dir=${input.cwd}/.pnpm-store`]
    : baseArgs;
  // No per-pid strace files on macOS; the basePath still gives runStraceTailer
  // a watchDir.  Default to a macOS tmp path when the caller didn't supply one.
  const basePath = input.straceBasePath ?? '/tmp/script-jail-strace/strace.out';

  // No-op matcher fallback (same contract as runInstallPhase): ENOENT events
  // are dropped, EACCES emitted plainly, protected paths stamped hidden.
  const matcher = input.protectedPaths ?? new ProtectedPathsMatcher({
    patterns: [],
    roots: { repo: '', nodeModules: '', home: '', tmp: '', cache: '' },
  });

  let eventCount = 0;

  // Tamper reason owned by this dispatcher.  Shim-channel parse failures set it
  // (fail-closed); the runner's recordTamper() is also called as defence in
  // depth for any runner that audits a shared events file.  First-writer-wins.
  let phaseTamperReason: string | null = null;
  const setPhaseTamper = (reason: string): void => {
    if (phaseTamperReason === null) phaseTamperReason = reason;
    input.strace.recordTamper(reason);
  };

  const emit = (ev: AttributedEvent): void => {
    const filtered = applyProtectedPathsPolicy(ev, matcher);
    if (filtered === null) return;
    input.emitter.emitEvent(filtered);
    eventCount++;
  };

  // -----------------------------------------------------------------------
  // Attribution snapshot machinery (ported from runInstallPhase, shim-only).
  //
  // On macOS the /proc walk yields null for every pid (MacOSProcReader's
  // readEnviron() is null), so attribution flows entirely through the shim
  // seed: a shim `exec` record stamps the process's own ctor-snapshotted npm
  // lifecycle env, and a `node_startup_done` marker carries the same snapshot.
  // We keep the SAME fallback ordering as the Linux shim-event chain so the
  // rendered attribution is byte-identical:
  //   shimExecAttribution → live /proc walk → fresh snapshot →
  //   node_startup_done marker → stale snapshot.
  //
  // There is no `+++ exited +++` line on macOS, so snapshots are never marked
  // stale by an exit handler — the `stale` field stays false (equivalent to
  // Linux's "exit line not yet drained" case).  The marker-ts demotion still
  // protects the recycled-pid case.
  // -----------------------------------------------------------------------
  const attributionSnapshotByPid: Map<
    number,
    { pkg: string; lifecycle: AttributedEvent['lifecycle']; recordedAtTs: number; stale: boolean }
  > = new Map();
  const nodeStartupMarkerByPid: Map<number, { ts: number; pathological: boolean }> = new Map();
  const nodeStartupAttributionByPid: Map<number, AttributionResult> = new Map();

  const recordAttribution = (
    pid: number,
    attr: { pkg: string; lifecycle: AttributedEvent['lifecycle'] },
    ts: number,
  ): void => {
    const existing = attributionSnapshotByPid.get(pid);
    if (existing === undefined || existing.recordedAtTs <= ts) {
      attributionSnapshotByPid.set(pid, {
        pkg: attr.pkg,
        lifecycle: attr.lifecycle,
        recordedAtTs: ts,
        stale: false,
      });
    }
  };

  const supersededByDifferentGenerationMarker = (
    pid: number,
    snapshot: { pkg: string; lifecycle: AttributedEvent['lifecycle']; recordedAtTs: number },
  ): boolean => {
    const marker = nodeStartupMarkerByPid.get(pid);
    if (marker === undefined || snapshot.recordedAtTs >= marker.ts) return false;
    const attrib = nodeStartupAttributionByPid.get(pid);
    if (attrib !== undefined) {
      return attrib.pkg !== snapshot.pkg || attrib.lifecycle !== snapshot.lifecycle;
    }
    return marker.pathological;
  };

  const snapshotAttribution = (
    pid: number,
  ): { pkg: string; lifecycle: AttributedEvent['lifecycle'] } | null => {
    const snapshot = attributionSnapshotByPid.get(pid);
    if (snapshot === undefined) return null;
    if (supersededByDifferentGenerationMarker(pid, snapshot)) return null;
    return { pkg: snapshot.pkg, lifecycle: snapshot.lifecycle };
  };

  const freshSnapshotAttribution = (
    pid: number,
  ): { pkg: string; lifecycle: AttributedEvent['lifecycle'] } | null => {
    const snapshot = attributionSnapshotByPid.get(pid);
    if (snapshot === undefined || snapshot.stale) return null;
    if (supersededByDifferentGenerationMarker(pid, snapshot)) return null;
    return { pkg: snapshot.pkg, lifecycle: snapshot.lifecycle };
  };

  const nodeStartupAttribution = (pid: number): AttributionResult | null =>
    nodeStartupAttributionByPid.get(pid) ?? null;

  // -----------------------------------------------------------------------
  // Node-bootstrap + pm-client noise filters (ported from runInstallPhase).
  //
  // On macOS every event — env reads, file reads, AND the node_startup_done
  // marker — arrives on the SINGLE in-order shim channel for a pid, so the
  // marker is the one boundary that ends BOTH the env-read window and the
  // file-read window (Linux split these across the shim + strace streams with
  // two distinct markers).  The node-bootstrap window therefore begins on a
  // shim `exec` whose basename is `node` (vs a strace spawn), candidate
  // tracking begins on a non-node exec (shebang npm/pnpm that become node),
  // and `node_startup_done` confirms+drops the candidate's buffered reads.
  // -----------------------------------------------------------------------
  const nodeBootstrapEnvPendingPids = new Set<number>();
  const nodeBootstrapFilePendingPids = new Set<number>();
  const nodeBootstrapChildrenByPid = new Map<number, Set<number>>();
  const nodeBootstrapCandidateEventsByPid = new Map<number, AttributedEvent[]>();
  const nodeBootstrapCandidateConfirmedPids = new Set<number>();
  const nodeBootstrapCandidateFileMarkerPids = new Set<number>();
  const nodeBootstrapEnvReads = new Set<string>();
  const nodeBootstrapFileReads = new Set<string>();
  const packageManagerClientPids = new Set<number>();
  const completedPackageManagerClientPids = new Set<number>();

  const nodeBootstrapSubtree = (rootPid: number): number[] => {
    const stack = [rootPid];
    for (let i = 0; i < stack.length; i++) {
      const current = stack[i]!;
      const children = nodeBootstrapChildrenByPid.get(current);
      if (children !== undefined) stack.push(...children);
    }
    return stack;
  };

  const clearNodeBootstrap = (rootPid: number): void => {
    for (const current of nodeBootstrapSubtree(rootPid)) {
      nodeBootstrapEnvPendingPids.delete(current);
      nodeBootstrapFilePendingPids.delete(current);
      nodeBootstrapChildrenByPid.delete(current);
    }
  };

  const clearNodeBootstrapEnv = (rootPid: number): void => {
    for (const current of nodeBootstrapSubtree(rootPid)) {
      nodeBootstrapEnvPendingPids.delete(current);
    }
  };

  const clearNodeBootstrapFile = (rootPid: number): void => {
    for (const current of nodeBootstrapSubtree(rootPid)) {
      nodeBootstrapFilePendingPids.delete(current);
      if (!nodeBootstrapEnvPendingPids.has(current)) {
        nodeBootstrapChildrenByPid.delete(current);
      }
    }
  };

  const beginNodeBootstrap = (pid: number): void => {
    clearNodeBootstrap(pid);
    nodeBootstrapEnvPendingPids.add(pid);
    nodeBootstrapFilePendingPids.add(pid);
  };

  const flushNodeBootstrapCandidate = (pid: number): void => {
    const buffered = nodeBootstrapCandidateEventsByPid.get(pid);
    if (buffered === undefined) return;
    nodeBootstrapCandidateEventsByPid.delete(pid);
    nodeBootstrapCandidateConfirmedPids.delete(pid);
    nodeBootstrapCandidateFileMarkerPids.delete(pid);
    for (const ev of buffered) emit(ev);
  };

  const dropNodeBootstrapCandidateAsNode = (pid: number): void => {
    const buffered = nodeBootstrapCandidateEventsByPid.get(pid);
    if (buffered === undefined) return;
    nodeBootstrapCandidateEventsByPid.delete(pid);
    nodeBootstrapCandidateConfirmedPids.delete(pid);
    nodeBootstrapCandidateFileMarkerPids.delete(pid);
    const recordEnvBaseline = !packageManagerClientPids.has(pid);
    for (const ev of buffered) {
      if (ev.raw.kind === 'read') {
        nodeBootstrapFileReads.add(ev.raw.path);
      } else if (ev.raw.kind === 'env_read' && recordEnvBaseline) {
        nodeBootstrapEnvReads.add(ev.raw.name);
      }
    }
  };

  const dropNodeBootstrapCandidateEnvReadsAsNode = (pid: number): void => {
    const buffered = nodeBootstrapCandidateEventsByPid.get(pid);
    if (buffered === undefined) return;
    const recordEnvBaseline = !packageManagerClientPids.has(pid);
    const keep: AttributedEvent[] = [];
    for (const ev of buffered) {
      if (ev.raw.kind === 'env_read') {
        if (recordEnvBaseline) nodeBootstrapEnvReads.add(ev.raw.name);
      } else {
        keep.push(ev);
      }
    }
    nodeBootstrapCandidateEventsByPid.set(pid, keep);
  };

  const beginNodeBootstrapCandidate = (pid: number): void => {
    flushNodeBootstrapCandidate(pid);
    nodeBootstrapCandidateConfirmedPids.delete(pid);
    nodeBootstrapCandidateFileMarkerPids.delete(pid);
    nodeBootstrapCandidateEventsByPid.set(pid, []);
  };

  const flushAllNodeBootstrapCandidates = (): void => {
    for (const pid of [...nodeBootstrapCandidateEventsByPid.keys()]) {
      flushNodeBootstrapCandidate(pid);
    }
  };

  const confirmNodeBootstrapCandidate = (pid: number): boolean => {
    if (!nodeBootstrapCandidateEventsByPid.has(pid)) return false;
    nodeBootstrapCandidateConfirmedPids.add(pid);
    dropNodeBootstrapCandidateEnvReadsAsNode(pid);
    if (nodeBootstrapCandidateFileMarkerPids.has(pid)) {
      dropNodeBootstrapCandidateAsNode(pid);
    }
    return true;
  };

  const completeNodeBootstrapCandidateFileMarker = (pid: number): boolean => {
    if (!nodeBootstrapCandidateEventsByPid.has(pid)) return false;
    nodeBootstrapCandidateFileMarkerPids.add(pid);
    if (nodeBootstrapCandidateConfirmedPids.has(pid)) {
      dropNodeBootstrapCandidateAsNode(pid);
    }
    return true;
  };

  const shouldFilterNodeBootstrapEnvRead = (raw: RawEvent): boolean => {
    if (raw.kind !== 'env_read' || raw.hidden) return false;
    if (nodeBootstrapEnvPendingPids.has(raw.pid)) {
      if (!packageManagerClientPids.has(raw.pid)) nodeBootstrapEnvReads.add(raw.name);
      return true;
    }
    return nodeBootstrapEnvReads.has(raw.name);
  };

  const shouldFilterPackageManagerClientEnvRead = (raw: RawEvent): boolean => {
    if (raw.kind !== 'env_read' || raw.hidden) return false;
    return packageManagerClientPids.has(raw.pid) || completedPackageManagerClientPids.has(raw.pid);
  };

  const shouldFilterNodeBootstrapFileRead = (raw: RawEvent): boolean => {
    if (raw.kind !== 'read' || raw.hidden || matcher.isProtected(raw.path)) return false;
    if (nodeBootstrapFilePendingPids.has(raw.pid)) {
      nodeBootstrapFileReads.add(raw.path);
      return true;
    }
    return nodeBootstrapFileReads.has(raw.path);
  };

  const shouldBufferNodeBootstrapCandidateFileRead = (ev: AttributedEvent): boolean => {
    if (ev.raw.kind !== 'read' || ev.raw.hidden || matcher.isProtected(ev.raw.path)) return false;
    const buffered = nodeBootstrapCandidateEventsByPid.get(ev.raw.pid);
    if (buffered === undefined) return false;
    if (nodeBootstrapCandidateFileMarkerPids.has(ev.raw.pid)) return false;
    buffered.push(ev);
    return true;
  };

  const shouldBufferNodeBootstrapCandidateEnvRead = (ev: AttributedEvent): boolean => {
    if (ev.raw.kind !== 'env_read' || ev.raw.hidden) return false;
    const buffered = nodeBootstrapCandidateEventsByPid.get(ev.raw.pid);
    if (buffered === undefined) return false;
    if (nodeBootstrapCandidateConfirmedPids.has(ev.raw.pid)) return false;
    buffered.push(ev);
    return true;
  };

  // -----------------------------------------------------------------------
  // Dispatch loop — shim channel only.
  //
  // The runner yields {pid,line,source}.  On macOS there are no per-pid strace
  // files, so `source` is always 'shim'; the trusted-channel rules apply to
  // every line.  A parse failure here is FATAL (setPhaseTamper) — the channel
  // must never fall through to a best-effort drop.  An unexpected non-'shim'
  // source is treated as an audit-pipeline contract breach (fail closed).
  //
  // `dispatchTs` is the monotonic generation token (same role as in
  // runInstallPhase): incremented for EVERY yielded line so the snapshot
  // bookkeeping has a single global ordering.
  // -----------------------------------------------------------------------
  let dispatchTs = 0;
  for await (const record of input.strace.run(cmd, args, {
    env: input.env,
    cwd: input.cwd,
    basePath,
  })) {
    const { pid, line, source } = record;
    const explicitTs = record.ts;
    const lineTs = explicitTs !== undefined ? explicitTs : dispatchTs;
    dispatchTs++;

    if (source !== 'shim') {
      const sourceStr: string = typeof source === 'string' ? source : `<${typeof source}>`;
      const MAX_SRC = 40;
      const sourceForReason = sourceStr.length > MAX_SRC ? `${sourceStr.slice(0, MAX_SRC)}…` : sourceStr;
      setPhaseTamper(
        `unexpected LineSource on macOS-bare (pid=${pid}, source=${JSON.stringify(sourceForReason)}). ` +
          'The Mach-O shim is the sole event source; only "shim" lines are expected.',
      );
      continue;
    }

    const shimEvent = parseMacosShimLine(line);
    if (shimEvent === null) {
      const MAX_PREFIX = 100;
      const prefix = line.length > MAX_PREFIX ? `${line.slice(0, MAX_PREFIX)}…` : line;
      setPhaseTamper(
        `shim channel had unparseable JSONL line (pid=${pid}): ${JSON.stringify(prefix)}`,
      );
      continue;
    }

    // ---- node_startup_done marker -----------------------------------------
    if (shimEvent.kind === 'node_startup_done') {
      // node_startup_done seed + generation bookkeeping (ported as-is from
      // runInstallPhase): record the marker generation on EVERY marker and
      // REPLACE the attribution entry (set for valid, DELETE for bare /
      // non-canonical / overlong so a recycled pid fails closed).
      const { attribution: startupAttrib, pathological: startupPathological } =
        classifyShimNodeStartupMarker(line);
      nodeStartupMarkerByPid.set(shimEvent.pid, { ts: lineTs, pathological: startupPathological });
      if (startupAttrib !== null) {
        nodeStartupAttributionByPid.set(shimEvent.pid, startupAttrib);
      } else {
        nodeStartupAttributionByPid.delete(shimEvent.pid);
      }
      // On macOS the single in-order marker ends BOTH the env-read and
      // file-read bootstrap windows for the pid: confirm the candidate
      // (drops its buffered env reads as node baseline) AND complete its file
      // marker (drops buffered file reads), then clear the live windows.
      confirmNodeBootstrapCandidate(shimEvent.pid);
      completeNodeBootstrapCandidateFileMarker(shimEvent.pid);
      clearNodeBootstrapEnv(shimEvent.pid);
      clearNodeBootstrapFile(shimEvent.pid);
      continue;
    }

    // ---- exec → synthesize spawn (+ <EXEC_FAIL_OPEN> on envp_alloc_failed) --
    if (shimEvent.kind === 'exec') {
      // Seed attribution from the shim's in-process npm lifecycle env (the
      // authoritative, never-reaped source on macOS).  Byte-identical to the
      // /proc-walk path via attributionFromEnvVars (inside shimExecAttribution).
      const shimAttrib = shimExecAttribution(line);
      if (shimAttrib !== null) recordAttribution(shimEvent.pid, shimAttrib, lineTs);

      // <EXEC_FAIL_OPEN>: the shim could not allocate the re-injected envp, so
      // the child ran OUTSIDE the audit envelope.  Surface it regardless of
      // result (it fires on the pre-call optimistic event).  Emit the exec
      // RawEvent as-is so normalize.ts produces <EXEC_FAIL_OPEN> — the ONLY
      // audit_bypass kind macOS produces (the strace-derived ones are absent).
      if (shimEvent.envp_alloc_failed) {
        const attribution =
          shimAttrib ??
          freshSnapshotAttribution(shimEvent.pid) ??
          nodeStartupAttribution(shimEvent.pid) ??
          snapshotAttribution(shimEvent.pid);
        if (attribution !== null) {
          emit({ raw: shimEvent, pkg: attribution.pkg, lifecycle: attribution.lifecycle });
        }
      }

      // The shim emits an optimistic result:'ok' BEFORE the exec and a
      // result:'failed' AFTER it returns (failure only).  The spawn attempt is
      // the optimistic 'ok'; a 'failed' event is the failed-exec counterpart
      // (the macOS bypass cross-check is dropped, so we just ignore it for the
      // spawn).  Synthesize the spawn ONLY for result:'ok'.
      if (shimEvent.result === 'ok') {
        // Bootstrap / pm-client classification keyed on the exec basename
        // (vs the Linux strace spawn argv).  A node basename begins the
        // bootstrap window; a non-node basename (shebang npm/pnpm) begins a
        // candidate that node_startup_done later confirms.
        const progBase = pathBasename(shimEvent.argv0 ?? shimEvent.prog);
        const isPmClient = isPackageManagerClientBasename(progBase);
        flushNodeBootstrapCandidate(shimEvent.pid);
        packageManagerClientPids.delete(shimEvent.pid);
        completedPackageManagerClientPids.delete(shimEvent.pid);
        if (isNodeBasename(progBase)) {
          beginNodeBootstrap(shimEvent.pid);
        } else {
          clearNodeBootstrap(shimEvent.pid);
          beginNodeBootstrapCandidate(shimEvent.pid);
        }
        if (isPmClient) packageManagerClientPids.add(shimEvent.pid);

        // Map exec → spawn RawEvent so normalize.ts lands it in spawn_attempts
        // untouched.  argv is [argv0 ?? prog] (the shim records prog/argv0, not
        // the full argv); result:'ok' is a successful spawn.
        const spawnRaw: SpawnEvent = {
          kind: 'spawn',
          argv: [shimEvent.argv0 ?? shimEvent.prog],
          result: 'ok',
          pid: shimEvent.pid,
          ts: shimEvent.ts,
        };
        const attribution =
          shimAttrib ??
          freshSnapshotAttribution(shimEvent.pid) ??
          nodeStartupAttribution(shimEvent.pid) ??
          snapshotAttribution(shimEvent.pid);
        if (attribution !== null) {
          emit({ raw: spawnRaw, pkg: attribution.pkg, lifecycle: attribution.lifecycle });
        }
      }
      continue;
    }

    // ---- env_read -----------------------------------------------------------
    if (shimEvent.kind === 'env_read') {
      if (shouldFilterNodeBootstrapEnvRead(shimEvent)) continue;
    }

    // ---- attribution chain for all remaining kinds (read/write/env_read/
    //      dlopen/connect/env_tamper) ----------------------------------------
    const attribution =
      freshSnapshotAttribution(shimEvent.pid) ??
      nodeStartupAttribution(shimEvent.pid) ??
      snapshotAttribution(shimEvent.pid);
    if (attribution === null) continue;

    const attributed: AttributedEvent = {
      raw: shimEvent,
      pkg: attribution.pkg,
      lifecycle: attribution.lifecycle,
    };

    // read/write: bootstrap-file-read filter + candidate buffering, then emit
    // (emit applies protected-paths policy: ENOENT-drop, EACCES-emit,
    // protected→hidden).
    if (shimEvent.kind === 'read' || shimEvent.kind === 'write') {
      if (shouldFilterNodeBootstrapFileRead(shimEvent)) continue;
      if (shouldBufferNodeBootstrapCandidateFileRead(attributed)) continue;
      emit(attributed);
      continue;
    }

    // env_read: candidate buffering + pm-client filter, then emit.
    if (shimEvent.kind === 'env_read') {
      if (shouldBufferNodeBootstrapCandidateEnvRead(attributed)) continue;
      if (shouldFilterPackageManagerClientEnvRead(shimEvent)) continue;
      emit(attributed);
      continue;
    }

    // connect / dlopen / env_tamper: emit directly (no fs/env-read filtering).
    emit(attributed);
  }

  // Flush any buffered candidate events that never got a node_startup_done
  // marker (the candidate turned out NOT to be node — e.g. a non-Node helper
  // exec'd via a shebang interpreter that isn't node).  These are real events
  // and must surface.
  flushAllNodeBootstrapCandidates();

  return {
    exitCode: input.strace.getExitCode(),
    eventCount,
    tamperReason: phaseTamperReason,
  };
}

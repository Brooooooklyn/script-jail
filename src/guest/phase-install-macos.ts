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

import { join, dirname } from 'node:path';

import { applyProtectedPathsPolicy, ProtectedPathsMatcher } from './protected-paths.js';
import { INSTALL_CMD } from '../shared/pm-commands.js';
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

// INSTALL_CMD is imported from ../shared/pm-commands.ts (shared with Linux
// Phase B and the host drop-in install). The macOS-bare backend is observe-only
// and does not sever the network, but the cache Phase A populated still makes
// the relink+build run with no required registry traffic.

// env-spy.cjs stamps its `node_startup_done` JSONL marker by reading these three
// npm lifecycle fields off `process.env` (signalNodeStartupDone, env-spy.cjs
// :327-329).  That JS read is `origEnv = process.env` → V8 `uv_os_getenv` → libc
// `getenv` → the Mach-O shim's getenv hook, so on macOS it surfaces as a
// PRE-marker `env_read` for EVERY Node pid env-spy loads into (it does not exist
// on Linux, where the marker block is inert because SCRIPT_JAIL_EMIT_NODE_STARTUP_JSONL
// is unset).  Those self-reads must NOT contaminate the GLOBAL
// `nodeBootstrapEnvReads` noise baseline: unlike genuine bootstrap noise
// (NODE_*/CF*/NS*/…), these names are also read POST-marker by the package's own
// lifecycle machinery and are recorded per-package on Linux.  A single
// non-pm-client pid's pre-marker self-read would otherwise globally suppress the
// name and drop every package's legitimate post-marker reads — observed: 6
// pre-marker self-reads poisoning 63 post-marker reads across 4 packages.  The
// pre-marker self-read is STILL filtered per-pid (it is bootstrap); we only keep
// these names out of the shared baseline so post-marker reads survive, matching
// Linux.  Must equal the field set env-spy stamps in signalNodeStartupDone.
const STARTUP_MARKER_NPM_FIELDS: ReadonlySet<string> = new Set([
  'npm_package_name',
  'npm_package_version',
  'npm_lifecycle_event',
]);

/**
 * Launch a package-manager command on macOS as `<re-signed node> <manager-cli.js>`
 * (npm) / `<re-signed node> <corepack.js> <manager>` (pnpm·yarn) instead of the
 * bare `npm`/`pnpm`/`yarn` bin.  Shared by BOTH install phases (the Phase-A fetch
 * spawner and the Phase-B install runner) — see the two failure modes below.
 *
 * CRITICAL difference from Linux. The bare bins are `#!/usr/bin/env node` shebang
 * scripts, and on a fresh runner the bare name also resolves on PATH to whatever
 * pm the environment supplies. Spawning the bare bin breaks in two ways, both of
 * which strip or reject our instrumentation before the manager ever does work:
 *   1. shebang → `/usr/bin/env`, a SIP/platform binary that STRIPS
 *      `DYLD_INSERT_LIBRARIES` before node starts → the Mach-O shim never loads
 *      and only env-spy (via NODE_OPTIONS, which SIP does not strip) fires, so the
 *      lock captures env reads but no spawn/connect/file events; and
 *   2. the ambient pm bin may itself be an **arm64e** (or universal-without-plain-
 *      arm64) standalone NOT under SIP, so dyld does NOT strip the insert and
 *      instead tries to load our THIN-arm64 dylib into it → `incompatible
 *      architecture (have 'arm64', need 'arm64e')` and the phase dies at launch.
 *
 * The orchestrator already runs UNDER the provisioned, re-signed, plain-arm64
 * node, so `process.execPath` IS that node. Executing it directly (manager JS
 * entry as argv[1]) keeps the first exec plain-arm64 — DYLD survives, the shim
 * loads — and never touches the ambient pm bin. From there the shim's SIP redirect
 * re-signs every later `sh`/coreutil hop, so the whole subtree stays instrumented.
 * pnpm/yarn route through corepack's JS entry (also under the provisioned node),
 * so BOTH phases drive the SAME corepack-pinned pm (previously Phase A used the
 * ambient pm and Phase B used corepack — a silent version split). On Linux this
 * indirection is unnecessary (LD_PRELOAD survives `/usr/bin/env`), so only the
 * macOS spawner + install runner call this.
 */
export function macosManagerLaunch(
  manager: 'npm' | 'pnpm' | 'yarn',
  subArgs: string[],
): { cmd: string; args: string[] } {
  const node = process.execPath;
  const toolchainRoot = dirname(dirname(node)); // .../node/<version>
  if (manager === 'npm') {
    const npmCli = join(toolchainRoot, 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
    return { cmd: node, args: [npmCli, ...subArgs] };
  }
  const corepackCli = join(toolchainRoot, 'lib', 'node_modules', 'corepack', 'dist', 'corepack.js');
  return { cmd: node, args: [corepackCli, manager, ...subArgs] };
}

/**
 * Build the Phase-B install command for macOS — `macosManagerLaunch` with the
 * Phase-B subcommand (`rebuild`/`install`) and pnpm's repo-disk store-dir pin
 * (IDENTICAL store-dir value to the one the fetch phase splices).
 */
function buildMacosInstallCommand(
  manager: 'npm' | 'pnpm' | 'yarn',
  cwd: string,
): { cmd: string; args: string[] } {
  const base = INSTALL_CMD[manager];
  const managerArgs =
    manager === 'pnpm' ? [...base.args, `--store-dir=${cwd}/.pnpm-store`] : base.args;
  return macosManagerLaunch(manager, managerArgs);
}

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
  // Launch as `<re-signed node> <manager-cli.js> …` so DYLD survives the first
  // exec (see buildMacosInstallCommand).  pnpm's store-dir pin is folded in
  // there, IDENTICAL to the value the fetch phase splices.
  const { cmd, args } = buildMacosInstallCommand(input.manager, input.cwd);
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
      } else if (
        ev.raw.kind === 'env_read' &&
        recordEnvBaseline &&
        !STARTUP_MARKER_NPM_FIELDS.has(ev.raw.name)
      ) {
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
        if (recordEnvBaseline && !STARTUP_MARKER_NPM_FIELDS.has(ev.raw.name)) {
          nodeBootstrapEnvReads.add(ev.raw.name);
        }
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
      if (
        !packageManagerClientPids.has(raw.pid) &&
        !STARTUP_MARKER_NPM_FIELDS.has(raw.name)
      ) {
        nodeBootstrapEnvReads.add(raw.name);
      }
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

      // Full argv for the synthesized spawn.  The macOS shim now serializes the
      // complete argv vector (Fix E); fall back to the single-element
      // [argv0 ?? prog] when it is absent (older shim / Linux-shaped records) so
      // the command line still renders something.  normalize.ts tokenizes + joins
      // with ' ' and unwraps `sh -c`, so a full argv renders byte-identically to
      // Linux's strace argv (e.g. `node postinstall.js`).
      const spawnArgv: string[] =
        shimEvent.argv && shimEvent.argv.length > 0
          ? shimEvent.argv
          : [shimEvent.argv0 ?? shimEvent.prog];

      // The shim emits an optimistic result:'ok' BEFORE the exec and a
      // result:'failed' AFTER it returns (failure only).  The spawn attempt is
      // the optimistic 'ok'; a 'failed' event with a recordable errno is the
      // ENOENT/EACCES blocked-spawn counterpart (parity with Linux's strace
      // `<ENOENT> node …/cli.js`).  Synthesize a spawn for BOTH, with the
      // appropriate `result`.
      if (shimEvent.result === 'ok') {
        // Bootstrap / pm-client classification keyed on the exec basename
        // (vs the Linux strace spawn argv).  A node basename begins the
        // bootstrap window; a non-node basename (shebang npm/pnpm) begins a
        // candidate that node_startup_done later confirms.  Only the SUCCESSFUL
        // exec opens a bootstrap window (a failed exec ran no child).
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
        // untouched.  argv is the full vector (Fix E); result:'ok' is a
        // successful spawn.
        const spawnRaw: SpawnEvent = {
          kind: 'spawn',
          argv: spawnArgv,
          result: 'ok',
          pid: shimEvent.pid,
          ts: shimEvent.ts,
          // Carry the shim's audit-blind signal: this exec ran a SIP system
          // binary we could not instrument.  Only set when true (omit otherwise)
          // so non-blind spawns stay byte-identical.  normalize.ts renders it as
          // an `<AUDIT_BLIND>` prefix in spawn_attempts.
          ...(shimEvent.audit_blind ? { audit_blind: true as const } : {}),
        };
        const attribution =
          shimAttrib ??
          freshSnapshotAttribution(shimEvent.pid) ??
          nodeStartupAttribution(shimEvent.pid) ??
          snapshotAttribution(shimEvent.pid);
        if (attribution !== null) {
          emit({ raw: spawnRaw, pkg: attribution.pkg, lifecycle: attribution.lifecycle });
        }
      } else {
        // result:'failed'.  Linux's strace parser records a failed execve as a
        // `spawn` with result 'enoent' (binary missing — how native binaries are
        // "blocked") or 'eacces' (found but not executable); normalize renders
        // `<ENOENT>`/`<EACCES>` <full argv> in spawn_blocked.  Mirror that ONLY
        // for the two errnos Linux surfaces — every other failure (incl. a shim
        // build with no `exec_errno`) is dropped, matching the old behavior and
        // avoiding inventing a spurious blocked-spawn result.
        const failedResult: SpawnEvent['result'] | null =
          shimEvent.exec_errno === 'ENOENT'
            ? 'enoent'
            : shimEvent.exec_errno === 'EACCES'
              ? 'eacces'
              : null;
        if (failedResult !== null) {
          const spawnRaw: SpawnEvent = {
            kind: 'spawn',
            argv: spawnArgv,
            result: failedResult,
            pid: shimEvent.pid,
            ts: shimEvent.ts,
            ...(shimEvent.audit_blind ? { audit_blind: true as const } : {}),
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
    installStdoutTail: input.strace.getStdoutTail?.() ?? '',
  };
}

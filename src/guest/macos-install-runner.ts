// macOS install runner — the StraceRunner for the macOS-bare backend.
//
// On Linux, Phase B runs the install command under `strace -ff` and the
// LinuxStraceRunner merges two channels: strace's per-pid text files AND the
// trusted JSONL shim channel (fd-3 pipe + SCRIPT_JAIL_LOG_FILE events file).
//
// macOS has no strace and no /proc, so the Mach-O shim is the SOLE event
// source: it emits absolute-path read/write, exec, env_read, env_tamper,
// connect, and node_startup_done JSONL into SCRIPT_JAIL_LOG_FILE (and env-spy
// writes env_read / node_startup_done JSONL into the same file).  This runner
// therefore:
//
//   - spawns the install command DIRECTLY (no `strace`, no `unshare` — the
//     macOS backend is observe-only and stays online per the plan),
//   - reuses `runStraceTailer` for the events-file + fd-3 channel ONLY (every
//     yielded line carries `source:'shim'`; there are no per-pid strace files
//     so the strace text channel never fires), inheriting the fs-based
//     events-file tamper machinery (inode/dev baseline + mtime/ctime/size
//     monotonicity) BUT omitting the parent-dir rename watcher: that watcher is
//     Linux-inotify-specific and FSEvents (which backs macOS `fs.watch`) reports
//     'rename' for ordinary appends, so it would false-positive on every run.
//     The transient rename-aside-and-back case it guards is a documented macOS
//     fidelity gap; the inode/dev/mtime/ctime baseline still fails closed,
//   - returns `getRootPid()→null`: there is no strace direct-child to pin, and
//     the macOS dispatch loop (`runInstallPhaseMacos`) does no cwd/dirfd
//     resolution that would need a seeded root pid (paths are already absolute).
//
// The StraceRunner interface fits unchanged: `run()` yields {pid,line,source},
// `getExitCode()`/`getTamperReason()`/`recordTamper()` behave exactly as the
// Linux runner's, and `getRootPid()` opts out with null.
//
// Linux behaviour is untouched — this module is only constructed on the
// macOS-bare path (see agent.ts main()).

import { spawn } from 'node:child_process';
import { basename, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';

import {
  runStraceTailer,
  type EventsFile,
  type SpawnImpl,
} from './agent.js';
import type { LineSource, StraceRunner } from './phase-install.js';

export class MacOSInstallRunner implements StraceRunner {
  private _exitCode = 0;
  private readonly _spawnImpl: SpawnImpl;
  private readonly _eventsFile: EventsFile | null;
  private readonly _tamperRef: { reason: string | null } = { reason: null };

  /**
   * @param spawnImpl  Injection seam for tests.  Production passes through to
   *                   `node:child_process.spawn`.
   * @param eventsFile Per-run events-file handle (path + baseline inode/dev)
   *                   created by the agent before the install launches.  When
   *                   `null`, the runner does not tail a shared events file
   *                   (used by tests that supply a pre-set environment via the
   *                   `opts.env` passed to `run()`).
   */
  constructor(spawnImpl?: SpawnImpl, eventsFile?: EventsFile | null) {
    this._spawnImpl = spawnImpl ?? (spawn as unknown as SpawnImpl);
    this._eventsFile = eventsFile ?? null;
  }

  getExitCode(): number {
    return this._exitCode;
  }

  /**
   * Returns the human-readable tamper reason recorded by the tailer's
   * events-file watcher, or null.  macOS keeps the fs-based inode/dev baseline +
   * mtime/ctime/size monotonicity (the SAME checks the Linux runner uses) but
   * omits the parent-dir rename watcher (FSEvents reports 'rename' for ordinary
   * appends → false positives) and the strace-derived <SYSCALL_EXEC_BYPASS> /
   * <EVENTS_FILE_FORGERY> detectors (no kernel channel to cross-check against).
   */
  getTamperReason(): string | null {
    return this._tamperRef.reason;
  }

  /**
   * Plumb a tamper reason from {@link runInstallPhaseMacos} (shim-channel JSONL
   * parse failures) into the same `_tamperRef` slot the events-file watcher
   * uses.  First-writer-wins — once non-null, subsequent calls are dropped so
   * the earliest signal survives.
   */
  recordTamper(reason: string): void {
    if (this._tamperRef.reason === null) {
      this._tamperRef.reason = reason;
    }
  }

  /**
   * No strace direct-child to pin, and the macOS dispatch loop does no
   * cwd/dirfd resolution that needs a seeded root pid (paths are already
   * absolute).  Opt out with null — the dispatcher then seeds nothing and
   * every event flows through the lean shim-only path.
   */
  getRootPid(): number | null {
    return null;
  }

  async *run(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string; basePath: string },
  ): AsyncIterable<{ pid: number; line: string; source: LineSource }> {
    // Spawn the install command DIRECTLY — no `strace`, no `unshare`.  The
    // Mach-O shim (DYLD_INSERT_LIBRARIES, set by buildChildEnvMacos) is the
    // sole event source; it writes JSONL into SCRIPT_JAIL_LOG_FILE.
    //
    // stdio:
    //   fd 0: stdin  → ignored
    //   fd 1: stdout → ignored
    //   fd 2: stderr → pipe (forwarded to process.stderr with a [macos] prefix)
    //   fd 3: pipe   → JSON channel for JS preloads that still write to fd 3
    //                  (env-spy's primary sink is the events file, but the
    //                  fd-3 fallback is kept for parity with the Linux wiring).
    const child = this._spawnImpl(cmd, args, {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ['ignore', 'ignore', 'pipe', 'pipe'],
    });

    // Capture the install command's exit disposition (code + signal) so the
    // tailer can tell a CLEAN exit from an ABNORMAL termination.  Mutated BEFORE
    // resolve() so exitPromise.then() observes it.  See
    // StraceTailerOptions.exitStatusRef.
    const exitStatus: { code: number | null; signal: NodeJS.Signals | null; spawnError?: boolean } = {
      code: null,
      signal: null,
    };
    const exitPromise = new Promise<void>((resolve) => {
      child.on('close', (code, signal) => {
        exitStatus.code = code;
        exitStatus.signal = signal;
        this._exitCode = code ?? 1;
        resolve();
      });
      child.on('error', () => {
        exitStatus.spawnError = true;
        this._exitCode = 1;
        resolve();
      });
    });

    // There are no per-pid strace files on macOS.  `runStraceTailer` still
    // needs a watchDir + basePrefix for its (here always-empty) per-pid file
    // scan; point it at the basePath's directory.  No file will ever match the
    // prefix, so the strace text channel stays silent and only the events-file
    // + fd-3 shim channel produces lines.
    const watchDir = dirname(opts.basePath);
    const basePrefix = basename(opts.basePath);

    // child.stdio[3] is the read end of the fd-3 pipe.
    const fd3Stream = child.stdio[3] as Readable | null;

    // Forward the install command's stderr line-by-line to process.stderr with
    // a [macos] prefix so diagnostics land on the orchestrator's console.
    let stderrRl: ReturnType<typeof createInterface> | null = null;
    if (child.stderr) {
      stderrRl = createInterface({ input: child.stderr, crlfDelay: Infinity });
      stderrRl.on('line', (line: string) => {
        process.stderr.write(`[macos] ${line}\n`);
      });
    }

    try {
      yield* runStraceTailer({
        watchDir,
        basePrefix,
        fd3Stream,
        ...(this._eventsFile !== null ? {
          eventsFilePath: this._eventsFile.path,
          eventsBaseline: this._eventsFile.baseline,
          // macOS DELIBERATELY omits eventsDirPath (+ eventsFileBasename) so the
          // parent-dir rename watcher stays OFF.  That watcher is tuned for Linux
          // inotify, where a Node 'rename' event means IN_MOVED/IN_CREATE/
          // IN_DELETE.  On macOS `fs.watch` is backed by FSEvents, which reports
          // 'rename' for ORDINARY appends too — so it would record a false
          // "events file parent directory rename detected" tamper on every run
          // and refuse to emit a lock.  The robust inode/dev/mtime/ctime baseline
          // and the events-FILE watcher remain active (they key off
          // eventsFilePath/eventsBaseline and are FS-semantics-agnostic), so the
          // lock is still trustworthy; we lose only the transient
          // rename-aside-and-back detection (a documented macOS fidelity gap,
          // alongside the dropped strace-derived detectors).
          tamperRef: this._tamperRef,
        } : {}),
        exitPromise,
        exitStatusRef: exitStatus,
        // No root-pid seeding: getRootPid() is null on macOS by design.  We do
        // NOT install recordRootPid — the install root would otherwise be
        // mis-pinned to the first phantom per-pid file (there are none here).
      });
    } finally {
      if (stderrRl !== null) {
        stderrRl.close();
        stderrRl = null;
      }
    }
  }
}

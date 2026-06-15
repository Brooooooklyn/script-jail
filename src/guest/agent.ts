// script-jail — agent.ts
// Guest orchestrator. Runs inside the Firecracker microVM.
//
// Flow:
//   1. Read + validate /etc/script-jail/config.yml
//   2. Detect package manager from lockfile presence
//   3. Build env dict for child processes
//   4. Connect to host via vsock (or injected Connection in tests)
//   5. Phase A (fetch, network on) → emit handshake "fetch_done"
//   6. Wait for host "go" signal
//   7. Phase B (install, network off, strace) → emit handshake "install_done"
//   8. Normalize + render → emitFinalLockfile
//   9. Exit

import { existsSync, readFileSync, watch as fsWatch, readdirSync, statSync, openSync, readSync, closeSync, fstatSync, mkdirSync, mkdtempSync, chmodSync, realpathSync, constants as fsConstants, type Stats } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import { createServer, type Server, type Socket } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import { PassThrough, Writable, type Readable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { dirname, basename, join as joinPath } from 'node:path';

import { Attribution, buildRootPkgKeys } from './attribution.js';
import { deriveSensitiveValues, maskExactValues, redactCredentialShapes } from '../shared/redact.js';
import { LinuxProcReader } from './proc-reader.js';
import { MacOSProcReader } from './proc-reader-macos.js';
import { Emitter } from './emit.js';
import { runFetchPhase, type Spawner } from './phase-fetch.js';
import { runInstallPhase, type LineSource, type StraceRunner } from './phase-install.js';
import { runInstallPhaseMacos, macosManagerLaunch } from './phase-install-macos.js';
import { MacOSInstallRunner } from './macos-install-runner.js';
import { ProtectedPathsMatcher } from './protected-paths.js';
import { normalize, type NormalizeContext } from '../lock/normalize.js';
import { render } from '../lock/render.js';
import { discoverPkgDirs } from './discover-pkg-dirs.js';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  CANON_PROTECTED_ENV_NAMES_MAX_LEN,
  MAX_PROTECTED_ENV_NAMES,
  PROTECTED_NAME_MAX_LEN,
} from '../shim/canon-buf-len.js';

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

const AgentConfig = z.object({
  protected: z.object({
    files: z.array(z.string()).default([]),
    env: z.array(z.string()).default([]),
  }).default({ files: [], env: [] }),
  spoof: z.object({
    platform: z.enum(['linux', 'darwin', 'win32']).default('linux'),
    arch: z.enum(['x64', 'arm64']).default('x64'),
  }).default({ platform: 'linux', arch: 'x64' }),
  // YAML happily decodes `node_version: 20` as a number; users will almost
  // always write the bare integer (matching how every Node-related field in
  // the rest of their CI YAML reads).  Coerce to string before Zod's `string()`
  // gate so the config doesn't reject on a stylistic ambiguity.  The field is
  // informational anyway — `process.version` of the running interpreter is the
  // authoritative source the renderer captures (see comment at the
  // `render({...})` call below).
  node_version: z.coerce.string().default(''),
  manager_lockfile_sha256: z.string().default(''),
  /** Absolute path to the lockfile inside the VM (used to detect manager). */
  lockfile_path: z.string().default(''),
  /** Where packages are installed inside the VM. Default: /work */
  work_dir: z.string().default('/work'),
  /** Log fd number. Default: 3 */
  log_fd: z.number().int().default(3),
  /** Per-package dirs for normalize context, keyed by pkg@version */
  pkg_dirs: z.record(z.string(), z.string()).default({}),
  /** Package manager override. Auto-detected from lockfile if not set. */
  manager: z.enum(['npm', 'pnpm', 'yarn']).optional(),
});

export type AgentConfig = z.infer<typeof AgentConfig>;

// ---------------------------------------------------------------------------
// Connection abstraction
// ---------------------------------------------------------------------------

export interface Connection {
  readable: Readable;
  writable: Writable;
  close(): void;
}

/**
 * Production connection via Linux vsock.
 *
 * Node has no native AF_VSOCK support, so the data path in the VM is:
 *   Firecracker -> AF_VSOCK port 10242 (socat in guest, see init.sh)
 *                  -> TCP 127.0.0.1:10243 (this listener)
 *
 * The guest agent LISTENS — Firecracker, via socat, makes the inbound
 * connection — so we open a TCP server on the loopback, await the first
 * (and only) inbound connection, then stop accepting.  Use the static
 * `listen()` factory; the constructor is internal.
 */
export class LinuxVsockConnection implements Connection {
  readonly readable: Readable;
  readonly writable: Writable;
  private readonly sock: Socket;
  private readonly server: Server;

  private constructor(server: Server, sock: Socket) {
    this.server = server;
    this.sock = sock;
    this.readable = sock;
    this.writable = sock;
  }

  /**
   * Bind a TCP listener on 127.0.0.1:<port>, wait for the single inbound
   * connection from the socat AF_VSOCK->TCP bridge, then stop listening
   * (one-shot).  Resolves once the host's connection has been accepted.
   */
  static async listen(port: number): Promise<LinuxVsockConnection> {
    const server = createServer();
    return new Promise<LinuxVsockConnection>((resolve, reject) => {
      const onError = (err: Error): void => {
        server.removeListener('connection', onConnection);
        reject(err);
      };
      const onConnection = (sock: Socket): void => {
        server.removeListener('error', onError);
        // One-shot: stop accepting further connections.  Existing accepted
        // socket stays open; `server.close()` only stops the listener.
        server.close();
        resolve(new LinuxVsockConnection(server, sock));
      };
      server.once('error', onError);
      server.once('connection', onConnection);
      server.listen(port, '127.0.0.1');
    });
  }

  close(): void {
    // Graceful half-close instead of `destroy()`: `end()` flushes any
    // buffered writes through the kernel send queue and sends FIN, so the
    // host (socat → vsock) receives the trailing JSONL frame BEFORE seeing
    // EOF.  `destroy()` aborts the connection, dropping any frame still in
    // the libuv write queue — the exact bug behind the "vsock session ended
    // without a final frame" with no upstream error context.
    //
    // The socket will be fully closed once the peer ACKs the FIN; the
    // event loop won't exit until then (good — we want to keep the process
    // alive long enough to flush).  For error paths that must call
    // process.exit(N), use `flushAndExit()` below — it waits for the
    // `end()` callback before exiting.
    this.sock.end();
    this.server.close();
  }
}

/**
 * Flush any pending writes to `writable`, then `process.exit(code)`.
 *
 * Why this exists: previously the agent's error paths did
 *   emitter.emitError(msg, true)
 *   input.connection.close()
 *   process.exit(1)
 * with `close()` calling `sock.destroy()` and `process.exit(1)` exiting
 * synchronously — both of which abandon bytes still in the libuv write
 * queue.  The host saw the connection close with no error frame and
 * surfaced the misleading "vsock session ended without a final frame".
 *
 * `writable.end(cb)` writes any buffered bytes, sends FIN, then invokes
 * `cb` once the bytes are in the kernel send buffer — at which point
 * socat (and the host) will receive them before the close.
 *
 * A 1 s ceiling guards against a wedged peer: a broken socket should not
 * be able to pin the agent forever just because it can't ACK.
 */
function flushAndExit(writable: NodeJS.WritableStream, code: number): void {
  // Capture the current `process.exit` so tests that swap it inside a
  // try/finally still see their stub when this function's writable-end
  // callback fires asynchronously, AFTER the test's `finally` has restored
  // the real exit.  Without the capture, the restored real (or
  // vitest-wrapped) exit terminates the test runner.
  const exitFn = process.exit.bind(process);
  let exited = false;
  const exitOnce = (): void => {
    if (exited) return;
    exited = true;
    exitFn(code);
  };
  const timer = setTimeout(exitOnce, 1000);
  timer.unref();
  try {
    writable.end(() => {
      clearTimeout(timer);
      exitOnce();
    });
  } catch {
    clearTimeout(timer);
    exitOnce();
  }
}

/** In-memory connection for tests. */
export class MemoryConnection implements Connection {
  readonly readable: Readable;
  readonly writable: Writable;

  constructor(readable: Readable, writable: Writable) {
    this.readable = readable;
    this.writable = writable;
  }

  close(): void {
    // Nothing to close for an in-memory stream.
  }
}

export class StdioConnection implements Connection {
  readonly readable: Readable;
  readonly writable: Writable;

  constructor() {
    this.readable = process.stdin;
    this.writable = process.stdout;
  }

  close(): void {
    process.stdout.end();
  }
}

// ---------------------------------------------------------------------------
// Production Spawner (Phase A only)
// ---------------------------------------------------------------------------

/** Production spawner wrapping node:child_process.spawn. Used for Phase A only.
 *  Phase B install is driven exclusively by the StraceRunner. */
export class LinuxSpawner implements Spawner {
  async spawn(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: opts.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

      child.on('error', reject);
      child.on('close', (code) => {
        resolve({ exitCode: code ?? 1, stdout, stderr });
      });
    });
  }
}

/**
 * macOS Phase-A (fetch) spawner.  Rewrites the bare `npm`/`pnpm`/`yarn` fetch
 * command into the provisioned `<re-signed node> <cli.js>` / corepack launch
 * (see `macosManagerLaunch`) so the first exec stays plain-arm64 and DYLD
 * survives.  The bare bin would otherwise shebang through `/usr/bin/env` (SIP
 * strips DYLD) or resolve to an arm64e ambient pm (dyld rejects our thin-arm64
 * insert) — Phase A would either run un-instrumented or crash at launch.  This
 * makes Phase A symmetric with the Phase-B `MacOSInstallRunner`, which already
 * launches via the same node+cli form.  The actual child-process plumbing is
 * delegated to `LinuxSpawner`; only the command is rewritten.  A non-manager
 * `cmd` (none today on the fetch path) passes through unchanged.
 */
export class MacOSSpawner implements Spawner {
  async spawn(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    const launch =
      cmd === 'npm' || cmd === 'pnpm' || cmd === 'yarn'
        ? macosManagerLaunch(cmd, args)
        : { cmd, args };
    return new LinuxSpawner().spawn(launch.cmd, launch.args, opts);
  }
}

// ---------------------------------------------------------------------------
// Production StraceRunner
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// StraceTailer — exported for unit tests
// ---------------------------------------------------------------------------

/**
 * Options for StraceTailer. The `fd3Stream` seam lets tests inject a fake
 * Readable instead of an actual child-process pipe.
 */
export interface StraceTailerOptions {
  /** Directory to watch for new per-pid strace output files. */
  watchDir: string;
  /** Basename prefix of per-pid files (e.g. "strace.out" → files like "strace.out.12345"). */
  basePrefix: string;
  /**
   * Readable stream representing the child's fd 3 (LD_PRELOAD JSONL).
   * When null, no fd-3 lines are emitted (useful when the child doesn't write to fd 3).
   */
  fd3Stream: Readable | null;
  /**
   * Absolute path of a shared JSONL events file produced by the env-shim and
   * env-spy preload (production channel — see {@link createEventsFile}).
   * Tailed alongside per-pid strace files; lines arrive with pid=0 (the same
   * synthetic pid we use for fd3 lines, since attribution happens later from
   * the embedded pid field).  When undefined, no events-file polling is done.
   */
  eventsFilePath?: string;
  /**
   * Baseline {inode, device} captured at events-file creation time.  On every
   * drain cycle the tailer re-stats the path and compares against this
   * baseline; any mismatch (replacement, deletion, EACCES, size shrinkage)
   * is recorded into `tamperRef.reason` so the agent can fail closed at
   * post-install time.
   *
   * SECURITY: this is the only barrier against a malicious lifecycle script
   * that unlinks / truncates / replaces the events file to erase
   * `audit_bypass` evidence before the tailer reads it.  When undefined no
   * tamper checking is performed (used by tests that supply a private path).
   *
   * `mtimeNs` and `ctimeNs` (both captured at file creation in
   * `createEventsFile`) are also part of the baseline so the tailer can
   * detect the "utimes restore" tamper: append → truncate → utimes-back-to-
   * original-mtime.  Pure mtime checking misses this because utimes can set
   * mtime to any value; ctime cannot — the kernel always advances ctime on
   * any metadata or content change.  See `drainEventsFile` for the
   * "ctime advanced without consumed bytes" gate that closes this hole.
   */
  eventsBaseline?: { ino: bigint; dev: bigint; mtimeNs: bigint; ctimeNs: bigint };
  /**
   * Absolute path of the parent directory that contains the events file
   * (Finding B).  When provided the tailer attaches a second `fs.watch` to
   * this directory and treats any `rename` event affecting the events-file
   * basename as tamper.
   *
   * Why this exists in addition to the inode-baseline check on the events
   * file itself: a hostile lifecycle script can `rename(events.jsonl,
   * events.bak)` aside, create a decoy at the same path, spawn a child that
   * `open()`s the decoy, then `rename(events.bak, events.jsonl)` back.  By
   * the time the next drain re-stats the path, the baseline inode is back —
   * but the child's fd is wired to the decoy and the original file's events
   * (including any `audit_bypass`) are dropped for that child.  The
   * directory-level inotify watch catches the transient swap because the
   * kernel reports IN_MOVED_FROM / IN_MOVED_TO regardless of timing.
   *
   * Test runners that supply a fake StraceRunner and want the watcher
   * inactive simply omit this option.
   */
  eventsDirPath?: string;
  /**
   * Basename of the events file inside `eventsDirPath`.  Used to filter the
   * directory watcher's `rename` events; the watcher only flags tamper when
   * a rename affects this exact basename.  Defaults to the basename of
   * `eventsFilePath` when both are provided.
   */
  eventsFileBasename?: string;
  /**
   * Optional sink for tamper detection.  When the tailer detects events-file
   * tampering it writes a human-readable reason here; the agent's main loop
   * reads this after install completes and fails closed if it is non-empty.
   * Using a ref-object so the writer (tailer) and reader (main) share state
   * without forcing an extra parameter through the StraceRunner interface.
   */
  tamperRef?: { reason: string | null };
  /**
   * Promise that resolves when the traced child process has exited.
   * The tailer waits for this, then does one final drain poll, then ends.
   */
  exitPromise: Promise<void>;
  /**
   * Disposition of the traced process (strace) at exit, populated by the
   * runner's close/error handler BEFORE {@link exitPromise} resolves.
   *
   * The post-exit freeze of the two "advanced WITHOUT new bytes" meta gates
   * (see the `childExited` flag in {@link runStraceTailer}) is a RELAXATION, so
   * it engages ONLY when strace exited NORMALLY — i.e. by exit(), `signal ===
   * null`, REGARDLESS of the exit code.  `strace -f` exits only after the WHOLE
   * traced tree has exited, so a normal strace exit (even a non-zero code,
   * which it propagates from a legitimately-failing-but-audited install) means
   * no in-model writer remains to race the polling window.  When strace is
   * instead terminated by a SIGNAL (`signal !== null`) — or fails to spawn
   * (`spawnError`) — a tracee may have killed its tracer and detached, or the
   * audit never ran; the tailer records a fatal tamper and leaves the gates
   * ARMED (fail closed).  A non-zero exit code alone is NOT abnormal here: it is
   * the tracee's propagated status, and treating it as tamper would refuse a
   * lockfile for every offline/failing postinstall (see the non-zero-Phase-B
   * leniency in main()).
   *
   * WHO MAY PASS THIS (security invariant — do NOT "fix" by widening): ONLY a
   * runner whose exit signal proves the WHOLE descendant tree has exited may
   * populate exitStatusRef, because the freeze trusts that proof.  That is the
   * Linux {@link LinuxStraceRunner}, which runs `strace -ff` and resolves
   * exitPromise only after the entire traced tree is gone.  The macOS
   * {@link MacOSInstallRunner} spawns the install command DIRECTLY (no
   * `strace -ff`) and resolves on that ONE process's close, so a normal exit
   * does NOT prove a daemonized/backgrounded descendant has exited — it MUST
   * NOT pass exitStatusRef.  When the disposition is absent (the macOS runner,
   * and unit tests that don't model exit status) the relaxation stays OFF and
   * the meta gates remain ARMED post-exit: fail-closed by default.  Passing a
   * normal-exit disposition from a direct-spawn runner would reopen the
   * post-exit survivor-tamper gap (Codex round-2 finding 1).
   */
  exitStatusRef?: { code: number | null; signal: NodeJS.Signals | null; spawnError?: boolean };
  /** Poll interval in ms for directory scan and file growth checks (default 50). */
  pollIntervalMs?: number;
  /** Extra drain time in ms after child exit to catch final writes (default 100). */
  drainMs?: number;
  /**
   * Hard cap (ms) on the post-exit settle loop that re-scans the per-pid
   * strace files until the capture stops growing (default 2000).  The loop
   * NEVER kills strace — by the time it runs strace has already exited and
   * flushed+closed every per-pid file, so this only bounds how long the
   * tailer keeps RE-READING.  Generous because all files are already final.
   * If the loop reaches this cap WITHOUT two quiet passes, the capture could
   * not be confirmed complete: the tailer records tamper (via {@link
   * tamperRef}) so the agent fails closed rather than emit a clean-looking
   * lockfile from a possibly-incomplete capture.
   */
  settleHardCapMs?: number;
  /**
   * Number of consecutive settle passes that must observe NO new per-pid
   * file and NO new bytes before the tailer concludes the capture is
   * complete (default 2).  A single `readdirSync` can momentarily miss a
   * just-created per-pid file (the sub-millisecond cmd-shim helpers
   * `dirname`/`sed`/`uname` are the motivating case); requiring two quiet
   * passes closes that enumeration window deterministically.
   */
  settleQuietPasses?: number;
  /**
   * Optional callback invoked once with the pid of the FIRST per-pid
   * strace output file discovered during tailing — i.e. the install
   * command's pid (strace's direct child).  Used by
   * `LinuxStraceRunner.getRootPid()` to expose the audit root to the
   * dispatcher in {@link runInstallPhase} so it can seed cwd state
   * for EXACTLY one pid instead of relying on a "first observed pid
   * wins" heuristic that could mis-seed a child whose strace per-pid
   * file is drained before the parent's.
   *
   * Strace's `-ff -o <basePath>` writes per-pid files in the order
   * the kernel creates the pids; the install command's pid is the
   * first one created (it's strace's direct child).  Polling /
   * inotify may yield those files in a different order than they
   * were created, but the FIRST file ever observed during the
   * tailing loop is overwhelmingly the install command's — there's
   * a small window during which no events have been written yet to
   * any per-pid file.  When the first poll/watch fires, the only
   * file present is the install command's.  We capture that pid
   * here.
   *
   * If no file is ever discovered (strace failed to spawn), the
   * callback is never invoked.
   */
  recordRootPid?(pid: number): void;
}

/**
 * StraceTailer merges:
 *   1. Lines from per-pid strace output files  → { pid: <pid>, line, source: 'strace' }
 *   2. JSONL lines from the fd3Stream pipe      → { pid: 0, line, source: 'shim' }
 *   3. JSONL lines from the events file path    → { pid: 0, line, source: 'shim' }
 *
 * The `source` discriminator lets the caller dispatch parsers safely: the
 * trusted shim channel never falls back to the strace text parser (which
 * would mask a partial-line poisoning attack — see {@link LineSource}),
 * and the strace channel never gets fed to the strict JSONL parser.
 *
 * The async generator ends once the child has exited and all trailing writes
 * have been drained.
 *
 * Exported separately so tests can exercise it without spawning real strace.
 */
export async function* runStraceTailer(
  opts: StraceTailerOptions,
): AsyncGenerator<{ pid: number; line: string; source: LineSource }> {
  const pollIntervalMs = opts.pollIntervalMs ?? 50;
  const drainMs = opts.drainMs ?? 100;
  const settleHardCapMs = opts.settleHardCapMs ?? 2000;
  const settleQuietPasses = opts.settleQuietPasses ?? 2;

  // Bounded async sleep used by the post-exit settle loop.  `unref` so a
  // pending delay never by itself keeps the process alive.
  const delay = (ms: number): Promise<void> =>
    new Promise<void>((resolve) => {
      const t = setTimeout(resolve, ms);
      (t as unknown as { unref?: () => void }).unref?.();
    });

  // Shared queue: all sources push here; the generator drains it.
  const queue: Array<{ pid: number; line: string; source: LineSource }> = [];
  let done = false; // set true once the child has exited and drain is complete

  // Notify the generator loop that new items are available or done changed.
  let wakeResolve: (() => void) | null = null;
  function wake(): void {
    if (wakeResolve) { const r = wakeResolve; wakeResolve = null; r(); }
  }

  // ---- per-pid file tailers -------------------------------------------------

  // Map from filename → current read position in that file.
  const filePos = new Map<string, number>();
  // Map from filename → partial (unterminated) line buffer.
  const fileBuf = new Map<string, string>();
  // Tracks whether we've already invoked opts.recordRootPid.  The FIRST
  // per-pid file ever discovered (by `pollDir` or `fs.watch`) is the
  // install command's strace output — strace writes the install root's
  // file before any of its descendants' files are created.  When this
  // flag is false and a parseable pid is encountered in `drainFile`,
  // we report the pid and flip the flag.
  let rootPidReported = false;

  function parsePidFromFilename(name: string): number {
    const suffix = name.slice(opts.basePrefix.length + 1); // strip "strace.out."
    const n = parseInt(suffix, 10);
    return isFinite(n) ? n : 0;
  }

  function drainFile(name: string): void {
    const fullPath = `${opts.watchDir}/${name}`;
    const pid = parsePidFromFilename(name);
    // Report the FIRST observed per-pid file's pid as the install root.
    // We check `filePos.has(name)` rather than `pos === 0` because a pid
    // observation BEFORE the file has any bytes is still a valid signal
    // — the file existed, the kernel chose that pid, that's enough to
    // pin the install root.  Subsequent drainFile calls for OTHER
    // filenames are descendants and must not overwrite the root.
    if (!rootPidReported && pid > 0 && !filePos.has(name)) {
      rootPidReported = true;
      try {
        opts.recordRootPid?.(pid);
      } catch {
        // Recording is best-effort; a callback throw must not abort
        // the tailer.  In practice the recorder just sets a field.
      }
    }
    const pos = filePos.get(name) ?? 0;

    let size = 0;
    try {
      size = statSync(fullPath).size;
    } catch {
      return; // file disappeared — ignore
    }
    if (size <= pos) return; // no new bytes

    const toRead = size - pos;
    const buf = Buffer.allocUnsafe(toRead);
    let fd = -1;
    let bytesRead = 0;
    try {
      fd = openSync(fullPath, 'r');
      bytesRead = readSync(fd, buf, 0, toRead, pos);
    } catch {
      if (fd >= 0) { try { closeSync(fd); } catch { /* ignore */ } }
      return;
    }
    closeSync(fd);

    filePos.set(name, pos + bytesRead);

    const chunk = (fileBuf.get(name) ?? '') + buf.slice(0, bytesRead).toString('utf8');
    const newlineIdx = chunk.lastIndexOf('\n');
    if (newlineIdx === -1) {
      fileBuf.set(name, chunk);
      return;
    }

    const complete = chunk.slice(0, newlineIdx);
    const remainder = chunk.slice(newlineIdx + 1);
    fileBuf.set(name, remainder);

    for (const line of complete.split('\n')) {
      if (line.length > 0) {
        // Per-pid strace files carry strace's text format — tagged
        // `'strace'` so the install-phase dispatcher never tries to
        // JSON.parse them.
        queue.push({ pid, line, source: 'strace' });
      }
    }
    wake();
  }

  function pollDir(): void {
    let entries: string[];
    try {
      entries = readdirSync(opts.watchDir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (!name.startsWith(opts.basePrefix + '.')) continue;
      drainFile(name);
    }
  }

  // ---- events-file tailer --------------------------------------------------
  //
  // Distinct from per-pid strace files because the events file lives outside
  // watchDir and a single absolute path (rather than a "prefix.PID" pattern)
  // is enough to identify it.  Position + partial-line buffer mirror the
  // per-pid logic in drainFile().
  //
  // SECURITY: every drain cycle re-stats the path and compares inode/device
  // against `opts.eventsBaseline`.  Any mismatch (the audited script
  // unlinked + recreated the file, replaced it with a symlink, truncated
  // it, or made it unreadable) is recorded into `opts.tamperRef.reason`.
  // The agent's main loop reads that after install completes and fails
  // closed.  Without this gate, a `rm /tmp/script-jail-events.jsonl`
  // followed by `envp_alloc_failed` would erase the `audit_bypass` signal
  // and let the action's check mode return clean.
  //
  // Append-then-truncate defence (Finding A): a polling tailer with a 50ms
  // window can MISS an intermediate `append → grow → truncate-back` cycle
  // entirely, because the next poll observes `size === eventsPos` again and
  // the new bytes are gone.  Multiple cross-checks plug the hole:
  //   1. `lastMtime` — kernel updates st_mtim on EVERY write; truncate(2)
  //      counts as a write.  If poll N sees mtime > lastMtime but the file
  //      is the same size as at the previous read position, bytes were
  //      written and then discarded between polls.
  //   2. `maxSeenSize` — monotonically tracks the largest size ever observed
  //      across polls.  A poll that observes `size < maxSeenSize` (even when
  //      `size >= eventsPos`) means the file was truncated.  This catches
  //      the case where a poll happens to land between an append and the
  //      truncation that follows.
  //   3. `lastConsumedCtime` — ctime advances on every metadata or content
  //      change AND CANNOT be reset by utimes(2) (only mtime/atime can).
  //      A second-finding (audit-trust 2026-05-18) tamper: append a line,
  //      truncate back to the previous size, THEN `utimes(path, atime,
  //      oldMtime)` to restore the original mtime.  That sequence leaves
  //      size === eventsPos AND mtime == lastMtime, so checks (1) and (2)
  //      see nothing — but ctime is now strictly greater than the ctime we
  //      observed at our last successful drain.  Flagging "ctime advanced
  //      since last drain but size still at eventsPos" closes the hole.
  //   4. mtime regression: a `utimes(path, atime, oldMtime)` that restores
  //      a previously-pinned mtime is itself tamper — legitimate writes
  //      only move mtime forward.  `mtime < maxObservedMtime` => tamper.
  // We also wire `fs.watch` (inotify on Linux) on the events file inode so
  // truncate(2) / open(O_TRUNC) generate `change` events the polling loop
  // would otherwise have to race to observe.
  let eventsPos = 0;
  let eventsBuf = '';
  let lastMtime: bigint = -1n; // -1n until first successful stat
  let maxSeenSize = 0;
  // Baseline ctime, captured at file creation in createEventsFile.  Updated
  // to the current ctime each time we successfully read bytes from the
  // file (the only legitimate cause of ctime advancement).  Any drain that
  // sees `current.ctime > lastConsumedCtime` while `size === eventsPos`
  // means something modified the file without leaving bytes for us — the
  // utimes-restore tamper signature.  Initialized lazily on the first
  // successful stat when no baseline was provided (tests that omit
  // eventsBaseline get the old behaviour).
  let lastConsumedCtime: bigint =
    opts.eventsBaseline !== undefined ? opts.eventsBaseline.ctimeNs : -1n;
  // Track max observed mtime across polls so a `utimes`-driven REGRESSION
  // is flagged even if it happens to land between drains.  Initialized from
  // the baseline mtime when known so utimes-back-to-pre-creation timestamps
  // are caught from the first poll.
  let maxObservedMtime: bigint =
    opts.eventsBaseline !== undefined ? opts.eventsBaseline.mtimeNs : -1n;
  // 2026-05-19: number of consecutive polls observing `ctime/mtime advanced
  // AND size === eventsPos` before flagging tamper.  Linux 5.10 (Ubuntu 22.04
  // rootfs) sometimes returns stat() with newer ctime/mtime than the
  // size-update it accompanies, producing a one-shot false positive during
  // active writes.  Three consecutive polls (~3 × pollIntervalMs) is enough
  // to outlast the kernel's lazy settle while still catching the real
  // tampers: a utimes-restore leaves the file quiescent after the attack,
  // and an append-then-truncate that bumps mtime without bytes likewise
  // settles past the kernel's lazy window.
  let ctimeAdvanceStablePolls = 0;
  let mtimeAdvanceStablePolls = 0;
  const META_ADVANCE_REQUIRED_POLLS = 3;
  // 2026-06-11: freeze the two "advanced WITHOUT new bytes" meta gates once the
  // traced process tree has exited.  Those gates are defense-in-depth against a
  // LIVE attacker racing the polling window with an append->truncate(->utimes-
  // restore) cycle that leaves `size === eventsPos`.  `strace -f` resolves
  // exitPromise only AFTER the whole traced tree has exited, so once
  // `childExited` is set no in-model process remains to perform that race.
  // Meanwhile the Ubuntu-22.04 microVM kernel finalizes the ctime of the LAST
  // byte-consuming write a few hundred microseconds AFTER readSync returns, with
  // mtime + size unchanged; at END OF AUDIT (writes stopped, `size ===
  // eventsPos` forever) that state is PERMANENT and would accumulate
  // META_ADVANCE_REQUIRED_POLLS into a FALSE "advanced without new bytes" tamper
  // that refuses a clean lockfile (observed flaking CI parity-test).  Freezing
  // ONLY these two counters post-exit removes the false positive without
  // weakening in-model detection: every other gate (size-grow drain, maxSeenSize
  // shrink, mtime-regression, inode/rename watchers) stays active post-exit, and
  // both gates stay fully strict for the ENTIRE active phase (the existing
  // utimes-restore + append-truncate tests trip pre-exit).  The only relaxation
  // is reachable solely by a process that outlived the tracer — outside the
  // audit's threat model.
  let childExited = false;
  // Provisional "ctime advanced without new bytes" verdict (2026-06-12).  The
  // end-of-audit lazy ctime finalize accumulates this gate's strikes BEFORE the
  // clean-exit disposition can flip `childExited` (a >150ms race on large
  // repos), so the ctime gate writes its suspicion HERE instead of firing the
  // fatal directly.  The exitPromise handler VOIDS it on a clean whole-tree
  // exit (benign finalize) and PROMOTES it (via recordTamper) after the settle
  // loop on an abnormal exit or when no disposition is supplied (macOS / unit
  // tests — fail-closed).  The mtime-advance gate keeps firing synchronously:
  // mtime is stamped at write time and does not exhibit the lazy finalize.
  let pendingCtimeTamper: string | null = null;
  function recordTamper(reason: string): void {
    if (opts.tamperRef && opts.tamperRef.reason === null) {
      opts.tamperRef.reason = reason;
    }
  }
  function drainEventsFile(): void {
    const path = opts.eventsFilePath;
    if (path === undefined || path === '') return;

    let stat: Stats;
    try {
      stat = statSync(path, { bigint: true }) as unknown as Stats;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        recordTamper(`events file disappeared: ${path}`);
      } else if (code === 'EACCES' || code === 'EPERM') {
        recordTamper(`events file became unreadable (${code}): ${path}`);
      }
      return;
    }

    // Baseline identity check: any change in {dev, ino} means the file
    // path has been rebound to a different inode (unlink + recreate,
    // rename-over, symlink swap) — the original audit trail is unreachable.
    const baseline = opts.eventsBaseline;
    if (baseline !== undefined) {
      const statIno = (stat as unknown as { ino: bigint }).ino;
      const statDev = (stat as unknown as { dev: bigint }).dev;
      if (statIno !== baseline.ino || statDev !== baseline.dev) {
        recordTamper(
          `events file inode mismatch (expected dev=${baseline.dev} ino=${baseline.ino}, got dev=${statDev} ino=${statIno}): ${path}`,
        );
        return;
      }
    }

    const sizeBig = (stat as unknown as { size: bigint }).size;
    // Detect truncation: a regular file's size MUST be monotonically
    // non-decreasing across our reads (writers use O_APPEND).  A shrink
    // means somebody ftruncate()/open(O_TRUNC)'d the file mid-run.
    const sizeNum = Number(sizeBig);
    if (sizeNum < eventsPos) {
      recordTamper(`events file shrank (size=${sizeNum} < eventsPos=${eventsPos}): ${path}`);
      return;
    }
    // Max-size monotonicity: even when `size >= eventsPos`, a regression
    // below `maxSeenSize` means an earlier poll (or fs.watch fire) saw a
    // larger size that has since been truncated away.  Without this gate,
    // append-then-truncate-to-same-pos cycles would pass undetected because
    // the polling loop can lose the intermediate growth between ticks.
    if (sizeNum < maxSeenSize) {
      recordTamper(
        `events file shrank below max-seen (size=${sizeNum} < maxSeenSize=${maxSeenSize}): ${path}`,
      );
      return;
    }
    if (sizeNum > maxSeenSize) maxSeenSize = sizeNum;

    // mtime regression: utimes(2) is the only way mtime can move backwards,
    // and no legitimate writer in this system calls utimes on the events
    // file.  A monotonic check against the largest mtime we have ever
    // observed (initialized from the baseline at creation) catches the
    // utimes-restore tamper where an attacker bumps mtime forward to write
    // a malicious line, then pins mtime back to its previous value to make
    // the older "mtime advanced without new bytes" gate quiet.
    const mtimeBig = (stat as unknown as { mtimeNs: bigint }).mtimeNs;
    const ctimeBig = (stat as unknown as { ctimeNs: bigint }).ctimeNs;
    if (maxObservedMtime !== -1n && mtimeBig < maxObservedMtime) {
      recordTamper(
        `events file mtime regressed (mtimeNs=${mtimeBig} < maxObserved=${maxObservedMtime}, size=${sizeNum} eventsPos=${eventsPos}): ${path}`,
      );
      return;
    }
    if (mtimeBig > maxObservedMtime) maxObservedMtime = mtimeBig;

    // ctime monotonicity (utimes-bypass defence): every metadata or content
    // modification advances ctime, and utimes(2) CANNOT roll it back — only
    // mtime/atime are settable.  If ctime has advanced since the last drain
    // that consumed bytes, the file was modified; if `size === eventsPos`
    // at the same time, the bytes that drove the modification are no longer
    // visible (truncated away) — and the attacker may have additionally
    // utimes-restored mtime to silence the legacy mtime-advanced check.
    // Flag tamper.
    //
    // NOTE: ctime advances on EVERY legitimate write too (the shim appends
    // a JSONL line → ctime + mtime + size all move together).  We only flag
    // when ctime has advanced AND there are no new bytes to read; the
    // `lastConsumedCtime` is updated after a successful read so subsequent
    // legitimate writes do not re-trip this gate.
    //
    // 2026-05-19 follow-up: on Linux 5.10 (Ubuntu 22.04 microVM rootfs) we
    // see spurious one-shot ctime advances of a few ms with size unchanged
    // — the kernel updates ctime slightly after the size-bumping write
    // returns, and a stat() that lands in the gap reports the new ctime
    // against an unchanged size.  A real utimes-restore attack persists
    // across many polls (the attacker stops touching the file once the
    // attack completes), so requiring N consecutive observations of the
    // suspicious state collapses the false positive without weakening the
    // defence.  The mtime-regression check above remains the primary
    // signal; this gate stays defence-in-depth for the narrow case where
    // the attacker restores mtime to a value still ≥ maxObservedMtime.
    //
    // 2026-06-11: but at END OF AUDIT that "one-shot" settle becomes PERMANENT
    // (no further writes refresh lastConsumedCtime), so N consecutive polls
    // accumulate a FALSE positive.  Freeze this gate once `childExited` — past
    // that point no in-model process is alive to race the window (see the
    // childExited declaration); byte-adding tampers are still caught by the
    // size-grow drain below.
    //
    // 2026-06-12: the childExited freeze loses a RACE.  `strace -ff` exits only
    // after the WHOLE traced tree exits; on a large repo many children finish
    // WITHOUT writing events, so strace lingers >> META_ADVANCE_REQUIRED_POLLS ×
    // pollIntervalMs (≥150ms) AFTER the last events byte was consumed.  The
    // kernel finalizes that last write's ctime almost immediately, so the
    // suspicious state {ctime advanced, size === eventsPos} is PERMANENT and
    // accumulates the full strike count BEFORE exitPromise resolves and flips
    // `childExited` (deterministic 2/2 on the docker parity job, ubuntu-24.04
    // host kernel).  A value window was tried and rejected: a pure ctime-delta
    // tolerance is attacker-forgeable (a same-UID script can append→truncate→
    // utimes-restore within the window after observing a consume).
    //
    // Fix: do NOT fire the fatal synchronously here.  Record the suspicion
    // PROVISIONALLY in `pendingCtimeTamper` and resolve it against the strace
    // EXIT DISPOSITION — a signal the attacker cannot forge.  On a CLEAN whole-
    // tree exit (exit(), signal === null) the lingering finalize is benign and
    // the provisional verdict is VOIDED (see the exitPromise handler).  On an
    // ABNORMAL exit (killed/crashed tracer → possible detached survivor) or
    // with NO disposition at all (the macOS direct-spawn runner — fail-closed,
    // armed-forever) the provisional verdict is PROMOTED to a real tamper after
    // the settle loop.  No value window, so the steady-state gate stays strict:
    // every byte-adding tamper is still caught by the size-grow drain below and
    // the maxSeenSize / mtime-regression gates, which fire unconditionally.
    if (
      !childExited &&
      lastConsumedCtime !== -1n &&
      ctimeBig > lastConsumedCtime &&
      sizeNum === eventsPos
    ) {
      ctimeAdvanceStablePolls += 1;
      if (ctimeAdvanceStablePolls >= META_ADVANCE_REQUIRED_POLLS) {
        pendingCtimeTamper =
          `events file ctime advanced without new bytes (ctimeNs=${ctimeBig} > lastConsumed=${lastConsumedCtime}, size=${sizeNum} == eventsPos): ${path}`;
        return;
      }
    } else {
      ctimeAdvanceStablePolls = 0;
    }

    // Retained as defense-in-depth: a plain append-then-truncate (no utimes
    // restore) bumps mtime AND ctime forward.  The ctime check above will
    // also fire in that case, but the original mtime check stays in place
    // so the pre-existing test contract continues to hold.  Same lazy-stat
    // race as ctime above — gate on N consecutive polls so we tolerate the
    // kernel's brief mtime/size desync without weakening the steady-state
    // tamper signal.  Frozen post-exit for the same reason as the ctime gate
    // (see the childExited declaration): no in-model writer remains.
    if (!childExited && lastMtime !== -1n && mtimeBig > lastMtime && sizeNum === eventsPos) {
      mtimeAdvanceStablePolls += 1;
      if (mtimeAdvanceStablePolls >= META_ADVANCE_REQUIRED_POLLS) {
        recordTamper(
          `events file mtime advanced without new bytes (mtimeNs=${mtimeBig} > last=${lastMtime}, size=${sizeNum} == eventsPos): ${path}`,
        );
        return;
      }
    } else {
      mtimeAdvanceStablePolls = 0;
    }
    lastMtime = mtimeBig;
    // Initialize ctime baseline lazily when the caller did not supply one
    // (test-only path: production always passes opts.eventsBaseline).  Until
    // initialized, the ctime gate above is dormant — first observation just
    // seeds the watermark.
    if (lastConsumedCtime === -1n) lastConsumedCtime = ctimeBig;
    if (maxObservedMtime === -1n) maxObservedMtime = mtimeBig;

    if (sizeNum <= eventsPos) return;

    const toRead = sizeNum - eventsPos;
    const buf = Buffer.allocUnsafe(toRead);
    let fd = -1;
    let bytesRead = 0;
    try {
      fd = openSync(path, 'r');
      // Verify the just-opened fd is still the SAME inode the stat above
      // resolved — guards against a race where the file is unlinked between
      // the stat and the open and a new file with the same path now exists.
      if (baseline !== undefined) {
        const fdStat = fstatSync(fd, { bigint: true });
        if (fdStat.ino !== baseline.ino || fdStat.dev !== baseline.dev) {
          closeSync(fd);
          recordTamper(
            `events file fd-stat mismatch on open (expected dev=${baseline.dev} ino=${baseline.ino}, got dev=${fdStat.dev} ino=${fdStat.ino}): ${path}`,
          );
          return;
        }
      }
      bytesRead = readSync(fd, buf, 0, toRead, eventsPos);
    } catch (err) {
      if (fd >= 0) { try { closeSync(fd); } catch { /* ignore */ } }
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'EACCES' || code === 'EPERM') {
        recordTamper(`events file became unreadable on open (${code}): ${path}`);
      }
      return;
    }
    closeSync(fd);

    eventsPos += bytesRead;
    // ctime almost certainly advanced as a result of the same writes we
    // just consumed.  Record it as the new "last consumed" baseline so the
    // utimes-restore gate above doesn't fire on the next poll for these
    // legitimate bytes.
    lastConsumedCtime = ctimeBig;

    const chunk = eventsBuf + buf.slice(0, bytesRead).toString('utf8');
    const newlineIdx = chunk.lastIndexOf('\n');
    if (newlineIdx === -1) {
      eventsBuf = chunk;
      return;
    }

    const complete = chunk.slice(0, newlineIdx);
    eventsBuf = chunk.slice(newlineIdx + 1);

    for (const line of complete.split('\n')) {
      if (line.length > 0) {
        // pid=0 matches the fd3Stream convention: attribution will read the
        // pid field embedded in the JSONL payload, not this synthetic one.
        // Tagged `'shim'` because the events file is written by trusted
        // shim/preload code under SCRIPT_JAIL_LOG_FILE; the dispatcher
        // treats parse failures here as fatal tamper.
        queue.push({ pid: 0, line, source: 'shim' });
      }
    }
    wake();
  }

  // ---- fd 3 readline -------------------------------------------------------

  let fd3Done = false;

  if (opts.fd3Stream !== null) {
    const rl = createInterface({ input: opts.fd3Stream, crlfDelay: Infinity });
    rl.on('line', (line: string) => {
      if (line.length > 0) {
        // fd-3 is the preload-owned pipe — tagged `'shim'`.
        queue.push({ pid: 0, line, source: 'shim' });
        wake();
      }
    });
    rl.on('close', () => {
      fd3Done = true;
      wake();
    });
  } else {
    fd3Done = true;
  }

  // ---- fs.watch + polling loop ---------------------------------------------

  let watcher: ReturnType<typeof fsWatch> | null = null;
  try {
    watcher = fsWatch(opts.watchDir, (_event, _filename) => {
      // Shim-first, matching the poll timer and settle loop below (2026-06-03).
      // This callback fires when a per-pid strace file changes; the events-file
      // inotify watcher (eventsWatcher) is a SEPARATE watch that can fire later
      // or in a different tick.  If this path enqueued the strace `spawn` before
      // the shim's `exec` record for the same exec was drained, the dispatcher
      // would process the spawn with no seeded attribution and drop a
      // reaped-helper spawn — reintroducing the cross-backend parity
      // nondeterminism this change fixes.  Draining the events file first seeds
      // the pid's attribution (from the shim's in-process npm env, written
      // before real_execve) ahead of the matching strace spawn regardless of
      // which watcher fires first.
      drainEventsFile();
      pollDir();
      wake();
    });
    watcher.on('error', () => { /* ignore — polling is the fallback */ });
  } catch {
    // fs.watch not available on this fs — polling only
  }

  // Inotify-backed watch on the events file inode itself (Finding A).  On
  // Linux `fs.watch` translates to inotify, which fires on EVERY write
  // including truncate(2) and open(O_TRUNC).  Triggering an immediate drain
  // on each fire collapses the polling-window race during which an
  // append-then-truncate cycle could otherwise erase evidence between two
  // 50ms ticks — the post-drain `mtime` and `maxSeenSize` checks then
  // observe the now-discarded growth and flag tamper.
  let eventsWatcher: ReturnType<typeof fsWatch> | null = null;
  if (opts.eventsFilePath !== undefined && opts.eventsFilePath !== '') {
    try {
      eventsWatcher = fsWatch(opts.eventsFilePath, { persistent: false }, () => {
        drainEventsFile();
        wake();
      });
      // Inotify reports IN_DELETE_SELF / IN_MOVE_SELF as a watcher 'rename'
      // event followed by EPERM on subsequent reads on some kernels.  The
      // drainEventsFile() polling fallback (above) will catch those via
      // stat() returning ENOENT or the inode-mismatch check, so a watcher
      // error here is non-fatal — just drop the watch.
      eventsWatcher.on('error', () => { /* polling is the fallback */ });
    } catch {
      // fs.watch unavailable on this fs (e.g. tmpfs in some test setups) —
      // mtime + max-size monotonicity in drainEventsFile() remains active.
    }
  }

  // Inotify-backed watch on the events file's PARENT DIRECTORY (Finding B).
  // The directory mode is 0700 (mkdtemp + explicit chmod in createEventsFile),
  // so under normal operation no non-root caller can rename/create/unlink
  // anything inside.  This watcher is the defense-in-depth signal for the
  // corner case where the directory perms are weakened — or for a future
  // change to a shared parent — and catches the transient-rename trick:
  //
  //   mv events.jsonl events.bak                # rename away
  //   <create decoy at events.jsonl>            # IN_CREATE on basename
  //   <child opens events.jsonl via path>       # child fd → decoy
  //   mv events.bak events.jsonl                # rename back, baseline OK
  //
  // The inode-baseline check on the events file alone misses this because
  // by the next drain cycle the original inode is back at the path.  The
  // kernel's IN_MOVED_FROM / IN_MOVED_TO / IN_CREATE fire regardless of
  // when the polling loop ticks, so the directory watcher captures the
  // transient swap.  Any `rename`-flavoured event whose filename matches
  // the events-file basename (or is null on some kernels — be conservative
  // and treat the event as tamper rather than ignore) records tamper.
  let eventsDirWatcher: ReturnType<typeof fsWatch> | null = null;
  if (
    opts.eventsDirPath !== undefined &&
    opts.eventsDirPath !== '' &&
    opts.eventsFilePath !== undefined &&
    opts.eventsFilePath !== ''
  ) {
    const expectedBasename =
      opts.eventsFileBasename ?? opts.eventsFilePath.slice(opts.eventsFilePath.lastIndexOf('/') + 1);
    try {
      eventsDirWatcher = fsWatch(
        opts.eventsDirPath,
        { persistent: false },
        (event, filename) => {
          // Inotify maps `IN_MOVED_FROM`, `IN_MOVED_TO`, `IN_CREATE`,
          // `IN_DELETE` to Node's "rename" event.  Any rename on our
          // expected basename — or a null filename which Linux emits when
          // the kernel cannot supply the name — is treated as tamper.
          // `change` events on a sibling file (none should exist in the
          // 0700 mkdtemp dir, but be defensive) are ignored.
          if (event !== 'rename') return;
          if (filename !== null && filename !== expectedBasename) return;
          recordTamper(
            `events file parent directory rename detected (filename=${filename ?? '<null>'}): ${opts.eventsDirPath}`,
          );
          // Also trigger an immediate drain — if the swap was a brief
          // rename-aside/back, the file content visible to the tailer may
          // have shifted, and the post-drain inode/mtime checks will pick
          // up any additional mismatch.
          drainEventsFile();
          wake();
        },
      );
      eventsDirWatcher.on('error', () => { /* polling is the fallback */ });
    } catch {
      // fs.watch unavailable on this fs — directory-level guard is best-
      // effort; inode/mtime/size checks remain the primary line of defense.
    }
  }

  // Poll on a fixed interval as fallback / complement to fs.watch.
  //
  // Drain the shim events file BEFORE the per-pid strace dir (2026-06-03): the
  // shim's `emit_exec` write happens in-process BEFORE `real_execve`, which is
  // what strace logs the execve syscall from — so for any given exec the shim
  // record exists in the events file before strace's execve line exists in the
  // per-pid file.  Draining shim-first queues that record ahead of the strace
  // `spawn` line for the same exec within a poll cycle, so the dispatcher has
  // already seeded the pid's attribution (from the shim's in-process npm env)
  // by the time it processes the strace spawn.  On the real Linux backends the
  // events-file inotify watcher (see eventsWatcher above) already drains the
  // shim record the instant it is written; this ordering makes the polling
  // fallback behave the same so attribution stays deterministic across
  // backends.
  let pollTimer: ReturnType<typeof setInterval> | null = setInterval(() => {
    drainEventsFile();
    pollDir();
    wake();
  }, pollIntervalMs);

  // ---- wait for child exit, then drain -------------------------------------

  opts.exitPromise.then(async () => {
    // Decide whether to freeze the two "advanced WITHOUT new bytes" meta gates
    // (see the childExited declaration).  The freeze is a RELAXATION, so it
    // engages ONLY when strace exited NORMALLY (by exit(), signal === null) —
    // the whole traced tree exited and strace flushed normally, leaving no
    // in-model writer to race the polling window.  Set BEFORE the settle drains
    // below so the kernel's permanent end-of-audit ctime finalize cannot
    // accumulate a false positive while we tail out the remaining bytes.
    //
    // SECURITY (Codex 2026-06-12, finding 1): exitPromise resolves on ANY strace
    // close — including a tracee (same UID) SIGKILLing its own tracer to detach
    // and keep running.  Freezing the gates on that would let the survivor do an
    // append->truncate->utimes-restore (size===eventsPos, mtime pinned) entirely
    // unobserved.  So a strace terminated by a SIGNAL (or that failed to spawn)
    // is a fatal tamper — a killed/crashed tracer can leave a detached survivor,
    // so the capture can no longer be trusted — and the gates stay ARMED.
    //
    // A non-zero exit CODE is NOT abnormal: `strace -f` propagates the tracee's
    // exit status, so a non-zero code is just a legitimately-failing-but-audited
    // install (offline postinstall, etc.).  The tracee tree still exited, so no
    // survivor remains and the freeze is safe — and treating it as tamper would
    // refuse a lockfile for every failing install (see main()'s non-zero-Phase-B
    // leniency).  Absent disposition (unit tests) leaves the relaxation OFF:
    // fail-closed default.  (A child that escaped the tracer via CLONE_UNTRACED
    // is caught separately at clone-parse time — see phase-install.ts.)
    const exitStatus = opts.exitStatusRef;
    if (exitStatus !== undefined) {
      if (exitStatus.signal !== null || exitStatus.spawnError === true) {
        recordTamper(
          `strace terminated abnormally (signal=${exitStatus.signal ?? '<none>'}` +
            `${exitStatus.spawnError === true ? ', spawn error' : ''}) — a killed or ` +
            `crashed tracer can leave a detached tracee alive; audit capture cannot be trusted`,
        );
      } else {
        childExited = true;
        // Clean whole-tree exit: any ctime advance the gate flagged while we
        // waited out the tracer was the kernel's benign end-of-audit finalize,
        // not a live attacker (none can remain past a clean exit).  Void the
        // provisional verdict — this is what wins the pre-notification race the
        // `childExited` freeze alone loses.
        //
        // ACCEPTED RESIDUAL (Codex round-4 [high], 2026-06-12): voiding here
        // also clears a REAL active-phase ctime-only tamper (truncate-back /
        // utimes-restore / same-size in-place substitution) that a same-UID
        // script performs and then lets the install exit 0.  This is a
        // deliberate, irreducible tradeoff, not an oversight:
        //   * {ctime advanced, size === eventsPos} is the EXACT signature of
        //     the benign lazy finalize, so no stat/poll signal distinguishes it
        //     from a tamper.  An inotify-fire-driven immediate gate was tried
        //     to close this (the finalize was assumed inotify-silent); it
        //     FALSE-POSITIVED on the real CI kernels (docker 24.04 host AND
        //     firecracker 22.04 microVM — the finalize re-stats > the pre-
        //     finalize watermark for benign writes), confirmed by CI and an
        //     independent review.  There is no FP-free poll/inotify fix.
        //   * The PRIMARY defense is intact and unaffected: the inotify-driven
        //     drain + the size/maxSeenSize gates read the attacker's appended
        //     bytes (recording the malicious line) UNLESS the attacker wins a
        //     sub-millisecond cross-process race against the concurrently-
        //     running tailer.  The ctime gate is only the defense-in-depth
        //     backstop for that race-won case; this void narrows it to the
        //     additional conjunction of {race won} AND {clean exit} AND {no
        //     subsequent observed activity}.
        //   * Same CLASS as PR #10's accepted post-exit-freeze residual: a root
        //     attacker racing the tailer is outside the enforceable boundary.
        // Keeping PR #10's strict active-phase immediate-fire instead would
        // re-introduce the large-repo false positive this whole change exists
        // to fix (legit installs of ~1000-pkg monorepos rejected as tampered) —
        // a guaranteed, frequent failure traded for a tight, rare race.
        pendingCtimeTamper = null;
      }
    }
    // By the time exitPromise resolves, strace has already fclose()'d every
    // per-pid file: it exits only after the whole traced process tree has
    // exited, and the agent NEVER kills it (no SIGKILL/SIGTERM anywhere in
    // LinuxStraceRunner.run).  So every byte of the capture is already on
    // disk — the only remaining job is to make sure the tailer READS all of
    // it.  A single `readdirSync` can momentarily miss a just-created per-pid
    // file (the sub-millisecond cmd-shim helpers dirname/sed/uname are the
    // motivating case: each writes a tiny `<basePrefix>.<pid>` file that can
    // come and go between two 50ms polls and be visible only now).  The old
    // code did ONE final pollDir() after a blind drainMs wait, so any file
    // not yet listed — or read short — on that single sweep was dropped,
    // producing a nondeterministic capture that diverged from the macOS
    // backend.  Replace it with a bounded settle loop that re-enumerates and
    // re-reads until the capture stops growing.
    //
    // INVARIANT: this loop must NEVER kill strace.  A SIGKILL would truncate
    // per-pid files mid-flush — the exact data loss being fixed.  The hard
    // cap only stops TAILING; strace has already exited by construction, so
    // file sizes are final and the loop reaches a fixed point quickly.
    const hardDeadline = Date.now() + settleHardCapMs;
    let quiet = 0;
    let prev = '';
    // Monotonic snapshot of total capture progress: per-pid file count +
    // summed read offsets + buffered partial lengths + the events-file
    // offset/partial.  It only ever increases while data is discovered or
    // read, so equality across two passes means nothing new appeared.
    const progressKey = (): string => {
      let posSum = 0;
      for (const p of filePos.values()) posSum += p;
      let bufSum = 0;
      for (const b of fileBuf.values()) bufSum += b.length;
      return `${filePos.size}:${posSum}:${eventsPos}:${bufSum}:${eventsBuf.length}`;
    };
    // First tick keeps the old short drainMs grace (cheap initial settle for
    // filesystems with lazy dirent visibility); completeness no longer
    // depends on it — the loop below is what guarantees it.
    await delay(drainMs);
    for (;;) {
      // Shim-first (see the poll-timer comment above): seed attribution from
      // the shim's in-process npm env before the matching strace spawn line is
      // dispatched.  By now strace has exited and all files are final, so this
      // is purely about queue order, not capture completeness.
      drainEventsFile();
      pollDir(); // re-enumerates ALL matching files; drainFile reads each to current EOF
      const cur = progressKey();
      if (cur === prev) {
        if (++quiet >= settleQuietPasses) break;
      } else {
        quiet = 0;
      }
      prev = cur;
      if (Date.now() >= hardDeadline) break; // safety net — never hang
      await delay(pollIntervalMs);
    }
    // Resolve any provisional ctime verdict.  A clean whole-tree exit already
    // set `childExited` and voided it above; reaching here with it still set
    // means the exit was ABNORMAL (killed/crashed tracer — possible detached
    // survivor) or NO disposition was supplied (macOS direct-spawn runner, or a
    // unit test) — both fail-closed, so PROMOTE the suspicion to a real tamper.
    if (pendingCtimeTamper !== null && !childExited) {
      recordTamper(pendingCtimeTamper);
    }
    if (quiet < settleQuietPasses) {
      // Cap hit before quiescence.  FAIL CLOSED: this is a security audit
      // tool, and a capture the tailer could not confirm complete must never
      // pass as a clean lockfile (a dropped execve/open/connect line could be
      // the only evidence of escaped behavior).  Record it through the same
      // tamperRef the events-file watcher uses, so runInstallPhase / main
      // refuse to emit a final lockfile (see getTamperReason() consumers).
      //
      // This is NOT expected to fire in normal OR adversarial operation: by
      // the time this loop runs strace has exited, so every per-pid file is
      // closed and the shim writers are dead — the capture is final and
      // quiesces within ~2 passes, orders of magnitude under the cap.  Hitting
      // the cap means the filesystem never settled (or an unexpected writer is
      // still active), which is itself an anomaly worth failing closed on.
      recordTamper(
        `strace capture did not quiesce within ${settleHardCapMs}ms after the traced ` +
          `process tree exited; capture may be incomplete`,
      );
      // Also log to stderr for immediate visibility in the guest console.
      try {
        process.stderr.write(
          `[strace-tailer] settle cap (${settleHardCapMs}ms) hit before quiescence; capture may be incomplete\n`,
        );
      } catch {
        // stderr write is best-effort.
      }
    }
    // Flush any partial lines in per-pid buffers (strace may omit final \n).
    for (const [name, partial] of fileBuf) {
      if (partial.length > 0) {
        const pid = parsePidFromFilename(name);
        queue.push({ pid, line: partial, source: 'strace' });
        fileBuf.set(name, '');
      }
    }
    // Same for the events-file partial buffer (defensive — writers always
    // emit \n-terminated lines, but POSIX doesn't require atomic writes
    // across newlines so a partial chunk is technically possible).
    if (eventsBuf.length > 0) {
      // A trailing partial chunk on the shim channel is unusual but not
      // necessarily malicious (writer crashed mid-line, kernel buffer
      // boundary, etc.).  Still tag it `'shim'` so the install-phase
      // dispatcher routes it to the shim parser; a parse failure there
      // will record tamper, which is the right outcome — we cannot
      // distinguish a benign torn write from a deliberate prefix
      // injection at this layer.
      queue.push({ pid: 0, line: eventsBuf, source: 'shim' });
      eventsBuf = '';
    }
    // Stop the poll timer.
    if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
    // Stop fs.watch.
    if (watcher !== null) { try { watcher.close(); } catch { /* ignore */ } watcher = null; }
    if (eventsWatcher !== null) { try { eventsWatcher.close(); } catch { /* ignore */ } eventsWatcher = null; }
    if (eventsDirWatcher !== null) { try { eventsDirWatcher.close(); } catch { /* ignore */ } eventsDirWatcher = null; }
    done = true;
    wake();
  }).catch(() => {
    done = true;
    wake();
  });

  // ---- generator loop ------------------------------------------------------

  try {
    while (true) {
      // Drain the queue first.
      while (queue.length > 0) {
        yield queue.shift()!;
      }

      // If we've set done AND fd3 is done AND queue is empty → finished.
      if (done && fd3Done && queue.length === 0) break;

      // Wait for a wake signal.
      await new Promise<void>((resolve) => { wakeResolve = resolve; });
    }
  } finally {
    // Cleanup on early consumer break (try/finally).
    if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
    if (watcher !== null) { try { watcher.close(); } catch { /* ignore */ } watcher = null; }
    if (eventsWatcher !== null) { try { eventsWatcher.close(); } catch { /* ignore */ } eventsWatcher = null; }
    if (eventsDirWatcher !== null) { try { eventsDirWatcher.close(); } catch { /* ignore */ } eventsDirWatcher = null; }
    // Drain any remaining partial lines (best-effort).
    for (const [name, partial] of fileBuf) {
      if (partial.length > 0) {
        const pid = parsePidFromFilename(name);
        queue.push({ pid, line: partial, source: 'strace' });
        fileBuf.set(name, '');
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Production StraceRunner
// ---------------------------------------------------------------------------

/**
 * Production strace runner.
 *
 * Spawns strace with `-ff -o <basePath>` which writes per-pid syscall files
 * at `<basePath>.<pid>`. While strace is running, `StraceTailer` watches the
 * output directory and tails each per-pid file as it grows, yielding
 * `{ pid, line }` records. The child's fd 3 is wired as a pipe so that
 * LD_PRELOAD JSONL records (env_read, dlopen) land here too, yielded as
 * `{ pid: 0, line }`.
 */
/** Minimal subset of ChildProcess used by LinuxStraceRunner. */
export interface SpawnResult {
  stderr: NodeJS.ReadableStream | null;
  /** stdio[3] is the fd-3 pipe (LD_PRELOAD JSONL). */
  stdio: Array<NodeJS.ReadableStream | null | undefined>;
  /**
   * The strace process pid.  Used by the runner (bug #1 fix,
   * 2026-05-19) to query `/proc/<pid>/task/<pid>/children` and
   * deterministically resolve the install command's pid (strace's
   * direct child) without depending on per-pid strace file discovery
   * order.  `undefined` when spawn failed catastrophically (e.g.
   * ENOENT on the strace binary) — the runner falls back to the
   * tailer's "first per-pid file observed" heuristic in that case.
   */
  pid: number | undefined;
  on(
    event: 'close',
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): this;
  on(event: 'error', listener: (err: Error) => void): this;
}

/** Injectable spawn function for LinuxStraceRunner (default: node:child_process.spawn). */
export type SpawnImpl = (
  cmd: string,
  args: string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv; stdio: Array<string> },
) => SpawnResult;

/**
 * Codex follow-up (bug #1, high, 2026-05-19): deterministically resolve the
 * pid of strace's direct child by polling
 * `/proc/<stracePid>/task/<stracePid>/children` for ≤ `deadlineMs` (default
 * 50ms, ≤10 iterations).  Strace's direct child IS the install command —
 * `execve(install_cmd, ...)` happens under `PTRACE_TRACEME` immediately
 * after fork() — so as soon as the children file contains exactly one pid
 * we have the install root.
 *
 * Returns:
 *   - the child pid on success,
 *   - `null` when the deadline expires without a single pid appearing,
 *   - `null` when MORE THAN ONE pid appears (ambiguous, e.g. strace itself
 *     spawned a helper thread; the dispatcher's null path is the safe
 *     conservative behaviour),
 *   - `null` when `/proc` is unavailable (some test sandboxes, non-Linux
 *     reads).
 *
 * Blocking is intentional: this runs ONCE per install, at agent startup
 * before any user-visible work, in a sub-100ms window.  The event loop
 * isn't carrying meaningful traffic at this point — the strace child has
 * just been fork()'d and hasn't yet emitted any per-pid file output for
 * the tailer to drain.
 *
 * Exported only so unit tests can exercise the parser without spawning
 * a real strace.
 */
export function readStraceChildPid(
  stracePid: number,
  deadlineMs = 50,
): number | null {
  const start = Date.now();
  // Cap iterations defensively in case `Date.now()` is somehow non-
  // monotonic in the runtime (a virtualisation quirk we don't see today
  // but is cheap to guard against).
  for (let iter = 0; iter < 10; iter++) {
    if (Date.now() - start >= deadlineMs) break;
    let raw: string;
    try {
      raw = readFileSync(
        `/proc/${stracePid}/task/${stracePid}/children`,
        'utf8',
      ).trim();
    } catch {
      // strace hasn't yet fork'd its child, or /proc is unavailable.
      // Brief synchronous backoff via a tight busy-wait keyed on
      // Date.now(); the deadline check above bounds total time.
      const sleepStart = Date.now();
      while (Date.now() - sleepStart < 5) { /* spin */ }
      continue;
    }
    if (raw.length === 0) {
      // No child observed yet — wait briefly and re-poll.  Same backoff
      // strategy as the catch branch above.
      const sleepStart = Date.now();
      while (Date.now() - sleepStart < 5) { /* spin */ }
      continue;
    }
    const pids = raw
      .split(/\s+/)
      .filter((s) => s.length > 0)
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n) && n > 0);
    if (pids.length === 1) return pids[0] ?? null;
    // Ambiguous (multiple children) — fail closed.
    if (pids.length > 1) return null;
    const sleepStart = Date.now();
    while (Date.now() - sleepStart < 5) { /* spin */ }
  }
  return null;
}

/**
 * Default BYTE cap for the RETAINED Phase-B install-stdout tail.  `main()`
 * enlarges this to comfortably exceed the longest protected env value (measured
 * in UTF-8 bytes) so a value echoed on one line fits whole before any front
 * drop.  Chosen well above any plausible single diagnostic line / credential.
 */
export const PHASE_B_STDOUT_TAIL_BYTES = 16384;

/**
 * Max bytes buffered for a SINGLE unterminated line before the collector gives
 * up and sticky-poisons.  Decoupled from {@link PHASE_B_STDOUT_TAIL_BYTES} so a
 * long but COMPLETE diagnostic line (Codex round-9 [medium]: real Yarn
 * `install --immutable` emitted a ~19 KB lockfile-descriptor line before its
 * `YN0028` explanation) is buffered, redacted WHOLE, and retained — rather than
 * poisoning and dropping the actionable error that follows.  Only a line that
 * never terminates within this bound is pathological enough to poison.
 */
export const PHASE_B_STDOUT_PENDING_MAX_BYTES = 1_048_576; // 1 MiB

/**
 * Attach a drained, byte-bounded tail collector to a child's STDOUT stream and
 * return a getter for the current (redacted-at-drop) tail; a no-op (`() => ''`)
 * when the stream is absent (test stubs / runners that don't pipe fd1).
 *
 * WHY IN-MEMORY, NOT A FILE (Codex round-4 [high] x2): an on-disk capture file
 * is unbounded (a verbose/malicious lifecycle script can fill the scratch disk
 * → ENOSPC) and persists secrets at rest in a predictable, cross-run-shared,
 * symlink-followable path.  A drained in-memory ring sidesteps both: it is hard
 * byte-capped and nothing touches disk.  The 'data' listener keeps the pipe
 * flowing so a verbose (1000-package) install cannot fill the OS pipe buffer
 * and deadlock the child.
 *
 * CLOSE-WAIT NOTE (Codex round-4 [high] #1, accepted): fd1-as-pipe makes the
 * child `close` event wait for stdout EOF.  This is NOT a new stall vector —
 * fd2 (strace diagnostics) and fd3 (the LD_PRELOAD JSONL channel, which MUST be
 * a live pipe) have been pipes since before this work shipped (v0.2.3), so a
 * daemonized/tracing-escaped descendant holding any inherited stdio already
 * gated `close`.  A drained fd1 joins that pre-existing set; it degrades a
 * lingering-child case to the outer timeout (fail-closed), never a bypass.
 *
 * SECRET SAFETY — PER-LINE redaction (line-local shapes + stateful decode).
 * Credentials in install stdout live on a single line, and `redactSensitive`
 * masks only a COMPLETE match (a known value, or a shape like `Bearer <token>`,
 * which is LINE-LOCAL by contract — see redactSensitive).  Failure modes closed:
 *
 *   (A) live-end partial match (Codex round-5): redacting an UNTERMINATED line
 *       lets a shape match a half-arrived token's prefix; the suffix then
 *       arrives detached and can't be re-matched.  → We NEVER redact the
 *       unterminated trailing `pending`; a line is redacted only once it is
 *       COMPLETE (its '\n' arrived), so the whole token is present.
 *   (B) split-by-front-drop / resume re-anchor (Codex round-6/8): any
 *       "suppress the over-cap line then RESUME" scheme leaks — a detached
 *       suffix re-anchors as a fresh complete line after the resume point, on
 *       ANY delimiter or write-split.  → For the unterminated case we NEVER
 *       resume (see below).
 *   (C) chunk-split multibyte corruption (Codex round-9 [high] #2): decoding
 *       each pipe chunk independently with toString('utf8') turns a codepoint
 *       split across a chunk boundary into U+FFFD, so the layer-1 exact-value
 *       redactor no longer matches and an ASCII suffix leaks.  → A stateful
 *       `StringDecoder` buffers an incomplete trailing sequence across chunks.
 *   (D) newline-spanning shape (Codex round-9 [high] #1): a shape regex with
 *       `\s` would match `Bearer\n<token>` under a whole-buffer pass but be
 *       MISSED per-line.  → redactSensitive's shapes are LINE-LOCAL, so per-line
 *       redaction is COMPLETE: no shape spans a '\n'.
 *
 * The invariant: EVERY byte committed to `redactedTail` belongs to a COMPLETE
 * logical line that was redacted WHILE WHOLE (marker + secret co-resident → both
 * masked, and — shapes being line-local — completely so).  A complete line is
 * therefore safe to retain at ANY length: redaction masks every known secret in
 * it BEFORE the byte-cap front-drop, so the front-drop only ever cuts
 * already-masked / non-secret bytes.  A long-but-complete diagnostic line
 * (Codex round-9 [medium]: real Yarn `--immutable` emits a ~19 KB lockfile line
 * before its `YN0028` explanation) is buffered up to `pendingMaxBytes`, redacted
 * whole, and retained — the error that follows is NOT dropped.
 *
 * The ONLY poison case is the genuinely-unhandleable one: a single UNTERMINATED
 * line that never terminates within `pendingMaxBytes`.  We can neither redact it
 * (failure A) nor resume past it (failure B), so we sticky-poison: emit one
 * marker, surface nothing further.  Phase B is OFFLINE (no exfil channel needs
 * the error text live), so this costs only diagnosability, never audit
 * correctness.  Accepted residuals: (1) a single >pendingMaxBytes line with no
 * newline poisons (pathological/adversarial — real tools terminate lines);
 * (2) a protected VALUE or a credential split across a '\n' by adversarial
 * output is matched per-line only (the PM does not split credentials across
 * lines, and this tail is reached only on the zero-event fail-closed path, not
 * from an audited lifecycle script).  macOS-bare is unaffected (captures no
 * stdout; getStdoutTail() returns '').  O(n): each byte scanned once for '\n',
 * each line redacted once.
 */
export function attachStdoutTailCollector(
  stream: Readable | null | undefined,
  redact: ((s: string) => string) | undefined,
  capBytes: number = PHASE_B_STDOUT_TAIL_BYTES,
  pendingMaxBytes: number = PHASE_B_STDOUT_PENDING_MAX_BYTES,
): () => string {
  if (!stream) return () => '';
  // pendingMaxBytes must be ≥ capBytes (a complete line up to it is redacted then
  // front-dropped into the capBytes tail).
  const pendingMax = Math.max(pendingMaxBytes, capBytes);
  const truncMarker = `\n<script-jail: stdout capture stopped — unterminated line over ${pendingMax}B (possible split secret); tail suppressed>\n`;
  const decoder = new StringDecoder('utf8'); // stateful: buffers incomplete multibyte across chunks (C)
  let redactedTail = ''; // committed: each constituent line was redacted WHOLE
  let pending = ''; // decoded bytes after the last newline (the unterminated trailing line)
  let pendingBytes = 0; // running UTF-8 byte length of `pending`, kept O(1) per data event
  let poisoned = false; // sticky: set only when an unterminated line exceeds pendingMax

  // Return the longest suffix of `s` whose UTF-8 byte length is ≤ capBytes,
  // cut on a CHARACTER boundary.  Slicing the raw byte buffer mid-codepoint
  // would decode the partial bytes to U+FFFD (3 bytes each), which can re-encode
  // LARGER than capBytes — so advance the start past any continuation bytes
  // (0x80–0xBF) to the next lead byte.  The dropped front is stale/redacted
  // output (earlier whole-redacted lines), so dropping a few extra bytes is fine.
  const capTail = (s: string): string => {
    const buf = Buffer.from(s, 'utf8');
    if (buf.length <= capBytes) return s;
    let start = buf.length - capBytes;
    while (start < buf.length && (buf[start]! & 0xc0) === 0x80) start++;
    return buf.subarray(start).toString('utf8');
  };

  // Append already-redacted text and byte-cap the retained tail by dropping its
  // (already-safe) FRONT.
  const appendRedacted = (s: string): void => {
    redactedTail = capTail(redactedTail + s);
  };

  // Sticky-poisoned terminal state: emit the marker once, surface nothing more.
  const poison = (): void => {
    appendRedacted(truncMarker);
    poisoned = true;
    pending = '';
    pendingBytes = 0;
  };

  // Drain all COMPLETE lines from `pending`, redacting each WHOLE.  Resets
  // `pendingBytes` to the residual tail's byte length — that tail is whatever
  // followed the LAST newline, so it is bounded by the chunk that carried the
  // newline (post-drain `pending` never holds a '\n'), keeping this cheap.
  const drainCompleteLines = (): void => {
    let nl: number;
    while ((nl = pending.indexOf('\n')) !== -1) {
      const line = pending.slice(0, nl + 1); // includes its '\n'
      pending = pending.slice(nl + 1);
      appendRedacted(redact ? redact(line) : line);
    }
    pendingBytes = Buffer.byteLength(pending, 'utf8');
  };

  stream.on('data', (chunk: Buffer | string) => {
    if (poisoned) return; // sticky
    // Stateful decode: an incomplete multibyte sequence at the chunk boundary is
    // held by the decoder and completed by the next chunk (failure mode C).
    const decoded = decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8'));
    if (decoded.length === 0) return; // only a partial codepoint arrived; nothing to do
    pending += decoded;
    // A newline can ONLY appear in the freshly-decoded bytes — post-drain
    // `pending` never retains one — so scan/drain only when this chunk actually
    // carries a '\n'.  Otherwise just advance the byte counter.  This keeps the
    // no-newline path O(1) per event instead of O(pending): a byte-at-a-time
    // unterminated stream up to pendingMax stays linear, never quadratic.
    if (decoded.indexOf('\n') !== -1) {
      drainCompleteLines(); // recomputes pendingBytes for the residual tail
    } else {
      pendingBytes += Buffer.byteLength(decoded, 'utf8');
    }
    // The trailing UNTERMINATED line is never redacted at the live end (A).  We
    // buffer it up to pendingMax so a long-but-complete diagnostic line is kept;
    // only a line that never terminates within that bound poisons (B).
    if (pendingBytes > pendingMax) {
      poison();
    }
  });
  // Flush any byte held by the decoder at EOF, then drain a final complete line.
  stream.on('end', () => {
    if (poisoned) return;
    pending += decoder.end();
    drainCompleteLines();
  });
  // Swallow late errors on the captured stream (e.g. EPIPE on teardown) so an
  // stdout-side hiccup never crashes the agent; the tail we have is best-effort.
  stream.on('error', () => { /* best-effort capture */ });

  return () => {
    // Finalize: when poisoned, surface only what was committed before the
    // overflow (the marker is already in redactedTail).  Otherwise the trailing
    // partial line (≤pendingMax) is redacted ONCE at true EOF — no later suffix
    // can arrive, so masking what's present cannot orphan anything.  Non-mutating
    // so repeated calls are stable.
    const finalPending = poisoned
      ? ''
      : pending
        ? (redact ? redact(pending) : pending)
        : '';
    return capTail(redactedTail + finalPending);
  };
}

export class LinuxStraceRunner implements StraceRunner {
  private _exitCode = 0;
  private readonly _spawnImpl: SpawnImpl;
  private readonly _eventsFile: EventsFile | null;
  private readonly _tamperRef: { reason: string | null } = { reason: null };
  // Codex follow-up (bug #1, high, 2026-05-19): pid of the install
  // command (strace's direct child) — captured the first time a
  // per-pid strace output file is observed in `runStraceTailer`.
  // Exposed via `getRootPid()` so the install-phase dispatcher can
  // seed `pidCwd` for EXACTLY this pid instead of relying on a "first
  // event yielded" heuristic that could mis-seed a child whose
  // per-pid file happens to be drained before the parent's.  Null
  // until the first per-pid file is observed (and remains null if
  // strace failed to spawn).
  private _rootPid: number | null = null;
  // Live getter over the drained, byte-bounded in-memory tail of the install
  // command's STDOUT (yarn Berry writes its setup/diagnostic errors here).  fd1
  // is wired as a pipe and a 'data' listener keeps it flowing so a verbose
  // install cannot fill the pipe and deadlock; only the last cap BYTES are
  // retained, redacted before each front-drop.  Wired in run(); read via
  // getStdoutTail() and surfaced REDACTED on the Phase-B fail-closed path.
  // Defaults to the empty-tail getter so it is safe to call before/without a
  // spawn.  Nothing touches disk (Codex round-4 [high]).
  private _stdoutTailGetter: () => string = () => '';
  // Redactor applied to the stdout tail before each front-drop and again at
  // emit time.  Injected from main() (where config.protected.env is known).
  // Undefined for test fakes / callers that don't capture stdout.
  private readonly _redactStdout: ((s: string) => string) | undefined;
  // Byte cap for the in-memory tail.  Sized by main() to exceed the longest
  // protected env value (in UTF-8 bytes) so the redactor sees whole values.
  private readonly _stdoutTailBytes: number;

  /**
   * @param spawnImpl  Injection seam for tests.  Production passes through
   *                   to `node:child_process.spawn`.
   * @param eventsFile Per-VM events-file handle (path + baseline inode/dev)
   *                   created by the agent before strace launches.  When
   *                   `null`, the runner does not point any writer at a
   *                   shared events file — used by tests that supply a
   *                   pre-set environment via the `opts.env` passed to
   *                   `run()`.
   * @param redactStdout Redactor for the stdout tail (masks complete protected
   *                   values + credential shapes).  Undefined for test fakes.
   * @param stdoutTailBytes Byte cap for the in-memory stdout tail.
   */
  constructor(
    spawnImpl?: SpawnImpl,
    eventsFile?: EventsFile | null,
    redactStdout?: (s: string) => string,
    stdoutTailBytes: number = PHASE_B_STDOUT_TAIL_BYTES,
  ) {
    this._spawnImpl = spawnImpl ?? (spawn as unknown as SpawnImpl);
    this._eventsFile = eventsFile ?? null;
    this._redactStdout = redactStdout;
    this._stdoutTailBytes = stdoutTailBytes;
  }

  getExitCode(): number {
    return this._exitCode;
  }

  /**
   * Returns the human-readable tamper reason recorded by the tailer's
   * events-file watcher, or null if no tampering was observed.  Only
   * meaningful after `run()` has been fully consumed.  Surface this in
   * `main()` to force-fail check mode when an audited process unlinked or
   * replaced the events file mid-install (Finding A).
   */
  getTamperReason(): string | null {
    return this._tamperRef.reason;
  }

  /**
   * Plumb a tamper reason from {@link runInstallPhase} (specifically: shim-
   * channel JSONL parse failures) into the same `_tamperRef` slot that the
   * events-file watcher uses.  First-writer-wins — once `_tamperRef.reason`
   * is non-null, subsequent calls are dropped so the earliest signal (which
   * is most likely the root cause) is preserved.
   */
  recordTamper(reason: string): void {
    if (this._tamperRef.reason === null) {
      this._tamperRef.reason = reason;
    }
  }

  getRootPid(): number | null {
    return this._rootPid;
  }

  getStdoutTail(): string {
    return this._stdoutTailGetter();
  }

  async *run(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string; basePath: string },
  ): AsyncIterable<{ pid: number; line: string; source: LineSource }> {
    // Audit-trust Finding 2 (high, 2026-05-18): strace's `-e trace=execve`
    // does NOT cover `execveat`.  A lifecycle script that issues
    // `syscall(SYS_execveat, AT_FDCWD, path, argv, envp, 0)` directly
    // bypasses the libc execve wrapper (so the shim sees no exec event)
    // AND, prior to this fix, also bypassed strace's observation entirely.
    // Adding `execveat` to the trace set means the strace-vs-shim
    // cross-check in phase-install can still flag the bypass as
    // `<SYSCALL_EXEC_BYPASS>`.  The strace parser (strace-parser.ts) is
    // updated in lockstep so an `execveat(...)` line produces the same
    // `spawn` RawEvent shape as `execve(...)`.
    // Audit-trust Finding 4 (high, 2026-05-18): strace's default string
    // size is 32 bytes, which truncates long paths in `openat(...)` output
    // (e.g. `/tmp/script-jail-events-abc123def4"...`) and silently
    // defeats the exact-string events-file forgery check.  `-s 4096`
    // raises the limit far above any realistic Linux PATH_MAX-ish input
    // while keeping per-line output manageable.  Truncation can still
    // happen for extreme payloads (argv with megabytes of args), but
    // 4096 covers every realistic events-file path AND every
    // realistic exec argv — and forgery detection only depends on the
    // openat path being intact.
    // Audit-trust Finding (high, 2026-05-19): include `chdir` and `fchdir`
    // in the trace set so phase-install can maintain a per-pid CWD table.
    // Without per-pid CWD tracking, a non-shim-loaded attacker pid could
    // `chdir("/tmp/script-jail-events-XXX")` and then issue
    // `openat(AT_FDCWD, "events.jsonl", O_APPEND|O_WRONLY)`; the
    // canonicalizer would resolve the relative target against the AGENT's
    // cwd (not the attacker's) and miss the equality check against the
    // canonical events file path — silently dropping the
    // `<EVENTS_FILE_FORGERY>` signal.  With `chdir`/`fchdir` traced, the
    // dispatcher in `runInstallPhase` updates a `pidCwd` map and resolves
    // AT_FDCWD-relative openat targets against the attacker's actual cwd.
    // Audit-trust Finding (high, 2026-05-19): include `openat2` in the
    // trace set.  Linux 5.6+ added openat2 as a more capable variant of
    // openat (it takes a `struct open_how` instead of bare flags + mode
    // and supports the RESOLVE_* sandboxing flags).  A raw-syscall
    // child can `syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how))`
    // to open the events file for write; without tracing openat2 the
    // events-file forgery detector sees no openat line and the
    // forgery slips past.  The strace parser learned `parseOpenat2` in
    // lockstep so the wire-format struct argument is decoded for the
    // flags field (write-bit detection) and the same RawEvent shape as
    // openat is emitted.
    // Audit-trust Finding (high, 2026-05-19): include legacy `open` and
    // `creat` in the trace set.  glibc routes every userspace `open(...)`
    // and `creat(...)` call through `openat(AT_FDCWD, ...)` on Linux, so
    // most lifecycle scripts never invoke the legacy syscalls directly.
    // BUT a native attacker can still issue raw `syscall(SYS_open,
    // "/tmp/script-jail-events-XXX/events.jsonl", O_WRONLY|O_APPEND)`
    // or `syscall(SYS_creat, path, mode)` to bypass the libc wrappers.
    // Without tracing these syscalls strace sees nothing, the parser
    // never emits a write RawEvent, and the events-file forgery
    // detector is silently defeated.  The strace parser gained
    // `parseOpen` and `parseCreat` in lockstep so each line produces
    // the same `read`/`write` RawEvent shape as openat (creat is
    // always a write — equivalent to `open(path, O_WRONLY|O_CREAT|
    // O_TRUNC, mode)`); the dirfdTable in phase-install consumes
    // `retFd` exactly like openat so a follow-up
    // `openat(<creat-fd>, ...)` resolves correctly.
    //
    // Audit-trust Finding (high, 2026-05-19, codex follow-up): include
    // `clone`, `clone3`, `vfork`, and `fork` so phase-install can
    // propagate per-pid cwd and dirfd-table state to forked children at
    // the moment the kernel creates them.  Without these, a child pid
    // that inherits a parent's `chdir("/root")` produces an
    // AT_FDCWD-relative openat that the dispatcher resolves with NO
    // tracked cwd — pre-fix that fell back to `input.cwd`, silently
    // dropping a `.ssh/id_rsa` probe.  Strace renders the syscalls as
    //   `clone(child_stack=..., flags=...) = <child_pid>`,
    //   `clone3({flags=..., ...}, <size>) = <child_pid>`,
    //   `vfork() = <child_pid>`, `fork() = <child_pid>`.
    // On the host's modern glibc, every fork goes through `clone` or
    // `clone3`, but tracing all four costs nothing and immunises us
    // against alpine/musl rootfs variants that still expose `fork(2)`.
    //
    // Audit-trust Finding (high, 2026-05-19, codex follow-up): include
    // `dup`, `dup2`, `dup3`, `close`, and `close_range` so the dirfdTable
    // can be invalidated when a pid mutates its fd table.  A process
    // can `openat(AT_FDCWD, "/pkg", O_DIRECTORY) = 7`, then
    // `openat(AT_FDCWD, "/root", O_DIRECTORY) = 8`, then untraced
    // `dup2(8, 7)`, then `openat(7, ".ssh/id_rsa", O_RDONLY)`.  Without
    // tracing the fd mutations the dirfdTable still maps `7 -> /pkg`,
    // so the openat resolves to `/pkg/.ssh/id_rsa` and bypasses the
    // protected-paths matcher.  After tracing them, phase-install
    // propagates / invalidates the dirfdTable entry at the dup/close,
    // and the openat either resolves correctly or fails closed via
    // the `<UNRESOLVED_PATH>` audit_bypass entry.
    //
    // Audit-trust Finding (high, 2026-05-19, codex follow-up):
    // include `fcntl` (and the 32-bit-arch variant `fcntl64`).  Pre-fix
    // we deliberately omitted these because the cmd subcommand variety
    // is large; phase-install now models the subcommands we care about
    // (F_DUPFD / F_DUPFD_CLOEXEC / F_SETFD / F_GETFD) and falls back to
    // `dirfdStateUnknown` for anything it doesn't recognise.  This
    // closes the post-exec-CLOEXEC bypass: a script that opens a dirfd
    // with O_CLOEXEC and then execs sees the kernel close the fd, but
    // our dirfdTable would have kept the stale entry indefinitely
    // without tracking the CLOEXEC bit + sweeping on exec.  Also catches
    // F_SETFD FD_CLOEXEC mutations on previously-non-CLOEXEC fds.
    const commandArgs = process.env['SCRIPT_JAIL_PHASE_B_UNSHARE_NET'] === '1'
      ? ['unshare', '-n', '--', cmd, ...args]
      : [cmd, ...args];
    const straceArgs = [
      '-ff',
      '-s', '4096',
      '-e', 'trace=open,openat,openat2,creat,execve,execveat,connect,readlinkat,statx,renameat2,unlinkat,faccessat2,chdir,fchdir,clone,clone3,vfork,fork,dup,dup2,dup3,close,close_range,fcntl,fcntl64,unshare',
      '-o', opts.basePath,
      ...commandArgs,
    ];

    const child = this._spawnImpl('strace', straceArgs, {
      cwd: opts.cwd,
      env: opts.env,
      // fd 0: stdin  → /dev/null
      // fd 1: stdout → pipe  (the install command inherits strace's fd1; yarn
      //                Berry writes its errors here — drained into a byte-
      //                bounded in-memory tail for the Phase-B fail-closed
      //                diagnostic)
      // fd 2: stderr → pipe  (strace diagnostics forwarded to process.stderr)
      // fd 3: pipe   → LD_PRELOAD JSONL (env_read / dlopen events)
      stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    });

    // Drain the install command's stdout into a byte-bounded in-memory ring.
    // MUST be attached before `yield*` below so the stream flows from the first
    // byte — an unread 'pipe' fd1 would fill the OS pipe buffer and deadlock a
    // verbose (1000-package) install.  strace writes its traces to `-o` files,
    // not stdout, so fd1 carries the traced install command's stdout only.
    // Nothing touches disk (Codex round-4 [high]: no unbounded/persistent file).
    this._stdoutTailGetter = attachStdoutTailCollector(
      child.stdio[1] as Readable | null,
      this._redactStdout,
      this._stdoutTailBytes,
    );

    // Codex follow-up (bug #1, high, 2026-05-19): deterministically capture
    // the install command's pid by reading `/proc/<strace_pid>/task/<strace_
    // pid>/children` immediately after spawn.  strace's direct child IS the
    // install command (strace exec'd it under PTRACE_TRACEME), so as soon as
    // exactly one pid appears in the children file we have the install root.
    //
    // Why this beats the prior "first per-pid file observed" heuristic:
    // strace writes one file per traced pid via `-ff -o <basePath>`.  The
    // tailer polls the directory with readdirSync() + fs.watch(); readdir
    // order is filesystem-dependent and fs.watch events are coalesced by
    // the kernel.  Under load — or simply on tmpfs where dirents come back
    // in inode order — a forked child's per-pid file can be discovered
    // BEFORE the strace-root's.  Pre-fix we'd seed pidCwd[<child>] =
    // input.cwd, certifying a wrong cwd for the child (whose actual cwd
    // was inherited from a chdir'd parent) and slipping AT_FDCWD-relative
    // probes past protected-paths.
    //
    // The /proc query is bounded (≤50ms / ≤10 iterations).  On the
    // production guest, strace forks its child within a single scheduler
    // quantum, so the loop usually completes on the first iteration.
    //
    // Codex follow-up (bug #3, high, 2026-05-19): TRI-STATE resolution.
    // Pre-fix, the file-observation fallback (recordRootPid below) ran
    // unconditionally — when readStraceChildPid returned null (timeout,
    // /proc unavailable, ambiguous multi-child), `_rootPid` was left null
    // here and the recordRootPid callback later happily seeded it from
    // the first per-pid strace file the tailer drained.  That is EXACTLY
    // the nondeterministic race we tried to eliminate (a forked child's
    // file can be drained before the install command's).
    //
    // Strict fix: decide ONCE at spawn time which resolution mode to use,
    // and disable the fallback when the /proc path was attempted but
    // didn't yield a definite pid.
    //
    //   A. `child.pid` exists AND readStraceChildPid returned a pid:
    //      use it; DISABLE the per-pid-file fallback (rootPid is pinned).
    //   B. `child.pid` exists but readStraceChildPid returned null
    //      (deadline expired, ambiguous multi-child, /proc unavailable):
    //      leave `_rootPid` null AND DISABLE the per-pid-file fallback.
    //      The dispatcher gets null from getRootPid(); no pid is seeded;
    //      every pid fails closed on AT_FDCWD-relative opens until it
    //      performs an observable chdir.  Conservative but correct.
    //   C. `child.pid` is undefined (spawn impl returned a stub — test
    //      fakes or a catastrophic failure where we can't query /proc
    //      at all): KEEP the per-pid-file fallback for test convenience.
    //      Production strace always produces a child.pid.
    //
    // The `_rootPidDeterministicResolution` flag captures the A/B vs C
    // distinction so the callback wire-up below can branch on it.  Once
    // true, no per-pid-file observation can clobber the decision — even
    // if a malicious or unusual event order produces a sibling's file
    // first.
    let rootPidDeterministicResolution = false;
    if (child.pid !== undefined) {
      // Production path: /proc must be consulted before we install the
      // tailer callback so the decision is fixed before any per-pid
      // file is drained.
      rootPidDeterministicResolution = true;
      const pid = readStraceChildPid(child.pid);
      if (pid !== null) {
        this._rootPid = pid;
      }
      // If pid === null we leave _rootPid as null and the dispatcher
      // fails closed.  The recordRootPid callback below is suppressed.
    }
    // Else: child.pid is undefined → spawn-stub / test path; allow the
    // per-pid-file fallback to seed _rootPid below.

    // Capture strace's exit disposition (code + signal) so the tailer can tell
    // a CLEAN whole-tree exit from an ABNORMAL termination (e.g. a tracee
    // SIGKILLing its tracer to detach and survive).  Mutated BEFORE resolve()
    // so the tailer's exitPromise.then() observes it.  See
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
        // Spawn/runtime error: strace never ran → classify as a spawn error so
        // the tailer fails closed instead of freezing its meta gates.
        exitStatus.spawnError = true;
        this._exitCode = 1;
        resolve();
      });
    });

    const watchDir = dirname(opts.basePath);
    const basePrefix = basename(opts.basePath);

    // child.stdio[3] is the read end of the fd-3 pipe.
    const fd3Stream = child.stdio[3] as Readable | null;

    // Forward strace's stderr line-by-line to process.stderr with a [strace]
    // prefix so any strace diagnostics (e.g. "strace: exec failed", ptrace
    // permission errors) land on the guest's ttyS0 console.
    let stderrRl: ReturnType<typeof createInterface> | null = null;
    if (child.stderr) {
      stderrRl = createInterface({ input: child.stderr, crlfDelay: Infinity });
      stderrRl.on('line', (line: string) => {
        process.stderr.write(`[strace] ${line}\n`);
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
          eventsDirPath: this._eventsFile.dirPath,
          eventsFileBasename: basename(this._eventsFile.path),
          tamperRef: this._tamperRef,
        } : {}),
        exitPromise,
        // Only this Linux `strace -ff` runner may pass exitStatusRef: strace
        // exits ONLY after the WHOLE traced tree has exited, so a normal exit
        // proves no in-model writer survives and the post-exit meta-gate freeze
        // is sound.  The macOS direct-spawn runner has no such proof and MUST
        // omit it — see StraceTailerOptions.exitStatusRef.
        exitStatusRef: exitStatus,
        // Codex follow-up (bug #3, high, 2026-05-19): the per-pid-file
        // fallback runs ONLY when the /proc-based deterministic
        // resolution was not attempted (i.e. child.pid was undefined,
        // typically a test spawn stub).  When the /proc path was
        // attempted but returned null (timeout, ambiguous,
        // unavailable), `rootPidDeterministicResolution` is true and
        // we deliberately DO NOT install this callback — the
        // dispatcher gets `null` from `getRootPid()` and fails closed.
        // First-writer-wins between the (single) /proc resolution and
        // the file-observation fallback is therefore replaced with a
        // mutually-exclusive decision made at spawn time.
        ...(rootPidDeterministicResolution
          ? {}
          : {
              recordRootPid: (pid: number): void => {
                if (this._rootPid === null) this._rootPid = pid;
              },
            }),
      });
    } finally {
      if (stderrRl !== null) {
        stderrRl.close();
        stderrRl = null;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

function detectManager(cwd: string): 'npm' | 'pnpm' | 'yarn' {
  if (existsSync(`${cwd}/pnpm-lock.yaml`)) return 'pnpm';
  if (existsSync(`${cwd}/yarn.lock`)) return 'yarn';
  return 'npm';
}

// ---------------------------------------------------------------------------
// Wait for host "go" signal
// ---------------------------------------------------------------------------

/**
 * Wait for the host to send the exact string "go\n" on the control stream.
 * Rejects on EOF, stream error, or if any line other than "go" is received.
 * This prevents an accidental or malformed control line from advancing the
 * agent to Phase B prematurely.
 *
 * TODO(v2): add a configurable timeout so the agent doesn't hang indefinitely
 * if the host disconnects without sending the signal.
 */
async function waitForGo(readable: Readable): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const rl = createInterface({ input: readable, crlfDelay: Infinity });

    const cleanup = (): void => {
      rl.removeListener('line', onLine);
      rl.removeListener('close', onClose);
      rl.close();
    };

    const onLine = (line: string): void => {
      const trimmed = line.trim();
      if (trimmed === 'go') {
        cleanup();
        resolve();
      } else {
        cleanup();
        reject(new Error(`script-jail agent: unexpected control signal from host: ${JSON.stringify(trimmed)}`));
      }
    };

    const onClose = (): void => {
      cleanup();
      reject(new Error('script-jail agent: host closed connection before sending "go" signal'));
    };

    rl.on('line', onLine);
    rl.on('close', onClose);
    readable.on('error', (err: Error) => {
      cleanup();
      reject(err);
    });
  });
}

// ---------------------------------------------------------------------------
// Build env dict for child processes
// ---------------------------------------------------------------------------

const LIFECYCLE_ALLOWED_SCRIPT_JAIL_ENV_NAMES = new Set([
  'SCRIPT_JAIL_LOG_FILE',
  'SCRIPT_JAIL_LOG_FD',
  'SCRIPT_JAIL_NODE_OPTIONS',
  'SCRIPT_JAIL_PRELOAD_PATH',
  'SCRIPT_JAIL_PROTECTED_ENV_NAMES',
  'SCRIPT_JAIL_SPOOF_ARCH',
  'SCRIPT_JAIL_SPOOF_PLATFORM',
  // macOS-bare only.  When set to '1', env-spy.cjs writes the
  // node_startup_done JSONL marker DIRECTLY (the Mach-O shim may not load into
  // a hardened node, so it cannot be relied on to fire the marker via setenv
  // interception).  Allowed so descendants that re-require env-spy via the
  // inherited NODE_OPTIONS see it.  No effect on Linux (the var is never set).
  'SCRIPT_JAIL_EMIT_NODE_STARTUP_JSONL',
  // macOS-bare only.  Directory of the materialized, re-signed /bin/sh,
  // /bin/bash, and coreutils copies the shim's sip_redirect rewrites system
  // binaries to (SIP strips DYLD_* for /bin and /usr/bin).  The shim captures
  // it at ctor; allowed so descendants see the same sticky value.
  'SCRIPT_JAIL_SHELL_SHIM_DIR',
  // macOS-bare only.  The install/repo root (config.work_dir).  The shim
  // captures it at ctor into CANON_WORK_DIR and uses it as is_external_system_tool
  // keep-root #6 so the WHOLE install tree — incl. top-level node_modules/.bin
  // helpers that are SIBLINGS of a lifecycle child's chdir'd cwd — stays audited
  // (the top-level-.bin false-strip).  Allowed so descendants see the same sticky
  // value; the shim re-injects it on every kept exec regardless.
  'SCRIPT_JAIL_WORK_DIR',
  // NOTE: SCRIPT_JAIL_MACOS_AUDIT_OPS is deliberately NOT allow-listed here.
  // It is an internal per-phase control set solely by main() (deleted from the
  // Phase-A fetch env, set to '1' on the Phase-B install env).  Allow-listing it
  // would let an AMBIENT value survive sanitization into audited children —
  // harmless-but-leaky on macOS and a real regression on Linux (the ELF .so has
  // no audit-ops gate, yet the var would still ride into the Linux lifecycle env
  // and break the "strip unknown SCRIPT_JAIL_* vars" invariant).  Keeping it off
  // the list means an ambient value is always stripped; main() is the sole
  // authority.  See the Phase A/B split in main().
]);

const LIFECYCLE_HOST_NOISE_ENV_NAMES = new Set([
  'COLS',
  'HOSTNAME',
  'LINES',
  'POSIXLY_CORRECT',
  'TERM',
]);

function sanitizeLifecycleBaseEnv(baseEnv: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};

  for (const [name, value] of Object.entries(baseEnv)) {
    if (value === undefined) continue;
    if (LIFECYCLE_HOST_NOISE_ENV_NAMES.has(name)) continue;
    if (name.startsWith('SCRIPT_JAIL_') && !LIFECYCLE_ALLOWED_SCRIPT_JAIL_ENV_NAMES.has(name)) {
      continue;
    }
    sanitized[name] = value;
  }

  return sanitized;
}

/**
 * @internal Exported for unit tests only — production calls this from
 * `main()`.  The over-long-protect-list rejection (audit-trust Finding 2)
 * is the load-bearing invariant tested via this surface.
 */
export function buildChildEnv(
  baseEnv: NodeJS.ProcessEnv,
  config: AgentConfig,
  eventsFilePath: string,
  preloadPaths?: AgentInput['preloadPaths'],
): NodeJS.ProcessEnv {
  const preloads = [
    preloadPaths?.platformSpoof ?? '/usr/local/lib/script-jail/platform-spoof.cjs',
    preloadPaths?.envSpy ?? '/usr/local/lib/script-jail/env-spy.cjs',
  ];
  const nativePreload = preloadPaths?.native ?? '/lib/libscriptjail.so';

  // Native addons and child_process internals are intentionally allowed. The
  // microVM plus strace/LD_PRELOAD layer records their file, env, network, and
  // exec activity without breaking real dependency install scripts.
  const requireFlags = preloads.map((p) => `--require=${p}`);
  const childNodeOptions = requireFlags.join(' ');

  // Finding 4 (audit-trust): the protected-env list used to be written to
  // `/tmp/script-jail-protected.txt` and the path leaked through the child
  // env via `SCRIPT_JAIL_PROTECTED_ENV_FILE`.  A lifecycle script running
  // as the same UID could truncate or overwrite the file before spawning a
  // child; the child's shim would then load the attacker's weakened list at
  // `shim_init` time and stop hiding NPM_TOKEN / GH_TOKEN / etc.
  //
  // The replacement encodes the list directly as a comma-separated env var
  // (`SCRIPT_JAIL_PROTECTED_ENV_NAMES`).  The shim captures it into a
  // CanonBuf at `shim_init` (before any audited code runs) and the existing
  // exec-rewrite (`STICKY_VARS` in src/shim/src/lib.rs) re-injects the
  // canonical value on every exec — so attackers cannot strip the entry from
  // a descendant's envp either.  The name itself is also added to
  // `AUDIT_PROTECTED_NAMES`, so setenv/unsetenv/putenv attempts to mutate it
  // are refused and audited.
  //
  // Comma is the separator: per shim-side parsing, names containing ',' are
  // not valid POSIX env-var names anyway (POSIX permits [A-Za-z_][A-Za-z0-9_]*),
  // so the channel is unambiguous.
  //
  // Audit-trust Finding 5 (medium, 2026-05-18): validate each entry as a
  // strict env-var name BEFORE applying the entry-count and byte-length
  // caps.  Previously the count check counted YAML array entries, but the
  // shim and env-spy parsers split on ',' and '\n' at runtime — a single
  // YAML string `"FOO,BAR,...,A65"` containing 65 names would pass the
  // entry-count gate (1 entry) but the shim's
  // `load_protect_list_from_bytes` would silently truncate after entry 64
  // and the dropped names would leak unannotated.
  //
  // The chosen alternative is the stricter form: refuse any entry that
  // does not match the POSIX env-var name grammar
  // `[A-Za-z_][A-Za-z0-9_]*`.  This rejects:
  //   * entries containing ',' (the wire separator).
  //   * entries containing '\n' (the alternate wire separator).
  //   * entries containing whitespace, '#', or any other byte that the
  //     shim parser would strip / interpret specially.
  // It also rejects leading-digit names — those would parse via the wire
  // format but cannot be set via the shell anyway (POSIX shells refuse
  // `1FOO=bar` assignment), so accepting them would be misleading.
  //
  // We fire this check FIRST so the error message points at the offending
  // YAML entry rather than at a downstream symptom (count cap, byte cap).
  // An empty entry is also rejected — those would be silently skipped by
  // the shim parser and the operator would not learn that the secret
  // they meant to protect never made it into the list.
  const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
  for (const [idx, name] of config.protected.env.entries()) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new Error(
        `SCRIPT_JAIL_PROTECTED_ENV_NAMES entry [${idx}] is empty or not a string; ` +
          `each \`protected.env\` entry must be a non-empty env-var name matching ` +
          `${ENV_NAME_RE.source}.`,
      );
    }
    if (!ENV_NAME_RE.test(name)) {
      // Surface a specific diagnostic for the two highest-signal cases
      // (comma / newline) since those produce the silent-truncation
      // bypass Finding 5 fixes.
      let detail: string;
      if (name.includes(',')) {
        detail =
          'must not contain a comma — the shim parser splits the wire format on `,` ' +
          'and would treat the entry as multiple names, defeating the entry-count cap.';
      } else if (name.includes('\n')) {
        detail =
          'must not contain a newline — the shim parser splits the wire format on `\\n` ' +
          'and would treat the entry as multiple names, defeating the entry-count cap.';
      } else {
        detail =
          `must match ${ENV_NAME_RE.source} (POSIX env-var name grammar).  ` +
          'Whitespace, comments, and non-ASCII bytes are rejected to avoid silent ' +
          'splitting / stripping inside the shim parser.';
      }
      throw new Error(
        `SCRIPT_JAIL_PROTECTED_ENV_NAMES entry [${idx}] (${JSON.stringify(name)}) ${detail}`,
      );
    }
  }

  const protectedNames = config.protected.env.join(',');
  const inheritedEnv = sanitizeLifecycleBaseEnv(baseEnv);

  // Audit-trust Finding 3 (2026-05-18): the shim's static protect-list
  // table has a fixed capacity (`MAX_PROTECTED` entries, each at most
  // `NAME_MAX_LEN - 1 = 255` bytes).  An overall byte-length check by
  // itself is not enough: a config of 100 short names (`A`,`B`,`C`,…) is
  // well under the 1023-byte CanonBuf cap but would silently drop every
  // entry past index 64 inside `load_protect_list_from_bytes` — those
  // names would leak through env-spy / shim getenv unannotated, exactly
  // the silent-truncation bug Finding 2 fixed for byte-length.
  //
  // Two specific guards: entry count and per-entry byte length.  Both
  // throw with a precise pointer at the offending entry so the action
  // operator can fix the misconfiguration without grepping the shim
  // source.  Both fire BEFORE the byte-length check below so a config
  // that violates multiple caps surfaces the most actionable error first.
  if (config.protected.env.length > MAX_PROTECTED_ENV_NAMES) {
    throw new Error(
      `SCRIPT_JAIL_PROTECTED_ENV_NAMES has ${config.protected.env.length} entries; ` +
        `the LD_PRELOAD shim's static protect-list table can hold at most ` +
        `${MAX_PROTECTED_ENV_NAMES} entries before silently dropping the suffix and ` +
        `leaking the dropped names unannotated.  Reduce the \`protected.env\` ` +
        `list in .script-jail.yml (or split secrets across multiple runs).`,
    );
  }
  for (const [idx, name] of config.protected.env.entries()) {
    const nameByteLen = Buffer.byteLength(name, 'utf8');
    if (nameByteLen > PROTECTED_NAME_MAX_LEN) {
      throw new Error(
        `SCRIPT_JAIL_PROTECTED_ENV_NAMES entry [${idx}] is ${nameByteLen} bytes ` +
          `(${JSON.stringify(name)}); the LD_PRELOAD shim's per-entry buffer can ` +
          `hold at most ${PROTECTED_NAME_MAX_LEN} bytes before silently dropping the ` +
          `entry and leaking the env-var name unannotated.  Shorten or remove ` +
          `the entry in the \`protected.env\` list in .script-jail.yml.`,
      );
    }
  }

  // Audit-trust Finding 2: the shim's `capture_canon` in `src/shim/src/lib.rs`
  // copies `SCRIPT_JAIL_PROTECTED_ENV_NAMES` into a fixed-size CanonBuf
  // (CANON_BUF_LEN = 1024 bytes including NUL).  If the host composes a list
  // whose UTF-8 encoding exceeds CANON_BUF_LEN - 1 = 1023 bytes, the shim
  // SILENTLY truncates the suffix at copy time and the dropped names are
  // never registered in the protect list — those env-var names would then
  // leak through env-spy / shim getenv unannotated for every audited child.
  //
  // Fail closed at config-construction time on the trusted host side, before
  // any audit begins.  `Buffer.byteLength('utf8')` matches what the shim sees:
  // libc passes the env var's raw bytes through to `capture_canon`, which
  // copies byte-by-byte until either NUL or CANON_BUF_LEN-1 is reached.
  // Throwing here surfaces the misconfiguration directly to the action
  // operator rather than producing a misleadingly-clean lockfile.
  const protectedNamesByteLen = Buffer.byteLength(protectedNames, 'utf8');
  if (protectedNamesByteLen > CANON_PROTECTED_ENV_NAMES_MAX_LEN) {
    throw new Error(
      `SCRIPT_JAIL_PROTECTED_ENV_NAMES is ${protectedNamesByteLen} bytes ` +
        `(comma-joined from ${config.protected.env.length} entries); the LD_PRELOAD ` +
        `shim's CanonBuf can hold at most ${CANON_PROTECTED_ENV_NAMES_MAX_LEN} bytes ` +
        `before silently truncating the suffix and leaking the dropped names ` +
        `unannotated.  Reduce the \`protected.env\` list in .script-jail.yml ` +
        `(or split secrets across multiple runs).`,
    );
  }

  // Redirect the bulk install cache/store off the small rootfs (and the 16 MB
  // /root tmpfs) onto the repo overlay disk — but INJECT ONLY the knob the
  // DETECTED manager actually consumes.  Setting a foreign manager's env knob
  // is a no-op for the install, but env-spy records ANY enumerated key as an
  // `env_read`, so an unconditionally-set `YARN_*` would surface in a pnpm
  // (or npm) lockfile as noise AND break cross-backend parity for fixtures of
  // a different manager.  Keying on the resolved manager keeps each lockfile
  // to exactly the redirect that ran.  Per-key rationale:
  //   pnpm → npm_config_store_dir : pnpm's content-addressed store (the knob
  //     pnpm reads; npm/yarn ignore it).  Without it a large dep graph
  //     overruns the rootfs partway through `pnpm fetch`.
  //   yarn → YARN_GLOBAL_FOLDER + YARN_CACHE_FOLDER : berry rewrites
  //     cacheFolder to `${globalFolder}/cache` under enableGlobalCache (the
  //     env source beats repo .yarnrc.yml); YARN_CACHE_FOLDER also covers
  //     classic 1.x and `enableGlobalCache:false` berry.  Without these the
  //     cache defaults under $HOME/.yarn on the /root tmpfs → ENOSPC on a
  //     ~1000-package yarn-4 monorepo.
  //   npm  → npm_config_cache : moves the ~/.npm cacache tree off /root.
  // All tokenize under the same `$REPO/...` longest-prefix bucket as the
  // established `$REPO/.pnpm-store` (src/lock/tokenize.ts).
  const resolvedManager = config.manager ?? detectManager(config.work_dir);
  const cacheRedirectEnv: Record<string, string> =
    resolvedManager === 'pnpm'
      ? { npm_config_store_dir: `${config.work_dir}/.pnpm-store` }
      : resolvedManager === 'yarn'
        ? {
            YARN_GLOBAL_FOLDER: `${config.work_dir}/.yarn-global`,
            YARN_CACHE_FOLDER: `${config.work_dir}/.yarn-cache`,
          }
        : { npm_config_cache: `${config.work_dir}/.npm-cache` };

  return {
    ...inheritedEnv,
    ...cacheRedirectEnv,
    LD_PRELOAD: nativePreload,
    // The file path is the production channel: npm spawns lifecycle node
    // processes with `stdio: 'inherit'`, which only propagates fds 0-2.
    // fd 3 (SCRIPT_JAIL_LOG_FD) is closed in the lifecycle child, so the
    // env-shim and env-spy preload need a destination that survives the
    // spawn — a known file path.  Both writers use O_WRONLY|O_APPEND
    // so concurrent writes don't race on file offset; POSIX makes writes
    // smaller than PIPE_BUF atomic on regular files.
    //
    // The path is generated per-VM via `createEventsFile` (mkdtemp + 0700
    // dir + O_EXCL file) so its name is unguessable; the agent also
    // captures the file's inode/device at creation and the tailer re-stats
    // on every drain cycle to detect unlink/replace/truncate attempts by
    // a malicious lifecycle script.  See {@link createEventsFile}.
    SCRIPT_JAIL_LOG_FILE: eventsFilePath,
    SCRIPT_JAIL_LOG_FD: String(config.log_fd),
    SCRIPT_JAIL_PROTECTED_ENV_NAMES: protectedNames,
    SCRIPT_JAIL_PRELOAD_PATH: nativePreload,
    SCRIPT_JAIL_SPOOF_PLATFORM: config.spoof.platform,
    SCRIPT_JAIL_SPOOF_ARCH: config.spoof.arch,
    // Canonical sticky value the Rust shim's `shim_init` captures into
    // CANON_NODE_OPTIONS via real_getenv_raw() and re-injects on every exec
    // (see src/shim/src/lib.rs), even when the immediate caller scrubs
    // NODE_OPTIONS.
    SCRIPT_JAIL_NODE_OPTIONS: childNodeOptions,
    NODE_OPTIONS: [
      ...(inheritedEnv['NODE_OPTIONS'] ? [inheritedEnv['NODE_OPTIONS']] : []),
      ...requireFlags,
    ].join(' '),
    // The manager-specific cache/store redirect is spread in above via
    // `...cacheRedirectEnv` (see the rationale where it is built).
  };
}

/**
 * macOS-bare variant of {@link buildChildEnv}.  Reuses ALL of the Linux
 * builder's protected-env validation and caps (entry count, per-entry byte
 * length, CanonBuf total), then re-targets the dynamic-linker injection from
 * ELF `LD_PRELOAD` to dyld `DYLD_INSERT_LIBRARIES` (+ `DYLD_FORCE_FLAT_NAMESPACE`
 * per the dyld interpose spike) and layers on the two macOS-only sticky vars.
 *
 * What changes vs Linux:
 *   - `LD_PRELOAD` → `DYLD_INSERT_LIBRARIES` (the Mach-O shim's load var) +
 *     `DYLD_FORCE_FLAT_NAMESPACE=1` (dyld two-level-namespace defeats
 *     __interpose unless flat namespace is forced).
 *   - `NODE_OPTIONS` `--require` preloads are KEPT verbatim: NODE_OPTIONS is
 *     honored even when a hardened node strips DYLD_* at exec, so env-spy /
 *     platform-spoof remain the in-node audit floor.
 *   - `SCRIPT_JAIL_PRELOAD_PATH` already points at the native preload (the
 *     dylib on macOS) via {@link buildChildEnv}'s `nativePreload`.
 *   - `SCRIPT_JAIL_PHASE_B_UNSHARE_NET` is intentionally NOT set: the macOS
 *     backend is observe-only and stays online.
 *   - `SCRIPT_JAIL_EMIT_NODE_STARTUP_JSONL=1`: env-spy writes the
 *     node_startup_done marker DIRECTLY (the dylib may not load into a hardened
 *     node, so the shim's setenv-interception marker path cannot be relied on).
 *   - `SCRIPT_JAIL_SHELL_SHIM_DIR` is threaded through (from `baseEnv`) so the
 *     shim's sip_redirect can rewrite /bin/sh, /bin/bash, and coreutils to the
 *     materialized re-signed copies (SIP strips DYLD_* for system binaries).
 *   - `SCRIPT_JAIL_MACOS_AUDIT_OPS` is intentionally NOT set here.  main()
 *     adds it only for Phase B so Phase A keeps env_read coverage without
 *     native file/connect auditing.
 *
 * @internal Exported for unit tests and the macOS-bare main() path.
 */
export function buildChildEnvMacos(
  baseEnv: NodeJS.ProcessEnv,
  config: AgentConfig,
  eventsFilePath: string,
  preloadPaths?: AgentInput['preloadPaths'],
): NodeJS.ProcessEnv {
  // Reuse the Linux builder for all validation + the shared SCRIPT_JAIL_* /
  // NODE_OPTIONS / npm_config_store_dir keys, then strip the ELF-only
  // LD_PRELOAD and overlay the dyld + macOS-only keys.
  const base = buildChildEnv(baseEnv, config, eventsFilePath, preloadPaths);
  const { LD_PRELOAD: nativePreload, ...rest } = base;

  const env: NodeJS.ProcessEnv = {
    ...rest,
    // dyld injection (vs ELF LD_PRELOAD).  Flat namespace is required for
    // __interpose to take effect across images.
    DYLD_INSERT_LIBRARIES: nativePreload,
    DYLD_FORCE_FLAT_NAMESPACE: '1',
    // env-spy writes the node_startup_done JSONL marker directly on macOS.
    SCRIPT_JAIL_EMIT_NODE_STARTUP_JSONL: '1',
  };

  // Thread the shell-shim dir through when the backend provided it.  Pulled
  // from baseEnv (the agent's own process.env) — sanitizeLifecycleBaseEnv
  // already allows SCRIPT_JAIL_SHELL_SHIM_DIR through, so it is also present
  // in `rest` when set; we re-assert it here for clarity and to centralise
  // the macOS contract in one place.
  const shellShimDir = baseEnv['SCRIPT_JAIL_SHELL_SHIM_DIR'];
  if (shellShimDir !== undefined && shellShimDir.length > 0) {
    env['SCRIPT_JAIL_SHELL_SHIM_DIR'] = shellShimDir;
  }

  // Pass the install/repo root down so the shim's `shim_init` captures it into
  // CANON_WORK_DIR and `is_external_system_tool` keeps the WHOLE install tree —
  // node_modules/<pkg> AND its SIBLING node_modules/.bin/<helper> — audited.
  // Without this, a top-level `.bin` helper that runs after a lifecycle script
  // `chdir`s into a package dir falls outside every other keep-root and would be
  // FALSE-STRIPPED of DYLD, blinding it (and its subtree) and tripping a spurious
  // parity GATE FAILURE vs Linux.  Sticky + re-injected by the shim (and audited
  // as env_tamper if a script unsets it), exactly like SCRIPT_JAIL_SHELL_SHIM_DIR.
  env['SCRIPT_JAIL_WORK_DIR'] = config.work_dir;

  return env;
}

/**
 * Tokenize roots for the macOS-bare backend (vs the fixed Linux microVM
 * layout).  Derived from the host environment so the rendered lock tokenizes
 * developer-machine paths into the SAME `$HOME` / `$TMPDIR` / `$CACHE` tokens
 * the Linux lock uses (reconciled against any residual divergence at diff time,
 * Phase 6):
 *   - `home`:  `$HOME` (os.homedir()).
 *   - `tmp`:   realpath of `$TMPDIR` (os.tmpdir()).  macOS hands out a per-user
 *              `/var/folders/.../T` TMPDIR whose realpath lives under
 *              `/private` — collapsing it here means tokenize sees the
 *              canonical form regardless of how a script spells the temp path.
 *   - `cache`: the macOS pnpm cache (`$HOME/Library/Caches/pnpm`).  The pnpm
 *              content-addressed store tails are hashes that `collapseUnstable`
 *              folds to `$CACHE/<hash>`, matching cross-OS.
 *
 * realpathSync may throw if `$TMPDIR` does not exist (it always does on a real
 * Mac, but be defensive in test rigs); fall back to the raw value.
 *
 * @internal Exported for unit tests and the macOS-bare main() path.
 */
export function macosTokenizeRoots(workDir: string): {
  repo: string;
  nodeModules: string;
  home: string;
  tmp: string;
  cache: string;
} {
  const home = homedir();
  const rawTmp = tmpdir();
  let tmp: string;
  try {
    tmp = realpathSync(rawTmp);
  } catch {
    tmp = rawTmp;
  }
  return {
    repo: workDir,
    nodeModules: `${workDir}/node_modules`,
    home,
    tmp,
    cache: `${home}/Library/Caches/pnpm`,
  };
}

/**
 * Per-VM events-file handle.  BOTH the parent directory AND the file
 * basename are randomized per VM run.  The directory is created via
 * mkdtemp with mode 0700; the file itself is opened with O_CREAT|O_EXCL
 * so we know nothing pre-existed.  `baseline` captures the {inode, device}
 * pair at creation so the tailer can re-stat on every drain cycle and detect
 * unlink / replace / truncate / symlink-swap by an audited lifecycle script.
 *
 * SECURITY: the static `/tmp/script-jail-events.jsonl` path that preceded
 * this was a trivial target — `rm /tmp/script-jail-events.jsonl` from a
 * postinstall script erased the audit trail before the agent could read it,
 * and the file's only consumer (the tailer) treated ENOENT as a silent no-op.
 * Randomizing the path raises the bar against blind-target attacks, and the
 * inode/dev baseline + tailer fail-closed gate catches the case where an
 * attacker discovers the path via /proc/self/environ.
 *
 * Randomizing the BASENAME (not just the parent directory) is also load-
 * bearing for the Layer-1 forgery detector in `phase-install.ts`: that
 * detector flags any non-shim-loaded openat-write whose target basename
 * equals the events file basename.  With a generic basename like
 * `events.jsonl`, a legitimate package that writes `./events.jsonl`
 * would be falsely flagged.  A per-run random basename
 * (`events-<32-hex>.jsonl`) eliminates that collision while preserving
 * the detector for genuine forgery attempts that scrape
 * `SCRIPT_JAIL_LOG_FILE`.
 */
export interface EventsFile {
  /** Absolute path of the JSONL events file inside the VM. */
  path: string;
  /** Directory containing the file (mode 0700, mkdtemp-generated). */
  dirPath: string;
  /**
   * Baseline {inode, device, mtimeNs, ctimeNs} pair, captured at creation
   * via fstat.  The tailer compares dev/ino on every drain to detect
   * unlink+recreate / symlink swap.  `ctimeNs` and `mtimeNs` are captured
   * additionally to detect the "utimes restore" tamper: a same-UID attacker
   * who appends to the file, truncates back to the previous size, and then
   * calls `utimes(path, atime, oldMtime)` can defeat a pure mtime-based
   * check (since mtime is settable) — but ctime is set by the kernel on
   * every metadata or content modification and CANNOT be reset by utimes,
   * making it a stronger signal that something happened to the file after
   * our last successful drain.  See `drainEventsFile` in `runStraceTailer`
   * for the use sites.
   */
  baseline: { ino: bigint; dev: bigint; mtimeNs: bigint; ctimeNs: bigint };
}

/**
 * Base directory for the agent's bulk audit artifacts: the audit-events
 * JSONL ({@link createEventsFile}) and the per-pid `strace -ff` logs (the
 * `straceBasePath` wiring in `main()`).
 *
 * On the VM backends (Firecracker, Apple VZ) the host attaches a third
 * virtio drive labelled `scratch` (4096 MiB ext4); src/rootfs/init.sh mounts
 * it at /scratch and exports `SCRIPT_JAIL_SCRATCH_DIR=/scratch` before
 * exec'ing the orchestrator.  Both artifact classes used to live on the
 * guest's 64 MB /tmp tmpfs, which a large repo overflows (ENOSPC) —
 * a ~1000-package yarn-berry monorepo produces hundreds of MB of strace
 * text alone, and the events JSONL grows with it.
 *
 * When the variable is unset (Docker/bare backends, macOS-bare, older hosts
 * without the scratch-disk contract, unit tests) we fall back to `/tmp` —
 * byte-for-byte the previous behaviour.  An empty value is treated as unset
 * so a degenerate `SCRIPT_JAIL_SCRATCH_DIR=` cannot produce relative
 * artifact paths.
 *
 * Resolved at CALL time (not import time) so init.sh's export is the only
 * production sequencing requirement and tests can flip the env per-case.
 *
 * @internal Exported for unit tests; production callers are
 * {@link createEventsFile}'s default parameter and `main()`.
 */
export function scratchBaseDir(env: NodeJS.ProcessEnv = process.env): string {
  const dir = env['SCRIPT_JAIL_SCRATCH_DIR'];
  return dir !== undefined && dir !== '' ? dir : '/tmp';
}

/**
 * Create the per-VM events file under a fresh 0700 tmpdir and return its
 * handle.  Called by `main()` BEFORE strace launches so the path is set in
 * `SCRIPT_JAIL_LOG_FILE` (via `buildChildEnv`) and the baseline can be
 * compared on every drain cycle.
 *
 * Implementation notes:
 *   - `parentDir` defaults to {@link scratchBaseDir}: the scratch disk when
 *     the host attached one (SCRIPT_JAIL_SCRATCH_DIR), else `/tmp`.
 *   - `mkdtempSync` returns a path with mode 0700 by default.
 *   - The file is opened with O_RDWR|O_CREAT|O_EXCL so we know we hold the
 *     fresh inode; if the path somehow already exists (it shouldn't, mkdtemp
 *     is unique), we fail rather than rebind to a foreign file.
 *   - fstat-on-fd captures dev+ino atomically with the create; nothing can
 *     race the create-then-stat pair.
 */
export function createEventsFile(parentDir: string = scratchBaseDir()): EventsFile {
  // Audit-trust Finding (medium, 2026-05-19): the events file basename
  // must NOT be a generic name like `events.jsonl`.  The Layer-1
  // basename safety net in `phase-install.ts` flags any non-shim-loaded
  // openat-write whose target basename equals the events file basename.
  // With a fixed `events.jsonl` basename, a legitimate package that
  // happens to write `./events.jsonl` (no chdir, just a relative path
  // in the cwd) would be falsely flagged as `<EVENTS_FILE_FORGERY>`.
  //
  // Generate a single cryptographic-random tag at create time and use
  // it for BOTH the directory name (which mkdtemp already randomizes
  // via its `XXXXXX` template, but we use our tag explicitly so the
  // file basename can share the same tag) AND the filename:
  //   /tmp/script-jail-events-<tag>/events-<tag>.jsonl
  // The basename `events-<tag>.jsonl` is then a 32-hex-character string
  // a package cannot guess in a single run, eliminating the false
  // positive while preserving Layer 1 against a same-rootfs attacker
  // that scrapes SCRIPT_JAIL_LOG_FILE.
  //
  // 16 random bytes → 32 hex chars; the birthday-collision space (~2^64)
  // is comfortably beyond any realistic guess budget inside one install.
  const tag = randomBytes(16).toString('hex');
  // We still use mkdtempSync for the directory create — it gives us
  // atomic O_EXCL semantics on the directory and is the established
  // safe primitive.  Append our random tag to the prefix so the final
  // directory name is `script-jail-events-<tag>XXXXXX` (mkdtemp
  // requires a `XXXXXX`-template suffix).  The leading `<tag>` is what
  // we use for the file basename — the trailing 6 chars from mkdtemp
  // are extra entropy we discard from the filename derivation.
  const dirPath = mkdtempSync(joinPath(parentDir, `script-jail-events-${tag}-`));
  // mkdtempSync is defined by POSIX to create with mode 0700 (umask is
  // not applied), but enforce it explicitly so the Finding-B parent-
  // directory guard does not rely on platform-default behaviour.  A
  // weakened mode here would let a non-root caller create decoy files at
  // a colliding path inside the watched directory.
  chmodSync(dirPath, 0o700);
  const path = joinPath(dirPath, `events-${tag}.jsonl`);
  // O_NOFOLLOW refuses to traverse a symlink at the final path component.
  // Defends a future code path that creates the events file in a less-
  // restricted location: if anything has dropped a symlink at our path
  // before we open(), open() fails with ELOOP rather than rebinding our
  // writers to an attacker-chosen target.  O_EXCL already protects this
  // specific create call (mkdtemp + unique name), but O_NOFOLLOW costs
  // nothing and closes the door to a class of TOCTOU-via-symlink swaps
  // on any future variant that reuses this helper.
  const fd = openSync(
    path,
    // eslint-disable-next-line no-bitwise -- POSIX open flag composition
    fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  let baseline: { ino: bigint; dev: bigint; mtimeNs: bigint; ctimeNs: bigint };
  try {
    const s = fstatSync(fd, { bigint: true });
    // ctimeNs (status-change time) is captured in addition to mtimeNs
    // because ctime is the only mtime-class field that cannot be reset by
    // utimes(2): the kernel updates it on EVERY metadata or content
    // modification, including content writes, truncates, chmod, AND a
    // utimes() call itself.  A utimes-restore tamper bumps ctime but leaves
    // mtime where the attacker pinned it — so tracking ctime monotonicity
    // post-create catches the attack that pure mtime monotonicity misses.
    baseline = { ino: s.ino, dev: s.dev, mtimeNs: s.mtimeNs, ctimeNs: s.ctimeNs };
  } finally {
    closeSync(fd);
  }
  return { path, dirPath, baseline };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Signature subset of `node:dns.lookup` we actually use: a single hostname
 * argument with a node-style (err, _address) callback.  Exposed as its own
 * type so tests can inject a deterministic fake without depending on the
 * runtime DNS resolver.
 */
export type DnsLookupFn = (
  hostname: string,
  callback: (err: NodeJS.ErrnoException | null) => void,
) => void;

export interface AgentInput {
  configPath?: string;
  connection: Connection;
  preloadPaths?: {
    native: string;
    platformSpoof: string;
    envSpy: string;
  };
  /** Used for Phase A (fetch) only. Defaults to LinuxSpawner. */
  spawner?: Spawner;
  /** Used for Phase B (install under strace). Defaults to LinuxStraceRunner. */
  strace?: StraceRunner;
  /**
   * Optional runner for the SECOND Phase-B pass that audits the ROOT project's
   * `prepare` script (npm `rebuild --foreground-scripts` / yarn `install
   * --immutable` do NOT run a root `prepare`, so it would otherwise never be
   * audited).  Production leaves this undefined and the agent constructs a
   * fresh runner over a SEPARATE events file.  TEST SEAM: when `strace` is
   * injected (tests) the prepare pass is SKIPPED unless `prepareStrace` is ALSO
   * injected — keeping every existing test (which injects only `strace`)
   * byte-for-byte unaffected.
   */
  prepareStrace?: StraceRunner;
  /**
   * TEST-ONLY seam.  Forces the prepare pass to run even when `strace` is
   * injected and `prepareStrace` is NOT — i.e. it drives the agent down the
   * "build my own prepare runner / events file" branch with an injected main
   * runner, so the fail-closed path (prepare events-file creation failure ⇒
   * fatal, no lockfile) can be exercised without a real strace.  Never set in
   * production (the `strace === undefined` branch covers it there).
   */
  forcePreparePass?: boolean;
  /**
   * Override for the running Node's version string.  Defaults to
   * `process.version` (e.g. "v20.11.0").  The leading "v" is stripped before
   * being written into the rendered lockfile so the field contains a plain
   * dotted version.  Exposed as an injection seam so tests don't drift across
   * CI Node versions.
   */
  nodeVersion?: string;
  /**
   * Optional override for the DNS lookup used by `verifyOffline()` after the
   * host's `go` signal.  Defaults to `node:dns.lookup`.  Tests inject a fake
   * to deterministically exercise both "lookup fails → offline" and "lookup
   * succeeds → fatal" branches without touching the network.
   */
  dnsLookup?: DnsLookupFn;
  /**
   * Optional override for the guest-side network drop.  Production runs
   * `ip link set eth0 down` (busybox `ip` applet on Ubuntu 22.04/24.04) via
   * the agent's `Spawner`.  Tests inject a stub to assert call ordering and
   * exercise the "command failed" branch without touching the VM's networking.
   */
  dropEth0?: () => Promise<void>;
  /**
   * Per-call override for the DNS-probe timeout in milliseconds.  Defaults
   * to 2000ms.  Exposed primarily so tests can shorten it for the
   * "lookup hangs forever → treated as offline" case.
   */
  verifyOfflineTimeoutMs?: number;
  /**
   * Optional sink for boot/phase breadcrumbs.  Production writes to
   * `process.stderr` (which the rootfs routes to /dev/console = ttyS0 =
   * host's `[fc:out]` stream) so failures surface in the action log
   * without needing to deserialize the vsock JSONL.  Tests inject a stub
   * to capture breadcrumbs in-process instead of polluting test stderr.
   */
  diag?: (msg: string) => void;
  /**
   * Injection seam for {@link createEventsFile}.  Production uses the
   * default (mkdtemp + open with O_EXCL|O_NOFOLLOW under
   * {@link scratchBaseDir} — the scratch disk when attached, else `/tmp`).
   * Tests
   * inject a fake to simulate the file-create failure path (e.g.
   * EMFILE / EACCES / EEXIST race) without arranging a read-only /tmp,
   * and to assert the agent fails closed instead of silently falling
   * back to an empty `SCRIPT_JAIL_LOG_FILE`.  Returning a value behaves
   * like the production helper; throwing exercises the fail-closed gate.
   */
  createEventsFile?: () => EventsFile;
}

/**
 * Confirm Phase B truly has no network by asking the resolver to look up a
 * well-known registry host, with a bounded timeout.  Returns:
 *   - `true`  — lookup failed (e.g. ENOTFOUND / ECONNREFUSED) → network is
 *               disabled as expected, safe to continue.
 *   - `true`  — lookup hung past `timeoutMs` → after we dropped eth0 the
 *               resolver will typically retry until it times out; counting
 *               that as "offline" is correct AND prevents the agent from
 *               stalling forever.
 *   - `false` — lookup succeeded within the timeout → the interface drop did
 *               not take effect and any `connect ok` events in Phase B would
 *               be FALSE NEGATIVES.  Caller MUST abort with a fatal error.
 */
async function verifyOfflineWithTimeout(
  lookup: DnsLookupFn,
  timeoutMs = 2000,
): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    new Promise<boolean>((resolve) => {
      lookup('registry.npmjs.org', (err) => {
        if (timer !== undefined) clearTimeout(timer);
        resolve(err !== null);
      });
    }),
    new Promise<boolean>((resolve) => {
      timer = setTimeout(() => { resolve(true); }, timeoutMs);
    }),
  ]);
}

/**
 * Drop the eth0 network interface from inside the guest using busybox's
 * `ip` applet (present on the Ubuntu 22.04/24.04 rootfs).  Falls back to the
 * traditional `ifconfig eth0 down` for rootfs variants that ship net-tools
 * but no `ip`.
 *
 * Both invocations are best-effort: a missing interface (e.g. a Phase B-only
 * test rig) is non-fatal — `verifyOfflineWithTimeout` is the final gate.
 *
 * Returns the spawn result of whichever command succeeded, or the last
 * failure if neither worked.
 */
async function defaultDropEth0(spawner: Spawner, env: NodeJS.ProcessEnv): Promise<void> {
  // The rootfs (src/rootfs/Dockerfile.base) installs busybox but deliberately
  // omits iproute2 / net-tools to keep the image small.  busybox's applets are
  // NOT symlinked into /usr/sbin under the default `apt-get install -y --no-
  // install-recommends busybox` recipe, so bare `ip` and `ifconfig` produce
  // ENOENT.  Invoke through `busybox <applet>` instead.
  //
  // The trailing bare-binary entries are retained as best-effort fallbacks
  // for any non-Ubuntu rootfs variant that may ship iproute2 or net-tools
  // directly (the abstraction here is the agent, not the rootfs).
  const tries: Array<{ cmd: string; args: string[] }> = [
    { cmd: 'busybox', args: ['ip', 'link', 'set', 'eth0', 'down'] },
    { cmd: 'busybox', args: ['ifconfig', 'eth0', 'down'] },
    { cmd: 'ip', args: ['link', 'set', 'eth0', 'down'] },
    { cmd: 'ifconfig', args: ['eth0', 'down'] },
  ];

  let lastErr: Error | null = null;
  for (const { cmd, args } of tries) {
    try {
      const res = await spawner.spawn(cmd, args, { env, cwd: '/' });
      if (res.exitCode === 0) return;
      lastErr = new Error(`${cmd} ${args.join(' ')} exited with code ${res.exitCode}: ${res.stderr}`);
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }
  throw lastErr ?? new Error('script-jail agent: dropEth0 failed for unknown reason');
}

/**
 * Boot breadcrumb writer.  Production path writes to process.stderr (which
 * the rootfs wires to /dev/console = ttyS0 = host's `[fc:out]` stream), so
 * each breadcrumb is visible in the action log.  Tests inject a stub via
 * `input.diag` to capture breadcrumbs without polluting test stderr.
 */
function diag(input: AgentInput, msg: string): void {
  if (input.diag) input.diag(msg);
  else process.stderr.write(`[agent] ${msg}\n`);
}

/**
 * Resolve the command for the second Phase-B pass that audits the ROOT
 * project's `prepare` lifecycle script.
 *
 * Why this pass exists: the main Phase-B install command for npm
 * (`npm rebuild --foreground-scripts`) and yarn-berry (`yarn install
 * --immutable`) does NOT run the ROOT project's `prepare` script — only
 * dependencies' lifecycle scripts.  A malicious root `prepare` would therefore
 * escape the audit (and the diff gate) entirely.  pnpm's `pnpm rebuild
 * --pending` DOES run the root `prepare` (confirmed), so pnpm needs no second
 * pass → returns `null`.
 *
 * Per manager:
 *   - npm  → `npm run prepare --if-present --foreground-scripts`.  `--if-present`
 *            makes it a clean exit-0 no-op when no `prepare` script exists, so we
 *            don't need to read package.json first.
 *   - yarn → yarn-berry has NO `--if-present`; `yarn run prepare` exits 1 when
 *            there is no `prepare` script, which would be a wasted (and
 *            confusingly nonzero) pass.  So we READ `${cwd}/package.json` and
 *            only return a command when `scripts.prepare` is a non-empty string.
 *            Any read/parse error → `null` (skip).
 *   - pnpm → `null` (already covered by `pnpm rebuild --pending`).
 *
 * Returns `null` when no prepare pass should run.
 */
export function resolvePrepareCommand(
  manager: 'npm' | 'pnpm' | 'yarn',
  cwd: string,
): { cmd: string; args: string[] } | null {
  if (manager === 'npm') {
    return { cmd: 'npm', args: ['run', 'prepare', '--if-present', '--foreground-scripts'] };
  }
  if (manager === 'yarn') {
    try {
      const pkgRaw = readFileSync(joinPath(cwd, 'package.json'), 'utf8');
      const pkg = JSON.parse(pkgRaw) as { scripts?: Record<string, unknown> };
      const prepare = pkg.scripts?.['prepare'];
      if (typeof prepare === 'string' && prepare.length > 0) {
        return { cmd: 'yarn', args: ['run', 'prepare'] };
      }
    } catch {
      // No package.json, unreadable, or malformed JSON → skip the prepare pass.
      return null;
    }
    return null;
  }
  // pnpm: `pnpm rebuild --pending` already runs the root prepare.
  return null;
}

/**
 * Redact secrets from package-manager output before it is surfaced to the host
 * (Phase A failure dump).  Defence in depth (Codex round-1 [medium], 2026-06-12):
 * the failure detail tails the install tool's STDOUT, which is repo-controlled
 * (yarn plugins, lifecycle banners, `.yarnrc.yml`/`.npmrc` echoes) and runs in a
 * process that inherits the audit env — so it could print a token or a
 * credentialed registry URL right before failing, republishing it into the
 * host's CI logs and the vsock error frame.
 *
 * Two redaction layers:
 *   1. VALUE-based: every protected env var's actual value (read from the
 *      agent's own process.env, which still holds the real secrets — the shim
 *      only hides them from the lifecycle CHILDREN) is masked wherever it
 *      appears.  This is exact and catches secrets echoed verbatim.
 *   2. PATTERN-based: credential shapes that may NOT be in the protected list —
 *      `user:pass@host` URL userinfo, npm `_authToken`/`_auth`/`_password`
 *      rc lines, and `Bearer <token>` headers.
 *
 * Short/empty values are skipped (layer 1) so a protected var set to e.g. "1"
 * does not blank out every digit of an ENOSPC trace.
 *
 * @internal Exported for unit tests.
 */
export function redactSensitive(
  text: string,
  protectedEnvNames: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): string {
  let out = text;
  // Layer 1 — exact protected values.  Sort longest-first so a value that is a
  // substring of another is not partially pre-masked.
  const values = protectedEnvNames
    .map((name) => ({ name, value: env[name] }))
    .filter((e): e is { name: string; value: string } =>
      typeof e.value === 'string' && e.value.length >= 4,
    )
    .sort((a, b) => b.value.length - a.value.length);
  for (const { name, value } of values) {
    out = out.split(value).join(`<REDACTED:${name}>`);
  }
  // Layer 2 — credential SHAPES regardless of the protected list.  Relocated
  // verbatim into the shared single-source redactor (see src/shared/redact.ts)
  // so the host part-1 capture path applies the IDENTICAL shape chain.  The
  // LINE-LOCAL CONTRACT (Codex round-9 [high] #1) is documented there.
  out = redactCredentialShapes(out);
  return out;
}

export async function main(input: AgentInput): Promise<void> {
  const configPath = input.configPath ?? '/etc/script-jail/config.yml';
  diag(input, `main(): configPath=${configPath}`);

  // 1. Read + validate config
  let rawConfig: unknown;
  try {
    const text = readFileSync(configPath, 'utf8');
    rawConfig = parseYaml(text);
  } catch (err) {
    throw new Error(`script-jail agent: failed to read config at ${configPath}: ${String(err)}`);
  }
  diag(input, 'config read + parsed');

  const config = AgentConfig.parse(rawConfig);
  diag(input, `config validated: manager=${config.manager ?? '(auto)'} work_dir=${config.work_dir}`);

  // 2. Build emitter pointing at the vsock connection
  const emitter = new Emitter(input.connection.writable);

  // 3. Detect package manager
  const manager = config.manager ?? detectManager(config.work_dir);
  diag(input, `manager resolved: ${manager}`);

  // 4. Create the audit-events file under a per-VM 0700 tmpdir BEFORE the
  //     child env is built so SCRIPT_JAIL_LOG_FILE points at this fresh path.
  //     The file's {inode, device} baseline is recorded and re-checked by the
  //     tailer on every drain cycle (Finding A).  If anything inside the VM
  //     unlinks / replaces / truncates the file, the agent fails closed and
  //     never emits a final lockfile — `findAuditBypass` cannot help if the
  //     evidence of an `envp_alloc_failed` was erased before the agent saw it.
  //
  //     Failure to create the file (EACCES on a read-only /tmp, EMFILE on
  //     fd exhaustion, EEXIST race against another tenant, etc.) is FATAL.
  //     The previous fallback path set SCRIPT_JAIL_LOG_FILE="" and continued,
  //     hoping the inherited fd 3 would carry audit traffic — but npm spawns
  //     lifecycle children with `stdio: 'inherit'`, which only propagates
  //     fds 0–2.  Any descendant Node process beyond the first child loses
  //     the audit sink entirely: env_read / dlopen / exec / env_tamper events
  //     would be written into the void, producing a final lockfile with
  //     missing signals that the audit_bypass gate (fe13357) and tamper
  //     detection (81d238e) cannot recover.  A transient /tmp blip would
  //     silently degrade the audit — so we bail with a fatal error frame
  //     instead.  The injection seam (`input.createEventsFile`) lets tests
  //     exercise this branch deterministically.
  const makeEventsFile = input.createEventsFile ?? createEventsFile;
  let eventsFile: EventsFile;
  try {
    eventsFile = makeEventsFile();
  } catch (err) {
    // Surface the error class/message but not the path — `/tmp/script-jail-
    // events-<random>` is short-lived and not sensitive, yet keeping the
    // diagnostic compact avoids leaking guest tmpdir layout to the host log.
    const reason = err instanceof Error ? err.message : String(err);
    emitter.emitError(
      `script-jail agent: failed to create audit-events file — ${reason}. ` +
        'Refusing to proceed: descendants of the install child only inherit ' +
        'fds 0–2 (stdio: inherit), so without SCRIPT_JAIL_LOG_FILE pointing ' +
        'at a real path the audit pipeline loses env_read / dlopen / exec / ' +
        'env_tamper events from grandchildren.',
      true,
    );
    flushAndExit(input.connection.writable, 1);
    return;
  }
  const eventsFilePath = eventsFile.path;

  // macOS-bare detection.  The orchestrator runs on the Mac itself (no VM) and
  // selects the native runner/proc-reader/env-builder/dispatcher.  Driven by
  // the explicit backend marker the CLI's mac-bare backend sets, OR a darwin
  // host fallback — but the darwin fallback applies ONLY when no runner was
  // injected.  Existing Linux-contract unit tests inject `input.strace` (a fake
  // that yields `source:'strace'` lines); on a darwin dev machine those must
  // still route through the Linux dispatcher, not the shim-only macOS one which
  // would fail-closed on a non-'shim' source.  Production macOS never injects a
  // runner, so the fallback fires there.  Every macOS branch below is gated on
  // this flag; Linux behaviour is byte-for-byte unchanged.
  const isMacosBare =
    process.env['SCRIPT_JAIL_BACKEND'] === 'macos-bare' ||
    (process.platform === 'darwin' && input.strace === undefined);

  // 5. Build child environment.  macOS swaps LD_PRELOAD → DYLD_INSERT_LIBRARIES
  //    (+ flat namespace), keeps NODE_OPTIONS preloads, adds the macOS-only
  //    sticky vars, and does NOT set SCRIPT_JAIL_PHASE_B_UNSHARE_NET.
  const childEnv = isMacosBare
    ? buildChildEnvMacos(process.env, config, eventsFilePath, input.preloadPaths)
    : buildChildEnv(process.env, config, eventsFilePath, input.preloadPaths);
  const fetchEnv = isMacosBare ? { ...childEnv } : childEnv;
  if (isMacosBare) {
    delete fetchEnv['SCRIPT_JAIL_MACOS_AUDIT_OPS'];
  }
  const installEnv = isMacosBare
    ? { ...childEnv, SCRIPT_JAIL_MACOS_AUDIT_OPS: '1' }
    : childEnv;

  // 6. Set up spawner (Phase A) and install runner (Phase B).  On macOS the
  //    runner spawns the install DIRECTLY (no strace/unshare) and the Mach-O
  //    shim is the sole event source.
  const spawner: Spawner =
    input.spawner ?? (isMacosBare ? new MacOSSpawner() : new LinuxSpawner());
  // Size the Phase-B stdout tail cap (BYTES) to comfortably exceed the longest
  // protected env value, so the redactor always masks whole values before any
  // front-drop (a value can't straddle the cap's front when the cap is wider
  // than the value — Codex round-3 [medium] #2 / round-4 byte-vs-char).  Use
  // Buffer.byteLength (UTF-8 bytes), since the collector caps in bytes.  4 KiB
  // emit cap + longest value + 4 KiB slack.
  const maxProtectedValueBytes = config.protected.env.reduce((max, name) => {
    const v = process.env[name];
    if (typeof v !== 'string') return max;
    const n = Buffer.byteLength(v, 'utf8');
    return n > max ? n : max;
  }, 0);
  const stdoutTailBytes = Math.max(
    PHASE_B_STDOUT_TAIL_BYTES,
    4096 + maxProtectedValueBytes + 4096,
  );
  const straceRunner: StraceRunner =
    input.strace ??
    (isMacosBare
      ? new MacOSInstallRunner(undefined, eventsFile)
      : new LinuxStraceRunner(
          undefined,
          eventsFile,
          (s) => redactSensitive(s, config.protected.env),
          stdoutTailBytes,
        ));

  // 7. Attribution.  Linux reads /proc; macOS has no /proc, so MacOSProcReader
  //    returns null environ (attribution flows through the shim event seed) and
  //    best-effort ppid via the sj-procinfo helper.
  const attribution = new Attribution(
    isMacosBare ? new MacOSProcReader() : new LinuxProcReader(),
  );

  // 8. Phase A: fetch (network on, no strace)
  diag(input, `Phase A starting: ${manager} fetch in ${config.work_dir}`);
  const fetchResult = await runFetchPhase({
    manager,
    cwd: config.work_dir,
    env: fetchEnv,
    spawner,
    // Backends that cannot land the host-owned pm-flags sidecar at the default
    // absolute `/etc/script-jail/pm-flags.json` (Docker, bare, macOS-bare —
    // only Firecracker's init copies it into /etc) point us at the staged copy
    // via this env var.  Unset on Firecracker → loadPmFlags() reads the /etc
    // default.  loadPmFlags re-sanitizes whatever it reads, so this is safe
    // even though the staged copy lives in the repo-controlled namespace.
    ...(process.env['SCRIPT_JAIL_PM_FLAGS_PATH'] !== undefined
      ? { pmFlagsPath: process.env['SCRIPT_JAIL_PM_FLAGS_PATH'] }
      : {}),
  });
  diag(input, `Phase A finished: ok=${fetchResult.ok}`);

  if (!fetchResult.ok) {
    // Build the failure detail from stderr AND a stdout tail: npm/pnpm put
    // their errors on stderr, but yarn Berry writes everything — including
    // YN0001 ENOSPC traces and resolution failures — to STDOUT with an empty
    // stderr.  Without the stdout tail the fatal frame reads
    // "Phase A (fetch) failed: " and the actual cause is invisible on the
    // host (found dogfooding napi-rs).  Tail-capped so a megabyte of yarn
    // progress output cannot bloat the vsock error frame.
    // Redact BEFORE tailing (Codex round-2 [high]): the value redactor only
    // masks COMPLETE protected values, so slicing to the last 4 KB first could
    // start the tail INSIDE a secret — the partial no longer matches and the
    // suffix leaks.  Redact the full stdout/stderr (the secret is wholly
    // present), THEN cap the already-masked text.  A mask token split by the
    // cap is harmless (a truncated `<REDACTED:` leaks nothing).
    // Developer install `args` are spliced into the Phase-A fetch argv only
    // (runFetchPhase surfaces the already-re-sanitized set).  A PM error such as
    // `npm warn invalid config registry="SECRET"` echoes a user-arg VALUE that
    // matches NO credential SHAPE and is NOT a protected-ENV value — so
    // `redactSensitive` alone would let it leak to the public Actions log
    // (adversarial-review round-7 [high]).  Mask the KNOWN exact user-arg values
    // FIRST (→ <REDACTED:USER-ARG>), THEN run the existing protected-env + shape
    // redactor.  Empty userInstallArgs ⇒ deriveSensitiveValues([]) ⇒ identity,
    // so the no-user-args failure dump stays byte-identical.  This single masked
    // `fetchDetail` feeds BOTH sinks below (serial console + fatal frame).
    const userArgValues = deriveSensitiveValues(fetchResult.userInstallArgs);
    const maskUserArgs = (text: string): string =>
      maskExactValues(text, userArgValues, 'REDACTED:USER-ARG');
    const stderrRedacted = redactSensitive(maskUserArgs(fetchResult.stderr), config.protected.env).trim();
    const stdoutRedacted = redactSensitive(maskUserArgs(fetchResult.stdout), config.protected.env).trim();
    const stdoutTail =
      stdoutRedacted.length > 4000 ? `…${stdoutRedacted.slice(-4000)}` : stdoutRedacted;
    const fetchDetail = [
      stderrRedacted,
      stdoutTail === '' ? '' : `--- stdout (tail) ---\n${stdoutTail}`,
    ]
      .filter((s) => s !== '')
      .join('\n');
    // Also write to process.stderr so the npm error reaches ttyS0 (the
    // VM's serial console) — `LinuxSpawner` captures the child's stderr
    // into a string, so without this dump the only host-visible symptom
    // would be the eventual fatal error frame.  Useful when the frame
    // itself doesn't make it (e.g. before this flushAndExit was added).
    process.stderr.write(
      `[agent] Phase A (fetch) failed:\n${fetchDetail}\n`,
    );
    emitter.emitError(`Phase A (fetch) failed: ${fetchDetail}`, true);
    flushAndExit(input.connection.writable, 1);
    return;
  }

  // NOTE: no post-Phase-A TMPDIR re-validation needed.  On the VM backends
  // TMPDIR is /sjtmp — a DEDICATED disk mounted at boot (init.sh), not a path
  // under the repo disk.  A mountpoint cannot be symlink-swapped without
  // umount, and init.sh drops CAP_SYS_ADMIN + CAP_SYS_RESOURCE from the bounding
  // set AND clamps max_user_namespaces=0 before this agent (and therefore every
  // Phase-A/Phase-B package-manager child) starts — so repo code can neither
  // umount/`mount --bind` over /sjtmp directly (EPERM) nor regain mount
  // authority inside a fresh user+mount namespace (creation blocked, and the
  // clamp can't be raised without CAP_SYS_RESOURCE).  /sjtmp also carries no
  // committed repo content to subvert.  Together these replace the three rounds
  // of point-in-time guards the old /work/.sj-tmp scheme needed (Codex rounds
  // 1-7, 2026-06-12).

  emitter.emitHandshake('fetch_done');

  // 9. Wait for host "go" signal (exact string "go\n" required)
  try {
    await waitForGo(input.connection.readable);
  } catch (err) {
    emitter.emitError(String(err), true);
    flushAndExit(input.connection.writable, 1);
    return;
  }

  const phaseBUsesUnshareNet = process.env['SCRIPT_JAIL_PHASE_B_UNSHARE_NET'] === '1';

  // macOS-bare is OBSERVE-ONLY and stays ONLINE (user decision 3): the Mach-O
  // shim records connect() attempts but does not enforce offline.  There is
  // also no eth0 to drop (no VM) and dropping the host's network would be
  // hostile to the developer's machine.  So the eth0-drop + DNS-offline gate
  // below is skipped on macOS — its `connect` events are recorded with their
  // true online result and reconciled at diff time (Phase 6).
  const skipOfflineEnforcement = phaseBUsesUnshareNet || isMacosBare;

  // 9b. Before verifying offline, drop the eth0 interface from inside the
  //     guest.  We use guest-side control because Firecracker's host-side
  //     rate-limiter API treats `size: 0` as "rate limiter disabled" (i.e.
  //     unlimited), not "no bandwidth" — making host-side disabling a no-op
  //     across versions.  `ip link set eth0 down` (busybox) authoritatively
  //     removes the interface from the routing table.
  //
  //     Failure here (e.g. no eth0 interface on a Phase B-only test rig) is
  //     surfaced as a non-fatal error frame but we continue: the DNS probe
  //     immediately below is the real gate.
  if (!skipOfflineEnforcement) {
    try {
      if (input.dropEth0) {
        await input.dropEth0();
      } else {
        await defaultDropEth0(spawner, childEnv);
      }
    } catch (err) {
      emitter.emitError(
        `script-jail agent: failed to drop eth0 from inside the guest: ${String(err)}`,
        false,
      );
    }
  }

  // 9c. Sanity check: confirm the interface drop actually killed network
  //     access.  If DNS still resolves *within the timeout* the audit would
  //     silently produce false-negative `connect ok` events for any
  //     postinstall script that talks to the network — abort fatally.
  //     A hung lookup is treated as offline (the resolver retries until it
  //     times out once the interface is down).
  //
  //     We `return` after `process.exit(1)` so tests that stub out
  //     `process.exit` don't fall through to Phase B; in production
  //     `process.exit` terminates the process and the return is unreached.
  if (!skipOfflineEnforcement) {
    const lookupFn: DnsLookupFn = input.dnsLookup ?? dnsLookup;
    const offline = await verifyOfflineWithTimeout(
      lookupFn,
      input.verifyOfflineTimeoutMs,
    );
    if (!offline) {
      emitter.emitError(
        'Phase B aborted: DNS still resolves after dropping eth0 — ' +
          'network was not disabled, audit results would be unreliable.',
        true,
      );
      flushAndExit(input.connection.writable, 1);
      return;
    }
  }

  // 10. Phase B: install (network off, under strace, StraceRunner owns the process)
  const collectedEvents: import('../lock/schema.js').AttributedEvent[] = [];

  // ROOT package keys, computed ONCE here so BOTH Phase-B passes (main install
  // and the root-prepare pass) and the post-phase normalize all agree on what
  // counts as the root project.  The ROOT project is not in node_modules, so
  // discoverPkgDirs never maps it; its lifecycle events attribute to
  // `<rootName>@<rootVersion>` (or bare `<rootName>` when npm sets no version).
  // Keys MUST match attribution's buildPkg() — use buildRootPkgKeys() as the
  // single source of truth.  Missing/invalid root package.json → empty set
  // (unchanged semantics: no root lifecycle events to surface).
  //
  // `canonicalRootKey` is the SINGLE key the prepare pass forces every event
  // onto (see the prepare-pass wrapping emitter below).  It is guaranteed to be
  // a member of `rootPkgKeys`: version present (even '') → `<name>@<version>`,
  // else the bare name, else null (degenerate no-root edge — nothing to force onto).
  let rootPkgKeys = new Set<string>();
  let canonicalRootKey: string | null = null;
  // Whether the ROOT manifest actually declares a non-empty `prepare` script.
  // The npm prepare pass uses `npm run prepare --if-present`, which no-ops when
  // no `prepare` script exists — so the nameless-root fail-closed gate below
  // must key off the SCRIPT's presence, NOT off `prepareCommand !== null`
  // (which is unconditionally non-null for npm).  Otherwise a perfectly benign
  // nameless npm root with no `prepare` would be wrongly blocked.
  let hasRootPrepareScript = false;
  // Whether the ROOT manifest declares a non-empty lifecycle script that the
  // MAIN Phase-B command runs on the ROOT.  npm `npm rebuild --foreground-scripts`
  // runs ONLY preinstall/install/postinstall.  pnpm `pnpm rebuild --pending`
  // ADDITIONALLY runs prepublish (pnpm 10) and prerebuild/rebuild/postrebuild
  // (pnpm 11) — verified by an exhaustive 24-candidate probe across pnpm 10.34 +
  // 11.1, all firing with npm_package_name UNSET on a nameless root.  The sandbox
  // pnpm floats to the repo's `packageManager`, so the gate must cover the UNION
  // of both pnpm versions.  `prepare` is gated separately (npm/yarn dedicated
  // pass; pnpm main-pass prepare gate above).  Drives the nameless-root gate below.
  let hasRootMainPassLifecycle = false;
  try {
    const rootManifest = JSON.parse(readFileSync(`${config.work_dir}/package.json`, 'utf8')) as {
      name?: unknown;
      version?: unknown;
      scripts?: {
        prepare?: unknown; preinstall?: unknown; install?: unknown; postinstall?: unknown;
        prepublish?: unknown; prerebuild?: unknown; rebuild?: unknown; postrebuild?: unknown;
      };
    };
    ({ keys: rootPkgKeys, canonical: canonicalRootKey } = buildRootPkgKeys(rootManifest));
    const scripts = rootManifest.scripts ?? {};
    const nonEmpty = (s: unknown): boolean => typeof s === 'string' && s.length > 0;
    hasRootPrepareScript = nonEmpty(scripts.prepare);
    hasRootMainPassLifecycle =
      nonEmpty(scripts.preinstall) ||
      nonEmpty(scripts.install) ||
      nonEmpty(scripts.postinstall) ||
      (manager === 'pnpm' &&
        (nonEmpty(scripts.prepublish) ||
          nonEmpty(scripts.prerebuild) ||
          nonEmpty(scripts.rebuild) ||
          nonEmpty(scripts.postrebuild)));
  } catch { /* missing/invalid root package.json → no root lifecycle events to surface */ }

  // Wrap the emitter to also collect events for normalize.
  const collectingEmitter = new Emitter(
    new (class extends Writable {
      override _write(chunk: Buffer, _enc: string, cb: () => void): void {
        const line = chunk.toString();
        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(line) as Record<string, unknown>;
        } catch {
          // Malformed line from a trusted internal writer — skip silently.
          cb();
          return;
        }
        if (frame['kind'] === 'event') {
          // Re-emit to the real emitter
          input.connection.writable.write(line);
          // Collect for normalize
          collectedEvents.push({
            raw: frame['raw'] as import('../lock/schema.js').RawEvent,
            pkg: frame['pkg'] as string,
            lifecycle: frame['lifecycle'] as import('../lock/schema.js').LifecycleStage,
          });
        } else {
          input.connection.writable.write(line);
        }
        cb();
      }
    })()
  );

  // Tokenize roots used by BOTH the install-phase protected-paths matcher and
  // the post-phase normalize step. Defined once so both stages agree on what
  // `$HOME`, `$REPO`, etc. resolve to.
  //
  // Linux uses the fixed microVM layout (/root, /tmp, /root/.cache/pnpm).
  // macOS-bare runs on the developer's Mac, so the roots are derived from the
  // host environment: $HOME, the realpath of $TMPDIR (macOS hands out a
  // per-user /var/folders/... TMPDIR that is a symlink target under /private —
  // realpath collapses it so tokenize sees the canonical form), and the macOS
  // pnpm cache.  The /private realpath + cache canonicalization is reconciled
  // against the Linux lock at diff time (Phase 6).
  // Linux `tmp` follows os.tmpdir(): init.sh exports TMPDIR=/sjtmp on the VM
  // backends (yarn Berry's zip-conversion staging ENOSPCs the 64 MB /tmp tmpfs
  // on real monorepos; /sjtmp is a DEDICATED 4 GiB disk, separate from both
  // /work and the audit /scratch — see init.sh), and tmpdir() honours it.
  // /sjtmp is not under $REPO (/work), so there is no prefix overlap to
  // reason about — its paths render $TMPDIR (with hash collapsing) cleanly.
  // The literal /tmp is kept as a second $TMPDIR alias (tmpLegacy) for tools
  // that ignore TMPDIR — without it their writes would record as raw
  // /tmp/<hash> paths and break determinism/parity.  Docker/bare set no
  // TMPDIR, so tmpdir() is '/tmp' there and the alias is omitted —
  // byte-identical to the previous hardcoded root.
  const linuxTmp = tmpdir();
  const roots = isMacosBare
    ? macosTokenizeRoots(config.work_dir)
    : {
        repo: config.work_dir,
        nodeModules: `${config.work_dir}/node_modules`,
        home: '/root',
        tmp: linuxTmp,
        ...(linuxTmp !== '/tmp' ? { tmpLegacy: '/tmp' } : {}),
        cache: '/root/.cache/pnpm',
      };

  const protectedPaths = new ProtectedPathsMatcher({
    patterns: config.protected.files,
    roots,
    // macOS-bare shim paths come back /private-canonicalized (F_GETPATH); the
    // matcher must collapse /private to match the non-/private `roots`, or the
    // benign cross-package read suppression misfires and floods external_reads.
    os: isMacosBare ? 'darwin' : 'linux',
  });

  // Best-effort create of the strace output dir.  init.sh (VM) and the Docker
  // backend normally pre-create it, but the bare Linux backend has no init
  // step, and the agent agreeing with init.sh on the scratch-vs-/tmp base is
  // now load-bearing — so make the agent self-sufficient.  Failure is left to
  // the existing fail-closed path: strace cannot open its `-o` files, Phase B
  // exits non-zero with zero events, and main() refuses to emit a lockfile.
  const straceBaseDir = `${scratchBaseDir()}/script-jail-strace`;
  try {
    mkdirSync(straceBaseDir, { recursive: true });
  } catch {
    // EEXIST cannot happen (recursive: true); EROFS/EACCES fall through to
    // the strace spawn failure described above.
  }

  const installInput = {
    manager,
    cwd: config.work_dir,
    env: installEnv,
    strace: straceRunner,
    attribution,
    emitter: collectingEmitter,
    // Scratch disk when SCRIPT_JAIL_SCRATCH_DIR is set (VM backends — init.sh
    // mounts the `scratch`-labelled drive and creates <base>/script-jail-strace
    // there), /tmp otherwise (the Docker backend creates /tmp/script-jail-strace
    // itself; macOS-bare never sets the var and uses the path only as the
    // tailer's always-empty watchDir).  Per-pid `strace -ff` logs for a large
    // repo overflow the 64 MB /tmp tmpfs — see scratchBaseDir().
    straceBasePath: `${straceBaseDir}/strace.out`,
    protectedPaths,
    rootPkgKeys,
  };

  // FAIL CLOSED (pnpm) — nameless-root unaudited `prepare`, MAIN-pass variant.
  //
  // The dedicated prepare-pass gate at section 11a only covers managers whose
  // root `prepare` runs in a SEPARATE pass: npm (`npm run prepare`) and yarn
  // (`yarn run prepare`).  resolvePrepareCommand('pnpm') is ALWAYS null, so that
  // gate is never reached for pnpm.  But pnpm's MAIN Phase-B command
  // (`pnpm rebuild --pending`, INSTALL_CMD.pnpm) DOES run the ROOT project's
  // `prepare` — verified against pnpm 10.34/11.1: a root manifest with a
  // `prepare` script but NO `name` runs that prepare with npm_package_name
  // UNSET.  With no name, attributionFromEnvVars returns null and the
  // dispatcher DROPS every non-spawn prepare event at its null-attribution
  // gate, leaving the root `prepare` UNAUDITED while a clean diff against the
  // resulting lock could still return `trusted` — and with `install: true` that
  // clean lock then runs the lifecycle scripts on the host.  Refuse to emit a
  // lockfile.
  //
  // Scope: this gate is pnpm-ONLY and fires BEFORE the main install runs the
  // root prepare.  npm/yarn must NOT be added here — their main pass does NOT
  // run the root prepare, so failing closed before it would falsely block a
  // nameless npm/yarn root whose prepare never executes in this pass; their
  // root prepare is gated (correctly) inside the dedicated pass at 11a.  Same
  // signal (`hasRootPrepareScript` + `canonicalRootKey === null`) and same fatal
  // shape (emitError(…, true) + flushAndExit(1) + return) as the 11a gate.
  if (manager === 'pnpm' && hasRootPrepareScript && canonicalRootKey === null) {
    emitter.emitError(
      'Root `prepare` script present but root package.json has no usable `name` — ' +
        'its audited events cannot be attributed and would be silently dropped, ' +
        'leaving the root `prepare` unaudited. Refusing to emit a lockfile ' +
        '(add a `name` to the root package.json).',
      true,
    );
    flushAndExit(input.connection.writable, 1);
    return;
  }

  // FAIL CLOSED (npm/pnpm) — nameless-root unaudited main-pass lifecycle scripts.
  //
  // The MAIN Phase-B install runs ROOT lifecycle scripts: npm
  // `npm rebuild --foreground-scripts` runs preinstall/install/postinstall; pnpm
  // `pnpm rebuild --pending` runs those PLUS prepublish (pnpm 10) and
  // prerebuild/rebuild/postrebuild (pnpm 11) — all verified to fire on a nameless
  // root with npm_package_name UNSET.  With no usable `name`
  // (canonicalRootKey === null) attributionFromEnvVars returns null, so the
  // dispatcher DROPS every non-spawn event from those scripts at its
  // null-attribution gate — the root lifecycle runs UNAUDITED, the lock looks
  // clean, and with `install: true` host part-2 then runs those same scripts on
  // the runner trusting that clean lock.  Refuse to emit a lockfile.  This is the
  // same unaudited-nameless-root class the prepare gates (above + 11a) close,
  // reached through the non-prepare main-pass lifecycles.  `hasRootMainPassLifecycle`
  // already encodes the per-manager set (npm: 3 names; pnpm: the wider union).
  //
  // Scope: npm + pnpm ONLY.  yarn (Berry) SYNTHESIZES an npm_package_name
  // (`root-workspace-<hash>`) for the root, so its lifecycle events are NOT
  // dropped (they surface, or fail the normalize pkgDir lookup) — gating yarn
  // here would FALSELY block a nameless yarn root whose benign lifecycle emitted
  // no escaping events.  Fires BEFORE the main install pass, same fatal shape as
  // the pnpm prepare gate above.
  if (
    (manager === 'npm' || manager === 'pnpm') &&
    hasRootMainPassLifecycle &&
    canonicalRootKey === null
  ) {
    emitter.emitError(
      'Root install-time lifecycle script (preinstall/install/postinstall, or for ' +
        'pnpm also prepublish/rebuild) present but root package.json has no usable ' +
        '`name` — its audited events cannot be attributed and would be silently ' +
        'dropped, leaving the root lifecycle unaudited. Refusing to emit a lockfile ' +
        '(add a `name` to the root package.json).',
      true,
    );
    flushAndExit(input.connection.writable, 1);
    return;
  }

  // macOS-bare uses the lean shim-only dispatcher (no strace channel); Linux
  // uses the full strace+shim dispatcher.  Both share PhaseInstallInput /
  // PhaseInstallResult so the downstream exit-code / tamper / normalize logic
  // below is identical.
  const installResult = isMacosBare
    ? await runInstallPhaseMacos(installInput)
    : await runInstallPhase(installInput);

  // 11. Phase B exit-code handling.  A non-zero exit is the COMMON case for a
  //     real repo: Phase B runs dependency lifecycle scripts offline under
  //     strace, and scripts that reach for the network (puppeteer fetching
  //     Chrome, esbuild fetching a platform binary) fail — `pnpm rebuild` /
  //     `npm rebuild` then propagate the first failure's exit code.  That
  //     failure IS audit data: the collected events already describe what
  //     the script attempted.  So a non-zero exit is NON-fatal **as long as
  //     the audit actually observed something**.
  //
  //     But a non-zero exit with ZERO collected events means the install
  //     machinery itself failed before any lifecycle script ran under audit
  //     (pnpm could not start, strace could not attach, the offline install
  //     aborted during resolution).  Emitting a lockfile then would publish
  //     a deceptively CLEAN artifact — empty not because the scripts were
  //     benign but because nothing was audited.  In `update` mode that empty
  //     lockfile gets committed and every future `check` passes silently.
  //     Fail closed in that case.  (A *zero* exit with zero events is fine —
  //     that is a genuinely clean repo with no escaping behaviour.)
  if (installResult.exitCode !== 0) {
    if (installResult.eventCount === 0) {
      // Append a REDACTED tail of the install command's stdout.  yarn Berry
      // writes its setup failures (Usage Errors, YN0028 immutable rejections,
      // resolution/scoped-registry errors) to stdout, NOT stderr — without
      // this the host saw only the generic message and the real cause was
      // invisible (the `--offline` bug took a container repro to diagnose).
      // Redact the FULL captured tail BEFORE tail-capping (the redactor masks
      // only COMPLETE protected values, so slicing first could start the tail
      // inside a secret and leak the suffix — same ordering as Phase A,
      // agent.ts Codex round-2 [high]).  A mask token split by the cap is
      // harmless.  The in-memory tail (getStdoutTail → attachStdoutTailCollector)
      // is byte-capped by main() to exceed the longest protected value's UTF-8
      // byte length, so any protected value is whole — hence already masked at
      // drop time — before any front-drop reaches it (Codex round-3 [medium] #2
      // / round-4 byte-vs-char).  This redact is idempotent over those masks.
      const stdoutRedacted = redactSensitive(
        installResult.installStdoutTail,
        config.protected.env,
      ).trim();
      const stdoutTail =
        stdoutRedacted.length > 4000
          ? `…${stdoutRedacted.slice(-4000)}`
          : stdoutRedacted;
      const detail =
        stdoutTail === ''
          ? ''
          : `\n--- install stdout (tail) ---\n${stdoutTail}`;
      // Also dump to the serial console (mirror Phase A), in case the error
      // frame itself doesn't reach the host.
      if (detail !== '') {
        process.stderr.write(
          `[agent] Phase B (install) failed (exit ${installResult.exitCode}):${detail}\n`,
        );
      }
      emitter.emitError(
        `Phase B (install) failed with exit code ${installResult.exitCode} ` +
          'and produced no audit events — the install never ran a lifecycle ' +
          'script under audit. Refusing to emit a lockfile that observed nothing.' +
          detail,
        true,
      );
      flushAndExit(input.connection.writable, 1);
      return;
    }
    emitter.emitError(
      `Phase B (install) exited non-zero (code ${installResult.exitCode}) — ` +
        'one or more dependency lifecycle scripts failed under audit. This is ' +
        'recorded in the lockfile, not treated as a fatal error.',
      false,
    );
  }

  // 11a. PREPARE PASS.  The main Phase-B install (`npm rebuild
  //      --foreground-scripts` / `yarn install --immutable`) does NOT run the
  //      ROOT project's `prepare` script — only dependencies' lifecycle
  //      scripts.  A malicious root `prepare` would otherwise escape the audit
  //      entirely.  pnpm's `pnpm rebuild --pending` DOES run the root prepare,
  //      so resolvePrepareCommand returns null for it (pass skipped).
  //
  //      This is a SECOND `runInstallPhase`/`runInstallPhaseMacos` pass — we
  //      reuse the whole security-critical dispatch loop (per-pid bypass
  //      detection, events-file forgery, synthesis) verbatim via the
  //      `commandOverride` seam rather than duplicating it.  Its events land
  //      in the SAME `collectingEmitter` → `collectedEvents` → the lockfile,
  //      and its tamper signal is MERGED into installResult below so the
  //      tamper gate at 11b still fails closed on a tampering prepare.
  //
  //      The pass needs its OWN events file: a fresh runner over the SHARED
  //      main events file would re-read from offset 0 and DOUBLE-EMIT every
  //      main event.
  //
  //      TEST SEAM: when `input.strace` was injected (tests) we only run the
  //      prepare pass if `input.prepareStrace` was ALSO injected.  Every
  //      existing test injects only `input.strace`, so this keeps them
  //      byte-for-byte unaffected (no prepare pass, no golden drift).
  const prepareCommand = resolvePrepareCommand(manager, config.work_dir);
  // Run the prepare pass when a command is resolved AND we have (or can build)
  // a runner.  TEST SEAM: the existing suite injects only `input.strace`; those
  // tests must neither run a prepare pass NOR fail closed, so we run only when a
  // prepare runner was injected (`input.prepareStrace`), or we are in production
  // (`input.strace === undefined`), or a test explicitly opts in
  // (`input.forcePreparePass`, used purely to exercise the fail-closed path).
  if (
    prepareCommand !== null &&
    (input.prepareStrace !== undefined ||
      input.strace === undefined ||
      input.forcePreparePass === true)
  ) {
    // FAIL CLOSED: the root declares a `prepare` script that WILL run, but the
    // root package.json has no usable `name` (canonicalRootKey === null).  In
    // that state npm sets no npm_package_name, so attributionFromEnvVars returns
    // null and the dispatcher DROPS every non-spawn prepare event at its
    // null-attribution gate — BEFORE they reach the force-attribution emitter
    // below.  The prepare's fs reads / writes / connects would therefore be
    // silently dropped, leaving the root `prepare` UNAUDITED while a clean diff
    // against the resulting lock could still return `trusted`.  Refuse to emit a
    // lockfile (mirrors the other prepare-pass fatal gates: emitError(…,true) +
    // flushAndExit(1) + return).
    //
    // Gate on `hasRootPrepareScript`, NOT on `prepareCommand !== null`: for npm
    // the command is unconditionally non-null and `--if-present` no-ops when no
    // `prepare` script exists, so keying off the command would wrongly block a
    // benign nameless npm root that has no prepare script at all.  yarn already
    // only resolves a command when a non-empty `scripts.prepare` is present, so
    // `hasRootPrepareScript` is consistent across both managers.
    if (hasRootPrepareScript && canonicalRootKey === null) {
      emitter.emitError(
        'Root `prepare` script present but root package.json has no usable `name` — ' +
          'its audited events cannot be attributed and would be silently dropped, ' +
          'leaving the root `prepare` unaudited. Refusing to emit a lockfile ' +
          '(add a `name` to the root package.json).',
        true,
      );
      flushAndExit(input.connection.writable, 1);
      return;
    }
    diag(input, `Phase B prepare pass: ${prepareCommand.cmd} ${prepareCommand.args.join(' ')}`);
    // Obtain the prepare runner and its audit sink.  An injected runner owns
    // its own sink; otherwise build a fresh runner over a SEPARATE events file
    // — a fresh runner over the SHARED main events file would re-read from
    // offset 0 and DOUBLE-EMIT every main event.
    let prepareRunner: StraceRunner;
    let prepareEventsFilePath = eventsFilePath;
    if (input.prepareStrace !== undefined) {
      prepareRunner = input.prepareStrace;
    } else {
      // FAIL CLOSED when the prepare events file cannot be created.  Silently
      // skipping (the earlier draft) would render a final lock with the root
      // `prepare` UNAUDITED, yet `check` mode could still return `trusted` if
      // that lock matched a committed one produced under the same degraded
      // condition (Codex review #2).  Same fatal posture as the MAIN events
      // file (section 4): an unaudited lifecycle stage must never ship.
      let pf: EventsFile;
      try {
        pf = makeEventsFile();
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        emitter.emitError(
          'script-jail agent: failed to create the audit-events file for the ' +
            `root-prepare pass — ${reason}. Refusing to emit a lockfile: the ` +
            'root `prepare` script would otherwise run UNAUDITED and a clean ' +
            'diff against it would be untrustworthy.',
          true,
        );
        flushAndExit(input.connection.writable, 1);
        return;
      }
      prepareEventsFilePath = pf.path;
      prepareRunner = isMacosBare
        ? new MacOSInstallRunner(undefined, pf)
        : new LinuxStraceRunner(
            undefined,
            pf,
            (s) => redactSensitive(s, config.protected.env),
            stdoutTailBytes,
          );
    }
    // Point the prepare child's audit sink at the events file the runner uses.
    const prepareChildEnv = isMacosBare
      ? buildChildEnvMacos(process.env, config, prepareEventsFilePath, input.preloadPaths)
      : buildChildEnv(process.env, config, prepareEventsFilePath, input.preloadPaths);
    const prepareEnv = isMacosBare
      ? { ...prepareChildEnv, SCRIPT_JAIL_MACOS_AUDIT_OPS: '1' }
      : prepareChildEnv;
    // FORCE-ATTRIBUTION emitter, used ONLY for the prepare pass.  This pass runs
    // `<manager> run prepare`, so ONLY the root's `prepare` executes — EVERY
    // event it produces genuinely belongs to the root's prepare, by
    // construction.  A malicious dependency cannot inject itself into this pass,
    // so this is bulletproof regardless of any forged `npm_package_name` /
    // lifecycle env.  We override attribution here at the emitter boundary —
    // the only place where "this came from the prepare pass" is still known;
    // once events land in the shared `collectedEvents` the pass identity is
    // lost.  This makes root identity NON-FORGEABLE for the prepare pass,
    // independent of the Linux process-tree anchoring.
    //
    // Mirrors `collectingEmitter` EXACTLY for non-event frames
    // (handshake/error/final/etc. pass through unchanged); only `kind:'event'`
    // frames are rewritten: pkg → canonicalRootKey, lifecycle → 'prepare', and
    // fs read/write events get `root_anchored = true` (non-fs raw is untouched;
    // normalize only consults root_anchored for read/write).  The FORCED frame
    // is what we push into the SHARED `collectedEvents` AND re-emit to the host
    // stream, so the two stay consistent.
    const preparingEmitter = new Emitter(
      new (class extends Writable {
        override _write(chunk: Buffer, _enc: string, cb: () => void): void {
          const line = chunk.toString();
          let frame: Record<string, unknown>;
          try {
            frame = JSON.parse(line) as Record<string, unknown>;
          } catch {
            // Malformed line from a trusted internal writer — skip silently.
            cb();
            return;
          }
          if (frame['kind'] === 'event') {
            const raw = frame['raw'] as import('../lock/schema.js').RawEvent;
            // Force attribution: this pass runs only the root's prepare.
            const forcedPkg = canonicalRootKey ?? (frame['pkg'] as string);
            const forcedLifecycle: import('../lock/schema.js').LifecycleStage = 'prepare';
            // Only stamp the non-forgeable root anchor when we actually have a
            // parseable root manifest (canonicalRootKey).  With no root manifest
            // `forcedPkg` falls back to the frame's own (dep) label, which is NOT
            // the root — stamping root_anchored there would forge the very signal
            // normalize relies on.  Inert today (the prepare pass only runs with a
            // root manifest) but makes the intent explicit.
            if ((raw.kind === 'read' || raw.kind === 'write') && canonicalRootKey !== null) {
              raw.root_anchored = true;
            }
            const forcedFrame = {
              ...frame,
              pkg: forcedPkg,
              lifecycle: forcedLifecycle,
              raw,
            };
            const forcedLine = `${JSON.stringify(forcedFrame)}\n`;
            // Re-emit the FORCED frame to the real emitter (host stream stays
            // consistent with what normalize sees).
            input.connection.writable.write(forcedLine);
            // Collect the FORCED event for normalize.
            collectedEvents.push({
              raw,
              pkg: forcedPkg,
              lifecycle: forcedLifecycle,
            });
          } else {
            input.connection.writable.write(line);
          }
          cb();
        }
      })()
    );
    const prepareInput = {
      manager,
      cwd: config.work_dir,
      env: prepareEnv,
      strace: prepareRunner,
      attribution,
      emitter: preparingEmitter,
      // A DIFFERENT strace base path so per-pid `-ff` logs don't collide with
      // the main install's files on the scratch disk.
      straceBasePath: `${straceBaseDir}/strace-prepare.out`,
      protectedPaths,
      rootPkgKeys,
      commandOverride: prepareCommand,
    };
    const prepareResult = isMacosBare
      ? await runInstallPhaseMacos(prepareInput)
      : await runInstallPhase(prepareInput);
    diag(
      input,
      `Phase B prepare pass finished: exit=${prepareResult.exitCode} events=${prepareResult.eventCount}`,
    );
    // MERGE.  Mirrors the main-path fail-closed gate (~3402-3452):
    //
    //   - prepareResult.exitCode !== 0 && prepareResult.eventCount === 0:
    //     FATAL.  The prepare script is KNOWN to exist (we only reach this
    //     branch when prepareCommand !== null), so a traced run must produce
    //     at least some events (node/sh startup emits fs reads).  Zero events
    //     with a nonzero exit means strace could not attach or the PM aborted
    //     before spawning the prepare script — i.e. the root `prepare` ran
    //     UNAUDITED.  A clean diff against the resulting lockfile would be
    //     untrustworthy.  Fail closed, exactly mirroring the main path.
    //
    //   - prepareResult.exitCode !== 0 && prepareResult.eventCount > 0:
    //     Non-fatal.  Audit data exists (prepare failed offline but was
    //     traced).  Fold counts/tamper and continue — same as the main path's
    //     non-fatal nonzero handling.
    //
    //   - prepareResult.exitCode === 0: unchanged (fold counts/tamper).
    //
    // TWO tamper sources for the non-fatal paths, exactly mirroring what 11b
    // does for the MAIN runner
    // (`installResult.tamperReason ?? straceRunner.getTamperReason()`):
    //   - `prepareResult.tamperReason` — the prepare DISPATCHER's owned reason
    //     (shim-channel parse failure / bad LineSource).
    //   - `prepareRunner.getTamperReason()` — the prepare RUNNER's events-file
    //     tamper (unlink / inode-swap / mtime regression on the prepare events
    //     file).  Critically, 11b only consults the MAIN `straceRunner`, never
    //     the prepare runner — so without folding it in here a file-tamper on
    //     the prepare pass's own events file would NOT fail closed.  First-
    //     non-null wins (preserve the earliest, most specific reason).
    if (prepareResult.exitCode !== 0 && prepareResult.eventCount === 0) {
      emitter.emitError(
        `Phase B (prepare pass) exited non-zero (code ${prepareResult.exitCode}) ` +
          'and produced no audit events — the root `prepare` script likely ran ' +
          'untraced (strace could not attach) or the package manager aborted ' +
          'before spawning it. Refusing to emit a lockfile: the root `prepare` ' +
          'would be unaudited and a clean diff against it would be untrustworthy.',
        true,
      );
      flushAndExit(input.connection.writable, 1);
      return;
    }
    if (prepareResult.exitCode !== 0) {
      emitter.emitError(
        `Phase B (prepare pass) exited non-zero (code ${prepareResult.exitCode}) — ` +
          'the root `prepare` script failed under audit. This is recorded in the ' +
          'lockfile, not treated as a fatal error.',
        false,
      );
    }
    installResult.eventCount += prepareResult.eventCount;
    const prepareTamper =
      prepareResult.tamperReason ?? prepareRunner.getTamperReason();
    if (installResult.tamperReason === null) {
      installResult.tamperReason = prepareTamper;
    }
  }

  // 11b. Events-file tamper check (Findings A + B): the tailer baseline-
  //      stats the SCRIPT_JAIL_LOG_FILE path on every drain cycle and records
  //      any anomaly (unlink, inode mismatch, truncate, EACCES, parent-dir
  //      rename, mtime regression, max-seen-size shrink).  An audit bypass
  //      that erased its own `audit_bypass` entry would still leave this
  //      tamper signal because the inode/dev pair is captured BEFORE any
  //      audited code runs.  Fail closed — the host sees this as "vsock
  //      session ended without a final frame" plus the error frame.
  //
  //      Finding D: the gate dispatches on the `StraceRunner` interface
  //      contract (`getTamperReason()`), NOT on `instanceof
  //      LinuxStraceRunner`.  Any runner implementation — wrapper,
  //      decorator, alternative production runner — that observes tamper
  //      can report it and force a fail-closed path through `main()`
  //      without subclassing the canonical Linux runner.  Tests that don't
  //      audit a shared events file simply return `null` and the gate is
  //      a no-op for them.
  //
  //      Finding 2 (audit-trust): we ALSO consult
  //      `installResult.tamperReason`, owned directly by `runInstallPhase`.
  //      The StraceRunner.recordTamper() contract allows no-op
  //      implementations, so the install-phase dispatcher cannot rely on
  //      the runner to surface shim-channel parse failures or unknown
  //      LineSource discriminator values via getTamperReason().  Treat
  //      either signal as fatal — defence in depth.  First-non-null wins
  //      so the earliest, most specific reason makes it into the error
  //      frame.
  const tamperReason =
    installResult.tamperReason ?? straceRunner.getTamperReason();
  if (tamperReason !== null) {
    emitter.emitError(
      `audit pipeline tampered with: ${tamperReason}. ` +
        'Refusing to emit a final lockfile — a clean diff would be untrustworthy.',
      true,
    );
    flushAndExit(input.connection.writable, 1);
    return;
  }

  emitter.emitHandshake('install_done');

  // 11c. Auto-discover installed packages from node_modules so normalize()
  //      can resolve every fs-event's pkg→dir mapping without requiring
  //      the consumer to hand-curate pkg_dirs in .script-jail.yml.
  //
  //      Why AFTER Phase B (not after Phase A as one might expect):
  //      pnpm's Phase A is `pnpm fetch`, which populates the pnpm store
  //      but leaves `${work_dir}/node_modules` empty.  Scanning before
  //      Phase B would discover 0 packages and route every install event
  //      to `<unattributed>` — silently producing an empty lockfile.
  //      npm and yarn DO populate node_modules in Phase A, but moving
  //      the scan after Phase B is harmless for them and gives one
  //      uniform code path across managers.  Phase B is also the right
  //      moment because by then any rebuild-time `node_modules` rewrites
  //      (e.g. yarn rebuild) have settled.
  const nodeModulesDir = `${config.work_dir}/node_modules`;
  const discoveredPkgDirs = discoverPkgDirs(nodeModulesDir);
  diag(input, `pkgDirs discovered: ${discoveredPkgDirs.size} packages`);

  // Merge: user-supplied pkg_dirs override wins on conflict — preserves
  // the escape hatch for hand-curated audits, even though consumers
  // typically leave pkg_dirs empty.
  const pkgDirs = new Map<string, string>(discoveredPkgDirs);
  for (const [k, v] of Object.entries(config.pkg_dirs)) pkgDirs.set(k, v);

  // The ROOT project is not in node_modules, so discoverPkgDirs never maps it.
  // Its lifecycle events attribute to `<rootName>@<rootVersion>` (or bare
  // `<rootName>` when npm sets no version): root pre/install/postinstall from
  // the MAIN install pass, and root `prepare` from the prepare pass.  We do NOT
  // register the root as a pkgDir — mapping it to work_dir would make the WHOLE
  // repo $PKG, dropping every root write into the repo as intra-package (hiding
  // the audited behaviour) and letting a dependency forge `npm_package_name=
  // <root>` to write anywhere under the repo with the write silently dropped
  // (Codex review #1).  Instead we pass the root keys to normalize as
  // `rootPkgKeys`, which tokenizes the root's fs events against $REPO/
  // $NODE_MODULES and SURFACES them (external_reads / escaped_writes) instead of
  // throwing on the missing pkgDir.  Keys MUST match attribution's buildPkg().
  // `rootPkgKeys` is computed ONCE before the Phase-B passes (section 10) and
  // threaded into both — we reuse the SAME set here.

  // 12. Normalize + render
  //
  // On macOS-bare the normalize pass MUST run with `os: 'darwin'` so the
  // darwin-only system-noise prefixes and the `/private` realpath
  // canonicalization (Phase 6 reconciliation) actually fire.  Omitting it
  // would silently leave the lock with raw `/System`, `/private/var`, … paths
  // that never reconcile against the Linux-produced committed lock.  The Linux
  // path keeps the default (`os` undefined → 'linux').
  const ctx: NormalizeContext = isMacosBare
    ? { roots, pkgDirs, rootPkgKeys, os: 'darwin' }
    : { roots, pkgDirs, rootPkgKeys };

  let yaml: string;
  try {
    const packages = normalize(collectedEvents, ctx);

    // Compute lockfile SHA256 if path is known.
    let sha256 = config.manager_lockfile_sha256;
    if (!sha256 && config.lockfile_path) {
      try {
        const lockfileContent = readFileSync(config.lockfile_path);
        sha256 = createHash('sha256').update(lockfileContent).digest('hex');
      } catch {
        sha256 = '';
      }
    }

    // The lockfile's `node_version` reflects the Node binary the audit
    // *actually ran against* — i.e. the Linux Node toolchain that `vp env
    // install` downloaded at guest boot (installed under
    // /opt/vp/js_runtime/node/<ver>/bin and placed on PATH by init.sh).  We
    // source it from the running process (process.version, e.g. "v20.11.0")
    // and strip the leading "v" for canonical YAML output.
    // `config.node_version` is retained in the schema for backwards
    // compatibility but no longer authoritative.
    const rawNodeVersion = input.nodeVersion ?? process.version;
    const nodeVersion = rawNodeVersion.replace(/^v/, '');

    yaml = render({
      manager,
      manager_lockfile_sha256: sha256,
      node_version: nodeVersion,
      generated_at: new Date().toISOString(),
      packages,
    });
  } catch (err) {
    emitter.emitError(`normalize/render failed: ${String(err)}`, true);
    input.connection.close();
    process.exitCode = 1;
    return;
  }

  emitter.emitFinalLockfile(yaml);
  input.connection.close();
}

// ---------------------------------------------------------------------------
// Entrypoint (when run directly)
// ---------------------------------------------------------------------------

// The agent runs in three name-shapes:
//   - production: bundled into dist/guest-agent.cjs by src/rootfs/build.ts
//     and copied into the rootfs at /usr/local/lib/script-jail/guest-agent.cjs
//   - local: someone running `oxnode src/guest/agent.ts` for ad-hoc debug
//   - tests: vitest imports { main } directly — argv[1] is vitest's runner
//     path, NOT any agent.* file, so isMain is false and this block is skipped
//
// The previous check (`endsWith('agent.js')`) excluded the production .cjs
// filename, which meant Node ran the bundle, registered no work, and exited
// with status 0. orchestrate.sh saw the immediate exit and aborted with
// "agent exited before binding" — the most confusing possible no-op crash.
const isMain =
  typeof process.argv[1] === 'string' &&
  (process.argv[1].endsWith('agent.js') ||
    process.argv[1].endsWith('agent.cjs') ||
    process.argv[1].endsWith('agent.ts'));

if (isMain) {
  // Boot breadcrumb — appears on the guest's ttyS0 console (host's [fc:out]).
  // Without this, "did the agent start at all?" was indistinguishable from
  // "did the agent exit immediately?" — both leave orchestrate.sh's polling
  // loop to time out with the same generic FATAL.
  process.stderr.write('[agent] start: pid=' + process.pid + ' node=' + process.version + ' argv1=' + String(process.argv[1]) + '\n');

  const runMain = (conn: Connection): Promise<void> =>
    main({
      connection: conn,
      ...(process.env['SCRIPT_JAIL_CONFIG_PATH'] !== undefined
        ? { configPath: process.env['SCRIPT_JAIL_CONFIG_PATH'] }
        : {}),
      ...(process.env['SCRIPT_JAIL_NATIVE_PRELOAD_PATH'] !== undefined ||
        process.env['SCRIPT_JAIL_PLATFORM_PRELOAD_PATH'] !== undefined ||
        process.env['SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH'] !== undefined
        ? {
            preloadPaths: {
              native: process.env['SCRIPT_JAIL_NATIVE_PRELOAD_PATH'] ?? '/lib/libscriptjail.so',
              platformSpoof: process.env['SCRIPT_JAIL_PLATFORM_PRELOAD_PATH'] ?? '/usr/local/lib/script-jail/platform-spoof.cjs',
              envSpy: process.env['SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH'] ?? '/usr/local/lib/script-jail/env-spy.cjs',
            },
          }
        : {}),
    });

  if (process.env['SCRIPT_JAIL_CONNECTION'] === 'stdio') {
    runMain(new StdioConnection())
      .then(() => {
        process.stderr.write('[agent] main() resolved cleanly\n');
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
        process.stderr.write('[agent] FATAL: ' + msg + '\n');
        process.exit(1);
      });
  } else {

  // Production: `nodeVersion` is intentionally omitted from main()'s input so
  // the renderer captures `process.version` of the running interpreter — which
  // is the Linux Node toolchain `vp env install` downloaded at guest boot
  // (under /opt/vp/js_runtime/node/<ver>/bin, placed on PATH by init.sh).
  //
  // The TCP port here (10243) is the guest-side endpoint of the socat
  // AF_VSOCK<->TCP bridge configured in src/rootfs/init.sh.  The host still
  // talks to Firecracker's UDS at vsock port 10242 (see src/main.ts) — socat
  // listens on AF_VSOCK 10242 inside the VM and forwards to TCP 10243 here.
  LinuxVsockConnection.listen(10243)
    .then((conn) => {
      process.stderr.write('[agent] vsock peer connected, entering main()\n');
      return runMain(conn);
    })
    .then(() => {
      process.stderr.write('[agent] main() resolved cleanly\n');
    })
    .catch((err: unknown) => {
      // Dump the full error to ttyS0 so the failure mode is visible on
      // the host's [fc:out] stream.  The previous code emitted to a stray
      // PassThrough that nothing read — the error went /dev/null and the
      // host saw only the generic "session ended without a final frame".
      const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
      process.stderr.write('[agent] FATAL: ' + msg + '\n');
      process.exit(1);
    });
  }
}

// Re-export PassThrough for use in tests if needed.
export { PassThrough };

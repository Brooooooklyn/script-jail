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

import { existsSync, readFileSync, writeFileSync, watch as fsWatch, readdirSync, statSync, openSync, readSync, closeSync, fstatSync, mkdtempSync, chmodSync, constants as fsConstants, type Stats } from 'node:fs';
import { createInterface } from 'node:readline';
import { createServer, type Server, type Socket } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import { PassThrough, Writable, type Readable } from 'node:stream';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { dirname, basename, join as joinPath } from 'node:path';

import { Attribution } from './attribution.js';
import { LinuxProcReader } from './proc-reader.js';
import { Emitter } from './emit.js';
import { runFetchPhase, type Spawner } from './phase-fetch.js';
import { runInstallPhase, type StraceRunner } from './phase-install.js';
import { ProtectedPathsMatcher } from './protected-paths.js';
import { normalize, type NormalizeContext } from '../lock/normalize.js';
import { render } from '../lock/render.js';
import { discoverPkgDirs } from './discover-pkg-dirs.js';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

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

type AgentConfig = z.infer<typeof AgentConfig>;

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
   * dlopen-block preload (production channel — see {@link createEventsFile}).
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
   */
  eventsBaseline?: { ino: bigint; dev: bigint };
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
  /** Poll interval in ms for directory scan and file growth checks (default 50). */
  pollIntervalMs?: number;
  /** Extra drain time in ms after child exit to catch final writes (default 100). */
  drainMs?: number;
}

/**
 * StraceTailer merges:
 *   1. Lines from per-pid strace output files  → { pid: <pid>, line }
 *   2. JSONL lines from the fd3Stream pipe      → { pid: 0, line }
 *
 * The async generator ends once the child has exited and all trailing writes
 * have been drained.
 *
 * Exported separately so tests can exercise it without spawning real strace.
 */
export async function* runStraceTailer(
  opts: StraceTailerOptions,
): AsyncGenerator<{ pid: number; line: string }> {
  const pollIntervalMs = opts.pollIntervalMs ?? 50;
  const drainMs = opts.drainMs ?? 100;

  // Shared queue: all sources push here; the generator drains it.
  const queue: Array<{ pid: number; line: string }> = [];
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

  function parsePidFromFilename(name: string): number {
    const suffix = name.slice(opts.basePrefix.length + 1); // strip "strace.out."
    const n = parseInt(suffix, 10);
    return isFinite(n) ? n : 0;
  }

  function drainFile(name: string): void {
    const fullPath = `${opts.watchDir}/${name}`;
    const pid = parsePidFromFilename(name);
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
        queue.push({ pid, line });
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
  // the new bytes are gone.  Two cross-checks plug the hole:
  //   1. `lastMtime` — kernel updates st_mtim on EVERY write; truncate(2)
  //      counts as a write.  If poll N sees mtime > lastMtime but the file
  //      is the same size as at the previous read position, bytes were
  //      written and then discarded between polls.
  //   2. `maxSeenSize` — monotonically tracks the largest size ever observed
  //      across polls.  A poll that observes `size < maxSeenSize` (even when
  //      `size >= eventsPos`) means the file was truncated.  This catches
  //      the case where a poll happens to land between an append and the
  //      truncation that follows.
  // We also wire `fs.watch` (inotify on Linux) on the events file inode so
  // truncate(2) / open(O_TRUNC) generate `change` events the polling loop
  // would otherwise have to race to observe.
  let eventsPos = 0;
  let eventsBuf = '';
  let lastMtime: bigint = -1n; // -1n until first successful stat
  let maxSeenSize = 0;
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

    // mtime monotonicity: every write — append OR truncate — bumps st_mtim.
    // If mtime has advanced since the previous successful stat but the size
    // is still at `eventsPos` (i.e. no new bytes for us to consume), bytes
    // were written and then discarded between our polls.  That's the
    // append-then-truncate canary: the new mtime is the only durable trace
    // of the writes the attacker tried to erase.
    const mtimeBig = (stat as unknown as { mtimeNs: bigint }).mtimeNs;
    if (lastMtime !== -1n && mtimeBig > lastMtime && sizeNum === eventsPos) {
      recordTamper(
        `events file mtime advanced without new bytes (mtimeNs=${mtimeBig} > last=${lastMtime}, size=${sizeNum} == eventsPos): ${path}`,
      );
      return;
    }
    lastMtime = mtimeBig;

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
        queue.push({ pid: 0, line });
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
        queue.push({ pid: 0, line });
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
      pollDir();
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
  let pollTimer: ReturnType<typeof setInterval> | null = setInterval(() => {
    pollDir();
    drainEventsFile();
    wake();
  }, pollIntervalMs);

  // ---- wait for child exit, then drain -------------------------------------

  opts.exitPromise.then(() => {
    // Give strace one more drain interval to flush trailing writes.
    setTimeout(() => {
      // Final poll
      pollDir();
      drainEventsFile();
      // Flush any partial lines in per-pid buffers (strace may omit final \n).
      for (const [name, partial] of fileBuf) {
        if (partial.length > 0) {
          const pid = parsePidFromFilename(name);
          queue.push({ pid, line: partial });
          fileBuf.set(name, '');
        }
      }
      // Same for the events-file partial buffer (defensive — writers always
      // emit \n-terminated lines, but POSIX doesn't require atomic writes
      // across newlines so a partial chunk is technically possible).
      if (eventsBuf.length > 0) {
        queue.push({ pid: 0, line: eventsBuf });
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
    }, drainMs);
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
        queue.push({ pid, line: partial });
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
  on(event: 'close', listener: (code: number | null) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
}

/** Injectable spawn function for LinuxStraceRunner (default: node:child_process.spawn). */
export type SpawnImpl = (
  cmd: string,
  args: string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv; stdio: Array<string> },
) => SpawnResult;

export class LinuxStraceRunner implements StraceRunner {
  private _exitCode = 0;
  private readonly _spawnImpl: SpawnImpl;
  private readonly _eventsFile: EventsFile | null;
  private readonly _tamperRef: { reason: string | null } = { reason: null };

  /**
   * @param spawnImpl  Injection seam for tests.  Production passes through
   *                   to `node:child_process.spawn`.
   * @param eventsFile Per-VM events-file handle (path + baseline inode/dev)
   *                   created by the agent before strace launches.  When
   *                   `null`, the runner does not point any writer at a
   *                   shared events file — used by tests that supply a
   *                   pre-set environment via the `opts.env` passed to
   *                   `run()`.
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
   * events-file watcher, or null if no tampering was observed.  Only
   * meaningful after `run()` has been fully consumed.  Surface this in
   * `main()` to force-fail check mode when an audited process unlinked or
   * replaced the events file mid-install (Finding A).
   */
  getTamperReason(): string | null {
    return this._tamperRef.reason;
  }

  async *run(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string; basePath: string },
  ): AsyncIterable<{ pid: number; line: string }> {
    const straceArgs = [
      '-ff',
      '-e', 'trace=openat,execve,connect,readlinkat,statx,renameat2,unlinkat,faccessat2',
      '-o', opts.basePath,
      cmd,
      ...args,
    ];

    const child = this._spawnImpl('strace', straceArgs, {
      cwd: opts.cwd,
      env: opts.env,
      // fd 0: stdin  → /dev/null
      // fd 1: stdout → ignored
      // fd 2: stderr → pipe  (strace diagnostics forwarded to process.stderr)
      // fd 3: pipe   → LD_PRELOAD JSONL (env_read / dlopen events)
      stdio: ['ignore', 'ignore', 'pipe', 'pipe'],
    });

    const exitPromise = new Promise<void>((resolve) => {
      child.on('close', (code) => { this._exitCode = code ?? 1; resolve(); });
      child.on('error', () => { this._exitCode = 1; resolve(); });
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

function buildChildEnv(
  baseEnv: NodeJS.ProcessEnv,
  config: AgentConfig,
  protectedEnvFilePath: string,
  eventsFilePath: string,
): NodeJS.ProcessEnv {
  const preloads = [
    '/usr/local/lib/script-jail/dlopen-block.cjs',
    '/usr/local/lib/script-jail/platform-spoof.cjs',
    '/usr/local/lib/script-jail/env-spy.cjs',
  ];

  return {
    ...baseEnv,
    LD_PRELOAD: '/lib/libscriptjail.so',
    // The file path is the production channel: npm spawns lifecycle node
    // processes with `stdio: 'inherit'`, which only propagates fds 0-2.
    // fd 3 (SCRIPT_JAIL_LOG_FD) is closed in the lifecycle child, so the
    // env-shim and dlopen-block preload need a destination that survives
    // the spawn — a known file path.  Both writers use O_WRONLY|O_APPEND
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
    SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedEnvFilePath,
    SCRIPT_JAIL_PRELOAD_PATH: '/lib/libscriptjail.so',
    SCRIPT_JAIL_SPOOF_PLATFORM: config.spoof.platform,
    SCRIPT_JAIL_SPOOF_ARCH: config.spoof.arch,
    SCRIPT_JAIL_NODE_OPTIONS: preloads.map((p) => `--require=${p}`).join(' '),
    NODE_OPTIONS: [
      ...(baseEnv['NODE_OPTIONS'] ? [baseEnv['NODE_OPTIONS']] : []),
      ...preloads.map((p) => `--require=${p}`),
    ].join(' '),
  };
}

/**
 * Per-VM events-file handle.  The path is randomized (mkdtemp under /tmp) and
 * the directory mode is 0700; the file itself is opened with O_CREAT|O_EXCL
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
 */
export interface EventsFile {
  /** Absolute path of the JSONL events file inside the VM. */
  path: string;
  /** Directory containing the file (mode 0700, mkdtemp-generated). */
  dirPath: string;
  /** Baseline inode + device pair, captured at creation via fstat. */
  baseline: { ino: bigint; dev: bigint };
}

/**
 * Create the per-VM events file under a fresh 0700 tmpdir and return its
 * handle.  Called by `main()` BEFORE strace launches so the path is set in
 * `SCRIPT_JAIL_LOG_FILE` (via `buildChildEnv`) and the baseline can be
 * compared on every drain cycle.
 *
 * Implementation notes:
 *   - `mkdtempSync` returns a path with mode 0700 by default.
 *   - The file is opened with O_RDWR|O_CREAT|O_EXCL so we know we hold the
 *     fresh inode; if the path somehow already exists (it shouldn't, mkdtemp
 *     is unique), we fail rather than rebind to a foreign file.
 *   - fstat-on-fd captures dev+ino atomically with the create; nothing can
 *     race the create-then-stat pair.
 */
export function createEventsFile(parentDir: string = '/tmp'): EventsFile {
  const dirPath = mkdtempSync(joinPath(parentDir, 'script-jail-events-'));
  // mkdtempSync is defined by POSIX to create with mode 0700 (umask is
  // not applied), but enforce it explicitly so the Finding-B parent-
  // directory guard does not rely on platform-default behaviour.  A
  // weakened mode here would let a non-root caller create decoy files at
  // a colliding path inside the watched directory.
  chmodSync(dirPath, 0o700);
  const path = joinPath(dirPath, 'events.jsonl');
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
  let baseline: { ino: bigint; dev: bigint };
  try {
    const s = fstatSync(fd, { bigint: true });
    baseline = { ino: s.ino, dev: s.dev };
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
  /** Used for Phase A (fetch) only. Defaults to LinuxSpawner. */
  spawner?: Spawner;
  /** Used for Phase B (install under strace). Defaults to LinuxStraceRunner. */
  strace?: StraceRunner;
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

  // 4. Write protected-env file to a temp location
  const protectedEnvPath = '/tmp/script-jail-protected.txt';
  writeFileSync(protectedEnvPath, config.protected.env.join('\n') + '\n', 'utf8');

  // 4b. Create the audit-events file under a per-VM 0700 tmpdir BEFORE the
  //     child env is built so SCRIPT_JAIL_LOG_FILE points at this fresh path.
  //     The file's {inode, device} baseline is recorded and re-checked by the
  //     tailer on every drain cycle (Finding A).  If anything inside the VM
  //     unlinks / replaces / truncates the file, the agent fails closed and
  //     never emits a final lockfile — `findAuditBypass` cannot help if the
  //     evidence of an `envp_alloc_failed` was erased before the agent saw it.
  //
  //     Tests inject a custom strace runner via `input.strace`; in that path
  //     we still create the events file (and pass its path via childEnv) so
  //     test environments using the production env-shim see a usable sink.
  //     The injected runner is free to ignore the path entirely.
  let eventsFile: EventsFile | null;
  try {
    eventsFile = createEventsFile();
  } catch (err) {
    // Creating the events file is non-fatal in test/CI environments where
    // /tmp may be read-only or otherwise unwritable — fall back to a NULL
    // path so the production env-shim's SCRIPT_JAIL_LOG_FILE branch is
    // skipped and writers fall through to SCRIPT_JAIL_LOG_FD.  We
    // deliberately do NOT bail here because the audit pipeline has other
    // signals (strace, fd 3) and the events file is one of several inputs.
    diag(input, `events-file create failed (non-fatal): ${String(err)}`);
    eventsFile = null;
  }
  const eventsFilePath = eventsFile !== null ? eventsFile.path : '';

  // 5. Build child environment
  const childEnv = buildChildEnv(process.env, config, protectedEnvPath, eventsFilePath);

  // 6. Set up spawner (Phase A) and strace runner (Phase B)
  const spawner: Spawner = input.spawner ?? new LinuxSpawner();
  const straceRunner: StraceRunner = input.strace ?? new LinuxStraceRunner(undefined, eventsFile);

  // 7. Attribution (reads /proc; real ProcReader in production)
  const attribution = new Attribution(new LinuxProcReader());

  // 8. Phase A: fetch (network on, no strace)
  diag(input, `Phase A starting: ${manager} fetch in ${config.work_dir}`);
  const fetchResult = await runFetchPhase({
    manager,
    cwd: config.work_dir,
    env: childEnv,
    spawner,
  });
  diag(input, `Phase A finished: ok=${fetchResult.ok}`);

  if (!fetchResult.ok) {
    // Also write to process.stderr so the npm error reaches ttyS0 (the
    // VM's serial console) — `LinuxSpawner` captures the child's stderr
    // into a string, so without this dump the only host-visible symptom
    // would be the eventual fatal error frame.  Useful when the frame
    // itself doesn't make it (e.g. before this flushAndExit was added).
    process.stderr.write(
      `[agent] Phase A (fetch) failed:\n${fetchResult.stderr}\n`,
    );
    emitter.emitError(`Phase A (fetch) failed: ${fetchResult.stderr}`, true);
    flushAndExit(input.connection.writable, 1);
    return;
  }

  emitter.emitHandshake('fetch_done');

  // Auto-discover installed packages from node_modules so normalize() can
  // resolve every fs-event's pkg→dir mapping without requiring the consumer
  // to hand-curate pkg_dirs in .script-jail.yml.
  //
  // This runs AFTER Phase A's fetch_done handshake (npm ci has populated
  // node_modules) and BEFORE Phase B (install under strace), so the map
  // is ready when collectedEvents are normalized at the end.
  const nodeModulesDir = `${config.work_dir}/node_modules`;
  const discoveredPkgDirs = discoverPkgDirs(nodeModulesDir);
  diag(input, `pkgDirs discovered: ${discoveredPkgDirs.size} packages`);

  // Merge: user-supplied pkg_dirs override wins on conflict — preserves the
  // escape hatch for hand-curated audits, even though consumers typically
  // leave pkg_dirs empty.
  const pkgDirs = new Map<string, string>(discoveredPkgDirs);
  for (const [k, v] of Object.entries(config.pkg_dirs)) pkgDirs.set(k, v);

  // 9. Wait for host "go" signal (exact string "go\n" required)
  try {
    await waitForGo(input.connection.readable);
  } catch (err) {
    emitter.emitError(String(err), true);
    flushAndExit(input.connection.writable, 1);
    return;
  }

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

  // 10. Phase B: install (network off, under strace, StraceRunner owns the process)
  const collectedEvents: import('../lock/schema.js').AttributedEvent[] = [];

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
  const roots = {
    repo: config.work_dir,
    nodeModules: `${config.work_dir}/node_modules`,
    home: '/root',
    tmp: '/tmp',
    cache: '/root/.cache/pnpm',
  };

  const protectedPaths = new ProtectedPathsMatcher({
    patterns: config.protected.files,
    roots,
  });

  const installResult = await runInstallPhase({
    manager,
    cwd: config.work_dir,
    env: childEnv,
    strace: straceRunner,
    attribution,
    emitter: collectingEmitter,
    straceBasePath: '/tmp/script-jail-strace/strace.out',
    protectedPaths,
  });

  // 11. If install failed, emit error and abort — do NOT emit a final lockfile
  //     for a failed install, which would give the host a partial/untrusted artifact.
  if (installResult.exitCode !== 0) {
    emitter.emitError(
      `Phase B (install) failed with exit code ${installResult.exitCode}`,
      true,
    );
    input.connection.close();
    process.exitCode = installResult.exitCode;
    return;
  }

  // 11b. Events-file tamper check (Finding A): the tailer baseline-stats the
  //      SCRIPT_JAIL_LOG_FILE path on every drain cycle and records any
  //      anomaly (unlink, inode mismatch, truncate, EACCES).  An audit
  //      bypass that erased its own `audit_bypass` entry would still leave
  //      this tamper signal because the inode/dev pair is captured BEFORE
  //      any audited code runs.  Fail closed here — the host sees this as
  //      "vsock session ended without a final frame" + the error frame.
  //
  //      Only meaningful when we created an events file AND the production
  //      strace runner is in use; test-injected runners do not own the
  //      events-file watcher and report no tamper status.
  if (eventsFile !== null && straceRunner instanceof LinuxStraceRunner) {
    const tamperReason = straceRunner.getTamperReason();
    if (tamperReason !== null) {
      emitter.emitError(
        `audit pipeline tampered with: ${tamperReason}. ` +
          'Refusing to emit a final lockfile — a clean diff would be untrustworthy.',
        true,
      );
      flushAndExit(input.connection.writable, 1);
      return;
    }
  }

  emitter.emitHandshake('install_done');

  // 12. Normalize + render
  const ctx: NormalizeContext = { roots, pkgDirs };

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

    // Task #12: the lockfile's `node_version` reflects the Node binary the
    // audit *actually ran against* — i.e. the runner's Node, packed onto the
    // host-node disk and mounted at /opt/host-node.  We source it from the
    // running process (process.version, e.g. "v20.11.0") and strip the
    // leading "v" for canonical YAML output.  `config.node_version` is
    // retained in the schema for backwards compatibility but no longer
    // authoritative.
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

  // Production: `nodeVersion` is intentionally omitted from main()'s input so
  // the renderer captures `process.version` of the running interpreter — which
  // is the host-mounted Node at /opt/host-node, picked up via PATH by init.sh.
  // That's the entire point of the host-Node mount (Task #12).
  //
  // The TCP port here (10243) is the guest-side endpoint of the socat
  // AF_VSOCK<->TCP bridge configured in src/rootfs/init.sh.  The host still
  // talks to Firecracker's UDS at vsock port 10242 (see src/main.ts) — socat
  // listens on AF_VSOCK 10242 inside the VM and forwards to TCP 10243 here.
  LinuxVsockConnection.listen(10243)
    .then((conn) => {
      process.stderr.write('[agent] vsock peer connected, entering main()\n');
      return main({ connection: conn });
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

// Re-export PassThrough for use in tests if needed.
export { PassThrough };

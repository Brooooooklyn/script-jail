// script-jail — src/action/firecracker/vsock.ts
//
// Host-side vsock connection handler.
//
// Protocol (Firecracker vsock-over-UDS pattern, host-initiated mode):
//   - When PUT /vsock is processed, Firecracker creates a Unix-domain
//     socket at the BASE `uds_path` configured on the device (no port
//     suffix). That socket is the host-initiated control socket.
//   - To dial a guest vsock port, the host connects to that base socket
//     and writes the handshake line "CONNECT <port>\n".  Firecracker
//     replies with "OK <port>\n" and bidirectional bytes follow.
//   - The `<uds_path>_<port>` form is for the OPPOSITE direction
//     (guest-initiated): the host would have to pre-create + listen on
//     that socket and the guest would dial AF_VSOCK <port>.  We do NOT
//     use that mode — see the transport-bridge note below.
//   - After the handshake, the guest emits JSONL frames (one JSON object
//     per line, newline-terminated).  The host parses each frame and
//     yields it as a typed GuestFrame.
//   - The host signals "go" by writing "go\n" to the socket.
//
// The `openVsockSession` function is injectable in tests: pass any
// net.Socket-like duplex (e.g. a pair of PassThrough streams) in place of
// the real UDS connection.
//
// Transport bridge (host <-> guest):
//   Node has no native AF_VSOCK support, so the guest agent cannot speak
//   AF_VSOCK directly.  The rootfs ships `socat`, and the guest's
//   /sbin/orchestrate script (invoked by init.sh under dumb-init) runs
//   `socat VSOCK-LISTEN:10242,fork TCP:127.0.0.1:10243` *only after* the
//   agent has bound TCP 127.0.0.1:10243 — confirmed by polling /proc/net/tcp
//   — so the bridge cannot accept a host CONNECT before the agent is ready.
//   The host side (this file) connects to Firecracker's BASE UDS at
//   `${udsPath}` and sends `CONNECT 10242\n`; Firecracker forwards that
//   to AF_VSOCK port 10242 in the guest, where socat accepts it and
//   pipes the bytes through to TCP 127.0.0.1:10243, where the agent's
//   `LinuxVsockConnection.listen` is waiting.  See src/rootfs/init.sh,
//   src/rootfs/orchestrate.sh, and src/guest/agent.ts.

import { createConnection, type Socket } from 'node:net';
import { createInterface } from 'node:readline';
import type { AttributedEvent } from '../../lock/schema.js';

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------

export type GuestFrame =
  | { kind: 'event'; event: AttributedEvent }
  | { kind: 'handshake'; phase: 'fetch_done' | 'install_done' }
  | { kind: 'error'; message: string; fatal: boolean }
  | { kind: 'final'; yaml: string };

// ---------------------------------------------------------------------------
// VsockSession
// ---------------------------------------------------------------------------

export interface VsockSession {
  /** Async iterable of parsed frames from the guest. */
  events: AsyncIterable<GuestFrame>;
  /** Writes "go\n" to the guest connection. */
  sendGo(): Promise<void>;
  /** Closes the underlying connection. */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Duplex abstraction for test injection
// ---------------------------------------------------------------------------

/** Minimal duplex interface used by VsockSession internals. */
export interface VsockDuplex {
  write(data: string): boolean;
  destroy(): void;
  /** The readable side for line-by-line parsing. */
  readable: NodeJS.ReadableStream;
}

// ---------------------------------------------------------------------------
// openVsockSession
// ---------------------------------------------------------------------------

/**
 * Opens a vsock session to the guest.
 *
 * Production:
 *   Connects to `${udsPath}_${port}` (the Firecracker UDS naming convention),
 *   sends the "CONNECT <port>\n" handshake, then parses JSONL frames.
 *
 * Tests:
 *   Pass `options.duplex` to inject a fake duplex.  The CONNECT handshake
 *   is still written to the duplex (so tests can assert on it).
 */
export async function openVsockSession(
  udsPath: string,
  port: number,
  options?: {
    /** Override the underlying duplex for tests. */
    duplex?: VsockDuplex | undefined;
    /** Timeout in ms while waiting for the first frame.  Default: 30_000. */
    connectTimeoutMs?: number | undefined;
  },
): Promise<VsockSession> {
  let duplex: VsockDuplex;

  if (options?.duplex !== undefined) {
    duplex = options.duplex;
    // In test mode the fake duplex is "always ready"; just emit CONNECT
    // so tests can assert on it.
    duplex.write(`CONNECT ${port}\n`);
  } else {
    // Production: host-initiated mode — connect to the BASE UDS path
    // Firecracker created on PUT /vsock (no `_<port>` suffix).  Retry
    // the CONNECT until the guest's AF_VSOCK listener (socat invoked by
    // /sbin/orchestrate) is up.  Firecracker accepts the UDS connection
    // immediately on PUT /vsock, but it replies to CONNECT with `ERR …`
    // or closes the socket when no guest listener exists yet.  Without
    // retry the host gives up at ~0.8s — long before the VM has even
    // booted past kernel init.  See protocol comment at top of file.
    const sock = await dialVsockWithRetry(
      udsPath,
      port,
      options?.connectTimeoutMs ?? 30_000,
    );
    duplex = socketToDuplex(sock);
    // CONNECT + OK handshake already completed inside dialVsockWithRetry.
  }

  // Build the async iterable over JSONL frames.
  const events = parseFrames(duplex.readable);

  const session: VsockSession = {
    events,

    sendGo: (): Promise<void> => {
      return new Promise<void>((resolve, reject) => {
        void reject; // unused — we resolve unconditionally
        const ok = duplex.write('go\n');
        if (!ok) {
          // Write buffer full — 'go\n' is already buffered; wait for drain
          // before resolving, but do NOT re-write it (that would double-send).
          const writeable = duplex as unknown as NodeJS.WritableStream;
          if (typeof (writeable as NodeJS.WritableStream & { once?: (event: string, cb: () => void) => void }).once === 'function') {
            (writeable as NodeJS.WritableStream & { once: (event: string, cb: () => void) => void })
              .once('drain', () => { resolve(); });
          } else {
            // Fallback: resolve after one tick (data is already buffered).
            setImmediate(() => { resolve(); });
          }
        } else {
          resolve();
        }
      });
    },

    close: async (): Promise<void> => {
      duplex.destroy();
    },
  };

  return session;
}

// ---------------------------------------------------------------------------
// JSONL frame parser
// ---------------------------------------------------------------------------

/**
 * Reads JSONL lines from `readable` and yields typed GuestFrame objects.
 *
 * Malformed JSON lines do NOT crash the stream — they are yielded as an
 * error frame with `fatal: false` so the caller can log them and continue.
 */
async function* parseFrames(
  readable: NodeJS.ReadableStream,
): AsyncIterable<GuestFrame> {
  const rl = createInterface({ input: readable, crlfDelay: Infinity });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let raw: unknown;
    try {
      raw = JSON.parse(trimmed);
    } catch {
      yield {
        kind: 'error',
        message: `script-jail vsock: malformed JSON frame: ${trimmed.slice(0, 200)}`,
        fatal: false,
      };
      continue;
    }

    if (typeof raw !== 'object' || raw === null) {
      yield {
        kind: 'error',
        message: `script-jail vsock: expected JSON object, got: ${trimmed.slice(0, 200)}`,
        fatal: false,
      };
      continue;
    }

    yield classifyFrame(raw as Record<string, unknown>);
  }
}

/** Classify a parsed JSON object into a typed GuestFrame. */
function classifyFrame(obj: Record<string, unknown>): GuestFrame {
  const kind = obj['kind'];

  switch (kind) {
    case 'event': {
      // We trust the guest to send well-formed events; the host normalizer
      // validates them more strictly.  Here we just pass them through.
      return {
        kind: 'event',
        event: obj as unknown as AttributedEvent,
      };
    }

    case 'handshake': {
      const phase = obj['phase'];
      if (phase === 'fetch_done' || phase === 'install_done') {
        return { kind: 'handshake', phase };
      }
      return {
        kind: 'error',
        message: `script-jail vsock: unknown handshake phase: ${String(phase)}`,
        fatal: false,
      };
    }

    case 'error': {
      return {
        kind: 'error',
        message: typeof obj['message'] === 'string' ? obj['message'] : String(obj['message']),
        fatal: obj['fatal'] === true,
      };
    }

    case 'final': {
      if (typeof obj['yaml'] !== 'string') {
        return {
          kind: 'error',
          message: `script-jail vsock: "final" frame missing "yaml" string field`,
          fatal: false,
        };
      }
      return { kind: 'final', yaml: obj['yaml'] };
    }

    default: {
      return {
        kind: 'error',
        message: `script-jail vsock: unknown frame kind: ${String(kind)}`,
        fatal: false,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Production connection helpers
// ---------------------------------------------------------------------------

function connectUnixSocket(sockPath: string, timeoutMs: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const sock = createConnection(sockPath);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`Timeout connecting to vsock UDS at ${sockPath}`));
    }, timeoutMs);

    sock.once('connect', () => {
      clearTimeout(timer);
      resolve(sock);
    });
    sock.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Dial the Firecracker vsock UDS in host-initiated mode and complete the
 * `CONNECT <port>` handshake. Retries on `ERR …`, on early-close, or on
 * timeout-without-OK — all expected during VM boot before the guest's
 * AF_VSOCK listener (socat) is up.  Resolves with a Socket whose first
 * inbound bytes are the start of the guest stream (the `OK <port>\n`
 * response has been consumed; any trailing bytes after `OK` are unshifted
 * back so the downstream JSONL parser doesn't miss them).
 */
async function dialVsockWithRetry(
  udsPath: string,
  port: number,
  totalTimeoutMs: number,
): Promise<Socket> {
  const deadline = Date.now() + totalTimeoutMs;
  let attempt = 0;
  let lastError = 'no attempts made';

  while (Date.now() < deadline) {
    attempt++;
    let sock: Socket;
    try {
      // 5 s per-attempt UDS connect.  The UDS file is created at
      // PUT /vsock so this almost always succeeds immediately; the
      // failure modes we retry are CONNECT-level, not connect-level.
      sock = await connectUnixSocket(udsPath, 5_000);
    } catch (err) {
      lastError = `attempt ${attempt}: UDS connect failed: ${(err as Error).message}`;
      await sleep(200);
      continue;
    }

    sock.write(`CONNECT ${port}\n`);

    const result = await waitForOkLine(sock, 1_000);
    if (result.kind === 'ok') {
      // Put any bytes that arrived after the OK newline back into the
      // socket's readable side so the downstream parser sees them.
      if (result.remainder.length > 0) sock.unshift(result.remainder);
      return sock;
    }

    sock.destroy();
    lastError = `attempt ${attempt}: ${result.reason}`;
    const backoff = Math.min(200 * 2 ** (attempt - 1), 2000);
    await sleep(backoff);
  }

  throw new Error(
    `script-jail: vsock CONNECT did not complete within ${totalTimeoutMs} ms — ${lastError}`,
  );
}

/**
 * Reads bytes from `sock` until either:
 *   - the first newline arrives: return { ok: true, remainder: rest }
 *     if the line begins with `OK `, otherwise { ok: false, reason: … }.
 *   - the socket closes or errors: return { ok: false, reason: 'closed' / 'error' }.
 *   - timeoutMs elapses: return { ok: false, reason: 'timeout' }.
 *
 * All listeners are removed before resolving so the caller can safely
 * reuse the socket (on OK) or destroy it (on failure).
 */
function waitForOkLine(
  sock: Socket,
  timeoutMs: number,
): Promise<{ kind: 'ok'; remainder: Buffer } | { kind: 'fail'; reason: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let settled = false;

    const finish = (result: { kind: 'ok'; remainder: Buffer } | { kind: 'fail'; reason: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.off('data', onData);
      sock.off('close', onClose);
      sock.off('error', onError);
      resolve(result);
    };

    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      const newlineIdx = all.indexOf(0x0a /* \n */);
      if (newlineIdx === -1) return;
      const line = all.subarray(0, newlineIdx).toString('utf8').trim();
      const remainder = all.subarray(newlineIdx + 1);
      if (line.startsWith('OK ')) {
        finish({ kind: 'ok', remainder });
      } else {
        finish({ kind: 'fail', reason: `unexpected handshake response: "${line}"` });
      }
    };
    const onClose = (): void => finish({ kind: 'fail', reason: 'socket closed before OK' });
    const onError = (err: Error): void => finish({ kind: 'fail', reason: `socket error: ${err.message}` });

    const timer = setTimeout(
      () => finish({ kind: 'fail', reason: `timeout waiting for OK response (${timeoutMs}ms)` }),
      timeoutMs,
    );

    sock.on('data', onData);
    sock.once('close', onClose);
    sock.once('error', onError);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function socketToDuplex(sock: Socket): VsockDuplex {
  return {
    write: (data: string): boolean => sock.write(data),
    destroy: (): void => { sock.destroy(); },
    readable: sock,
  };
}

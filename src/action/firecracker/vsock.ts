// script-jail — src/action/firecracker/vsock.ts
//
// Host-side vsock connection handler.
//
// Protocol (Firecracker vsock-over-UDS pattern):
//   - Firecracker exposes the guest's vsock port as a Unix domain socket at
//     `${udsBasePath}_${port}` on the host.
//   - The host connects by writing the handshake line "CONNECT <port>\n" to
//     the socket, then the guest's kernel routes traffic into the VM.
//   - After the handshake, the guest emits JSONL frames (one JSON object per
//     line, newline-terminated).  The host parses each frame and yields it
//     as a typed GuestFrame.
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
//   The host side (this file) connects to Firecracker's UDS at
//   `${udsPath}_${port}` and sends `CONNECT 10242\n`; Firecracker forwards
//   that to AF_VSOCK port 10242 in the guest, where socat accepts it and
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
  } else {
    // Production: connect to the UDS Firecracker exposes.
    const sockPath = `${udsPath}_${port}`;
    const sock = await connectUnixSocket(sockPath, options?.connectTimeoutMs ?? 30_000);
    duplex = socketToDuplex(sock);
  }

  // Send the vsock CONNECT handshake.
  duplex.write(`CONNECT ${port}\n`);

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

function socketToDuplex(sock: Socket): VsockDuplex {
  return {
    write: (data: string): boolean => sock.write(data),
    destroy: (): void => { sock.destroy(); },
    readable: sock,
  };
}

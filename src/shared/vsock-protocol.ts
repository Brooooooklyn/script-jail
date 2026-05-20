// script-jail — src/shared/vsock-protocol.ts
//
// Generic JSONL frame protocol spoken between the guest agent and any host
// runner (Firecracker on Linux CI, Virtualization.framework on macOS).  The
// protocol shape is identical across runners; only the underlying transport
// (Firecracker host-initiated UDS vs. VZ VZVirtioSocketListener) differs.
//
// Wire format:
//   - One JSON object per line, newline-terminated (JSONL).
//   - Each frame has a `kind` field that discriminates the union below.
//   - The guest emits frames; the host parses them.
//
// Frame kinds:
//   - `event`     — an audited file/env/dlopen/execve/connect event.
//   - `handshake` — boot milestone marker (`fetch_done` or `install_done`).
//   - `error`     — guest-side error.  `fatal: true` aborts the run; `false`
//                   is a recoverable diagnostic the host should log.
//   - `final`     — the rendered lockfile YAML.  Exactly one per successful
//                   run, emitted after `install_done`.
//
// Parser behaviour:
//   Malformed JSON lines do NOT crash the stream — `parseFrames` yields them
//   as an error frame with `fatal: false` so the host can log and continue.
//   This matters when the guest's stdout/vsock occasionally interleaves
//   non-JSON noise (e.g. partial writes during a panic).

import { createInterface } from 'node:readline';
import type { AttributedEvent } from '../lock/schema.js';

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
// JSONL frame parser
// ---------------------------------------------------------------------------

/**
 * Reads JSONL lines from `readable` and yields typed GuestFrame objects.
 *
 * Malformed JSON lines do NOT crash the stream — they are yielded as an
 * error frame with `fatal: false` so the caller can log them and continue.
 */
export async function* parseFrames(
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

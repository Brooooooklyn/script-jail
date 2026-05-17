// script-jail — test/action/firecracker/vsock.test.ts
//
// Tests for openVsockSession() using pipe-based fake duplexes.
//
// The fake duplex captures what the host writes and lets us inject JSONL
// frames as if they came from the guest.

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { openVsockSession, type VsockDuplex, type GuestFrame } from '../../../src/action/firecracker/vsock.js';

// ---------------------------------------------------------------------------
// Fake duplex
// ---------------------------------------------------------------------------

interface FakeDuplex extends VsockDuplex {
  /** Inject a line (JSONL frame) from the guest side. */
  guestSend(line: string): void;
  /** Close the guest side (signals EOF to the host). */
  guestClose(): void;
  /** Everything the host wrote to the duplex. */
  hostWrote(): string;
}

function makeFakeDuplex(): FakeDuplex {
  const guestToHost = new PassThrough(); // guest writes → host reads
  let hostOutput = '';

  const duplex: FakeDuplex = {
    write(data: string): boolean {
      hostOutput += data;
      return true;
    },
    destroy(): void {
      guestToHost.destroy();
    },
    get readable() {
      return guestToHost as unknown as NodeJS.ReadableStream;
    },
    guestSend(line: string): void {
      guestToHost.write(line + '\n');
    },
    guestClose(): void {
      guestToHost.end();
    },
    hostWrote(): string {
      return hostOutput;
    },
  };

  return duplex;
}

// ---------------------------------------------------------------------------
// Helper: collect all frames from a session into an array, then close.
// ---------------------------------------------------------------------------

async function collectFrames(
  duplex: FakeDuplex,
  lines: string[],
): Promise<GuestFrame[]> {
  const session = await openVsockSession('/tmp/vsock-test.sock', 10242, { duplex });

  // Feed frames and then close to signal EOF.
  for (const line of lines) {
    duplex.guestSend(line);
  }
  duplex.guestClose();

  const frames: GuestFrame[] = [];
  for await (const frame of session.events) {
    frames.push(frame);
  }
  return frames;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('openVsockSession', () => {
  it('writes "CONNECT <port>\\n" handshake to the duplex on open', async () => {
    const duplex = makeFakeDuplex();
    duplex.guestClose(); // immediately close so the iterable finishes

    await openVsockSession('/tmp/vsock.sock', 10242, { duplex });

    expect(duplex.hostWrote()).toContain('CONNECT 10242\n');
  });

  it('parses a handshake fetch_done frame', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'handshake', phase: 'fetch_done' }),
    ]);

    expect(frames).toHaveLength(1);
    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('handshake');
    if (frame0.kind === 'handshake') {
      expect(frame0.phase).toBe('fetch_done');
    }
  });

  it('parses a handshake install_done frame', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'handshake', phase: 'install_done' }),
    ]);

    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('handshake');
    if (frame0.kind === 'handshake') {
      expect(frame0.phase).toBe('install_done');
    }
  });

  it('parses an error frame', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'error', message: 'Phase A failed', fatal: true }),
    ]);

    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('error');
    if (frame0.kind === 'error') {
      expect(frame0.message).toBe('Phase A failed');
      expect(frame0.fatal).toBe(true);
    }
  });

  it('parses a final frame with yaml', async () => {
    const duplex = makeFakeDuplex();
    const yaml = 'schema_version: 1\npackages: {}';
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'final', yaml }),
    ]);

    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('final');
    if (frame0.kind === 'final') {
      expect(frame0.yaml).toBe(yaml);
    }
  });

  it('parses an event frame', async () => {
    const duplex = makeFakeDuplex();
    const eventPayload = {
      kind: 'event',
      raw: { kind: 'read', path: '/etc/passwd', pid: 100, ts: 1234, hidden: false },
      pkg: 'express@4.18.0',
      lifecycle: 'postinstall',
    };
    const frames = await collectFrames(duplex, [JSON.stringify(eventPayload)]);

    expect(frames[0]!.kind).toBe('event');
  });

  it('yields an error frame (non-fatal) for malformed JSON — does not throw', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      'this is not valid JSON {{{',
    ]);

    expect(frames).toHaveLength(1);
    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('error');
    if (frame0.kind === 'error') {
      expect(frame0.fatal).toBe(false);
      expect(frame0.message).toContain('malformed JSON');
    }
  });

  it('yields an error frame for unknown frame kinds', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'unknown_future_kind', data: 42 }),
    ]);

    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('error');
    if (frame0.kind === 'error') {
      expect(frame0.message).toContain('unknown frame kind');
    }
  });

  it('handles multiple frames in sequence', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'handshake', phase: 'fetch_done' }),
      JSON.stringify({ kind: 'handshake', phase: 'install_done' }),
      JSON.stringify({ kind: 'final', yaml: 'schema_version: 1' }),
    ]);

    expect(frames).toHaveLength(3);
    expect(frames[0]!.kind).toBe('handshake');
    expect(frames[1]!.kind).toBe('handshake');
    expect(frames[2]!.kind).toBe('final');
  });

  it('skips blank lines without producing frames', async () => {
    const duplex = makeFakeDuplex();
    const session = await openVsockSession('/tmp/vsock-test.sock', 10242, { duplex });

    duplex.guestSend('');
    duplex.guestSend('   ');
    duplex.guestSend(JSON.stringify({ kind: 'handshake', phase: 'fetch_done' }));
    duplex.guestClose();

    const frames: GuestFrame[] = [];
    for await (const frame of session.events) {
      frames.push(frame);
    }

    // Only one real frame (blank lines skipped).
    expect(frames).toHaveLength(1);
    expect(frames[0]!.kind).toBe('handshake');
  });

  it('sendGo() writes "go\\n" to the duplex', async () => {
    const duplex = makeFakeDuplex();
    duplex.guestClose();

    const session = await openVsockSession('/tmp/vsock.sock', 10242, { duplex });
    await session.sendGo();

    expect(duplex.hostWrote()).toContain('go\n');
  });

  it('sendGo() under backpressure: sends exactly one "go\\n" and resolves', async () => {
    // Build a FakeDuplex whose first write() returns false (backpressure),
    // then emits 'drain' asynchronously.  Assert 'go\n' is written exactly once.
    const { EventEmitter } = await import('node:events');
    const emitter = new EventEmitter();
    const guestToHost = new (await import('node:stream')).PassThrough();

    let writeCount = 0;
    const writes: string[] = [];

    const backpressureDuplex: VsockDuplex & { once: (event: string, cb: () => void) => void } = {
      write(data: string): boolean {
        writes.push(data);
        writeCount++;
        if (data === 'go\n') {
          // Simulate backpressure: buffer is full on the first go write.
          // Schedule a drain event after a tick.
          setImmediate(() => emitter.emit('drain'));
          return false;
        }
        return true; // CONNECT handshake succeeds immediately
      },
      destroy(): void {
        guestToHost.destroy();
      },
      get readable(): NodeJS.ReadableStream {
        return guestToHost as unknown as NodeJS.ReadableStream;
      },
      once(event: string, cb: () => void): void {
        emitter.once(event, cb);
      },
    };

    guestToHost.end(); // close guest side so events iterable finishes

    const session = await openVsockSession('/tmp/vsock-bp.sock', 10242, {
      duplex: backpressureDuplex,
    });

    await session.sendGo();

    // Exactly one 'go\n' must have been written (not two).
    const goWrites = writes.filter((w) => w === 'go\n');
    expect(goWrites).toHaveLength(1);
  });

  it('close() does not throw', async () => {
    const duplex = makeFakeDuplex();
    duplex.guestClose();

    const session = await openVsockSession('/tmp/vsock.sock', 10242, { duplex });
    await expect(session.close()).resolves.toBeUndefined();
  });

  it('yields an error frame when final frame lacks yaml field', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'final' }), // missing yaml
    ]);

    const frame0 = frames[0]!;
    expect(frame0.kind).toBe('error');
    if (frame0.kind === 'error') {
      expect(frame0.message).toContain('"final"');
    }
  });

  it('yields an error frame for unknown handshake phase', async () => {
    const duplex = makeFakeDuplex();
    const frames = await collectFrames(duplex, [
      JSON.stringify({ kind: 'handshake', phase: 'unknown_phase' }),
    ]);

    expect(frames[0]!.kind).toBe('error');
  });
});

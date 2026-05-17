// script-jail — emit.ts
// JSONL emitter for the vsock channel between the guest agent and the host.
//
// All methods serialize one frame as a single JSON line terminated by '\n'.
// The emitter is safe to call from a single-threaded execution context.
// NOTE: If ever used from concurrent code paths the caller must serialize
// writes externally; Writable.write() is not atomically concurrent-safe.

import type { Writable } from 'node:stream';
import type { AttributedEvent } from '../lock/schema.js';

export class Emitter {
  private readonly out: Writable;

  constructor(out: Writable) {
    this.out = out;
  }

  /**
   * Emit one attributed event as a JSONL line.
   * Frame shape: {"kind":"event","raw":{...},"pkg":"...","lifecycle":"..."}\n
   */
  emitEvent(ev: AttributedEvent): void {
    this._writeLine({ kind: 'event', raw: ev.raw, pkg: ev.pkg, lifecycle: ev.lifecycle });
  }

  /**
   * Emit the final rendered lockfile YAML.
   * The yaml string is JSON-escaped and embedded inside the frame.
   * Frame shape: {"kind":"final","yaml":"<escaped YAML string>"}\n
   */
  emitFinalLockfile(yaml: string): void {
    this._writeLine({ kind: 'final', yaml });
  }

  /**
   * Emit a handshake frame signalling a phase boundary.
   * Frame shape: {"kind":"handshake","phase":"fetch_done"|"install_done"}\n
   */
  emitHandshake(phase: 'fetch_done' | 'install_done'): void {
    this._writeLine({ kind: 'handshake', phase });
  }

  /**
   * Emit an error frame.
   * Frame shape: {"kind":"error","message":"...","fatal":bool}\n
   */
  emitError(message: string, fatal: boolean): void {
    this._writeLine({ kind: 'error', message, fatal });
  }

  private _writeLine(obj: unknown): void {
    this.out.write(JSON.stringify(obj) + '\n');
  }
}

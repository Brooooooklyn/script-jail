// Tests for src/guest/emit.ts
// Pure unit tests — no I/O, no child processes.

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { Emitter } from '../../src/guest/emit.js';
import type { AttributedEvent } from '../../src/lock/schema.js';

function makeEmitter(): { emitter: Emitter; getOutput: () => string } {
  const pt = new PassThrough();
  const chunks: string[] = [];
  pt.on('data', (chunk: Buffer) => { chunks.push(chunk.toString()); });
  const emitter = new Emitter(pt);
  return { emitter, getOutput: () => chunks.join('') };
}

describe('Emitter', () => {
  describe('emitEvent', () => {
    it('writes a JSONL line with kind=event', () => {
      const { emitter, getOutput } = makeEmitter();
      const ev: AttributedEvent = {
        raw: { kind: 'read', path: '/work/index.js', pid: 42, ts: 1, hidden: false },
        pkg: 'my-pkg@1.0.0',
        lifecycle: 'postinstall',
      };
      emitter.emitEvent(ev);
      const output = getOutput();
      expect(output.endsWith('\n')).toBe(true);
      const parsed = JSON.parse(output.trim()) as Record<string, unknown>;
      expect(parsed['kind']).toBe('event');
      expect(parsed['pkg']).toBe('my-pkg@1.0.0');
      expect(parsed['lifecycle']).toBe('postinstall');
      expect((parsed['raw'] as Record<string, unknown>)['path']).toBe('/work/index.js');
    });

    it('handles all raw event kinds', () => {
      const cases: AttributedEvent[] = [
        {
          raw: { kind: 'write', path: '/tmp/out.js', pid: 1, ts: 0, hidden: false },
          pkg: 'pkg@1.0.0',
          lifecycle: 'install',
        },
        {
          raw: { kind: 'env_read', name: 'PATH', pid: 1, ts: 0, hidden: false },
          pkg: 'pkg@1.0.0',
          lifecycle: 'install',
        },
        {
          raw: { kind: 'spawn', argv: ['node', '--version'], result: 'ok', pid: 1, ts: 0 },
          pkg: 'pkg@1.0.0',
          lifecycle: 'install',
        },
        {
          raw: { kind: 'dlopen', filename: '/lib/foo.node', result: 'blocked', pid: 1, ts: 0 },
          pkg: 'pkg@1.0.0',
          lifecycle: 'install',
        },
        {
          raw: { kind: 'connect', host: '1.2.3.4', port: 443, result: 'ok', pid: 1, ts: 0 },
          pkg: 'pkg@1.0.0',
          lifecycle: 'install',
        },
      ];

      for (const ev of cases) {
        const { emitter, getOutput } = makeEmitter();
        emitter.emitEvent(ev);
        const line = getOutput().trim();
        expect(() => JSON.parse(line)).not.toThrow();
        const parsed = JSON.parse(line) as Record<string, unknown>;
        expect(parsed['kind']).toBe('event');
        expect((parsed['raw'] as Record<string, unknown>)['kind']).toBe(ev.raw.kind);
      }
    });
  });

  describe('emitFinalLockfile', () => {
    it('writes kind=final with yaml field', () => {
      const { emitter, getOutput } = makeEmitter();
      const yaml = 'schema_version: 1\nmanager: npm\n';
      emitter.emitFinalLockfile(yaml);
      const output = getOutput();
      expect(output.endsWith('\n')).toBe(true);
      const parsed = JSON.parse(output.trim()) as Record<string, unknown>;
      expect(parsed['kind']).toBe('final');
      expect(parsed['yaml']).toBe(yaml);
    });

    it('correctly embeds YAML with special characters', () => {
      const { emitter, getOutput } = makeEmitter();
      const yaml = 'key: "value with \\"quotes\\" and\\nnewlines"\n';
      emitter.emitFinalLockfile(yaml);
      const parsed = JSON.parse(getOutput().trim()) as Record<string, unknown>;
      expect(parsed['yaml']).toBe(yaml);
    });
  });

  describe('emitHandshake', () => {
    it('writes fetch_done handshake', () => {
      const { emitter, getOutput } = makeEmitter();
      emitter.emitHandshake('fetch_done');
      const parsed = JSON.parse(getOutput().trim()) as Record<string, unknown>;
      expect(parsed['kind']).toBe('handshake');
      expect(parsed['phase']).toBe('fetch_done');
    });

    it('writes install_done handshake', () => {
      const { emitter, getOutput } = makeEmitter();
      emitter.emitHandshake('install_done');
      const parsed = JSON.parse(getOutput().trim()) as Record<string, unknown>;
      expect(parsed['kind']).toBe('handshake');
      expect(parsed['phase']).toBe('install_done');
    });
  });

  describe('emitError', () => {
    it('writes kind=error with message and fatal=true', () => {
      const { emitter, getOutput } = makeEmitter();
      emitter.emitError('something went wrong', true);
      const parsed = JSON.parse(getOutput().trim()) as Record<string, unknown>;
      expect(parsed['kind']).toBe('error');
      expect(parsed['message']).toBe('something went wrong');
      expect(parsed['fatal']).toBe(true);
    });

    it('writes kind=error with fatal=false', () => {
      const { emitter, getOutput } = makeEmitter();
      emitter.emitError('minor issue', false);
      const parsed = JSON.parse(getOutput().trim()) as Record<string, unknown>;
      expect(parsed['fatal']).toBe(false);
    });
  });

  describe('multiple calls', () => {
    it('each call writes a separate newline-terminated line', () => {
      const { emitter, getOutput } = makeEmitter();
      emitter.emitHandshake('fetch_done');
      emitter.emitHandshake('install_done');
      emitter.emitError('err', false);

      const output = getOutput();
      const lines = output.split('\n').filter((l) => l.length > 0);
      expect(lines).toHaveLength(3);
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }
    });
  });
});

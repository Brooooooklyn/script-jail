import { describe, it, expect } from 'vitest';
import {
  FsReadEvent,
  FsWriteEvent,
  EnvReadEvent,
  SpawnEvent,
  DlopenEvent,
  NetworkEvent,
  RawEvent,
  AttributedEvent,
  LifecycleStage,
  LifecycleBlock,
  Lock,
} from '../../src/lock/schema.js';

describe('schema', () => {
  describe('FsReadEvent', () => {
    it('parses a valid read event', () => {
      const raw = { kind: 'read', path: '/work/foo', pid: 1, ts: 0, hidden: false };
      expect(FsReadEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects when kind is wrong', () => {
      const raw = { kind: 'write', path: '/work/foo', pid: 1, ts: 0, hidden: false };
      expect(FsReadEvent.safeParse(raw).success).toBe(false);
    });
    it('rejects missing required field', () => {
      const raw = { kind: 'read', path: '/work/foo', pid: 1, ts: 0 };
      expect(FsReadEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('FsWriteEvent', () => {
    it('parses a valid write event', () => {
      const raw = { kind: 'write', path: '/tmp/out', pid: 2, ts: 1, hidden: true };
      expect(FsWriteEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects wrong kind', () => {
      const raw = { kind: 'read', path: '/tmp/out', pid: 2, ts: 1, hidden: true };
      expect(FsWriteEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('EnvReadEvent', () => {
    it('parses a valid env_read event', () => {
      const raw = { kind: 'env_read', name: 'HOME', pid: 3, ts: 2, hidden: false };
      expect(EnvReadEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects missing name', () => {
      const raw = { kind: 'env_read', pid: 3, ts: 2, hidden: false };
      expect(EnvReadEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('SpawnEvent', () => {
    it('parses result=ok', () => {
      const raw = { kind: 'spawn', argv: ['node', 'install.js'], result: 'ok', pid: 4, ts: 3 };
      expect(SpawnEvent.safeParse(raw).success).toBe(true);
    });
    it('parses result=enoent', () => {
      const raw = { kind: 'spawn', argv: ['bash'], result: 'enoent', pid: 4, ts: 3 };
      expect(SpawnEvent.safeParse(raw).success).toBe(true);
    });
    it('parses result=eacces', () => {
      const raw = { kind: 'spawn', argv: ['./script.sh'], result: 'eacces', pid: 4, ts: 3 };
      expect(SpawnEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects invalid result', () => {
      const raw = { kind: 'spawn', argv: ['node'], result: 'denied', pid: 4, ts: 3 };
      expect(SpawnEvent.safeParse(raw).success).toBe(false);
    });
    it('rejects missing argv', () => {
      const raw = { kind: 'spawn', result: 'ok', pid: 4, ts: 3 };
      expect(SpawnEvent.safeParse(raw).success).toBe(false);
    });
    it('has no hidden field', () => {
      const parsed = SpawnEvent.safeParse({ kind: 'spawn', argv: ['node'], result: 'ok', pid: 4, ts: 3 });
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        expect((parsed.data as Record<string, unknown>)['hidden']).toBeUndefined();
      }
    });
    it('parses the optional macOS audit_blind flag when true', () => {
      const raw = { kind: 'spawn', argv: ['/usr/bin/find', '.'], result: 'ok', pid: 4, ts: 3, audit_blind: true };
      const parsed = SpawnEvent.safeParse(raw);
      expect(parsed.success).toBe(true);
      if (parsed.success) expect(parsed.data.audit_blind).toBe(true);
    });
    it('omits audit_blind when absent (byte-stable: never materialized as false)', () => {
      const parsed = SpawnEvent.safeParse({ kind: 'spawn', argv: ['node'], result: 'ok', pid: 4, ts: 3 });
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        expect((parsed.data as Record<string, unknown>)['audit_blind']).toBeUndefined();
      }
    });
  });

  describe('DlopenEvent', () => {
    it('parses a valid dlopen event', () => {
      const raw = { kind: 'dlopen', filename: 'libssl.so', result: 'blocked', pid: 5, ts: 4 };
      expect(DlopenEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects result != blocked', () => {
      const raw = { kind: 'dlopen', filename: 'libssl.so', result: 'ok', pid: 5, ts: 4 };
      expect(DlopenEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('NetworkEvent', () => {
    it('parses result=ok', () => {
      const raw = { kind: 'connect', host: 'example.com', port: 443, result: 'ok', pid: 6, ts: 5 };
      expect(NetworkEvent.safeParse(raw).success).toBe(true);
    });
    it('parses result=blocked', () => {
      const raw = { kind: 'connect', host: '1.2.3.4', port: 80, result: 'blocked', pid: 6, ts: 5 };
      expect(NetworkEvent.safeParse(raw).success).toBe(true);
    });
    it('rejects invalid result', () => {
      const raw = { kind: 'connect', host: 'x.com', port: 443, result: 'denied', pid: 6, ts: 5 };
      expect(NetworkEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('RawEvent discriminated union', () => {
    it('dispatches to FsReadEvent on kind=read', () => {
      const raw = { kind: 'read', path: '/tmp/x', pid: 1, ts: 0, hidden: false };
      const result = RawEvent.safeParse(raw);
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.kind).toBe('read');
    });
    it('dispatches to NetworkEvent on kind=connect', () => {
      const raw = { kind: 'connect', host: 'h', port: 1234, result: 'ok', pid: 1, ts: 0 };
      const result = RawEvent.safeParse(raw);
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.kind).toBe('connect');
    });
    it('rejects unknown kind', () => {
      const raw = { kind: 'unknown_kind', path: '/x', pid: 1, ts: 0 };
      expect(RawEvent.safeParse(raw).success).toBe(false);
    });
  });

  describe('AttributedEvent', () => {
    const validRaw = { kind: 'read', path: '/work/x', pid: 1, ts: 0, hidden: false };

    it('round-trips an attributed event', () => {
      const ev = { raw: validRaw, pkg: 'esbuild@0.21.5', lifecycle: 'postinstall' };
      const result = AttributedEvent.safeParse(ev);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.pkg).toBe('esbuild@0.21.5');
        expect(result.data.lifecycle).toBe('postinstall');
        expect(result.data.raw.kind).toBe('read');
      }
    });

    it('rejects invalid lifecycle stage', () => {
      const ev = { raw: validRaw, pkg: 'foo@1.0.0', lifecycle: 'notareal' };
      expect(AttributedEvent.safeParse(ev).success).toBe(false);
    });

    it('accepts all lifecycle stages', () => {
      const stages: LifecycleStage[] = ['preinstall', 'install', 'postinstall', 'prepare'];
      for (const lifecycle of stages) {
        const ev = { raw: validRaw, pkg: 'foo@1.0.0', lifecycle };
        expect(AttributedEvent.safeParse(ev).success).toBe(true);
      }
    });
  });

  describe('LifecycleBlock', () => {
    it('applies defaults for empty input', () => {
      const result = LifecycleBlock.safeParse({});
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.external_reads).toEqual([]);
        expect(result.data.network_attempts).toEqual([]);
      }
    });

    it('parses a full block', () => {
      const block = {
        external_reads: ['$CACHE/something'],
        escaped_writes: [],
        env_read: ['HOME'],
        spawn_attempts: ['node install.js'],
        spawn_blocked: [],
        dlopen_attempts: [],
        network_attempts: ['connect example.com:443'],
      };
      const result = LifecycleBlock.safeParse(block);
      expect(result.success).toBe(true);
    });
  });

  describe('Lock', () => {
    it('parses a minimal valid lock document', () => {
      const doc = {
        schema_version: 1,
        manager: 'pnpm',
        manager_lockfile_sha256: 'abc123',
        node_version: '20.0.0',
        generated_at: '2026-05-16T00:00:00Z',
        packages: {},
      };
      expect(Lock.safeParse(doc).success).toBe(true);
    });

    it('rejects invalid manager', () => {
      const doc = {
        schema_version: 1,
        manager: 'bun',
        manager_lockfile_sha256: 'abc',
        node_version: '20.0.0',
        generated_at: '2026-05-16T00:00:00Z',
        packages: {},
      };
      expect(Lock.safeParse(doc).success).toBe(false);
    });

    it('rejects wrong schema_version', () => {
      const doc = {
        schema_version: 2,
        manager: 'npm',
        manager_lockfile_sha256: 'abc',
        node_version: '20.0.0',
        generated_at: '2026-05-16T00:00:00Z',
        packages: {},
      };
      expect(Lock.safeParse(doc).success).toBe(false);
    });
  });
});

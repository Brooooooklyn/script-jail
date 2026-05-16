// Unit tests for src/guest/protected-paths.ts
//
// Two surfaces:
//   - ProtectedPathsMatcher.isProtected(rawPath): pattern matching on the
//     tokenized form of an absolute path (~ → $HOME, $REPO/etc. as-is).
//   - applyProtectedPathsPolicy(ev, matcher): policy decision for an
//     AttributedEvent (emit/drop/hidden).

import { describe, it, expect } from 'vitest';
import {
  ProtectedPathsMatcher,
  applyProtectedPathsPolicy,
} from '../../src/guest/protected-paths.js';
import type { AttributedEvent } from '../../src/lock/schema.js';

const roots = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.cache/pnpm',
};

const pkgId = 'esbuild@0.21.5';

function readEv(path: string, errno?: 'ENOENT' | 'EACCES'): AttributedEvent {
  const raw = errno === undefined
    ? { kind: 'read' as const, path, pid: 1, ts: 0, hidden: false }
    : { kind: 'read' as const, path, pid: 1, ts: 0, hidden: false, errno };
  return { raw, pkg: pkgId, lifecycle: 'postinstall' };
}

function writeEv(path: string, errno?: 'ENOENT' | 'EACCES'): AttributedEvent {
  const raw = errno === undefined
    ? { kind: 'write' as const, path, pid: 1, ts: 0, hidden: false }
    : { kind: 'write' as const, path, pid: 1, ts: 0, hidden: false, errno };
  return { raw, pkg: pkgId, lifecycle: 'postinstall' };
}

// ── ProtectedPathsMatcher.isProtected ────────────────────────────────────────

describe('ProtectedPathsMatcher', () => {
  describe('tilde expansion', () => {
    it('~/.ssh/** matches /root/.ssh/id_rsa', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.ssh/**'], roots });
      expect(m.isProtected('/root/.ssh/id_rsa')).toBe(true);
    });

    it('~/.ssh/** matches nested /root/.ssh/keys/foo.pem', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.ssh/**'], roots });
      expect(m.isProtected('/root/.ssh/keys/foo.pem')).toBe(true);
    });

    it('~/.ssh/** does NOT match /root/.npmrc (different subdir)', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.ssh/**'], roots });
      expect(m.isProtected('/root/.npmrc')).toBe(false);
    });

    it('~/.npmrc matches /root/.npmrc exactly', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.npmrc'], roots });
      expect(m.isProtected('/root/.npmrc')).toBe(true);
    });

    it('bare ~ is normalized to $HOME and matches /root', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~'], roots });
      expect(m.isProtected('/root')).toBe(true);
    });
  });

  describe('$HOME match', () => {
    it('explicit $HOME/.aws/** pattern matches /root/.aws/credentials', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['$HOME/.aws/**'], roots });
      expect(m.isProtected('/root/.aws/credentials')).toBe(true);
    });

    it('does not match a path outside $HOME', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['$HOME/.aws/**'], roots });
      expect(m.isProtected('/work/.aws/credentials')).toBe(false);
    });
  });

  describe('$REPO match', () => {
    it('$REPO/.env matches /work/.env exactly', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['$REPO/.env'], roots });
      expect(m.isProtected('/work/.env')).toBe(true);
    });

    it('$REPO/.env.* matches /work/.env.local', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['$REPO/.env.*'], roots });
      expect(m.isProtected('/work/.env.local')).toBe(true);
    });

    it('$REPO/.env.* does NOT match /work/.env (no extension)', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['$REPO/.env.*'], roots });
      expect(m.isProtected('/work/.env')).toBe(false);
    });
  });

  describe('dotfile match (micromatch dot: true required)', () => {
    it('~/.gnupg/** matches a dotfile inside a dot-prefixed dir', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.gnupg/**'], roots });
      expect(m.isProtected('/root/.gnupg/pubring.gpg')).toBe(true);
    });

    it('plain $HOME/* would NOT match without dot:true; with dot:true it matches .npmrc', () => {
      // Sanity check that dot:true is in effect.
      const m = new ProtectedPathsMatcher({ patterns: ['$HOME/*'], roots });
      expect(m.isProtected('/root/.npmrc')).toBe(true);
    });
  });

  describe('multiple patterns', () => {
    it('matches any of several patterns', () => {
      const m = new ProtectedPathsMatcher({
        patterns: ['~/.ssh/**', '~/.aws/**', '$REPO/.env'],
        roots,
      });
      expect(m.isProtected('/root/.ssh/id_rsa')).toBe(true);
      expect(m.isProtected('/root/.aws/credentials')).toBe(true);
      expect(m.isProtected('/work/.env')).toBe(true);
      expect(m.isProtected('/work/src/index.ts')).toBe(false);
    });
  });

  describe('no-match cases', () => {
    it('returns false when no patterns are configured', () => {
      const m = new ProtectedPathsMatcher({ patterns: [], roots });
      expect(m.isProtected('/root/.ssh/id_rsa')).toBe(false);
    });

    it('returns false for paths outside any tokenized root', () => {
      const m = new ProtectedPathsMatcher({ patterns: ['~/.ssh/**'], roots });
      expect(m.isProtected('/etc/passwd')).toBe(false);
    });
  });
});

// ── applyProtectedPathsPolicy ───────────────────────────────────────────────

describe('applyProtectedPathsPolicy', () => {
  const matcher = new ProtectedPathsMatcher({
    patterns: ['~/.ssh/**', '$REPO/.env'],
    roots,
  });

  describe('non-fs events', () => {
    it('passes spawn events through unchanged', () => {
      const ev: AttributedEvent = {
        raw: { kind: 'spawn', argv: ['node'], result: 'ok', pid: 1, ts: 0 },
        pkg: pkgId,
        lifecycle: 'postinstall',
      };
      expect(applyProtectedPathsPolicy(ev, matcher)).toBe(ev);
    });

    it('passes env_read events through unchanged', () => {
      const ev: AttributedEvent = {
        raw: { kind: 'env_read', name: 'HOME', pid: 1, ts: 0, hidden: false },
        pkg: pkgId,
        lifecycle: 'postinstall',
      };
      expect(applyProtectedPathsPolicy(ev, matcher)).toBe(ev);
    });
  });

  describe('successful fs events (no errno)', () => {
    it('passes successful reads through unchanged', () => {
      const ev = readEv('/root/.ssh/id_rsa'); // no errno: syscall succeeded
      expect(applyProtectedPathsPolicy(ev, matcher)).toBe(ev);
    });

    it('passes successful writes through unchanged', () => {
      const ev = writeEv('/work/.env');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBe(ev);
    });
  });

  describe('protected ENOENT reads', () => {
    it('stamps hidden=true and strips errno', () => {
      const ev = readEv('/root/.ssh/id_rsa', 'ENOENT');
      const out = applyProtectedPathsPolicy(ev, matcher);
      expect(out).not.toBeNull();
      expect(out!.raw.kind).toBe('read');
      if (out!.raw.kind === 'read') {
        expect(out!.raw.hidden).toBe(true);
        expect(out!.raw.errno).toBeUndefined();
        expect(out!.raw).not.toHaveProperty('errno'); // truly stripped
      }
    });
  });

  describe('unprotected ENOENT reads', () => {
    it('drops them (preserves existing noise filter)', () => {
      const ev = readEv('/usr/lib/missing.so', 'ENOENT');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });
  });

  describe('protected EACCES reads', () => {
    it('stamps hidden=true and strips errno', () => {
      const ev = readEv('/root/.ssh/id_rsa', 'EACCES');
      const out = applyProtectedPathsPolicy(ev, matcher);
      expect(out).not.toBeNull();
      if (out!.raw.kind === 'read') {
        expect(out!.raw.hidden).toBe(true);
        expect(out!.raw).not.toHaveProperty('errno');
      }
    });
  });

  describe('unprotected EACCES reads', () => {
    it('emits with hidden=false and strips errno', () => {
      const ev = readEv('/etc/shadow', 'EACCES');
      const out = applyProtectedPathsPolicy(ev, matcher);
      expect(out).not.toBeNull();
      if (out!.raw.kind === 'read') {
        expect(out!.raw.hidden).toBe(false);
        expect(out!.raw).not.toHaveProperty('errno');
      }
    });
  });

  describe('protected ENOENT writes', () => {
    it('stamps hidden=true and strips errno', () => {
      const ev = writeEv('/work/.env', 'ENOENT');
      const out = applyProtectedPathsPolicy(ev, matcher);
      expect(out).not.toBeNull();
      if (out!.raw.kind === 'write') {
        expect(out!.raw.hidden).toBe(true);
        expect(out!.raw).not.toHaveProperty('errno');
      }
    });
  });

  describe('unprotected ENOENT writes', () => {
    it('drops them', () => {
      const ev = writeEv('/tmp/some-temp-file', 'ENOENT');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });
  });
});

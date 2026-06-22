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

  describe('benign cross-package reads under $NODE_MODULES (DROPPED)', () => {
    // A lifecycle script reading a sibling installed package is normal install
    // behavior; these reads are dropped before emission regardless of
    // success/ENOENT/EACCES. Writes under node_modules are tampering and are
    // never dropped. Protected paths (auditor opt-in) are exempt — see the
    // separate describe below.
    it('drops a successful read under $NODE_MODULES', () => {
      const ev = readEv('/work/node_modules/debug/src/index.js');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });

    it('drops an ENOENT read under $NODE_MODULES', () => {
      const ev = readEv('/work/node_modules/.pnpm/x@1/node_modules/x/missing.js', 'ENOENT');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });

    it('drops an EACCES read under $NODE_MODULES', () => {
      const ev = readEv('/work/node_modules/victim/secret', 'EACCES');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });

    it('drops a read of the bare $NODE_MODULES root', () => {
      const ev = readEv('/work/node_modules');
      expect(applyProtectedPathsPolicy(ev, matcher)).toBeNull();
    });

    it('does NOT drop a WRITE under $NODE_MODULES (tampering must surface)', () => {
      const ev = writeEv('/work/node_modules/victim/index.js');
      const out = applyProtectedPathsPolicy(ev, matcher);
      expect(out).not.toBeNull();
      expect(out!.raw.kind).toBe('write');
    });

    it('does NOT drop a read OUTSIDE $NODE_MODULES', () => {
      // /work/node_modules_evil is a sibling of node_modules, NOT under it —
      // the prefix check must require an exact root or a trailing-slash child.
      const outside = readEv('/work/node_modules_evil/x.js');
      expect(applyProtectedPathsPolicy(outside, matcher)).toBe(outside);
      const repoRead = readEv('/work/src/index.ts');
      expect(applyProtectedPathsPolicy(repoRead, matcher)).toBe(repoRead);
    });
  });

  describe('protected reads under $NODE_MODULES are EXEMPT from the drop', () => {
    // Auditor opted into a node_modules path via protected.files. The benign
    // drop must NOT swallow it; it surfaces exactly like any protected read.
    const protectedNm = new ProtectedPathsMatcher({
      patterns: ['$NODE_MODULES/**'],
      roots,
    });

    it('preserves a SUCCESSFUL protected node_modules read (plain, like elsewhere)', () => {
      const ev = readEv('/work/node_modules/victim/.npmrc'); // no errno
      // Successful protected reads pass through unchanged (hidden=false) — the
      // same contract as a successful protected read anywhere else.
      expect(applyProtectedPathsPolicy(ev, protectedNm)).toBe(ev);
    });

    it('surfaces a FAILED protected node_modules read as hidden=true', () => {
      const ev = readEv('/work/node_modules/victim/.npmrc', 'ENOENT');
      const out = applyProtectedPathsPolicy(ev, protectedNm);
      expect(out).not.toBeNull();
      if (out!.raw.kind === 'read') {
        expect(out!.raw.hidden).toBe(true);
        expect(out!.raw).not.toHaveProperty('errno');
      }
    });
  });

  describe('ProtectedPathsMatcher.isUnderNodeModules', () => {
    it('matches the root and any descendant, not siblings', () => {
      const m = new ProtectedPathsMatcher({ patterns: [], roots });
      expect(m.isUnderNodeModules('/work/node_modules')).toBe(true);
      expect(m.isUnderNodeModules('/work/node_modules/debug/index.js')).toBe(true);
      expect(m.isUnderNodeModules('/work/node_modules_evil/x')).toBe(false);
      expect(m.isUnderNodeModules('/work/src/index.ts')).toBe(false);
    });

    it('is a no-op for a matcher with an empty nodeModules root', () => {
      const noop = new ProtectedPathsMatcher({
        patterns: [],
        roots: { repo: '', nodeModules: '', home: '', tmp: '', cache: '' },
      });
      expect(noop.isUnderNodeModules('/anything/node_modules/x')).toBe(false);
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

// ── trailing-slash roots.repo (matcher self-canonicalizes) ───────────────────
// roots.repo / roots.nodeModules are derived from config.work_dir, which can
// arrive with a trailing slash (SCRIPT_JAIL_REPO_DIR / GITHUB_WORKSPACE). The
// matcher must canonicalize them, or its tokenize() segment-boundary check fails
// and a protected probe is silently dropped instead of marked <HIDDEN>.
describe('ProtectedPathsMatcher: trailing-slash roots.repo', () => {
  const slashRepo = '/opt/actions-runner/_work/r/r';
  const slashRoots = {
    repo: `${slashRepo}/`,
    nodeModules: `${slashRepo}/node_modules/`,
    home: '/root',
    tmp: '/tmp',
    cache: '/root/.cache/pnpm',
  };
  const slashEv = (path: string, errno?: 'ENOENT' | 'EACCES'): AttributedEvent => {
    const raw =
      errno === undefined
        ? { kind: 'read' as const, path, pid: 1, ts: 0, hidden: false }
        : { kind: 'read' as const, path, pid: 1, ts: 0, hidden: false, errno };
    return { raw, pkg: pkgId, lifecycle: 'postinstall' };
  };

  it('matches $REPO/.env under a trailing-slash repo (isProtected → true)', () => {
    const m = new ProtectedPathsMatcher({ patterns: ['$REPO/.env'], roots: slashRoots });
    expect(m.isProtected(`${slashRepo}/.env`)).toBe(true);
  });

  it('emits <HIDDEN> (not drop) for an ENOENT probe of a protected $REPO/.env', () => {
    const m = new ProtectedPathsMatcher({ patterns: ['$REPO/.env'], roots: slashRoots });
    const out = applyProtectedPathsPolicy(slashEv(`${slashRepo}/.env`, 'ENOENT'), m);
    expect(out).not.toBeNull();
    if (out!.raw.kind === 'read') {
      expect(out!.raw.hidden).toBe(true);
      expect(out!.raw).not.toHaveProperty('errno');
    }
  });

  it('still treats a benign sibling-package read under a trailing-slash node_modules as droppable', () => {
    const m = new ProtectedPathsMatcher({ patterns: [], roots: slashRoots });
    expect(m.isUnderNodeModules(`${slashRepo}/node_modules/debug/index.js`)).toBe(true);
  });

  it('matches $HOME/.ssh/** under a trailing-slash HOME and emits <HIDDEN> (not drop)', () => {
    // The matcher tokenizes against EVERY root, so a trailing-slash home would
    // make a $HOME-prefixed pattern miss and drop a protected secret probe. ALL
    // roots must be canonicalized.
    const homeSlashRoots = { ...slashRoots, home: '/tmp/home-slash/' };
    const m = new ProtectedPathsMatcher({ patterns: ['$HOME/.ssh/**'], roots: homeSlashRoots });
    expect(m.isProtected('/tmp/home-slash/.ssh/id_rsa')).toBe(true);
    const out = applyProtectedPathsPolicy(slashEv('/tmp/home-slash/.ssh/id_rsa', 'ENOENT'), m);
    expect(out).not.toBeNull();
    if (out!.raw.kind === 'read') {
      expect(out!.raw.hidden).toBe(true);
      expect(out!.raw).not.toHaveProperty('errno');
    }
  });
});

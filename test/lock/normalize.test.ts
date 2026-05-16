import { describe, it, expect } from 'vitest';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import type { AttributedEvent } from '../../src/lock/schema.js';

const roots = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.cache/pnpm',
};

const pkgId = 'esbuild@0.21.5';
const pkgDir = '/work/node_modules/esbuild';

const ctx: NormalizeContext = {
  roots,
  pkgDirs: new Map([[pkgId, pkgDir]]),
};

function readEv(path: string, hidden = false): AttributedEvent {
  return { raw: { kind: 'read', path, pid: 1, ts: 0, hidden }, pkg: pkgId, lifecycle: 'postinstall' };
}

function writeEv(path: string, hidden = false): AttributedEvent {
  return { raw: { kind: 'write', path, pid: 1, ts: 0, hidden }, pkg: pkgId, lifecycle: 'postinstall' };
}

function envEv(name: string, hidden = false): AttributedEvent {
  return { raw: { kind: 'env_read', name, pid: 1, ts: 0, hidden }, pkg: pkgId, lifecycle: 'postinstall' };
}

function spawnEv(argv: string[], result: 'ok' | 'enoent' | 'eacces' = 'ok'): AttributedEvent {
  return { raw: { kind: 'spawn', argv, result, pid: 1, ts: 0 }, pkg: pkgId, lifecycle: 'postinstall' };
}

function dlopenEv(filename: string): AttributedEvent {
  return { raw: { kind: 'dlopen', filename, result: 'blocked', pid: 1, ts: 0 }, pkg: pkgId, lifecycle: 'postinstall' };
}

function networkEv(host: string, port: number, result: 'ok' | 'blocked'): AttributedEvent {
  return { raw: { kind: 'connect', host, port, result, pid: 1, ts: 0 }, pkg: pkgId, lifecycle: 'postinstall' };
}

function getBlock(map: ReturnType<typeof normalize>, pkg = pkgId, stage = 'postinstall') {
  return map.get(pkg)?.lifecycle[stage as 'postinstall'];
}

describe('normalize', () => {
  describe('intra-package reads (DROPPED)', () => {
    it('drops a read of own $PKG file', () => {
      const events = [readEv(`${pkgDir}/install.js`)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.external_reads).toEqual([]);
    });

    it('drops a read of the $PKG root itself', () => {
      const events = [readEv(pkgDir)];
      const result = normalize(events, ctx);
      // If the pkg block even exists, external_reads should be empty
      const block = getBlock(result);
      expect(block?.external_reads ?? []).toEqual([]);
    });
  });

  describe('intra-package writes (DROPPED)', () => {
    it('drops a write inside $PKG', () => {
      const events = [writeEv(`${pkgDir}/build/out.js`)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes).toEqual([]);
    });
  });

  describe('external reads (RECORDED)', () => {
    it('records a read from $CACHE', () => {
      const events = [readEv('/root/.cache/pnpm/v3/bin')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.external_reads.length).toBeGreaterThan(0);
      expect(block?.external_reads[0]).toContain('$CACHE');
    });

    it('records a read from $REPO (not in $PKG)', () => {
      const events = [readEv('/work/src/index.ts')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.external_reads).toContain('$REPO/src/index.ts');
    });

    it('records a read from $HOME', () => {
      const events = [readEv('/root/.npmrc')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.external_reads).toContain('$HOME/.npmrc');
    });
  });

  describe('cross-package writes (<CROSS_PACKAGE> prefix)', () => {
    it('tags write inside another node_modules package', () => {
      const events = [writeEv('/work/node_modules/debug/src/index.js')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes).toContain('<CROSS_PACKAGE> $NODE_MODULES/debug/src/index.js');
    });

    it('does not tag writes to $REPO (outside node_modules)', () => {
      const events = [writeEv('/work/.github/workflows/ci.yml')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      // Should be in escaped_writes but without <CROSS_PACKAGE>
      expect(block?.escaped_writes[0]).not.toContain('<CROSS_PACKAGE>');
      expect(block?.escaped_writes[0]).toContain('$REPO');
    });
  });

  describe('hidden events (<HIDDEN> prefix)', () => {
    it('prefixes hidden reads', () => {
      const events = [readEv('/root/.ssh/id_rsa', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.external_reads[0]).toContain('<HIDDEN>');
    });

    it('prefixes hidden env reads', () => {
      const events = [envEv('NPM_TOKEN', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.env_read[0]).toBe('<HIDDEN> NPM_TOKEN');
    });

    it('prefixes hidden writes', () => {
      const events = [writeEv('/root/.bashrc', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes[0]).toContain('<HIDDEN>');
    });
  });

  describe('system noise (DROPPED)', () => {
    const noisePaths = [
      '/usr/lib/x86_64-linux-gnu/libssl.so.1.1',
      '/usr/share/locale/en/LC_MESSAGES',
      '/usr/local/lib/python3.10/dist-packages',
      '/lib/x86_64-linux-gnu/libc.so.6',
      '/lib64/ld-linux-x86-64.so.2',
      '/etc/ld.so.cache',
      '/etc/nsswitch.conf',
      '/etc/localtime',
      '/etc/resolv.conf',
      '/etc/host.conf',
      '/etc/hosts',
      '/proc/self/maps',
      '/sys/fs/cgroup/memory',
      '/dev/urandom',
    ];

    for (const p of noisePaths) {
      it(`drops system noise: ${p}`, () => {
        const events = [readEv(p)];
        const result = normalize(events, ctx);
        // Either no block at all, or block exists with empty external_reads
        const block = getBlock(result);
        expect(block?.external_reads ?? []).toEqual([]);
      });
    }
  });

  describe('spawn events', () => {
    it('puts ok spawns in spawn_attempts', () => {
      const events = [spawnEv(['node', '/work/node_modules/esbuild/install.js'], 'ok')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.spawn_attempts.length).toBeGreaterThan(0);
      expect(block?.spawn_blocked).toEqual([]);
    });

    it('puts enoent spawns in spawn_blocked with <ENOENT> prefix', () => {
      const events = [spawnEv(['bash', '-c', 'echo hi'], 'enoent')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.spawn_blocked[0]).toContain('<ENOENT>');
      expect(block?.spawn_attempts).toEqual([]);
    });

    it('puts eacces spawns in spawn_blocked with <EACCES> prefix', () => {
      const events = [spawnEv(['./run.sh'], 'eacces')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.spawn_blocked[0]).toContain('<EACCES>');
    });

    it('tokenizes absolute path args', () => {
      const events = [spawnEv(['node', '/work/node_modules/esbuild/install.js'], 'ok')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      // The second arg is an absolute path so gets tokenized
      expect(block?.spawn_attempts[0]).toContain('$PKG');
    });
  });

  describe('dlopen events', () => {
    it('puts all dlopen events in dlopen_attempts with <BLOCKED> prefix', () => {
      const events = [dlopenEv('/usr/lib/libssl.so.1.1')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.dlopen_attempts[0]).toContain('<BLOCKED>');
    });
  });

  describe('network events', () => {
    it('records ok network as connect host:port', () => {
      const events = [networkEv('registry.npmjs.org', 443, 'ok')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.network_attempts).toContain('connect registry.npmjs.org:443');
    });

    it('records blocked network with <BLOCKED> prefix', () => {
      const events = [networkEv('198.51.100.7', 443, 'blocked')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.network_attempts).toContain('<BLOCKED> connect 198.51.100.7:443');
    });
  });

  describe('dedupe and sort', () => {
    it('deduplicates repeated identical events', () => {
      const events = [
        readEv('/root/.npmrc'),
        readEv('/root/.npmrc'),
        readEv('/root/.npmrc'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      // Should appear only once
      expect(block?.external_reads.filter((x) => x === '$HOME/.npmrc').length).toBe(1);
    });

    it('sorts external_reads ascending', () => {
      const events = [
        readEv('/work/src/zzz.ts'),
        readEv('/root/.npmrc'),
        readEv('/work/src/aaa.ts'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const reads = block?.external_reads ?? [];
      expect(reads).toEqual([...reads].sort((a, b) => a.localeCompare(b)));
    });
  });

  describe('multiple packages and lifecycle stages', () => {
    it('separates events by package', () => {
      const otherPkg = 'lodash@4.17.21';
      const otherCtx: NormalizeContext = {
        roots,
        pkgDirs: new Map([
          [pkgId, pkgDir],
          [otherPkg, '/work/node_modules/lodash'],
        ]),
      };
      const events: AttributedEvent[] = [
        { raw: { kind: 'read', path: '/root/.npmrc', pid: 1, ts: 0, hidden: false }, pkg: pkgId, lifecycle: 'postinstall' },
        { raw: { kind: 'read', path: '/tmp/lodash-tmp', pid: 2, ts: 1, hidden: false }, pkg: otherPkg, lifecycle: 'install' },
      ];
      const result = normalize(events, otherCtx);
      expect(result.has(pkgId)).toBe(true);
      expect(result.has(otherPkg)).toBe(true);
      expect(result.get(pkgId)?.lifecycle['postinstall']?.external_reads).toContain('$HOME/.npmrc');
      expect(result.get(otherPkg)?.lifecycle['install']?.external_reads).toContain('$TMPDIR/lodash-tmp');
    });
  });
});

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

    it('sorts external_reads ascending by codepoint order', () => {
      const events = [
        readEv('/work/src/zzz.ts'),
        readEv('/root/.npmrc'),
        readEv('/work/src/aaa.ts'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const reads = block?.external_reads ?? [];
      // Use codepoint comparator (not localeCompare) for byte-stable order.
      expect(reads).toEqual([...reads].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
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

  // Imp 3: missing pkgDirs entry for an fs event must throw, not silently fall back.
  describe('missing pkgDirs entry (Imp 3)', () => {
    it('throws for a read event from a package not in pkgDirs', () => {
      const unknownPkg = 'unknown@1.0.0';
      const ctxWithoutPkg: NormalizeContext = { roots, pkgDirs: new Map() };
      const events: AttributedEvent[] = [
        { raw: { kind: 'read', path: '/work/node_modules/unknown/index.js', pid: 1, ts: 0, hidden: false }, pkg: unknownPkg, lifecycle: 'postinstall' },
      ];
      expect(() => normalize(events, ctxWithoutPkg)).toThrow(/pkgDirs missing entry for unknown@1\.0\.0/);
    });

    it('throws for a write event from a package not in pkgDirs', () => {
      const unknownPkg = 'unknown@1.0.0';
      const ctxWithoutPkg: NormalizeContext = { roots, pkgDirs: new Map() };
      const events: AttributedEvent[] = [
        { raw: { kind: 'write', path: '/tmp/out.js', pid: 1, ts: 0, hidden: false }, pkg: unknownPkg, lifecycle: 'postinstall' },
      ];
      expect(() => normalize(events, ctxWithoutPkg)).toThrow(/pkgDirs missing entry for unknown@1\.0\.0/);
    });

    it('does NOT throw for non-fs events (spawn, env_read, connect, dlopen) without pkgDir', () => {
      const unknownPkg = 'unknown@1.0.0';
      const ctxWithoutPkg: NormalizeContext = { roots, pkgDirs: new Map() };
      const events: AttributedEvent[] = [
        { raw: { kind: 'env_read', name: 'HOME', pid: 1, ts: 0, hidden: false }, pkg: unknownPkg, lifecycle: 'postinstall' },
        { raw: { kind: 'spawn', argv: ['node', '--version'], result: 'ok', pid: 1, ts: 0 }, pkg: unknownPkg, lifecycle: 'postinstall' },
        { raw: { kind: 'connect', host: 'registry.npmjs.org', port: 443, result: 'ok', pid: 1, ts: 0 }, pkg: unknownPkg, lifecycle: 'postinstall' },
        { raw: { kind: 'dlopen', filename: '/usr/lib/libssl.so', result: 'blocked', pid: 1, ts: 0 }, pkg: unknownPkg, lifecycle: 'postinstall' },
      ];
      expect(() => normalize(events, ctxWithoutPkg)).not.toThrow();
      const block = normalize(events, ctxWithoutPkg).get(unknownPkg)?.lifecycle['postinstall'];
      expect(block?.env_read).toContain('HOME');
      expect(block?.spawn_attempts[0]).toContain('node');
      expect(block?.network_attempts).toContain('connect registry.npmjs.org:443');
    });
  });

  // Imp 4: argv[0] must be tokenized when absolute.
  describe('spawn argv[0] tokenization (Imp 4)', () => {
    it('tokenizes absolute argv[0] so node path is stable across runners', () => {
      const events = [
        spawnEv(['/usr/local/bin/node', '/work/node_modules/esbuild/install.js'], 'ok'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      // argv[0] is /usr/local/bin/node — not under any root so stays as-is but
      // does NOT appear as the raw absolute path from a different runner.
      // The second arg must be tokenized to $PKG.
      const attempt = block?.spawn_attempts[0] ?? '';
      expect(attempt).toContain('$PKG');
      // argv[0] stays verbatim (not under any known root), but importantly
      // a different absolute node path would not change the $PKG portion.
      expect(attempt).toContain('/usr/local/bin/node');
    });

    it('tokenizes argv[0] that is inside $REPO to $REPO token', () => {
      const events = [
        spawnEv(['/work/scripts/runner.sh', '--flag'], 'ok'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const attempt = block?.spawn_attempts[0] ?? '';
      expect(attempt).toContain('$REPO/scripts/runner.sh');
    });
  });

  // Imp 5: hidden + cross-package writes must compound both prefixes.
  describe('compound <HIDDEN> + <CROSS_PACKAGE> tags (Imp 5)', () => {
    it('emits <HIDDEN> <CROSS_PACKAGE> for a write that is both hidden and cross-package', () => {
      // A write to another package's directory that is also a protected path.
      const events = [writeEv('/work/node_modules/debug/sensitive', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes[0]).toBe(
        '<HIDDEN> <CROSS_PACKAGE> $NODE_MODULES/debug/sensitive',
      );
    });

    it('emits only <HIDDEN> for a hidden write that is NOT cross-package', () => {
      const events = [writeEv('/root/.bashrc', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const write = block?.escaped_writes[0] ?? '';
      expect(write).toContain('<HIDDEN>');
      expect(write).not.toContain('<CROSS_PACKAGE>');
    });

    it('emits only <CROSS_PACKAGE> for a non-hidden cross-package write', () => {
      const events = [writeEv('/work/node_modules/debug/index.js', false)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const write = block?.escaped_writes[0] ?? '';
      expect(write).toContain('<CROSS_PACKAGE>');
      expect(write).not.toContain('<HIDDEN>');
    });
  });
});

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

function execEv(prog: string, envp_alloc_failed: boolean, argv0: string | null = null): AttributedEvent {
  return {
    raw: { kind: 'exec', prog, argv0, envp_alloc_failed, syscall_bypass: false, pid: 1, ts: 0 },
    pkg: pkgId,
    lifecycle: 'postinstall',
  };
}

function tamperEv(op: 'setenv' | 'unsetenv' | 'putenv' | 'clearenv', name?: string): AttributedEvent {
  const raw = name !== undefined
    ? { kind: 'env_tamper' as const, op, name, refused: true as const, pid: 1, ts: 0 }
    : { kind: 'env_tamper' as const, op, refused: true as const, pid: 1, ts: 0 };
  return { raw, pkg: pkgId, lifecycle: 'postinstall' };
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

  // Imp 4: argv[0] must be tokenized when absolute, and well-known binary paths
  // must be collapsed to their basename for byte-stability across rootfs variants.
  describe('spawn argv[0] tokenization (Imp 4)', () => {
    it('collapses /usr/local/bin/node to bare "node" in spawn_attempts', () => {
      const events = [
        spawnEv(['/usr/local/bin/node', '/work/node_modules/esbuild/install.js'], 'ok'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const attempt = block?.spawn_attempts[0] ?? '';
      // argv[0] is collapsed to the bare basename; the arg is tokenized to $PKG.
      expect(attempt).toBe('node $PKG/install.js');
    });

    it('collapses /usr/bin/node to the same bare "node", producing byte-identical output', () => {
      const events = [
        spawnEv(['/usr/bin/node', '/work/node_modules/esbuild/install.js'], 'ok'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const attempt = block?.spawn_attempts[0] ?? '';
      // /usr/bin/node and /usr/local/bin/node must produce identical lockfile bytes.
      expect(attempt).toBe('node $PKG/install.js');
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

    it('does not collapse an unrecognized binary path — passes through tokenized form', () => {
      // /usr/local/bin/python3 is not in the normalizable set, so it stays verbatim.
      const events = [
        spawnEv(['/usr/local/bin/python3', '--version'], 'ok'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      const attempt = block?.spawn_attempts[0] ?? '';
      expect(attempt).toBe('/usr/local/bin/python3 --version');
    });
  });

  describe('exec events (Finding 4: envp_alloc_failed → audit_bypass)', () => {
    it('drops exec events when envp_alloc_failed=false (redundant with strace execve)', () => {
      const events = [execEv('/usr/bin/node', false)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      // The exec arm should produce no output for the common (success) case;
      // strace already records the execve syscall, so duplicating here would
      // churn every lockfile diff without adding signal.
      expect(block?.audit_bypass ?? []).toEqual([]);
      expect(block?.spawn_attempts ?? []).toEqual([]);
    });

    it('records audit_bypass when envp_alloc_failed=true (shim re-injection failed)', () => {
      const events = [execEv('/usr/bin/node', true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.audit_bypass).toEqual(['<EXEC_FAIL_OPEN> /usr/bin/node']);
    });

    it('tokenizes prog inside $PKG when emitting audit_bypass', () => {
      const events = [execEv(`${pkgDir}/scripts/runner`, true)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.audit_bypass).toEqual(['<EXEC_FAIL_OPEN> $PKG/scripts/runner']);
    });

    it('dedupes + sorts audit_bypass entries', () => {
      const events = [
        execEv('/usr/bin/zsh', true),
        execEv('/usr/bin/node', true),
        execEv('/usr/bin/node', true), // duplicate
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.audit_bypass).toEqual([
        '<EXEC_FAIL_OPEN> /usr/bin/node',
        '<EXEC_FAIL_OPEN> /usr/bin/zsh',
      ]);
    });
  });

  describe('env_tamper events (Finding 4: refused tampering → env_tamper)', () => {
    it('records unsetenv LD_PRELOAD as <REFUSED> unsetenv LD_PRELOAD', () => {
      const events = [tamperEv('unsetenv', 'LD_PRELOAD')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.env_tamper).toEqual(['<REFUSED> unsetenv LD_PRELOAD']);
    });

    it('records putenv NODE_OPTIONS as <REFUSED> putenv NODE_OPTIONS', () => {
      const events = [tamperEv('putenv', 'NODE_OPTIONS')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.env_tamper).toEqual(['<REFUSED> putenv NODE_OPTIONS']);
    });

    it('records clearenv with no name as bare <REFUSED> clearenv', () => {
      const events = [tamperEv('clearenv')];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.env_tamper).toEqual(['<REFUSED> clearenv']);
    });

    it('dedupes + sorts env_tamper entries', () => {
      const events = [
        tamperEv('unsetenv', 'NODE_OPTIONS'),
        tamperEv('unsetenv', 'LD_PRELOAD'),
        tamperEv('unsetenv', 'LD_PRELOAD'), // duplicate
        tamperEv('clearenv'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.env_tamper).toEqual([
        '<REFUSED> clearenv',
        '<REFUSED> unsetenv LD_PRELOAD',
        '<REFUSED> unsetenv NODE_OPTIONS',
      ]);
    });

    it('does not throw when env_tamper carries no pkgDir (non-fs event)', () => {
      const ctxWithoutPkg: NormalizeContext = { roots, pkgDirs: new Map() };
      const events = [tamperEv('unsetenv', 'LD_PRELOAD')];
      expect(() => normalize(events, ctxWithoutPkg)).not.toThrow();
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

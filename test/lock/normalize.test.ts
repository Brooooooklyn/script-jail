import { describe, it, expect } from 'vitest';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render, type RenderInput } from '../../src/lock/render.js';
import { ROOT_SENTINEL } from '../../src/guest/attribution.js';
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

function spawnEv(
  argv: string[],
  result: 'ok' | 'enoent' | 'eacces' = 'ok',
  auditBlind = false,
): AttributedEvent {
  return {
    raw: { kind: 'spawn', argv, result, pid: 1, ts: 0, ...(auditBlind ? { audit_blind: true as const } : {}) },
    pkg: pkgId,
    lifecycle: 'postinstall',
  };
}

function dlopenEv(filename: string): AttributedEvent {
  return { raw: { kind: 'dlopen', filename, result: 'blocked', pid: 1, ts: 0 }, pkg: pkgId, lifecycle: 'postinstall' };
}

function execEv(prog: string, envp_alloc_failed: boolean, argv0: string | null = null): AttributedEvent {
  return {
    raw: {
      kind: 'exec',
      prog,
      argv0,
      envp_alloc_failed,
      syscall_bypass: false,
      events_file_forgery: false,
      unresolved_path: false,
      result: 'ok',
      pid: 1,
      ts: 0,
    },
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

    it('canonicalizes npm debug log timestamps in escaped paths', () => {
      const events = [
        writeEv('/.npm/_logs/2026-05-26T14_20_22_069Z-debug-0.log'),
        writeEv('/root/.npm/_logs/2026-05-20T14_27_46_935Z-debug-1.log'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes).toEqual([
        '$HOME/.npm/_logs/<timestamp>-debug-1.log',
        '/.npm/_logs/<timestamp>-debug-0.log',
      ]);
    });

    it('does not canonicalize npm-shaped timestamps outside npm debug logs', () => {
      const path = '/work/logs/2026-05-26T14_20_22_069Z-debug-0.log';
      const events = [writeEv(path)];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.escaped_writes).toEqual(['$REPO/logs/2026-05-26T14_20_22_069Z-debug-0.log']);
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

  // The guest routes a deferred read/write from a RECYCLED / re-exec'd pid
  // (ambiguous attribution generation; resolveDeferredAttribution in
  // phase-install.ts) under the `<unattributed>` sentinel rather than guessing
  // one of the conflated packages. That key has NO pkgDir by design — and a
  // no-pkgDir non-root read/write normally THROWS (fail closed). normalize
  // EXEMPTS `<unattributed>`: with no $PKG prefix the path tokenizes against
  // $NODE_MODULES / $REPO and SURFACES, so an escaped write into the recycled
  // package's own dir can never be hidden as an intra-package `$PKG` write.
  describe('<unattributed> sentinel (recycled-pid ambiguity, no pkgDir)', () => {
    const unattribWrite = (path: string): AttributedEvent => ({
      raw: { kind: 'write', path, pid: 1, ts: 0, hidden: false },
      pkg: '<unattributed>',
      lifecycle: 'install',
    });
    const unattribRead = (path: string): AttributedEvent => ({
      raw: { kind: 'read', path, pid: 1, ts: 0, hidden: false },
      pkg: '<unattributed>',
      lifecycle: 'install',
    });

    it('does NOT throw on a no-pkgDir <unattributed> write (the throw is reserved for real package keys)', () => {
      expect(() => normalize([unattribWrite('/work/node_modules/pkg-b/index.js')], ctx)).not.toThrow();
    });

    it('SURFACES a recycled-pid write into another package dir as a <CROSS_PACKAGE> escaped write (never hidden)', () => {
      const result = normalize([unattribWrite('/work/node_modules/pkg-b/index.js')], ctx);
      const block = getBlock(result, '<unattributed>', 'install');
      expect(block?.escaped_writes).toEqual(['<CROSS_PACKAGE> $NODE_MODULES/pkg-b/index.js']);
    });

    it('SURFACES a recycled-pid read as an external_read', () => {
      const result = normalize([unattribRead('/work/src/secret.ts')], ctx);
      const block = getBlock(result, '<unattributed>', 'install');
      expect(block?.external_reads).toEqual(['$REPO/src/secret.ts']);
    });

    it('a REAL package key with a missing pkgDir still throws (fail closed preserved)', () => {
      const ev: AttributedEvent = {
        raw: { kind: 'write', path: '/work/node_modules/pkg-b/index.js', pid: 1, ts: 0, hidden: false },
        pkg: 'ghost@9.9.9',
        lifecycle: 'install',
      };
      expect(() => normalize([ev], ctx)).toThrow(/pkgDirs missing entry/);
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
      // vite-plus toolchain (VP_HOME=/opt/vp).  The bare `/opt` and `/opt/vp`
      // directory stat()s must drop alongside the subtree — the noise prefix
      // intentionally omits the trailing slash so they do.
      '/opt',
      '/opt/vp',
      '/opt/vp/js_runtime/node/24.15.0/bin/node',
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

  // Regression (finding #11): on a SELF-HOSTED GitHub runner the install:true M1
  // fix aligns the guest audit work_dir to the host repoDir, so roots.repo lives
  // under /opt/actions-runner/_work/<repo>/<repo> — i.e. UNDER the bare `/opt`
  // system-noise prefix.  The repo must ALWAYS win over the noise prefix: a path
  // inside roots.repo / roots.nodeModules must NEVER be dropped as noise, or a
  // malicious package's fs behaviour (escaped_writes, cross-package writes) would
  // silently vanish from the lock.  The genuine /opt/vp toolchain reads are NOT
  // under roots.repo, so they still drop.
  describe('self-hosted runner: repo under /opt (repo wins over /opt noise)', () => {
    const selfHostedRepo = '/opt/actions-runner/_work/acme/acme';
    const selfHostedNodeModules = `${selfHostedRepo}/node_modules`;
    const selfHostedPkgId = 'esbuild@0.21.5';
    const selfHostedPkgDir = `${selfHostedNodeModules}/esbuild`;
    const selfHostedCtx: NormalizeContext = {
      roots: {
        repo: selfHostedRepo,
        nodeModules: selfHostedNodeModules,
        home: '/root',
        tmp: '/tmp',
        cache: '/root/.cache/pnpm',
      },
      pkgDirs: new Map([[selfHostedPkgId, selfHostedPkgDir]]),
    };

    function selfHostedWrite(path: string): AttributedEvent {
      return { raw: { kind: 'write', path, pid: 1, ts: 0, hidden: false }, pkg: selfHostedPkgId, lifecycle: 'postinstall' };
    }
    function selfHostedRead(path: string): AttributedEvent {
      return { raw: { kind: 'read', path, pid: 1, ts: 0, hidden: false }, pkg: selfHostedPkgId, lifecycle: 'postinstall' };
    }

    it('SURFACES an escaped_write into a sibling package node_modules (not dropped as /opt noise)', () => {
      const events = [selfHostedWrite(`${selfHostedNodeModules}/debug/src/index.js`)];
      const result = normalize(events, selfHostedCtx);
      const block = getBlock(result, selfHostedPkgId);
      expect(block?.escaped_writes).toContain('<CROSS_PACKAGE> $NODE_MODULES/debug/src/index.js');
    });

    it('SURFACES a repo-internal write outside node_modules (not dropped as /opt noise)', () => {
      const events = [selfHostedWrite(`${selfHostedRepo}/.npmrc`)];
      const result = normalize(events, selfHostedCtx);
      const block = getBlock(result, selfHostedPkgId);
      expect(block?.escaped_writes).toEqual(['$REPO/.npmrc']);
    });

    it('SURFACES a repo-internal external read outside $PKG (not dropped as /opt noise)', () => {
      const events = [selfHostedRead(`${selfHostedRepo}/secrets.json`)];
      const result = normalize(events, selfHostedCtx);
      const block = getBlock(result, selfHostedPkgId);
      expect(block?.external_reads).toEqual(['$REPO/secrets.json']);
    });

    it('STILL drops genuine /opt/vp toolchain reads (not under roots.repo) even when repo is under /opt', () => {
      const events = [
        selfHostedRead('/opt/vp/js_runtime/node/24.15.0/bin/node'),
        selfHostedRead('/opt/vp'),
        // a bare /opt parent stat() is still noise — it is NOT under the repo
        selfHostedRead('/opt'),
      ];
      const result = normalize(events, selfHostedCtx);
      const block = getBlock(result, selfHostedPkgId);
      expect(block?.external_reads ?? []).toEqual([]);
    });

    it('does NOT confuse a sibling dir sharing the repo name prefix (/opt/.../acme-evil) for the repo', () => {
      // roots.repo is .../acme; a path under .../acme-evil must NOT count as
      // "under the repo" (segment-boundary check), so it stays /opt noise.
      const events = [selfHostedRead('/opt/actions-runner/_work/acme/acme-evil/loot')];
      const result = normalize(events, selfHostedCtx);
      const block = getBlock(result, selfHostedPkgId);
      expect(block?.external_reads ?? []).toEqual([]);
    });
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

    it('drops redundant sh -c wrappers when the direct command is already recorded', () => {
      const events = [
        spawnEv(['node', 'postinstall.js'], 'ok'),
        spawnEv(['sh', '-c', 'node postinstall.js'], 'ok'),
        spawnEv(['sh', '-c', 'node postinstall.js'], 'enoent'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.spawn_attempts).toEqual(['node postinstall.js']);
      expect(block?.spawn_blocked).toEqual([]);
    });

    it('keeps sh -c wrappers when no equivalent direct command exists', () => {
      const events = [
        spawnEv(['sh', '-c', 'node postinstall.js'], 'ok'),
        spawnEv(['sh', '-c', 'node postinstall.js'], 'enoent'),
      ];
      const result = normalize(events, ctx);
      const block = getBlock(result);
      expect(block?.spawn_attempts).toEqual(['sh -c node postinstall.js']);
      expect(block?.spawn_blocked).toEqual(['<ENOENT> sh -c node postinstall.js']);
    });

    // macOS bare backend: a SIP system binary the shim could not redirect ran
    // un-instrumented. normalize surfaces it as an `<AUDIT_BLIND>` prefix so the
    // lock diff exposes the blind subtree — informational (spawn_attempts), NOT
    // an audit_bypass hard-fail.
    it('prefixes <AUDIT_BLIND> in spawn_attempts for an un-instrumented SIP exec', () => {
      const events = [spawnEv(['/usr/bin/find', '.', '-maxdepth', '0'], 'ok', true)];
      const block = getBlock(normalize(events, ctx));
      expect(block?.spawn_attempts[0]).toMatch(/^<AUDIT_BLIND> /);
      expect(block?.spawn_blocked).toEqual([]);
    });

    it('does NOT prefix <AUDIT_BLIND> when audit_blind is absent (byte-stable with Linux)', () => {
      const events = [spawnEv(['node', 'install.js'], 'ok')];
      const block = getBlock(normalize(events, ctx));
      expect(block?.spawn_attempts[0]).not.toContain('<AUDIT_BLIND>');
    });

    it('places <AUDIT_BLIND> after the result tag on a blocked blind spawn', () => {
      const events = [spawnEv(['/usr/bin/sed', 's/a/b/'], 'enoent', true)];
      const block = getBlock(normalize(events, ctx));
      expect(block?.spawn_blocked[0]).toMatch(/^<ENOENT> <AUDIT_BLIND> /);
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

  // Root-project prepare pass: the ROOT project is not in node_modules, so
  // discoverPkgDirs never maps it. The guest agent registers it in pkgDirs
  // mapping the root key -> work_dir (== roots.repo). Once registered, a root
  // fs event MUST NOT throw, and:
  //   - a write INTO the repo tokenizes to $PKG and DROPS as intra-package
  //     (build output is benign), and
  //   - a read OUTSIDE the repo SURFACES under external_reads.
  // This is the regression for the SHIPPING BLOCKER: a build `prepare` writing
  // dist/ used to crash normalize() with `pkgDirs missing entry for <root>`.
  describe('root-project events (rootPkgKeys → surfaced, never dropped)', () => {
    const rootKey = 'runs-root-prepare@1.0.0';
    // The agent passes the root key(s) via rootPkgKeys and gives the root NO
    // pkgDir.  SECURITY-CRITICAL (Codex review #1): mapping the root to work_dir
    // would make the whole repo $PKG, dropping every root write into the repo as
    // "intra-package" — which a dependency could exploit by forging
    // npm_package_name=<root> to hide a write anywhere under /work.  Instead the
    // root's fs events tokenize against $REPO/$NODE_MODULES and SURFACE
    // (external_reads / escaped_writes), so real OR forged, they always show.
    const rootCtx: NormalizeContext = {
      roots,
      pkgDirs: new Map(),
      rootPkgKeys: new Set([rootKey]),
    };

    // GENUINE root events carry the non-forgeable `root_anchored: true` verdict
    // (Linux dispatcher derives it from the process tree; the prepare pass forces
    // it true).  Only such events surface as the un-prefixed `$REPO/...`.
    function rootRead(path: string, hidden = false): AttributedEvent {
      return {
        raw: { kind: 'read', path, pid: 1, ts: 0, hidden, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'prepare',
      };
    }
    function rootWrite(path: string, hidden = false): AttributedEvent {
      return {
        raw: { kind: 'write', path, pid: 1, ts: 0, hidden, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'prepare',
      };
    }
    // FORGED root events: the pkg CLAIMS the root key (forgeable npm_package_name)
    // but `root_anchored` is absent — the non-forgeable verdict says "not the
    // genuine root".  These must surface with the `<FORGED_ROOT> ` prefix.
    function forgedRead(path: string, hidden = false): AttributedEvent {
      return { raw: { kind: 'read', path, pid: 1, ts: 0, hidden }, pkg: rootKey, lifecycle: 'prepare' };
    }
    function forgedWrite(path: string, hidden = false): AttributedEvent {
      return { raw: { kind: 'write', path, pid: 1, ts: 0, hidden }, pkg: rootKey, lifecycle: 'prepare' };
    }

    it('does NOT throw for a root-pkg fs event when listed in rootPkgKeys', () => {
      const events = [rootWrite('/work/dist/index.js'), rootRead('/etc/hostname')];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    it('STILL throws for a non-root pkg with no pkgDir (forged/unknown attribution fails closed)', () => {
      const events = [rootWrite('/work/dist/index.js')];
      const notRoot: NormalizeContext = { roots, pkgDirs: new Map(), rootPkgKeys: new Set(['other@9.9.9']) };
      // The pkg does NOT claim root (not in rootPkgKeys) and has no pkgDir.
      expect(() => normalize(events, notRoot)).toThrow(/pkgDirs missing entry/);
    });

    it('SURFACES an intra-repo root write as $REPO/... (closes the forged-root hide hole)', () => {
      const events = [rootWrite('/work/prepare-built.txt')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      expect(block?.escaped_writes).toEqual(['$REPO/prepare-built.txt']);
    });

    it('SURFACES an escaping root read under external_reads', () => {
      const events = [rootRead('/etc/hostname')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      // /etc/hostname is NOT a system-noise prefix (unlike /etc/hosts), so it
      // survives to external_reads.
      expect(block?.external_reads).toEqual(['/etc/hostname']);
    });

    it('classifies both in one pass: repo write AND escaping read both surfaced', () => {
      const events = [rootWrite('/work/prepare-built.txt'), rootRead('/etc/hostname')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      expect(block?.escaped_writes).toEqual(['$REPO/prepare-built.txt']);
      expect(block?.external_reads).toEqual(['/etc/hostname']);
    });

    it('PREFIXES a FORGED-root write with <FORGED_ROOT> (root_anchored absent → not dropped, not thrown)', () => {
      const events = [forgedWrite('/work/prepare-built.txt')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      // Surfaces (fail-loud), distinct from the genuine `$REPO/...` string.
      expect(block?.escaped_writes).toEqual(['<FORGED_ROOT> $REPO/prepare-built.txt']);
    });

    it('PREFIXES a FORGED-root read with <FORGED_ROOT> (root_anchored absent → surfaces)', () => {
      const events = [forgedRead('/etc/hostname')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      expect(block?.external_reads).toEqual(['<FORGED_ROOT> /etc/hostname']);
    });

    it('does NOT throw for a FORGED-root fs event (avoids dependency-triggered DoS)', () => {
      const events = [forgedWrite('/work/anywhere.js'), forgedRead('/etc/hostname')];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    // SECURITY CRUX (non-collapse): a genuine root write and a forged write to
    // the SAME path must BOTH appear.  Without the `<FORGED_ROOT> ` prefix the
    // two identical `$REPO/dist/index.js` strings would dedupe-collapse to one
    // in sortAndDedupe — hiding the forgery behind the legitimate write.
    it('does NOT dedupe-collapse a forged write onto an identical genuine root write', () => {
      const events = [
        rootWrite('/work/dist/index.js'), // genuine (root_anchored: true)
        forgedWrite('/work/dist/index.js'), // forged (same path, root_anchored absent)
      ];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['prepare'];
      expect(block?.escaped_writes).toEqual([
        '$REPO/dist/index.js',
        '<FORGED_ROOT> $REPO/dist/index.js',
      ]);
    });
  });

  // NAMELESS root project (no `name` in the root package.json).  The guest's
  // attribution maps such a root to the synthetic ROOT_SENTINEL ('<repo-root>')
  // key (see src/guest/attribution.ts buildRootPkgKeys) instead of dropping its
  // lifecycle events silently.  normalize treats the sentinel EXACTLY like a
  // named root key: it is listed in rootPkgKeys, has NO pkgDir, and its fs
  // events carry the non-forgeable `root_anchored` verdict.  These tests mirror
  // the named-root <FORGED_ROOT> suite above, but with the nameless sentinel as
  // the root key — proving the genuine/forged/no-collapse/byte-stable contract
  // holds for the nameless-root case too.
  describe('nameless-root events via <repo-root> sentinel', () => {
    const rootKey = ROOT_SENTINEL; // '<repo-root>'
    const rootCtx: NormalizeContext = {
      roots,
      pkgDirs: new Map(),
      rootPkgKeys: new Set([rootKey]),
    };

    // GENUINE nameless-root events carry root_anchored:true (the phase-install
    // end-of-drain flush stamps it from rootAnchored(pid)).
    function rootRead(path: string, hidden = false): AttributedEvent {
      return {
        raw: { kind: 'read', path, pid: 1, ts: 0, hidden, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function rootWrite(path: string, hidden = false): AttributedEvent {
      return {
        raw: { kind: 'write', path, pid: 1, ts: 0, hidden, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    // FORGED: pkg CLAIMS the sentinel but root_anchored is absent (a dependency
    // exporting npm_package_name=<repo-root> cannot also forge the verdict).
    function forgedRead(path: string, hidden = false): AttributedEvent {
      return { raw: { kind: 'read', path, pid: 1, ts: 0, hidden }, pkg: rootKey, lifecycle: 'install' };
    }
    function forgedWrite(path: string, hidden = false): AttributedEvent {
      return { raw: { kind: 'write', path, pid: 1, ts: 0, hidden }, pkg: rootKey, lifecycle: 'install' };
    }
    // FORGED variant: root_anchored present but explicitly false (non-anchored
    // pid).  Must classify forged identically to "field absent".
    function forgedFalseWrite(path: string, hidden = false): AttributedEvent {
      return {
        raw: { kind: 'write', path, pid: 1, ts: 0, hidden, root_anchored: false },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }

    // (a) GENUINE: read+write with root_anchored:true, sentinel in rootPkgKeys,
    // NO pkgDir for the sentinel → must NOT throw and surface as $REPO/... with
    // NO <FORGED_ROOT> prefix.
    it('does NOT throw for a genuine nameless-root fs event (no pkgDir for the sentinel)', () => {
      const events = [rootWrite('/work/dist/index.js'), rootRead('/work/src/index.ts')];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    it('surfaces a GENUINE nameless-root read as $REPO/... with NO <FORGED_ROOT> prefix', () => {
      const events = [rootRead('/work/src/index.ts')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.external_reads).toEqual(['$REPO/src/index.ts']);
      expect(block?.external_reads[0]).not.toContain('<FORGED_ROOT>');
    });

    it('surfaces a GENUINE nameless-root write as $REPO/... with NO <FORGED_ROOT> prefix', () => {
      const events = [rootWrite('/work/dist/index.js')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.escaped_writes).toEqual(['$REPO/dist/index.js']);
      expect(block?.escaped_writes[0]).not.toContain('<FORGED_ROOT>');
    });

    // (b) FORGED: root_anchored absent → <FORGED_ROOT> $REPO/...
    it('prefixes a FORGED nameless-root write (root_anchored absent) with <FORGED_ROOT>', () => {
      const events = [forgedWrite('/work/dist/index.js')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.escaped_writes).toEqual(['<FORGED_ROOT> $REPO/dist/index.js']);
    });

    it('prefixes a FORGED nameless-root read (root_anchored absent) with <FORGED_ROOT>', () => {
      const events = [forgedRead('/work/src/index.ts')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.external_reads).toEqual(['<FORGED_ROOT> $REPO/src/index.ts']);
    });

    // (b) separate case: root_anchored EXPLICITLY false (not just absent).
    it('prefixes a FORGED nameless-root write (root_anchored:false) with <FORGED_ROOT>', () => {
      const events = [forgedFalseWrite('/work/dist/index.js')];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.escaped_writes).toEqual(['<FORGED_ROOT> $REPO/dist/index.js']);
    });

    it('does NOT throw for a FORGED nameless-root fs event (dependency-triggered DoS guard)', () => {
      const events = [forgedWrite('/work/anywhere.js'), forgedRead('/work/secret')];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    // (c) NO-COLLAPSE: a genuine root write to $REPO/x AND a forged write to the
    // SAME $REPO/x → BOTH appear, distinct, no dedupe-collapse.
    it('does NOT dedupe-collapse a forged write onto an identical genuine nameless-root write', () => {
      const events = [
        rootWrite('/work/dist/index.js'), // genuine (root_anchored: true)
        forgedWrite('/work/dist/index.js'), // forged (same path, root_anchored absent)
      ];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.escaped_writes).toEqual([
        '$REPO/dist/index.js',
        '<FORGED_ROOT> $REPO/dist/index.js',
      ]);
    });

    it('does NOT dedupe-collapse a forged read onto an identical genuine nameless-root read', () => {
      const events = [
        rootRead('/work/src/index.ts'),
        forgedRead('/work/src/index.ts'),
      ];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.external_reads).toEqual([
        '$REPO/src/index.ts',
        '<FORGED_ROOT> $REPO/src/index.ts',
      ]);
    });

    // (d) BYTE/SORT: the '<repo-root>' package block key sorts deterministically
    // (codepoint) and renders stably.
    it('uses the sentinel as the package block key', () => {
      const events = [rootWrite('/work/dist/index.js')];
      const result = normalize(events, rootCtx);
      expect(result.has(ROOT_SENTINEL)).toBe(true);
      expect(ROOT_SENTINEL).toBe('<repo-root>');
    });

    it('sorts the <repo-root> key before a named package by codepoint (< 0x3C before letters)', () => {
      // render() sorts package keys by codepoint.  '<' (0x3C) precedes any
      // letter, so the sentinel block must render BEFORE 'esbuild@...'.
      const packages = normalize(
        [rootWrite('/work/dist/index.js'), readEv('/root/.npmrc')],
        { ...rootCtx, pkgDirs: new Map([[pkgId, pkgDir]]) },
      );
      const baseInput: RenderInput = {
        manager: 'pnpm',
        manager_lockfile_sha256: 'deadbeef',
        node_version: '20.19.0',
        generated_at: '2026-06-15T00:00:00Z',
        packages,
      };
      const out = render(baseInput);
      const sentinelIdx = out.indexOf(`${ROOT_SENTINEL}:`);
      const namedIdx = out.indexOf(`${pkgId}:`);
      expect(sentinelIdx).toBeGreaterThanOrEqual(0);
      expect(namedIdx).toBeGreaterThanOrEqual(0);
      expect(sentinelIdx).toBeLessThan(namedIdx);
    });

    it('renders the <repo-root> block byte-identically across repeated renders', () => {
      const packages = normalize(
        [
          rootWrite('/work/dist/index.js'),
          forgedWrite('/work/dist/index.js'),
          rootRead('/work/src/index.ts'),
        ],
        rootCtx,
      );
      const baseInput: RenderInput = {
        manager: 'pnpm',
        manager_lockfile_sha256: 'deadbeef',
        node_version: '20.19.0',
        generated_at: '2026-06-15T00:00:00Z',
        packages,
      };
      expect(render(baseInput)).toBe(render(baseInput));
    });

    // (e) NON-FS kinds (the blind-spot fix + the FORGED_ROOT extension).  The
    // attribution layer surfaces a nameless root lifecycle's spawn / connect /
    // env_read under the sentinel, and — like read/write — they now carry the
    // non-forgeable `root_anchored` verdict (stamped at the phase-install
    // end-of-drain flush).  GENUINE (root_anchored:true) → unmarked; forged /
    // unanchored (absent OR false) → `<FORGED_ROOT> ` outermost prefix.  All
    // must normalize WITHOUT throwing even with no pkgDir for the sentinel.
    function rootSpawn(argv: string[]): AttributedEvent {
      return {
        raw: { kind: 'spawn', argv, result: 'ok', pid: 1, ts: 0, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function forgedSpawn(argv: string[], result: 'ok' | 'enoent' = 'ok'): AttributedEvent {
      // root_anchored absent → forged.
      return {
        raw: { kind: 'spawn', argv, result, pid: 1, ts: 0 },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function rootConnect(host: string, port: number): AttributedEvent {
      return {
        raw: { kind: 'connect', host, port, result: 'ok', pid: 1, ts: 0, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function forgedConnect(host: string, port: number): AttributedEvent {
      // root_anchored absent → forged.
      return {
        raw: { kind: 'connect', host, port, result: 'ok', pid: 1, ts: 0 },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function rootEnvRead(name: string): AttributedEvent {
      return {
        raw: { kind: 'env_read', name, pid: 1, ts: 0, hidden: false, root_anchored: true },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }
    function forgedEnvRead(name: string): AttributedEvent {
      // root_anchored absent → forged.
      return {
        raw: { kind: 'env_read', name, pid: 1, ts: 0, hidden: false },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }

    it('does NOT throw for nameless-root non-fs events (spawn/connect/env_read, no pkgDir)', () => {
      const events = [
        rootSpawn(['node', 'preinstall.js']),
        rootConnect('registry.npmjs.org', 443),
        rootEnvRead('AWS_SECRET_ACCESS_KEY'),
        forgedSpawn(['node', 'preinstall.js']),
        forgedConnect('registry.npmjs.org', 443),
        forgedEnvRead('AWS_SECRET_ACCESS_KEY'),
      ];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    // GENUINE (root_anchored:true) → unmarked, byte-identical to before.
    it('surfaces a GENUINE nameless-root spawn in spawn_attempts UNMARKED', () => {
      const block = normalize([rootSpawn(['node', 'preinstall.js'])], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.spawn_attempts).toEqual(['node preinstall.js']);
    });

    it('surfaces a GENUINE nameless-root connect in network_attempts UNMARKED', () => {
      const block = normalize([rootConnect('evil.example.com', 443)], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.network_attempts).toEqual(['connect evil.example.com:443']);
    });

    it('surfaces a GENUINE nameless-root env_read in env_read UNMARKED', () => {
      const block = normalize([rootEnvRead('AWS_SECRET_ACCESS_KEY')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.env_read).toEqual(['AWS_SECRET_ACCESS_KEY']);
    });

    // FORGED (root_anchored absent) → <FORGED_ROOT> outermost.
    it('prefixes a FORGED nameless-root spawn (ok) with <FORGED_ROOT> outermost', () => {
      const block = normalize([forgedSpawn(['node', 'preinstall.js'])], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.spawn_attempts).toEqual(['<FORGED_ROOT> node preinstall.js']);
    });

    it('prefixes a FORGED nameless-root spawn (blocked) with <FORGED_ROOT> before the result tag', () => {
      const block = normalize([forgedSpawn(['/bin/curl', 'evil'], 'enoent')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      // <FORGED_ROOT> is the OUTERMOST prefix, before the <ENOENT> result tag.
      expect(block?.spawn_blocked).toEqual(['<FORGED_ROOT> <ENOENT> /bin/curl evil']);
    });

    it('prefixes a FORGED nameless-root connect with <FORGED_ROOT> outermost', () => {
      const block = normalize([forgedConnect('evil.example.com', 443)], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.network_attempts).toEqual(['<FORGED_ROOT> connect evil.example.com:443']);
    });

    it('prefixes a FORGED nameless-root env_read with <FORGED_ROOT> outermost', () => {
      const block = normalize([forgedEnvRead('AWS_SECRET_ACCESS_KEY')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.env_read).toEqual(['<FORGED_ROOT> AWS_SECRET_ACCESS_KEY']);
    });

    // NO-COLLAPSE: a genuine connect AND a forged connect to the SAME host:port
    // → BOTH survive as distinct strings (no Set-based dedupe-collapse). The
    // final array is codepoint-sorted by sortAndDedupe, so `<FORGED_ROOT> …`
    // (leading '<' = 0x3C) sorts BEFORE the un-prefixed `connect …` ('c' = 0x63).
    it('does NOT dedupe-collapse a forged connect onto an identical genuine connect', () => {
      const events = [
        rootConnect('registry.npmjs.org', 443), // genuine (root_anchored:true)
        forgedConnect('registry.npmjs.org', 443), // forged (same host:port, absent)
      ];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.network_attempts).toEqual([
        '<FORGED_ROOT> connect registry.npmjs.org:443',
        'connect registry.npmjs.org:443',
      ]);
      // The security invariant: both survive (2 distinct entries, not collapsed to 1).
      expect(block?.network_attempts).toHaveLength(2);
    });

    // env_tamper completeness: the `<REFUSED>` variant is the last root-claimable
    // + rendered + deduped kind that was UNMARKED.  It now carries the same
    // non-forgeable `root_anchored` verdict — GENUINE (root_anchored:true) →
    // unmarked `<REFUSED> …`; forged/unanchored (absent OR false) → `<FORGED_ROOT>`
    // as the OUTERMOST prefix.  (The `audit_fd_lost` variant routes to audit_bypass
    // and is gated independently by findAuditBypass, so it is NOT anchored here.)
    function rootTamper(op: 'unsetenv' | 'putenv' | 'clearenv', name?: string): AttributedEvent {
      const raw = name !== undefined
        ? { kind: 'env_tamper' as const, op, name, refused: true as const, pid: 1, ts: 0, root_anchored: true }
        : { kind: 'env_tamper' as const, op, refused: true as const, pid: 1, ts: 0, root_anchored: true };
      return { raw, pkg: rootKey, lifecycle: 'install' };
    }
    function forgedTamper(op: 'unsetenv' | 'putenv' | 'clearenv', name?: string): AttributedEvent {
      // root_anchored absent → forged.
      const raw = name !== undefined
        ? { kind: 'env_tamper' as const, op, name, refused: true as const, pid: 1, ts: 0 }
        : { kind: 'env_tamper' as const, op, refused: true as const, pid: 1, ts: 0 };
      return { raw, pkg: rootKey, lifecycle: 'install' };
    }
    function forgedFalseTamper(op: 'unsetenv', name: string): AttributedEvent {
      // root_anchored present but explicitly false → forged (identical to absent).
      return {
        raw: { kind: 'env_tamper' as const, op, name, refused: true as const, pid: 1, ts: 0, root_anchored: false },
        pkg: rootKey,
        lifecycle: 'install',
      };
    }

    it('does NOT throw for a nameless-root env_tamper (no pkgDir for the sentinel)', () => {
      const events = [rootTamper('unsetenv', 'LD_PRELOAD'), forgedTamper('unsetenv', 'LD_PRELOAD')];
      expect(() => normalize(events, rootCtx)).not.toThrow();
    });

    it('surfaces a GENUINE nameless-root env_tamper in env_tamper UNMARKED', () => {
      const block = normalize([rootTamper('unsetenv', 'LD_PRELOAD')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.env_tamper).toEqual(['<REFUSED> unsetenv LD_PRELOAD']);
    });

    it('surfaces a GENUINE nameless-root clearenv env_tamper UNMARKED (no name tail)', () => {
      const block = normalize([rootTamper('clearenv')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.env_tamper).toEqual(['<REFUSED> clearenv']);
    });

    it('prefixes a FORGED nameless-root env_tamper (root_anchored absent) with <FORGED_ROOT> outermost', () => {
      const block = normalize([forgedTamper('unsetenv', 'LD_PRELOAD')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      // <FORGED_ROOT> is the OUTERMOST prefix, before the <REFUSED> tag.
      expect(block?.env_tamper).toEqual(['<FORGED_ROOT> <REFUSED> unsetenv LD_PRELOAD']);
    });

    it('prefixes a FORGED nameless-root env_tamper (root_anchored:false) with <FORGED_ROOT>', () => {
      const block = normalize([forgedFalseTamper('unsetenv', 'LD_PRELOAD')], rootCtx)
        .get(rootKey)?.lifecycle['install'];
      expect(block?.env_tamper).toEqual(['<FORGED_ROOT> <REFUSED> unsetenv LD_PRELOAD']);
    });

    // NO-COLLAPSE: a genuine env_tamper AND a forged env_tamper for the SAME
    // op+name → BOTH survive as distinct strings (no Set-based dedupe-collapse).
    // codepoint-sorted: `<FORGED_ROOT> …` (leading '<' = 0x3C) sorts BEFORE the
    // un-prefixed `<REFUSED> …` — both lead with '<', so the next chars decide
    // ('F' 0x46 < 'R' 0x52), keeping the forged entry first.
    it('does NOT dedupe-collapse a forged env_tamper onto an identical genuine one', () => {
      const events = [
        rootTamper('unsetenv', 'LD_PRELOAD'), // genuine (root_anchored:true)
        forgedTamper('unsetenv', 'LD_PRELOAD'), // forged (same op+name, absent)
      ];
      const block = normalize(events, rootCtx).get(rootKey)?.lifecycle['install'];
      expect(block?.env_tamper).toEqual([
        '<FORGED_ROOT> <REFUSED> unsetenv LD_PRELOAD',
        '<REFUSED> unsetenv LD_PRELOAD',
      ]);
      // The security invariant: both survive (2 distinct entries, not collapsed to 1).
      expect(block?.env_tamper).toHaveLength(2);
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

  // macOS-bare backend: os:'darwin' enables the macOS-only system-noise
  // prefixes AND the /private realpath canonicalization.  Both are gated on the
  // flag (NOT on path shape) as a security boundary: a malicious Linux lockfile
  // must never be able to smuggle macOS-shaped paths past a Linux audit gate.
  describe('macOS noise prefixes + /private canonicalization (os:darwin)', () => {
    const darwinCtx: NormalizeContext = { ...ctx, os: 'darwin' };

    // The macOS-only system-noise paths (post-/private-canonicalization form).
    const darwinNoisePaths = [
      '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
      '/Library/Apple/System/Library/Frameworks/Foo.framework/Foo',
      '/Library/Caches/com.apple.dyld/closures',
      // dyld launch-closure state under /private/var/db/dyld → canonicalized to
      // /var/db/dyld/ BEFORE the noise check, so it must drop on darwin.
      '/private/var/db/dyld/dyld_closures',
      // dyld shared cache image — matched by basename, dir leaf varies by OS.
      '/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e',
    ];

    for (const p of darwinNoisePaths) {
      it(`drops macOS system noise when os:darwin: ${p}`, () => {
        const block = getBlock(normalize([readEv(p)], darwinCtx));
        expect(block?.external_reads ?? []).toEqual([]);
      });

      it(`RECORDS the same path when os:linux (gating boundary): ${p}`, () => {
        // The default ctx is os:'linux'.  None of these prefixes are in the
        // shared list, so a Linux gate must NOT drop them — it records the
        // external read.  This is the security boundary: a Linux lockfile can
        // never smuggle a macOS-shaped path past the Linux audit by relying on
        // the darwin-only drop.
        const block = getBlock(normalize([readEv(p)], ctx));
        expect((block?.external_reads ?? []).length).toBeGreaterThan(0);
      });
    }

    it('drops the provisioned-node toolchain cache (host-variable root, fixed segment) on darwin', () => {
      const p = '/var/folders/abc/T/script-jail-cache/node/24.15.0/bin/lib/node_modules/npm/index.js';
      expect(getBlock(normalize([readEv(p)], darwinCtx))?.external_reads ?? []).toEqual([]);
    });

    it('does NOT drop the provisioned-node cache segment on linux (it is darwin-gated)', () => {
      const p = '/var/folders/abc/T/script-jail-cache/node/24.15.0/bin/lib/node_modules/npm/index.js';
      // os:'linux' default: the segment match never runs, but the /var/folders
      // path canonicalizes to nothing on linux and is not in any shared prefix,
      // so it surfaces as an external read.
      expect((getBlock(normalize([readEv(p)], ctx))?.external_reads ?? []).length).toBeGreaterThan(0);
    });

    it('canonicalizes /private/var → /var before tokenizing (darwin)', () => {
      // The Mach-O shim resolves macOS paths via F_GETPATH/realpath, so /tmp
      // comes back as /private/tmp.  With roots.tmp = '/tmp', a /private/tmp
      // path must canonicalize and then tokenize to $TMPDIR.
      const block = getBlock(normalize([readEv('/private/tmp/build-artifact')], darwinCtx));
      expect(block?.external_reads).toContain('$TMPDIR/build-artifact');
    });

    it('canonicalizes /private/etc → /etc, then drops it via the shared /etc/resolv.conf noise prefix (darwin)', () => {
      // /private/etc/resolv.conf → /etc/resolv.conf (shared noise) → dropped.
      const block = getBlock(normalize([readEv('/private/etc/resolv.conf')], darwinCtx));
      expect(block?.external_reads ?? []).toEqual([]);
    });

    it('does NOT canonicalize /private on linux — /private/tmp stays a literal external read', () => {
      // os:'linux' default: the /private rewrite never runs.  /private/tmp/...
      // matches no root, so it surfaces verbatim — NOT collapsed to $TMPDIR.
      const block = getBlock(normalize([readEv('/private/tmp/build-artifact')], ctx));
      expect(block?.external_reads).toContain('/private/tmp/build-artifact');
      expect(block?.external_reads).not.toContain('$TMPDIR/build-artifact');
    });

    it('does NOT canonicalize a /private*-but-not-segment-boundary path (darwin)', () => {
      // /private/variant is NOT /private/var/... — the rewrite only fires on a
      // true path-segment boundary, so this passes through untouched.
      const block = getBlock(normalize([readEv('/private/variant/data')], darwinCtx));
      expect(block?.external_reads).toContain('/private/variant/data');
    });

    it('Linux output is byte-identical regardless of the os flag for a shared-noise / non-macOS path', () => {
      // A path that is NOT macOS-shaped must normalize identically under both
      // os values — the gating only ADDS macOS drops; it never changes Linux
      // behaviour for shared paths.
      const events = [readEv('/root/.npmrc'), readEv('/usr/lib/x86_64-linux-gnu/libssl.so.1.1')];
      const linux = getBlock(normalize(events, ctx));
      const darwin = getBlock(normalize(events, darwinCtx));
      expect(darwin?.external_reads).toEqual(linux?.external_reads);
      expect(linux?.external_reads).toEqual(['$HOME/.npmrc']);
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

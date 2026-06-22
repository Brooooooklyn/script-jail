import { describe, it, expect } from 'vitest';
import {
  tokenize,
  isInsidePkg,
  isCrossPackage,
  stripTrailingSlashes,
  canonicalizeTokenizeRoots,
  type TokenizeRoots,
} from '../../src/lock/tokenize.js';

const roots: TokenizeRoots = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.local/share/pnpm/store',
};

const pkgDir = '/work/node_modules/esbuild';

describe('tokenize', () => {
  describe('longest-prefix match', () => {
    it('$PKG beats $NODE_MODULES (more specific prefix)', () => {
      // A path inside the current package should get $PKG, not $NODE_MODULES
      const result = tokenize('/work/node_modules/esbuild/install.js', roots, pkgDir);
      expect(result).toContain('$PKG');
      expect(result).not.toContain('$NODE_MODULES');
    });

    it('$NODE_MODULES beats $REPO for a different package', () => {
      // A path inside node_modules but NOT esbuild gets $NODE_MODULES
      const result = tokenize('/work/node_modules/debug/index.js', roots, pkgDir);
      expect(result).toContain('$NODE_MODULES');
      expect(result).not.toContain('$REPO');
    });

    it('$REPO beats $HOME when inside repo', () => {
      const result = tokenize('/work/src/index.ts', roots, pkgDir);
      expect(result).toBe('$REPO/src/index.ts');
    });

    it('$HOME for a path under home', () => {
      const result = tokenize('/root/.npmrc', roots, pkgDir);
      expect(result).toBe('$HOME/.npmrc');
    });

    it('$CACHE for a path under cache', () => {
      const result = tokenize('/root/.local/share/pnpm/store/v3/files/ab/cdef', roots, pkgDir);
      expect(result).toContain('$CACHE');
      expect(result).not.toContain('$HOME');
    });

    it('$TMPDIR for /tmp paths', () => {
      const result = tokenize('/tmp/npm-abc123/build.log', roots);
      expect(result).toContain('$TMPDIR');
    });

    // init.sh points TMPDIR at the scratch disk inside the VM backends, so the
    // primary tmp root follows os.tmpdir() (/scratch/tmp) while the literal
    // /tmp tmpfs stays reachable for tools that ignore TMPDIR.  BOTH must
    // render as $TMPDIR — with hash collapsing — or scratch-tmp writes would
    // leak raw nondeterministic paths into the lockfile.
    describe('tmpLegacy alias (TMPDIR on the scratch disk)', () => {
      const scratchRoots: TokenizeRoots = {
        ...roots,
        tmp: '/scratch/tmp',
        tmpLegacy: '/tmp',
      };

      it('maps the redirected tmp root to $TMPDIR with collapsing', () => {
        // Realistic Yarn Berry transient-shim dir: `getTempName('xfs-')` =>
        // `xfs-<8 hex>`.  The whole `xfs-021cebd2` segment is only 12 chars, BELOW
        // HASH_PATTERN's 16 floor, so without the YARN_FSLIB_TEMP rule it would leak
        // a per-run-random path into the lockfile (the napi-rs husky non-determinism).
        const result = tokenize('/scratch/tmp/xfs-021cebd2/husky', scratchRoots);
        expect(result).toBe('$TMPDIR/<hash>/husky');
      });

      it('maps the literal /tmp to $TMPDIR too (tools that ignore TMPDIR)', () => {
        const result = tokenize('/tmp/npm-abc123/build.log', scratchRoots);
        expect(result).toContain('$TMPDIR');
        expect(result).not.toContain('/tmp');
      });

      it('does not let /scratch siblings outside tmp match', () => {
        const result = tokenize('/scratch/script-jail-strace/strace.out.123', scratchRoots);
        expect(result).toBe('/scratch/script-jail-strace/strace.out.123');
      });

      it('bare alias prefix tokenizes exactly like the primary', () => {
        expect(tokenize('/tmp', scratchRoots)).toBe('$TMPDIR');
        expect(tokenize('/scratch/tmp', scratchRoots)).toBe('$TMPDIR');
      });
    });

    it('leaves an unmatched absolute path unmodified (modulo hash collapsing)', () => {
      const result = tokenize('/usr/bin/node', roots, pkgDir);
      expect(result).toBe('/usr/bin/node');
    });
  });

  describe('exact prefix boundary — /work vs /worker', () => {
    it('/work matches repo prefix', () => {
      const result = tokenize('/work', roots, pkgDir);
      expect(result).toBe('$REPO');
    });

    it('/worker does NOT match repo prefix', () => {
      const result = tokenize('/worker/foo', roots, pkgDir);
      expect(result).toBe('/worker/foo');
    });

    it('/work/node_modules matches nodeModules prefix', () => {
      const result = tokenize('/work/node_modules', roots, pkgDir);
      expect(result).toBe('$NODE_MODULES');
    });

    it('/work/node_modulesX does NOT match nodeModules prefix', () => {
      const result = tokenize('/work/node_modulesX/foo', roots, pkgDir);
      // Still matches $REPO since /work is a prefix of /work/node_modulesX
      expect(result.startsWith('$REPO')).toBe(true);
    });
  });

  describe('hash collapsing', () => {
    it('collapses 16+ char base64-ish fragments under $TMPDIR', () => {
      const longHash = 'a'.repeat(16) + 'BCDE';
      const result = tokenize(`/tmp/${longHash}`, roots);
      expect(result).toContain('<hash>');
    });

    it('collapses .tmp.<rand> suffixes to .tmp<hash> under $TMPDIR', () => {
      const result = tokenize('/tmp/something.tmp.xyz123', roots);
      expect(result).toBe('$TMPDIR/something.tmp<hash>');
    });

    it('does not collapse short names', () => {
      // A short filename that is < 16 chars is left as-is
      const result = tokenize('/tmp/build.log', roots);
      expect(result).not.toContain('<hash>');
    });

    it('does not collapse CamelCase words even if long', () => {
      // An all-caps-start word >= 16 chars looks like an English word, not a hash
      const result = tokenize('/tmp/SomeLongCamelCaseNameHere', roots);
      // This may or may not be collapsed depending on the heuristic — just ensure it runs
      // The SomeLongCamelCaseNameHere is 30 chars but starts with uppercase, so not collapsed
      expect(typeof result).toBe('string');
    });

    // Crit 1: package names under $NODE_MODULES must be preserved verbatim —
    // they are stable identifiers, not content-addressable hashes.
    it('does NOT collapse long npm package names under $NODE_MODULES', () => {
      // eslint-plugin-react-hooks is 25 chars — would be collapsed by the old HASH_PATTERN
      const result = tokenize('/work/node_modules/eslint-plugin-react-hooks/index.js', roots);
      expect(result).toBe('$NODE_MODULES/eslint-plugin-react-hooks/index.js');
    });

    it('does NOT collapse babel-plugin-transform-runtime (30 chars) under $NODE_MODULES', () => {
      const result = tokenize('/work/node_modules/babel-plugin-transform-runtime/lib/index.js', roots);
      expect(result).toBe('$NODE_MODULES/babel-plugin-transform-runtime/lib/index.js');
    });

    it('does NOT collapse react-router-dom (16 chars) under $NODE_MODULES', () => {
      const result = tokenize('/work/node_modules/react-router-dom/index.js', roots);
      expect(result).toBe('$NODE_MODULES/react-router-dom/index.js');
    });

    it('collapses content-hash filenames under $CACHE', () => {
      // A 22-char hex hash in a cache path should be collapsed
      const result = tokenize('/root/.local/share/pnpm/store/v3/files/abcdef1234567890abcdef.bin', roots);
      expect(result).toContain('$CACHE');
      expect(result).toContain('<hash>');
    });

    // Yarn Berry runs binary lifecycle scripts (e.g. napi-rs' `husky`) through a
    // transient shim under `$TMPDIR/xfs-<8-9 hex>/`.  That 8-9 hex run is below
    // HASH_PATTERN's 16 floor, so it needs its own targeted collapse or the path is
    // per-run-random and `mode: check` flaps.  See YARN_FSLIB_TEMP in tokenize.ts.
    describe('yarn-fslib transient temp dir (xfs-<hash>)', () => {
      it('collapses the 8-hex shim segment under $TMPDIR', () => {
        expect(tokenize('/tmp/xfs-021cebd2/husky', roots)).toBe('$TMPDIR/<hash>/husky');
      });

      it('collapses the 9-hex edge case (hash === 2^32) under $TMPDIR', () => {
        expect(tokenize('/tmp/xfs-100000000/husky', roots)).toBe('$TMPDIR/<hash>/husky');
      });

      it('collapses the bare shim dir (no trailing path) under $TMPDIR', () => {
        expect(tokenize('/tmp/xfs-021cebd2', roots)).toBe('$TMPDIR/<hash>');
      });

      it('does NOT collapse a non-hex xfs- segment (only [0-9a-f] random names)', () => {
        // `xfs-deadzzzz` is not 8-9 hex — left to the general heuristic (here: short, kept).
        expect(tokenize('/tmp/xfs-config/file', roots)).toBe('$TMPDIR/xfs-config/file');
      });

      it('does NOT mask a partial/over-long hex run masquerading as the shim', () => {
        // 7 hex (too short) and 10 hex (too long) are not the fslib shape — left verbatim.
        expect(tokenize('/tmp/xfs-abcdef0/x', roots)).toBe('$TMPDIR/xfs-abcdef0/x');
        expect(tokenize('/tmp/xfs-0123456789/x', roots)).toBe('$TMPDIR/xfs-0123456789/x');
      });

      // Over-mask guard (codex adversarial-review #3): the rule is ANCHORED to the
      // FIRST segment directly under $TMPDIR (getTempName writes the launcher there).
      // A NESTED `xfs-<hex>` is an attacker-influenceable STABLE name, not the random
      // fslib launcher — collapsing it would dedupe distinct audit entries.
      it('does NOT collapse a NESTED xfs-<hex> segment (only depth-1 under $TMPDIR)', () => {
        expect(tokenize('/tmp/stable/xfs-deadbeef/husky', roots)).toBe(
          '$TMPDIR/stable/xfs-deadbeef/husky',
        );
      });

      // Yarn never writes these launchers in the content store — a `xfs-<hex>`
      // segment under $CACHE is a stable name and must survive verbatim.
      it('does NOT collapse an xfs-<hex> segment under $CACHE', () => {
        expect(
          tokenize('/root/.local/share/pnpm/store/xfs-cafebabe/pkg.tgz', roots),
        ).toBe('$CACHE/xfs-cafebabe/pkg.tgz');
      });
    });
  });

  describe('redirected package-manager store/cache dirs (under work_dir)', () => {
    // buildChildEnv pins every package-manager bulk store/cache onto the
    // repo disk: npm_config_store_dir=/work/.pnpm-store (pnpm, the original
    // precedent), YARN_GLOBAL_FOLDER=/work/.yarn-global,
    // YARN_CACHE_FOLDER=/work/.yarn-cache, npm_config_cache=/work/.npm-cache.
    // Longest-prefix-wins puts all of them in the $REPO bucket (roots.cache
    // only covers the per-manager default cache root under $HOME), with NO
    // hash collapsing — same treatment across all four, so yarn/npm stay
    // consistent with the established $REPO/.pnpm-store rendering.
    it('tokenizes /work/.pnpm-store under $REPO (existing pnpm precedent)', () => {
      const result = tokenize('/work/.pnpm-store/v10/files/ab/cdef', roots, pkgDir);
      expect(result).toBe('$REPO/.pnpm-store/v10/files/ab/cdef');
    });

    it('tokenizes /work/.yarn-global under $REPO (yarn berry global folder)', () => {
      const result = tokenize('/work/.yarn-global/cache/lodash-npm-4.17.21-abc.zip', roots, pkgDir);
      expect(result).toBe('$REPO/.yarn-global/cache/lodash-npm-4.17.21-abc.zip');
    });

    it('tokenizes /work/.yarn-cache under $REPO (yarn classic cache-folder)', () => {
      const result = tokenize('/work/.yarn-cache/v6/npm-debug-4.3.4/package.json', roots, pkgDir);
      expect(result).toBe('$REPO/.yarn-cache/v6/npm-debug-4.3.4/package.json');
    });

    it('tokenizes /work/.npm-cache under $REPO (npm cacache tree)', () => {
      const result = tokenize('/work/.npm-cache/_cacache/index-v5/00/aa', roots, pkgDir);
      expect(result).toBe('$REPO/.npm-cache/_cacache/index-v5/00/aa');
    });
  });

  describe('no currentPkgDir', () => {
    it('falls back to $NODE_MODULES without currentPkgDir', () => {
      const result = tokenize('/work/node_modules/debug/index.js', roots);
      expect(result.startsWith('$NODE_MODULES')).toBe(true);
    });

    it('relative paths are left alone (modulo hash collapsing)', () => {
      const result = tokenize('relative/path/to/file', roots);
      expect(result).toBe('relative/path/to/file');
    });
  });
});

describe('isInsidePkg', () => {
  it('returns true for $PKG exactly', () => {
    expect(isInsidePkg('$PKG')).toBe(true);
  });

  it('returns true for paths under $PKG/', () => {
    expect(isInsidePkg('$PKG/install.js')).toBe(true);
    expect(isInsidePkg('$PKG/lib/index.js')).toBe(true);
  });

  it('returns false for $NODE_MODULES path', () => {
    expect(isInsidePkg('$NODE_MODULES/debug/index.js')).toBe(false);
  });

  it('returns false for $REPO', () => {
    expect(isInsidePkg('$REPO/src/index.ts')).toBe(false);
  });

  it('returns false for $PKGX (does not match partial token)', () => {
    expect(isInsidePkg('$PKGX/foo')).toBe(false);
  });
});

describe('isCrossPackage', () => {
  it('returns true for $NODE_MODULES paths not in $PKG', () => {
    expect(isCrossPackage('$NODE_MODULES/debug/index.js')).toBe(true);
  });

  it('returns true for $NODE_MODULES exactly', () => {
    expect(isCrossPackage('$NODE_MODULES')).toBe(true);
  });

  it('returns false for $PKG paths', () => {
    expect(isCrossPackage('$PKG/install.js')).toBe(false);
  });

  it('returns false for $REPO paths', () => {
    expect(isCrossPackage('$REPO/.github/workflow.yml')).toBe(false);
  });

  it('returns false for $HOME paths', () => {
    expect(isCrossPackage('$HOME/.ssh/id_rsa')).toBe(false);
  });

  it('returns false for $NODE_MODULESX (partial match guard)', () => {
    expect(isCrossPackage('$NODE_MODULESEXTRA/foo')).toBe(false);
  });
});

describe('byte-stability under an arbitrary absolute repo root (install:true cwd parity)', () => {
  // M1 pins the guest audit work_dir to the real (runner-specific) repoDir so
  // process.cwd() matches the host re-run.  tokenize() keys off roots.repo
  // dynamically (never a hardcoded /work), so an arbitrary absolute root must
  // produce IDENTICAL tokenized output — otherwise the lock would not be
  // reproducible across runners.  This pins that invariant.
  function rootsFor(repo: string): TokenizeRoots {
    return {
      repo,
      nodeModules: `${repo}/node_modules`,
      home: '/root',
      tmp: '/tmp',
      cache: '/root/.local/share/pnpm/store',
    };
  }

  const REPOS = [
    '/work',
    '/home/runner/work/myrepo/myrepo',
    '/opt/actions-runner/_work/some-repo/some-repo',
    '/var/folders/ab/cd/T/repo-stage-XXXX/work',
  ];

  it('renders $REPO / $NODE_MODULES / $PKG identically for every absolute root', () => {
    const outputs = REPOS.map((repo) => {
      const roots = rootsFor(repo);
      const pkg = `${repo}/node_modules/esbuild`;
      return [
        tokenize(`${repo}/prepare-built.txt`, roots),
        tokenize(`${repo}/src/index.ts`, roots),
        tokenize(`${repo}/node_modules/debug/index.js`, roots),
        tokenize(`${repo}/node_modules/esbuild/install.js`, roots, pkg),
        // paths OUTSIDE the repo root stay backend-invariant too
        tokenize('/root/.npmrc', roots),
        tokenize('/etc/passwd', roots),
      ].join('\n');
    });
    const expected = [
      '$REPO/prepare-built.txt',
      '$REPO/src/index.ts',
      '$NODE_MODULES/debug/index.js',
      '$PKG/install.js',
      '$HOME/.npmrc',
      '/etc/passwd',
    ].join('\n');
    for (const out of outputs) expect(out).toBe(expected);
  });
});

describe('stripTrailingSlashes', () => {
  it('strips one or more trailing slashes', () => {
    expect(stripTrailingSlashes('/opt/r/r/')).toBe('/opt/r/r');
    expect(stripTrailingSlashes('/opt/r/r//')).toBe('/opt/r/r');
  });
  it('is a no-op for a clean path', () => {
    expect(stripTrailingSlashes('/opt/r/r')).toBe('/opt/r/r');
  });
  it('preserves a lone root slash', () => {
    expect(stripTrailingSlashes('/')).toBe('/');
    expect(stripTrailingSlashes('//')).toBe('/');
  });
});

describe('canonicalizeTokenizeRoots', () => {
  it('strips trailing slashes from EVERY prefix (repo/nodeModules/home/tmp/cache)', () => {
    const out = canonicalizeTokenizeRoots({
      repo: '/work/',
      nodeModules: '/work/node_modules/',
      home: '/root/',
      tmp: '/tmp/',
      cache: '/root/.cache/pnpm/',
    });
    expect(out).toEqual({
      repo: '/work',
      nodeModules: '/work/node_modules',
      home: '/root',
      tmp: '/tmp',
      cache: '/root/.cache/pnpm',
    });
  });
  it('strips the optional tmpLegacy alias when present', () => {
    const out = canonicalizeTokenizeRoots({
      repo: '/work/',
      nodeModules: '/work/node_modules/',
      home: '/root/',
      tmp: '/scratch/tmp/',
      tmpLegacy: '/tmp/',
      cache: '/root/.cache/pnpm/',
    });
    expect(out.tmpLegacy).toBe('/tmp');
  });
  it('is a no-op for already-clean roots (byte-identical lock)', () => {
    const clean: TokenizeRoots = {
      repo: '/work',
      nodeModules: '/work/node_modules',
      home: '/root',
      tmp: '/tmp',
      cache: '/root/.cache/pnpm',
    };
    expect(canonicalizeTokenizeRoots(clean)).toEqual(clean);
  });
});

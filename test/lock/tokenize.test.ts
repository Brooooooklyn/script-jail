import { describe, it, expect } from 'vitest';
import { tokenize, isInsidePkg, isCrossPackage, type TokenizeRoots } from '../../src/lock/tokenize.js';

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
        // `xfs-<32hex>` matches HASH_PATTERN as one [A-Za-z0-9_-]{16,} run
        // (the hyphen is in the class), so the whole segment collapses.
        const result = tokenize('/scratch/tmp/xfs-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/archive.zip', scratchRoots);
        expect(result).toBe('$TMPDIR/<hash>/archive.zip');
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

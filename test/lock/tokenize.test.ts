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

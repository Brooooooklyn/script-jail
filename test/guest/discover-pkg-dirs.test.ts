// Tests for src/guest/discover-pkg-dirs.ts

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { discoverPkgDirs } from '../../src/guest/discover-pkg-dirs.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let testDir: string;

beforeEach(() => {
  testDir = join(
    tmpdir(),
    `discover-pkg-dirs-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

/** Write a package.json with the given name and version under dir/package.json */
function writePkg(dir: string, name: string, version: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version }), 'utf8');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('discoverPkgDirs()', () => {
  it('returns an empty Map when node_modules does not exist', () => {
    const result = discoverPkgDirs(join(testDir, 'node_modules'));
    expect(result.size).toBe(0);
  });

  it('returns an empty Map when node_modules is empty', () => {
    const nm = join(testDir, 'node_modules');
    mkdirSync(nm);
    const result = discoverPkgDirs(nm);
    expect(result.size).toBe(0);
  });

  it('walks flat layout and scoped packages, skipping dotfiles and no-manifest dirs', () => {
    const nm = join(testDir, 'node_modules');

    // Regular packages
    writePkg(join(nm, 'foo'), 'foo', '1.0.0');
    writePkg(join(nm, 'bar'), 'bar', '2.0.0');

    // Scoped package
    writePkg(join(nm, '@scope', 'baz'), '@scope/baz', '0.1.0');

    // Dotfiles/dirs — must be skipped
    mkdirSync(join(nm, '.bin'), { recursive: true });
    writeFileSync(join(nm, '.package-lock.json'), '{}', 'utf8');

    // Invalid JSON — skipped, error logged
    mkdirSync(join(nm, 'broken'), { recursive: true });
    writeFileSync(join(nm, 'broken', 'package.json'), 'this is not json', 'utf8');

    // Directory with no package.json — skipped silently
    mkdirSync(join(nm, 'no-manifest'), { recursive: true });

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(3);
    expect(result.get('foo@1.0.0')).toBe(join(nm, 'foo'));
    expect(result.get('bar@2.0.0')).toBe(join(nm, 'bar'));
    expect(result.get('@scope/baz@0.1.0')).toBe(join(nm, '@scope', 'baz'));

    // dotfiles should NOT appear
    expect([...result.keys()].some((k) => k.startsWith('.'))).toBe(false);
  });

  it('uses package.json name rather than filesystem dirname', () => {
    // Simulate a `file:` dep or aliased install where the dir name differs from
    // the actual package name stored in package.json.
    const nm = join(testDir, 'node_modules');
    const dir = join(nm, 'aliased-dir-name');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'actual-pkg-name', version: '3.0.0' }),
      'utf8',
    );

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(1);
    expect(result.has('actual-pkg-name@3.0.0')).toBe(true);
    expect(result.has('aliased-dir-name@3.0.0')).toBe(false);
  });

  it('skips packages with missing name or version fields', () => {
    const nm = join(testDir, 'node_modules');

    // Missing version
    const dir1 = join(nm, 'no-version');
    mkdirSync(dir1, { recursive: true });
    writeFileSync(join(dir1, 'package.json'), JSON.stringify({ name: 'no-version' }), 'utf8');

    // Missing name
    const dir2 = join(nm, 'no-name');
    mkdirSync(dir2, { recursive: true });
    writeFileSync(join(dir2, 'package.json'), JSON.stringify({ version: '1.0.0' }), 'utf8');

    const result = discoverPkgDirs(nm);
    expect(result.size).toBe(0);
  });

  it('does not throw on invalid JSON in package.json', () => {
    const nm = join(testDir, 'node_modules');
    const dir = join(nm, 'broken');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), '{ invalid json }', 'utf8');

    // Must not throw.
    expect(() => discoverPkgDirs(nm)).not.toThrow();
    const result = discoverPkgDirs(nm);
    expect(result.size).toBe(0);
  });

  it('logs a warning to stderr for invalid JSON but continues', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    const nm = join(testDir, 'node_modules');
    const dir = join(nm, 'broken');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), 'NOT VALID JSON', 'utf8');

    discoverPkgDirs(nm);

    const warnCalls = stderrSpy.mock.calls.map((c) => String(c[0]));
    expect(warnCalls.some((msg) => msg.includes('broken') && msg.includes('invalid JSON'))).toBe(true);

    stderrSpy.mockRestore();
  });

  it('handles multiple packages correctly with last-writer-wins for duplicate name@version', () => {
    const nm = join(testDir, 'node_modules');

    writePkg(join(nm, 'pkg-a'), 'pkg-a', '1.0.0');
    writePkg(join(nm, 'pkg-b'), 'pkg-b', '1.0.0');
    writePkg(join(nm, 'pkg-c'), 'pkg-c', '2.5.3');

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(3);
    expect(result.get('pkg-a@1.0.0')).toBe(join(nm, 'pkg-a'));
    expect(result.get('pkg-b@1.0.0')).toBe(join(nm, 'pkg-b'));
    expect(result.get('pkg-c@2.5.3')).toBe(join(nm, 'pkg-c'));
  });

  it('discovers packages installed as symlinks (npm 7+ file: dep layout)', () => {
    // npm 7+ installs `file:` deps as symlinks in node_modules: the source
    // package lives elsewhere on disk and node_modules/<name> is a symlink
    // to it.  `Dirent.isDirectory()` returns false for such entries — only
    // `isSymbolicLink()` is true — so discoverPkgDirs must accept both.
    const sourceDir = join(testDir, 'src-pkg');
    writePkg(sourceDir, 'linked-pkg', '4.2.0');

    const nm = join(testDir, 'node_modules');
    mkdirSync(nm, { recursive: true });
    symlinkSync(sourceDir, join(nm, 'linked-pkg'), 'dir');

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(1);
    // The recorded path is the entry path under node_modules, not the
    // symlink target — callers join `package.json` paths against this.
    expect(result.get('linked-pkg@4.2.0')).toBe(join(nm, 'linked-pkg'));
  });

  it('discovers scoped packages installed as symlinks', () => {
    const sourceDir = join(testDir, 'src-scoped');
    writePkg(sourceDir, '@scope/linked', '0.5.0');

    const nm = join(testDir, 'node_modules');
    mkdirSync(join(nm, '@scope'), { recursive: true });
    symlinkSync(sourceDir, join(nm, '@scope', 'linked'), 'dir');

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(1);
    expect(result.get('@scope/linked@0.5.0')).toBe(join(nm, '@scope', 'linked'));
  });

  it('tolerates dangling symlinks silently', () => {
    const nm = join(testDir, 'node_modules');
    mkdirSync(nm, { recursive: true });
    // Symlink to a nonexistent target — ENOENT is handled inside readAndRegister.
    symlinkSync(join(testDir, 'nonexistent-target'), join(nm, 'broken-link'), 'dir');

    expect(() => discoverPkgDirs(nm)).not.toThrow();
    const result = discoverPkgDirs(nm);
    expect(result.size).toBe(0);
  });

  it('skips dotfiles within scope directories', () => {
    const nm = join(testDir, 'node_modules');

    // Valid scoped package
    writePkg(join(nm, '@scope', 'valid'), '@scope/valid', '1.0.0');

    // Dotfile within scope dir — must be skipped
    mkdirSync(join(nm, '@scope', '.bin'), { recursive: true });

    const result = discoverPkgDirs(nm);

    expect(result.size).toBe(1);
    expect(result.get('@scope/valid@1.0.0')).toBe(join(nm, '@scope', 'valid'));
  });
});

describe('discoverPkgDirs() — pnpm .pnpm virtual store', () => {
  it('discovers transitive deps that live only under .pnpm', () => {
    const nm = join(testDir, 'node_modules');
    // A transitive dep is present ONLY under .pnpm, never at top-level.
    writePkg(
      join(nm, '.pnpm', 'transitive@2.3.4', 'node_modules', 'transitive'),
      'transitive',
      '2.3.4',
    );

    const result = discoverPkgDirs(nm);

    expect(result.get('transitive@2.3.4')).toBe(
      join(nm, '.pnpm', 'transitive@2.3.4', 'node_modules', 'transitive'),
    );
  });

  it('registers the real package dir, not a sibling dependency symlink', () => {
    const nm = join(testDir, 'node_modules');
    // `host` lives at its own .pnpm entry (real dir).
    writePkg(join(nm, '.pnpm', 'host@1.0.0', 'node_modules', 'host'), 'host', '1.0.0');
    // `dep` lives at its own .pnpm entry, and is present beside `host` as a
    // SYMLINK (pnpm wires a package's deps in as links).
    writePkg(join(nm, '.pnpm', 'dep@2.0.0', 'node_modules', 'dep'), 'dep', '2.0.0');
    symlinkSync(
      join(nm, '.pnpm', 'dep@2.0.0', 'node_modules', 'dep'),
      join(nm, '.pnpm', 'host@1.0.0', 'node_modules', 'dep'),
      'dir',
    );

    const result = discoverPkgDirs(nm);

    // `dep` is registered at its OWN canonical real path — never the symlink
    // path under host's node_modules.
    expect(result.get('dep@2.0.0')).toBe(
      join(nm, '.pnpm', 'dep@2.0.0', 'node_modules', 'dep'),
    );
    expect(result.get('host@1.0.0')).toBe(
      join(nm, '.pnpm', 'host@1.0.0', 'node_modules', 'host'),
    );
  });

  it('discovers scoped packages inside the .pnpm store', () => {
    const nm = join(testDir, 'node_modules');
    writePkg(
      join(nm, '.pnpm', '@scope+tool@1.2.3', 'node_modules', '@scope', 'tool'),
      '@scope/tool',
      '1.2.3',
    );

    const result = discoverPkgDirs(nm);

    expect(result.get('@scope/tool@1.2.3')).toBe(
      join(nm, '.pnpm', '@scope+tool@1.2.3', 'node_modules', '@scope', 'tool'),
    );
  });

  it('the .pnpm real directory overrides a top-level symlink for a direct dep', () => {
    const nm = join(testDir, 'node_modules');
    const realDir = join(nm, '.pnpm', 'pkg@1.0.0', 'node_modules', 'pkg');
    writePkg(realDir, 'pkg', '1.0.0');
    // Direct dep: top-level node_modules/pkg is a symlink into .pnpm.
    symlinkSync(realDir, join(nm, 'pkg'), 'dir');

    const result = discoverPkgDirs(nm);

    // The canonical real .pnpm path wins over the top-level symlink path.
    expect(result.get('pkg@1.0.0')).toBe(realDir);
  });
});

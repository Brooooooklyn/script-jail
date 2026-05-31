// script-jail — test/scripts/main-package-manifest.test.ts
//
// PKG-4 guard for the MAIN `package.json` published as `script-jail`.
//
// After the cross-platform split, the main package is JS-only: it ships
// `dist/cli.cjs`, `dist/guest-agent.cjs`, the preload bundles, and the
// README. The runtime artifacts (rootfs / shim / VZ helper) now live in the
// three per-platform optional packages `@script-jail/{darwin-arm64,linux-x64,
// linux-arm64}`. The main package therefore must:
//   - NOT declare `os`/`cpu` (it must install everywhere so npm can pick the
//     one matching `optionalDependencies` entry for the host platform),
//   - list exactly the four JS-only `files` entries (no `images/` or `bin/`),
//   - pin all three optional deps to the package's own `version`,
//   - keep `bin.script-jail` pointed at `dist/cli.cjs`.
//
// This test reads the real `package.json` from the repo root directly (the
// canonical spec module `scripts/npm-packages.mjs` is PKG-1 and lands after
// PKG-4; PKG-4 is the authoritative source for these fields).

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pkgPath = fileURLToPath(new URL('../../package.json', import.meta.url));
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<
  string,
  unknown
>;

const EXPECTED_FILES = [
  'dist/cli.cjs',
  'dist/guest-agent.cjs',
  'dist/preloads/*.cjs',
  'README.md',
];

const OPTIONAL_DEP_NAMES = [
  '@script-jail/darwin-arm64',
  '@script-jail/linux-x64',
  '@script-jail/linux-arm64',
];

describe('main package.json (PKG-4)', () => {
  it('declares no os/cpu fields (must install on every platform)', () => {
    expect(pkg).not.toHaveProperty('os');
    expect(pkg).not.toHaveProperty('cpu');
  });

  it('files is exactly the four JS-only entries', () => {
    expect(pkg.files).toEqual(EXPECTED_FILES);
  });

  it('files references no images/ or bin/ runtime artifacts', () => {
    const files = pkg.files as string[];
    for (const entry of files) {
      expect(entry.startsWith('images/')).toBe(false);
      expect(entry.startsWith('bin/')).toBe(false);
    }
  });

  it('optionalDependencies are exactly the three scoped platform packages, all pinned to version', () => {
    const optional = pkg.optionalDependencies as Record<string, string>;
    expect(Object.keys(optional).sort()).toEqual([...OPTIONAL_DEP_NAMES].sort());
    for (const name of OPTIONAL_DEP_NAMES) {
      expect(optional[name]).toBe(pkg.version);
    }
  });

  it('bin.script-jail points at dist/cli.cjs', () => {
    const bin = pkg.bin as Record<string, string>;
    expect(bin['script-jail']).toBe('dist/cli.cjs');
  });
});

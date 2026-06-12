// script-jail — test/scripts/main-package-manifest.test.ts
//
// PKG-4 guard for the repo-root `package.json` (the dev manifest from which
// the published `script-jail` main package is derived).
//
// After the cross-platform split, the main package is JS-only: it ships
// `dist/cli.cjs`, `dist/guest-agent.cjs`, the preload bundles, and the
// README. The runtime artifacts (rootfs / shim / VZ helper) now live in the
// three per-platform optional packages `@script-jail/{darwin-arm64,linux-x64,
// linux-arm64}`.
//
// IMPORTANT — `optionalDependencies` live in the SPEC, not here. The repo-root
// `package.json` MUST NOT declare the `@script-jail/*` optional deps: those
// packages do not exist on the registry until the release publishes them, so
// listing them here makes `pnpm install --frozen-lockfile` fail with
// ERR_PNPM_OUTDATED_LOCKFILE on every clean checkout (including the release
// `build` job that produces the very artifacts being published). The published
// main manifest gets its `optionalDependencies` from `scripts/npm-packages.mjs`
// (PKG-1), injected by `scripts/assemble-npm-packages.mjs::buildMainManifest`
// (guarded by npm-packages.test.ts + assemble-npm-packages.test.ts). This test
// guards the repo-root manifest against re-introducing that lockfile break.
//
// The repo-root manifest therefore must:
//   - NOT declare `os`/`cpu` (it must install everywhere so npm can pick the
//     one matching `optionalDependencies` entry for the host platform),
//   - NOT declare `optionalDependencies` (see above),
//   - list exactly the four JS-only `files` entries (no `images/` or `bin/`),
//   - keep `bin.script-jail` pointed at `dist/cli.cjs`.

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
  // Preloads are listed EXPLICITLY (not a `dist/preloads/*.cjs` glob) so the
  // packlist gate can detect a missing one — see scripts/npm-packages.mjs.
  'dist/preloads/env-spy.cjs',
  'dist/preloads/platform-spoof.cjs',
  'dist/preloads/dlopen-block.cjs',
  'README.md',
];

describe('main package.json (PKG-4)', () => {
  it('declares no os/cpu fields (must install on every platform)', () => {
    expect(pkg).not.toHaveProperty('os');
    expect(pkg).not.toHaveProperty('cpu');
  });

  it('files is exactly the JS-only entries (explicit preloads, no glob)', () => {
    expect(pkg.files).toEqual(EXPECTED_FILES);
  });

  it('files references no images/ or bin/ runtime artifacts', () => {
    const files = pkg.files as string[];
    for (const entry of files) {
      expect(entry.startsWith('images/')).toBe(false);
      expect(entry.startsWith('bin/')).toBe(false);
    }
  });

  it('does NOT declare optionalDependencies (they live in the spec; declaring them here breaks frozen-lockfile installs)', () => {
    // The @script-jail/* platform packages are not on the registry until the
    // release publishes them, so a repo-root `optionalDependencies` entry has
    // no lockfile counterpart and fails `pnpm install --frozen-lockfile`. The
    // published manifest gets these deps from scripts/npm-packages.mjs via the
    // assembler instead.
    expect(pkg).not.toHaveProperty('optionalDependencies');
  });

  it('declares repository.url (required for npm OIDC trusted-publish provenance)', () => {
    // buildMainManifest spreads the root package.json into the published main
    // manifest; an empty/missing repository.url is rejected by npm provenance
    // with E422 (the v0.2.3 main-package publish failed exactly here). Must
    // match the repo the release.yml OIDC token is issued for.
    expect(pkg.repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/Brooooooklyn/script-jail.git',
    });
  });

  it('bin.script-jail points at dist/cli.cjs', () => {
    const bin = pkg.bin as Record<string, string>;
    expect(bin['script-jail']).toBe('dist/cli.cjs');
  });
});

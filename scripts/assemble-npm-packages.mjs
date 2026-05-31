#!/usr/bin/env node
// PKG-3: stage the four publishable npm package dirs from CI build artifacts.
//
// The release `publish` job downloads every build artifact into ./artifacts
// (the FC/Docker rootfs ext4s, the libscriptjail shims, the VZ kernel, the
// Mach-O VZ helper, and the committed dist/ JS bundles). This script turns
// those raw artifacts into four ready-to-`npm publish` package dirs under a
// staging root, using scripts/npm-packages.mjs as the single source of truth:
//
//   node scripts/assemble-npm-packages.mjs \
//     --artifacts <artifactsDir> --out <stagingRoot> --version <v>
//
// For each package in `npmPackages(version)`:
//   - create <stagingRoot>/<dir>/ (e.g. script-jail, script-jail-darwin-arm64),
//   - write a clean published package.json (2-space indent + trailing newline),
//   - materialize its artifacts (gzip or copy) with the spec file mode.
//
// MAIN PACKAGE: derived from the repo-root package.json so the published
// manifest stays in lockstep with the committed metadata, but with `files`
// and `optionalDependencies` overwritten from the canonical spec and the
// dev-only fields (devDependencies / scripts / packageManager) dropped. Its
// JS lives in the committed bundles, copied from <artifacts>/dist/...; the
// README is taken from the repo root. The main spec carries no `artifacts`.
//
// PLATFORM PACKAGES: each `artifacts` entry's `src` is resolved against the
// `--artifacts` dir (the rootfs ext4s / shims / kernel live under
// images/<name>; the VZ helper `script-jail-vm-arm64-darwin` lives at the
// artifacts root). `gzip:true` streams the source through zlib into `dest`;
// otherwise it is copied. Each `dest` is chmod'd to the spec `mode` (0o755 for
// the executable VZ helper, else 0o644).
//
// REPRODUCIBLE GZIP (MEDIUM fix WS2 reviewer #1): Node's zlib at a fixed level
// is RUN-TO-RUN deterministic (it writes no mtime / no FNAME header), which is
// all that is required — nothing pins the .ext4.gz SHA (the artifact manifest
// has no .gz entry, the packlist gate checks only file list / size / mode, and
// src/cli/rootfs-cache.ts validates the gz against a self-computed digest). We
// do NOT claim byte-identity with GNU `gzip -n`; that goal is unachievable
// (different OS-identifier header byte / deflate stream) and unnecessary.

import {
  createReadStream,
  createWriteStream,
  copyFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { createGzip, constants as zlibConstants } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { npmPackages } from './npm-packages.mjs';

// Fixed zlib level → run-to-run deterministic gz bytes (see header).
const GZIP_LEVEL = zlibConstants.Z_BEST_COMPRESSION;

const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

// The committed JS bundles shipped by the main package, relative to the
// artifacts dir's `dist/`. Mirrors the main spec `files` (the preload glob is
// expanded to the three default preloads injected at build time).
const MAIN_BUNDLE_FILES = [
  'dist/cli.cjs',
  'dist/guest-agent.cjs',
  'dist/preloads/env-spy.cjs',
  'dist/preloads/platform-spoof.cjs',
  'dist/preloads/dlopen-block.cjs',
];

await main(process.argv.slice(2));

async function main(argv) {
  const opts = parseArgs(argv);
  const packages = npmPackages(opts.version);

  // Validate every required source up front so a missing artifact fails the
  // whole run before any package dir is written.
  validateSources(packages, opts.artifactsDir);

  rmSync(opts.out, { recursive: true, force: true });
  mkdirSync(opts.out, { recursive: true });

  for (const pkg of packages) {
    const pkgDir = join(opts.out, pkg.dir);
    mkdirSync(pkgDir, { recursive: true });

    writeManifest(pkg, pkgDir);

    if (pkg.name === 'script-jail') {
      stageMainBundles(opts.artifactsDir, pkgDir);
    }

    for (const art of pkg.artifacts) {
      await materializeArtifact(art, opts.artifactsDir, pkgDir);
    }
  }

  console.log(
    `assembled ${packages.length} npm package(s) into ${opts.out} ` +
      `(version ${opts.version})`,
  );
}

function parseArgs(argv) {
  const opts = { artifactsDir: undefined, out: undefined, version: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case '--artifacts':
        opts.artifactsDir = value;
        i += 1;
        break;
      case '--out':
        opts.out = value;
        i += 1;
        break;
      case '--version':
        opts.version = value;
        i += 1;
        break;
      default:
        fail(`unknown argument: ${flag}`);
    }
  }
  if (!opts.artifactsDir) fail('--artifacts <dir> is required');
  if (!opts.out) fail('--out <stagingRoot> is required');
  if (!opts.version) fail('--version <v> is required');
  return opts;
}

// Confirm every source path exists before mutating the staging root, naming
// the first missing artifact (relative to the artifacts dir, plus the README).
function validateSources(packages, artifactsDir) {
  const missing = [];
  for (const pkg of packages) {
    if (pkg.name === 'script-jail') {
      for (const rel of MAIN_BUNDLE_FILES) {
        if (!existsSync(join(artifactsDir, rel))) missing.push(rel);
      }
      if (!existsSync(join(REPO_ROOT, 'README.md'))) missing.push('README.md');
    }
    for (const art of pkg.artifacts) {
      if (!existsSync(join(artifactsDir, art.src))) missing.push(art.src);
    }
  }
  if (missing.length > 0) {
    fail(
      `missing artifact(s) under ${artifactsDir}:\n` +
        missing.map((m) => `  ${m}`).join('\n'),
    );
  }
}

function writeManifest(pkg, pkgDir) {
  const manifest =
    pkg.name === 'script-jail'
      ? buildMainManifest(pkg)
      : pkg.packageJson;
  writeFileSync(
    join(pkgDir, 'package.json'),
    JSON.stringify(manifest, null, 2) + '\n',
  );
}

// Derive the published main manifest from the repo-root package.json, keeping
// it in lockstep with the committed metadata while overwriting the
// publish-relevant fields from the canonical spec and dropping dev-only fields.
function buildMainManifest(pkg) {
  const root = JSON.parse(
    readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'),
  );
  const {
    devDependencies: _dev,
    scripts: _scripts,
    packageManager: _pm,
    files: _files,
    optionalDependencies: _opt,
    ...kept
  } = root;
  return {
    ...kept,
    version: pkg.packageJson.version,
    files: pkg.packageJson.files,
    optionalDependencies: pkg.packageJson.optionalDependencies,
  };
}

function stageMainBundles(artifactsDir, pkgDir) {
  for (const rel of MAIN_BUNDLE_FILES) {
    const dest = join(pkgDir, rel);
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(join(artifactsDir, rel), dest);
    chmodSync(dest, 0o644);
  }
  const readmeDest = join(pkgDir, 'README.md');
  copyFileSync(join(REPO_ROOT, 'README.md'), readmeDest);
  chmodSync(readmeDest, 0o644);
}

async function materializeArtifact(art, artifactsDir, pkgDir) {
  const src = join(artifactsDir, art.src);
  const dest = join(pkgDir, art.dest);
  mkdirSync(dirname(dest), { recursive: true });

  if (art.gzip) {
    await pipeline(
      createReadStream(src),
      createGzip({ level: GZIP_LEVEL }),
      createWriteStream(dest),
    );
  } else {
    copyFileSync(src, dest);
  }

  chmodSync(dest, art.mode ?? 0o644);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

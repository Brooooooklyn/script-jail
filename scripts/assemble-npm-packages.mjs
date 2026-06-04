#!/usr/bin/env node
// PKG-3: stage the four publishable npm package dirs from CI build artifacts.
//
// The release `publish` job downloads the producer's BINARY build artifacts
// into ./artifacts (the FC/Docker rootfs ext4s, the libscriptjail shims, the
// VZ kernel, and the Mach-O VZ helper). The committed dist/ JS bundles are NOT
// downloaded — they are read from REPO_ROOT (the tagged checkout). This script
// turns those inputs into four ready-to-`npm publish` package dirs under a
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
// DIST vs BINARY SOURCE SPLIT (build-once / download-forever):
//   - The JS bundles (`dist/*`: cli.cjs, guest-agent.cjs, preloads) come from
//     REPO_ROOT — the TAGGED checkout, whose committed bundles carry the REAL
//     backfilled manifest. The producer workflow's artifacts intentionally do
//     NOT carry dist/* (its dist/main.cjs would embed the PRE-backfill
//     placeholder manifest), so taking dist from the producer would publish a
//     broken Action.
//   - The BINARY image assets (rootfs ext4s, shims, kernels, Mach-O VZ helper)
//     come from `--artifacts` (the producer's uploaded build artifacts). These
//     are manifest-invariant and cannot be rebuilt at tag time.
//
// MAIN PACKAGE: derived from the repo-root package.json so the published
// manifest stays in lockstep with the committed metadata, but with `files`
// and `optionalDependencies` overwritten from the canonical spec and the
// dev-only fields (devDependencies / scripts / packageManager) dropped. Its
// JS lives in the committed bundles, copied from REPO_ROOT/dist/...; the
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

import { npmPackages, MAIN_PRELOADS } from './npm-packages.mjs';

// Fixed zlib level → run-to-run deterministic gz bytes (see header).
const GZIP_LEVEL = zlibConstants.Z_BEST_COMPRESSION;

const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

// The committed JS bundles shipped by the main package, relative to REPO_ROOT's
// `dist/` (NOT the artifacts dir — see the dist-vs-binary split in the header).
// The preload list comes from MAIN_PRELOADS (PKG-1) so the staged set and the
// packlist-gated set are the same single source.
const MAIN_BUNDLE_FILES = [
  'dist/cli.cjs',
  'dist/guest-agent.cjs',
  ...MAIN_PRELOADS.map((name) => `dist/preloads/${name}`),
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
      stageMainBundles(pkgDir);
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
// the first missing artifact. The dist/* JS bundles + README resolve against
// REPO_ROOT (the tagged checkout); the binary `artifacts` resolve against the
// producer's downloaded artifacts dir (see the dist-vs-binary split header).
function validateSources(packages, artifactsDir) {
  const missing = [];
  for (const pkg of packages) {
    if (pkg.name === 'script-jail') {
      for (const rel of MAIN_BUNDLE_FILES) {
        if (!existsSync(join(REPO_ROOT, rel))) missing.push(`${rel} (REPO_ROOT)`);
      }
      if (!existsSync(join(REPO_ROOT, 'README.md'))) {
        missing.push('README.md (REPO_ROOT)');
      }
    }
    for (const art of pkg.artifacts) {
      if (!existsSync(join(artifactsDir, art.src))) {
        missing.push(`${art.src} (artifacts)`);
      }
    }
  }
  if (missing.length > 0) {
    fail(
      `missing source(s) (dist/* + README from REPO_ROOT, binaries from ` +
        `${artifactsDir}):\n` +
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

// Stage the main package's committed JS bundles + README from REPO_ROOT — the
// TAGGED checkout, whose dist/* carries the real backfilled manifest. These are
// deliberately NOT sourced from the producer's artifacts (see header).
function stageMainBundles(pkgDir) {
  for (const rel of MAIN_BUNDLE_FILES) {
    const dest = join(pkgDir, rel);
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(join(REPO_ROOT, rel), dest);
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

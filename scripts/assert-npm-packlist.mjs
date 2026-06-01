#!/usr/bin/env node
// PKG-2: per-package npm packlist gate.
//
// npm silently omits missing `files` entries, so `npm pack --dry-run` alone is
// not a release gate. This script reads a *staged* package's `package.json`,
// looks up its canonical spec in scripts/npm-packages.mjs (the single source of
// truth for the cross-platform split), and asserts the `npm pack --dry-run
// --json` output matches the spec's `files` exactly, plus:
//   - the darwin VZ helper `script-jail-vm` is executable (mode 0o755), and
//   - the packed size is within the package's `maxPackBytes`.
//
// The canonical `files` lists are fully explicit (the main package enumerates
// its preloads rather than globbing `dist/preloads/*.cjs`), so a MISSING file
// is a real mismatch here. A leftover glob-expansion branch remains for
// defensiveness but is not exercised by the canonical packages.
//
// Usage:
//   node scripts/assert-npm-packlist.mjs [<stagingDir>]   # one package (default ".")
//   node scripts/assert-npm-packlist.mjs --all <stagingRoot>   # every subdir
//
// `SCRIPT_JAIL_NPM_MAX_PACK_BYTES` overrides the per-package size cap.
//
// LOW fix (WS2 reviewer #3): the only mode assertion is the 0o755 exec bit on
// the darwin VZ helper `script-jail-vm`. `npm pack --dry-run --json` reports
// the main package's `dist/cli.cjs` at 0o644 even though it is the `bin`
// target — npm flips the exec bit at install time — so do NOT add a 0o755
// check on the main package's bin.

import { spawnSync } from 'node:child_process';
import { readFileSync, globSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { npmPackages } from './npm-packages.mjs';

main(process.argv.slice(2));

function main(argv) {
  if (argv[0] === '--all') {
    const root = argv[1];
    if (!root) fail('--all requires a staging root directory');
    // The staged dirs MUST be EXACTLY the canonical package set. An incomplete
    // (or extra) staging that slipped through would otherwise publish a partial
    // set — and `npm publish` is non-transactional and non-re-runnable for an
    // already-published version, so a half-published release cannot be retried.
    // Dir names do not depend on the version, so a placeholder is fine here.
    const expectedDirs = npmPackages('0.0.0')
      .map((p) => p.dir)
      .sort();
    const actualDirs = readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
    const missing = expectedDirs.filter((d) => !actualDirs.includes(d));
    const extra = actualDirs.filter((d) => !expectedDirs.includes(d));
    if (missing.length > 0 || extra.length > 0) {
      fail(
        `staged package dirs under ${root} do not match the canonical set\n` +
          `  expected:   ${expectedDirs.join(', ')}\n` +
          `  missing:    ${missing.length ? missing.join(', ') : '(none)'}\n` +
          `  unexpected: ${extra.length ? extra.join(', ') : '(none)'}`,
      );
    }
    for (const dir of expectedDirs) {
      assertPackage(join(root, dir));
    }
    console.log(
      `npm packlist ok: ${expectedDirs.length} canonical package(s) under ${root}`,
    );
    return;
  }

  const dir = argv[0] ?? '.';
  assertPackage(dir);
}

function assertPackage(dir) {
  const manifest = readPackageJson(dir);
  const spec = lookupSpec(manifest);

  const expectedFiles = expandExpectedFiles(dir, spec).sort();
  const pack = runNpmPack(dir);

  const actualFiles = Array.isArray(pack.files)
    ? pack.files
        .map((entry) => entry?.path)
        .filter((path) => typeof path === 'string')
        .sort()
    : [];

  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    fail(
      `npm pack file list mismatch for ${manifest.name} (${dir})\n` +
        `expected:\n${expectedFiles.map((f) => `  ${f}`).join('\n')}\n` +
        `actual:\n${actualFiles.map((f) => `  ${f}`).join('\n')}`,
    );
  }

  // The darwin VZ helper must remain executable (0o755). npm flips the bin's
  // exec bit at install time, so the main package's `dist/cli.cjs` is reported
  // at 0o644 here — do NOT assert 0o755 on it.
  const helper = pack.files.find((entry) => entry.path === 'script-jail-vm');
  if (helper && (helper.mode & 0o755) !== 0o755) {
    fail(
      `script-jail-vm must be executable (mode 0o755) in ${manifest.name}, ` +
        `got mode 0o${helper.mode.toString(8)}`,
    );
  }

  const maxPackBytes = resolveMaxPackBytes(spec);
  if (typeof pack.size !== 'number' || pack.size > maxPackBytes) {
    fail(
      `${manifest.name} npm pack size ${pack.size} exceeds limit ${maxPackBytes}`,
    );
  }

  console.log(
    `npm packlist ok: ${manifest.name} — ${actualFiles.length} files, ` +
      `${formatBytes(pack.size)} packed`,
  );
}

function readPackageJson(dir) {
  const path = join(dir, 'package.json');
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    fail(`cannot read ${path}: ${err.message}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (err) {
    fail(`invalid JSON in ${path}: ${err.message}`);
  }
  if (typeof manifest.name !== 'string' || !manifest.name) {
    fail(`${path} is missing a string "name"`);
  }
  if (typeof manifest.version !== 'string' || !manifest.version) {
    fail(`${path} is missing a string "version"`);
  }
  return manifest;
}

function lookupSpec(manifest) {
  const specs = npmPackages(manifest.version);
  const spec = specs.find((p) => p.name === manifest.name);
  if (!spec) {
    fail(
      `staged package "${manifest.name}" is not one of the canonical packages: ` +
        specs.map((p) => p.name).join(', '),
    );
  }
  return spec;
}

// Expected packed paths = spec `files` (globs expanded against the staged dir)
// plus the always-included package.json.
function expandExpectedFiles(dir, spec) {
  const files = spec.packageJson.files;
  if (!Array.isArray(files)) {
    fail(`spec for ${spec.name} has no "files" array`);
  }
  const expected = new Set(['package.json']);
  for (const pattern of files) {
    if (pattern.includes('*')) {
      const matches = globSync(pattern, { cwd: dir });
      if (matches.length === 0) {
        fail(`no files matched "${pattern}" in ${dir}`);
      }
      for (const match of matches) {
        // Normalize to forward-slash POSIX paths to match npm pack output.
        expected.add(relative(dir, join(dir, match)).split('\\').join('/'));
      }
    } else {
      expected.add(pattern);
    }
  }
  return [...expected];
}

function runNpmPack(dir) {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: dir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.status !== 0) {
    fail(`npm pack --dry-run failed in ${dir}\n${result.stderr}${result.stdout}`);
  }

  let packs;
  try {
    packs = JSON.parse(result.stdout);
  } catch {
    fail(`npm pack --dry-run did not return JSON in ${dir}:\n${result.stdout}`);
  }

  if (!Array.isArray(packs) || packs.length !== 1) {
    fail(`expected one npm pack result in ${dir}, got ${JSON.stringify(packs)}`);
  }

  const pack = packs[0];
  if (typeof pack !== 'object' || pack === null || !Array.isArray(pack.files)) {
    fail(`invalid npm pack result in ${dir}: ${JSON.stringify(pack)}`);
  }
  return pack;
}

function resolveMaxPackBytes(spec) {
  const override = process.env.SCRIPT_JAIL_NPM_MAX_PACK_BYTES;
  if (override !== undefined) {
    const parsed = Number.parseInt(override, 10);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      fail(`invalid SCRIPT_JAIL_NPM_MAX_PACK_BYTES: ${override}`);
    }
    return parsed;
  }
  if (typeof spec.maxPackBytes !== 'number' || spec.maxPackBytes <= 0) {
    fail(`spec for ${spec.name} has no positive maxPackBytes`);
  }
  return spec.maxPackBytes;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function formatBytes(value) {
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

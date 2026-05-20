// Walk node_modules, return Map<"name@version", absolute-dir-path>.
//
// Handles flat layout (npm/yarn classic) AND @scope/<pkg> subdirs.
// Skips dotfiles (.bin, .package-lock.json, .modules.yaml, .pnpm, etc.).
// Reads each <dir>/package.json; tolerates missing/invalid manifests (skip + log to process.stderr).

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Walk a node_modules directory and return a Map from "name@version" to the
 * absolute directory path of that package.
 *
 * Layout rules:
 *   - Entries starting with `.` are skipped (npm dotfiles: .bin, .package-lock.json, etc.)
 *   - Entries starting with `@` are scope directories; each subdirectory within
 *     them is treated as a scoped package (one level of recursion only).
 *   - All other directories are assumed to be packages; their package.json is
 *     read to extract `name` and `version`.  If either is missing or the file
 *     is unparseable, the package is skipped with a stderr warning.
 *   - The parsed `name` from package.json is used as the key (NOT the filesystem
 *     dirname) to handle `file:` deps and other cases where the dir name differs.
 *
 * pnpm: with the default isolated layout, only DIRECT dependencies appear in
 * the top-level node_modules; every transitive dependency lives ONLY under
 * `node_modules/.pnpm/<name>@<version>(_<peerhash>)/node_modules/<name>`.
 * The top-level pass above therefore finds only direct deps for a pnpm
 * install.  After it we walk `.pnpm/` (see {@link scanPnpmVirtualStore}) so
 * every package that can run a lifecycle script is registered — otherwise
 * `normalize()` throws on the first transitive-dependency event.
 *
 * Returns an empty Map if `nodeModulesDir` does not exist or cannot be read.
 */
export function discoverPkgDirs(nodeModulesDir: string): Map<string, string> {
  const result = new Map<string, string>();

  let entries: import('node:fs').Dirent<string>[];
  try {
    entries = readdirSync(nodeModulesDir, { withFileTypes: true, encoding: 'utf8' });
  } catch {
    // node_modules doesn't exist yet or isn't readable — return empty map.
    return result;
  }

  for (const entry of entries) {
    // Skip dotfiles (.bin, .package-lock.json, .modules.yaml, .pnpm, etc.)
    if (entry.name.startsWith('.')) continue;

    const entryPath = join(nodeModulesDir, entry.name);

    if (entry.name.startsWith('@')) {
      // Scoped package directory — recurse one level.
      let scopeEntries: import('node:fs').Dirent<string>[];
      try {
        scopeEntries = readdirSync(entryPath, { withFileTypes: true, encoding: 'utf8' });
      } catch {
        continue; // unreadable scope dir — skip
      }
      for (const scopeEntry of scopeEntries) {
        if (scopeEntry.name.startsWith('.')) continue;
        // Accept directories AND symlinks: npm 7+ installs `file:` deps as
        // symlinks pointing at the source dir, and `Dirent.isDirectory()`
        // returns false for them (the entry itself is a link, not a dir).
        // The downstream `readAndRegister` is ENOENT-tolerant, so dangling
        // links fall through silently.
        if (!scopeEntry.isDirectory() && !scopeEntry.isSymbolicLink()) continue;
        const pkgPath = join(entryPath, scopeEntry.name);
        readAndRegister(pkgPath, result);
      }
    } else {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      readAndRegister(entryPath, result);
    }
  }

  // pnpm isolated layout: register every package in the `.pnpm/` virtual
  // store.  Runs AFTER the top-level pass so a package's real `.pnpm`
  // directory — where pnpm actually executes its lifecycle scripts, and the
  // path strace records — overrides the top-level symlink path that the pass
  // above registered for direct dependencies.
  scanPnpmVirtualStore(join(nodeModulesDir, '.pnpm'), result);

  return result;
}

/**
 * Walk pnpm's `.pnpm` virtual store and register every package's canonical
 * real directory.  pnpm lays each resolved package out at
 *   .pnpm/<name>@<version>(_<peerhash>)/node_modules/<name>
 * with that package's own dependencies present alongside it as SYMLINKS.
 * We register only the real directories (the packages themselves) and skip
 * the symlinks (each linked dependency is registered via its own `.pnpm`
 * entry), so every package maps to the directory pnpm runs its scripts in.
 *
 * No-op when `.pnpm` does not exist (npm / yarn, or pnpm with
 * `node-linker=hoisted`).
 */
function scanPnpmVirtualStore(pnpmDir: string, result: Map<string, string>): void {
  let flatEntries: import('node:fs').Dirent<string>[];
  try {
    flatEntries = readdirSync(pnpmDir, { withFileTypes: true, encoding: 'utf8' });
  } catch {
    return; // no .pnpm dir — not a default-layout pnpm install
  }

  for (const flat of flatEntries) {
    // Each `<name>@<version>(_<peerhash>)` entry is a directory; skip
    // `lock.yaml` and any other non-directory bookkeeping files.
    if (!flat.isDirectory()) continue;

    const innerNm = join(pnpmDir, flat.name, 'node_modules');
    let innerEntries: import('node:fs').Dirent<string>[];
    try {
      innerEntries = readdirSync(innerNm, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      continue; // no node_modules inside this entry — skip
    }

    for (const inner of innerEntries) {
      if (inner.name.startsWith('.')) continue;
      // Symlinks are this package's dependency links — registered via their
      // own `.pnpm` entry.  Only real directories are packages that
      // physically live here.
      if (inner.isSymbolicLink() || !inner.isDirectory()) continue;

      if (inner.name.startsWith('@')) {
        // Scope grouping directory — recurse one level.
        const scopeDir = join(innerNm, inner.name);
        let scopeEntries: import('node:fs').Dirent<string>[];
        try {
          scopeEntries = readdirSync(scopeDir, { withFileTypes: true, encoding: 'utf8' });
        } catch {
          continue;
        }
        for (const se of scopeEntries) {
          if (se.name.startsWith('.')) continue;
          if (se.isSymbolicLink() || !se.isDirectory()) continue;
          readAndRegister(join(scopeDir, se.name), result);
        }
      } else {
        readAndRegister(join(innerNm, inner.name), result);
      }
    }
  }
}

function readAndRegister(pkgPath: string, result: Map<string, string>): void {
  const manifestPath = join(pkgPath, 'package.json');
  let raw: string;
  try {
    raw = readFileSync(manifestPath, 'utf8');
  } catch (err) {
    // Missing package.json — skip silently (some packages lack one, e.g. .bin symlinks).
    // EACCES or other OS errors get a stderr warning since they may indicate a problem.
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      process.stderr.write(
        `[discover-pkg-dirs] warning: could not read ${manifestPath}: ${String(err)}\n`,
      );
    }
    return;
  }

  let manifest: unknown;
  try {
    manifest = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(
      `[discover-pkg-dirs] warning: invalid JSON in ${manifestPath}: ${String(err)}\n`,
    );
    return;
  }

  if (
    typeof manifest !== 'object' ||
    manifest === null ||
    typeof (manifest as Record<string, unknown>)['name'] !== 'string' ||
    typeof (manifest as Record<string, unknown>)['version'] !== 'string'
  ) {
    // Missing name or version — skip silently (workspace roots, etc. may have these).
    return;
  }

  const name = (manifest as Record<string, unknown>)['name'] as string;
  const version = (manifest as Record<string, unknown>)['version'] as string;
  if (!name || !version) return;

  result.set(`${name}@${version}`, pkgPath);
}

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
 * pnpm: the `.pnpm/` virtual store is skipped (starts with `.`); pnpm hoists
 * the canonical name-keyed layout into `node_modules/<name>` anyway.
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
        if (!scopeEntry.isDirectory()) continue;
        const pkgPath = join(entryPath, scopeEntry.name);
        readAndRegister(pkgPath, result);
      }
    } else {
      if (!entry.isDirectory()) continue;
      readAndRegister(entryPath, result);
    }
  }

  return result;
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

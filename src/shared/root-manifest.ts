// script-jail — src/shared/root-manifest.ts
//
// script-jail reads the ROOT project manifest exclusively as `package.json`
// (root identity / name / version, lifecycle scripts, pnpm config).  pnpm
// (uniquely among the supported managers) ALSO accepts `package.yaml` and
// `package.json5` as the root manifest and reads `pnpm.configDependencies` +
// lifecycle scripts from them.  A repo that uses one of those alternates would
// slip past our package.json-only reasoning two ways:
//   * `pnpm.configDependencies` in the alternate → a pre-trust fetch/extract of
//     an attacker-published config package during the host no-scripts install,
//   * lifecycle scripts in the alternate → on a nameless root they run with
//     npm_package_name UNSET, their events drop at the null-attribution gate, and
//     the lock looks deceptively clean (the FIX-C class, reached via the manifest
//     format instead of a missing `name`).
//
// `package.json` SHADOWS the alternates (pnpm ignores `package.yaml` /
// `package.json5` whenever a `package.json` exists — verified on pnpm 10/11), so
// the gap is reachable ONLY when there is no `package.json`.  We have no JSON5
// parser and parsing the alternate would not, by itself, make the rest of the
// pipeline manifest-format-aware — so the safe, complete move is to FAIL CLOSED
// on that exact shape (no `package.json` + an alternate present).  Both the
// install preflight (host side) and the guest agent consult this single source.

import { existsSync } from 'node:fs';
import { join } from 'node:path';

/** Alternate root-manifest basenames pnpm accepts (besides package.json). */
const ALT_ROOT_MANIFESTS = ['package.yaml', 'package.json5'] as const;

/**
 * The alternate root-manifest basename when the repo uses one WITHOUT a
 * `package.json` (the exploitable shape), else null.  When a `package.json`
 * exists it shadows the alternates, so there is nothing to flag.
 */
export function unsupportedAltRootManifest(repoDir: string): string | null {
  if (existsSync(join(repoDir, 'package.json'))) return null;
  for (const name of ALT_ROOT_MANIFESTS) {
    if (existsSync(join(repoDir, name))) return name;
  }
  return null;
}

// npm-jar — scripts/validate-manifest.ts
//
// Release-workflow gate.  Invoked from `.github/workflows/release.yml` at
// the top of the `build` job to refuse to publish a tag whose
// `PINNED_MANIFEST.expected` still contains placeholder strings (or any
// other non-canonical 64-char lowercase-hex value).
//
// The same validator runs at action startup from `src/main.ts`; running it
// here as well moves the failure from "every consumer's CI" to "the
// maintainer's tag push", which is the place where it can actually be
// fixed.  See `src/action/validate-manifest.ts` for the underlying check.

import { PINNED_MANIFEST } from '../src/action/artifact-manifest.js';
import { validateManifest } from '../src/action/validate-manifest.js';

try {
  validateManifest(PINNED_MANIFEST);
  console.log(
    `validate-manifest: OK — all ${Object.keys(PINNED_MANIFEST.expected).length} ` +
      `entries in PINNED_MANIFEST.expected are canonical 64-char lowercase hex.`,
  );
} catch (err) {
  process.stderr.write(
    `${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(1);
}

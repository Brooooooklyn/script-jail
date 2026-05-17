// npm-jar — scripts/validate-manifest.ts
//
// Release-workflow gate.  Invoked from `.github/workflows/release.yml` at
// the top of the `build` job to report on `PINNED_MANIFEST.expected`.
//
// The same validator runs at action startup from `src/main.ts`; running it
// here as well moves the failure from "every consumer's CI" to "the
// maintainer's tag push", which is the place where it can actually be
// fixed.  See `src/action/validate-manifest.ts` for the underlying check.
//
// Modes:
//   (default)                — hard-fail (exit 1) on any non-canonical entry.
//   --warn-only-placeholders — exit 0 ONLY when every offending entry is a
//                              recognised `PLACEHOLDER_SHA256_*` bootstrap
//                              string; any other malformed value (wrong
//                              length, uppercase hex, accidental typo) still
//                              exits 1.  This mode exists so the release
//                              workflow can tolerate the documented "first
//                              tag on a fresh fork" bootstrap loop without
//                              also silencing real packaging bugs.
//
// The library validator (`src/action/validate-manifest.ts`) is intentionally
// strict and has no flag — it is the consumer-facing hard-fail.

import { PINNED_MANIFEST } from '../src/action/artifact-manifest.js';
import { validateManifest } from '../src/action/validate-manifest.js';

/**
 * Canonical SHA-256 hex digest.  Mirrors `SHA256_HEX_RE` in
 * src/action/validate-manifest.ts; duplicated here (not exported) because
 * the library validator's API is "throw on any failure" and we deliberately
 * do not widen it for this single CLI use-case.
 */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * The bootstrap placeholder strings live in src/action/artifact-manifest.ts
 * as `PLACEHOLDER_SHA256_<NAME>`.  We recognise only this exact prefix —
 * any other malformed value (typo'd hash, uppercase, wrong length) is
 * treated as a real bug and re-raised, even under --warn-only-placeholders.
 */
const PLACEHOLDER_PREFIX = 'PLACEHOLDER_SHA256_';

const args = process.argv.slice(2);
const warnOnlyPlaceholders = args.includes('--warn-only-placeholders');

try {
  validateManifest(PINNED_MANIFEST);
  console.log(
    `validate-manifest: OK — all ${Object.keys(PINNED_MANIFEST.expected).length} ` +
      `entries in PINNED_MANIFEST.expected are canonical 64-char lowercase hex.`,
  );
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);

  if (warnOnlyPlaceholders) {
    // Re-classify offenders: are they ALL recognised bootstrap placeholders,
    // or did something else slip in (uppercase, wrong length, typo)?  Only
    // the all-placeholder case is the documented bootstrap loop — anything
    // else is a real bug and must still hard-fail the release.
    const offenders: Array<{ name: string; value: string }> = [];
    const nonPlaceholder: string[] = [];
    for (const [name, value] of Object.entries(PINNED_MANIFEST.expected)) {
      if (!SHA256_HEX_RE.test(value)) {
        offenders.push({ name, value });
        if (!value.startsWith(PLACEHOLDER_PREFIX)) {
          nonPlaceholder.push(name);
        }
      }
    }

    if (nonPlaceholder.length === 0 && offenders.length > 0) {
      // All-placeholder bootstrap state.  Print the validator's message to
      // stderr (so it still appears in CI logs) and exit 0.
      process.stderr.write(`${message}\n`);
      process.stderr.write(
        `validate-manifest: --warn-only-placeholders — all ${offenders.length} ` +
          `offending entries are bootstrap placeholders; treating as warning.\n`,
      );
      process.exit(0);
    }

    // Mixed or non-placeholder failure: hard-fail despite the flag, with an
    // extra explanatory line so the maintainer understands why warn-only
    // did NOT save them.
    process.stderr.write(`${message}\n`);
    process.stderr.write(
      `validate-manifest: --warn-only-placeholders does NOT suppress this ` +
        `failure: non-placeholder offenders present (` +
        `[${nonPlaceholder.join(', ')}]). Fix these by writing real ` +
        `64-char lowercase-hex SHA-256 digests into ` +
        `src/action/artifact-manifest.ts.\n`,
    );
    process.exit(1);
  }

  process.stderr.write(`${message}\n`);
  process.exit(1);
}

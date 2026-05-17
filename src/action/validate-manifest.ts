// script-jail — src/action/validate-manifest.ts
//
// Fail-fast startup check for `PINNED_MANIFEST`.  Every value in
// `manifest.expected` must be a canonical 64-char lowercase-hex SHA-256
// digest; anything else (placeholder strings, wrong length, uppercase hex)
// means the action was published without real release-asset hashes and the
// pre-fetch step is guaranteed to fail later — but only AFTER downloading
// multi-MB artifacts, with a confusing "SHA-256 mismatch" message that does
// not point the user at the underlying packaging bug.
//
// Wired from two places:
//   1. `src/main.ts` calls this very early so the action exits before any
//      filesystem or network side effects.
//   2. `.github/workflows/release.yml` invokes `scripts/validate-manifest.ts`
//      at the top of the build job so a maintainer cannot publish a tag
//      whose manifest would 100% fail for every consumer.
//
// We intentionally accept ONLY lowercase hex.  Both `sha256sum` and Node's
// `createHash('sha256').digest('hex')` emit lowercase, and the runtime
// comparison in `pre-fetch-artifacts.ts` is byte-equal — so anything but
// canonical lowercase guarantees a runtime mismatch even when the bytes are
// otherwise correct.

import type { ArtifactManifest } from './pre-fetch-artifacts.js';

/** Path the error message points the user to. */
const MANIFEST_PATH = 'src/action/artifact-manifest.ts';

/** Canonical SHA-256 hex digest: exactly 64 lowercase hex characters. */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * Validate that every entry in `manifest.expected` is a canonical 64-char
 * lowercase-hex SHA-256.  Throws a single descriptive error listing every
 * offending entry name so the user fixes them all in one round-trip.
 */
export function validateManifest(manifest: ArtifactManifest): void {
  const offenders: string[] = [];
  for (const [name, value] of Object.entries(manifest.expected)) {
    if (!SHA256_HEX_RE.test(value)) {
      offenders.push(name);
    }
  }
  if (offenders.length === 0) return;

  throw new Error(
    `script-jail: action artifact manifest at ${MANIFEST_PATH} has unpinned ` +
      `entries: [${offenders.join(', ')}]. This indicates the action was ` +
      `published without real release-asset hashes. Open a GitHub issue ` +
      `against the action repository (${manifest.repo}).`,
  );
}

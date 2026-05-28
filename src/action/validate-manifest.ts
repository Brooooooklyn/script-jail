// script-jail — src/action/validate-manifest.ts
//
// Fail-fast startup check for `PINNED_MANIFEST`.  Every value in
// `manifest.expected` must be a canonical 64-char lowercase-hex SHA-256
// digest, and every Docker image ref must be digest-pinned; anything else
// (placeholder strings, wrong length, uppercase hex, tag-only images) means
// the action was published without real release pins and would fail later
// with a less useful download/pull error.
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

import type {
  ArtifactManifest,
  ManifestPlatform,
} from './pre-fetch-artifacts.js';

/** Path the error message points the user to. */
const MANIFEST_PATH = 'src/action/artifact-manifest.ts';

/** Canonical SHA-256 hex digest: exactly 64 lowercase hex characters. */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const DOCKER_DIGEST_RE = /@sha256:([0-9a-f]{64})$/;

/** Platforms iterated by `validateManifest`.  Order matters only for the
 *  resulting offender list (linux before darwin), which is otherwise
 *  unstable across map-iteration changes. */
const PLATFORMS: ReadonlyArray<ManifestPlatform> = ['linux', 'darwin'];

/**
 * Validate that every entry in `manifest.expected[platform]` is a canonical
 * 64-char lowercase-hex SHA-256, for every platform.  Throws a single
 * descriptive error listing every offending entry (prefixed with
 * `<platform>/`) so the user fixes them all in one round-trip.
 *
 * Also enforces the current manifest shape: `expected` MUST be platform-keyed
 * (`{ linux: {...}, darwin: {...} }`).  A flat manifest is rejected outright
 * — a maintainer who pastes the pre-PR-5 layout would otherwise silently
 * produce a zero-offender pass.
 */
export function validateManifest(manifest: ArtifactManifest): void {
  // Shape gate: the platform-keyed layout is the only legal shape.
  // We check for the two known section keys explicitly rather than rejecting
  // "anything that doesn't match the union", which would mis-fire on a
  // manifest that ships extra (future) platform sections.
  const expected = manifest.expected as
    | Readonly<Record<string, unknown>>
    | undefined;
  if (
    expected === undefined ||
    typeof expected !== 'object' ||
    expected.linux === undefined ||
    expected.darwin === undefined ||
    typeof expected.linux !== 'object' ||
    typeof expected.darwin !== 'object'
  ) {
    throw new Error(
      `script-jail: action artifact manifest at ${MANIFEST_PATH} is not ` +
        `platform-keyed.  Expected \`expected: { linux: {...}, darwin: {...} }\`. ` +
        `Open a GitHub issue against the action repository (${manifest.repo}).`,
    );
  }

  const offenders: string[] = [];
  for (const platform of PLATFORMS) {
    const section = manifest.expected[platform];
    for (const [name, value] of Object.entries(section)) {
      if (!SHA256_HEX_RE.test(value)) {
        offenders.push(`${platform}/${name}`);
      }
    }
  }
  if (manifest.dockerImages !== undefined) {
    for (const [arch, images] of Object.entries(manifest.dockerImages)) {
      for (const [runnerImage, ref] of Object.entries(images)) {
        if (!DOCKER_DIGEST_RE.test(ref)) {
          offenders.push(`docker/${arch}/${runnerImage}`);
        }
      }
    }
  }
  if (offenders.length === 0) return;

  throw new Error(
    `script-jail: action artifact manifest at ${MANIFEST_PATH} has unpinned ` +
      `entries: [${offenders.join(', ')}]. This indicates the action was ` +
      `published without real release-asset hashes or Docker image refs. Open a GitHub issue ` +
      `against the action repository (${manifest.repo}).`,
  );
}

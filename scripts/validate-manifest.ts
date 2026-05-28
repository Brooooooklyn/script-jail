// script-jail — scripts/validate-manifest.ts
//
// Release-workflow gate.  Invoked from `.github/workflows/release.yml` at
// the top of the `build` job to report on `PINNED_MANIFEST.expected` and
// Docker image refs.
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
//                              length, uppercase hex, accidental typo,
//                              tag-only Docker ref) still exits 1.  This mode exists so the release
//                              workflow can tolerate the documented "first
//                              tag on a fresh fork" bootstrap loop without
//                              also silencing real packaging bugs.
//
// The library validator (`src/action/validate-manifest.ts`) is intentionally
// strict and has no flag — it is the consumer-facing hard-fail.

import { PINNED_MANIFEST } from '../src/action/artifact-manifest.js';
import { validateManifest } from '../src/action/validate-manifest.js';
import type {
  ArtifactArch,
  ManifestPlatform,
} from '../src/action/pre-fetch-artifacts.js';

/**
 * Canonical SHA-256 hex digest.  Mirrors `SHA256_HEX_RE` in
 * src/action/validate-manifest.ts; duplicated here (not exported) because
 * the library validator's API is "throw on any failure" and we deliberately
 * do not widen it for this single CLI use-case.
 */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const DOCKER_DIGEST_RE = /@sha256:([0-9a-f]{64})$/;
const DOCKER_PLACEHOLDER_RE = /@sha256:(PLACEHOLDER_SHA256_[A-Za-z0-9_]+)$/;

/**
 * The bootstrap placeholder strings live in src/action/artifact-manifest.ts
 * as `PLACEHOLDER_SHA256_<NAME>`.  We recognise only this exact prefix —
 * any other malformed value (typo'd hash, uppercase, wrong length) is
 * treated as a real bug and re-raised, even under --warn-only-placeholders.
 */
const PLACEHOLDER_PREFIX = 'PLACEHOLDER_SHA256_';

const args = process.argv.slice(2);
const warnOnlyPlaceholders = args.includes('--warn-only-placeholders');

const PLATFORMS: ReadonlyArray<ManifestPlatform> = ['linux', 'darwin'];
const ARCHES: ReadonlyArray<ArtifactArch> = ['x64', 'arm64'];

function totalEntries(): number {
  let n = 0;
  for (const p of PLATFORMS) {
    const section = PINNED_MANIFEST.expected[p];
    if (section !== undefined) n += Object.keys(section).length;
  }
  for (const arch of ARCHES) {
    const images = PINNED_MANIFEST.dockerImages?.[arch];
    if (images !== undefined) n += Object.keys(images).length;
  }
  return n;
}

function collectOffenders(): Array<{ name: string; value: string; placeholder: boolean }> {
  const offenders: Array<{ name: string; value: string; placeholder: boolean }> = [];

  for (const platform of PLATFORMS) {
    const section = PINNED_MANIFEST.expected[platform];
    if (section === undefined) continue;
    for (const [name, value] of Object.entries(section)) {
      if (!SHA256_HEX_RE.test(value)) {
        offenders.push({
          name: `${platform}/${name}`,
          value,
          placeholder: value.startsWith(PLACEHOLDER_PREFIX),
        });
      }
    }
  }

  for (const arch of ARCHES) {
    const images = PINNED_MANIFEST.dockerImages?.[arch];
    if (images === undefined) continue;
    for (const [runnerImage, ref] of Object.entries(images)) {
      if (!DOCKER_DIGEST_RE.test(ref)) {
        offenders.push({
          name: `docker/${arch}/${runnerImage}`,
          value: ref,
          placeholder: DOCKER_PLACEHOLDER_RE.test(ref),
        });
      }
    }
  }

  return offenders;
}

try {
  validateManifest(PINNED_MANIFEST);
  console.log(
    `validate-manifest: OK — all ${totalEntries()} entries in ` +
      `PINNED_MANIFEST.expected.{linux,darwin} and dockerImages are ` +
      `canonical SHA-256 pins.`,
  );
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);

  if (warnOnlyPlaceholders) {
    // Re-classify offenders: are they ALL recognised bootstrap placeholders,
    // or did something else slip in (uppercase, wrong length, typo)?  Only
    // the all-placeholder case is the documented bootstrap loop — anything
    // else is a real bug and must still hard-fail the release.  Offender
    // names are prefixed with `<platform>/` so the maintainer sees which
    // section to fix.
    const offenders = collectOffenders();
    const nonPlaceholder = offenders
      .filter((offender) => !offender.placeholder)
      .map((offender) => offender.name);

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

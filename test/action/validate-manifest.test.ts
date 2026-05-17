// npm-jar — test/action/validate-manifest.test.ts
//
// Unit tests for validateManifest() — the fail-fast startup check that
// refuses to run the action when `PINNED_MANIFEST.expected` still contains
// placeholder strings, wrong-length values, or non-canonical hex.  See
// `src/action/validate-manifest.ts` for the production code.

import { describe, it, expect } from 'vitest';

import { validateManifest } from '../../src/action/validate-manifest.js';
import type { ArtifactManifest } from '../../src/action/pre-fetch-artifacts.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A 64-character lowercase hex digest — the canonical form we require. */
const REAL_SHA_A = 'a'.repeat(64);
const REAL_SHA_B = 'b'.repeat(64);
const REAL_SHA_C =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function manifestWith(
  expected: Readonly<Record<string, string>>,
): ArtifactManifest {
  return {
    repo: 'brooklyn/npm-jar',
    tag: 'v0.1.0',
    expected,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('validateManifest', () => {
  it('passes for an all-real, canonical-lowercase-hex manifest', () => {
    const m = manifestWith({
      'rootfs-ubuntu-22.04.ext4': REAL_SHA_A,
      'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
      'libnpmjar.so': REAL_SHA_C,
    });
    expect(() => validateManifest(m)).not.toThrow();
  });

  it('throws with the offending entry name and a pointer to the manifest file when a placeholder is present', () => {
    const m = manifestWith({
      'rootfs-ubuntu-22.04.ext4': 'PLACEHOLDER_SHA256_ROOTFS_UBUNTU_22_04',
      'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
      'libnpmjar.so': REAL_SHA_C,
    });
    expect(() => validateManifest(m)).toThrowError(
      /src\/action\/artifact-manifest\.ts/,
    );
    expect(() => validateManifest(m)).toThrowError(
      /rootfs-ubuntu-22\.04\.ext4/,
    );
    // The error should also surface the repo so the user knows where to file.
    expect(() => validateManifest(m)).toThrowError(/brooklyn\/npm-jar/);
  });

  it('throws when a value is hex but the wrong length (e.g. 63 chars)', () => {
    const m = manifestWith({
      'rootfs-ubuntu-22.04.ext4': 'a'.repeat(63), // one char short
      'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
      'libnpmjar.so': REAL_SHA_C,
    });
    expect(() => validateManifest(m)).toThrowError(
      /rootfs-ubuntu-22\.04\.ext4/,
    );
  });

  it('throws when a value contains uppercase hex (canonical lowercase only)', () => {
    const m = manifestWith({
      'rootfs-ubuntu-22.04.ext4': 'A'.repeat(64), // uppercase
      'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
      'libnpmjar.so': REAL_SHA_C,
    });
    expect(() => validateManifest(m)).toThrowError(
      /rootfs-ubuntu-22\.04\.ext4/,
    );
  });
});

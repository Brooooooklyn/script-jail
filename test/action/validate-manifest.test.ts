// script-jail — test/action/validate-manifest.test.ts
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
const REAL_SHA_D = 'd'.repeat(64);
const REAL_SHA_E = 'e'.repeat(64);
const REAL_SHA_F = 'f'.repeat(64);
const REAL_SHA_G =
  'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const REAL_SHA_H =
  '0011223344556677889900aabbccddeeff00112233445566778899aabbccddee';

/** Build a fully-populated platform-keyed manifest with canonical hex. */
function goodManifest(): ArtifactManifest {
  return {
    repo: 'brooklyn/script-jail',
    tag: 'v0.1.0',
    expected: {
      linux: {
        'rootfs-ubuntu-22.04.ext4': REAL_SHA_A,
        'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
        'libscriptjail.so': REAL_SHA_C,
      },
      darwin: {
        'rootfs-ubuntu-22.04-arm64.ext4': REAL_SHA_D,
        'rootfs-ubuntu-24.04-arm64.ext4': REAL_SHA_E,
        'libscriptjail-arm64.so': REAL_SHA_F,
        'vmlinux-vz-x86_64': REAL_SHA_G,
        'vmlinux-vz-arm64': REAL_SHA_H,
        'script-jail-vm-arm64-darwin': REAL_SHA_A,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('validateManifest', () => {
  it('passes for an all-real, canonical-lowercase-hex platform-keyed manifest', () => {
    expect(() => validateManifest(goodManifest())).not.toThrow();
  });

  it('throws when a linux entry is a placeholder, prefixed with linux/', () => {
    const m = goodManifest();
    (m.expected.linux as Record<string, string>)[
      'rootfs-ubuntu-22.04.ext4'
    ] = 'PLACEHOLDER_SHA256_LINUX_ROOTFS_UBUNTU_22_04';
    expect(() => validateManifest(m)).toThrowError(
      /src\/action\/artifact-manifest\.ts/,
    );
    expect(() => validateManifest(m)).toThrowError(
      /linux\/rootfs-ubuntu-22\.04\.ext4/,
    );
    expect(() => validateManifest(m)).toThrowError(/brooklyn\/script-jail/);
  });

  it('throws and prefixes darwin/ for offenders in the darwin section', () => {
    // Tracks the TDD requirement: an offender in
    // darwin.libscriptjail-arm64.so must report as
    // `darwin/libscriptjail-arm64.so` so the maintainer knows which platform
    // section to fix.
    const m = goodManifest();
    (m.expected.darwin as Record<string, string>)['libscriptjail-arm64.so'] =
      'PLACEHOLDER_SHA256_DARWIN_LIBSCRIPTJAIL_ARM64_SO';
    expect(() => validateManifest(m)).toThrowError(
      /darwin\/libscriptjail-arm64\.so/,
    );
  });

  it('reports multiple offenders across both sections in one error', () => {
    const m = goodManifest();
    (m.expected.linux as Record<string, string>)['libscriptjail.so'] =
      'PLACEHOLDER_SHA256_LINUX_LIBSCRIPTJAIL_SO';
    (m.expected.darwin as Record<string, string>)['vmlinux-vz-arm64'] =
      'PLACEHOLDER_SHA256_VMLINUX_VZ_ARM64';
    expect(() => validateManifest(m)).toThrowError(
      /linux\/libscriptjail\.so/,
    );
    expect(() => validateManifest(m)).toThrowError(/darwin\/vmlinux-vz-arm64/);
  });

  it('throws when a value is hex but the wrong length (e.g. 63 chars)', () => {
    const m = goodManifest();
    (m.expected.linux as Record<string, string>)['rootfs-ubuntu-22.04.ext4'] =
      'a'.repeat(63);
    expect(() => validateManifest(m)).toThrowError(
      /linux\/rootfs-ubuntu-22\.04\.ext4/,
    );
  });

  it('throws when a value contains uppercase hex (canonical lowercase only)', () => {
    const m = goodManifest();
    (m.expected.darwin as Record<string, string>)['vmlinux-vz-x86_64'] =
      'A'.repeat(64);
    expect(() => validateManifest(m)).toThrowError(
      /darwin\/vmlinux-vz-x86_64/,
    );
  });

  it('rejects a flat (non-platform-keyed) manifest at runtime', () => {
    // The platform-keyed layout (5.2) is the only legal shape after PR 5.
    // A maintainer who copy-pastes the old flat structure must see a
    // clear error, not a silent zero-offender pass.
    const flat = {
      repo: 'brooklyn/script-jail',
      tag: 'v0.1.0',
      expected: {
        'rootfs-ubuntu-22.04.ext4': REAL_SHA_A,
        'libscriptjail.so': REAL_SHA_C,
      },
    } as unknown as ArtifactManifest;
    expect(() => validateManifest(flat)).toThrowError(
      /platform-keyed|linux|darwin/,
    );
  });

  it('rejects a half-shape manifest missing the darwin section', () => {
    // Important-5 regression test: the shape gate in
    // `src/action/validate-manifest.ts` checks `expected.linux === undefined ||
    // expected.darwin === undefined`.  A manifest that ships only `linux`
    // (e.g. a maintainer who forgot to add the darwin block when adopting
    // the platform-keyed layout) MUST be rejected — otherwise the action
    // would later try to read `expected.darwin` and crash.
    const linuxOnly = {
      repo: 'brooklyn/script-jail',
      tag: 'v0.1.0',
      expected: {
        linux: {
          'rootfs-ubuntu-22.04.ext4': REAL_SHA_A,
          'rootfs-ubuntu-24.04.ext4': REAL_SHA_B,
          'libscriptjail.so': REAL_SHA_C,
        },
      },
    } as unknown as ArtifactManifest;
    expect(() => validateManifest(linuxOnly)).toThrowError(
      /platform-keyed/,
    );
    // The error message must clearly identify the missing section by
    // naming the expected layout — i.e. include `darwin` in the diagnostic.
    expect(() => validateManifest(linuxOnly)).toThrowError(/darwin/);
  });

  it('rejects a half-shape manifest missing the linux section', () => {
    // Same shape-gate regression as above, mirrored: darwin-only must
    // also be rejected.
    const darwinOnly = {
      repo: 'brooklyn/script-jail',
      tag: 'v0.1.0',
      expected: {
        darwin: {
          'rootfs-ubuntu-22.04-arm64.ext4': REAL_SHA_D,
          'rootfs-ubuntu-24.04-arm64.ext4': REAL_SHA_E,
          'libscriptjail-arm64.so': REAL_SHA_F,
          'vmlinux-vz-x86_64': REAL_SHA_G,
          'vmlinux-vz-arm64': REAL_SHA_H,
          'script-jail-vm-arm64-darwin': REAL_SHA_A,
        },
      },
    } as unknown as ArtifactManifest;
    expect(() => validateManifest(darwinOnly)).toThrowError(
      /platform-keyed/,
    );
    expect(() => validateManifest(darwinOnly)).toThrowError(/linux/);
  });
});

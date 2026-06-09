// script-jail — test/scripts/build-shim-freshness.test.ts
//
// Tests for the freshness check that gates `buildShim()` in scripts/build.ts.
//
// Why: a prior version of `buildShim` skipped `cargo build` whenever
// `images/libscriptjail.so` existed at all. That meant a stale .so from
// before the exec-shim work (or any earlier commit) could be embedded into
// the rootfs. The rootfs ELF validation only catches *malformed* files; it
// cannot detect a structurally-valid but stale artifact. These tests pin the
// mtime-based freshness rule so that doesn't recur.

import { describe, it, expect } from 'vitest';
import {
  mkdtempSync,
  writeFileSync,
  rmSync,
  utimesSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  decideShimRebuild,
  shimArtifactIsStale,
  shimSourceInputs,
} from '../../scripts/build.js';

// ---------------------------------------------------------------------------
// decideShimRebuild — pure logic
// ---------------------------------------------------------------------------

describe('decideShimRebuild', () => {
  it('rebuilds when the artifact does not exist', () => {
    expect(decideShimRebuild(null, [1_000, 2_000])).toBe(true);
  });

  it('rebuilds when no shim sources can be found (broken checkout)', () => {
    expect(decideShimRebuild(5_000, [])).toBe(true);
  });

  it('rebuilds when any source is newer than the artifact', () => {
    expect(decideShimRebuild(5_000, [4_000, 4_500, 6_000])).toBe(true);
  });

  it('reuses when every source is strictly older than the artifact', () => {
    expect(decideShimRebuild(10_000, [9_999, 1_000])).toBe(false);
  });

  it('reuses when sources have the exact same mtime as the artifact', () => {
    // Equal mtime → not "newer than" → safe to reuse. Touching a file
    // bumps its mtime by at least 1 ms on all supported filesystems.
    expect(decideShimRebuild(5_000, [5_000])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shimArtifactIsStale — filesystem wrapper
// ---------------------------------------------------------------------------

describe('shimArtifactIsStale', () => {
  it('returns true when the artifact file does not exist', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-stale-'));
    try {
      const artifact = join(dir, 'libscriptjail.so');
      const source = join(dir, 'src.toml');
      writeFileSync(source, 'x');
      expect(shimArtifactIsStale(artifact, [source])).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns true when a source mtime is newer than the artifact', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-stale-'));
    try {
      const artifact = join(dir, 'libscriptjail.so');
      const source = join(dir, 'src.toml');
      writeFileSync(artifact, 'old');
      writeFileSync(source, 'new');

      // Force the artifact to be older than the source.
      const past = new Date(Date.now() - 60_000);
      utimesSync(artifact, past, past);
      const now = new Date();
      utimesSync(source, now, now);

      expect(shimArtifactIsStale(artifact, [source])).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns false when every source is older than the artifact', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-fresh-'));
    try {
      const artifact = join(dir, 'libscriptjail.so');
      const source = join(dir, 'src.toml');
      writeFileSync(source, 'old');
      writeFileSync(artifact, 'new');

      const past = new Date(Date.now() - 60_000);
      utimesSync(source, past, past);
      const now = new Date();
      utimesSync(artifact, now, now);

      expect(shimArtifactIsStale(artifact, [source])).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed (stale) when a declared source is missing, even if the rest are older', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-missing-'));
    try {
      const artifact = join(dir, 'libscriptjail.so');
      const present = join(dir, 'present.toml');
      const missing = join(dir, 'does-not-exist.toml');
      writeFileSync(present, 'x');
      writeFileSync(artifact, 'x');

      const past = new Date(Date.now() - 60_000);
      utimesSync(present, past, past);
      const now = new Date();
      utimesSync(artifact, now, now);

      // Even though `present` is older than the artifact, a MISSING declared
      // source means the checkout is incomplete → force a rebuild (which then
      // fails loudly on the real missing input) rather than trust the artifact.
      expect(shimArtifactIsStale(artifact, [present, missing])).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns true when none of the provided sources exist (degenerate)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shim-degenerate-'));
    try {
      const artifact = join(dir, 'libscriptjail.so');
      writeFileSync(artifact, 'x');
      const missing = join(dir, 'nope.toml');
      expect(shimArtifactIsStale(artifact, [missing])).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// shimSourceInputs — paths are well-formed
// ---------------------------------------------------------------------------

describe('shimSourceInputs', () => {
  it('includes Cargo.toml, Cargo.lock, rust-toolchain.toml, and src/lib.rs', () => {
    const inputs = shimSourceInputs('/repo');
    expect(inputs).toContain('/repo/src/shim/Cargo.toml');
    expect(inputs).toContain('/repo/Cargo.lock');
    expect(inputs).toContain('/repo/rust-toolchain.toml');
    expect(inputs).toContain('/repo/src/shim/src/lib.rs');
  });

  it('includes the macOS Mach-O port modules and the C variadic bridge', () => {
    const inputs = shimSourceInputs('/repo');
    // Mach-O hook modules (cfg-gated to darwin in lib.rs).
    expect(inputs).toContain('/repo/src/shim/src/interpose.rs');
    expect(inputs).toContain('/repo/src/shim/src/fileops.rs');
    expect(inputs).toContain('/repo/src/shim/src/net.rs');
    // C variadic bridge for open/openat (Darwin arm64 stack-passed `mode`):
    // editing either must bust the freshness gate so the cached dylib rebuilds.
    expect(inputs).toContain('/repo/src/shim/build.rs');
    expect(inputs).toContain('/repo/src/shim/src/open_variadic.c');
    // macOS-26 non-`_np` posix_spawn chdir interposes — also compiled by build.rs
    // via the cc crate, so editing it must bust the freshness gate too.
    expect(inputs).toContain('/repo/src/shim/src/sj_spawn_chdir_np2.c');
  });
});

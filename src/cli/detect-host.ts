// script-jail — src/cli/detect-host.ts
//
// Host capability detection for the macOS CLI surface.
//
// script-jail v1 runs the audited install inside a microVM.  On Linux CI the
// hypervisor is Firecracker + KVM; on a developer's laptop we use Apple's
// Virtualization.framework (VZ) via a native binary that PR 3-5 will plug in.
// VZ has a hard floor at macOS 14 (Sonoma) because that is the first release
// to expose the `LinuxBootLoader` + vsock APIs we need without extra
// entitlements.  This module is the single gatekeeper that decides whether
// the host can even attempt to launch a VM; the CLI bails out here BEFORE
// touching any artifacts so we can surface a clear actionable message rather
// than letting a generic ENOENT/permission error surface from deep inside
// the VZ helper.
//
// Detection rules:
//   - `process.platform === 'darwin'`  (anything else → NotMacOSError)
//   - `os.release()` parses as `<darwinMajor>.<minor>.<patch>` and
//     `darwinMajor - 9 >= 14` (Sonoma).  Darwin major → macOS major mapping
//     (kernel version, not marketing name):
//       - Darwin 23 = macOS 14 (Sonoma)
//       - Darwin 24 = macOS 15 (Sequoia)
//       - Darwin 25 = macOS 16
//     Marketing names (e.g. Apple's "macOS 26" branding) are derived from
//     year and are not tied to the kernel major.  We gate on the
//     kernel-derived major.  See
//     https://en.wikipedia.org/wiki/Darwin_(operating_system)#Release_history.
//   - `process.arch === 'arm64'` or `process.arch === 'x64'`.  Any other arch
//     (ia32 / mips / ppc / s390x / arm) → UnsupportedArchError.
//
// All three fields on `DetectHostInput` are injection seams used by the unit
// tests in test/cli/detect-host.test.ts.  Production callers pass no
// argument; the defaults read `process.platform`, `os.release()`,
// `process.arch`.

import { release as realRelease } from 'node:os';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type HostArch = 'x64' | 'arm64';

export interface DetectedHost {
  /** macOS major version (14 = Sonoma, 15 = Sequoia, …). */
  macosMajor: number;
  hostArch: HostArch;
}

export interface DetectHostInput {
  /** Defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /** Defaults to `os.release()`.  Darwin kernel version, e.g. '23.6.0'. */
  release?: string;
  /** Defaults to `process.arch`. */
  arch?: NodeJS.Architecture;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Thrown when the host is not macOS. */
export class NotMacOSError extends Error {
  constructor(actualPlatform: string) {
    super(
      `script-jail CLI requires macOS (detected '${actualPlatform}'). ` +
      `On Linux CI, use the GitHub Action (uses: Brooooooklyn/npm-jar@v1) instead.`,
    );
    this.name = 'NotMacOSError';
  }
}

/** Thrown when macOS is too old (anything pre-14 Sonoma). */
export class UnsupportedMacOSError extends Error {
  constructor(public readonly resolvedMajor: number, public readonly minimum: number) {
    super(
      `script-jail CLI requires macOS ${minimum}+ (Sonoma or newer); ` +
      `detected macOS ${resolvedMajor}. Upgrade macOS or run the audit on Linux CI.`,
    );
    this.name = 'UnsupportedMacOSError';
  }
}

/** Thrown when the host CPU architecture is neither x64 nor arm64. */
export class UnsupportedArchError extends Error {
  constructor(actualArch: string) {
    super(
      `script-jail CLI requires an x64 or arm64 host (detected '${actualArch}').`,
    );
    this.name = 'UnsupportedArchError';
  }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/** Minimum supported macOS major (Sonoma). */
const MIN_MACOS_MAJOR = 14;

/**
 * Inspect the host and return `{ macosMajor, hostArch }` or throw a typed
 * error explaining why the CLI cannot run here.
 *
 * Pure-ish: no filesystem or network IO; only reads `os.release()` and
 * `process.{platform,arch}` (or the injected equivalents).
 */
export function detectHost(input: DetectHostInput = {}): DetectedHost {
  const platform = input.platform ?? process.platform;
  if (platform !== 'darwin') {
    throw new NotMacOSError(platform);
  }

  const release = input.release ?? realRelease();
  const darwinMajor = parseInt(release.split('.')[0] ?? '', 10);
  if (!Number.isFinite(darwinMajor)) {
    // Defensive: os.release() always returns a parseable form on macOS, but
    // an injected garbage string would otherwise yield NaN and silently pass
    // the `< MIN_MACOS_MAJOR` check via NaN-comparison weirdness.
    throw new UnsupportedMacOSError(0, MIN_MACOS_MAJOR);
  }
  const macosMajor = darwinMajor - 9;
  if (macosMajor < MIN_MACOS_MAJOR) {
    throw new UnsupportedMacOSError(macosMajor, MIN_MACOS_MAJOR);
  }

  const arch = input.arch ?? process.arch;
  if (arch !== 'arm64' && arch !== 'x64') {
    throw new UnsupportedArchError(arch);
  }

  return { macosMajor, hostArch: arch };
}

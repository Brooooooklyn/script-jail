// script-jail — src/cli/detect-platform.ts
//
// Host/platform capability detection for the script-jail CLI surface.
//
// This is the generalized successor to the macOS-only `detect-host.ts`.  The
// CLI now runs the audited install on two host families:
//
//   - macOS: two backends.  `vz` (arm64 only) boots the Linux guest inside an
//     Apple Virtualization.framework (VZ) microVM via the native
//     `script-jail-vm` helper — VZ has a hard floor at macOS 14 (Sonoma), the
//     first release to expose the `LinuxBootLoader` + vsock APIs we need
//     without extra entitlements, and the helper/kernel/rootfs artifacts are
//     arm64-only.  `bare` runs the install natively on the Mac under the
//     Mach-O shim (no VM), so it also works on Intel macs (darwin/x64).  Both
//     share the macOS 14 floor.  `detectPlatform` therefore DETECTS darwin-x64
//     (it no longer throws); the VZ-only arm64 gate lives in
//     `src/cli/index.ts`.
//
//   - Linux (x64 / arm64): the install runs through the same firecracker →
//     docker → bare backends the GitHub Action uses, materializing the
//     platform-package rootfs+shim locally instead of downloading them.
//
// This module is the single gatekeeper that decides whether the host can even
// attempt an audit; the CLI bails out here BEFORE touching any artifacts so we
// surface a clear actionable message rather than letting a generic
// ENOENT/permission error escape from deep inside a backend.
//
// Darwin major → macOS major mapping (kernel version, not marketing name):
//   - Darwin 23 = macOS 14 (Sonoma)
//   - Darwin 24 = macOS 15 (Sequoia)
//   - Darwin 25 = macOS 16
// Marketing names (e.g. Apple's "macOS 26" branding) are derived from year and
// are not tied to the kernel major.  We gate on the kernel-derived major.  See
// https://en.wikipedia.org/wiki/Darwin_(operating_system)#Release_history.
//
// All fields on `DetectPlatformInput` are injection seams used by the unit
// tests in test/cli/detect-platform.test.ts.  Production callers pass no
// argument; the defaults read `process.platform`, `os.release()`,
// `process.arch`.

import { release as realRelease } from 'node:os';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** The two CPU architectures script-jail ships runtime artifacts for. */
export type PlatformArch = 'x64' | 'arm64';

/** The two host operating systems script-jail's CLI supports. */
export type PlatformOs = 'darwin' | 'linux';

export interface DetectedPlatform {
  os: PlatformOs;
  arch: PlatformArch;
  /**
   * macOS major version (14 = Sonoma, 15 = Sequoia, …).  Present only for
   * `os: 'darwin'`; absent (not `undefined`-valued) on Linux so callers can
   * branch on `'macosMajor' in platform`.
   */
  macosMajor?: number;
}

export interface DetectPlatformInput {
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

/**
 * Thrown when the host is not macOS.
 *
 * Retained for backwards compatibility with callers that branched on this
 * specific class while the CLI was macOS-only.  `detectPlatform` itself throws
 * `NotSupportedPlatformError` for unsupported operating systems; this class is
 * still thrown by the `detect-host.ts` compat shim.
 */
export class NotMacOSError extends Error {
  constructor(actualPlatform: string) {
    super(
      `script-jail CLI requires macOS (detected '${actualPlatform}'). ` +
      `On Linux CI, use the GitHub Action (uses: Brooooooklyn/scriptjail@<pinned-tag>) instead.`,
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

/**
 * Thrown for an Intel mac (darwin/x64).  script-jail's macOS path uses Apple
 * Virtualization.framework with arm64-only kernel/rootfs/helper artifacts, so
 * Intel macs cannot be supported.
 */
export class UnsupportedDarwinArchError extends Error {
  constructor() {
    super(
      `script-jail CLI: Intel macs (darwin-x64) are not supported. The macOS ` +
      `audit path uses Apple Virtualization.framework (VZ) with arm64-only ` +
      `runtime artifacts. Use an Apple Silicon mac, or run the audit on ` +
      `Linux CI via the GitHub Action.`,
    );
    this.name = 'UnsupportedDarwinArchError';
  }
}

/** Thrown when the host OS is neither macOS nor Linux. */
export class NotSupportedPlatformError extends Error {
  constructor(actualPlatform: string) {
    super(
      `script-jail CLI supports macOS (Apple Silicon) and Linux (x64/arm64); ` +
      `detected '${actualPlatform}'. On other platforms, run the audit on ` +
      `Linux CI via the GitHub Action (uses: Brooooooklyn/scriptjail@<pinned-tag>).`,
    );
    this.name = 'NotSupportedPlatformError';
  }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/** Minimum supported macOS major (Sonoma). */
export const MIN_MACOS_MAJOR = 14;

/**
 * Inspect the host and return a `DetectedPlatform` or throw a typed error
 * explaining why the CLI cannot run here.
 *
 * Pure-ish: no filesystem or network IO; only reads `os.release()` and
 * `process.{platform,arch}` (or the injected equivalents).
 */
export function detectPlatform(input: DetectPlatformInput = {}): DetectedPlatform {
  const platform = input.platform ?? process.platform;
  const arch = input.arch ?? process.arch;

  if (platform === 'darwin') {
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

    // darwin-x64 (Intel mac) is DETECTED, not rejected here.  The bare macOS
    // backend builds the Mach-O shim from source and runs natively (no VM), so
    // an Intel mac CAN audit via `--backend bare`.  Only the VZ path is
    // arm64-only — that gate moved into `src/cli/index.ts`
    // (`darwin + vz + x64` → `UnsupportedDarwinArchError`) so detection stays a
    // pure capability report.  (The legacy `detectHost` shim still throws for
    // x64 to preserve its macOS-VZ-only contract; see detect-host.ts.)
    if (arch === 'x64') {
      return { os: 'darwin', arch: 'x64', macosMajor };
    }
    if (arch !== 'arm64') {
      throw new UnsupportedArchError(arch);
    }

    return { os: 'darwin', arch: 'arm64', macosMajor };
  }

  if (platform === 'linux') {
    if (arch !== 'x64' && arch !== 'arm64') {
      throw new UnsupportedArchError(arch);
    }
    return { os: 'linux', arch };
  }

  throw new NotSupportedPlatformError(platform);
}

// ---------------------------------------------------------------------------
// Platform-package naming
// ---------------------------------------------------------------------------

/**
 * The scoped optional-dependency package name that ships the runtime artifacts
 * for a given platform, e.g. `@script-jail/linux-x64`.  The basenames inside
 * each package are a load-bearing contract with `src/shared/artifacts.ts`.
 */
export function platformPackageName(p: DetectedPlatform): string {
  return `@script-jail/${p.os}-${p.arch}`;
}

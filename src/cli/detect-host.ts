// script-jail — src/cli/detect-host.ts
//
// Backwards-compatibility shim over `detect-platform.ts`.
//
// The CLI host gate was originally macOS-only and returned the legacy shape
// `{ macosMajor, hostArch }`.  Detection has since been generalized into
// `detect-platform.ts` (`detectPlatform` → `DetectedPlatform`) to also cover
// Linux x64/arm64.  Until `src/cli/index.ts` migrates to `detectPlatform`
// (Phase 1 Task 1.4), the existing call sites and their injected test doubles
// keep importing from here, so this module:
//
//   - re-exports the typed error classes (including the new
//     `UnsupportedDarwinArchError`),
//   - keeps the `DetectedHost` / `HostArch` / `DetectHostInput` types, and
//   - provides a `detectHost` adapter that delegates the OS/arch gate to
//     `detectPlatform` and maps the macOS-arm64 result back to the legacy
//     `{ macosMajor, hostArch }` shape.
//
// Behaviour change (intentional, single-sourced via `detectPlatform`): Intel
// macs (darwin/x64) are no longer accepted — `detectHost` now throws
// `UnsupportedDarwinArchError` for them instead of returning
// `{ macosMajor, hostArch: 'x64' }`.  Linux hosts still throw `NotMacOSError`
// here (this adapter only ever returns the macOS shape); the Linux runtime
// path uses `detectPlatform` directly.

import {
  detectPlatform,
  MIN_MACOS_MAJOR,
  NotMacOSError,
  NotSupportedPlatformError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  UnsupportedDarwinArchError,
  type DetectPlatformInput,
} from './detect-platform.js';

// ---------------------------------------------------------------------------
// Re-exports (preserve the legacy public surface)
// ---------------------------------------------------------------------------

export {
  MIN_MACOS_MAJOR,
  NotMacOSError,
  UnsupportedMacOSError,
  UnsupportedArchError,
  UnsupportedDarwinArchError,
};

// ---------------------------------------------------------------------------
// Legacy types
// ---------------------------------------------------------------------------

export type HostArch = 'x64' | 'arm64';

export interface DetectedHost {
  /** macOS major version (14 = Sonoma, 15 = Sequoia, …). */
  macosMajor: number;
  hostArch: HostArch;
}

/** @deprecated use `DetectPlatformInput` from `./detect-platform.js`. */
export type DetectHostInput = DetectPlatformInput;

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/**
 * Legacy macOS-only host gate.  Delegates to `detectPlatform` and maps the
 * macOS-arm64 result to `{ macosMajor, hostArch }`.
 *
 * - macOS arm64 (Sonoma+) → `{ macosMajor, hostArch: 'arm64' }`.
 * - Intel mac (darwin/x64) → throws `UnsupportedDarwinArchError`.
 * - too-old macOS → throws `UnsupportedMacOSError`.
 * - non-macOS → throws `NotMacOSError` (this adapter never returns a Linux
 *   shape; Linux callers use `detectPlatform` directly).
 */
export function detectHost(input: DetectHostInput = {}): DetectedHost {
  let platform;
  try {
    platform = detectPlatform(input);
  } catch (err) {
    // `detectPlatform` throws `NotSupportedPlatformError` for non-macOS,
    // non-Linux hosts and `NotMacOSError`/etc. are macOS-specific.  This
    // adapter's contract is macOS-only, so translate the generalized
    // "unsupported OS" into the legacy `NotMacOSError`.
    if (err instanceof NotSupportedPlatformError) {
      throw new NotMacOSError(input.platform ?? process.platform);
    }
    throw err;
  }

  if (platform.os !== 'darwin') {
    // Linux is a supported platform for `detectPlatform`, but this legacy
    // adapter only models macOS.  Preserve the historical `NotMacOSError`.
    throw new NotMacOSError(platform.os);
  }

  return { macosMajor: platform.macosMajor!, hostArch: platform.arch };
}

// script-jail — src/cli/arch-flags.ts
//
// Former per-package-manager payload builder for cross-arch dependency
// resolution.
//
// Why this exists:
//   The old parity strategy forced every macOS arm64 run to resolve the Linux
//   x64 dependency tree.  That aligned package selection with x64 Linux CI, but
//   lifecycle scripts still executed inside a real arm64 VM. Native addon and
//   binary validation paths therefore diverged badly (`@swc/core` falling back
//   to `@swc/wasm`, esbuild EACCES/ENOEXEC, etc.).
//
//   The parity direction is now same-arch instead: run Linux CI on arm64 and
//   let package managers resolve the host/guest architecture naturally.  This
//   helper remains as a small compatibility seam for tests and older callers,
//   but production no longer emits package-manager sidecars.
//
// This module is pure: it returns the payloads as strings/objects.  The CLI
// is responsible for materialising them onto disk (via the existing
// `config-override` / `makeOverlay` plumbing) so the same files are visible
// inside the VM where the package manager actually runs.

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type ArchFlagPm = 'npm' | 'pnpm' | 'yarn' | 'yarn-classic';
export type ArchFlagHostArch = 'x64' | 'arm64';
export type ArchFlagSpoofPlatform = 'linux' | 'darwin' | 'win32';

export interface ArchFlagInput {
  pm: ArchFlagPm;
  hostArch: ArchFlagHostArch;
  /**
   * Effective process.platform exposed to Node children by platform-spoof.
   * Defaults to the action/CLI default, linux.
   */
  spoofPlatform?: ArchFlagSpoofPlatform;
  /**
   * Effective process.arch exposed to Node children by platform-spoof.
   * Defaults to the action/CLI runtime default.
   */
  spoofArch?: ArchFlagHostArch;
}

/**
 * Payload to layer onto the VM's repo disk before the install runs.
 *
 * The sidecar fields are intentionally retained for the shared pipeline's test
 * seam and for backwards compatibility with older integrations that may inject
 * their own overlay builder.  The default builder below never sets them.
 */
export interface ArchFlagOverlay {
  pmFlagsJson?: { extra_install_args: string[] };
  yarnrcOverlay?: string;
  pnpmArchOverlay?: string;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// buildArchFlagOverlay
// ---------------------------------------------------------------------------

/**
 * Build the overlay required for a (pm, hostArch) pair.
 *
 * Current production policy is same-arch parity, so no package-manager flags
 * are emitted for any package manager, host arch, or spoof target.
 */
export function buildArchFlagOverlay(_input: ArchFlagInput): ArchFlagOverlay {
  return { warnings: [] };
}

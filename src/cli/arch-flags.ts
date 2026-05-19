// script-jail — src/cli/arch-flags.ts
//
// Per-package-manager payload builder that forces a Linux/x64 dependency
// resolution from an arm64 macOS host.
//
// Why this exists:
//   The script-jail audit ALWAYS runs inside a Linux/x64 VM (Phase B install
//   under strace).  A developer running `script-jail init` from an arm64
//   macOS laptop would, by default, see their package manager resolve
//   arm64-darwin platform-specific subpackages (e.g. `@swc/core-darwin-arm64`).
//   Those subpackages don't exist on the Linux/x64 VM, so the install would
//   fail or — worse — silently audit a different dependency tree than CI.
//
//   To keep the local lockfile byte-stable against the one CI would produce,
//   we feed each package manager the "I am a Linux/x64 glibc machine" hint
//   at install time:
//     - npm / pnpm:  `--cpu=x64 --os=linux --libc=glibc` install flags.
//     - yarn 4+ (Berry):  a `supportedArchitectures` block in `.yarnrc.yml`.
//     - yarn classic (v1):  unsupported — emit a warning, no overlay.
//
// On x64 hosts no overlay is needed; npm/pnpm/yarn already resolve x64-linux
// subpackages by default, and the audit VM's arch matches.
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

export interface ArchFlagInput {
  pm: ArchFlagPm;
  hostArch: ArchFlagHostArch;
}

/**
 * Payload to layer onto the VM's repo disk before the install runs.
 *
 *   `pmFlagsJson`     — JSON file landed at /etc/script-jail/pm-flags.json,
 *                       read by phase-install.ts to splice extra args into
 *                       the package manager's `install` invocation.
 *   `yarnrcOverlay`   — YAML content to write at <repo-root>/.yarnrc.yml.
 *                       Yarn Berry merges this with any committed .yarnrc.yml.
 *   `warnings`        — Non-fatal messages the CLI should print so the user
 *                       knows we punted on a case (currently: yarn classic
 *                       on arm64).
 */
export interface ArchFlagOverlay {
  pmFlagsJson?: { extra_install_args: string[] };
  yarnrcOverlay?: string;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// buildArchFlagOverlay
// ---------------------------------------------------------------------------

/**
 * Build the overlay required for a (pm, hostArch) pair.  Pure function;
 * caller decides how to materialize the result.
 */
export function buildArchFlagOverlay(input: ArchFlagInput): ArchFlagOverlay {
  // x64 hosts: nothing to do.  The VM is x64/linux too; package managers
  // resolve the right subpackages out of the box.
  if (input.hostArch === 'x64') {
    return { warnings: [] };
  }

  // arm64 host paths.
  switch (input.pm) {
    case 'npm':
    case 'pnpm':
      // npm honors --cpu / --os / --libc since v10; pnpm accepts the same
      // flags (with --libc accepted from pnpm v9+).  Phase B passes them
      // verbatim to `<pm> install` via /etc/script-jail/pm-flags.json.
      return {
        pmFlagsJson: {
          extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'],
        },
        warnings: [],
      };

    case 'yarn':
      // Yarn 4+ (Berry) reads `supportedArchitectures` from .yarnrc.yml.
      // We hand-write the YAML rather than calling `yaml.stringify` so the
      // exact form is part of the public contract (snapshotted in tests) —
      // any drift in the `yaml` library's output would silently change the
      // file's bytes and reduce the diff stability we promise for the lock
      // file.
      return {
        yarnrcOverlay:
          'supportedArchitectures:\n' +
          '  os:\n' +
          '    - linux\n' +
          '  cpu:\n' +
          '    - x64\n' +
          '  libc:\n' +
          '    - glibc\n',
        warnings: [],
      };

    case 'yarn-classic':
      // Yarn v1 has no per-install architecture filter.  We can't force the
      // resolution from the host; the lockfile written from an arm64 mac
      // will diverge from a Linux/x64 CI run.  Emit a warning so the user
      // knows to either upgrade Yarn or run the audit on Linux.
      return {
        warnings: [
          'yarn classic (v1) does not support per-install architecture filters; ' +
          'lockfile audit on arm64 hosts will reflect arm64 subpackages and may ' +
          'diverge from CI. Consider upgrading to yarn 4+.',
        ],
      };

    default: {
      // Bun is filtered out earlier by `detectPm` (BunUnsupportedError); any
      // other value is a programming error in the caller.  We don't degrade
      // silently — better to crash with a clear message than to ship an
      // unflagged install.
      const exhaustive: never = input.pm;
      throw new Error(`buildArchFlagOverlay: unsupported pm '${String(exhaustive)}'`);
    }
  }
}

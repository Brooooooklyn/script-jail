// script-jail — src/cli/arch-flags.ts
//
// Per-package-manager payload builder that forces a Linux/x64 dependency
// resolution whenever the package manager would otherwise see a non-canonical
// platform/arch signal.
//
// Why this exists:
//   The script-jail audit's canonical dependency tree is Linux/x64.  A
//   developer running `script-jail init` from an arm64 macOS laptop, or any
//   run whose platform-spoof preload makes the package manager see
//   process.arch/process.platform as something other than linux/x64, would by
//   default resolve different platform-specific subpackages (e.g.
//   `@swc/core-darwin-arm64`).  Those subpackages don't exist on the canonical
//   Linux/x64 run, so the install would fail or — worse — silently audit a
//   different dependency tree than CI.
//
//   To keep the local lockfile byte-stable against the one CI would produce,
//   we feed each package manager the "I am a Linux/x64 glibc machine" hint
//   at install time.  Each manager has a DIFFERENT mechanism — there is no
//   single flag form that works everywhere:
//     - npm:  `--cpu=x64 --os=linux --libc=glibc` install flags (npm 10+).
//             These are CLI flags `npm ci` honours during resolution.
//     - pnpm: a `pnpm.supportedArchitectures` block in the repo's root
//             `package.json`.  pnpm does NOT accept `--cpu/--os/--libc` on
//             the CLI (`pnpm fetch --cpu=x64` errors with "Unknown options:
//             'cpu', 'os', 'libc'").  Empirically verified on pnpm 9.15.0:
//             `pnpm fetch` reads the `pnpm` config block out of package.json
//             even though it ignores the dependency manifest, so the hint
//             must live there.  `.npmrc` and `pnpm-workspace.yaml` are NOT
//             honoured for `supportedArchitectures` on pnpm 9.x.  Adding the
//             block does not invalidate `--frozen-lockfile` (it is a
//             resolution preference, not part of the lockfile manifest).
//     - yarn 4+ (Berry):  a `supportedArchitectures` block in `.yarnrc.yml`.
//     - yarn classic (v1):  unsupported — emit a warning, no overlay.
//
// On x64 hosts with default linux/x64 spoofing no overlay is needed;
// npm/pnpm/yarn already resolve x64-linux subpackages by default.
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
   * Defaults to the action/CLI default, x64.
   */
  spoofArch?: ArchFlagHostArch;
}

/**
 * Payload to layer onto the VM's repo disk before the install runs.
 *
 *   `pmFlagsJson`     — JSON file landed at /etc/script-jail/pm-flags.json,
 *                       read by phase-fetch.ts to splice extra args into
 *                       npm's `ci` invocation.  npm ONLY — pnpm does not
 *                       accept `--cpu/--os/--libc` on the CLI.
 *   `yarnrcOverlay`   — YAML content to write at <repo-root>/.yarnrc.yml.
 *                       Yarn Berry merges this with any committed .yarnrc.yml.
 *   `pnpmArchOverlay` — JSON content landed at /etc/script-jail/pnpm-arch.json.
 *                       Holds the `supportedArchitectures` object; the guest
 *                       (`src/guest/apply-pnpm-arch.ts`) merges it into the
 *                       repo's root `package.json` under the `pnpm` key
 *                       before Phase A runs `pnpm fetch`.  pnpm reads the
 *                       block from package.json — there is no CLI form.
 *   `warnings`        — Non-fatal messages the CLI should print so the user
 *                       knows we punted on a case (currently: yarn classic
 *                       on arm64).
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
 * Build the overlay required for a (pm, hostArch) pair.  Pure function;
 * caller decides how to materialize the result.
 */
export function buildArchFlagOverlay(input: ArchFlagInput): ArchFlagOverlay {
  // Canonical path: the host and the package-manager process both see
  // linux/x64, so package managers resolve the right subpackages out of the
  // box.  If the host is arm64 OR platform-spoof makes the package manager see
  // a non-linux/x64 target, force the dependency tree back to linux/x64.
  const spoofPlatform = input.spoofPlatform ?? 'linux';
  const spoofArch = input.spoofArch ?? 'x64';
  const needsLinuxX64Overlay =
    input.hostArch === 'arm64' ||
    spoofPlatform !== 'linux' ||
    spoofArch !== 'x64';

  if (!needsLinuxX64Overlay) {
    return { warnings: [] };
  }

  // Non-canonical package-manager platform/arch paths.
  switch (input.pm) {
    case 'npm':
      // npm honours --cpu / --os / --libc as `npm ci` flags since v10.  They
      // affect dependency resolution, which npm does in Phase A — so Phase A
      // (`phase-fetch.ts`) splices them into `npm ci` via
      // /etc/script-jail/pm-flags.json.
      return {
        pmFlagsJson: {
          extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'],
        },
        warnings: [],
      };

    case 'pnpm':
      // pnpm does NOT accept --cpu / --os / --libc on the CLI; passing them
      // makes `pnpm fetch` fail with "Unknown options: 'cpu', 'os', 'libc'".
      // The real mechanism is a `supportedArchitectures` block under the
      // `pnpm` key of the repo's root package.json.  We hand-write the JSON
      // (rather than JSON.stringify'ing an object) so the exact bytes are
      // part of the public contract — snapshotted in tests — and the merge
      // the guest performs into package.json is fully deterministic.  The
      // guest (`apply-pnpm-arch.ts`) reads this from
      // /etc/script-jail/pnpm-arch.json and merges it before Phase A.
      return {
        pnpmArchOverlay:
          '{\n' +
          '  "supportedArchitectures": {\n' +
          '    "os": ["linux"],\n' +
          '    "cpu": ["x64"],\n' +
          '    "libc": ["glibc"]\n' +
          '  }\n' +
          '}\n',
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
          'lockfile audit on arm64 hosts or spoofed non-linux/x64 targets may ' +
          'reflect non-canonical subpackages and diverge from CI. Consider ' +
          'upgrading to yarn 4+.',
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

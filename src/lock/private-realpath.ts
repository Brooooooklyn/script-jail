// script-jail — macOS /private realpath canonicalization (shared helper).
//
// On macOS /var, /tmp, and /etc are symlinks into /private, so the absolute
// path the Mach-O shim resolves (via F_GETPATH / realpath) comes back as
// /private/var/..., /private/tmp/..., /private/etc/...  The Linux side and the
// tokenize roots both use the bare /var, /tmp, /etc forms.
//
// Two consumers need this collapse and MUST agree on it:
//   - `src/lock/normalize.ts`     — strips /private before isSystemNoise + tokenize.
//   - `src/guest/protected-paths.ts` — strips /private before the raw-path
//     cross-package-drop / protected-pattern checks, so the matcher's
//     non-/private roots (derived from a non-/private work_dir) match the
//     shim's /private-canonicalized paths.  Without this the benign
//     cross-package read suppression misfires on macOS and floods
//     `external_reads` with ~140 `$NODE_MODULES/.pnpm/...` entries.
//
// Linux paths never start with `/private/var|tmp|etc`, so this is a no-op there
// — callers still gate on `os === 'darwin'` as a defence-in-depth boundary so a
// hostile Linux lockfile can never smuggle macOS-shaped paths past a Linux gate.

const PRIVATE_REALPATH_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ['/private/var', '/var'],
  ['/private/tmp', '/tmp'],
  ['/private/etc', '/etc'],
];

/**
 * Collapse a macOS `/private/{var,tmp,etc}` realpath prefix to its bare form.
 * Only rewrites at a true path-segment boundary: `/private/var` and
 * `/private/var/x` rewrite; `/private/variant` does not.  Returns `path`
 * unchanged when no prefix matches (always the case on Linux).
 */
export function canonicalizePrivateRealpath(path: string): string {
  for (const [from, to] of PRIVATE_REALPATH_PREFIXES) {
    if (path === from || path.startsWith(`${from}/`)) {
      return `${to}${path.slice(from.length)}`;
    }
  }
  return path;
}

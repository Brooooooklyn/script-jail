// script-jail — src/guest/load-pm-flags.ts
//
// Loader for /etc/script-jail/pm-flags.json.
//
// NPM ONLY.  If a caller lands `/etc/script-jail/pm-flags.json`, Phase A
// (`phase-fetch.ts`) reads it here and appends `extra_install_args` to the
// `npm ci` invocation. npm resolves its dependency graph during Phase A, so
// any explicit package-manager hints must take effect there, NOT during Phase B
// (`phase-install.ts`) which runs `npm rebuild` against the already-resolved
// tree.
//
// pnpm and yarn do NOT accept `--cpu/--os/--libc` on the CLI and are NOT
// served by this loader:
//   * pnpm uses a `pnpm.supportedArchitectures` block merged into the repo's
//     package.json before Phase A (see `apply-pnpm-arch.ts`).
//   * yarn Berry uses a `.yarnrc.yml` `supportedArchitectures` overlay landed
//     by the CLI on the repo disk before the VM boots.
//
// Defensive read: the file is optional, and the normal same-arch parity path
// does not write it. Missing-file / parse-failure / schema-mismatch all
// degrade silently to "no extra args" — we do NOT fail the install for a
// malformed override.

import * as fs from 'node:fs';

import { z } from 'zod';

import { sanitizeArchInstallArgs, sanitizeInstallArgs } from '../shared/pm-commands.js';

// `extra_install_args` carries npm-ONLY arch hints (`--cpu/--os/--libc`) and is
// applied only to `npm ci` (pnpm/yarn reject those CLI flags — see
// phase-fetch.ts). `user_install_args` carries DEVELOPER-supplied install flags
// (the action `args` input, e.g. `-D`/`--prod`/`--omit=dev`) and is applied to
// ALL THREE managers' fetch command. Both default to empty so the normal
// same-arch / no-args parity path stays untouched.
const PmFlagsSchema = z.object({
  extra_install_args: z.array(z.string()),
  user_install_args: z.array(z.string()).optional(),
});

/** Absolute path inside the VM where the CLI lands the override file. */
export const PM_FLAGS_PATH = '/etc/script-jail/pm-flags.json';

/**
 * Load the npm/developer install-arg flags.
 *
 * Two delivery channels, content first:
 *   - `content` — the pm-flags.json JSON delivered DIRECTLY via the
 *     `SCRIPT_JAIL_PM_FLAGS_CONTENT` env var (threaded by the agent).  This is
 *     the production channel on every backend: it keeps script-jail's OWN
 *     control sidecar OFF any lifecycle-visible filesystem path, so a clean-repo
 *     `fs.existsSync('/etc/script-jail/pm-flags.json')` is false in BOTH the
 *     audit and the host re-run (Codex re-review, audit-only sidecar oracle).
 *     The content rides the AGENT's process env, which `buildChildEnv` strips
 *     from every lifecycle child, so a child's own `process.env` never sees it.
 *   - `filePath` — fallback file read (the `/etc` default, or a unit-test temp
 *     file).  Retained for defense in depth and tests; no backend stages a file
 *     here in production any more.
 *
 * `content` wins when present, even if empty-string (an empty override is still
 * an explicit "no args", not a reason to fall back to a stale file).
 */
export function loadPmFlags(
  filePath: string = PM_FLAGS_PATH,
  content?: string,
): { extraInstallArgs: string[]; userInstallArgs: string[] } {
  try {
    const raw = content !== undefined ? content : fs.readFileSync(filePath, 'utf8');
    const parsed = PmFlagsSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) return { extraInstallArgs: [], userInstallArgs: [] };
    // SECURITY (defense in depth): this content is delivered through the
    // repo-controlled staging namespace (it originates from a file the host
    // writes from the action config, then rides `SCRIPT_JAIL_PM_FLAGS_CONTENT`
    // env or, as a fallback, a file path).  The host overlay always produces
    // sanitized content, but a backend delivery gap must NEVER let a
    // tree-steering / script-re-enabling flag survive into the network-on Phase A
    // fetch.  BOTH array fields flow into the install argv, so
    // we re-sanitize BOTH at the point of use with the SAME fail-closed allowlist
    // the host install applies — sanitizing only one channel would just move the
    // smuggling surface to the other (an attacker who can influence the file
    // would put `--dir`/`--lockfile-dir` in `extra_install_args` instead).
    //
    // `extra_install_args` is the npm cross-arch-hint channel (`--cpu/--os/--libc`)
    // — a SEPARATE allowlist (`sanitizeArchInstallArgs`) so the hints survive if
    // `buildArchFlagOverlay` is ever revived (it is dormant today, emitted EMPTY),
    // while a steering flag smuggled through this channel is still dropped.  Both
    // channels stay fail-closed by construction.
    return {
      extraInstallArgs: sanitizeArchInstallArgs(parsed.data.extra_install_args).kept,
      userInstallArgs: sanitizeInstallArgs(parsed.data.user_install_args ?? []).kept,
    };
  } catch {
    // ENOENT, malformed JSON, EACCES, etc. — degrade silently.
    return { extraInstallArgs: [], userInstallArgs: [] };
  }
}

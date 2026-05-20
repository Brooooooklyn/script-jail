// script-jail — src/guest/load-pm-flags.ts
//
// Loader for /etc/script-jail/pm-flags.json.
//
// NPM ONLY.  The macOS CLI (`src/cli/`) lands `/etc/script-jail/pm-flags.json`
// when forcing a Linux/x64 install resolution from an arm64 host running
// **npm**.  npm accepts `--cpu=x64 --os=linux --libc=glibc` as `npm ci`
// flags; Phase A (`phase-fetch.ts`) reads them here and appends them to the
// `npm ci` invocation — npm resolves its dependency graph during Phase A, so
// the arch hints must take effect there, NOT during Phase B
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
// Defensive read: the file is optional (the action does not write it, only
// the macOS CLI does).  Missing-file / parse-failure / schema-mismatch all
// degrade silently to "no extra args" — we do NOT fail the install for a
// malformed override; the worst case is that the audit proceeds without the
// arch hint, which is exactly the pre-PR 2 behaviour.

import * as fs from 'node:fs';

import { z } from 'zod';

const PmFlagsSchema = z.object({
  extra_install_args: z.array(z.string()),
});

/** Absolute path inside the VM where the CLI lands the override file. */
export const PM_FLAGS_PATH = '/etc/script-jail/pm-flags.json';

export function loadPmFlags(
  filePath: string = PM_FLAGS_PATH,
): { extraInstallArgs: string[] } {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = PmFlagsSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) return { extraInstallArgs: [] };
    return { extraInstallArgs: parsed.data.extra_install_args };
  } catch {
    // ENOENT, malformed JSON, EACCES, etc. — degrade silently.
    return { extraInstallArgs: [] };
  }
}

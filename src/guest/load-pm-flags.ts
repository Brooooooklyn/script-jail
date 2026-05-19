// script-jail — src/guest/load-pm-flags.ts
//
// Loader for /etc/script-jail/pm-flags.json.
//
// The macOS CLI (`src/cli/`) lands a `/etc/script-jail/pm-flags.json` file
// alongside the config when forcing a Linux/x64 install resolution from an
// arm64 host (npm/pnpm `--cpu=x64 --os=linux --libc=glibc`).  Phase A
// (`phase-fetch.ts`) reads it here and appends `extra_install_args` to the
// package manager's fetch/resolve invocation — npm/pnpm resolve their
// dependency graph during Phase A, so the arch hints must take effect there,
// NOT during Phase B (`phase-install.ts`) which runs `npm rebuild` /
// `pnpm install --offline` against the already-resolved tree.
//
// Yarn does not accept these flags on the CLI; the equivalent overlay is
// written by the CLI as a `.yarnrc.yml` (`supportedArchitectures`) and is
// not consulted through this loader.
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

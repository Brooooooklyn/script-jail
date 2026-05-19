// script-jail — phase-fetch.ts
// Phase A: fetch packages with network ON.
//
// Per-manager command notes:
//   npm: `npm ci --ignore-scripts`
//     npm has no clean "fetch-only" command. We run `npm ci --ignore-scripts`
//     which downloads packages into node_modules but skips lifecycle scripts.
//     Phase B will then run `npm rebuild --foreground-scripts` to execute
//     scripts against the already-populated node_modules under strace with
//     network disabled. This two-step gymnastics is necessary because:
//       - npm pack/install always merges fetch+install into one command.
//       - --ignore-scripts suppresses scripts in phase A so we can audit
//         them separately in the offline phase B.
//
//   pnpm: `pnpm fetch`
//     Fetches tarballs to the store without linking. Clean separation.
//
//   yarn: `yarn install --immutable --mode=skip-build`
//     Fetches and links packages but skips lifecycle script execution.
//     Phase B runs `yarn install --immutable --offline` which re-links and
//     triggers scripts (or yarn rebuild if needed).
//
// pm-flags.json (arch-resolution hints):
//   The macOS CLI may land /etc/script-jail/pm-flags.json containing
//   { "extra_install_args": ["--cpu=x64", "--os=linux", "--libc=glibc"] }.
//   These flags affect *dependency resolution*, which npm and pnpm do during
//   Phase A — so they MUST be appended here (not in Phase B, where the tree
//   is already resolved).  yarn does not accept these CLI flags; the
//   equivalent overlay is a `.yarnrc.yml` `supportedArchitectures` block
//   materialised by the CLI on the repo disk before the VM boots — so we
//   skip yarn here.

import { loadPmFlags } from './load-pm-flags.js';

export interface Spawner {
  spawn(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

export interface PhaseFetchInput {
  manager: 'npm' | 'pnpm' | 'yarn';
  cwd: string;
  env: NodeJS.ProcessEnv;
  spawner: Spawner;
  /**
   * Optional override for the pm-flags.json path.  Defaults to
   * `/etc/script-jail/pm-flags.json` via `loadPmFlags()`.  Exposed so unit
   * tests can stub the file location without mocking the filesystem.
   */
  pmFlagsPath?: string;
}

const FETCH_CMD: Record<'npm' | 'pnpm' | 'yarn', { cmd: string; args: string[] }> = {
  npm:  { cmd: 'npm',  args: ['ci', '--ignore-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['fetch'] },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--mode=skip-build'] },
};

export async function runFetchPhase(
  input: PhaseFetchInput,
): Promise<{ ok: boolean; stderr: string }> {
  const { cmd, args: baseArgs } = FETCH_CMD[input.manager];

  // Append pm-flags.json extras for npm / pnpm (yarn uses .yarnrc.yml overlay
  // landed by the CLI; no equivalent CLI form exists).  Order: <pm> <subcmd>
  // <baseArgs> <extra_install_args>.  Extras go last so they appear after the
  // fixed flags — package-manager argv parsers all treat trailing repeated
  // flags as overriding earlier ones, but here we never conflict with
  // baseArgs anyway (none of `ci` / `fetch` / `install` accept --cpu/--os).
  let args = baseArgs;
  if (input.manager === 'npm' || input.manager === 'pnpm') {
    const { extraInstallArgs } = loadPmFlags(input.pmFlagsPath);
    if (extraInstallArgs.length > 0) {
      args = [...baseArgs, ...extraInstallArgs];
    }
  }

  const result = await input.spawner.spawn(cmd, args, {
    env: input.env,
    cwd: input.cwd,
  });

  return {
    ok: result.exitCode === 0,
    stderr: result.stderr,
  };
}

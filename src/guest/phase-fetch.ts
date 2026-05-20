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
//   pnpm: `pnpm install --frozen-lockfile --ignore-scripts`
//     Materialises node_modules from the lockfile with network ON.
//     `--ignore-scripts` is REQUIRED: it suppresses every lifecycle script
//     in Phase A so they can all be re-run under strace in Phase B.
//
//     We deliberately do NOT use `pnpm fetch` here.  `pnpm fetch` only
//     populates the content-addressed store and builds the *virtual* store;
//     a subsequent `pnpm install --offline` then just links the top-level
//     node_modules and runs the REPO's own scripts — it never re-runs
//     DEPENDENCY build scripts, because the virtual store is already built.
//     That produced an audit which observed ZERO dependency lifecycle
//     scripts (an empty lockfile for any real monorepo).  Mirroring npm
//     (`npm ci --ignore-scripts` → `npm rebuild`), Phase A now does a full
//     scriptless install and Phase B runs `pnpm rebuild` so every dependency
//     build script executes under strace.  `--config.side-effects-cache=false`
//     keeps pnpm from caching built artifacts so Phase B always re-runs the
//     scripts fresh.
//
//   yarn: `yarn install --immutable --mode=skip-build`
//     Fetches and links packages but skips lifecycle script execution.
//     Phase B runs `yarn install --immutable --offline` which re-links and
//     triggers scripts (or yarn rebuild if needed).
//
// Arch-resolution hints (forcing Linux/x64 resolution from an arm64 host):
//   Each package manager has a DIFFERENT mechanism and they are applied at
//   different layers — there is no single CLI form that works everywhere:
//
//   * npm  — /etc/script-jail/pm-flags.json holds
//            { "extra_install_args": ["--cpu=x64","--os=linux","--libc=glibc"] }.
//            npm honours these as `npm ci` flags and resolves the dependency
//            graph during Phase A, so they MUST be appended here (Phase B is
//            too late — the tree is already resolved).
//
//   * pnpm — pnpm does NOT accept --cpu/--os/--libc on the CLI (`pnpm
//            install --cpu=x64` fails with "Unknown options: 'cpu', 'os',
//            'libc'").  Its mechanism is a `pnpm.supportedArchitectures`
//            block in the repo's root package.json.  `pnpm install` reads
//            that block and picks the platform variants to resolve and
//            download — so the guest merges it into package.json HERE,
//            before `pnpm install` runs.  See `apply-pnpm-arch.ts`.
//
//   * yarn — Berry reads `supportedArchitectures` from a `.yarnrc.yml` the
//            CLI lands on the repo disk before the VM boots; nothing to do
//            here.
//
//   All three overlay files are OPTIONAL: only the macOS CLI stages them and
//   only on an arm64 host.  Absence is the normal action path.

import { applyPnpmArchOverlay } from './apply-pnpm-arch.js';
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
   * Optional override for the pm-flags.json path (npm only).  Defaults to
   * `/etc/script-jail/pm-flags.json` via `loadPmFlags()`.  Exposed so unit
   * tests can stub the file location without mocking the filesystem.
   */
  pmFlagsPath?: string;
  /**
   * Optional override for the pnpm-arch.json path (pnpm only).  Defaults to
   * `/etc/script-jail/pnpm-arch.json` via `applyPnpmArchOverlay()`.  Exposed
   * so unit tests can stub the file location.
   */
  pnpmArchPath?: string;
}

const FETCH_CMD: Record<'npm' | 'pnpm' | 'yarn', { cmd: string; args: string[] }> = {
  npm:  { cmd: 'npm',  args: ['ci', '--ignore-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false'] },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--mode=skip-build'] },
};

export async function runFetchPhase(
  input: PhaseFetchInput,
): Promise<{ ok: boolean; stderr: string }> {
  const { cmd, args: baseArgs } = FETCH_CMD[input.manager];

  // npm: append pm-flags.json extras (`--cpu/--os/--libc`) to `npm ci`.
  // Order: npm ci <baseArgs> <extra_install_args>.  Extras go last so they
  // appear after the fixed flags — they never conflict with `ci`'s flags.
  let args = baseArgs;
  if (input.manager === 'npm') {
    const { extraInstallArgs } = loadPmFlags(input.pmFlagsPath);
    if (extraInstallArgs.length > 0) {
      args = [...baseArgs, ...extraInstallArgs];
    }
  }

  // pnpm: pnpm rejects --cpu/--os/--libc on the CLI, so the arch hint is a
  // `pnpm.supportedArchitectures` block merged into the repo's package.json
  // BEFORE `pnpm install` runs (install reads that block to pick which
  // platform variants to resolve and download).  No-op when the overlay file
  // is absent (the normal action path) — see apply-pnpm-arch.ts.
  if (input.manager === 'pnpm') {
    applyPnpmArchOverlay({ cwd: input.cwd, ...(input.pnpmArchPath !== undefined ? { overlayPath: input.pnpmArchPath } : {}) });
  }

  // For pnpm: force the content-addressed store onto the repo overlay
  // disk (4 GB, same filesystem as node_modules so hardlinks work).
  // The default ~/.local/share/pnpm/store lives on the much smaller
  // rootfs ext4 (~512 MB), which overruns silently on real monorepos
  // (vuejs/core ≈ 500 MB).  pnpm's CLI flag wins over .npmrc / env in
  // its config precedence chain, so this is the only fully reliable
  // place to set it — the `npm_config_store_dir` env in agent.ts
  // turned out to be a no-op in pnpm 11.x against fixtures that ship
  // their own .npmrc.  `--store-dir` is a global pnpm flag and may
  // legally appear before or after the subcommand.
  if (input.manager === 'pnpm') {
    args = [...args, `--store-dir=${input.cwd}/.pnpm-store`];
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

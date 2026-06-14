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
//     Phase B runs `yarn install --immutable` (NOT `--offline` — that is a
//     Yarn Classic flag Berry rejects) which re-links and runs the deferred
//     build scripts against this cache, offline via the netns sever.
//
// Optional package-manager resolution hints:
//   The normal same-arch parity path does not stage these files.  If a future
//   explicit override mode supplies them, each package manager has a DIFFERENT
//   mechanism and they are applied at different layers — there is no single
//   CLI form that works everywhere:
//
//   * npm  — /etc/script-jail/pm-flags.json holds
//            { "extra_install_args": [...] }. npm honours these as `npm ci`
//            flags and resolves the dependency graph during Phase A, so they
//            MUST be appended here (Phase B is too late — the tree is already
//            resolved).
//
//   * pnpm — pnpm does NOT accept --cpu/--os/--libc on the CLI. Its override
//            mechanism is a `pnpm.supportedArchitectures` block in the repo's
//            root package.json. `pnpm install` reads that block and picks the
//            platform variants to resolve and download — so the guest merges
//            it into package.json HERE, before `pnpm install` runs. See
//            `apply-pnpm-arch.ts`.
//
//   * yarn — Berry reads `supportedArchitectures` from a `.yarnrc.yml` the
//            CLI lands on the repo disk before the VM boots; nothing to do
//            here.
//
//   All three overlay files are OPTIONAL. Absence is the normal action and
//   CLI path after the switch to arm64 CI parity.

import { FETCH_CMD, pnpmStoreDirArg } from '../shared/pm-commands.js';
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

// FETCH_CMD lives in ../shared/pm-commands.ts so the host drop-in install
// (src/action/host-install.ts part-1) uses the byte-identical command.

export async function runFetchPhase(
  input: PhaseFetchInput,
): Promise<{ ok: boolean; stderr: string; stdout: string }> {
  const { cmd, args: baseArgs } = FETCH_CMD[input.manager];

  // pm-flags.json carries two distinct channels (load-pm-flags.ts):
  //   * extra_install_args — npm-ONLY arch hints (`--cpu/--os/--libc`).  pnpm
  //     and yarn reject those CLI flags, so they are spliced for npm only.
  //   * user_install_args  — DEVELOPER install flags (the action `args` input,
  //     e.g. `-D`/`--prod`/`--omit=dev`), already sanitized of any
  //     script-re-enabler host-side.  These are valid for ALL three managers
  //     and MUST be applied identically here and in the host part-1 install
  //     (src/action/host-install.ts) or the byte-stable lock drifts.
  // Order: <cmd> <fixed baseArgs> <npm arch hints> <user args>.  User args go
  // last (after the fixed flags) but BEFORE the pnpm `--store-dir` splice below.
  const { extraInstallArgs, userInstallArgs } = loadPmFlags(input.pmFlagsPath);
  let args = baseArgs;
  if (input.manager === 'npm' && extraInstallArgs.length > 0) {
    args = [...args, ...extraInstallArgs];
  }
  if (userInstallArgs.length > 0) {
    args = [...args, ...userInstallArgs];
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
  // legally appear before or after the subcommand.  The flag string is
  // shared with the host install via pnpmStoreDirArg so the two cannot drift.
  args = [...args, ...pnpmStoreDirArg(input.manager, input.cwd)];

  const result = await input.spawner.spawn(cmd, args, {
    env: input.env,
    cwd: input.cwd,
  });

  return {
    ok: result.exitCode === 0,
    stderr: result.stderr,
    // yarn Berry writes its progress AND its errors (YN0001 ENOSPC traces,
    // resolution failures, …) to STDOUT; stderr is typically empty.  Return
    // stdout too so the agent's Phase A failure dump can include it — an
    // empty fatal message hides the actual cause (found dogfooding napi-rs).
    stdout: result.stdout,
  };
}

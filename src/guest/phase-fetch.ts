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

import { accessSync, constants as fsConstants, statSync } from 'node:fs';
import { delimiter, isAbsolute, join, resolve } from 'node:path';

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
   * The pm-flags.json content delivered DIRECTLY via env
   * (`SCRIPT_JAIL_PM_FLAGS_CONTENT`).  Preferred over `pmFlagsPath` so the
   * control sidecar never lands at a lifecycle-visible filesystem path
   * (audit-only sidecar oracle).  The production delivery channel on every
   * backend; the path is the fallback / test seam.
   */
  pmFlagsContent?: string;
  /**
   * Optional override for the pnpm-arch.json path (pnpm only).  Defaults to
   * `/etc/script-jail/pnpm-arch.json` via `applyPnpmArchOverlay()`.  Exposed
   * so unit tests can stub the file location.
   */
  pnpmArchPath?: string;
  /**
   * The pnpm-arch.json content delivered DIRECTLY via env
   * (`SCRIPT_JAIL_PNPM_ARCH_CONTENT`).  Preferred over `pnpmArchPath` — same
   * audit-only sidecar oracle close as `pmFlagsContent`.
   */
  pnpmArchContent?: string;
}

// FETCH_CMD lives in ../shared/pm-commands.ts so the host drop-in install
// (src/action/host-install.ts part-1) uses the byte-identical command.

// ---------------------------------------------------------------------------
// SECURITY: pin npm's `git` config to the guest's OWN trusted git (Phase A)
// ---------------------------------------------------------------------------
//
// npm's `git` CONFIG selects the git BINARY npm invokes to clone a non-GitHub
// git dependency (git+https://gitlab.com/…, git+ssh://, git+file://; GitHub
// deps use the codeload HTTPS tarball and never trigger git).  `npm ci
// --ignore-scripts` INVOKES that configured git during Phase A — `--ignore-scripts`
// only disables lifecycle SCRIPTS, which is orthogonal to which git binary runs.
// A repo `.npmrc` can OVERRIDE the git binary (`git=./fake-git`), and the
// sandbox stages the repo verbatim (including that `./fake-git`), so without a
// pin the AUDIT would clone a fake/benign tree while the host (already pinned to
// a trusted git via src/action/host-install.ts) clones the REAL tree — the lock
// would match yet authorize an un-audited dependency tree.  Pin the guest fetch
// to a trusted git so host==guest parity holds.
//
// npm config precedence: an `npm_config_git` ENV var BEATS the project `.npmrc`,
// so injecting it into the fetch child env defeats the repo override.  The guest
// PATH is curated and carries NO checkout dir, so resolving git on the guest
// PATH (to an ABSOLUTE path, skipping any candidate under the staged repo `cwd`)
// is safe; the bare literal `git` fallback still OVERRIDES (defeats) the repo
// `.npmrc git=` entry and npm resolves it via the curated PATH.  The guest's git
// can clone ANY url, including legit private git deps, so this does not break
// them — it only stops a checkout-resident fake git from being honored.
// npm-specific but harmless for pnpm/yarn (they ignore `npm_config_git`), so it
// is applied ONLY on the npm fetch.  Phase B (`npm rebuild`) never clones, so the
// pin belongs here on the fetch path.
function trustedGuestGit(cwd: string): string {
  const pathVar = process.env['PATH'];
  if (pathVar !== undefined && pathVar !== '') {
    const repo = resolve(cwd);
    for (const dir of pathVar.split(delimiter)) {
      if (dir === '') continue;
      const candidate = join(dir, 'git');
      // Only an ABSOLUTE candidate OUTSIDE the staged repo: a relative PATH
      // entry (e.g. `.`) or one under the checkout could point npm at a
      // repo-placed shadow `git`.
      if (!isAbsolute(candidate)) continue;
      if (candidate === repo || candidate.startsWith(repo + '/')) continue;
      // MODEL execvp (#45, mirror the host twin resolveGitFromPath + resolveBareOnPath,
      // round-17c/17d): npm execs npm_config_git as a bare-name resolution, so only a
      // regular, EXECUTABLE file is a real hit.  A DIRECTORY or NON-EXECUTABLE file named
      // `git` earlier on PATH is skipped by execvp (it keeps scanning); existsSync alone
      // returned it and pinned it, failing a git: dep clone that would otherwise fall
      // through to the real git.  statSync follows symlinks; a missing candidate throws →
      // skip.  Robustness only: the guest PATH is curated (no checkout dir), and the host
      // twin fails identically, so there is no audit-vs-host divergence.
      let st;
      try {
        st = statSync(candidate);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      try {
        accessSync(candidate, fsConstants.X_OK);
      } catch {
        continue;
      }
      return candidate;
    }
  }
  // No git outside the repo on PATH — fall back to the bare literal.  It still
  // OVERRIDES the repo `.npmrc git=` value (defeating the redirect) and npm
  // resolves it via the curated guest PATH (which has no checkout dir).
  return 'git';
}

export async function runFetchPhase(
  input: PhaseFetchInput,
): Promise<{ ok: boolean; stderr: string; stdout: string; userInstallArgs: string[] }> {
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
  const { extraInstallArgs, userInstallArgs } = loadPmFlags(
    input.pmFlagsPath,
    input.pmFlagsContent,
  );
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
    applyPnpmArchOverlay({
      cwd: input.cwd,
      ...(input.pnpmArchPath !== undefined ? { overlayPath: input.pnpmArchPath } : {}),
      ...(input.pnpmArchContent !== undefined ? { content: input.pnpmArchContent } : {}),
    });
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

  // SECURITY (npm only): pin the git binary to the guest's trusted git so the
  // audit clones the SAME (real) tree the host does, defeating a repo
  // `.npmrc git=./fake-git` redirect.  Set LAST so it overrides any inherited
  // `npm_config_git` from `input.env`.  pnpm/yarn ignore this key, so a clone
  // of `input.env` only for npm keeps their fetch env byte-identical (no spurious
  // env_read of an unread key).  See trustedGuestGit() above.
  const env =
    input.manager === 'npm'
      ? { ...input.env, npm_config_git: trustedGuestGit(input.cwd) }
      : input.env;

  const result = await input.spawner.spawn(cmd, args, {
    env,
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
    // Surface the (already re-sanitized) developer install args spliced into
    // the fetch argv above.  On the Phase-A FAILURE path the agent masks these
    // exact values out of the redacted detail BEFORE it reaches either sink
    // (serial console + fatal frame) — a PM error like
    // `npm warn invalid config registry="SECRET"` echoes a user-arg value that
    // matches no credential SHAPE and no protected-ENV value, so without this
    // it would leak to the public Actions log (adversarial-review round-7).
    userInstallArgs,
  };
}

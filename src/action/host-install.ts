// script-jail — src/action/host-install.ts
//
// The drop-in install on the GitHub-Actions runner (NOT the sandbox).  Two
// halves, mirroring the guest's two-phase split, so the host's node_modules is
// "the thing the sandbox audited":
//
//   part 1  hostInstallNoScripts  — package-manager install with EVERY
//           lifecycle script disabled (FETCH_CMD).  Always safe: no untrusted
//           code runs.  Populates the REAL repoDir/node_modules.
//
//   part 2  hostRunScripts        — runs the deferred lifecycle scripts
//           (INSTALL_CMD).  The caller MUST gate this on a clean audit
//           (runAudit's `trusted`), so it only ever runs scripts whose
//           behaviour matches the committed, reviewed lock.
//
// SECURITY NOTES
//   * Both halves spawn the package manager with an argv array and `shell:false`
//     — developer `args` are NEVER interpreted by a shell (no injection).
//   * `sanitizeInstallArgs` strips any arg that would re-enable scripts during
//     part 1; the FETCH_CMD disable flag always wins.
//   * Part 2 runs ONLINE with full host access (the runner has no netns sever).
//     This is inherent — real postinstalls fetch prebuilt binaries — so a
//     `connect` the sandbox recorded as `<BLOCKED>` WILL succeed here.  Trust
//     derives from the reviewed lock, not from host isolation.  See docs.

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, isAbsolute, join } from 'node:path';

import {
  FETCH_CMD,
  INSTALL_CMD,
  pnpmStoreDirArg,
  sanitizeInstallArgs,
  type Manager,
} from '../shared/pm-commands.js';
import { deriveSensitiveValues, maskExactValues, redactCredentialShapes } from '../shared/redact.js';

// ---------------------------------------------------------------------------
// SECURITY: pin npm's `git` config to the trusted runner git
// ---------------------------------------------------------------------------
//
// npm's `git` CONFIG selects the git BINARY npm invokes for git operations
// (clone / ls-remote) and is read from the project `.npmrc` in repoDir.  When
// the lockfile carries a NON-GitHub git dependency (git+https://gitlab.com/…,
// git+ssh://, git+file://; GitHub deps use the codeload HTTPS tarball and never
// trigger git), `npm ci --ignore-scripts` INVOKES that configured git to fetch
// the dep.  `--ignore-scripts` does NOT prevent this — it disables lifecycle
// SCRIPTS, which is orthogonal to which git binary runs.  So a PR that commits
// `.npmrc` with `git=./evil` + a non-GitHub git dep would execute `./evil` on
// the runner during the pre-trust host part-1, BEFORE the trust gate.
//
// npm config precedence: an `npm_config_git` ENV var BEATS the project
// `.npmrc`, so injecting it into the child env defeats the override.  We
// resolve the ABSOLUTE path of the trusted runner git ONCE (an absolute path so
// a repo-placed `./git` in cwd cannot shadow a bare `git`).  If it can't be
// resolved we fall back to the bare literal `git` — still a value that
// OVERRIDES (and thus defeats) the repo `.npmrc git=` entry; npm then resolves
// it via PATH like any other command.  npm-specific but harmless for
// pnpm/yarn (they ignore `npm_config_git`).
let RESOLVED_TRUSTED_GIT: string | undefined;
function trustedGitPath(): string {
  if (RESOLVED_TRUSTED_GIT !== undefined) return RESOLVED_TRUSTED_GIT;
  RESOLVED_TRUSTED_GIT = resolveGitFromPath() ?? 'git';
  return RESOLVED_TRUSTED_GIT;
}

/**
 * Scan `process.env.PATH` for the first executable named `git`/`git.exe` and
 * return its ABSOLUTE path.  Returns `undefined` when none is found (caller
 * falls back to the bare literal, which still overrides the repo `.npmrc`).
 */
function resolveGitFromPath(): string | undefined {
  const pathVar = process.env['PATH'];
  if (pathVar === undefined || pathVar === '') return undefined;
  const names = process.platform === 'win32' ? ['git.exe', 'git.cmd', 'git'] : ['git'];
  for (const dir of pathVar.split(delimiter)) {
    if (dir === '') continue;
    for (const name of names) {
      const candidate = join(dir, name);
      // Only accept an ABSOLUTE candidate so a relative PATH entry (e.g. `.`)
      // can't point npm at a repo-placed shadow binary.
      if (isAbsolute(candidate) && existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

/**
 * Child env for the host PM spawns: the inherited environment plus the
 * `npm_config_git` pin (see the security note above) and, for yarn, the
 * startup-exec env neutralizers below.  MERGES over `process.env` so PATH /
 * HOME / registry auth are preserved.
 *
 * SECURITY (yarn): Yarn Berry maps env vars to config, so an INHERITED `YARN_*`
 * can re-introduce exactly the startup code-exec the preflight blocks in
 * `.yarnrc.yml`:
 *   * `YARN_YARN_PATH` re-execs a repo binary as "yarn",
 *   * `YARN_PLUGINS` loads a repo module at startup,
 *   * `YARN_RC_FILENAME` redirects yarn to an ALTERNATE repo rc that declares
 *     yarnPath/plugins — dodging the preflight, which inspects only `.yarnrc.yml`,
 *   * `YARN_ENABLE_CONSTRAINTS_CHECKS` runs a repo `yarn.config.cjs`.
 * The host process inherits `process.env`, so we override these four on the yarn
 * child to neutralize every inherited-ENV vector (verified against Yarn Berry
 * 4.x).  Registry auth flows through UNRELATED keys (`YARN_NPM_AUTH_TOKEN` /
 * `YARN_NPM_REGISTRY_SERVER`) and is preserved.  This mirrors the `npm_config_git`
 * pin (a config-redirect defense) and is HOST-ONLY: the SANDBOX keeps repo config
 * so the hooks are AUDITED there (the enforcement boundary).  `YARN_IGNORE_PATH=1`
 * kills yarnPath from BOTH the file and the env; `YARN_RC_FILENAME` is forced to
 * the preflight-vetted default so an env redirect cannot dodge the static reject.
 *
 * SCOPE: `YARN_PLUGINS=''` governs only the ENV plugin source, NOT the rc-file
 * `plugins:` cascade — Berry still loads a `plugins:` entry from a PARENT-dir or
 * `~/.yarnrc.yml` even under this env (the rc loop runs unconditionally when
 * `useRc`).  Parent dirs ABOVE the checkout and `~` are runner-owned (out of the
 * PR-author threat model: actions/checkout confines a PR to `$GITHUB_WORKSPACE`).
 * But repoDir is NOT always the checkout root: with `SCRIPT_JAIL_REPO_DIR` it can
 * be a SUBDIRECTORY of the checkout, in which case the PR-controlled ancestor rc
 * files BETWEEN repoDir and `$GITHUB_WORKSPACE` ARE in scope — so the preflight
 * (install-preflight.ts) now scans every `.yarnrc.yml` from repoDir up to and
 * including `$GITHUB_WORKSPACE`, rejecting an ancestor `plugins:`/`yarnPath`
 * before this env is ever used.  The repo's own `.yarnrc.yml plugins:` is
 * likewise rejected there.
 */
function hostInstallEnv(pm: Manager): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, npm_config_git: trustedGitPath() };
  if (pm === 'yarn') {
    env['YARN_IGNORE_PATH'] = '1';
    env['YARN_RC_FILENAME'] = '.yarnrc.yml';
    env['YARN_PLUGINS'] = '';
    env['YARN_ENABLE_CONSTRAINTS_CHECKS'] = 'false';
  }
  return env;
}

/** Minimal sink so the module is testable without touching the real streams. */
export interface HostInstallIo {
  stdout: { write(s: string): void };
  stderr: { write(s: string): void };
  warn(msg: string): void;
}

/**
 * Injectable process runner (tests pass a fake).  Returns the child's exit
 * status (`null` when killed by a signal) and any spawn-level error.
 *
 * A capturing runner additionally returns the child's `stdout`/`stderr` as
 * strings so the caller can redact them before writing to the job log
 * (`undefined` ⇒ the runner inherited the streams live, nothing to redact).
 */
export type HostSpawn = (
  cmd: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) => {
  status: number | null;
  signal?: NodeJS.Signals | null;
  error?: Error | undefined;
  stdout?: string;
  stderr?: string;
};

// 64 MiB capture cap: verbose installs (npm/pnpm/yarn debug spew) can be large;
// the default 1 MiB maxBuffer would truncate and surface ENOBUFS instead of the
// real exit status, losing the diagnostic we need on failure.
const CAPTURE_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * Part-1 runner: inherit stdin, but CAPTURE stdout+stderr so they can be piped
 * through the redactor before reaching the job log.  Part 1 takes the user
 * `args`, so the PM's own diagnostics may echo a user-supplied secret back —
 * inheriting them live would leak (e.g. `npm warn invalid config
 * registry="SECRET"`).  `shell:false` keeps args as discrete argv items.
 */
const captureSpawn: HostSpawn = (cmd, args, cwd, env) => {
  const r = spawnSync(cmd, args, {
    cwd,
    // SECURITY: `env` carries the `npm_config_git` pin so a repo `.npmrc git=`
    // cannot redirect npm's git binary during the PRE-TRUST part-1 install
    // (see hostInstallEnv() / trustedGitPath()).
    env,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    encoding: 'utf8',
    maxBuffer: CAPTURE_MAX_BUFFER,
  });
  return {
    status: r.status,
    signal: r.signal,
    error: r.error,
    stdout: typeof r.stdout === 'string' ? r.stdout : '',
    stderr: typeof r.stderr === 'string' ? r.stderr : '',
  };
};

/**
 * Part-2 runner: stream straight to the job log.  Part 2 (hostRunScripts) takes
 * NO user args — its argv is credential-free — and lifecycle scripts can run
 * long, so users want LIVE progress.  Keep `stdio:'inherit'`; nothing to redact.
 */
const inheritSpawn: HostSpawn = (cmd, args, cwd, env) => {
  // SECURITY: `env` carries the same git pin as part 1 (defense-in-depth;
  // harmless for pnpm/yarn, which ignore npm_config_git).
  const r = spawnSync(cmd, args, { cwd, env, stdio: 'inherit', shell: false });
  return { status: r.status, signal: r.signal, error: r.error };
};

/**
 * Part 1 — install dependencies on the host with lifecycle scripts disabled.
 * Throws on spawn failure or a non-zero exit (no usable tree → fail the job).
 */
export function hostInstallNoScripts(
  pm: Manager,
  repoDir: string,
  args: ReadonlyArray<string>,
  io: HostInstallIo,
  spawn: HostSpawn = captureSpawn,
): void {
  const { kept, dropped, droppedKeys } = sanitizeInstallArgs(args);
  // SECURITY: never log raw `dropped` tokens — they may carry credential values
  // (e.g. `--ignore-scripts=SECRET`).  Log only the canonical flag names
  // (droppedKeys) which are well-known constants, never user-supplied text.
  if (droppedKeys.length > 0) {
    const n = dropped.length; // raw token count (flag + consumed value tokens)
    const keys = droppedKeys.join(', ');
    io.warn(
      `script-jail: ignoring ${n} install arg${n === 1 ? '' : 's'} matching ${keys} — ` +
        `it would re-enable lifecycle scripts in the no-scripts install ` +
        `(the sandbox is the only place scripts run unaudited).`,
    );
  }
  const base = FETCH_CMD[pm];
  // SECURITY (host part-1 ONLY): pnpm executes a repo `.pnpmfile.cjs` (and
  // config-relocated pnpmfiles) at `require` time during `pnpm install
  // --ignore-scripts`, BEFORE the trust gate — `--ignore-scripts` does NOT stop
  // it.  `--ignore-pnpmfile` is a robust catch-all (no path-enumeration gap) that
  // suppresses EVERY pnpmfile variant; for a repo that legitimately ships a
  // pnpmfile its committed `pnpmfileChecksum` then makes this `--frozen-lockfile`
  // install abort (fail closed).  This is a HOST-ONLY deviation from the shared
  // FETCH_CMD: the SANDBOX fetch keeps the pnpmfile so the hook is AUDITED there
  // (the enforcement boundary).  Repos that ship a pnpmfile are already refused
  // install upstream (install-preflight.ts), so for the clean repos that reach
  // here this flag is a no-op and the host/sandbox trees still match byte-for-byte.
  const hostHardening = pm === 'pnpm' ? ['--ignore-pnpmfile'] : [];
  // Order mirrors the guest fetch phase: <fixed args> <user args> <store-dir>.
  // The pnpm `--store-dir` pin is appended last so the host links against the
  // same repo-local store the audited sandbox used (see pnpmStoreDirArg).
  const finalArgs = [...base.args, ...kept, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  // SECURITY: safeDisplayArgs is used for the banner AND error messages.  It
  // contains ONLY the fixed base args + store-dir (no user-supplied tokens).
  // A count-only suffix documents that user args exist without echoing them.
  const safeBaseArgs = [...base.args, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  const userArgSuffix =
    kept.length > 0
      ? ` (+${kept.length} user install arg${kept.length === 1 ? '' : 's'}, not shown)`
      : '';
  io.stdout.write(
    `[script-jail] host install (lifecycle scripts disabled): ${base.cmd} ${safeBaseArgs.join(' ')}${userArgSuffix}\n`,
  );
  // Pass safeBaseArgs (without user tokens) as displayArgs so that error
  // messages (signal / non-zero exit) never expose credentials.
  const safeDisplayArgs = kept.length > 0
    ? [...safeBaseArgs, `(+${kept.length} user install arg${kept.length === 1 ? '' : 's'}, not shown)`]
    : safeBaseArgs;
  // The PM's OWN captured stdout/stderr is run through the redactor before it
  // reaches the job log (the user args this part takes can be echoed back by
  // the PM — e.g. `npm warn invalid config registry="SECRET"`).  Written
  // REGARDLESS of exit status: the user needs to see PM output, especially on
  // failure.  Redaction is LOG-ONLY — the real `args` already went to spawn.
  const sensitive = deriveSensitiveValues(kept);
  const onOutput = (stdout: string, stderr: string): void => {
    if (stdout.length > 0) io.stdout.write(redactCaptured(stdout, sensitive));
    if (stderr.length > 0) io.stderr.write(redactCaptured(stderr, sensitive));
  };
  runOrThrow(base.cmd, finalArgs, repoDir, hostInstallEnv(pm), spawn, 'no-scripts install', io, safeDisplayArgs, onOutput);
}

/** Mask user-arg values first (exact), then catch credential SHAPES. */
function redactCaptured(text: string, sensitive: readonly string[]): string {
  let red = maskExactValues(text, sensitive, 'REDACTED:USER-ARG');
  red = redactCredentialShapes(red);
  return red;
}

/**
 * Part 2 — run the lifecycle scripts part 1 deferred.  The caller MUST have
 * confirmed the audit is `trusted` before calling this.  Throws on failure.
 */
export function hostRunScripts(
  pm: Manager,
  repoDir: string,
  io: HostInstallIo,
  spawn: HostSpawn = inheritSpawn,
): void {
  const cmd = INSTALL_CMD[pm];
  // Same store-dir pin as part 1 / the guest install phase: pnpm must relink
  // against the repo-local store, not the runner default (parity).
  const finalArgs = [...cmd.args, ...pnpmStoreDirArg(pm, repoDir)];
  io.stdout.write(`[script-jail] host lifecycle scripts (audit matched): ${cmd.cmd} ${finalArgs.join(' ')}\n`);
  // hostRunScripts has no user args — finalArgs is credential-free, safe as displayArgs.
  runOrThrow(cmd.cmd, finalArgs, repoDir, hostInstallEnv(pm), spawn, 'lifecycle-script run', io, finalArgs);
}

/**
 * Spawn `cmd args` in `cwd` and throw a descriptive error on failure.
 *
 * SECURITY: error messages MUST NOT interpolate the real `args` when the caller
 * passes user-controlled tokens (e.g. registry auth tokens).  Instead the caller
 * supplies a separate `displayArgs` whose text is safe to expose in the GitHub
 * Actions log.  The real `args` are passed to `spawn` unchanged — only the
 * human-readable error messages use `displayArgs`.
 *
 * `displayArgs` MUST be set to a credential-free representation.  For
 * `hostInstallNoScripts` that means the fixed base args + a count-only suffix
 * for any user args; for `hostRunScripts` (no user args) it is identical to
 * `args`.
 */
function runOrThrow(
  cmd: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  spawn: HostSpawn,
  label: string,
  io: HostInstallIo,
  displayArgs: string[],
  onOutput?: (stdout: string, stderr: string) => void,
): void {
  const r = spawn(cmd, args, cwd, env);
  // Surface captured output (redacted by the caller's closure) BEFORE any
  // error/throw check, so the PM's own diagnostics reach the log even when the
  // run failed.  A live-inheriting runner returns no stdout/stderr → no-op.
  if (onOutput !== undefined && (r.stdout !== undefined || r.stderr !== undefined)) {
    onOutput(r.stdout ?? '', r.stderr ?? '');
  }
  if (r.error !== undefined) {
    // spawn-level failure: never had an argv in a shell — no leak path here.
    throw new Error(`script-jail: host ${label} could not spawn "${cmd}": ${r.error.message}`);
  }
  if (r.signal != null) {
    // Use displayArgs (safe), NOT args (may contain credentials).
    throw new Error(`script-jail: host ${label} (\`${cmd} ${displayArgs.join(' ')}\`) was killed by ${r.signal}`);
  }
  if (r.status !== 0) {
    // Use displayArgs (safe), NOT args (may contain credentials).
    throw new Error(
      `script-jail: host ${label} (\`${cmd} ${displayArgs.join(' ')}\`) exited with code ${r.status ?? 'null'}`,
    );
  }
  io.stdout.write(`[script-jail] host ${label} complete\n`);
}

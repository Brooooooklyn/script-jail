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

import {
  FETCH_CMD,
  INSTALL_CMD,
  pnpmStoreDirArg,
  sanitizeInstallArgs,
  type Manager,
} from '../shared/pm-commands.js';

/** Minimal sink so the module is testable without touching the real streams. */
export interface HostInstallIo {
  stdout: { write(s: string): void };
  warn(msg: string): void;
}

/**
 * Injectable process runner (tests pass a fake).  Returns the child's exit
 * status (`null` when killed by a signal) and any spawn-level error.
 */
export type HostSpawn = (
  cmd: string,
  args: string[],
  cwd: string,
) => { status: number | null; signal?: NodeJS.Signals | null; error?: Error | undefined };

const defaultSpawn: HostSpawn = (cmd, args, cwd) => {
  // stdio:'inherit' streams the install straight to the job log; shell:false
  // (the default, asserted for clarity) keeps args as discrete argv items.
  const r = spawnSync(cmd, args, { cwd, stdio: 'inherit', shell: false });
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
  spawn: HostSpawn = defaultSpawn,
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
  // Order mirrors the guest fetch phase: <fixed args> <user args> <store-dir>.
  // The pnpm `--store-dir` pin is appended last so the host links against the
  // same repo-local store the audited sandbox used (see pnpmStoreDirArg).
  const finalArgs = [...base.args, ...kept, ...pnpmStoreDirArg(pm, repoDir)];
  // SECURITY: safeDisplayArgs is used for the banner AND error messages.  It
  // contains ONLY the fixed base args + store-dir (no user-supplied tokens).
  // A count-only suffix documents that user args exist without echoing them.
  const safeBaseArgs = [...base.args, ...pnpmStoreDirArg(pm, repoDir)];
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
  runOrThrow(base.cmd, finalArgs, repoDir, spawn, 'no-scripts install', io, safeDisplayArgs);
}

/**
 * Part 2 — run the lifecycle scripts part 1 deferred.  The caller MUST have
 * confirmed the audit is `trusted` before calling this.  Throws on failure.
 */
export function hostRunScripts(
  pm: Manager,
  repoDir: string,
  io: HostInstallIo,
  spawn: HostSpawn = defaultSpawn,
): void {
  const cmd = INSTALL_CMD[pm];
  // Same store-dir pin as part 1 / the guest install phase: pnpm must relink
  // against the repo-local store, not the runner default (parity).
  const finalArgs = [...cmd.args, ...pnpmStoreDirArg(pm, repoDir)];
  io.stdout.write(`[script-jail] host lifecycle scripts (audit matched): ${cmd.cmd} ${finalArgs.join(' ')}\n`);
  // hostRunScripts has no user args — finalArgs is credential-free, safe as displayArgs.
  runOrThrow(cmd.cmd, finalArgs, repoDir, spawn, 'lifecycle-script run', io, finalArgs);
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
  spawn: HostSpawn,
  label: string,
  io: HostInstallIo,
  displayArgs: string[],
): void {
  const r = spawn(cmd, args, cwd);
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

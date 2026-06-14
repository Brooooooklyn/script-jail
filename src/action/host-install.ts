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

import { FETCH_CMD, INSTALL_CMD, sanitizeInstallArgs, type Manager } from '../shared/pm-commands.js';

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
  const { kept, dropped } = sanitizeInstallArgs(args);
  for (const d of dropped) {
    io.warn(
      `script-jail: ignoring install arg "${d}" — it would re-enable lifecycle ` +
        `scripts in the no-scripts install (the sandbox is the only place scripts run unaudited).`,
    );
  }
  const base = FETCH_CMD[pm];
  const finalArgs = [...base.args, ...kept];
  io.stdout.write(`[script-jail] host install (lifecycle scripts disabled): ${base.cmd} ${finalArgs.join(' ')}\n`);
  runOrThrow(base.cmd, finalArgs, repoDir, spawn, 'no-scripts install', io);
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
  io.stdout.write(`[script-jail] host lifecycle scripts (audit matched): ${cmd.cmd} ${cmd.args.join(' ')}\n`);
  runOrThrow(cmd.cmd, cmd.args, repoDir, spawn, 'lifecycle-script run', io);
}

function runOrThrow(
  cmd: string,
  args: string[],
  cwd: string,
  spawn: HostSpawn,
  label: string,
  io: HostInstallIo,
): void {
  const r = spawn(cmd, args, cwd);
  if (r.error !== undefined) {
    throw new Error(`script-jail: host ${label} could not spawn "${cmd}": ${r.error.message}`);
  }
  if (r.signal != null) {
    throw new Error(`script-jail: host ${label} (\`${cmd} ${args.join(' ')}\`) was killed by ${r.signal}`);
  }
  if (r.status !== 0) {
    throw new Error(
      `script-jail: host ${label} (\`${cmd} ${args.join(' ')}\`) exited with code ${r.status ?? 'null'}`,
    );
  }
  io.stdout.write(`[script-jail] host ${label} complete\n`);
}

// macOS ProcReader — no /proc filesystem available.
//
// On Linux, attribution walks /proc/<pid>/{status,environ} to find the npm
// lifecycle context of a spawned process.  macOS has neither: there is no
// /proc, and KERN_PROCARGS2 is SIP-fragile and fails for reaped pids (see
// Phase 1 of the plan).  So this reader is intentionally minimal:
//
//   - `readEnviron()` always returns null.  `Attribution._walk` explicitly
//     supports a null environ (attribution.ts:209-211): it keeps walking up
//     the ppid chain, and a process whose environ is unreadable contributes
//     nothing of its own.  On macOS attribution therefore flows ENTIRELY
//     through the shim event seed (`shimExecAttribution` /
//     `shimNodeStartupAttribution` in phase-install.ts) — the shim stamps a
//     process's own ctor-snapshotted npm lifecycle env into its `exec` /
//     `node_startup_done` records, which seed `recordAttribution` /
//     `nodeStartupAttributionByPid` byte-identically to the /proc-walk path.
//
//   - `readPpid()` is best-effort via the `sj-procinfo` helper (a separate
//     `[[bin]]` in the shim crate that calls `proc_pidinfo(PROC_PIDTBSDINFO)`
//     — same-uid-safe, SIP-safe).  When the helper path is unset / missing /
//     the pid is gone, it returns null so attribution leans 100% on the shim
//     seed.  Never throws (the ProcReader contract).
//
// Linux behaviour is untouched: this module is only constructed on the
// macOS-bare path (see agent.ts main()).

import { spawnSync } from 'node:child_process';
import type { ProcReader } from './attribution.js';

export class MacOSProcReader implements ProcReader {
  /**
   * Absolute path to the `sj-procinfo` helper binary, or null to disable
   * ppid resolution entirely (attribution then leans 100% on the shim seed).
   * Resolved from `SCRIPT_JAIL_PROCINFO_PATH` when not supplied explicitly.
   */
  private readonly procinfoPath: string | null;

  /**
   * @param procinfoPath  Path to the `sj-procinfo` helper.  When undefined,
   *                      falls back to the `SCRIPT_JAIL_PROCINFO_PATH` env var;
   *                      when that is also unset, ppid resolution is disabled.
   */
  constructor(procinfoPath?: string | null) {
    if (procinfoPath !== undefined) {
      this.procinfoPath = procinfoPath;
    } else {
      const fromEnv = process.env['SCRIPT_JAIL_PROCINFO_PATH'];
      this.procinfoPath = fromEnv !== undefined && fromEnv.length > 0 ? fromEnv : null;
    }
  }

  /**
   * macOS has no /proc/<pid>/environ.  `Attribution._walk` treats a null
   * return as "this process contributes no environ; keep walking the ppid
   * chain" — so attribution flows through the shim event seed.  Never throws.
   */
  readEnviron(_pid: number): Map<string, string> | null {
    return null;
  }

  /**
   * Best-effort parent pid via the `sj-procinfo` helper.  Returns null when
   * the helper is unconfigured, fails to spawn, exits non-zero (pid gone /
   * not permitted), or prints an unparseable value.  Never throws — the
   * ProcReader contract requires it, and a null here just means the walk
   * terminates and we lean on the shim seed for this pid.
   */
  readPpid(pid: number): number | null {
    if (this.procinfoPath === null) return null;
    try {
      const result = spawnSync(this.procinfoPath, [String(pid)], {
        encoding: 'utf8',
        // Don't go through a shell — the path is trusted but argument-injection
        // hardening costs nothing, and a shell would also strip our DYLD env.
        shell: false,
        // Bound the call: the helper does a single proc_pidinfo() and prints.
        timeout: 1000,
      });
      if (result.status !== 0) return null;
      const out = typeof result.stdout === 'string' ? result.stdout.trim() : '';
      if (out.length === 0) return null;
      const ppid = parseInt(out, 10);
      return Number.isFinite(ppid) && ppid > 0 ? ppid : null;
    } catch {
      // spawn failure (ENOENT on the helper, EPERM, etc.) — fall back to the
      // shim seed.  Mirrors LinuxProcReader's never-throw contract.
      return null;
    }
  }
}

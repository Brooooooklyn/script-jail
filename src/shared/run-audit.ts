// script-jail — src/shared/run-audit.ts
//
// Shared audit-pipeline core called by BOTH the GitHub Action entry
// (src/main.ts, Firecracker on Linux) and the macOS CLI entry
// (src/cli/index.ts, Apple Virtualization.framework).
//
// Why this exists:
//   The two entries used to duplicate three security/correctness-relevant
//   steps and they drifted:
//
//     1. `findAuditBypass` — defence-in-depth scan of the generated
//        lockfile for `<EXEC_FAIL_OPEN>` audit-bypass entries.  Without
//        this gate, an attacker can commit a lockfile that ALREADY records
//        the bypass; every subsequent install then byte-equal-matches and
//        sails through the diff gate while bypassing the audit envelope.
//        Action ran it; CLI did not.
//
//     2. `buildArchFlagOverlay({pm, hostArch, spoofPlatform, spoofArch})` +
//        warning fan-out — needed on arm64 macOS hosts and on runs whose
//        platform-spoof config would make the package manager see a
//        non-linux/x64 target.  The dependency tree must stay Linux/x64 even
//        when lifecycle scripts are being spoofed to exercise other branches.
//
//     3. `extraRepoOverlayFiles` (.yarnrc.yml + etc/script-jail/pm-flags.json
//        + etc/script-jail/pnpm-arch.json) threading through makeOverlay.
//        Action did not thread these.
//        Same reasoning: keeping the wiring identical means we cannot ship
//        an arm64-targeting Action that silently drops the overlay.
//
// Each entry stays a thin wrapper that owns only what it CANNOT share:
//   * input parsing (env vars vs argv);
//   * host detection / artifact resolution;
//   * constructing the launcher closure (Firecracker / VZ);
//   * the output adapter (action emits GH `::warning::` + setOutput; CLI
//     writes plain stderr).
//
// `runAudit` owns:
//   * arch-flag overlay invocation + warnings;
//   * effective-config materialisation;
//   * extraRepoOverlayFiles assembly;
//   * `makeOverlay(...)`;
//   * `launch(overlay)` (the caller-supplied closure);
//   * overlay cleanup in `finally` (single ownership — the caller's
//     launcher MUST NOT call cleanup itself);
//   * `update` write or `check` diff + audit-bypass gate.

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';

import { buildArchFlagOverlay } from '../cli/arch-flags.js';
import {
  findAuditBypass,
  formatAuditBypassError,
  renderDiff,
} from '../action/diff.js';
import { buildEffectiveConfig } from '../action/config-override.js';
import {
  makeOverlay,
  type OverlayResult,
} from '../action/firecracker/overlay.js';

// ---------------------------------------------------------------------------
// Test seams
// ---------------------------------------------------------------------------
//
// The entry-level wrappers (src/main.ts, src/cli/index.ts) accept dependency
// overrides for `makeOverlay`, `buildArchFlagOverlay`, etc. so unit tests can
// short-circuit slow / privileged steps.  We re-expose those seams here so
// runAudit honours the overrides instead of always reaching for the imported
// module-level binding.  Production callers leave them undefined.

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RunAuditIo {
  /** Emit a non-fatal warning.  Action uses GH `::warning::`; CLI writes stderr. */
  warn: (msg: string) => void;
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  /**
   * Set a GitHub Actions output.  The Action wires `@actions/core.setOutput`
   * here; the CLI leaves this undefined.
   */
  setOutput?: (name: string, value: string) => void;
  /**
   * Emit a GitHub Actions `::error file=...,line=1::` annotation when the
   * audit-bypass gate fires.  Only the Action supplies this — the CLI
   * leaves it undefined but the security gate STILL fires via the stderr
   * message written above.
   */
  emitAuditBypassAnnotation?: (lockLabel: string, message: string) => void;
}

export interface LauncherResult {
  /** YAML produced by the VM's `final` frame. */
  finalYaml: string;
  /**
   * Non-fatal warnings the launcher accumulated during the VM run.
   * Currently unused by runAudit but kept on the contract so future
   * diagnostics (e.g. "no final frame, prior warnings: …") have a place.
   */
  nonFatalWarnings: string[];
}

export interface RunAuditInput {
  /** Absolute path to the user's repository root on the host. */
  repoDir: string;
  /** Absolute path to the user's script-jail config YAML on the host. */
  configPath: string;
  /** Absolute path to the install-lock YAML (existing or to be created). */
  lockPath: string;
  /** `update` → write the generated lockfile; `check` → diff + bypass gate. */
  mode: 'update' | 'check';
  overrides: {
    spoofPlatform?: 'linux' | 'darwin' | 'win32';
    spoofArch?: 'x64' | 'arm64';
  };
  /** Detected package manager for the user's repo. */
  pm: 'npm' | 'pnpm' | 'yarn';
  /** Host architecture of the runner / dev box. */
  hostArch: 'x64' | 'arm64';
  /** Absolute path to the base rootfs ext4. */
  baseRootfsPath: string;
  /**
   * PARENT directory under which runAudit creates its private per-run
   * scratch dir (via `mkdtempSync`).  The scratch dir holds the rewritten
   * config YAML plus any `.yarnrc.yml` / `pm-flags.json` sidecars and is
   * removed in the same `finally` that cleans up the overlay.
   *
   * MUST NOT be the user's repo root — buildEffectiveConfig writes fixed
   * filenames into this directory and any leftover (e.g. on a crash
   * between mkdtemp and the finally) would land in the consumer's working
   * tree.  Action passes `RUNNER_TEMP/script-jail-images`; CLI passes
   * `os.tmpdir()`.
   */
  workDir: string;
  /**
   * Caller-provided launcher closure.  runAudit calls `overlay.cleanup()`
   * AFTER `launch()` returns OR throws — the launcher MUST NOT clean up
   * the overlay itself (single ownership).
   */
  launch: (overlay: OverlayResult) => Promise<LauncherResult>;
  io: RunAuditIo;
  /**
   * Optional test seam — overrides the arch-flag overlay builder.  The CLI
   * (and its tests) inject a sniffer so they can assert that `hostArch`
   * flows through from `detectHost` (NOT process.arch).  Production
   * callers leave this undefined.
   */
  buildArchFlagOverlay?: typeof buildArchFlagOverlay;
  /**
   * Optional test seam — overrides the overlay builder.  Tests use this to
   * short-circuit the (slow, root-needing) `mkfs.ext4` path; production
   * callers leave it undefined.
   */
  makeOverlay?: typeof makeOverlay;
}

// ---------------------------------------------------------------------------
// runAudit
// ---------------------------------------------------------------------------

export async function runAudit(
  input: RunAuditInput,
): Promise<{ exitCode: number }> {
  const doBuildArchFlagOverlay =
    input.buildArchFlagOverlay ?? buildArchFlagOverlay;
  const doMakeOverlay = input.makeOverlay ?? makeOverlay;

  // 1. Arch-flag overlay (+ warning fan-out).  No-op only when both the host
  //    and the platform-spoof target are canonical linux/x64.  We treat 'yarn'
  //    as yarn-berry by default — the worst case for yarn-classic users on
  //    non-canonical targets is a missed warning, not incorrect output.
  const archOverlay = doBuildArchFlagOverlay({
    pm: input.pm,
    hostArch: input.hostArch,
    spoofPlatform: input.overrides.spoofPlatform ?? 'linux',
    spoofArch: input.overrides.spoofArch ?? 'x64',
  });
  for (const w of archOverlay.warnings) input.io.warn(w);

  // 2. Allocate a PRIVATE per-run scratch dir under input.workDir.
  //    buildEffectiveConfig writes fixed filenames here (config.yml,
  //    .yarnrc.yml, etc/script-jail/pm-flags.json); a per-run mkdtemp
  //    namespace keeps concurrent invocations isolated AND prevents the
  //    fixed filenames from leaking into a caller-supplied workDir that
  //    happens to overlap with the user's repository tree (e.g. an
  //    accidental `workDir: cwd` from the CLI).  Cleaned up in the same
  //    `finally` that owns the overlay so a launch crash still removes it.
  const scratchDir = mkdtempSync(join(input.workDir, 'script-jail-config-'));

  let result: LauncherResult;
  let overlay: OverlayResult | null = null;
  try {
    // 3. Build the effective config + sidecars under the private scratch.
    //    The user's source config file on the host is never modified.
    const effectiveConfig = buildEffectiveConfig({
      userConfigPath: input.configPath,
      overrides: {
        // buildEffectiveConfig expects required SpoofPlatform / SpoofArch —
        // both entries' input shapes already default these, so we coerce
        // here rather than threading the defaults through runAudit.
        spoofPlatform: input.overrides.spoofPlatform ?? 'linux',
        spoofArch: input.overrides.spoofArch ?? 'x64',
      },
      workDir: scratchDir,
      ...(archOverlay.yarnrcOverlay !== undefined
        ? { yarnrcOverlay: archOverlay.yarnrcOverlay }
        : {}),
      ...(archOverlay.pmFlagsJson !== undefined
        ? { pmFlagsJson: archOverlay.pmFlagsJson }
        : {}),
      ...(archOverlay.pnpmArchOverlay !== undefined
        ? { pnpmArchOverlay: archOverlay.pnpmArchOverlay }
        : {}),
    });

    // 4. Assemble extraRepoOverlayFiles.  Mirrors src/cli/index.ts pre-
    //    refactor (relPath strings `.yarnrc.yml` and
    //    `etc/script-jail/pm-flags.json`).  These land on the immutable
    //    repo disk so they are visible inside the VM where the package
    //    manager actually runs.
    const extraRepoOverlayFiles: Array<{ relPath: string; content: string }> = [];
    if (effectiveConfig.yarnrcPath !== undefined) {
      extraRepoOverlayFiles.push({
        relPath: '.yarnrc.yml',
        content: readFileSync(effectiveConfig.yarnrcPath, 'utf8'),
      });
    }
    if (effectiveConfig.pmFlagsPath !== undefined) {
      extraRepoOverlayFiles.push({
        relPath: 'etc/script-jail/pm-flags.json',
        content: readFileSync(effectiveConfig.pmFlagsPath, 'utf8'),
      });
    }
    if (effectiveConfig.pnpmArchPath !== undefined) {
      extraRepoOverlayFiles.push({
        relPath: 'etc/script-jail/pnpm-arch.json',
        content: readFileSync(effectiveConfig.pnpmArchPath, 'utf8'),
      });
    }

    // 5. Build per-run overlay (rootfs + repo ext4 disks).
    overlay = await doMakeOverlay({
      baseRootfsPath: input.baseRootfsPath,
      repoSrcPath: input.repoDir,
      configPath: effectiveConfig.configPath,
      extraRepoOverlayFiles,
    });

    // 6. Launch the VM via the caller-supplied closure.  We own the
    //    cleanup so the launcher can stay tight on the host-specific
    //    lifecycle (Firecracker socket teardown, VZ child reap, etc.).
    result = await input.launch(overlay);
  } finally {
    if (overlay !== null) {
      try { await overlay.cleanup(); } catch { /* swallow — diagnostic only */ }
    }
    // Scratch dir is removed last so a cleanup failure on the overlay
    // does not leak the sidecar files.  rm with `force: true` is a no-op
    // if the dir was already removed (e.g. by a future overlay impl that
    // co-locates its workDir under our scratchDir).
    try { await rm(scratchDir, { recursive: true, force: true }); } catch { /* swallow */ }
  }

  // 6. Post-VM: write or diff.
  if (input.mode === 'update') {
    writeFileSync(input.lockPath, result.finalYaml, 'utf8');
    // Diagnostic: emit path + byte count so the next workflow run can map
    // an empty-on-disk lockfile back to either (a) a wrong path or (b) an
    // empty finalYaml.  Cheap; pays for itself the next time
    // `test -s "$LOCK"` fails downstream.
    input.io.stderr.write(
      `[script-jail] wrote ${Buffer.byteLength(result.finalYaml, 'utf8')} bytes to ${input.lockPath}\n`,
    );
    input.io.setOutput?.('lockfile', input.lockPath);
    input.io.setOutput?.('diff', '');
    return { exitCode: 0 };
  }

  // mode === 'check'
  const committed = existsSync(input.lockPath)
    ? readFileSync(input.lockPath, 'utf8')
    : '';

  const lockLabel = relativeForDisplay(input.lockPath, input.repoDir);
  const diff = renderDiff({
    lockPath: lockLabel,
    committed,
    generated: result.finalYaml,
  });

  if (diff.unified !== '') {
    input.io.stdout.write(diff.unified);
    // Make sure the annotations don't smash onto the diff's last line.
    if (!diff.unified.endsWith('\n')) input.io.stdout.write('\n');
  }
  for (const ann of diff.annotations) {
    input.io.stdout.write(`${ann}\n`);
  }

  // SECURITY: scan the generated lockfile for `audit_bypass` entries
  // INDEPENDENTLY of the diff result.  An attacker could commit a
  // lockfile that already records `<EXEC_FAIL_OPEN> …` — then every
  // subsequent install bypasses the audit envelope but the byte-equal
  // diff returns match=true.  Lockfile equality alone is not success.
  // This gate fires in BOTH paths (drift AND match) and in BOTH entries
  // (Action + CLI).
  const bypassEntries = findAuditBypass(result.finalYaml);

  input.io.setOutput?.('lockfile', input.lockPath);
  input.io.setOutput?.('diff', diff.unified);

  if (bypassEntries.length > 0) {
    const msg = formatAuditBypassError(bypassEntries);
    input.io.stderr.write(`${msg}\n`);
    // The action also surfaces a GH-Actions annotation so the bypass
    // shows up in the PR UI even if the diff path was clean.  The CLI
    // passes undefined for emitAuditBypassAnnotation — its stderr
    // message above is sufficient.
    input.io.emitAuditBypassAnnotation?.(lockLabel, msg);
    return { exitCode: 1 };
  }

  return { exitCode: diff.match ? 0 : 1 };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns `absPath` made relative to `repoDir` when it is inside the repo.
 * Falls back to the absolute path otherwise.  Used purely for cosmetic
 * annotation labels — the underlying read/write uses the absolute path.
 *
 * Lifted from the (now-removed) copies in src/main.ts and src/cli/index.ts
 * so both entries share the same display logic.
 */
function relativeForDisplay(absPath: string, repoDir: string): string {
  const rel = relative(repoDir, absPath);
  // If `rel` starts with ".." or is absolute on Windows, the path escapes
  // the repo — keep the absolute path to avoid a misleading label.
  if (rel.startsWith('..') || isAbsolute(rel)) return absPath;
  return rel;
}

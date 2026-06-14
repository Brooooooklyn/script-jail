// script-jail — src/main.ts
//
// GitHub Action entry point.  Wired in action.yml as `runs.main: dist/main.cjs`.
//
// Flow:
//   1. Parse inputs (./action/inputs.ts) and detect the PM (./shared/detect-pm.ts).
//   2. Select an audit backend (Firecracker, Docker, or bare Linux).
//   3. Hand off to `runAudit` (../shared/run-audit.ts) which owns:
//        - arch-flag overlay
//        - effective-config + extraRepoOverlayFiles assembly
//        - the post-VM diff / write / audit-bypass gate
//      ...and call the selected backend for step (4).
//   4. The backend starts its isolated execution surface, drives the
//      handshake → final exchange, and tears down in `finally`.
//
// This module is intentionally thin: each step delegates to a helper that is
// independently unit-tested.

import { setOutput } from '@actions/core';
import { existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parseInputs } from './action/inputs.js';
import { hostInstallNoScripts, hostRunScripts } from './action/host-install.js';
import { detectPm, BunUnsupportedError, type DetectedPm } from './shared/detect-pm.js';
import { detectRunnerImage } from './action/runner-image.js';
import { warn } from './action/log.js';
import {
  ensureBinaries,
  NodeHttpClient,
} from './action/firecracker/download.js';
import { preFetchArtifacts } from './action/pre-fetch-artifacts.js';
import { PINNED_MANIFEST } from './action/artifact-manifest.js';
import { validateManifest } from './action/validate-manifest.js';
import { makeOverlay } from './action/firecracker/overlay.js';
import { launchVm } from './action/firecracker/launch.js';
import { openVsockSession } from './action/firecracker/vsock.js';
import { teardown } from './action/firecracker/teardown.js';
import { runAudit } from './shared/run-audit.js';
import { collectNetworkAttempts, formatEgressWarning } from './action/diff.js';
import { createFirecrackerBackend } from './action/backend/firecracker.js';
import { createDockerBackend } from './action/backend/docker.js';
import { createBareBackend } from './action/backend/bare.js';
import { runSelectedBackend } from './action/backend/select.js';
import type { BackendMap } from './action/backend/select.js';

// ---------------------------------------------------------------------------
// Pinned versions
// ---------------------------------------------------------------------------

export type ActionHostArch = 'x64' | 'arm64';

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

export interface MainDeps {
  validateManifest?: typeof validateManifest;
  preFetchArtifacts?: typeof preFetchArtifacts;
  ensureBinaries?: typeof ensureBinaries;
  makeOverlay?: typeof makeOverlay;
  launchVm?: typeof launchVm;
  openVsockSession?: typeof openVsockSession;
  teardown?: typeof teardown;
  exitProcess?: (code: number) => never;
  /** Host drop-in install seams — injectable so tests need not spawn a real PM. */
  hostInstallNoScripts?: typeof hostInstallNoScripts;
  hostRunScripts?: typeof hostRunScripts;
}

export async function main(deps: MainDeps = {}): Promise<void> {
  const {
    validateManifest: doValidateManifest = validateManifest,
    preFetchArtifacts: doPreFetchArtifacts = preFetchArtifacts,
    ensureBinaries: doEnsureBinaries = ensureBinaries,
    // makeOverlay is now owned by runAudit; the MainDeps seam threads
    // through so existing tests / future maintainers can still stub it.
    makeOverlay: doMakeOverlay = makeOverlay,
    launchVm: doLaunchVm = launchVm,
    openVsockSession: doOpenVsockSession = openVsockSession,
    teardown: doTeardown = teardown,
    exitProcess = process.exit as (code: number) => never,
    hostInstallNoScripts: doHostInstallNoScripts = hostInstallNoScripts,
    hostRunScripts: doHostRunScripts = hostRunScripts,
  } = deps;

  // ---------------------------------------------------------------------
  // E2E self-test escape hatch
  // ---------------------------------------------------------------------
  // The Layer 2 e2e workflow (`.github/workflows/e2e.yml`) invokes this
  // very action against itself via `uses: ./` on every PR/main push.  At
  // that point:
  //
  //   * `PINNED_MANIFEST` still carries `PLACEHOLDER_SHA256_*` entries
  //     (real SHAs only land in the manifest AFTER the first tagged
  //     release computes them — see release.yml's "Compute SHAs" step).
  //     `validateManifest` would therefore reject startup before any
  //     useful work happens.
  //
  //   * The Layer 2 workflow runs `pnpm build -- --runner-image=…` on
  //     the runner BEFORE invoking the action, which places real rootfs
  //     + libscriptjail.so files under `imagesDir`.  `preFetchArtifacts`
  //     would then SHA-check those locally-built files against the
  //     placeholder manifest, see a mismatch, and try to re-download
  //     from a release that does not yet exist.
  //
  // `SCRIPT_JAIL_E2E_SELF_TEST=1` skips BOTH gates so the e2e workflow can
  // exercise the action's real boot path against its own working tree.
  // The variable is intentionally NOT exposed as an action input — only
  // the workflow that owns this repo sets it, and consumers' workflows
  // never see it (GitHub Actions only inherits `env:` you explicitly
  // declare on the step or job).  Setting it in a consumer workflow
  // would disable the manifest-validation safety net and is unsupported.
  const selfTest = process.env['SCRIPT_JAIL_E2E_SELF_TEST'] === '1';

  if (!selfTest) {
    // Fail-fast: refuse to do ANY work if the action was published with
    // placeholder (or otherwise non-canonical) artifact SHAs.  This MUST be
    // the first real executable statement of main() — earlier ordering placed
    // it after parseInputs()/detectPm(), so a packaging bug could be masked by
    // a lockfile-missing error or by the BunUnsupportedError clean-exit
    // (process.exit(0)) below, neither of which surface the real issue.
    // Without this gate, the pre-fetch step would only catch the mistake
    // AFTER downloading multi-MB release assets, and surface it as a
    // confusing "SHA-256 mismatch" instead of "this is a packaging bug,
    // file an issue".
    doValidateManifest(PINNED_MANIFEST);
  }

  // Source of truth for "where is the user's repo?" is the SCRIPT_JAIL_REPO_DIR
  // env var if set, then the action step's working-directory (process.cwd()),
  // and only as a final fallback GITHUB_WORKSPACE.  GitHub Actions reserves
  // GITHUB_WORKSPACE as a default environment variable and silently ignores
  // step-level `env: GITHUB_WORKSPACE: …` overrides — so the e2e self-test
  // workflow (which needs to point the action at a staged consumer dir under
  // RUNNER_TEMP, not at the checkout) cannot use that mechanism.  Honoring
  // `working-directory:` (which Actions DOES respect for JS actions by
  // chdir-ing the spawned Node process) gives a reliable knob without
  // introducing a new action input.  For ordinary consumers, the action's
  // cwd equals GITHUB_WORKSPACE so behaviour is unchanged.
  const repoDir =
    process.env['SCRIPT_JAIL_REPO_DIR'] ??
    process.cwd() ??
    process.env['GITHUB_WORKSPACE'] ??
    '';

  const actionHostArch = detectActionHostArch();
  const inputs = parseInputs({ repoDir, defaultSpoofArch: actionHostArch });

  // --- PM detection --------------------------------------------------------
  // BunUnsupportedError is non-fatal: emit a ::warning and exit cleanly so
  // bun-using repos can install the action without breaking their CI.
  let pm: DetectedPm;
  try {
    pm = detectPm({ repoDir });
  } catch (err) {
    if (err instanceof BunUnsupportedError) {
      warn(err.message);
      exitProcess(0);
    }
    throw err;
  }

  // --- Drop-in install: fail-closed preconditions --------------------------
  // When `install: true` the action ALSO installs deps on the runner, but BOTH
  // host halves run AFTER the audit (below), never here: part 1 must not
  // populate node_modules before the backend stages its copy of the repo, or
  // the freshly built tree (esp. pnpm's external-store symlinks) gets copied
  // into the sandbox and diverges the audit.  Here we only enforce the
  // preconditions that must fail BEFORE spending an audit: install needs a
  // committed lock to gate against, and must run in `check` (update regenerates
  // the lock and skips the audit-bypass scan, so there would be no fail-closed
  // signal to run lifecycle scripts against).
  if (inputs.install) {
    if (inputs.mode === 'update') {
      process.stdout.write(
        '::error::script-jail: `install: true` requires `mode: check`. ' +
          'Update mode regenerates the lock and skips the audit-bypass gate, so there is no ' +
          'fail-closed signal to run lifecycle scripts against. Generate the lock with ' +
          '`mode: update` (install off), commit it, then enable `install` with `mode: check`.\n',
      );
      exitProcess(1);
    }
    if (!existsSync(inputs.lockPath)) {
      process.stdout.write(
        `::error::script-jail: \`install: true\` requires a committed lock at ${inputs.lockPath}. ` +
          'Generate one with `mode: update` (install off), commit it, then enable `install`.\n',
      );
      exitProcess(1);
    }
  }

  // --- Detect runner image -------------------------------------------------
  const runnerImage = detectRunnerImage();

  // --- Resolve image paths -------------------------------------------------
  // imagesDir must live OUTSIDE the user's repo (we previously joined it onto
  // repoDir, which polluted their working tree).  RUNNER_TEMP is the GitHub
  // Actions runner's scratch directory — writable and cleaned between jobs.
  // os.tmpdir() is the dev/test fallback.
  //
  // The rootfs image (`rootfs-<runner-image>.ext4`) is also resolved here.
  // `preFetchArtifacts()` below downloads it (and libscriptjail.so) from the
  // GitHub release matching PINNED_MANIFEST.tag; if the download or its
  // SHA-256 check fails, the pre-fetch step throws before `launchVm` runs.

  const imagesDir = process.env['RUNNER_TEMP']
    ? join(process.env['RUNNER_TEMP'], 'script-jail-images')
    : join(tmpdir(), 'script-jail-images');
  mkdirSync(imagesDir, { recursive: true });

  // Backends own their own artifact needs. Firecracker downloads/caches the
  // kernel/rootfs path, Docker pulls a pinned image, and bare fetches the shim.
  const http = new NodeHttpClient();
  const backends: BackendMap = {
    firecracker: createFirecrackerBackend({
      preFetchArtifacts: doPreFetchArtifacts,
      ensureBinaries: doEnsureBinaries,
      makeOverlay: doMakeOverlay,
      launchVm: doLaunchVm,
      openVsockSession: doOpenVsockSession,
      teardown: doTeardown,
      cacheFirecracker: inputs.cacheFirecracker,
      warn,
      // Existing e2e tests inject the whole Firecracker stack and run on macOS
      // too; keep those fakes from tripping the real /dev/kvm availability gate.
      skipAvailabilityCheck: deps.launchVm !== undefined,
    }),
    docker: createDockerBackend({ stderr: process.stderr }),
    bare: createBareBackend({
      preFetchArtifacts: doPreFetchArtifacts,
      stderr: process.stderr,
    }),
  };

  const result = await runAudit({
    repoDir,
    configPath: inputs.configPath,
    lockPath: inputs.lockPath,
    mode: inputs.mode,
    overrides: {
      spoofPlatform: inputs.spoofPlatform,
      spoofArch: inputs.spoofArch,
    },
    pm: pm.manager,
    hostArch: actionHostArch,
    // Developer install args reach the sandbox fetch (so the audited tree
    // matches what part 1 installed on the host).
    args: inputs.args,
    // Pass `imagesDir` as the workDir so the rewritten config lives under
    // the same RUNNER_TEMP-rooted tree we already use for binaries.
    // GitHub Actions purges RUNNER_TEMP between jobs; without this,
    // leaving the workDir at buildEffectiveConfig's mkdtemp default
    // would accumulate stray dirs under os.tmpdir() on self-hosted runners.
    workDir: imagesDir,
    execute: (auditInput) => runSelectedBackend({
      requested: inputs.backend,
      backends,
      warn,
      ctx: {
        ...auditInput,
        imagesDir,
        runnerImage,
        arch: actionHostArch,
        manifest: PINNED_MANIFEST,
        http,
        selfTest,
      },
    }),
    io: {
      warn,
      setOutput,
      stdout: process.stdout,
      stderr: process.stderr,
      emitAuditBypassAnnotation: (lockLabel, msg) => {
        process.stdout.write(`::error file=${lockLabel},line=1::${msg}\n`);
      },
    },
  });

  // --- Drop-in install: part 1 (host no-scripts) + part 2 (run scripts) ----
  // Both host halves run AFTER the audit so the freshly built node_modules is
  // never staged into the sandbox copy (which would diverge the audit — pnpm's
  // external-store symlinks in particular).  Part 1 (lifecycle scripts
  // disabled) is always safe and runs even on drift, so the safe no-scripts
  // tree is left on the runner.  Part 2 (run the deferred scripts) is gated
  // STRICTLY on a clean audit (`trusted` ⇔ check-mode, lock matched, no
  // audit-bypass entry); on drift/bypass it is skipped, the safe tree stays in
  // place, and the job fails via the non-zero exit below.  Part 2 runs the
  // scripts ONLINE on the runner (no netns sever) — trust derives from the
  // reviewed, matched lock.
  if (inputs.install) {
    doHostInstallNoScripts(pm.manager, repoDir, inputs.args, { stdout: process.stdout, warn });
    if (result.trusted) {
      // Surface the egress from the GENERATED lock runAudit just produced — it
      // is guaranteed well-formed (the guest rendered it) and, on a trusted
      // check, semantically equals the committed lock.  Re-reading the
      // committed file would risk a parse failure (it can be malformed in a
      // canonicalized volatile field yet still diff-match), silently dropping
      // the warning while part 2 still runs scripts online.  Phase B was
      // offline so these connects were recorded `<BLOCKED>`, but part 2 runs
      // ONLINE — they WILL succeed.
      const egress = collectNetworkAttempts(result.generatedLock ?? '');
      if (egress.length > 0) {
        const { summary, detail } = formatEgressWarning(egress);
        warn(summary);
        process.stdout.write(detail);
      }
      doHostRunScripts(pm.manager, repoDir, { stdout: process.stdout, warn });
    }
  }

  // Preserve the existing semantics: in `update` mode runAudit returns
  // exitCode 0 and main historically fell through to `return` rather than
  // calling exitProcess.  In `check` mode the pre-refactor code called
  // exitProcess(1) on drift/bypass and `return` on match.  We honour that
  // distinction by exiting only on non-zero codes.  Existing tests that
  // inject `exitProcess` to capture this behaviour stay green.
  if (result.exitCode !== 0) exitProcess(result.exitCode);
}

export function detectActionHostArch(arch: string = process.arch): ActionHostArch {
  if (arch === 'x64' || arch === 'arm64') return arch;
  throw new Error(
    `script-jail action requires an x64 or arm64 Linux runner (detected '${arch}').`,
  );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

main().catch((err: unknown) => {
  process.stderr.write(
    `${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});

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
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parseInputs } from './action/inputs.js';
import {
  hostInstallNoScripts,
  hostRunScripts,
  trustedHostTmpdir,
} from './action/host-install.js';
import { detectPreTrustConfigExec, detectInstallWorkDirDivergence, detectCheckoutRelativeHome, detectReservedScriptJailPaths, detectSubdirInstallAncestorEscape, readProtectedEnvNames } from './action/install-preflight.js';
import { detectPm, BunUnsupportedError, type DetectedPm } from './shared/detect-pm.js';
import { NODE_VERSION } from './rootfs/vite-plus.js';
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
import { runSelectedBackend, INSTALL_ALIGNED_BACKENDS } from './action/backend/select.js';
import type { BackendMap } from './action/backend/select.js';
import type { ConcreteBackend } from './action/backend/types.js';
import { buildRootPkgKeys } from './guest/attribution.js';

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

/**
 * Parse the leading major from a Node version string (`v24.15.0` or `24.15.0`).
 * Returns NaN when unparseable, which the install:true Node-parity gate treats as
 * a mismatch (fail closed). See thread [42].
 */
function nodeMajorOf(version: string): number {
  const m = version.replace(/^v/, '').match(/^(\d+)/);
  return m === null ? NaN : parseInt(m[1]!, 10);
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
  // env var if set, then process.cwd(), and only as a final fallback
  // GITHUB_WORKSPACE.  For a `uses:` (JS) action the runner sets the process cwd
  // to GITHUB_WORKSPACE and does NOT honor a step-level `working-directory:`
  // (that applies only to `run:` shell steps — a JS action would have to
  // process.chdir() itself, which we never do).  So for ordinary consumers
  // process.cwd() === GITHUB_WORKSPACE and behaviour is unchanged.  GitHub
  // Actions also reserves GITHUB_WORKSPACE as a default env var and silently
  // ignores a step-level `env: GITHUB_WORKSPACE: …` override, so the e2e
  // self-test workflow (which must point the action at a staged consumer dir
  // under RUNNER_TEMP, not the checkout) cannot use that mechanism.
  // SCRIPT_JAIL_REPO_DIR is the only knob that points the action at a different
  // dir, and is the documented escape hatch used by the e2e workflow.
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
    // SECURITY: the spoof inputs (spoof-platform / spoof-arch) are applied ONLY
    // to the AUDITED scripts inside the sandbox.  Host part-2 (hostRunScripts)
    // runs the REAL scripts on this runner with NO spoofing.  If the spoof
    // target differs from the real execution host, a package can branch on
    // process.platform / process.arch so the SPOOFED branch is audited while the
    // runner EXECUTES the other branch — the trusted lock then does not describe
    // what runs.  Fail closed BEFORE the audit (and before any host install)
    // unless the spoof target equals the real runner.  The part-2 scripts run on
    // this very process (hostRunScripts → local spawnSync), so the real host is
    // `process.platform` (linux on a supported runner) and `actionHostArch`.
    // The DEFAULTS — spoof-platform 'linux', spoof-arch = real host arch — pass
    // on a Linux runner (linux == linux, arch == arch).
    if (inputs.spoofPlatform !== process.platform || inputs.spoofArch !== actionHostArch) {
      process.stdout.write(
        `::error::script-jail: \`install: true\` requires the spoof target to match the runner. ` +
          `Spoof platform/arch (${inputs.spoofPlatform}/${inputs.spoofArch}) must equal the real ` +
          `runner (${process.platform}/${actionHostArch}); otherwise an audited script can branch ` +
          `on process.platform/arch so the sandbox audits one branch while the runner executes the ` +
          `other, and the trusted lock would not describe what actually runs. Remove the spoof ` +
          `override (or set it to the runner's real platform/arch) when using \`install\`.\n`,
      );
      exitProcess(1);
    }
    // SECURITY (Codex review thread [42]): the host part-2 re-run executes the REAL
    // lifecycle scripts under the GitHub Action's bundled Node runtime (action.yml
    // `using: node24`), while the AUDIT runs under the pinned guest Node
    // (vite-plus.ts NODE_VERSION). A native addon (`npm`/`pnpm rebuild`) compiles
    // against the host's native ABI, and a script can branch on process.version /
    // process.versions.modules; the lock's node_version is the audit pin (host-blind)
    // and is byte-stable, so a host-vs-audit Node-MAJOR mismatch lets the runner
    // build/run a different branch than was audited — the same audit-vs-host execution
    // divergence the platform/arch spoof gate above closes. Gate on MAJOR (not exact
    // x.y.z): a shared major implies a shared native module ABI (NODE_MODULE_VERSION),
    // so this catches a real toolchain mismatch without over-firing on GitHub's
    // node24 patch bumps.
    const auditNodeMajor = nodeMajorOf(NODE_VERSION);
    const hostNodeMajor = nodeMajorOf(process.version);
    if (hostNodeMajor !== auditNodeMajor) {
      process.stdout.write(
        `::error::script-jail: \`install: true\` requires the runner's Node major to match the ` +
          `audited toolchain. The sandbox audits under Node ${NODE_VERSION} (major ${auditNodeMajor}), ` +
          `but this runner executes host lifecycle scripts under ${process.version} ` +
          `(major ${Number.isFinite(hostNodeMajor) ? hostNodeMajor : 'unknown'}); a package can branch ` +
          `on process.version / native ABI so the audited branch differs from what the runner builds and ` +
          `runs, and the trusted lock would not describe it. Align the runner's Node (e.g. ` +
          `actions/setup-node with node-version ${auditNodeMajor}) with the audited major, or audit ` +
          `without \`install\`.\n`,
      );
      exitProcess(1);
    }
    // SECURITY: refuse install when the repo declares package-manager CONFIG
    // that EXECUTES repo-controlled code on the runner during the pre-trust
    // no-scripts host install (pnpm `.pnpmfile.cjs` / relocated pnpmfiles; yarn
    // `.yarnrc.yml` yarnPath / plugins / constraints).  `--ignore-scripts` /
    // `--mode=skip-build` do NOT stop these config hooks, and host part-1 runs
    // BEFORE the trust gate.  In pure-audit mode (install off) these run only
    // inside the sandbox (audited by design), so the gate is install-only.  The
    // pnpm side has a robust host `--ignore-pnpmfile` backstop (host-install.ts);
    // this static reject is the clean early message + the sole enforcement for
    // yarn (no yarn flag suppresses all three vectors).  When repoDir is a
    // SUBDIRECTORY of the checkout (SCRIPT_JAIL_REPO_DIR pointing at a subdir),
    // yarn Berry walks UP and loads an ANCESTOR `.yarnrc.yml plugins:`/`yarnPath`
    // at startup; pass GITHUB_WORKSPACE as the bound so the preflight scans
    // ancestor config up to (but never above) the checkout root.  For ordinary
    // consumers repoDir === workspaceRoot, so this scans exactly repoDir.
    const workspaceRoot = process.env['GITHUB_WORKSPACE'];
    const configExecReason = detectPreTrustConfigExec(repoDir, pm.manager, workspaceRoot);
    if (configExecReason !== null) {
      process.stdout.write(
        `::error::script-jail: \`install: true\` refused — ${configExecReason}\n`,
      );
      exitProcess(1);
    }
    // SECURITY: a consumer `work_dir` (config-file field, no clamp) that diverges
    // from the host install cwd (always repoDir root) lets the guest audit a
    // benign SUBPROJECT clean while host part-2 runs UN-AUDITED repo-root
    // lifecycle scripts on the runner (FC/docker; bare/mac-bare discard work_dir).
    // Fail closed before the audit.  (install-preflight.ts:detectInstallWorkDirDivergence.)
    // NB: this gate reads the CONSUMER config; M1 cwd parity then force-pins the
    // EFFECTIVE config work_dir to repoDir (via installWorkDir above) on the
    // ACCEPTED path — so a consumer subproject work_dir is still refused here,
    // while the default path aligns guest cwd to repoDir for FC/docker.
    const workDirDivergence = detectInstallWorkDirDivergence(inputs.configPath);
    if (workDirDivergence !== null) {
      process.stdout.write(`::error::script-jail: \`install: true\` refused — ${workDirDivergence}\n`);
      exitProcess(1);
    }
    // SECURITY: a checkout-relative $HOME makes a PR-committed `$HOME/.yarnrc.yml`
    // (plugins/yarnPath) or `$HOME/.npmrc` (script-shell) execute on the runner at
    // package-manager config-load — pre-trust, unseen by the sandbox (different
    // HOME).  hostInstallEnv preserves HOME, and the repoDir->workspaceRoot scan
    // above misses a sibling/non-ancestor $HOME, so gate it here.  (install-preflight.ts:detectCheckoutRelativeHome.)
    const homeReason = detectCheckoutRelativeHome(process.env['HOME'], repoDir, workspaceRoot);
    if (homeReason !== null) {
      process.stdout.write(`::error::script-jail: \`install: true\` refused — ${homeReason}\n`);
      exitProcess(1);
    }
    // SECURITY: refuse a checkout that commits ANY file under the script-jail-owned
    // overlay directory etc/script-jail/ (pm-flags.json / pnpm-arch.json / config.yml —
    // FC copies the generated config.yml INTO the staged tree, shadowing a committed one).
    // The audit sees script-jail's host-written content there (overlay overwrites the
    // staged copy), but host part-2 re-runs lifecycle scripts against the REAL checkout
    // where the committed file persists — a host-vs-sandbox content distinguisher the
    // value-blind lock cannot capture. Directory-level (not a file list) so a future
    // sidecar can't re-open the class. (install-preflight.ts:detectReservedScriptJailPaths.)
    const reservedPathReason = detectReservedScriptJailPaths(repoDir);
    if (reservedPathReason !== null) {
      process.stdout.write(`::error::script-jail: \`install: true\` refused — ${reservedPathReason}\n`);
      exitProcess(1);
    }
    // SECURITY: refuse install when repoDir is a STRICT SUBDIR of the checkout root.
    // The audit stages only repoDir, but host part-2 re-runs lifecycle scripts at
    // cwd=repoDir on the runner where the PR-committed ancestor (repoDir→workspaceRoot)
    // is readable/executable (`../<file>` read, or require('../../mal.js') of code the
    // sandbox never ran) — an un-staged-ancestor escape the value-blind lock cannot
    // capture, and the WHOLE ancestor class (not just etc/script-jail). Only reachable
    // via SCRIPT_JAIL_REPO_DIR=<subdir>+install:true; fail closed on that topology.
    // (install-preflight.ts:detectSubdirInstallAncestorEscape.)
    const subdirEscapeReason = detectSubdirInstallAncestorEscape(repoDir, workspaceRoot);
    if (subdirEscapeReason !== null) {
      process.stdout.write(`::error::script-jail: \`install: true\` refused — ${subdirEscapeReason}\n`);
      exitProcess(1);
    }
    // SECURITY (Codex re-review, bare-backend staged-symlink escape): install:true
    // re-runs lifecycle scripts on the host at cwd=repoDir, trusting the audit. That
    // trust holds ONLY if the audit ran at the SAME absolute path (repoDir) — true for
    // firecracker/docker, FALSE for `bare`, which audits in a TEMP staged copy where a
    // committed relative symlink is rewritten to the original checkout: the audit
    // resolves it to ENOENT (read dropped) while host part-2 resolves+EXECUTES the real
    // file host part-1 created — un-audited code while the lock says trusted. Refuse an
    // explicit non-aligned backend BEFORE any host install; auto also drops bare under
    // install (select.ts requireRepoDirAligned). Allowlist via INSTALL_ALIGNED_BACKENDS
    // so a future backend is fail-closed until proven repoDir-aligned.
    if (inputs.backend !== 'auto' && !INSTALL_ALIGNED_BACKENDS.has(inputs.backend)) {
      process.stdout.write(
        `::error::script-jail: \`install: true\` is not supported on the \`${inputs.backend}\` ` +
          `backend — it audits in a temporary staged copy whose path differs from the checkout, ` +
          `so a committed symlink can make the host re-run execute code the audit never resolved. ` +
          `Use \`backend: firecracker\` or \`backend: docker\` (which audit at the checkout path), ` +
          `or audit without \`install\`.\n`,
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

  // Capture the CONCRETE backend the audit actually ran on, so the install:true
  // host re-run can match its env (TMPDIR-presence parity — see hostTmpdir below).
  let auditBackend: ConcreteBackend | undefined;
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
    // install:true cwd parity: pin the guest audit work_dir to the real
    // repoDir so the sandbox runs lifecycle scripts at the SAME cwd the
    // uninstrumented host re-run uses, closing a `process.cwd()` detection
    // oracle (FC/docker; bare/mac-bare re-pin to their staged path, so the
    // cwd parity is a documented residual there).  Undefined in pure-audit
    // mode (guest default /work stands).
    ...(inputs.install ? { installWorkDir: repoDir } : {}),
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
      // install:true requires a repoDir-aligned backend (FC/docker); drop `bare`
      // from auto and reject an explicit bare here as a backstop to the pre-audit
      // gate.  (Codex re-review: bare-backend staged-symlink escape.)
      requireRepoDirAligned: inputs.install,
      onBackendSelected: (name) => {
        auditBackend = name;
      },
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
    // TMPDIR-presence parity with the AUDITING backend (value-blind env-read oracle):
    // the Firecracker guest exports TMPDIR=/sjtmp into the lifecycle child (an ENOSPC
    // mitigation), while Docker exports none.  So the host re-run sets TMPDIR ONLY when
    // Firecracker audited, and leaves it unset (dropped by the hostInstallEnv allowlist)
    // when Docker audited — matching whichever produced the lock so a lifecycle script
    // reading `process.env.TMPDIR` takes the SAME branch on both sides.  install:true only
    // ever runs FC/Docker (gated above), so a non-FC backend here is Docker → drop.
    //
    // SECURITY (codex round-4 [high]): the FC host value comes from trustedHostTmpdir()
    // — a FIXED /tmp, realpath-canonicalized + asserted absolute/outside-checkout — NOT
    // os.tmpdir(), which would honor the AMBIENT process.env.TMPDIR/TMP/TEMP a malicious
    // workflow `env:` controls and let an attacker redirect trusted-host tempfile WRITES
    // under the checkout.  The value still differs from the VM's /sjtmp — an accepted
    // residual only a script branching on TMPDIR's VALUE could see (same class as the
    // cwd/cache-path residuals; /sjtmp is a dedicated VM disk that cannot exist on host).
    const hostTmpdir = auditBackend === 'firecracker' ? trustedHostTmpdir() : undefined;
    doHostInstallNoScripts(pm.manager, repoDir, inputs.args, { stdout: process.stdout, stderr: process.stderr, warn }, undefined, hostTmpdir);
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
        // Build the root-project package ids (bare `name` AND `name@version`)
        // so formatEgressWarning can tell whether a `prepare` egress entry is
        // the ROOT's.  The host rebuild does NOT run root `prepare` for
        // npm/yarn, so that egress is audited-only there; pnpm's
        // `rebuild --pending` does run it.  Uses buildRootPkgKeys() — the same
        // single source of truth as the guest's rootPkgKeys — to guarantee the
        // two sides stay in sync (including the empty-version '' edge case).
        let rootPackageIds = new Set<string>();
        try {
          const rootManifest = JSON.parse(
            readFileSync(join(repoDir, 'package.json'), 'utf8'),
          ) as { name?: unknown; version?: unknown };
          ({ keys: rootPackageIds } = buildRootPkgKeys(rootManifest));
        } catch {
          /* missing/invalid root package.json → empty set (no entry is root) */
        }
        const { summary, detail } = formatEgressWarning(egress, {
          manager: pm.manager,
          rootPackageIds,
        });
        warn(summary);
        process.stdout.write(detail);
      }
      // Host part-2 redacts the trusted-script lifecycle output before it reaches
      // the job log: the consumer-declared protected.env values (exact) + credential
      // shapes (F6).  Names default to [] when no config / field — shapes still apply.
      const protectedEnvNames = readProtectedEnvNames(inputs.configPath);
      // #19 fidelity (npm-only): part-2 re-passes the developer dep-selection
      // args (same `inputs.args` part-1 took) so `npm rebuild` runs lifecycle
      // scripts with the same NODE_ENV/omit env as the single-phase `npm ci
      // <args>` — in lockstep with the guest Phase B audit.
      await doHostRunScripts(pm.manager, repoDir, inputs.args, { stdout: process.stdout, stderr: process.stderr, warn }, protectedEnvNames, undefined, undefined, hostTmpdir);
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

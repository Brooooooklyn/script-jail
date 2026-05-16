// npm-jar — src/main.ts
//
// GitHub Action entry point.  Wired in action.yml as `runs.main: dist/main.js`.
//
// Flow:
//   1. Parse inputs (./action/inputs.ts) and detect the PM (./action/detect-pm.ts).
//   2. Ensure Firecracker + vmlinux are downloaded (./action/firecracker/download.ts).
//   3. Build the per-run overlay (./action/firecracker/overlay.ts).
//   4. Launch the VM (./action/firecracker/launch.ts) and open the vsock
//      session (./action/firecracker/vsock.ts).
//   5. Drive the handshake → final exchange with the guest.
//   6. Teardown (./action/firecracker/teardown.ts) ALWAYS runs in `finally`.
//   7. Post-VM: render diff (./action/diff.ts) or write the new lockfile.
//
// This module is intentionally thin: each step delegates to a helper that is
// independently unit-tested.  There is no unit test for main.ts itself —
// orchestration involves real OS resources (sockets, KVM, mkfs.ext4) that
// cannot be mocked cleanly without growing this file beyond what is readable.

import { setOutput } from '@actions/core';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { randomBytes } from 'node:crypto';

import { parseInputs } from './action/inputs.js';
import { detectPm, BunUnsupportedError, type DetectedPm } from './action/detect-pm.js';
import { detectRunnerImage } from './action/runner-image.js';
import { resolveHostNodePrefix } from './action/host-node-prefix.js';
import { renderDiff } from './action/diff.js';
import { warn } from './action/log.js';
import { buildEffectiveConfig } from './action/config-override.js';
import { maybeClearCache } from './action/cache.js';
import {
  ensureBinaries,
  NodeHttpClient,
} from './action/firecracker/download.js';
import { preFetchArtifacts } from './action/pre-fetch-artifacts.js';
import { PINNED_MANIFEST } from './action/artifact-manifest.js';
import { makeOverlay } from './action/firecracker/overlay.js';
import { launchVm, type VmHandle } from './action/firecracker/launch.js';
import { openVsockSession, type VsockSession } from './action/firecracker/vsock.js';
import { teardown } from './action/firecracker/teardown.js';
import type { OverlayResult } from './action/firecracker/overlay.js';

// ---------------------------------------------------------------------------
// Pinned versions
// ---------------------------------------------------------------------------

/** Firecracker release version (must match a key in KNOWN_VERSIONS). */
const FIRECRACKER_VERSION = '1.8.0';

// Pinned from Firecracker CI artifacts (v1.10, kernel 5.10.223).
// See src/rootfs/vmlinux.md for provenance and a "build your own" recipe;
// production deployments may prefer a stricter kernel config — refer to the
// tag-pinned policy doc at:
//   https://github.com/firecracker-microvm/firecracker/blob/v1.8.0/docs/kernel-policy.md
const PINNED_VMLINUX_URL =
  'https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223';
const PINNED_VMLINUX_SHA256 =
  '22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65';

/** vsock port the guest agent listens on. */
const VSOCK_PORT = 10242;

/** Guest CID for the vsock socket (host CID is fixed at 2). */
const GUEST_CID = 3;

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

export async function main(): Promise<void> {
  const repoDir = process.env['GITHUB_WORKSPACE'] ?? process.cwd();

  const inputs = parseInputs({ repoDir });

  // --- PM detection --------------------------------------------------------
  // BunUnsupportedError is non-fatal: emit a ::warning and exit cleanly so
  // bun-using repos can install the action without breaking their CI.
  let pm: DetectedPm;
  try {
    pm = detectPm({ repoDir });
  } catch (err) {
    if (err instanceof BunUnsupportedError) {
      warn(err.message);
      process.exit(0);
    }
    throw err;
  }
  // We still call detectPm() for its validation side effects (lockfile
  // present, not bun-only) and the lockfileSha256 it computes — the actual
  // package-manager choice now lives in the guest agent config on the repo
  // disk, not in the rootfs filename.  Marked `void` so noUnusedLocals stays
  // happy until a follow-up (Task #12+) wires `pm.lockfileSha256` through.
  void pm;

  // --- Detect runner image -------------------------------------------------
  const runnerImage = detectRunnerImage();

  // --- Resolve image paths -------------------------------------------------
  // imagesDir must live OUTSIDE the user's repo (we previously joined it onto
  // repoDir, which polluted their working tree).  RUNNER_TEMP is the GitHub
  // Actions runner's scratch directory — writable and cleaned between jobs.
  // os.tmpdir() is the dev/test fallback.
  //
  // The rootfs image (`rootfs-<runner-image>.ext4`) is also resolved here.
  // `preFetchArtifacts()` below downloads it (and libnpmjar.so) from the
  // GitHub release matching PINNED_MANIFEST.tag; if the download or its
  // SHA-256 check fails, the pre-fetch step throws before `launchVm` runs.
  const imagesDir = process.env['RUNNER_TEMP']
    ? join(process.env['RUNNER_TEMP'], 'npm-jar-images')
    : join(tmpdir(), 'npm-jar-images');
  mkdirSync(imagesDir, { recursive: true });

  // --- Honour `cache-firecracker: false` -----------------------------------
  // With caching disabled we remove the cacheable artifacts (Firecracker
  // tarball + binary + vmlinux) so ensureBinaries below takes the fresh-
  // download path.  Useful for forcing a re-pull after rotating the pinned
  // SHAs in this file, or to validate the download path on demand.  We do
  // NOT wipe the whole imagesDir — the rootfs ext4 lives there too and is
  // provisioned by a separate step (see `baseRootfsPath` below); deleting
  // it would break the very next call to `makeOverlay()`.
  maybeClearCache({
    imagesDir,
    firecrackerVersion: FIRECRACKER_VERSION,
    cacheFirecracker: inputs.cacheFirecracker,
  });

  // The rootfs image is keyed by runner image (e.g. rootfs-ubuntu-24.04.ext4)
  // rather than by (node-major, package-manager): Node is bind-mounted from
  // the host (Task #12), so the rootfs only needs to match the host's
  // glibc / shared-library set.
  const baseRootfsPath = join(
    imagesDir,
    `rootfs-${runnerImage}.ext4`,
  );

  // --- Pre-fetch release artifacts (rootfs + .so) --------------------------
  // GitHub JavaScript actions don't support `runs.pre`, so the pre-fetch
  // happens here, inside main(), before any other VM-side work.  See
  // `./action/pre-fetch-artifacts.ts` for the asymmetry note on libnpmjar.so
  // (baked into the released rootfs, so the .so download is informational
  // for the v1 production path).
  const http = new NodeHttpClient();
  await preFetchArtifacts({
    imagesDir,
    runnerImage,
    manifest: PINNED_MANIFEST,
    http,
  });

  // --- Ensure Firecracker + kernel are present -----------------------------
  const { firecrackerPath, vmlinuxPath } = await ensureBinaries({
    imagesDir,
    firecrackerVersion: FIRECRACKER_VERSION,
    kernelUrl: PINNED_VMLINUX_URL,
    kernelSha256: PINNED_VMLINUX_SHA256,
    http,
  });

  // --- Resolve host-node prefix --------------------------------------------
  // The rootfs ships no Node binary; we pack the runner's Node install into a
  // third ext4 disk and mount it at /opt/host-node inside the VM.  Whichever
  // Node the user's workflow set up (typically via actions/setup-node) is the
  // Node the audit runs against.
  //
  // We deliberately do NOT use `process.execPath` here.  This action is wired
  // as `runs.using: node20`, so `process.execPath` is the GitHub Actions
  // runner's bundled Node, not the user-selected Node.  `resolveHostNodePrefix`
  // walks PATH instead (where `actions/setup-node` has prepended its toolcache
  // bin/ directory) so it finds the right Node.
  const hostNodePrefix = resolveHostNodePrefix();

  // --- Apply spoof-platform / spoof-arch overrides -------------------------
  // The user's config YAML ships `spoof.platform` and `spoof.arch`, which the
  // guest agent reads and exports as NPM_JAR_SPOOF_PLATFORM / _ARCH for the
  // platform-spoof preload (see src/guest/agent.ts and platform-spoof.cjs).
  // The action also advertises `spoof-platform` / `spoof-arch` inputs and
  // users supplying them expect them to take precedence over whatever is on
  // disk.  We materialise an effective copy of the config to a per-run temp
  // path, applying the overrides, and feed that path into makeOverlay() so
  // the override lands in the VM's repo disk at /etc/npm-jar/config.yml.
  // The user's source file on the host is never modified.
  // Pass `imagesDir` as the workDir so the rewritten config lives under the
  // same RUNNER_TEMP-rooted tree we already use for binaries.  GitHub Actions
  // purges RUNNER_TEMP between jobs; without this, leaving the workDir at the
  // helper's mkdtemp default would accumulate stray dirs under os.tmpdir() on
  // self-hosted runners.
  const effectiveConfigPath = buildEffectiveConfig({
    userConfigPath: inputs.configPath,
    overrides: {
      spoofPlatform: inputs.spoofPlatform,
      spoofArch: inputs.spoofArch,
    },
    workDir: imagesDir,
  });

  // --- Build per-run overlay ----------------------------------------------
  const overlay: OverlayResult = await makeOverlay({
    baseRootfsPath,
    repoSrcPath: repoDir,
    configPath: effectiveConfigPath,
    hostNodePrefix,
  });

  // --- Generate unique per-run socket paths --------------------------------
  const runId = randomBytes(4).toString('hex');
  const apiSocketPath = join(tmpdir(), `npm-jar-fc-api-${runId}.sock`);
  const vsockUdsPath = join(tmpdir(), `npm-jar-vsock-${runId}`);

  let vm: VmHandle | null = null;
  let vsock: VsockSession | null = null;
  let finalYaml: string | null = null;
  let fatalError: Error | null = null;
  // Non-fatal guest errors are surfaced as ::warning:: annotations as they
  // arrive, AND retained here so we can attach them to a "no final frame"
  // diagnostic if the session ends without a `final`.
  const nonFatalErrors: string[] = [];

  try {
    // --- Boot the VM -------------------------------------------------------
    // Phase A networking is enabled at launch (tap0 + /network-interfaces/eth0
    // in `launch.ts`).  Phase B's offline guarantee is enforced from inside
    // the guest itself: after receiving `go` the agent runs `ip link set eth0
    // down` (see `src/guest/agent.ts`) and then verifies with a DNS probe.
    // We deliberately do NOT touch Firecracker's host-side rate-limiter API
    // here — its `size: 0` is interpreted as "rate limiter disabled" (i.e.
    // unlimited), not "no bandwidth", so a host-side patch would be a silent
    // no-op.  The guest is the source of truth for interface state.
    vm = await launchVm({
      firecrackerPath,
      vmlinuxPath,
      rootfsPath: overlay.rootfsCopyPath,
      repoDiskPath: overlay.repoDiskPath,
      hostNodeDiskPath: overlay.hostNodeDiskPath,
      vsockCid: GUEST_CID,
      vsockUdsPath,
      enableNetwork: true,
      socketPath: apiSocketPath,
    });

    // --- Open vsock session -----------------------------------------------
    vsock = await openVsockSession(vsockUdsPath, VSOCK_PORT);

    // --- Drive the protocol -----------------------------------------------
    for await (const frame of vsock.events) {
      if (frame.kind === 'event') {
        // We deliberately ignore the live event stream: the guest agent does
        // its own normalisation inside the VM and emits the YAML in the
        // `final` frame.  Host-side normalisation is not on the v1 roadmap.
        continue;
      }
      if (frame.kind === 'handshake') {
        if (frame.phase === 'fetch_done') {
          // Release the guest with `go`.  Network teardown happens inside
          // the guest before Phase B starts (see `src/guest/agent.ts`,
          // `dropEth0`) — host-side rate-limiter patching is unreliable
          // because Firecracker treats `size: 0` as "rate limiter disabled"
          // (unlimited), not "no bandwidth".
          await vsock.sendGo();
          continue;
        }
        // `install_done` is an FYI marker; the agent will follow with `final`.
        // No action needed here, but we keep the branch explicit so future
        // handshake phases must opt in rather than fall through unnoticed.
        continue;
      }
      if (frame.kind === 'error') {
        if (frame.fatal) {
          fatalError = new Error(`npm-jar guest fatal: ${frame.message}`);
          break;
        }
        // Non-fatal errors are surfaced as warnings AND retained so that, if
        // the stream ends without a final frame, we can attach them to the
        // diagnostic message instead of throwing a context-free error.
        nonFatalErrors.push(frame.message);
        warn(`npm-jar guest: ${frame.message}`);
        continue;
      }
      if (frame.kind === 'final') {
        finalYaml = frame.yaml;
        break;
      }
    }
  } finally {
    await teardown({
      vm,
      overlay,
      vsock,
      apiSocketPath,
      vsockUdsPath,
    });
  }

  if (fatalError !== null) throw fatalError;
  if (finalYaml === null) {
    const tail =
      nonFatalErrors.length > 0
        ? ` Prior warnings: [${nonFatalErrors.map((m) => JSON.stringify(m)).join(', ')}]`
        : '';
    throw new Error(
      `npm-jar: vsock session ended without a final frame.${tail}`,
    );
  }

  // --- Post-VM: diff or write ---------------------------------------------
  if (inputs.mode === 'check') {
    const committed = existsSync(inputs.lockPath)
      ? readFileSync(inputs.lockPath, 'utf8')
      : '';

    const diff = renderDiff({
      lockPath: relativeForDisplay(inputs.lockPath, repoDir),
      committed,
      generated: finalYaml,
    });

    if (diff.unified !== '') {
      process.stdout.write(diff.unified);
      // Make sure the annotations don't smash onto the diff's last line.
      if (!diff.unified.endsWith('\n')) process.stdout.write('\n');
    }
    for (const ann of diff.annotations) {
      process.stdout.write(`${ann}\n`);
    }

    setOutput('lockfile', inputs.lockPath);
    setOutput('diff', diff.unified);

    if (!diff.match) process.exit(1);
    return;
  }

  // mode === 'update'
  writeFileSync(inputs.lockPath, finalYaml, 'utf8');
  setOutput('lockfile', inputs.lockPath);
  setOutput('diff', '');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns `absPath` made relative to `repoDir` when it is inside the repo.
 * Falls back to the absolute path otherwise.  Used purely for cosmetic
 * annotation labels — the underlying read/write uses the absolute path.
 */
function relativeForDisplay(absPath: string, repoDir: string): string {
  const rel = relative(repoDir, absPath);
  // If `rel` starts with ".." or is absolute on Windows, the path escapes the
  // repo — keep the absolute path to avoid a misleading label.
  if (rel.startsWith('..') || isAbsolute(rel)) return absPath;
  return rel;
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

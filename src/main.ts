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
import { detectPm, BunUnsupportedError } from './action/detect-pm.js';
import { renderDiff } from './action/diff.js';
import {
  ensureBinaries,
  NodeHttpClient,
} from './action/firecracker/download.js';
import { makeOverlay } from './action/firecracker/overlay.js';
import { launchVm, type VmHandle } from './action/firecracker/launch.js';
import { openVsockSession, type VsockSession } from './action/firecracker/vsock.js';
import { teardown } from './action/firecracker/teardown.js';
import type { OverlayResult } from './action/firecracker/overlay.js';

// ---------------------------------------------------------------------------
// Pinned versions / placeholders
// ---------------------------------------------------------------------------

/** Firecracker release version (must match a key in KNOWN_VERSIONS). */
const FIRECRACKER_VERSION = '1.8.0';

/**
 * TODO(ops): populate the production vmlinux URL + SHA-256.  These are
 * placeholders so the action can be compiled and unit-tested before the
 * ops team has uploaded a kernel image.
 */
const PLACEHOLDER_VMLINUX_URL =
  'https://example.invalid/npm-jar/vmlinux-PLACEHOLDER';
const PLACEHOLDER_VMLINUX_SHA256 =
  'PLACEHOLDER_SHA256_VMLINUX_NOT_YET_PUBLISHED';

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
  let pm;
  try {
    pm = await detectPm({ repoDir });
  } catch (err) {
    if (err instanceof BunUnsupportedError) {
      process.stdout.write(`::warning::${err.message}\n`);
      process.exit(0);
    }
    throw err;
  }

  // --- Resolve image paths -------------------------------------------------
  const imagesDir = join(repoDir, 'images');
  mkdirSync(imagesDir, { recursive: true });

  // The rootfs image is keyed by node-major + manager (e.g. rootfs-node20-pnpm.ext4).
  const baseRootfsPath = join(
    imagesDir,
    `rootfs-node${inputs.nodeVersion}-${pm.manager}.ext4`,
  );

  // --- Ensure Firecracker + kernel are present -----------------------------
  const { firecrackerPath, vmlinuxPath } = await ensureBinaries({
    imagesDir,
    firecrackerVersion: FIRECRACKER_VERSION,
    kernelUrl: PLACEHOLDER_VMLINUX_URL,
    kernelSha256: PLACEHOLDER_VMLINUX_SHA256,
    http: new NodeHttpClient(),
  });

  // --- Build per-run overlay ----------------------------------------------
  const overlay: OverlayResult = await makeOverlay({
    baseRootfsPath,
    repoSrcPath: repoDir,
    configPath: inputs.configPath,
  });

  // --- Generate unique per-run socket paths --------------------------------
  const runId = randomBytes(4).toString('hex');
  const apiSocketPath = join(tmpdir(), `npm-jar-fc-api-${runId}.sock`);
  const vsockUdsPath = join(tmpdir(), `npm-jar-vsock-${runId}`);

  let vm: VmHandle | null = null;
  let vsock: VsockSession | null = null;
  let finalYaml: string | null = null;
  let fatalError: Error | null = null;

  try {
    // --- Boot the VM -------------------------------------------------------
    // TODO(v2): toggle network OFF after fetch_done handshake.  Phase A leaves
    // the network on for the entire run because the current guest agent does
    // not yet signal a phase transition the host can act on.
    vm = await launchVm({
      firecrackerPath,
      vmlinuxPath,
      rootfsPath: overlay.rootfsCopyPath,
      repoDiskPath: overlay.repoDiskPath,
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
        // Events are emitted continuously; the host normalizer will use them
        // in a future iteration.  For v1 we ignore the live stream because
        // the guest emits the final lockfile YAML directly.
        continue;
      }
      if (frame.kind === 'handshake') {
        if (frame.phase === 'fetch_done') {
          await vsock.sendGo();
        }
        continue;
      }
      if (frame.kind === 'error') {
        if (frame.fatal) {
          fatalError = new Error(`npm-jar guest fatal: ${frame.message}`);
          break;
        }
        // Non-fatal errors are surfaced as warnings.
        process.stdout.write(`::warning::npm-jar guest: ${frame.message}\n`);
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
    throw new Error(
      'npm-jar: guest did not emit a "final" frame before the vsock stream ended.',
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

    process.stdout.write(diff.unified);
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

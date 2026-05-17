// script-jail — src/action/firecracker/teardown.ts
//
// Safe cleanup for a Firecracker microVM run.
//
// Design contract:
//   - `teardown` NEVER throws.  Every sub-step is wrapped in try/catch.
//   - Null handles are silently ignored (safe to call from partial-failure paths).
//   - Errors are logged to stderr for post-mortem inspection but do not abort
//     remaining cleanup steps.
//
// Cleanup order:
//   1. Close the vsock session (stops listening for frames).
//   2. Kill the Firecracker process.
//   3. Wait for the process to exit (up to 3 s, then SIGKILL).
//   4. Remove the Firecracker API socket file.
//   5. Remove the vsock UDS file(s).
//   6. Remove the per-run overlay work directory via overlay.cleanup().

import { unlink, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import type { VmHandle } from './launch.js';
import type { OverlayResult } from './overlay.js';
import type { VsockSession } from './vsock.js';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface TeardownHandles {
  /** The running VM handle, or null if the VM was never started. */
  vm: VmHandle | null;
  /** The overlay result (owns the work dir), or null if never created. */
  overlay: OverlayResult | null;
  /** The vsock session, or null if never opened. */
  vsock: VsockSession | null;
  /**
   * Path to the Firecracker API socket (removed on teardown).
   * Required to remove the socket file even if the VmHandle is null.
   */
  apiSocketPath?: string | undefined;
  /**
   * Base path of the vsock UDS.  Firecracker creates `<udsPath>_<port>`.
   * Provide the base path; teardown removes all matching files.
   */
  vsockUdsPath?: string | undefined;
}

// ---------------------------------------------------------------------------
// teardown
// ---------------------------------------------------------------------------

export async function teardown(handles: TeardownHandles): Promise<void> {
  // 1. Close vsock session.
  if (handles.vsock !== null) {
    await safeRun('close vsock session', () => handles.vsock!.close());
  }

  // 2. Kill the Firecracker process.
  if (handles.vm !== null) {
    await safeRun('kill VM', () => handles.vm!.kill());

    // 3. Wait for exit (max 3 s), then hard-kill.
    await safeRun('wait for VM exit', () =>
      Promise.race([
        handles.vm!.waitForExit(),
        timeout(3_000).then(() => {
          // If we're still here after 3 s it's a zombie — not much we can do.
          console.warn('[teardown] VM did not exit within 3 s after SIGKILL.');
        }),
      ]),
    );
  }

  // 4. Remove the Firecracker API socket.
  if (handles.apiSocketPath !== undefined) {
    await safeRun('remove API socket', () => removeIfExists(handles.apiSocketPath!));
  } else if (handles.vm !== null) {
    // No explicit path provided; we can't remove it but we log for awareness.
    console.warn('[teardown] apiSocketPath not provided; API socket not removed.');
  }

  // 5. Remove vsock UDS files.
  //    Firecracker creates `<udsPath>_<port>` patterns.
  //    We attempt to remove the base path and the known port variant.
  if (handles.vsockUdsPath !== undefined) {
    const base = handles.vsockUdsPath;
    // Remove the exact path (may be the base path itself).
    await safeRun('remove vsock UDS (base)', () => removeIfExists(base));
    // Also try the port-suffixed variant Firecracker creates.
    // Port 10242 is the default script-jail vsock port.
    await safeRun('remove vsock UDS (port suffix)', () => removeIfExists(`${base}_10242`));
  }

  // 6. Clean up the overlay work directory.
  if (handles.overlay !== null) {
    await safeRun('overlay cleanup', () => handles.overlay!.cleanup());
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Run an async operation; log errors but never throw. */
async function safeRun(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    console.error(
      `[teardown] ${label} failed (continuing): ` +
      `${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

async function removeIfExists(filePath: string): Promise<void> {
  if (!existsSync(filePath)) return;
  try {
    await unlink(filePath);
  } catch (err) {
    // If the file is actually a directory (shouldn't happen for sockets, but
    // be defensive) fall back to rm -r.
    await rm(filePath, { recursive: true, force: true });
  }
}

function timeout(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

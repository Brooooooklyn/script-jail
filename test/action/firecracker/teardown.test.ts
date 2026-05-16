// npm-jar — test/action/firecracker/teardown.test.ts
//
// Tests for teardown().  All handles are mocks; no real filesystem or
// subprocess interaction happens here.

import { describe, it, expect, vi } from 'vitest';
import { teardown, type TeardownHandles } from '../../../src/action/firecracker/teardown.js';
import type { VmHandle } from '../../../src/action/firecracker/launch.js';
import type { OverlayResult } from '../../../src/action/firecracker/overlay.js';
import type { VsockSession } from '../../../src/action/firecracker/vsock.js';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Fake handle builders
// ---------------------------------------------------------------------------

function makeVmHandle(overrides?: Partial<VmHandle>): VmHandle {
  return {
    pid: 1234,
    apiClient: { put: async () => {}, patch: async () => {} },
    kill: vi.fn(async () => {}),
    waitForExit: vi.fn(async () => 0),
    ...overrides,
  };
}

function makeOverlayResult(overrides?: Partial<OverlayResult>): OverlayResult {
  return {
    rootfsCopyPath: '/tmp/rootfs.ext4',
    repoDiskPath: '/tmp/repo.ext4',
    hostNodeDiskPath: '/tmp/host-node.ext4',
    workDir: '/tmp/work',
    cleanup: vi.fn(async () => {}),
    ...overrides,
  };
}

function makeVsockSession(overrides?: Partial<VsockSession>): VsockSession {
  return {
    events: (async function* () {})(),
    sendGo: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('teardown', () => {
  it('does not throw when all handles are null', async () => {
    const handles: TeardownHandles = { vm: null, overlay: null, vsock: null };
    await expect(teardown(handles)).resolves.toBeUndefined();
  });

  it('calls vsock.close()', async () => {
    const vsock = makeVsockSession();
    await teardown({ vm: null, overlay: null, vsock });
    expect(vsock.close).toHaveBeenCalledOnce();
  });

  it('calls vm.kill()', async () => {
    const vm = makeVmHandle();
    await teardown({ vm, overlay: null, vsock: null });
    expect(vm.kill).toHaveBeenCalledOnce();
  });

  it('calls vm.waitForExit()', async () => {
    const vm = makeVmHandle();
    await teardown({ vm, overlay: null, vsock: null });
    expect(vm.waitForExit).toHaveBeenCalledOnce();
  });

  it('calls overlay.cleanup()', async () => {
    const overlay = makeOverlayResult();
    await teardown({ vm: null, overlay, vsock: null });
    expect(overlay.cleanup).toHaveBeenCalledOnce();
  });

  it('calls all three cleanup operations when all handles are set', async () => {
    const vm = makeVmHandle();
    const overlay = makeOverlayResult();
    const vsock = makeVsockSession();

    await teardown({ vm, overlay, vsock });

    expect(vsock.close).toHaveBeenCalledOnce();
    expect(vm.kill).toHaveBeenCalledOnce();
    expect(overlay.cleanup).toHaveBeenCalledOnce();
  });

  it('continues cleanup after vsock.close() throws', async () => {
    const vsock = makeVsockSession({
      close: vi.fn(async () => { throw new Error('vsock close failed'); }),
    });
    const vm = makeVmHandle();
    const overlay = makeOverlayResult();

    // Must NOT throw.
    await expect(teardown({ vm, overlay, vsock })).resolves.toBeUndefined();

    // The other cleanups should still have been called.
    expect(vm.kill).toHaveBeenCalledOnce();
    expect(overlay.cleanup).toHaveBeenCalledOnce();
  });

  it('continues cleanup after vm.kill() throws', async () => {
    const vm = makeVmHandle({
      kill: vi.fn(async () => { throw new Error('kill failed'); }),
    });
    const overlay = makeOverlayResult();
    const vsock = makeVsockSession();

    await expect(teardown({ vm, overlay, vsock })).resolves.toBeUndefined();

    expect(vsock.close).toHaveBeenCalledOnce();
    expect(overlay.cleanup).toHaveBeenCalledOnce();
  });

  it('continues cleanup after overlay.cleanup() throws', async () => {
    const vm = makeVmHandle();
    const vsock = makeVsockSession();
    const overlay = makeOverlayResult({
      cleanup: vi.fn(async () => { throw new Error('cleanup exploded'); }),
    });

    await expect(teardown({ vm, overlay, vsock })).resolves.toBeUndefined();
    expect(vm.kill).toHaveBeenCalledOnce();
    expect(vsock.close).toHaveBeenCalledOnce();
  });

  it('removes the API socket file when apiSocketPath is set', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'npm-jar-teardown-test-'));
    const apiSocketPath = join(dir, 'fc.sock');
    writeFileSync(apiSocketPath, ''); // create the file

    try {
      await teardown({ vm: null, overlay: null, vsock: null, apiSocketPath });
      expect(existsSync(apiSocketPath)).toBe(false);
    } finally {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  it('does not throw when API socket file does not exist', async () => {
    await expect(teardown({
      vm: null,
      overlay: null,
      vsock: null,
      apiSocketPath: '/tmp/nonexistent-fc.sock',
    })).resolves.toBeUndefined();
  });

  it('removes the vsock UDS file when vsockUdsPath is set', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'npm-jar-teardown-vsock-'));
    const vsockUdsPath = join(dir, 'vsock.sock');
    writeFileSync(vsockUdsPath, '');

    try {
      await teardown({ vm: null, overlay: null, vsock: null, vsockUdsPath });
      expect(existsSync(vsockUdsPath)).toBe(false);
    } finally {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  it('handles all-null handles with extra socket paths gracefully', async () => {
    await expect(teardown({
      vm: null,
      overlay: null,
      vsock: null,
      apiSocketPath: '/tmp/no-such-file-abc123.sock',
      vsockUdsPath: '/tmp/no-such-vsock-abc123.sock',
    })).resolves.toBeUndefined();
  });

  it('cleanup order: vsock first, overlay last', async () => {
    const order: string[] = [];
    const vsock = makeVsockSession({
      close: vi.fn(async () => { order.push('vsock.close'); }),
    });
    const vm = makeVmHandle({
      kill: vi.fn(async () => { order.push('vm.kill'); }),
      waitForExit: vi.fn(async () => { order.push('vm.waitForExit'); return 0; }),
    });
    const overlay = makeOverlayResult({
      cleanup: vi.fn(async () => { order.push('overlay.cleanup'); }),
    });

    await teardown({ vm, overlay, vsock });

    expect(order[0]).toBe('vsock.close');
    expect(order[order.length - 1]).toBe('overlay.cleanup');
  });
});

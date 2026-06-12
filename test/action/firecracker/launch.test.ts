// script-jail — test/action/firecracker/launch.test.ts
//
// Unit tests for launchVm().  All OS interaction is injected:
//   - FakeSpawner: records spawn calls and returns a fake handle.
//   - FakeApiClient: records every PUT/PATCH call.
//   - FakePoller: immediately resolves (no real socket polling).

import { describe, it, expect } from 'vitest';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type {
  Spawner,
  SpawnHandle,
  FirecrackerApiClient,
  SocketPoller,
} from '../../../src/action/firecracker/launch.js';
import { launchVm, UnixSocketApiClient } from '../../../src/action/firecracker/launch.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface ApiCall {
  method: 'PUT' | 'PATCH';
  path: string;
  body: unknown;
}

function makeFakeApiClient(): { client: FirecrackerApiClient; calls: ApiCall[] } {
  const calls: ApiCall[] = [];
  const client: FirecrackerApiClient = {
    async put(path, body) { calls.push({ method: 'PUT', path, body }); },
    async patch(path, body) { calls.push({ method: 'PATCH', path, body }); },
  };
  return { client, calls };
}

function makeFakeSpawner(): {
  spawner: Spawner;
  spawnCalls: Array<{ cmd: string; args: ReadonlyArray<string> }>;
  handle: SpawnHandle & { _pid: number };
} {
  const spawnCalls: Array<{ cmd: string; args: ReadonlyArray<string> }> = [];
  const handle: SpawnHandle & { _pid: number } = {
    _pid: 1234,
    get pid() { return 1234; },
    kill: (_signal) => true,
    waitForExit: () => Promise.resolve(0),
  };
  const spawner: Spawner = {
    spawn(cmd, args, _opts) {
      spawnCalls.push({ cmd, args: [...args] });
      return handle;
    },
  };
  return { spawner, spawnCalls, handle };
}

function makeFakePoller(): SocketPoller {
  return {
    async waitForSocket(_path, _timeout) {
      // Immediately resolve — no real filesystem polling.
    },
  };
}

// ---------------------------------------------------------------------------
// Default launch input
// ---------------------------------------------------------------------------

function makeInput(
  overrides: Partial<Parameters<typeof launchVm>[0]> = {},
): Parameters<typeof launchVm>[0] {
  const { client } = makeFakeApiClient();
  const { spawner } = makeFakeSpawner();
  return {
    firecrackerPath: '/usr/bin/firecracker',
    vmlinuxPath: '/images/vmlinux',
    rootfsPath: '/run/rootfs.ext4',
    // Required since the round-1 review hardening: the guest's init.sh
    // fail-closes when the scratch device is absent, so every launch must
    // attach it.
    scratchDiskPath: '/run/scratch.ext4',
    // Required like scratch: init.sh fail-closes when the sjtmp device is
    // absent (TMPDIR=/sjtmp), so every launch must attach it.
    sjtmpDiskPath: '/run/sjtmp.ext4',
    vsockCid: 100,
    vsockUdsPath: '/tmp/vsock.sock',
    enableNetwork: false,
    socketPath: '/tmp/fc.sock',
    apiClient: client,
    spawner,
    poller: makeFakePoller(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('launchVm', () => {
  it('spawns firecracker with --api-sock argument', async () => {
    const { spawner, spawnCalls } = makeFakeSpawner();
    const { client } = makeFakeApiClient();
    const socketPath = '/tmp/test-fc.sock';

    await launchVm(makeInput({ spawner, apiClient: client, socketPath }));

    expect(spawnCalls).toHaveLength(1);
    const [call] = spawnCalls;
    expect(call!.cmd).toBe('/usr/bin/firecracker');
    expect(call!.args).toContain('--api-sock');
    expect(call!.args).toContain(socketPath);
  });

  it('sends PUT /boot-source with kernel path and boot_args', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner, vmlinuxPath: '/images/vmlinux' }));

    const bootSource = calls.find((c) => c.path === '/boot-source');
    expect(bootSource).toBeDefined();
    expect(bootSource!.method).toBe('PUT');
    expect((bootSource!.body as Record<string, unknown>)['kernel_image_path']).toBe('/images/vmlinux');
    expect(typeof (bootSource!.body as Record<string, unknown>)['boot_args']).toBe('string');
  });

  it('sends PUT /drives/rootfs with correct shape', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner, rootfsPath: '/run/my-rootfs.ext4' }));

    const rootfsDrive = calls.find((c) => c.path === '/drives/rootfs');
    expect(rootfsDrive).toBeDefined();
    expect(rootfsDrive!.method).toBe('PUT');
    const body = rootfsDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('rootfs');
    expect(body['path_on_host']).toBe('/run/my-rootfs.ext4');
    expect(body['is_root_device']).toBe(true);
    expect(body['is_read_only']).toBe(false);
  });

  it('sends PUT /machine-config with vcpu and mem', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner, vcpu: 4, memMB: 4096 }));

    const machineConfig = calls.find((c) => c.path === '/machine-config');
    expect(machineConfig).toBeDefined();
    const body = machineConfig!.body as Record<string, unknown>;
    expect(body['vcpu_count']).toBe(4);
    expect(body['mem_size_mib']).toBe(4096);
  });

  it('uses defaults of vcpu=2, memMB=2048 when not specified', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner }));

    const machineConfig = calls.find((c) => c.path === '/machine-config');
    const body = machineConfig!.body as Record<string, unknown>;
    expect(body['vcpu_count']).toBe(2);
    expect(body['mem_size_mib']).toBe(2048);
  });

  it('sends PUT /vsock with correct CID and UDS path', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({
      apiClient: client,
      spawner,
      vsockCid: 42,
      vsockUdsPath: '/tmp/my-vsock.sock',
    }));

    const vsock = calls.find((c) => c.path === '/vsock');
    expect(vsock).toBeDefined();
    expect(vsock!.method).toBe('PUT');
    const body = vsock!.body as Record<string, unknown>;
    expect(body['guest_cid']).toBe(42);
    expect(body['uds_path']).toBe('/tmp/my-vsock.sock');
  });

  it('sends PUT /actions with action_type InstanceStart as the last call', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner }));

    const last = calls[calls.length - 1];
    expect(last!.path).toBe('/actions');
    expect((last!.body as Record<string, unknown>)['action_type']).toBe('InstanceStart');
  });

  it('does NOT send /network-interfaces when enableNetwork=false', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner, enableNetwork: false }));

    const netCall = calls.find((c) => c.path.startsWith('/network-interfaces'));
    expect(netCall).toBeUndefined();
  });

  it('boot sequence order: boot-source → drives → machine-config → vsock → actions', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner }));

    const paths = calls.map((c) => c.path);
    const bootIdx = paths.indexOf('/boot-source');
    const drivesIdx = paths.indexOf('/drives/rootfs');
    const machineIdx = paths.indexOf('/machine-config');
    const vsockIdx = paths.indexOf('/vsock');
    const actionsIdx = paths.indexOf('/actions');

    expect(bootIdx).toBeGreaterThanOrEqual(0);
    expect(bootIdx).toBeLessThan(drivesIdx);
    expect(drivesIdx).toBeLessThan(machineIdx);
    expect(machineIdx).toBeLessThan(vsockIdx);
    expect(vsockIdx).toBeLessThan(actionsIdx);
  });

  it('returned VmHandle.pid matches the spawner handle pid', async () => {
    const { client } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    const handle = await launchVm(makeInput({ apiClient: client, spawner }));

    expect(handle.pid).toBe(1234);
  });

  it('sends PUT /drives/repo when repoDiskPath is provided', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({
      apiClient: client,
      spawner,
      repoDiskPath: '/run/repo.ext4',
    }));

    const repoDrive = calls.find((c) => c.path === '/drives/repo');
    expect(repoDrive).toBeDefined();
    const body = repoDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('repo');
    expect(body['path_on_host']).toBe('/run/repo.ext4');
    expect(body['is_root_device']).toBe(false);
    // Repo disk is per-run scratch — Phase A needs to write /work/node_modules.
    expect(body['is_read_only']).toBe(false);
  });

  it('does NOT send /drives/repo when repoDiskPath is not provided', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner, repoDiskPath: undefined }));

    const repoDrive = calls.find((c) => c.path === '/drives/repo');
    expect(repoDrive).toBeUndefined();
  });

  it('sends PUT /drives/scratch (rw) after /drives/repo when scratchDiskPath is provided', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({
      apiClient: client,
      spawner,
      repoDiskPath: '/run/repo.ext4',
      scratchDiskPath: '/run/scratch.ext4',
    }));

    const scratchDrive = calls.find((c) => c.path === '/drives/scratch');
    expect(scratchDrive).toBeDefined();
    expect(scratchDrive!.method).toBe('PUT');
    const body = scratchDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('scratch');
    expect(body['path_on_host']).toBe('/run/scratch.ext4');
    expect(body['is_root_device']).toBe(false);
    // Scratch is where the guest spills strace logs + the events JSONL —
    // it MUST be writable or the guest falls back to the 64 MB /tmp tmpfs.
    expect(body['is_read_only']).toBe(false);

    // Attach order: rootfs → repo → scratch.
    const paths = calls.map((c) => c.path);
    const repoIdx = paths.indexOf('/drives/repo');
    const scratchIdx = paths.indexOf('/drives/scratch');
    expect(repoIdx).toBeGreaterThanOrEqual(0);
    expect(scratchIdx).toBeGreaterThan(repoIdx);
  });

  it('sends PUT /drives/sjtmp (rw) after /drives/scratch', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({
      apiClient: client,
      spawner,
      scratchDiskPath: '/run/scratch.ext4',
      sjtmpDiskPath: '/run/sjtmp.ext4',
    }));

    const sjtmpDrive = calls.find((c) => c.path === '/drives/sjtmp');
    expect(sjtmpDrive).toBeDefined();
    expect(sjtmpDrive!.method).toBe('PUT');
    const body = sjtmpDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('sjtmp');
    expect(body['path_on_host']).toBe('/run/sjtmp.ext4');
    expect(body['is_root_device']).toBe(false);
    // TMPDIR=/sjtmp — the install writes here, so it MUST be writable.
    expect(body['is_read_only']).toBe(false);

    // Attach order: scratch → sjtmp (sjtmp last).
    const paths = calls.map((c) => c.path);
    const scratchIdx = paths.indexOf('/drives/scratch');
    const sjtmpIdx = paths.indexOf('/drives/sjtmp');
    expect(scratchIdx).toBeGreaterThanOrEqual(0);
    expect(sjtmpIdx).toBeGreaterThan(scratchIdx);
  });

  it('ALWAYS sends /drives/sjtmp (required — init.sh fail-closes without it)', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    await launchVm(makeInput({ apiClient: client, spawner }));

    const sjtmpDrive = calls.find((c) => c.path === '/drives/sjtmp');
    expect(sjtmpDrive).toBeDefined();
    const body = sjtmpDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('sjtmp');
    expect(body['path_on_host']).toBe('/run/sjtmp.ext4');
    expect(body['is_read_only']).toBe(false);
  });

  it('ALWAYS sends /drives/scratch (required — init.sh fail-closes without it)', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    // No scratch override — the default input's scratch disk must be PUT
    // unconditionally.  A launch without the drive would boot a guest whose
    // init.sh fatals on the missing `scratch` label.
    await launchVm(makeInput({ apiClient: client, spawner }));

    const scratchDrive = calls.find((c) => c.path === '/drives/scratch');
    expect(scratchDrive).toBeDefined();
    const body = scratchDrive!.body as Record<string, unknown>;
    expect(body['drive_id']).toBe('scratch');
    expect(body['path_on_host']).toBe('/run/scratch.ext4');
    expect(body['is_read_only']).toBe(false);
  });

  it('uses the custom bootArgs when provided', async () => {
    const { client, calls } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();
    const customArgs = 'console=ttyS0 custom=1';

    await launchVm(makeInput({ apiClient: client, spawner, bootArgs: customArgs }));

    const bootSource = calls.find((c) => c.path === '/boot-source');
    expect((bootSource!.body as Record<string, unknown>)['boot_args']).toBe(customArgs);
  });

  it('throws if spawner is NOT injected and platform is not linux', async () => {
    // Only run this assertion when tests are run on macOS.
    if (process.platform === 'linux') return;

    const { client } = makeFakeApiClient();

    // No spawner injected → real platform gate fires.
    await expect(
      launchVm({
        firecrackerPath: '/usr/bin/firecracker',
        vmlinuxPath: '/images/vmlinux',
        rootfsPath: '/run/rootfs.ext4',
        scratchDiskPath: '/run/scratch.ext4',
        sjtmpDiskPath: '/run/sjtmp.ext4',
        vsockCid: 100,
        vsockUdsPath: '/tmp/vsock.sock',
        enableNetwork: false,
        socketPath: '/tmp/fc.sock',
        apiClient: client,
        // spawner intentionally omitted
      }),
    ).rejects.toThrow(/Firecracker requires Linux/);
  });

  it('VmHandle.kill() calls the spawner handle kill', async () => {
    const killCalls: Array<NodeJS.Signals | number | undefined> = [];

    const handle: SpawnHandle = {
      pid: 999,
      kill: (sig) => { killCalls.push(sig); return true; },
      waitForExit: () => Promise.resolve(0),
    };

    const spawner: Spawner = {
      spawn(_cmd, _args, _opts) { return handle; },
    };

    const { client } = makeFakeApiClient();
    const vmHandle = await launchVm(makeInput({ apiClient: client, spawner }));
    await vmHandle.kill();

    expect(killCalls).toHaveLength(1);
  });

  it('returned VmHandle.apiClient exposes both put and patch', async () => {
    const { client } = makeFakeApiClient();
    const { spawner } = makeFakeSpawner();

    const handle = await launchVm(makeInput({ apiClient: client, spawner }));

    expect(typeof handle.apiClient.put).toBe('function');
    expect(typeof handle.apiClient.patch).toBe('function');
  });

  it('kills the process and re-throws when an API call fails mid-sequence', async () => {
    const killCalls: Array<NodeJS.Signals | number | undefined> = [];

    const handle: SpawnHandle = {
      pid: 7777,
      kill: (sig) => { killCalls.push(sig); return true; },
      waitForExit: () => Promise.resolve(0),
    };

    const spawner: Spawner = {
      spawn(_cmd, _args, _opts) { return handle; },
    };

    // Fail on the /machine-config call.
    const errorClient: FirecrackerApiClient = {
      async put(path) {
        if (path === '/machine-config') {
          throw new Error('simulated API failure');
        }
      },
      async patch() {},
    };

    await expect(
      launchVm(makeInput({ apiClient: errorClient, spawner, poller: makeFakePoller() })),
    ).rejects.toThrow('simulated API failure');

    // The spawned process MUST have been killed.
    expect(killCalls.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// UnixSocketApiClient — status code guard tests
// ---------------------------------------------------------------------------

/**
 * Spin up a minimal HTTP/1.1 server on a Unix socket that responds with a
 * fixed status code, then assert whether UnixSocketApiClient resolves or rejects.
 */
function withFakeFirecrackerServer(
  statusCode: number | undefined,
  body: string,
  test: (socketPath: string) => Promise<void>,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'script-jail-api-test-'));
    const socketPath = join(tmpDir, 'fc.sock');

    const server = createServer((sock) => {
      // Read until we have consumed the request headers, then respond.
      let received = '';
      sock.on('data', (chunk: Buffer) => {
        received += chunk.toString();
        if (received.includes('\r\n\r\n')) {
          // Send a minimal HTTP/1.1 response.
          const statusLine =
            statusCode !== undefined
              ? `HTTP/1.1 ${statusCode} Status\r\n`
              : 'HTTP/1.1 \r\n'; // malformed — triggers undefined in Node
          const response =
            `${statusLine}Content-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`;
          sock.end(response);
        }
      });
    });

    server.listen(socketPath, async () => {
      try {
        await test(socketPath);
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        server.close();
        try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
      }
    });

    server.on('error', reject);
  });
}

describe('UnixSocketApiClient status code guard', () => {
  it('rejects with a descriptive error when statusCode is 500', async () => {
    await withFakeFirecrackerServer(500, '{"error":"internal"}', async (socketPath) => {
      const client = new UnixSocketApiClient(socketPath);
      await expect(client.put('/boot-source', {})).rejects.toThrow(/HTTP 500/);
    });
  });

  it('rejects when statusCode is 404', async () => {
    await withFakeFirecrackerServer(404, 'not found', async (socketPath) => {
      const client = new UnixSocketApiClient(socketPath);
      await expect(client.put('/nonexistent', {})).rejects.toThrow(/HTTP 404/);
    });
  });

  it('resolves when statusCode is 204 (Firecracker success)', async () => {
    await withFakeFirecrackerServer(204, '', async (socketPath) => {
      const client = new UnixSocketApiClient(socketPath);
      await expect(client.put('/boot-source', {})).resolves.toBeUndefined();
    });
  });

  it('resolves when statusCode is 200', async () => {
    await withFakeFirecrackerServer(200, '{}', async (socketPath) => {
      const client = new UnixSocketApiClient(socketPath);
      await expect(client.put('/boot-source', {})).resolves.toBeUndefined();
    });
  });
});

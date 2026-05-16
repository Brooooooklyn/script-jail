// npm-jar — src/action/firecracker/launch.ts
//
// Boots a Firecracker microVM via its REST API (a Unix socket).
//
// Platform constraint: Firecracker is Linux-only and requires /dev/kvm.
// `launchVm` will throw early with a clear message on macOS or when
// /dev/kvm is absent.  Unit tests bypass this gate by injecting a
// FakeSpawner and a fake FirecrackerApiClient so they never touch the OS.
//
// Boot sequence (see launchVm):
//   1. Spawn firecracker subprocess with --api-sock.
//   2. Poll for the Unix socket to appear (up to 5 s).
//   3. PUT /boot-source
//   4. PUT /drives/rootfs
//   5. PUT /machine-config
//   6. (optional) set up tap + PUT /network-interfaces/eth0
//   7. PUT /vsock
//   8. PUT /actions { action_type: "InstanceStart" }
//
// All filesystem / subprocess operations are behind injectable interfaces
// (Spawner, FirecrackerApiClient, SocketPoller) so unit tests never touch
// the OS.

import { request as httpRequest } from 'node:http';
import { existsSync } from 'node:fs';
import { unlink } from 'node:fs/promises';
import { spawn as nodeSpawn, spawnSync } from 'node:child_process';
import { platform } from 'node:process';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/**
 * Firecracker REST API client.  The production implementation talks over
 * a Unix socket; tests inject a fake that records calls.
 */
export interface FirecrackerApiClient {
  put(path: string, body: unknown): Promise<void>;
  patch(path: string, body: unknown): Promise<void>;
}

/** Abstraction over child_process.spawn so tests can inject a fake. */
export interface Spawner {
  spawn(
    cmd: string,
    args: ReadonlyArray<string>,
    opts: { stdio: 'ignore' },
  ): SpawnHandle;
}

/** Minimal handle returned by Spawner.spawn. */
export interface SpawnHandle {
  pid: number;
  kill(signal?: NodeJS.Signals | number): boolean;
  /** Resolves with the process exit code. */
  waitForExit(): Promise<number>;
}

/** Polls until the firecracker API socket appears (or times out). */
export interface SocketPoller {
  waitForSocket(socketPath: string, timeoutMs: number): Promise<void>;
}

export interface LaunchInput {
  firecrackerPath: string;
  vmlinuxPath: string;
  /** Overlay'd rootfs ext4 path. */
  rootfsPath: string;
  /** Optional second disk (repo). If provided, added as drive id "repo". */
  repoDiskPath?: string | undefined;
  vcpu?: number | undefined;       // default 2
  memMB?: number | undefined;      // default 2048
  /** Guest CID for vsock (must be > 2; host CID is 2). */
  vsockCid: number;
  /** Host-side vsock Unix socket path (Firecracker pattern: <udsPath>_<port>). */
  vsockUdsPath: string;
  /**
   * Phase A: enable tap networking.
   * Phase B: false (network isolated).
   */
  enableNetwork: boolean;
  /** Path for the Firecracker API socket. Created by firecracker at boot. */
  socketPath: string;
  /**
   * Kernel command line.  Defaults include console=ttyS0 reboot=k panic=1
   * pci=off plus the overlay=nojournal hint.
   */
  bootArgs?: string | undefined;
  // -------------------------------------------------------------------------
  // Injection points for tests
  // -------------------------------------------------------------------------
  /** Override the API client (default: production Unix-socket client). */
  apiClient?: FirecrackerApiClient | undefined;
  /** Override the process spawner (default: production node:child_process). */
  spawner?: Spawner | undefined;
  /** Override the socket poller (default: filesystem poll). */
  poller?: SocketPoller | undefined;
}

export interface VmHandle {
  pid: number;
  apiClient: FirecrackerApiClient;
  kill(): Promise<void>;
  waitForExit(): Promise<number>;
}

// ---------------------------------------------------------------------------
// Default boot args
// ---------------------------------------------------------------------------

const DEFAULT_BOOT_ARGS =
  'console=ttyS0 reboot=k panic=1 pci=off ' +
  'ro rootfstype=ext4 init=/sbin/init';

// ---------------------------------------------------------------------------
// launchVm
// ---------------------------------------------------------------------------

/**
 * Boots a Firecracker microVM and returns a handle.
 *
 * Throws immediately if:
 *   - Running on macOS (Firecracker is Linux-only).
 *   - /dev/kvm is absent (VM acceleration not available).
 *
 * These checks are skipped when `input.spawner` is injected (test mode).
 */
export async function launchVm(input: LaunchInput): Promise<VmHandle> {
  const {
    firecrackerPath,
    vmlinuxPath,
    rootfsPath,
    repoDiskPath,
    vcpu = 2,
    memMB = 2048,
    vsockCid,
    vsockUdsPath,
    enableNetwork,
    socketPath,
    bootArgs = DEFAULT_BOOT_ARGS,
  } = input;

  // Platform guard — only skip when a fake spawner is injected.
  if (!input.spawner) {
    if (platform !== 'linux') {
      throw new Error(
        `npm-jar: Firecracker requires Linux. Current platform: ${platform}. ` +
        `Run this action in a Linux environment or inject a test spawner.`,
      );
    }
    if (!existsSync('/dev/kvm')) {
      throw new Error(
        'npm-jar: /dev/kvm not found. Firecracker requires KVM. ' +
        'Ensure the runner has hardware virtualisation enabled.',
      );
    }
  }

  const spawner: Spawner = input.spawner ?? new NodeSpawner();
  const poller: SocketPoller = input.poller ?? new FsSocketPoller();
  const apiClient: FirecrackerApiClient =
    input.apiClient ?? new UnixSocketApiClient(socketPath);

  // 1. Spawn the firecracker subprocess.
  const handle = spawner.spawn(
    firecrackerPath,
    ['--api-sock', socketPath],
    { stdio: 'ignore' },
  );

  // 2. Wait for the API socket to be ready.
  try {
    await poller.waitForSocket(socketPath, 5_000);
  } catch (err) {
    handle.kill('SIGKILL');
    throw new Error(
      `npm-jar: firecracker API socket did not appear at ${socketPath} within 5 s. ` +
      `Inner error: ${String(err)}`,
    );
  }

  // Steps 3–8: configure and start the VM.  If anything fails after the
  // process is alive we MUST kill it — otherwise we leak a zombie Firecracker
  // process with no way for the caller to clean it up (they have no VmHandle).
  try {
    // 3. PUT /boot-source
    await apiClient.put('/boot-source', {
      kernel_image_path: vmlinuxPath,
      boot_args: bootArgs,
    });

    // 4. PUT /drives/rootfs
    await apiClient.put('/drives/rootfs', {
      drive_id: 'rootfs',
      path_on_host: rootfsPath,
      is_root_device: true,
      is_read_only: false,
    });

    // 4b. Optional repo disk.
    if (repoDiskPath !== undefined) {
      await apiClient.put('/drives/repo', {
        drive_id: 'repo',
        path_on_host: repoDiskPath,
        is_root_device: false,
        is_read_only: true,
      });
    }

    // 5. PUT /machine-config
    await apiClient.put('/machine-config', {
      vcpu_count: vcpu,
      mem_size_mib: memMB,
    });

    // 6. Optional network (Phase A only).
    if (enableNetwork) {
      await setupTapDevice(apiClient);
    }

    // 7. PUT /vsock
    await apiClient.put('/vsock', {
      guest_cid: vsockCid,
      uds_path: vsockUdsPath,
    });

    // 8. PUT /actions — start the VM.
    await apiClient.put('/actions', {
      action_type: 'InstanceStart',
    });
  } catch (err) {
    // Clean up the spawned process before re-throwing so callers don't need
    // to handle a partial-init state.
    handle.kill('SIGKILL');
    // Remove the API socket if it exists (Firecracker creates it at startup).
    try {
      await unlink(socketPath);
    } catch { /* ignore — socket may not exist */ }
    throw err;
  }

  return {
    pid: handle.pid,
    apiClient,
    kill: async (): Promise<void> => {
      handle.kill('SIGKILL');
    },
    waitForExit: (): Promise<number> => handle.waitForExit(),
  };
}

// ---------------------------------------------------------------------------
// Network setup helper
// ---------------------------------------------------------------------------

/**
 * Creates a tap0 device on the host and registers it with Firecracker.
 *
 * Requires root (or CAP_NET_ADMIN).  Logs a warning and skips if the
 * `ip` command is not found or returns a non-zero exit code.
 *
 * TODO(v2): Dynamically allocate tap device names to support multiple
 * concurrent VMs on the same host.
 */
async function setupTapDevice(api: FirecrackerApiClient): Promise<void> {
  // Attempt to create the tap device.  Failures are non-fatal — the VM
  // starts without a network interface, which is acceptable during tests.
  const mkTap = spawnSync('ip', ['tuntap', 'add', 'tap0', 'mode', 'tap'], {
    stdio: 'ignore',
  });

  if (mkTap.status !== 0) {
    console.warn(
      '[launch] tap device setup failed (ip tuntap add). ' +
      'Network will not be available inside the VM. ' +
      'Run as root or with CAP_NET_ADMIN to enable networking.',
    );
    return;
  }

  spawnSync('ip', ['link', 'set', 'tap0', 'up'], { stdio: 'ignore' });

  await api.put('/network-interfaces/eth0', {
    iface_id: 'eth0',
    guest_mac: '06:00:AC:10:00:02',
    host_dev_name: 'tap0',
  });
}

// ---------------------------------------------------------------------------
// Production Spawner
// ---------------------------------------------------------------------------

class NodeSpawner implements Spawner {
  spawn(
    cmd: string,
    args: ReadonlyArray<string>,
    opts: { stdio: 'ignore' },
  ): SpawnHandle {
    const child = nodeSpawn(cmd, [...args], {
      stdio: opts.stdio,
      detached: false,
    });

    let exitCode: number | undefined;
    const exitPromise = new Promise<number>((resolve) => {
      child.on('close', (code) => {
        exitCode = code ?? 1;
        resolve(exitCode);
      });
      child.on('error', () => {
        exitCode = 1;
        resolve(1);
      });
    });

    return {
      pid: child.pid ?? -1,
      kill: (signal?: NodeJS.Signals | number): boolean => {
        return child.kill(signal);
      },
      waitForExit: () => exitPromise,
    };
  }
}

// ---------------------------------------------------------------------------
// Production SocketPoller
// ---------------------------------------------------------------------------

class FsSocketPoller implements SocketPoller {
  async waitForSocket(socketPath: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (existsSync(socketPath)) return;
      await sleep(50);
    }
    throw new Error(`Timeout waiting for socket: ${socketPath}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Production FirecrackerApiClient (Unix socket HTTP)
// ---------------------------------------------------------------------------

/**
 * Sends HTTP requests to the Firecracker REST API over a Unix domain socket.
 *
 * Firecracker's API server speaks plain HTTP/1.1 over a UDS, so we use
 * `node:http.request` with `socketPath`.
 */
export class UnixSocketApiClient implements FirecrackerApiClient {
  constructor(private readonly socketPath: string) {}

  async put(path: string, body: unknown): Promise<void> {
    return this._request('PUT', path, body);
  }

  async patch(path: string, body: unknown): Promise<void> {
    return this._request('PATCH', path, body);
  }

  private _request(method: string, path: string, body: unknown): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const payload = JSON.stringify(body);

      const req = httpRequest(
        {
          socketPath: this.socketPath,
          path,
          method,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
        },
        (res) => {
          // Drain the response body.
          res.resume();
          res.on('end', () => {
            if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode >= 300) {
              reject(
                new Error(
                  `Firecracker API ${method} ${path} returned HTTP ${res.statusCode ?? '?'}`,
                ),
              );
            } else {
              resolve();
            }
          });
        },
      );

      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }
}

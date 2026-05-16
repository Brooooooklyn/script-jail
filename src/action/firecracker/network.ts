// npm-jar — src/action/firecracker/network.ts
//
// Runtime network control for a launched Firecracker microVM.
//
// Firecracker exposes no API for removing a network interface after boot, but
// `PATCH /network-interfaces/<iface_id>` accepts updated rate-limiter buckets.
// A token bucket with `size: 0` and any non-zero `refill_time` never
// accumulates capacity, so no bytes can flow in either direction.
//
// We use this to drop Phase A networking immediately after the guest's
// `fetch_done` handshake.  By the time the host releases the guest with `go`,
// the in-VM `connect()` syscalls used by malicious postinstall scripts have
// already lost their path to the world.

import type { FirecrackerApiClient } from './launch.js';

/**
 * Disable network on the named interface by zeroing both rate-limiter
 * buckets.  After this call no bytes flow in either direction.
 *
 * Idempotent: re-calling is a no-op (Firecracker accepts identical patches).
 */
export async function disableNetwork(
  api: FirecrackerApiClient,
  ifaceId: string = 'eth0',
): Promise<void> {
  const body = {
    iface_id: ifaceId,
    rx_rate_limiter: { bandwidth: { size: 0, refill_time: 1 } },
    tx_rate_limiter: { bandwidth: { size: 0, refill_time: 1 } },
  };
  await api.patch(`/network-interfaces/${ifaceId}`, body);
}

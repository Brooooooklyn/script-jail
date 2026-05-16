// npm-jar — test/action/firecracker/network.test.ts
//
// Unit tests for disableNetwork().  We inject a fake FirecrackerApiClient
// that records every PUT/PATCH call so we can assert exact contract shape.

import { describe, it, expect } from 'vitest';
import type { FirecrackerApiClient } from '../../../src/action/firecracker/launch.js';
import { disableNetwork } from '../../../src/action/firecracker/network.js';

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

describe('disableNetwork', () => {
  it('PATCHes /network-interfaces/eth0 by default', async () => {
    const { client, calls } = makeFakeApiClient();

    await disableNetwork(client);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe('PATCH');
    expect(calls[0]!.path).toBe('/network-interfaces/eth0');
  });

  it('uses zero-bucket rate-limiters for both directions', async () => {
    const { client, calls } = makeFakeApiClient();

    await disableNetwork(client);

    const body = calls[0]!.body as Record<string, unknown>;
    expect(body['iface_id']).toBe('eth0');
    expect(body['rx_rate_limiter']).toEqual({
      bandwidth: { size: 0, refill_time: 1 },
    });
    expect(body['tx_rate_limiter']).toEqual({
      bandwidth: { size: 0, refill_time: 1 },
    });
  });

  it('honours a custom interface id', async () => {
    const { client, calls } = makeFakeApiClient();

    await disableNetwork(client, 'eth1');

    expect(calls[0]!.path).toBe('/network-interfaces/eth1');
    expect((calls[0]!.body as Record<string, unknown>)['iface_id']).toBe('eth1');
  });

  it('is idempotent — re-calling sends identical patches', async () => {
    const { client, calls } = makeFakeApiClient();

    await disableNetwork(client);
    await disableNetwork(client);

    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(calls[1]);
  });

  it('propagates API errors to the caller', async () => {
    const failing: FirecrackerApiClient = {
      async put() { /* unused */ },
      async patch() { throw new Error('boom'); },
    };

    await expect(disableNetwork(failing)).rejects.toThrow('boom');
  });
});

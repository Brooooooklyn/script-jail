// npm-jar — test/action/host-node-prefix.test.ts
//
// Unit tests for resolveHostNodePrefix().  The helper derives the Node
// installation prefix from `process.execPath` and validates that the prefix
// looks like a self-contained Node tree.  Tests inject a fake filesystem
// stub to avoid relying on the host's actual layout.

import { describe, it, expect } from 'vitest';
import { resolveHostNodePrefix } from '../../src/action/host-node-prefix.js';

function makeFs(existing: ReadonlyArray<string>): { existsSync(p: string): boolean } {
  const set = new Set(existing);
  return { existsSync: (p) => set.has(p) };
}

describe('resolveHostNodePrefix', () => {
  it('returns two-dirname-up from a hostedtoolcache execPath', () => {
    const execPath = '/opt/hostedtoolcache/node/20.11.0/x64/bin/node';
    // For hostedtoolcache, the path prefix alone is enough — no marker file
    // required.
    const fs = makeFs([execPath]);
    expect(resolveHostNodePrefix(execPath, fs)).toBe(
      '/opt/hostedtoolcache/node/20.11.0/x64',
    );
  });

  it('accepts a prefix that contains include/node/node.h', () => {
    const execPath = '/usr/local/bin/node';
    const fs = makeFs([execPath, '/usr/local/include/node/node.h']);
    expect(resolveHostNodePrefix(execPath, fs)).toBe('/usr/local');
  });

  it('accepts a prefix that contains share/doc/node', () => {
    const execPath = '/opt/node/bin/node';
    const fs = makeFs([execPath, '/opt/node/share/doc/node']);
    expect(resolveHostNodePrefix(execPath, fs)).toBe('/opt/node');
  });

  it('throws when execPath has no node marker and is not under hostedtoolcache', () => {
    const execPath = '/usr/local/bin/node';
    const fs = makeFs([execPath]); // no include/node/node.h, no share/doc/node
    expect(() => resolveHostNodePrefix(execPath, fs)).toThrow(
      /does not appear to be a self-contained Node install/,
    );
    expect(() => resolveHostNodePrefix(execPath, fs)).toThrow(
      /actions\/setup-node/,
    );
  });

  it('includes the execPath in the error message for debuggability', () => {
    const execPath = '/usr/bin/node';
    const fs = makeFs([execPath]);
    expect(() => resolveHostNodePrefix(execPath, fs)).toThrow(/\/usr\/bin\/node/);
  });

  it('also accepts a hostedtoolcache path on a different architecture', () => {
    const execPath = '/opt/hostedtoolcache/node/22.4.0/arm64/bin/node';
    const fs = makeFs([execPath]);
    expect(resolveHostNodePrefix(execPath, fs)).toBe(
      '/opt/hostedtoolcache/node/22.4.0/arm64',
    );
  });
});

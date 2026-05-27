// script-jail — test/cli/arch-flags.test.ts
//
// Tests for src/cli/arch-flags.ts.  Pure function; no IO; trivial setup.

import { describe, it, expect } from 'vitest';

import { buildArchFlagOverlay } from '../../src/cli/arch-flags.js';

describe('buildArchFlagOverlay', () => {
  it.each([
    ['npm', 'x64'],
    ['pnpm', 'x64'],
    ['yarn', 'x64'],
    ['yarn-classic', 'x64'],
    ['npm', 'arm64'],
    ['pnpm', 'arm64'],
    ['yarn', 'arm64'],
    ['yarn-classic', 'arm64'],
  ] as const)('returns empty overlay for %s on %s', (pm, hostArch) => {
    const overlay = buildArchFlagOverlay({ pm, hostArch });
    expect(overlay).toEqual({ warnings: [] });
  });

  it('does not force x64 when the spoof target is non-canonical', () => {
    const overlay = buildArchFlagOverlay({
      pm: 'pnpm',
      hostArch: 'arm64',
      spoofPlatform: 'linux',
      spoofArch: 'x64',
    });

    expect(overlay).toEqual({ warnings: [] });
  });
});

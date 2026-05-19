// script-jail — test/cli/arch-flags.test.ts
//
// Tests for src/cli/arch-flags.ts.  Pure function; no IO; trivial setup.

import { describe, it, expect } from 'vitest';
import { parse as parseYaml } from 'yaml';

import { buildArchFlagOverlay } from '../../src/cli/arch-flags.js';

describe('buildArchFlagOverlay — x64 host', () => {
  it.each(['npm', 'pnpm', 'yarn', 'yarn-classic'] as const)(
    'returns empty overlay for %s on x64',
    (pm) => {
      const overlay = buildArchFlagOverlay({ pm, hostArch: 'x64' });
      expect(overlay).toEqual({ warnings: [] });
    },
  );
});

describe('buildArchFlagOverlay — arm64 host', () => {
  it('npm: pmFlagsJson with --cpu/--os/--libc flags, no yarnrcOverlay', () => {
    const overlay = buildArchFlagOverlay({ pm: 'npm', hostArch: 'arm64' });
    expect(overlay.pmFlagsJson).toEqual({
      extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'],
    });
    expect(overlay.yarnrcOverlay).toBeUndefined();
    expect(overlay.warnings).toEqual([]);
  });

  it('pnpm: pmFlagsJson with --cpu/--os/--libc flags, no yarnrcOverlay', () => {
    const overlay = buildArchFlagOverlay({ pm: 'pnpm', hostArch: 'arm64' });
    expect(overlay.pmFlagsJson).toEqual({
      extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'],
    });
    expect(overlay.yarnrcOverlay).toBeUndefined();
    expect(overlay.warnings).toEqual([]);
  });

  it('yarn (berry): yarnrcOverlay parses to the expected YAML shape', () => {
    const overlay = buildArchFlagOverlay({ pm: 'yarn', hostArch: 'arm64' });
    expect(overlay.pmFlagsJson).toBeUndefined();
    expect(overlay.warnings).toEqual([]);
    expect(typeof overlay.yarnrcOverlay).toBe('string');
    const parsed = parseYaml(overlay.yarnrcOverlay ?? '') as Record<string, unknown>;
    expect(parsed).toEqual({
      supportedArchitectures: {
        os: ['linux'],
        cpu: ['x64'],
        libc: ['glibc'],
      },
    });
  });

  it('yarn (berry): yarnrcOverlay byte-equals the pinned snapshot', () => {
    const overlay = buildArchFlagOverlay({ pm: 'yarn', hostArch: 'arm64' });
    // Pinned exactly to lock byte stability — the YAML library could change
    // its emitted form between minor versions and we don't want the audit's
    // .yarnrc.yml to drift silently across releases.
    expect(overlay.yarnrcOverlay).toBe(
      'supportedArchitectures:\n' +
      '  os:\n' +
      '    - linux\n' +
      '  cpu:\n' +
      '    - x64\n' +
      '  libc:\n' +
      '    - glibc\n',
    );
  });

  it('yarn-classic: empty overlay + 1 warning about v1 limitations', () => {
    const overlay = buildArchFlagOverlay({ pm: 'yarn-classic', hostArch: 'arm64' });
    expect(overlay.pmFlagsJson).toBeUndefined();
    expect(overlay.yarnrcOverlay).toBeUndefined();
    expect(overlay.warnings).toHaveLength(1);
    expect(overlay.warnings[0]).toMatch(/yarn classic|v1/);
    expect(overlay.warnings[0]).toMatch(/arm64/);
  });
});

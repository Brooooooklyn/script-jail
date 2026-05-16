// npm-jar — test/rootfs/build-config.test.ts
// Unit tests for the pure-function helpers in src/rootfs/build.ts.
// These tests do NOT invoke docker, mkfs.ext4, or any filesystem mutation;
// they only verify input-shape parsing and output-path computation.
//
// End-to-end rootfs build verification (docker build + ext4 conversion) happens
// in CI via `pnpm build` against a Docker-enabled Linux runner.

import { describe, it, expect } from 'vitest';
import {
  imageFilename,
  imageOutputPath,
  dockerTag,
  formatBytes,
  SIZE_WARN_THRESHOLD_BYTES,
} from '../../src/rootfs/build.js';
import type { BuildInput } from '../../src/rootfs/build.js';

// ---------------------------------------------------------------------------
// imageFilename
// ---------------------------------------------------------------------------

describe('imageFilename', () => {
  it('produces the expected filename for node20/pnpm', () => {
    expect(imageFilename({ nodeMajor: 20, pm: 'pnpm' })).toBe('rootfs-node20-pnpm.ext4');
  });

  it('produces the expected filename for node22/yarn', () => {
    expect(imageFilename({ nodeMajor: 22, pm: 'yarn' })).toBe('rootfs-node22-yarn.ext4');
  });

  it('produces the expected filename for node18/npm', () => {
    expect(imageFilename({ nodeMajor: 18, pm: 'npm' })).toBe('rootfs-node18-npm.ext4');
  });

  it('includes the nodeMajor as a number (no decimals)', () => {
    const name = imageFilename({ nodeMajor: 20, pm: 'npm' });
    expect(name).toMatch(/^rootfs-node\d+-npm\.ext4$/);
  });
});

// ---------------------------------------------------------------------------
// imageOutputPath
// ---------------------------------------------------------------------------

describe('imageOutputPath', () => {
  it('joins outputDir with imageFilename', () => {
    const input: BuildInput = { nodeMajor: 20, pm: 'pnpm', outputDir: '/some/dir' };
    expect(imageOutputPath(input)).toBe('/some/dir/rootfs-node20-pnpm.ext4');
  });

  it('handles outputDir with trailing slash gracefully', () => {
    // path.join normalises trailing slashes
    const input: BuildInput = { nodeMajor: 20, pm: 'npm', outputDir: '/out/' };
    // path.join('/out/', 'rootfs-node20-npm.ext4') === '/out/rootfs-node20-npm.ext4'
    expect(imageOutputPath(input)).toMatch(/rootfs-node20-npm\.ext4$/);
  });

  it('is an absolute path when outputDir is absolute', () => {
    const input: BuildInput = { nodeMajor: 22, pm: 'yarn', outputDir: '/images' };
    expect(imageOutputPath(input)).toMatch(/^\//);
  });
});

// ---------------------------------------------------------------------------
// dockerTag
// ---------------------------------------------------------------------------

describe('dockerTag', () => {
  it('formats the tag as npm-jar-rootfs:<nodeMajor>-<pm>', () => {
    expect(dockerTag({ nodeMajor: 20, pm: 'pnpm' })).toBe('npm-jar-rootfs:20-pnpm');
  });

  it('includes the full node major version', () => {
    expect(dockerTag({ nodeMajor: 22, pm: 'yarn' })).toBe('npm-jar-rootfs:22-yarn');
  });

  it('works for npm pm', () => {
    expect(dockerTag({ nodeMajor: 18, pm: 'npm' })).toBe('npm-jar-rootfs:18-npm');
  });

  it('does not include a colon within the tag portion', () => {
    const tag = dockerTag({ nodeMajor: 20, pm: 'pnpm' });
    // Should have exactly one colon (separating name from tag)
    expect(tag.split(':').length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// formatBytes
// ---------------------------------------------------------------------------

describe('formatBytes', () => {
  it('formats values under 1 GB as MB', () => {
    expect(formatBytes(100 * 1024 * 1024)).toBe('100.0 MB');
  });

  it('formats values at exactly 1 GB as GB', () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.0 GB');
  });

  it('formats 150 MB correctly', () => {
    expect(formatBytes(150 * 1024 * 1024)).toBe('150.0 MB');
  });

  it('formats 1.5 GB correctly', () => {
    expect(formatBytes(1.5 * 1024 * 1024 * 1024)).toBe('1.5 GB');
  });

  it('formats small values (< 1 MB) as MB with decimals', () => {
    // 512 KB = 0.5 MB
    expect(formatBytes(512 * 1024)).toBe('0.5 MB');
  });
});

// ---------------------------------------------------------------------------
// SIZE_WARN_THRESHOLD_BYTES
// ---------------------------------------------------------------------------

describe('SIZE_WARN_THRESHOLD_BYTES', () => {
  it('is exactly 200 MB', () => {
    expect(SIZE_WARN_THRESHOLD_BYTES).toBe(200 * 1024 * 1024);
  });

  it('a 150 MB image should be below the threshold', () => {
    expect(150 * 1024 * 1024).toBeLessThan(SIZE_WARN_THRESHOLD_BYTES);
  });

  it('a 201 MB image should exceed the threshold', () => {
    expect(201 * 1024 * 1024).toBeGreaterThan(SIZE_WARN_THRESHOLD_BYTES);
  });
});

// ---------------------------------------------------------------------------
// BuildInput shape validation (type-level; runtime sanity checks)
// ---------------------------------------------------------------------------

describe('BuildInput shape', () => {
  it('accepts all three pm values', () => {
    const pms: Array<BuildInput['pm']> = ['npm', 'pnpm', 'yarn'];
    for (const pm of pms) {
      const input: BuildInput = { nodeMajor: 20, pm, outputDir: '/images' };
      // imageFilename must produce a non-empty string for each pm
      expect(imageFilename(input)).toBeTruthy();
    }
  });

  it('accepts different node major versions', () => {
    const versions = [18, 20, 22, 24];
    for (const nodeMajor of versions) {
      const input: BuildInput = { nodeMajor, pm: 'pnpm', outputDir: '/images' };
      expect(imageFilename(input)).toContain(String(nodeMajor));
    }
  });
});

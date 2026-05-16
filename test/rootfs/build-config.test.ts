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
  ubuntuBaseTag,
  ubuntuMajor,
  parseRunnerImageArg,
  formatBytes,
  SIZE_WARN_THRESHOLD_BYTES,
} from '../../src/rootfs/build.js';
import type { BuildInput, RunnerImage } from '../../src/rootfs/build.js';

// ---------------------------------------------------------------------------
// imageFilename
// ---------------------------------------------------------------------------

describe('imageFilename', () => {
  it('produces the expected filename for ubuntu-22.04', () => {
    expect(imageFilename({ runnerImage: 'ubuntu-22.04' })).toBe(
      'rootfs-ubuntu-22.04.ext4',
    );
  });

  it('produces the expected filename for ubuntu-24.04', () => {
    expect(imageFilename({ runnerImage: 'ubuntu-24.04' })).toBe(
      'rootfs-ubuntu-24.04.ext4',
    );
  });

  it('matches the `rootfs-<runner-image>.ext4` shape main.ts expects', () => {
    // main.ts builds the rootfs path as `rootfs-${runnerImage}.ext4`; this
    // test fails loudly if the shape ever drifts between the two files.
    const images: ReadonlyArray<RunnerImage> = ['ubuntu-22.04', 'ubuntu-24.04'];
    for (const runnerImage of images) {
      expect(imageFilename({ runnerImage })).toBe(`rootfs-${runnerImage}.ext4`);
    }
  });
});

// ---------------------------------------------------------------------------
// imageOutputPath
// ---------------------------------------------------------------------------

describe('imageOutputPath', () => {
  it('joins outputDir with imageFilename', () => {
    const input: BuildInput = { runnerImage: 'ubuntu-24.04', outputDir: '/some/dir' };
    expect(imageOutputPath(input)).toBe('/some/dir/rootfs-ubuntu-24.04.ext4');
  });

  it('handles outputDir with trailing slash gracefully', () => {
    // path.join normalises trailing slashes
    const input: BuildInput = { runnerImage: 'ubuntu-22.04', outputDir: '/out/' };
    expect(imageOutputPath(input)).toMatch(/rootfs-ubuntu-22\.04\.ext4$/);
  });

  it('is an absolute path when outputDir is absolute', () => {
    const input: BuildInput = { runnerImage: 'ubuntu-24.04', outputDir: '/images' };
    expect(imageOutputPath(input)).toMatch(/^\//);
  });
});

// ---------------------------------------------------------------------------
// dockerTag
// ---------------------------------------------------------------------------

describe('dockerTag', () => {
  it('formats the tag as npm-jar-rootfs:<runner-image>', () => {
    expect(dockerTag({ runnerImage: 'ubuntu-22.04' })).toBe(
      'npm-jar-rootfs:ubuntu-22.04',
    );
  });

  it('produces a distinct tag for ubuntu-24.04', () => {
    expect(dockerTag({ runnerImage: 'ubuntu-24.04' })).toBe(
      'npm-jar-rootfs:ubuntu-24.04',
    );
  });

  it('has exactly one colon separating name from tag', () => {
    // The runner-image portion (ubuntu-22.04) contains a dot but no colon —
    // the docker tag spec allows dots but treats colons as separators, so the
    // colon-count must remain at 1.
    const tag = dockerTag({ runnerImage: 'ubuntu-22.04' });
    expect(tag.split(':').length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// ubuntuBaseTag / ubuntuMajor
// ---------------------------------------------------------------------------

describe('ubuntuBaseTag', () => {
  it('maps ubuntu-22.04 to ubuntu:22.04', () => {
    expect(ubuntuBaseTag({ runnerImage: 'ubuntu-22.04' })).toBe('ubuntu:22.04');
  });

  it('maps ubuntu-24.04 to ubuntu:24.04', () => {
    expect(ubuntuBaseTag({ runnerImage: 'ubuntu-24.04' })).toBe('ubuntu:24.04');
  });
});

describe('ubuntuMajor', () => {
  it('returns 22.04 for ubuntu-22.04', () => {
    expect(ubuntuMajor({ runnerImage: 'ubuntu-22.04' })).toBe('22.04');
  });

  it('returns 24.04 for ubuntu-24.04', () => {
    expect(ubuntuMajor({ runnerImage: 'ubuntu-24.04' })).toBe('24.04');
  });
});

// ---------------------------------------------------------------------------
// parseRunnerImageArg
// ---------------------------------------------------------------------------

describe('parseRunnerImageArg', () => {
  it('returns undefined when the flag is absent', () => {
    expect(parseRunnerImageArg([])).toBeUndefined();
    expect(parseRunnerImageArg(['--skip-rootfs'])).toBeUndefined();
  });

  it('parses --runner-image=ubuntu-22.04', () => {
    expect(parseRunnerImageArg(['--runner-image=ubuntu-22.04'])).toBe('ubuntu-22.04');
  });

  it('parses --runner-image=ubuntu-24.04', () => {
    expect(parseRunnerImageArg(['--runner-image=ubuntu-24.04'])).toBe('ubuntu-24.04');
  });

  it('throws on an unknown value rather than silently defaulting', () => {
    expect(() => parseRunnerImageArg(['--runner-image=debian-12'])).toThrow(
      /Unknown --runner-image/,
    );
  });

  it('returns the FIRST recognised value when the flag is repeated', () => {
    // We don't formally specify first-wins, but exercising the loop with a
    // repeated flag locks in the current behaviour and surfaces a regression
    // if the parser is ever refactored (the loop returns on the first hit).
    expect(
      parseRunnerImageArg([
        '--runner-image=ubuntu-22.04',
        '--runner-image=ubuntu-24.04',
      ]),
    ).toBe('ubuntu-22.04');
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
// BuildInput shape (type-level; runtime sanity over the two known images)
// ---------------------------------------------------------------------------

describe('BuildInput shape', () => {
  it('accepts each supported runner image', () => {
    const images: ReadonlyArray<RunnerImage> = ['ubuntu-22.04', 'ubuntu-24.04'];
    for (const runnerImage of images) {
      const input: BuildInput = { runnerImage, outputDir: '/images' };
      // imageFilename must produce a non-empty string for each image
      expect(imageFilename(input)).toBeTruthy();
      // and the filename includes the runner image verbatim
      expect(imageFilename(input)).toContain(runnerImage);
    }
  });
});

// script-jail — test/rootfs/build-config.test.ts
// Unit tests for the pure-function helpers in src/rootfs/build.ts.
// These tests do NOT invoke docker, mkfs.ext4, or any filesystem mutation;
// they only verify input-shape parsing and output-path computation.
//
// End-to-end rootfs build verification (docker build + ext4 conversion) happens
// in CI via `pnpm build` against a Docker-enabled Linux runner.

import { existsSync } from 'node:fs';
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
  ROOTFS_FIXED_UUID,
  ROOTFS_SOURCE_DATE_EPOCH,
  ROOTFS_SIZE_MB,
  ROOTFS_MKE2FS_CONFIG_PATH,
  ALPINE_HELPER_REF,
  UBUNTU_BASE_DIGEST,
  buildMkfsExt4Args,
  mkfsEnv,
  buildNormalizeMtimesArgv,
  buildMkfsExt4ViaDockerScript,
  buildDockerBuildArgs,
  buildDebugfsSuperblockTimeCommands,
  buildDebugfsInodeTimeCommands,
  buildDebugfsTimeScript,
  EXPORT_TREE_VOLATILE_CONTENT,
  singleQuoteForSh,
} from '../../src/rootfs/build.js';
import { spawnSync } from 'node:child_process';
import type { BuildInput, RunnerImage, BuildArch } from '../../src/rootfs/build.js';

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
  it('formats the tag as script-jail-rootfs:<runner-image>', () => {
    expect(dockerTag({ runnerImage: 'ubuntu-22.04' })).toBe(
      'script-jail-rootfs:ubuntu-22.04',
    );
  });

  it('produces a distinct tag for ubuntu-24.04', () => {
    expect(dockerTag({ runnerImage: 'ubuntu-24.04' })).toBe(
      'script-jail-rootfs:ubuntu-24.04',
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

// ---------------------------------------------------------------------------
// Reproducible-rootfs constants (R1: byte-stable ext4)
// ---------------------------------------------------------------------------

describe('ROOTFS_FIXED_UUID', () => {
  it('matches the canonical 8-4-4-4-12 UUID shape', () => {
    expect(ROOTFS_FIXED_UUID).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('is the pinned value (changing it rebakes every released SHA)', () => {
    expect(ROOTFS_FIXED_UUID).toBe('5343524a-2d6a-6169-6c2d-726f6f746673');
  });
});

describe('ROOTFS_SOURCE_DATE_EPOCH', () => {
  it('is a stable positive integer', () => {
    expect(Number.isInteger(ROOTFS_SOURCE_DATE_EPOCH)).toBe(true);
    expect(ROOTFS_SOURCE_DATE_EPOCH).toBeGreaterThan(0);
  });

  it('is the pinned value', () => {
    expect(ROOTFS_SOURCE_DATE_EPOCH).toBe(1700000000);
  });
});

// ---------------------------------------------------------------------------
// buildMkfsExt4Args
// ---------------------------------------------------------------------------

describe('buildMkfsExt4Args', () => {
  const args = buildMkfsExt4Args('/export/dir', '/out/rootfs.ext4', 1024);

  it('places -U immediately before the fixed UUID', () => {
    const i = args.indexOf('-U');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe(ROOTFS_FIXED_UUID);
  });

  it('places -E immediately before hash_seed=<UUID>', () => {
    const i = args.indexOf('-E');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe(`hash_seed=${ROOTFS_FIXED_UUID}`);
  });

  it('preserves -d <exportDir>', () => {
    const i = args.indexOf('-d');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe('/export/dir');
  });

  it('preserves -L rootfs', () => {
    const i = args.indexOf('-L');
    expect(args[i + 1]).toBe('rootfs');
  });

  it('disables both has_journal AND metadata_csum_seed via -O', () => {
    // metadata_csum_seed must be disabled so the metadata-checksum seed derives
    // from the pinned -U UUID instead of an independent random seed (the classic
    // remaining ext4 nondeterminism, R1).
    const i = args.indexOf('-O');
    expect(i).toBeGreaterThanOrEqual(0);
    const value = args[i + 1]!;
    expect(value).toContain('^has_journal');
    expect(value).toContain('^metadata_csum_seed');
  });

  it('pins the block size to 4096 (-b 4096)', () => {
    const i = args.indexOf('-b');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe('4096');
  });

  it('pins the inode size to 256 (-I 256)', () => {
    const i = args.indexOf('-I');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe('256');
  });

  it('pins the inode count via -i 16384 (not left to size-class fs_type resolution)', () => {
    // inode_ratio resolved from the conf depends on a size-class [fs_types]
    // entry, which the checked-in mke2fs.conf omits — making the fallback
    // e2fsprogs-version-dependent.  Pinning -i on argv removes that drift
    // vector so a runner-image e2fsprogs bump cannot change the inode count
    // between the v0.1.0 and v0.1.1 builds (R1 cross-run reproducibility).
    const i = args.indexOf('-i');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(args[i + 1]).toBe('16384');
  });

  it('preserves -m 0', () => {
    const i = args.indexOf('-m');
    expect(args[i + 1]).toBe('0');
  });

  it('ends with <outImage> then <sizeMB>M positionals', () => {
    expect(args[args.length - 2]).toBe('/out/rootfs.ext4');
    expect(args[args.length - 1]).toBe('1024M');
  });

  it('uses the configured size by default in the native path', () => {
    const native = buildMkfsExt4Args('/x', '/y.ext4', ROOTFS_SIZE_MB);
    expect(native[native.length - 1]).toBe(`${ROOTFS_SIZE_MB}M`);
  });

  it('is pure — repeated calls deeply-equal', () => {
    expect(buildMkfsExt4Args('/export/dir', '/out/rootfs.ext4', 1024)).toEqual(args);
  });
});

// ---------------------------------------------------------------------------
// mkfsEnv
// ---------------------------------------------------------------------------

describe('mkfsEnv', () => {
  it('sets SOURCE_DATE_EPOCH to the pinned epoch as a string', () => {
    expect(mkfsEnv().SOURCE_DATE_EPOCH).toBe('1700000000');
  });

  it('points MKE2FS_CONFIG at the checked-in src/rootfs/mke2fs.conf', () => {
    expect(mkfsEnv().MKE2FS_CONFIG).toBe(ROOTFS_MKE2FS_CONFIG_PATH);
    // The path is absolute and ends with the checked-in conf (slash-normalised
    // so the assertion holds on both POSIX and Windows path separators).
    const normalised = mkfsEnv().MKE2FS_CONFIG.replace(/\\/g, '/');
    expect(normalised.endsWith('src/rootfs/mke2fs.conf')).toBe(true);
  });

  it('MKE2FS_CONFIG points at a file that actually exists', () => {
    expect(existsSync(mkfsEnv().MKE2FS_CONFIG)).toBe(true);
  });

  it('is pure — repeated calls deeply-equal', () => {
    expect(mkfsEnv()).toEqual(mkfsEnv());
  });
});

// ---------------------------------------------------------------------------
// buildNormalizeMtimesArgv
// ---------------------------------------------------------------------------

describe('buildNormalizeMtimesArgv', () => {
  const argv = buildNormalizeMtimesArgv('/tmp/x', 1700000000);

  it('runs find against the target dir', () => {
    expect(argv[0]).toBe('find');
    expect(argv).toContain('/tmp/x');
  });

  it('does not dereference symlinks', () => {
    expect(argv).toContain('--no-dereference');
  });

  it('pins the mtime to the epoch', () => {
    expect(argv).toContain('--date=@1700000000');
  });

  it('uses touch via -exec ... +', () => {
    expect(argv).toContain('-exec');
    expect(argv).toContain('touch');
    expect(argv[argv.length - 1]).toBe('+');
  });

  it('is pure — repeated calls deeply-equal', () => {
    expect(buildNormalizeMtimesArgv('/tmp/x', 1700000000)).toEqual(argv);
  });
});

// ---------------------------------------------------------------------------
// buildMkfsExt4ViaDockerScript (Alpine helper)
// ---------------------------------------------------------------------------

describe('buildMkfsExt4ViaDockerScript', () => {
  const script = buildMkfsExt4ViaDockerScript('rootfs.ext4', 1024);

  it('passes the same -U <UUID> flag as the native path', () => {
    expect(script).toContain(`-U ${ROOTFS_FIXED_UUID}`);
  });

  it('passes the same -E hash_seed=<UUID> flag as the native path', () => {
    expect(script).toContain(`-E hash_seed=${ROOTFS_FIXED_UUID}`);
  });

  it('exports SOURCE_DATE_EPOCH before invoking mkfs.ext4', () => {
    const epochIdx = script.indexOf(`SOURCE_DATE_EPOCH=${ROOTFS_SOURCE_DATE_EPOCH}`);
    const mkfsIdx = script.indexOf('mkfs.ext4');
    expect(epochIdx).toBeGreaterThanOrEqual(0);
    expect(mkfsIdx).toBeGreaterThanOrEqual(0);
    expect(epochIdx).toBeLessThan(mkfsIdx);
  });

  it('exports MKE2FS_CONFIG (the bind-mounted conf) before invoking mkfs.ext4', () => {
    // The Alpine path must pin the same feature set as the native path; the
    // conf is bind-mounted into the container and pointed at via MKE2FS_CONFIG.
    const cfgIdx = script.indexOf('export MKE2FS_CONFIG=');
    const mkfsIdx = script.indexOf('mkfs.ext4');
    expect(cfgIdx).toBeGreaterThanOrEqual(0);
    expect(mkfsIdx).toBeGreaterThanOrEqual(0);
    expect(cfgIdx).toBeLessThan(mkfsIdx);
  });

  it('disables metadata_csum_seed via the shared -O flag', () => {
    expect(script).toContain('^metadata_csum_seed');
  });

  it('normalizes mtimes (--no-dereference --date=@epoch) before mkfs', () => {
    const findIdx = script.indexOf('--no-dereference');
    const dateIdx = script.indexOf(`--date=@${ROOTFS_SOURCE_DATE_EPOCH}`);
    const mkfsIdx = script.indexOf('mkfs.ext4');
    expect(findIdx).toBeGreaterThanOrEqual(0);
    expect(dateIdx).toBeGreaterThanOrEqual(0);
    expect(findIdx).toBeLessThan(mkfsIdx);
    expect(dateIdx).toBeLessThan(mkfsIdx);
  });

  it('writes the requested image name and size', () => {
    expect(script).toContain('/out/rootfs.ext4');
    expect(script).toContain('1024M');
  });

  it('sanitizes build-time-volatile content before normalizing mtimes', () => {
    // The Alpine path must drop the Docker-injected /etc files + timestamped
    // logs BEFORE the normalize, mirroring sanitizeExportTree on the native
    // path.  Anchor on the hostname truncate and a log removal.
    const sanitizeIdx = script.indexOf(': > /rootfs/etc/hostname');
    const rmLogIdx = script.indexOf('rm -rf /rootfs/var/log/dpkg.log');
    const normalizeIdx = script.indexOf('--no-dereference');
    expect(sanitizeIdx).toBeGreaterThanOrEqual(0);
    expect(rmLogIdx).toBeGreaterThanOrEqual(0);
    expect(sanitizeIdx).toBeLessThan(normalizeIdx);
    expect(rmLogIdx).toBeLessThan(normalizeIdx);
  });

  it('runs a debugfs timestamp post-pass AFTER mkfs.ext4', () => {
    // The post-pass (workaround for e2fsprogs < 1.47.1 not honouring
    // SOURCE_DATE_EPOCH) must run after the filesystem exists.
    const mkfsIdx = script.indexOf('mkfs.ext4');
    const debugfsIdx = script.indexOf('debugfs -w -f');
    expect(mkfsIdx).toBeGreaterThanOrEqual(0);
    expect(debugfsIdx).toBeGreaterThanOrEqual(0);
    expect(mkfsIdx).toBeLessThan(debugfsIdx);
  });

  it('pins the superblock + per-inode times to the fixed epoch in the post-pass', () => {
    expect(script).toContain(`ssv mkfs_time @${ROOTFS_SOURCE_DATE_EPOCH}`);
    expect(script).toContain(`sif <%s> crtime @${ROOTFS_SOURCE_DATE_EPOCH}`);
    // Reads the inode count from dumpe2fs and loops over it.
    expect(script).toContain('dumpe2fs -h /out/rootfs.ext4');
    expect(script).toContain('Inode count:');
  });
});

// ---------------------------------------------------------------------------
// debugfs timestamp post-pass helpers (R1 — e2fsprogs < 1.47.1 workaround)
// ---------------------------------------------------------------------------

describe('buildDebugfsSuperblockTimeCommands', () => {
  const cmds = buildDebugfsSuperblockTimeCommands(1700000000);

  it('pins mkfs_time, lastcheck, and wtime to @epoch', () => {
    expect(cmds).toContain('ssv mkfs_time @1700000000');
    expect(cmds).toContain('ssv lastcheck @1700000000');
    expect(cmds).toContain('ssv wtime @1700000000');
  });

  it('emits wtime LAST so debugfs persists the pinned write time on close', () => {
    const lines = cmds.split('\n');
    expect(lines[lines.length - 1]).toBe('ssv wtime @1700000000');
  });

  it('is pure — repeated calls deeply-equal', () => {
    expect(buildDebugfsSuperblockTimeCommands(1700000000)).toEqual(cmds);
  });
});

describe('buildDebugfsInodeTimeCommands', () => {
  const cmds = buildDebugfsInodeTimeCommands(11, 1700000000);

  it('pins all four time fields of the inode to @epoch', () => {
    expect(cmds).toContain('sif <11> atime @1700000000');
    expect(cmds).toContain('sif <11> ctime @1700000000');
    expect(cmds).toContain('sif <11> mtime @1700000000');
    expect(cmds).toContain('sif <11> crtime @1700000000');
  });

  it('references the inode in the debugfs <N> form', () => {
    expect(cmds).toContain('<11>');
    expect(cmds).not.toContain('<11 ');
  });

  it('is pure — repeated calls deeply-equal', () => {
    expect(buildDebugfsInodeTimeCommands(11, 1700000000)).toEqual(cmds);
  });
});

describe('buildDebugfsTimeScript', () => {
  const script = buildDebugfsTimeScript(1700000000, 3);

  it('starts with the superblock commands', () => {
    expect(script.startsWith(buildDebugfsSuperblockTimeCommands(1700000000))).toBe(true);
  });

  it('includes one inode block per inode 1..inodeCount inclusive', () => {
    expect(script).toContain('sif <1> crtime @1700000000');
    expect(script).toContain('sif <2> crtime @1700000000');
    expect(script).toContain('sif <3> crtime @1700000000');
    // No inode beyond the count.
    expect(script).not.toContain('sif <4>');
    // Inode 0 is never a valid inode.
    expect(script).not.toContain('sif <0>');
  });

  it('ends with an explicit quit', () => {
    const lines = script.split('\n');
    expect(lines[lines.length - 1]).toBe('quit');
  });

  it('emits exactly superblock(3) + 4*count + quit lines', () => {
    const lines = buildDebugfsTimeScript(1700000000, 5).split('\n');
    expect(lines.length).toBe(3 + 4 * 5 + 1);
  });
});

// ---------------------------------------------------------------------------
// EXPORT_TREE_VOLATILE_CONTENT (R1 — drop build-time-volatile CONTENT)
// ---------------------------------------------------------------------------

describe('EXPORT_TREE_VOLATILE_CONTENT', () => {
  it('truncates the Docker-injected /etc files and machine-id', () => {
    expect(EXPORT_TREE_VOLATILE_CONTENT.truncate).toContain('etc/hostname');
    expect(EXPORT_TREE_VOLATILE_CONTENT.truncate).toContain('etc/hosts');
    expect(EXPORT_TREE_VOLATILE_CONTENT.truncate).toContain('etc/resolv.conf');
    expect(EXPORT_TREE_VOLATILE_CONTENT.truncate).toContain('etc/machine-id');
  });

  it('removes the timestamp-bearing apt/dpkg logs', () => {
    expect(EXPORT_TREE_VOLATILE_CONTENT.remove).toContain('var/log/dpkg.log');
    expect(EXPORT_TREE_VOLATILE_CONTENT.remove).toContain('var/log/alternatives.log');
    expect(EXPORT_TREE_VOLATILE_CONTENT.remove).toContain('var/log/apt');
  });

  it('uses repo-relative paths (no leading slash) so join(exportDir, rel) works', () => {
    for (const rel of [
      ...EXPORT_TREE_VOLATILE_CONTENT.truncate,
      ...EXPORT_TREE_VOLATILE_CONTENT.remove,
    ]) {
      expect(rel.startsWith('/')).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// singleQuoteForSh + Alpine helper host-shell round-trip
// ---------------------------------------------------------------------------

describe('singleQuoteForSh', () => {
  it('wraps a plain string in single quotes', () => {
    expect(singleQuoteForSh('abc')).toBe(`'abc'`);
  });

  it('escapes embedded single quotes via the close/escape/reopen idiom', () => {
    expect(singleQuoteForSh(`a'b`)).toBe(`'a'\\''b'`);
  });

  it('round-trips through a real shell back to the original bytes', () => {
    // The whole point: a string single-quoted by this helper, when handed to
    // `sh -c "printf %s <quoted>"`, must echo back byte-identical — including $,
    // ", backticks, and embedded single quotes.
    const original = `a $VAR "x" \`cmd\` 'q' \\n end`;
    const quoted = singleQuoteForSh(original);
    const r = spawnSync('/bin/sh', ['-c', `printf %s ${quoted}`], {
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(original);
  });
});

describe('buildMkfsExt4ViaDockerScript host-shell embedding', () => {
  // The script is single-quoted by makeExt4ViaDocker and then runs through the
  // host `/bin/sh -c` (execSync) before reaching the container's `sh -c`.  Prove
  // the inner body survives that round-trip AND is syntactically valid sh — a
  // quoting regression here would only surface as a runtime failure on the
  // macOS Alpine path, which no unit test other than this one can catch.
  const inner = buildMkfsExt4ViaDockerScript('rootfs.ext4', 1024);
  const quoted = singleQuoteForSh(inner);

  it('reaches the inner shell byte-identical through the host shell', () => {
    const r = spawnSync('/bin/sh', ['-c', `printf %s ${quoted}`], {
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(inner);
  });

  it('is syntactically valid POSIX sh after the round-trip', () => {
    // `sh -nc <body>` parses without executing; the outer `/bin/sh -c` unwraps
    // the single quotes exactly as the real run() path does.
    const r = spawnSync('/bin/sh', ['-c', `sh -nc ${quoted}`], {
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Digest-pinned base images
// ---------------------------------------------------------------------------

const DIGEST_REF = /^[a-z0-9./:-]+@sha256:[0-9a-f]{64}$/;

describe('ALPINE_HELPER_REF', () => {
  it('is a digest-pinned reference', () => {
    expect(ALPINE_HELPER_REF).toMatch(DIGEST_REF);
  });
});

describe('UBUNTU_BASE_DIGEST', () => {
  const images: ReadonlyArray<RunnerImage> = ['ubuntu-22.04', 'ubuntu-24.04'];
  const arches: ReadonlyArray<BuildArch> = ['x64', 'arm64'];

  it('has a digest-pinned reference for every (runnerImage, arch)', () => {
    for (const runnerImage of images) {
      for (const arch of arches) {
        expect(UBUNTU_BASE_DIGEST[runnerImage][arch]).toMatch(DIGEST_REF);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// buildDockerBuildArgs threads the pinned UBUNTU_REF
// ---------------------------------------------------------------------------

describe('buildDockerBuildArgs', () => {
  const images: ReadonlyArray<RunnerImage> = ['ubuntu-22.04', 'ubuntu-24.04'];
  const arches: ReadonlyArray<BuildArch> = ['x64', 'arm64'];

  it('includes the pinned UBUNTU_REF for the right (runnerImage, arch)', () => {
    for (const runnerImage of images) {
      for (const arch of arches) {
        const args = buildDockerBuildArgs({ runnerImage, outputDir: '/images', arch });
        expect(args).toContain(
          `--build-arg UBUNTU_REF=${UBUNTU_BASE_DIGEST[runnerImage][arch]}`,
        );
      }
    }
  });

  it('still threads UBUNTU_MAJOR for the downstream apt-mirror sed logic', () => {
    const args = buildDockerBuildArgs({ runnerImage: 'ubuntu-24.04', outputDir: '/images', arch: 'x64' });
    expect(args).toContain('--build-arg UBUNTU_MAJOR=24.04');
  });
});

// script-jail — test/scripts/check-publish-artifacts.test.ts
//
// Unit tests for scripts/check-publish-artifacts.sh — the publish-job gate
// that verifies the downloaded build artifacts' SHA-256 digests against the
// tagged source's `src/action/artifact-manifest.ts` (and, for dist/main.cjs,
// the tagged source's dist/main.cjs itself).
//
// The script is shell, not TS, because the release workflow's publish job
// deliberately runs WITHOUT `pnpm install` — see the file header in
// scripts/check-publish-artifacts.sh.  These tests drive the script via
// child_process so we exercise the same code path the workflow does.
//
// `PINNED_MANIFEST.expected` is platform-keyed, so the fixture builders below
// produce the nested layout. The tests cover both the
// "linux/dist-only" subset (driven by SCRIPT_JAIL_CHECK_DARWIN_ARTIFACTS=0)
// and the full platform set (default).

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Resolve the script path from the repo root.
const repoRoot = new URL('../../', import.meta.url).pathname.replace(
  /\/$/,
  '',
);
const SCRIPT = join(repoRoot, 'scripts/check-publish-artifacts.sh');

const tempDirs: string[] = [];

afterAll(() => {
  for (const d of tempDirs) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

function makeWorkspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-checkpub-'));
  tempDirs.push(dir);
  mkdirSync(join(dir, 'src/action'), { recursive: true });
  mkdirSync(join(dir, 'art/images'), { recursive: true });
  mkdirSync(join(dir, 'art/dist'), { recursive: true });
  return dir;
}

function sha256(bytes: string | Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

interface ManifestEntries {
  // linux section
  linuxRootfs22: string;
  linuxRootfs24: string;
  linuxLibso: string;
  // darwin section
  darwinRootfs22Arm64: string;
  darwinRootfs24Arm64: string;
  darwinLibsoArm64: string;
  vmlinuxVzX86_64: string;
  vmlinuxVzArm64: string;
  scriptJailVmArm64Darwin: string;
}

const PLACEHOLDER_LINUX_ROOTFS_22 = 'PLACEHOLDER_SHA256_LINUX_ROOTFS_UBUNTU_22_04';
const PLACEHOLDER_LINUX_ROOTFS_24 = 'PLACEHOLDER_SHA256_LINUX_ROOTFS_UBUNTU_24_04';
const PLACEHOLDER_LINUX_LIBSO = 'PLACEHOLDER_SHA256_LINUX_LIBSCRIPTJAIL_SO';
const PLACEHOLDER_DARWIN_ROOTFS_22_ARM64 = 'PLACEHOLDER_SHA256_DARWIN_ROOTFS_UBUNTU_22_04_ARM64';
const PLACEHOLDER_DARWIN_ROOTFS_24_ARM64 = 'PLACEHOLDER_SHA256_DARWIN_ROOTFS_UBUNTU_24_04_ARM64';
const PLACEHOLDER_DARWIN_LIBSO_ARM64 = 'PLACEHOLDER_SHA256_DARWIN_LIBSCRIPTJAIL_ARM64_SO';
const PLACEHOLDER_VMLINUX_VZ_X86_64 = 'PLACEHOLDER_SHA256_VMLINUX_VZ_X86_64';
const PLACEHOLDER_VMLINUX_VZ_ARM64 = 'PLACEHOLDER_SHA256_VMLINUX_VZ_ARM64';
const PLACEHOLDER_SJ_VM_ARM64_DARWIN = 'PLACEHOLDER_SHA256_SCRIPT_JAIL_VM_ARM64_DARWIN';

function allPlaceholders(): ManifestEntries {
  return {
    linuxRootfs22: PLACEHOLDER_LINUX_ROOTFS_22,
    linuxRootfs24: PLACEHOLDER_LINUX_ROOTFS_24,
    linuxLibso: PLACEHOLDER_LINUX_LIBSO,
    darwinRootfs22Arm64: PLACEHOLDER_DARWIN_ROOTFS_22_ARM64,
    darwinRootfs24Arm64: PLACEHOLDER_DARWIN_ROOTFS_24_ARM64,
    darwinLibsoArm64: PLACEHOLDER_DARWIN_LIBSO_ARM64,
    vmlinuxVzX86_64: PLACEHOLDER_VMLINUX_VZ_X86_64,
    vmlinuxVzArm64: PLACEHOLDER_VMLINUX_VZ_ARM64,
    scriptJailVmArm64Darwin: PLACEHOLDER_SJ_VM_ARM64_DARWIN,
  };
}

function writeManifest(workspace: string, entries: ManifestEntries): string {
  const path = join(workspace, 'src/action/artifact-manifest.ts');
  const contents = [
    "import type { ArtifactManifest } from './pre-fetch-artifacts.js';",
    '',
    'export const PINNED_MANIFEST: ArtifactManifest = {',
    "  repo: 'brooklyn/script-jail',",
    "  tag: 'v0.0.0',",
    '  expected: {',
    '    linux: {',
    `      'rootfs-ubuntu-22.04.ext4': '${entries.linuxRootfs22}',`,
    `      'rootfs-ubuntu-24.04.ext4': '${entries.linuxRootfs24}',`,
    `      'libscriptjail.so':         '${entries.linuxLibso}',`,
    '    },',
    '    darwin: {',
    `      'rootfs-ubuntu-22.04-arm64.ext4': '${entries.darwinRootfs22Arm64}',`,
    `      'rootfs-ubuntu-24.04-arm64.ext4': '${entries.darwinRootfs24Arm64}',`,
    `      'libscriptjail-arm64.so':         '${entries.darwinLibsoArm64}',`,
    `      'vmlinux-vz-x86_64':              '${entries.vmlinuxVzX86_64}',`,
    `      'vmlinux-vz-arm64':               '${entries.vmlinuxVzArm64}',`,
    `      'script-jail-vm-arm64-darwin':    '${entries.scriptJailVmArm64Darwin}',`,
    '    },',
    '  },',
    '};',
    '',
  ].join('\n');
  writeFileSync(path, contents, 'utf8');
  return path;
}

interface LinuxArtifactBytes {
  rootfs22: string;
  rootfs24: string;
  libso: string;
  dist: string;
  /**
   * Optional bytes for `dist/cli.cjs`.  When set, the helper writes
   * `dist/cli.cjs` alongside `dist/main.cjs` so the cli.cjs SHA-verification
   * tests can land the artifact in the expected location.  Tests that omit
   * this exercise the "cli.cjs not in the artifact directory" path (which
   * `--dist-cli-source` would still flag via the required-files gate).
   */
  cli?: string;
}

interface DarwinArtifactBytes {
  rootfs22Arm64: string;
  rootfs24Arm64: string;
  libsoArm64: string;
  vmlinuxVzX86_64: string;
  vmlinuxVzArm64: string;
  scriptJailVmArm64Darwin: string;
}

interface LinuxOnlyOutput {
  dir: string;
  shas: {
    rootfs22: string;
    rootfs24: string;
    libso: string;
    dist: string;
    /** SHA of `dist/cli.cjs` when `bytes.cli` was provided; undefined otherwise. */
    cli?: string;
  };
}

function writeLinuxArtifacts(
  workspace: string,
  bytes: LinuxArtifactBytes,
): LinuxOnlyOutput {
  const dir = join(workspace, 'art');
  writeFileSync(join(dir, 'images/rootfs-ubuntu-22.04.ext4'), bytes.rootfs22);
  writeFileSync(join(dir, 'images/rootfs-ubuntu-24.04.ext4'), bytes.rootfs24);
  writeFileSync(join(dir, 'images/libscriptjail.so'), bytes.libso);
  writeFileSync(join(dir, 'dist/main.cjs'), bytes.dist);
  if (bytes.cli !== undefined) {
    writeFileSync(join(dir, 'dist/cli.cjs'), bytes.cli);
  }
  const shas: LinuxOnlyOutput['shas'] = {
    rootfs22: sha256(bytes.rootfs22),
    rootfs24: sha256(bytes.rootfs24),
    libso: sha256(bytes.libso),
    dist: sha256(bytes.dist),
  };
  if (bytes.cli !== undefined) {
    shas.cli = sha256(bytes.cli);
  }
  return { dir, shas };
}

interface FullArtifactsOutput {
  dir: string;
  linuxShas: {
    rootfs22: string;
    rootfs24: string;
    libso: string;
    dist: string;
  };
  darwinShas: {
    rootfs22Arm64: string;
    rootfs24Arm64: string;
    libsoArm64: string;
    vmlinuxVzX86_64: string;
    vmlinuxVzArm64: string;
    scriptJailVmArm64Darwin: string;
  };
}

function writeAllArtifacts(
  workspace: string,
  linux: LinuxArtifactBytes,
  darwin: DarwinArtifactBytes,
): FullArtifactsOutput {
  const linuxOut = writeLinuxArtifacts(workspace, linux);
  const dir = linuxOut.dir;
  writeFileSync(
    join(dir, 'images/rootfs-ubuntu-22.04-arm64.ext4'),
    darwin.rootfs22Arm64,
  );
  writeFileSync(
    join(dir, 'images/rootfs-ubuntu-24.04-arm64.ext4'),
    darwin.rootfs24Arm64,
  );
  writeFileSync(join(dir, 'images/libscriptjail-arm64.so'), darwin.libsoArm64);
  writeFileSync(join(dir, 'images/vmlinux-vz-x86_64'), darwin.vmlinuxVzX86_64);
  writeFileSync(join(dir, 'images/vmlinux-vz-arm64'), darwin.vmlinuxVzArm64);
  writeFileSync(
    join(dir, 'script-jail-vm-arm64-darwin'),
    darwin.scriptJailVmArm64Darwin,
  );
  return {
    dir,
    linuxShas: linuxOut.shas,
    darwinShas: {
      rootfs22Arm64: sha256(darwin.rootfs22Arm64),
      rootfs24Arm64: sha256(darwin.rootfs24Arm64),
      libsoArm64: sha256(darwin.libsoArm64),
      vmlinuxVzX86_64: sha256(darwin.vmlinuxVzX86_64),
      vmlinuxVzArm64: sha256(darwin.vmlinuxVzArm64),
      scriptJailVmArm64Darwin: sha256(darwin.scriptJailVmArm64Darwin),
    },
  };
}

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runScript(args: string[], env: Record<string, string> = {}): RunResult {
  const result = spawnSync('bash', [SCRIPT, ...args], {
    encoding: 'utf8',
    timeout: 10_000,
    env: { ...process.env, ...env },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

// Sanity check: the script and a sha256sum binary must be available.  All
// real CI runners (and our dev hosts via coreutils) ship sha256sum.
beforeAll(() => {
  const probe = spawnSync('sha256sum', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    throw new Error(
      'sha256sum is required to run these tests; install GNU coreutils.',
    );
  }
});

describe('scripts/check-publish-artifacts.sh — linux-only subset', () => {
  // The linux-only tests opt out of darwin-artifact checks via the env var
  // so the existing build flow (`scripts/build.ts` on a non-release runner)
  // can keep using this script without producing the darwin artifacts.
  const env = { SCRIPT_JAIL_CHECK_DARWIN_ARTIFACTS: '0' };

  it('exits 0 with a warning when the manifest is all placeholders (bootstrap)', () => {
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, allPlaceholders());
    const { dir } = writeLinuxArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    });

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/::warning::/);
    expect(r.stdout).toMatch(/bootstrap path/);
  });

  it('exits 0 when every linux artifact SHA matches the manifest', () => {
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'rootfs22-bytes',
      rootfs24: 'rootfs24-bytes',
      libso: 'libscriptjail-bytes',
      dist: 'dist-main-bytes',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const entries = allPlaceholders();
    entries.linuxRootfs22 = shas.rootfs22;
    entries.linuxRootfs24 = shas.rootfs24;
    entries.linuxLibso = shas.libso;
    // Real linux SHAs + still-placeholder darwin SHAs would be a "mixed"
    // manifest the script rejects.  Promote the darwin keys to real SHAs
    // too (any 64-hex string will do — the darwin artifacts are not even
    // checked when CHECK_DARWIN_ARTIFACTS=0).
    entries.darwinRootfs22Arm64 = 'a'.repeat(64);
    entries.darwinRootfs24Arm64 = 'b'.repeat(64);
    entries.darwinLibsoArm64 = 'c'.repeat(64);
    entries.vmlinuxVzX86_64 = 'd'.repeat(64);
    entries.vmlinuxVzArm64 = 'e'.repeat(64);
    entries.scriptJailVmArm64Darwin = 'f'.repeat(64);
    const manifestPath = writeManifest(ws, entries);

    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, bytes.dist);

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
      ],
      env,
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
  });

  it('exits 1 and names the offending linux artifact when a SHA mismatches', () => {
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'actual-22-bytes',
      rootfs24: 'rootfs24-bytes',
      libso: 'libscriptjail-bytes',
      dist: 'dist-main-bytes',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const wrong = 'a'.repeat(64);
    const entries = allPlaceholders();
    entries.linuxRootfs22 = wrong;
    entries.linuxRootfs24 = shas.rootfs24;
    entries.linuxLibso = shas.libso;
    entries.darwinRootfs22Arm64 = 'b'.repeat(64);
    entries.darwinRootfs24Arm64 = 'c'.repeat(64);
    entries.darwinLibsoArm64 = 'd'.repeat(64);
    entries.vmlinuxVzX86_64 = 'e'.repeat(64);
    entries.vmlinuxVzArm64 = 'f'.repeat(64);
    entries.scriptJailVmArm64Darwin = '0'.repeat(64);
    const manifestPath = writeManifest(ws, entries);

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/SHA mismatch/);
    // Offender prefixed with `linux/`.
    expect(r.stderr).toMatch(/linux\/rootfs-ubuntu-22\.04\.ext4/);
    expect(r.stderr).toMatch(new RegExp(`expected=${wrong}`));
    expect(r.stderr).toMatch(new RegExp(`computed=${shas.rootfs22}`));
  });

  it('exits 1 when the manifest mixes placeholders with real SHAs (packaging bug)', () => {
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const wrong = 'b'.repeat(64);
    const entries = allPlaceholders();
    // Linux: placeholder + real-but-wrong + real-matching
    entries.linuxRootfs22 = PLACEHOLDER_LINUX_ROOTFS_22;
    entries.linuxRootfs24 = wrong;
    entries.linuxLibso = shas.libso;
    // Leave darwin entirely placeholders.
    const manifestPath = writeManifest(ws, entries);

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/mixed with/);
    expect(r.stdout).not.toMatch(/::warning::/);
  });

  it('verifies dist/main.cjs even in bootstrap mode (mismatch hard-fails)', () => {
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, allPlaceholders());
    const { dir } = writeLinuxArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'tampered-dist-bytes',
    });
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, 'trusted-dist-bytes');

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
      ],
      env,
    );
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/dist\/main\.cjs mismatch/);
    expect(r.stderr).toMatch(/refusing to publish/);
  });

  it('verifies dist/main.cjs in bootstrap mode (match exits 0 with warning)', () => {
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, allPlaceholders());
    const distBytes = 'trusted-dist-bytes';
    const { dir } = writeLinuxArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: distBytes,
    });
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, distBytes);

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
      ],
      env,
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/::warning::/);
  });

  it('rejects a manifest with a duplicate key in a platform sub-block', () => {
    // Regression test: a duplicated entry within ONE platform sub-block
    // must fail the parser instead of silently picking one value.
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const manifestPath = join(ws, 'src/action/artifact-manifest.ts');
    const contents = [
      'export const PINNED_MANIFEST: ArtifactManifest = {',
      "  repo: 'brooklyn/script-jail',",
      "  tag: 'v0.0.0',",
      '  expected: {',
      '    linux: {',
      `      'rootfs-ubuntu-22.04.ext4': '${shas.rootfs22}',`,
      `      'rootfs-ubuntu-22.04.ext4': '${'f'.repeat(64)}',`,
      `      'rootfs-ubuntu-24.04.ext4': '${shas.rootfs24}',`,
      `      'libscriptjail.so':         '${shas.libso}',`,
      '    },',
      '    darwin: {',
      `      'rootfs-ubuntu-22.04-arm64.ext4': '${'a'.repeat(64)}',`,
      `      'rootfs-ubuntu-24.04-arm64.ext4': '${'b'.repeat(64)}',`,
      `      'libscriptjail-arm64.so':         '${'c'.repeat(64)}',`,
      `      'vmlinux-vz-x86_64':              '${'d'.repeat(64)}',`,
      `      'vmlinux-vz-arm64':               '${'e'.repeat(64)}',`,
      `      'script-jail-vm-arm64-darwin':    '${'0'.repeat(64)}',`,
      '    },',
      '  },',
      '};',
      '',
    ].join('\n');
    writeFileSync(manifestPath, contents, 'utf8');

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(
      /manifest key 'linux\/rootfs-ubuntu-22\.04\.ext4' appears 2 times/,
    );
  });

  it('ignores commented-out example entries outside the expected block', () => {
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);

    const manifestPath = join(ws, 'src/action/artifact-manifest.ts');
    const contents = [
      '// Example (do not remove):',
      "//   'rootfs-ubuntu-22.04.ext4': 'PLACEHOLDER_SHA256_DECOY',",
      '',
      'export const PINNED_MANIFEST: ArtifactManifest = {',
      "  repo: 'brooklyn/script-jail',",
      "  tag: 'v0.0.0',",
      '  expected: {',
      '    linux: {',
      `      'rootfs-ubuntu-22.04.ext4': '${shas.rootfs22}',`,
      `      'rootfs-ubuntu-24.04.ext4': '${shas.rootfs24}',`,
      `      'libscriptjail.so':         '${shas.libso}',`,
      '    },',
      '    darwin: {',
      `      'rootfs-ubuntu-22.04-arm64.ext4': '${'a'.repeat(64)}',`,
      `      'rootfs-ubuntu-24.04-arm64.ext4': '${'b'.repeat(64)}',`,
      `      'libscriptjail-arm64.so':         '${'c'.repeat(64)}',`,
      `      'vmlinux-vz-x86_64':              '${'d'.repeat(64)}',`,
      `      'vmlinux-vz-arm64':               '${'e'.repeat(64)}',`,
      `      'script-jail-vm-arm64-darwin':    '${'0'.repeat(64)}',`,
      '    },',
      '  },',
      '};',
      '',
    ].join('\n');
    writeFileSync(manifestPath, contents, 'utf8');

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
    expect(r.stdout).not.toMatch(/::warning::/);
  });

  it('exits 1 when a required artifact file is missing', () => {
    const ws = makeWorkspace();
    const entries = allPlaceholders();
    entries.linuxRootfs22 = 'c'.repeat(64);
    entries.linuxRootfs24 = 'd'.repeat(64);
    entries.linuxLibso = 'e'.repeat(64);
    const manifestPath = writeManifest(ws, entries);
    const dir = join(ws, 'art');

    const r = runScript(['--manifest', manifestPath, '--dir', dir], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/required artifact\(s\) missing/);
  });

  it('exits 1 and names dist/cli.cjs when --dist-cli-source mismatches', () => {
    // Critical-2 regression test: the publish job uploads `dist/cli.cjs` to
    // every release alongside `dist/main.cjs`, and a compromised build-job
    // dependency could tamper with it.  When `--dist-cli-source` is passed,
    // the gate must compare the downloaded artifact's bytes to the fresh-
    // checkout source copy and fail-fast on mismatch.
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'trusted-main-bytes',
      cli: 'tampered-cli-bytes',
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const entries = allPlaceholders();
    entries.linuxRootfs22 = shas.rootfs22;
    entries.linuxRootfs24 = shas.rootfs24;
    entries.linuxLibso = shas.libso;
    entries.darwinRootfs22Arm64 = 'a'.repeat(64);
    entries.darwinRootfs24Arm64 = 'b'.repeat(64);
    entries.darwinLibsoArm64 = 'c'.repeat(64);
    entries.vmlinuxVzX86_64 = 'd'.repeat(64);
    entries.vmlinuxVzArm64 = 'e'.repeat(64);
    entries.scriptJailVmArm64Darwin = 'f'.repeat(64);
    const manifestPath = writeManifest(ws, entries);

    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, bytes.dist);
    // The tagged source copy of dist/cli.cjs differs from what landed in the
    // artifact directory — i.e. the build job's output was tampered with.
    const distCliSource = join(ws, 'dist-cli-source.js');
    writeFileSync(distCliSource, 'trusted-cli-bytes');

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
        '--dist-cli-source',
        distCliSource,
      ],
      env,
    );
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/SHA mismatch/);
    expect(r.stderr).toMatch(/dist\/cli\.cjs/);
    expect(r.stderr).toMatch(new RegExp(`computed=${sha256(bytes.cli!)}`));
    expect(r.stderr).toMatch(
      new RegExp(`expected=${sha256('trusted-cli-bytes')}`),
    );
  });

  it('silently skips the dist/cli.cjs check when --dist-cli-source is omitted', () => {
    // Back-compat: a caller that doesn't opt into cli.cjs verification must
    // see no failure even when dist/cli.cjs isn't present in the artifact
    // directory.  The flag is intentionally additive — the linux-only tests
    // above all run this path.
    const ws = makeWorkspace();
    const bytes: LinuxArtifactBytes = {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'dist-main-bytes',
      // No `cli` — dist/cli.cjs does NOT exist in the artifact directory.
    };
    const { dir, shas } = writeLinuxArtifacts(ws, bytes);
    const entries = allPlaceholders();
    entries.linuxRootfs22 = shas.rootfs22;
    entries.linuxRootfs24 = shas.rootfs24;
    entries.linuxLibso = shas.libso;
    entries.darwinRootfs22Arm64 = 'a'.repeat(64);
    entries.darwinRootfs24Arm64 = 'b'.repeat(64);
    entries.darwinLibsoArm64 = 'c'.repeat(64);
    entries.vmlinuxVzX86_64 = 'd'.repeat(64);
    entries.vmlinuxVzArm64 = 'e'.repeat(64);
    entries.scriptJailVmArm64Darwin = 'f'.repeat(64);
    const manifestPath = writeManifest(ws, entries);

    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, bytes.dist);

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
      ],
      env,
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
    expect(r.stderr).not.toMatch(/cli\.cjs/);
  });

  it('verifies dist/cli.cjs in bootstrap mode (mismatch hard-fails)', () => {
    // Like dist/main.cjs, dist/cli.cjs MUST be checked in bootstrap mode —
    // skipping it would leave the npm CLI bundle outside the gate exactly
    // when consumers (npm-install users) most need it intact.
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, allPlaceholders());
    const { dir } = writeLinuxArtifacts(ws, {
      rootfs22: 'r22',
      rootfs24: 'r24',
      libso: 'libso',
      dist: 'trusted-main-bytes',
      cli: 'tampered-cli-bytes',
    });
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, 'trusted-main-bytes');
    const distCliSource = join(ws, 'dist-cli-source.js');
    writeFileSync(distCliSource, 'trusted-cli-bytes');

    const r = runScript(
      [
        '--manifest',
        manifestPath,
        '--dir',
        dir,
        '--dist-source',
        distSource,
        '--dist-cli-source',
        distCliSource,
      ],
      env,
    );
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/dist\/cli\.cjs/);
    expect(r.stderr).toMatch(/refusing to publish/);
  });
});

describe('scripts/check-publish-artifacts.sh — full platform set', () => {
  // Default mode: SCRIPT_JAIL_CHECK_DARWIN_ARTIFACTS=1 — the script also
  // verifies the darwin/* artifacts the release workflow uploads.

  it('exits 0 when every linux + darwin artifact SHA matches', () => {
    const ws = makeWorkspace();
    const linux: LinuxArtifactBytes = {
      rootfs22: 'lr22',
      rootfs24: 'lr24',
      libso: 'lso',
      dist: 'dist-bytes',
    };
    const darwin: DarwinArtifactBytes = {
      rootfs22Arm64: 'dr22a',
      rootfs24Arm64: 'dr24a',
      libsoArm64: 'dsoa',
      vmlinuxVzX86_64: 'kx86',
      vmlinuxVzArm64: 'karm',
      scriptJailVmArm64Darwin: 'sjvm',
    };
    const { dir, linuxShas, darwinShas } = writeAllArtifacts(ws, linux, darwin);
    const entries: ManifestEntries = {
      linuxRootfs22: linuxShas.rootfs22,
      linuxRootfs24: linuxShas.rootfs24,
      linuxLibso: linuxShas.libso,
      darwinRootfs22Arm64: darwinShas.rootfs22Arm64,
      darwinRootfs24Arm64: darwinShas.rootfs24Arm64,
      darwinLibsoArm64: darwinShas.libsoArm64,
      vmlinuxVzX86_64: darwinShas.vmlinuxVzX86_64,
      vmlinuxVzArm64: darwinShas.vmlinuxVzArm64,
      scriptJailVmArm64Darwin: darwinShas.scriptJailVmArm64Darwin,
    };
    const manifestPath = writeManifest(ws, entries);
    const distSource = join(ws, 'dist-source.js');
    writeFileSync(distSource, linux.dist);

    const r = runScript([
      '--manifest',
      manifestPath,
      '--dir',
      dir,
      '--dist-source',
      distSource,
    ]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/OK — all artifact SHAs match/);
  });

  it('exits 1 with a darwin/ prefix when a darwin artifact SHA mismatches', () => {
    const ws = makeWorkspace();
    const linux: LinuxArtifactBytes = {
      rootfs22: 'lr22',
      rootfs24: 'lr24',
      libso: 'lso',
      dist: 'dist-bytes',
    };
    const darwin: DarwinArtifactBytes = {
      rootfs22Arm64: 'dr22a',
      rootfs24Arm64: 'dr24a',
      libsoArm64: 'dsoa',
      vmlinuxVzX86_64: 'kx86',
      vmlinuxVzArm64: 'karm',
      scriptJailVmArm64Darwin: 'sjvm',
    };
    const { dir, linuxShas, darwinShas } = writeAllArtifacts(ws, linux, darwin);
    const wrongKernel = '9'.repeat(64);
    const entries: ManifestEntries = {
      linuxRootfs22: linuxShas.rootfs22,
      linuxRootfs24: linuxShas.rootfs24,
      linuxLibso: linuxShas.libso,
      darwinRootfs22Arm64: darwinShas.rootfs22Arm64,
      darwinRootfs24Arm64: darwinShas.rootfs24Arm64,
      darwinLibsoArm64: darwinShas.libsoArm64,
      vmlinuxVzX86_64: wrongKernel, // lie about kernel SHA
      vmlinuxVzArm64: darwinShas.vmlinuxVzArm64,
      scriptJailVmArm64Darwin: darwinShas.scriptJailVmArm64Darwin,
    };
    const manifestPath = writeManifest(ws, entries);

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/SHA mismatch/);
    expect(r.stderr).toMatch(/darwin\/vmlinux-vz-x86_64/);
    expect(r.stderr).toMatch(new RegExp(`expected=${wrongKernel}`));
    expect(r.stderr).toMatch(new RegExp(`computed=${darwinShas.vmlinuxVzX86_64}`));
  });

  it('rejects a manifest missing the linux: platform section', () => {
    // Half-shape: only darwin present, no linux block.  The parser must
    // refuse rather than continue with an empty linux block.
    const ws = makeWorkspace();
    const linux: LinuxArtifactBytes = {
      rootfs22: 'lr22',
      rootfs24: 'lr24',
      libso: 'lso',
      dist: 'dist',
    };
    const darwin: DarwinArtifactBytes = {
      rootfs22Arm64: 'dr22a',
      rootfs24Arm64: 'dr24a',
      libsoArm64: 'dsoa',
      vmlinuxVzX86_64: 'kx86',
      vmlinuxVzArm64: 'karm',
      scriptJailVmArm64Darwin: 'sjvm',
    };
    const { dir } = writeAllArtifacts(ws, linux, darwin);

    const manifestPath = join(ws, 'src/action/artifact-manifest.ts');
    const contents = [
      'export const PINNED_MANIFEST: ArtifactManifest = {',
      "  repo: 'brooklyn/script-jail',",
      "  tag: 'v0.0.0',",
      '  expected: {',
      '    darwin: {',
      `      'rootfs-ubuntu-22.04-arm64.ext4': '${'a'.repeat(64)}',`,
      `      'rootfs-ubuntu-24.04-arm64.ext4': '${'b'.repeat(64)}',`,
      `      'libscriptjail-arm64.so':         '${'c'.repeat(64)}',`,
      `      'vmlinux-vz-x86_64':              '${'d'.repeat(64)}',`,
      `      'vmlinux-vz-arm64':               '${'e'.repeat(64)}',`,
      `      'script-jail-vm-arm64-darwin':    '${'0'.repeat(64)}',`,
      '    },',
      '  },',
      '};',
      '',
    ].join('\n');
    writeFileSync(manifestPath, contents, 'utf8');

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/linux: \{ \.\.\. \} sub-block/);
  });

  it('bootstrap mode prints linux + darwin SHAs in the maintainer paste-block', () => {
    // The bootstrap branch is also the place we surface the computed SHAs
    // for the maintainer to copy back into the manifest. The print-block must
    // include every key in both platform sections.
    const ws = makeWorkspace();
    const manifestPath = writeManifest(ws, allPlaceholders());
    const linux: LinuxArtifactBytes = {
      rootfs22: 'lr22',
      rootfs24: 'lr24',
      libso: 'lso',
      dist: 'dist',
    };
    const darwin: DarwinArtifactBytes = {
      rootfs22Arm64: 'dr22a',
      rootfs24Arm64: 'dr24a',
      libsoArm64: 'dsoa',
      vmlinuxVzX86_64: 'kx86',
      vmlinuxVzArm64: 'karm',
      scriptJailVmArm64Darwin: 'sjvm',
    };
    const { dir } = writeAllArtifacts(ws, linux, darwin);

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/::warning::/);
    expect(r.stderr).toMatch(/linux\/libscriptjail\.so/);
    expect(r.stderr).toMatch(/darwin\/vmlinux-vz-x86_64/);
    expect(r.stderr).toMatch(/darwin\/script-jail-vm-arm64-darwin/);
  });

  it('rejects a hybrid manifest with real linux SHAs and placeholder darwin SHAs', () => {
    // This is the most likely real-world packaging mistake: a maintainer
    // pastes the linux SHAs from the bootstrap run's step-summary but forgets
    // to fill in the darwin section. The script's mixed-rejection logic
    // (`scripts/check-publish-artifacts.sh` near the `"mixed with"` line)
    // handles it today; this regression test prevents silent breakage.
    const ws = makeWorkspace();
    const linux: LinuxArtifactBytes = {
      rootfs22: 'lr22',
      rootfs24: 'lr24',
      libso: 'lso',
      dist: 'dist-bytes',
    };
    const darwin: DarwinArtifactBytes = {
      rootfs22Arm64: 'dr22a',
      rootfs24Arm64: 'dr24a',
      libsoArm64: 'dsoa',
      vmlinuxVzX86_64: 'kx86',
      vmlinuxVzArm64: 'karm',
      scriptJailVmArm64Darwin: 'sjvm',
    };
    const { dir, linuxShas } = writeAllArtifacts(ws, linux, darwin);
    // All three linux entries pasted as real (matching) SHAs.  Every
    // darwin entry — and the vmlinux-vz / script-jail-vm SHAs that live in
    // the darwin section — is still a placeholder.
    const entries: ManifestEntries = {
      linuxRootfs22: linuxShas.rootfs22,
      linuxRootfs24: linuxShas.rootfs24,
      linuxLibso: linuxShas.libso,
      darwinRootfs22Arm64: PLACEHOLDER_DARWIN_ROOTFS_22_ARM64,
      darwinRootfs24Arm64: PLACEHOLDER_DARWIN_ROOTFS_24_ARM64,
      darwinLibsoArm64: PLACEHOLDER_DARWIN_LIBSO_ARM64,
      vmlinuxVzX86_64: PLACEHOLDER_VMLINUX_VZ_X86_64,
      vmlinuxVzArm64: PLACEHOLDER_VMLINUX_VZ_ARM64,
      scriptJailVmArm64Darwin: PLACEHOLDER_SJ_VM_ARM64_DARWIN,
    };
    const manifestPath = writeManifest(ws, entries);

    const r = runScript(['--manifest', manifestPath, '--dir', dir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/mixed with/);
    // No bootstrap-warning — this is a hard rejection, not a documented
    // bootstrap loop.
    expect(r.stdout).not.toMatch(/::warning::/);
  });
});

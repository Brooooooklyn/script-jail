// script-jail — test/cli/spawn-vm.test.ts
//
// Unit tests for the pure helpers in src/cli/spawn-vm.ts.  The integration
// surface (actually spawning script-jail-vm) is exercised by the gated mac
// parity test in test/e2e/mac-parity.test.ts.  Here we cover:
//
//   - resolveScriptJailVmBinary lookup order + missing-binary error
//   - checkArtifacts kernel/rootfs missing-file diagnostics
//   - toJsonPayload field-name mapping (camelCase → snake_case)

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  resolveScriptJailVmBinary,
  checkArtifacts,
  toJsonPayload,
  MacOSVmBinaryNotFoundError,
  MacOSVmArtifactNotFoundError,
  type VmConfig,
} from '../../src/cli/spawn-vm.js';

let scratch: string;

beforeEach(() => {
  scratch = mkdtempSync(join(tmpdir(), 'script-jail-spawn-vm-test-'));
});

afterEach(() => {
  try { rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
});

function touchExe(p: string): string {
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, '#!/bin/sh\nexit 0\n');
  chmodSync(p, 0o755);
  return p;
}

describe('resolveScriptJailVmBinary', () => {
  it('honours SCRIPT_JAIL_VM_BIN when the path exists', () => {
    const envBin = touchExe(join(scratch, 'env-bin', 'script-jail-vm'));
    const found = resolveScriptJailVmBinary({ envOverride: envBin });
    expect(found).toBe(envBin);
  });

  it('falls back to target/release/script-jail-vm when env override is absent', () => {
    const repoRoot = join(scratch, 'repo');
    const cargoBin = touchExe(
      join(repoRoot, 'target', 'release', 'script-jail-vm'),
    );
    const found = resolveScriptJailVmBinary({
      envOverride: '',
      repoRoot,
      packageRoot: join(scratch, 'package-root-empty'),
    });
    expect(found).toBe(cargoBin);
  });

  it('falls back to bin/darwin-<arch>/script-jail-vm when target/ is missing', () => {
    const packageRoot = join(scratch, 'pkg');
    const installedBin = touchExe(
      join(packageRoot, 'bin', 'darwin-arm64', 'script-jail-vm'),
    );
    const found = resolveScriptJailVmBinary({
      envOverride: '',
      repoRoot: join(scratch, 'no-repo'),
      packageRoot,
      arch: 'arm64',
    });
    expect(found).toBe(installedBin);
  });

  it('throws MacOSVmBinaryNotFoundError listing every checked path', () => {
    expect(() =>
      resolveScriptJailVmBinary({
        envOverride: '',
        repoRoot: join(scratch, 'no-repo'),
        packageRoot: join(scratch, 'no-pkg'),
        arch: 'arm64',
      }),
    ).toThrow(MacOSVmBinaryNotFoundError);

    // The error message should mention both the cargo target path and the
    // installed bin path so a confused dev sees what was tried.
    try {
      resolveScriptJailVmBinary({
        envOverride: '',
        repoRoot: join(scratch, 'no-repo'),
        packageRoot: join(scratch, 'no-pkg'),
        arch: 'x64',
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MacOSVmBinaryNotFoundError);
      const msg = (err as Error).message;
      expect(msg).toContain('target/release/script-jail-vm');
      expect(msg).toContain('darwin-x64');
    }
  });
});

describe('checkArtifacts', () => {
  it('throws MacOSVmArtifactNotFoundError("kernel", …) when kernel is missing', () => {
    const rootfs = join(scratch, 'rootfs.ext4');
    writeFileSync(rootfs, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: join(scratch, 'no-kernel'),
        rootfsDiskPath: rootfs,
      }),
    ).toThrow(/kernel not found/);
  });

  it('throws MacOSVmArtifactNotFoundError("rootfs", …) when rootfs is missing', () => {
    const kernel = join(scratch, 'kernel');
    writeFileSync(kernel, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: kernel,
        rootfsDiskPath: join(scratch, 'no-rootfs'),
      }),
    ).toThrow(/rootfs not found/);
  });

  it('points the kernel-missing error at local build or release artifacts', () => {
    try {
      checkArtifacts({
        kernelPath: join(scratch, 'no-kernel'),
        rootfsDiskPath: join(scratch, 'no-rootfs'),
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MacOSVmArtifactNotFoundError);
      const msg = (err as Error).message;
      expect(msg).toContain('pnpm build');
      expect(msg).toContain('release artifact');
    }
  });

  it('passes when all artifacts exist', () => {
    const kernel = join(scratch, 'kernel');
    const rootfs = join(scratch, 'rootfs');
    writeFileSync(kernel, 'fake');
    writeFileSync(rootfs, 'fake');
    expect(() =>
      checkArtifacts({ kernelPath: kernel, rootfsDiskPath: rootfs }),
    ).not.toThrow();
  });
});

describe('toJsonPayload', () => {
  it('translates camelCase fields to the snake_case Rust expects', () => {
    const cfg: VmConfig = {
      kernelPath: '/k',
      kernelCmdline: 'console=hvc0',
      rootfsDiskPath: '/r',
      repoDiskPath: '/re',
      vsockUdsPath: '/v',
      vsockPort: 10242,
      vcpuCount: 2,
      memoryMb: 2048,
      enableNetwork: true,
      mode: 'update',
      repoDir: '/cwd',
      configPath: '/cwd/.script-jail.yml',
      lockPath: '/cwd/.script-jail.lock.yml',
    };
    const payload = toJsonPayload(cfg);
    expect(payload).toEqual({
      kernel_path: '/k',
      kernel_cmdline: 'console=hvc0',
      rootfs_disk_path: '/r',
      repo_disk_path: '/re',
      vsock_uds_path: '/v',
      vsock_port: 10242,
      vcpu_count: 2,
      memory_mb: 2048,
      enable_network: true,
    });
    // CLI-side bookkeeping (mode/repoDir/configPath/lockPath) MUST NOT leak
    // into the Rust payload — those fields are consumed by the CLI itself.
    expect((payload as unknown as Record<string, unknown>)['mode']).toBeUndefined();
    expect((payload as unknown as Record<string, unknown>)['repo_dir']).toBeUndefined();
  });
});

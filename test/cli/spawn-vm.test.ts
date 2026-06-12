// script-jail — test/cli/spawn-vm.test.ts
//
// Unit tests for the pure helpers in src/cli/spawn-vm.ts.  The integration
// surface (actually spawning script-jail-vm) is exercised by the gated mac
// parity test in test/e2e/mac-parity.test.ts.  Here we cover:
//
//   - resolveScriptJailVmBinary lookup order + missing-binary error
//   - checkArtifacts kernel/rootfs/scratch missing-file diagnostics
//   - toJsonPayload field-name mapping (camelCase → snake_case)
//   - assertVmHelperEntitlement (codesign exec injected via CodesignRunner)
//   - spawnVm preflight ordering (artifacts, then entitlement — both before
//     any child process is spawned)

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  resolveScriptJailVmBinary,
  checkArtifacts,
  toJsonPayload,
  spawnVm,
  assertVmHelperEntitlement,
  VZ_ENTITLEMENT,
  MacOSVmBinaryNotFoundError,
  MacOSVmArtifactNotFoundError,
  MacOSVmEntitlementError,
  type CodesignRunner,
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
      platformPackageDir: join(scratch, 'platform-dir-empty'),
    });
    expect(found).toBe(cargoBin);
  });

  it('falls back to <platformPackageDir>/script-jail-vm when target/ is missing', () => {
    // The published @script-jail/<os>-<arch> package ships the VZ helper at its
    // ROOT (alongside the rootfs/shim/kernel), NOT under a bin/darwin-<arch>/
    // subdir — the package itself is already os/cpu-specific.
    const platformPackageDir = join(scratch, 'script-jail-darwin-arm64');
    const installedBin = touchExe(join(platformPackageDir, 'script-jail-vm'));
    const found = resolveScriptJailVmBinary({
      envOverride: '',
      repoRoot: join(scratch, 'no-repo'),
      platformPackageDir,
    });
    expect(found).toBe(installedBin);
  });

  it('throws MacOSVmBinaryNotFoundError listing every checked path', () => {
    const platformPackageDir = join(scratch, 'no-platform-pkg');
    expect(() =>
      resolveScriptJailVmBinary({
        envOverride: '',
        repoRoot: join(scratch, 'no-repo'),
        platformPackageDir,
      }),
    ).toThrow(MacOSVmBinaryNotFoundError);

    // The error message should mention both the cargo target path and the
    // platform-package helper path so a confused dev sees what was tried.
    try {
      resolveScriptJailVmBinary({
        envOverride: '',
        repoRoot: join(scratch, 'no-repo'),
        platformPackageDir,
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MacOSVmBinaryNotFoundError);
      const msg = (err as Error).message;
      expect(msg).toContain('target/release/script-jail-vm');
      expect(msg).toContain(join(platformPackageDir, 'script-jail-vm'));
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

  it('throws MacOSVmArtifactNotFoundError("scratch disk", …) when the scratch disk is missing', () => {
    const kernel = join(scratch, 'kernel');
    const rootfs = join(scratch, 'rootfs');
    writeFileSync(kernel, 'fake');
    writeFileSync(rootfs, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: kernel,
        rootfsDiskPath: rootfs,
        scratchDiskPath: join(scratch, 'no-scratch.ext4'),
      }),
    ).toThrow(/scratch disk not found/);
  });

  it('passes when the scratch disk exists', () => {
    const kernel = join(scratch, 'kernel');
    const rootfs = join(scratch, 'rootfs');
    const scratchDisk = join(scratch, 'scratch.ext4');
    writeFileSync(kernel, 'fake');
    writeFileSync(rootfs, 'fake');
    writeFileSync(scratchDisk, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: kernel,
        rootfsDiskPath: rootfs,
        scratchDiskPath: scratchDisk,
      }),
    ).not.toThrow();
  });

  it('throws MacOSVmArtifactNotFoundError("sjtmp disk", …) when the sjtmp disk is missing', () => {
    const kernel = join(scratch, 'kernel');
    const rootfs = join(scratch, 'rootfs');
    const scratchDisk = join(scratch, 'scratch.ext4');
    writeFileSync(kernel, 'fake');
    writeFileSync(rootfs, 'fake');
    writeFileSync(scratchDisk, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: kernel,
        rootfsDiskPath: rootfs,
        scratchDiskPath: scratchDisk,
        sjtmpDiskPath: join(scratch, 'no-sjtmp.ext4'),
      }),
    ).toThrow(/sjtmp disk not found/);
  });

  it('passes when the sjtmp disk exists', () => {
    const kernel = join(scratch, 'kernel');
    const rootfs = join(scratch, 'rootfs');
    const scratchDisk = join(scratch, 'scratch.ext4');
    const sjtmpDisk = join(scratch, 'sjtmp.ext4');
    writeFileSync(kernel, 'fake');
    writeFileSync(rootfs, 'fake');
    writeFileSync(scratchDisk, 'fake');
    writeFileSync(sjtmpDisk, 'fake');
    expect(() =>
      checkArtifacts({
        kernelPath: kernel,
        rootfsDiskPath: rootfs,
        scratchDiskPath: scratchDisk,
        sjtmpDiskPath: sjtmpDisk,
      }),
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
      scratchDiskPath: '/sc',
      sjtmpDiskPath: '/sj',
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
      scratch_disk_path: '/sc',
      sjtmp_disk_path: '/sj',
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

// ---------------------------------------------------------------------------
// assertVmHelperEntitlement — VZ entitlement preflight
// ---------------------------------------------------------------------------

/** CodesignRunner stub that records its args and returns a fixed result. */
function fakeCodesign(result: {
  status: number | null;
  stdout?: string;
  stderr?: string;
  error?: Error;
}): { run: CodesignRunner; calls: Array<ReadonlyArray<string>> } {
  const calls: Array<ReadonlyArray<string>> = [];
  const run: CodesignRunner = (args) => {
    calls.push(args);
    return {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      error: result.error,
    };
  };
  return { run, calls };
}

describe('assertVmHelperEntitlement', () => {
  it('passes when codesign reports the virtualization entitlement (DER text format)', () => {
    // macOS ≥13 `codesign -d --entitlements -` output shape.
    const { run } = fakeCodesign({
      status: 0,
      stdout: `[Dict]\n\t[Key] ${VZ_ENTITLEMENT}\n\t[Value]\n\t\t[Bool] true\n`,
    });
    expect(() => assertVmHelperEntitlement('/bin/helper', run)).not.toThrow();
  });

  it('passes when codesign reports the entitlement in the legacy XML format', () => {
    const { run } = fakeCodesign({
      status: 0,
      stdout:
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n' +
        `<key>${VZ_ENTITLEMENT}</key><true/>\n</dict></plist>\n`,
    });
    expect(() => assertVmHelperEntitlement('/bin/helper', run)).not.toThrow();
  });

  it('throws MacOSVmEntitlementError when the binary is signed without the entitlement', () => {
    // Signed, but the entitlements blob has no virtualization key (codesign
    // exits 0 with empty stdout for "no entitlements at all").
    const { run } = fakeCodesign({ status: 0, stdout: '' });
    expect(() => assertVmHelperEntitlement('/bin/helper', run)).toThrow(
      MacOSVmEntitlementError,
    );
  });

  it('throws MacOSVmEntitlementError for a completely unsigned binary', () => {
    const { run } = fakeCodesign({
      status: 1,
      stderr: '/bin/helper: code object is not signed at all\n',
    });
    expect(() => assertVmHelperEntitlement('/bin/helper', run)).toThrow(
      MacOSVmEntitlementError,
    );
  });

  it('the error names the entitlement and the codesign re-sign remediation', () => {
    const { run } = fakeCodesign({ status: 0, stdout: '' });
    try {
      assertVmHelperEntitlement('/some/script-jail-vm', run);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MacOSVmEntitlementError);
      const e = err as MacOSVmEntitlementError;
      expect(e.binaryPath).toBe('/some/script-jail-vm');
      expect(e.message).toContain(VZ_ENTITLEMENT);
      expect(e.message).toContain(
        'codesign --force --sign - --entitlements src/host-mac/script-jail-vm.entitlements',
      );
      expect(e.message).toContain('/some/script-jail-vm');
    }
  });

  it('degrades gracefully (skips, no throw) when codesign itself is unavailable', () => {
    const enoent = Object.assign(new Error('spawnSync codesign ENOENT'), {
      code: 'ENOENT',
    });
    const { run } = fakeCodesign({ status: null, error: enoent });
    expect(() => assertVmHelperEntitlement('/bin/helper', run)).not.toThrow();
  });

  it('invokes codesign with -d --entitlements - <binary>', () => {
    const { run, calls } = fakeCodesign({
      status: 0,
      stdout: `[Key] ${VZ_ENTITLEMENT}\n`,
    });
    assertVmHelperEntitlement('/bin/helper', run);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(['-d', '--entitlements', '-', '/bin/helper']);
  });
});

// ---------------------------------------------------------------------------
// spawnVm preflights (no child process is ever spawned in these tests)
// ---------------------------------------------------------------------------

describe('spawnVm — preflights', () => {
  function makeVmConfig(over: Partial<VmConfig>): VmConfig {
    return {
      kernelPath: join(scratch, 'kernel'),
      kernelCmdline: 'console=hvc0',
      rootfsDiskPath: join(scratch, 'rootfs.ext4'),
      repoDiskPath: join(scratch, 'repo.ext4'),
      scratchDiskPath: join(scratch, 'scratch.ext4'),
      sjtmpDiskPath: join(scratch, 'sjtmp.ext4'),
      vsockUdsPath: join(scratch, 'vsock.sock'),
      vsockPort: 10242,
      vcpuCount: 2,
      memoryMb: 2048,
      enableNetwork: true,
      mode: 'update',
      repoDir: scratch,
      configPath: join(scratch, '.script-jail.yml'),
      lockPath: join(scratch, '.script-jail.lock.yml'),
      ...over,
    };
  }

  it('rejects with "scratch disk not found" when the scratch ext4 is missing', async () => {
    const binary = touchExe(join(scratch, 'bin', 'script-jail-vm'));
    writeFileSync(join(scratch, 'kernel'), 'fake');
    writeFileSync(join(scratch, 'rootfs.ext4'), 'fake');
    // scratch.ext4 deliberately NOT created.

    await expect(
      spawnVm(makeVmConfig({}), { binary }),
    ).rejects.toThrow(/scratch disk not found/);
  });

  it('rejects with MacOSVmEntitlementError when the helper lacks the VZ entitlement', async () => {
    const binary = touchExe(join(scratch, 'bin', 'script-jail-vm'));
    writeFileSync(join(scratch, 'kernel'), 'fake');
    writeFileSync(join(scratch, 'rootfs.ext4'), 'fake');
    writeFileSync(join(scratch, 'scratch.ext4'), 'fake');
    writeFileSync(join(scratch, 'sjtmp.ext4'), 'fake');

    const { run, calls } = fakeCodesign({ status: 0, stdout: '' });
    await expect(
      spawnVm(makeVmConfig({}), { binary, codesignRunner: run }),
    ).rejects.toThrow(MacOSVmEntitlementError);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(['-d', '--entitlements', '-', binary]);
  });
});

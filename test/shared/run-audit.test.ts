// script-jail — test/shared/run-audit.test.ts
//
// Unit tests for the shared audit pipeline that both the GitHub Action and
// the macOS CLI call.  We inject every external dependency (overlay builder,
// arch-flag builder, the launcher closure) so the suite stays fast and
// cross-platform.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  runAudit,
  type RunAuditInput,
  type RunAuditIo,
} from '../../src/shared/run-audit.js';

class Sink {
  chunks: string[] = [];
  write(s: string): boolean { this.chunks.push(s); return true; }
  get text(): string { return this.chunks.join(''); }
}

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'run-audit-test-'));
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** Build a config + repo layout so buildEffectiveConfig can read the YAML. */
function setupRepo(): {
  repoDir: string;
  configPath: string;
  lockPath: string;
  workDir: string;
} {
  const repoDir = join(testDir, 'repo');
  mkdirSync(repoDir, { recursive: true });
  writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'demo' }));
  const configPath = join(repoDir, '.script-jail.yml');
  writeFileSync(configPath, 'spoof:\n  platform: linux\n  arch: x64\n');
  const lockPath = join(repoDir, '.script-jail.lock.yml');
  const workDir = join(testDir, 'work');
  mkdirSync(workDir, { recursive: true });
  return { repoDir, configPath, lockPath, workDir };
}

/** Stubbed makeOverlay that records its inputs but creates no real disks. */
function stubOverlay(workDir: string, capture?: {
  calls: Array<Parameters<NonNullable<RunAuditInput['makeOverlay']>>[0]>;
  cleanups: number;
}): NonNullable<RunAuditInput['makeOverlay']> {
  return async (opts) => {
    capture?.calls.push(opts);
    return {
      rootfsCopyPath: join(workDir, 'rootfs.ext4'),
      repoDiskPath: join(workDir, 'repo.ext4'),
      scratchDiskPath: join(workDir, 'scratch.ext4'),
      sjtmpDiskPath: join(workDir, 'sjtmp.ext4'),
      workDir,
      cleanup: async () => {
        if (capture !== undefined) capture.cleanups++;
      },
    };
  };
}

/** Default IO sinks; tests that need to assert on writes hold the refs. */
function makeIo(over: Partial<RunAuditIo> = {}): {
  io: RunAuditIo;
  stdout: Sink;
  stderr: Sink;
  warnings: string[];
} {
  const stdout = new Sink();
  const stderr = new Sink();
  const warnings: string[] = [];
  const io: RunAuditIo = {
    warn: (msg) => warnings.push(msg),
    stdout,
    stderr,
    ...over,
  };
  return { io, stdout, stderr, warnings };
}

function baseInput(launch: RunAuditInput['launch'], over: Partial<RunAuditInput> = {}): RunAuditInput {
  const { repoDir, configPath, lockPath, workDir } = setupRepo();
  const { io } = makeIo();
  return {
    repoDir,
    configPath,
    lockPath,
    mode: 'update',
    overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
    pm: 'pnpm',
    hostArch: 'x64',
    baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
    workDir,
    launch,
    io,
    makeOverlay: stubOverlay(workDir),
    ...over,
  };
}

describe('runAudit — update mode', () => {
  it('writes the generated YAML to lockPath and returns exitCode 0', async () => {
    const input = baseInput(async () => ({
      finalYaml: 'pkg: demo\ngenerated_at: 2024-01-01T00:00:00Z\n',
      nonFatalWarnings: [],
    }));
    const result = await runAudit(input);
    expect(result.exitCode).toBe(0);
    const written = readFileSync(input.lockPath, 'utf8');
    expect(written).toBe('pkg: demo\ngenerated_at: 2024-01-01T00:00:00Z\n');
  });

  it('emits a stderr diagnostic with the byte count after a successful write', async () => {
    const yaml = 'pkg: demo\n';
    const { io, stderr } = makeIo();
    const input = baseInput(async () => ({ finalYaml: yaml, nonFatalWarnings: [] }), { io });
    await runAudit(input);
    expect(stderr.text).toMatch(/\[script-jail\] wrote \d+ bytes to/);
  });

  it('routes setOutput("lockfile", ...) and setOutput("diff", "") in update mode', async () => {
    const outputs: Record<string, string> = {};
    const { io } = makeIo({
      setOutput: (name, value) => { outputs[name] = value; },
    });
    const input = baseInput(async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] }), { io });
    await runAudit(input);
    expect(outputs['lockfile']).toBe(input.lockPath);
    expect(outputs['diff']).toBe('');
  });
});

describe('runAudit — check mode', () => {
  function lockYaml(extraPackages: Record<string, unknown> = {}): string {
    // Minimal but parseable shape that satisfies the schema's optional
    // `packages` map.  findAuditBypass tolerates missing fields.
    return [
      'schema_version: 1',
      'generated_at: <ts>',
      'manager: pnpm',
      'manager_lockfile_sha256: <hash>',
      'packages:',
      ...Object.entries(extraPackages).map(([id, body]) => {
        return `  ${id}:\n${String(body).split('\n').map((l) => l.length > 0 ? `    ${l}` : l).join('\n')}`;
      }),
    ].join('\n') + '\n';
  }

  it('returns exitCode 0 when generated matches committed', async () => {
    const yaml = lockYaml();
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    writeFileSync(lockPath, yaml);
    const result = await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'check',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: yaml, nonFatalWarnings: [] }),
      io: makeIo().io,
      makeOverlay: stubOverlay(workDir),
    });
    expect(result.exitCode).toBe(0);
  });

  it('returns exitCode 1 and writes a unified diff when committed drifts', async () => {
    const committed = lockYaml();
    const generated = lockYaml() + '# extra trailing comment line\n';
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    writeFileSync(lockPath, committed);
    const { io, stdout } = makeIo();
    const result = await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'check',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: generated, nonFatalWarnings: [] }),
      io,
      makeOverlay: stubOverlay(workDir),
    });
    expect(result.exitCode).toBe(1);
    expect(stdout.text).toContain('# extra trailing comment line');
    // The annotation form is checked by the diff module's own tests; here we
    // just verify it was emitted.
    expect(stdout.text).toMatch(/::error file=.*\.script-jail\.lock\.yml/);
  });

  it('fires the audit-bypass gate when the generated lockfile carries <EXEC_FAIL_OPEN> entries', async () => {
    const yaml = [
      'schema_version: 1',
      'generated_at: <ts>',
      'manager: pnpm',
      'manager_lockfile_sha256: <hash>',
      'packages:',
      '  malicious@1.0.0:',
      '    lifecycle:',
      '      postinstall:',
      '        audit_bypass:',
      '          - "<EXEC_FAIL_OPEN> /usr/bin/curl"',
      '',
    ].join('\n');
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    // Pre-commit the SAME bypass-carrying lockfile so the byte-equal diff
    // returns match:true — proving the gate fires INDEPENDENTLY of the diff.
    writeFileSync(lockPath, yaml);
    const { io, stderr } = makeIo();
    let annotationLabel: string | null = null;
    let annotationMsg: string | null = null;
    io.emitAuditBypassAnnotation = (label, msg) => {
      annotationLabel = label;
      annotationMsg = msg;
    };
    const result = await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'check',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: yaml, nonFatalWarnings: [] }),
      io,
      makeOverlay: stubOverlay(workDir),
    });
    expect(result.exitCode).toBe(1);
    expect(stderr.text).toMatch(/Audit envelope was bypassed/);
    expect(annotationMsg).toMatch(/Audit envelope was bypassed/);
    // Path label should be relative when the lockfile is inside the repo.
    expect(annotationLabel).toBe('.script-jail.lock.yml');
  });

  it('does NOT emit a GH annotation when io.emitAuditBypassAnnotation is undefined (CLI path)', async () => {
    const yaml = [
      'schema_version: 1',
      'packages:',
      '  malicious@1.0.0:',
      '    lifecycle:',
      '      postinstall:',
      '        audit_bypass:',
      '          - "<EXEC_FAIL_OPEN> /usr/bin/curl"',
      '',
    ].join('\n');
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    writeFileSync(lockPath, yaml);
    const { io, stderr, stdout } = makeIo(); // emitAuditBypassAnnotation undefined
    const result = await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'check',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: yaml, nonFatalWarnings: [] }),
      io,
      makeOverlay: stubOverlay(workDir),
    });
    expect(result.exitCode).toBe(1);
    // Stderr message still fires — that's the cross-entry security signal.
    expect(stderr.text).toMatch(/Audit envelope was bypassed/);
    // But no ::error file=...:: annotation appears in stdout.
    expect(stdout.text).not.toMatch(/::error file=/);
  });
});

describe('runAudit — arch-flag overlay fan-out', () => {
  it('forwards every warning from buildArchFlagOverlay to io.warn', async () => {
    const { io, warnings } = makeIo();
    const input = baseInput(async () => ({ finalYaml: '', nonFatalWarnings: [] }), {
      io,
      pm: 'yarn',
      hostArch: 'arm64',
      buildArchFlagOverlay: () => ({
        warnings: ['first warning', 'second warning'],
      }),
    });
    await runAudit(input);
    expect(warnings).toEqual(['first warning', 'second warning']);
  });

  it('passes hostArch from the input verbatim to buildArchFlagOverlay (no process.arch leak)', async () => {
    let captured: { pm: string; hostArch: string } | null = null;
    const input = baseInput(async () => ({ finalYaml: '', nonFatalWarnings: [] }), {
      pm: 'pnpm',
      hostArch: 'arm64',
      buildArchFlagOverlay: ({ pm, hostArch }) => {
        captured = { pm, hostArch };
        return { warnings: [] };
      },
    });
    await runAudit(input);
    expect(captured).toEqual({ pm: 'pnpm', hostArch: 'arm64' });
  });

  it('passes effective spoof platform/arch to buildArchFlagOverlay so spoofed PM resolution is corrected', async () => {
    let captured: {
      pm: string;
      hostArch: string;
      spoofPlatform: string | undefined;
      spoofArch: string | undefined;
    } | null = null;
    const input = baseInput(async () => ({ finalYaml: '', nonFatalWarnings: [] }), {
      pm: 'pnpm',
      hostArch: 'x64',
      overrides: { spoofPlatform: 'linux', spoofArch: 'arm64' },
      buildArchFlagOverlay: ({ pm, hostArch, spoofPlatform, spoofArch }) => {
        captured = { pm, hostArch, spoofPlatform, spoofArch };
        return { warnings: [] };
      },
    });
    await runAudit(input);
    expect(captured).toEqual({
      pm: 'pnpm',
      hostArch: 'x64',
      spoofPlatform: 'linux',
      spoofArch: 'arm64',
    });
  });

  it('threads yarnrcOverlay / pmFlagsJson into extraRepoOverlayFiles when buildArchFlagOverlay returns them', async () => {
    const calls: Array<Parameters<NonNullable<RunAuditInput['makeOverlay']>>[0]> = [];
    const capture = { calls, cleanups: 0 };
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'update',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'arm64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] }),
      io: makeIo().io,
      makeOverlay: stubOverlay(workDir, capture),
      buildArchFlagOverlay: () => ({
        warnings: [],
        pmFlagsJson: { extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] },
      }),
    });
    expect(capture.calls).toHaveLength(1);
    const extras = capture.calls[0]!.extraRepoOverlayFiles;
    expect(extras).toBeDefined();
    expect(extras!.some((e) => e.relPath === 'etc/script-jail/pm-flags.json')).toBe(true);
  });

  it('threads pnpmArchOverlay into extraRepoOverlayFiles as etc/script-jail/pnpm-arch.json', async () => {
    const calls: Array<Parameters<NonNullable<RunAuditInput['makeOverlay']>>[0]> = [];
    const capture = { calls, cleanups: 0 };
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    const archJson =
      '{\n  "supportedArchitectures": {\n    "os": ["linux"],\n' +
      '    "cpu": ["x64"],\n    "libc": ["glibc"]\n  }\n}\n';
    await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'update',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'arm64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] }),
      io: makeIo().io,
      makeOverlay: stubOverlay(workDir, capture),
      buildArchFlagOverlay: () => ({ warnings: [], pnpmArchOverlay: archJson }),
    });
    expect(capture.calls).toHaveLength(1);
    const extras = capture.calls[0]!.extraRepoOverlayFiles;
    expect(extras).toBeDefined();
    const archEntry = extras!.find(
      (e) => e.relPath === 'etc/script-jail/pnpm-arch.json',
    );
    expect(archEntry).toBeDefined();
    // pnpm-style pmFlagsJson must NOT also appear.
    expect(extras!.some((e) => e.relPath === 'etc/script-jail/pm-flags.json')).toBe(false);
    expect(archEntry!.content).toBe(archJson);
  });
});

describe('runAudit — overlay cleanup', () => {
  it('calls overlay.cleanup() after a successful launch', async () => {
    const capture: {
      calls: Array<Parameters<NonNullable<RunAuditInput['makeOverlay']>>[0]>;
      cleanups: number;
    } = { calls: [], cleanups: 0 };
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    await runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'update',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => ({ finalYaml: 'x: 1\n', nonFatalWarnings: [] }),
      io: makeIo().io,
      makeOverlay: stubOverlay(workDir, capture),
    });
    expect(capture.cleanups).toBe(1);
  });

  it('calls overlay.cleanup() even when launch() throws', async () => {
    const capture: {
      calls: Array<Parameters<NonNullable<RunAuditInput['makeOverlay']>>[0]>;
      cleanups: number;
    } = { calls: [], cleanups: 0 };
    const { repoDir, configPath, lockPath, workDir } = setupRepo();
    await expect(runAudit({
      repoDir, configPath, lockPath, workDir,
      mode: 'update',
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      pm: 'pnpm', hostArch: 'x64',
      baseRootfsPath: join(testDir, 'rootfs-base.ext4'),
      launch: async () => { throw new Error('launch boom'); },
      io: makeIo().io,
      makeOverlay: stubOverlay(workDir, capture),
    })).rejects.toThrow(/launch boom/);
    expect(capture.cleanups).toBe(1);
  });
});

describe('runAudit — launcher contract', () => {
  it('passes the OverlayResult from makeOverlay to launch() verbatim', async () => {
    let captured: { rootfsCopyPath: string } | null = null;
    const input = baseInput(async (overlay) => {
      captured = { rootfsCopyPath: overlay.rootfsCopyPath };
      return { finalYaml: '', nonFatalWarnings: [] };
    });
    await runAudit(input);
    expect(captured).not.toBeNull();
    expect(captured!.rootfsCopyPath).toMatch(/rootfs\.ext4$/);
  });
});

describe('runAudit — scratch dir isolation', () => {
  // Regression for Codex review finding: a previous draft passed `cwd` as
  // workDir from the CLI, which made buildEffectiveConfig write
  // `config.yml` / `.yarnrc.yml` / `etc/script-jail/pm-flags.json` into the
  // user's repo.  runAudit now mkdtemps under workDir and removes the
  // private dir in `finally`, so the workDir parent itself stays clean
  // even if a caller passes a long-lived directory.
  it('does NOT write config.yml or pm-flags.json directly into workDir', async () => {
    const { readdirSync } = await import('node:fs');
    const input = baseInput(async () => ({ finalYaml: '', nonFatalWarnings: [] }));
    const beforeEntries = new Set(readdirSync(input.workDir));
    await runAudit(input);
    const afterEntries = readdirSync(input.workDir).filter((e) => !beforeEntries.has(e));
    // Nothing left behind at all (mkdtemp dir was removed).
    expect(afterEntries).toEqual([]);
  });

  it('cleans up the private scratch dir even when launch() throws', async () => {
    const { readdirSync } = await import('node:fs');
    const input = baseInput(async () => { throw new Error('launch boom'); });
    const beforeEntries = new Set(readdirSync(input.workDir));
    await expect(runAudit(input)).rejects.toThrow(/launch boom/);
    const afterEntries = readdirSync(input.workDir).filter((e) => !beforeEntries.has(e));
    expect(afterEntries).toEqual([]);
  });
});

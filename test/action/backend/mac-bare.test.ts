import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

import {
  createMacBareExecute,
  MacBareUnavailableError,
  type MacBareExecuteDeps,
} from '../../../src/action/backend/mac-bare.js';
import type { AuditExecutionInput, LauncherResult } from '../../../src/shared/run-audit.js';
import type { ProvisionedNodeMac } from '../../../src/cli/provision-node-mac.js';

const RESULT: LauncherResult = { finalYaml: 'schema: 1\n', nonFatalWarnings: [] };

const PROVISIONED: ProvisionedNodeMac = {
  nodeBinDir: '/fake/node/bin',
  nodePath: '/fake/node/bin/node',
  shellShimDir: '/fake/shims',
  nodeVersion: '24.16.0',
  preResignSha256: 'a'.repeat(64),
};

// Every seam defaults to a VALID darwin-arm64 environment; each test overrides
// ONE dimension to exercise a single precondition branch in isolation.
function makeDeps(over: Partial<MacBareExecuteDeps> = {}): MacBareExecuteDeps {
  return {
    imagesDir: '/fake/images',
    repoRoot: '/fake/repo',
    arch: 'arm64',
    platform: 'darwin',
    existsSync: (() => true) as unknown as NonNullable<MacBareExecuteDeps['existsSync']>,
    validateMachOShimFile: (() => null) as unknown as NonNullable<MacBareExecuteDeps['validateMachOShimFile']>,
    provisionNodeMac: (async () => PROVISIONED) as unknown as NonNullable<MacBareExecuteDeps['provisionNodeMac']>,
    runAgentProcess: (async () => RESULT) as unknown as NonNullable<MacBareExecuteDeps['runAgentProcess']>,
    ...over,
  };
}

function makeInput(over: Partial<AuditExecutionInput> = {}): AuditExecutionInput {
  return {
    repoDir: '/nonexistent/repo',
    configPath: '/nonexistent/config.yml',
    extraRepoOverlayFiles: [],
    scratchDir: '/nonexistent/scratch',
    pm: 'npm',
    hostArch: 'arm64',
    mode: 'check',
    ...over,
  };
}

describe('createMacBareExecute — fail-closed preconditions', () => {
  it('rejects on a non-darwin host', async () => {
    const exec = createMacBareExecute(makeDeps({ platform: 'linux' }));
    await expect(exec(makeInput())).rejects.toBeInstanceOf(MacBareUnavailableError);
    await expect(exec(makeInput())).rejects.toThrow(/requires macOS/);
  });

  it('hard-fails when the Mach-O shim dylib is absent (no silent empty lock)', async () => {
    // existsSync true for everything EXCEPT the dylib, so guest-agent / preload
    // resolution still succeeds and the failure is specifically "shim absent".
    const exec = createMacBareExecute(
      makeDeps({
        existsSync: ((p: unknown) =>
          !String(p).includes('libscriptjail')) as unknown as NonNullable<MacBareExecuteDeps['existsSync']>,
      }),
    );
    await expect(exec(makeInput())).rejects.toThrow(/shim not found/i);
  });

  it('hard-fails when a bundled runtime file cannot be resolved (guest-agent / preloads)', async () => {
    // resolveRuntimePaths walks the same root-candidate list for all three
    // bundled JS artifacts (root/<name> and root/dist/[preloads/]<name> across
    // SCRIPT_JAIL_ACTION_ROOT / GITHUB_ACTION_PATH / repoRoot / repoRoot/.. /
    // cwd), so one loop covers them; each iteration blanks exactly ONE file so
    // the MacBareUnavailableError must name the missing artifact.
    for (const missing of ['guest-agent.cjs', 'platform-spoof.cjs', 'env-spy.cjs']) {
      const exec = createMacBareExecute(
        makeDeps({
          existsSync: ((p: unknown) =>
            !String(p).includes(missing)) as unknown as NonNullable<MacBareExecuteDeps['existsSync']>,
        }),
      );
      const err = await exec(makeInput()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(MacBareUnavailableError);
      expect(String((err as Error).message)).toContain(`${missing} was not found`);
    }
  });

  it('hard-fails when the dylib is PRESENT but BROKEN — R2 present-but-invalid guard', async () => {
    // The shim is the sole event source on macOS; a present-but-unloadable
    // dylib (wrong arch / ELF / fat / no __interpose) would otherwise produce a
    // clean-looking EMPTY lock.  validateMachOShimFile returning non-null must
    // hard-fail BEFORE any provisioning / staging happens.
    let provisioned = false;
    const exec = createMacBareExecute(
      makeDeps({
        validateMachOShimFile: (() =>
          'wrong architecture: got x86-64 (CPU_TYPE_X86_64), expected arm64 (CPU_TYPE_ARM64)') as unknown as NonNullable<MacBareExecuteDeps['validateMachOShimFile']>,
        provisionNodeMac: (async () => {
          provisioned = true;
          return PROVISIONED;
        }) as unknown as NonNullable<MacBareExecuteDeps['provisionNodeMac']>,
      }),
    );
    const err = await exec(makeInput()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MacBareUnavailableError);
    expect(String((err as Error).message)).toMatch(/is unusable/);
    expect(String((err as Error).message)).toMatch(/wrong architecture/);
    // It must fail BEFORE the expensive provision step.
    expect(provisioned).toBe(false);
  });
});

describe('createMacBareExecute — valid shim flows through', () => {
  const tmps: string[] = [];
  function tmp(prefix: string): string {
    const d = mkdtempSync(join(tmpdir(), prefix));
    tmps.push(d);
    return d;
  }
  afterEach(() => {
    for (const d of tmps.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it('a VALID shim reaches runAgentProcess with the macos-bare env contract', async () => {
    const repoDir = tmp('mb-repo-');
    writeFileSync(join(repoDir, 'package.json'), '{"name":"x"}\n');
    const scratchDir = tmp('mb-scratch-');
    const configPath = join(scratchDir, 'config.yml');
    writeFileSync(configPath, 'manager: npm\nwork_dir: /orig\n');

    let capturedEnv: NodeJS.ProcessEnv | null = null;
    let capturedCmd: string | null = null;
    const exec = createMacBareExecute(
      makeDeps({
        env: { PATH: '/usr/bin:/bin' },
        runAgentProcess: ((opts: { cmd: string; env: NodeJS.ProcessEnv }) => {
          capturedCmd = opts.cmd;
          capturedEnv = opts.env;
          return Promise.resolve(RESULT);
        }) as unknown as NonNullable<MacBareExecuteDeps['runAgentProcess']>,
      }),
    );

    const out = await exec(makeInput({ repoDir, scratchDir, configPath }));
    expect(out).toEqual(RESULT);

    // Runs UNDER the re-signed node so the shim can inject into children.
    expect(capturedCmd).toBe(PROVISIONED.nodePath);

    const env = capturedEnv as unknown as NodeJS.ProcessEnv;
    expect(env['SCRIPT_JAIL_BACKEND']).toBe('macos-bare');
    expect(env['SCRIPT_JAIL_CONNECTION']).toBe('stdio');
    expect(env['SCRIPT_JAIL_NATIVE_PRELOAD_PATH']).toMatch(/libscriptjail-arm64\.dylib$/);
    expect(env['SCRIPT_JAIL_SHELL_SHIM_DIR']).toBe(PROVISIONED.shellShimDir);
    // The install/repo root keep-root (is_external_system_tool #6): the shim
    // captures SCRIPT_JAIL_WORK_DIR at ctor so top-level node_modules/.bin
    // helpers stay audited after a lifecycle chdir.  It MUST equal the rewritten
    // backend config's work_dir (the staged repo), so the agent's config.work_dir
    // and the shim's CANON_WORK_DIR anchor are the SAME tree.
    const workDir = env['SCRIPT_JAIL_WORK_DIR'];
    expect(workDir).toBeDefined();
    expect(workDir!.startsWith(scratchDir + '/')).toBe(true);
    const backendConfig = parseYaml(
      readFileSync(join(scratchDir, 'config.backend.yml'), 'utf8'),
    ) as { work_dir?: string };
    expect(workDir).toBe(backendConfig.work_dir);
    // Observe-only: macOS bare stays ONLINE — it must NOT drop the network.
    expect(env['SCRIPT_JAIL_PHASE_B_UNSHARE_NET']).toBeUndefined();
    // Provisioned bin dir is PREPENDED so bare npm/pnpm/yarn resolve to it.
    expect((env['PATH'] ?? '').startsWith(PROVISIONED.nodeBinDir + ':')).toBe(true);
  });
});

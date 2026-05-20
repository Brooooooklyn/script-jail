// script-jail — test/scripts/build-vmlinux-vz.test.ts
//
// Argument-parsing and host-platform-branching tests for the VZ kernel
// builder, `images/kernel/build.sh`.  We intentionally do NOT exercise the
// real build path here — building a Linux kernel takes 30+ minutes and
// pulls in a full kernel toolchain (flex, bison, libelf-dev, libssl-dev,
// gcc-aarch64-linux-gnu when cross-building).  Real builds happen in CI
// from the release workflow.
//
// What this suite covers:
//   - missing --arch flag → exit 2 with a usage hint
//   - --arch=foobar      → exit 2 with the accepted-values list
//   - --arch=x86_64 / --arch=arm64 are recognised as valid args (no parse
//     error — the script may still bail later for a missing toolchain,
//     but the argument-parsing branch must accept it cleanly)
//   - Darwin host       → exit 2 with the "use the release CI" message

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const repoRoot = new URL('../../', import.meta.url).pathname.replace(
  /\/$/,
  '',
);
const SCRIPT = join(repoRoot, 'images/kernel/build.sh');

beforeAll(() => {
  if (!existsSync(SCRIPT)) {
    throw new Error(
      `Expected build script at ${SCRIPT}; PR 5 ships this file.`,
    );
  }
});

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runScript(
  args: string[],
  env: Record<string, string> = {},
): RunResult {
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

describe('images/kernel/build.sh — argument parsing', () => {
  it('exits 2 when --arch is missing', () => {
    // SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST=linux forces the Darwin-branch
    // skip so we exercise the arg-parsing logic regardless of which OS
    // runs the test.
    const r = runScript([], { SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST: 'linux' });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--arch/);
  });

  it('exits 2 when --arch is an unrecognised value', () => {
    const r = runScript(['--arch=mips'], {
      SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST: 'linux',
    });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--arch/);
    expect(r.stderr).toMatch(/x86_64/);
    expect(r.stderr).toMatch(/arm64/);
  });

  it('accepts --arch=x86_64 as a valid value (no parse error)', () => {
    // We stop the script before the actual kernel build via the
    // SCRIPT_JAIL_KERNEL_BUILD_DRY_RUN=1 sentinel — the script must echo
    // a recognisable "would build" line and exit 0.  This decouples the
    // arg-parsing test from the existence of a kernel toolchain.
    const r = runScript(['--arch=x86_64'], {
      SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST: 'linux',
      SCRIPT_JAIL_KERNEL_BUILD_DRY_RUN: '1',
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/x86_64/);
    expect(r.stdout).toMatch(/(dry-run|DRY RUN)/i);
  });

  it('accepts --arch=arm64 as a valid value (no parse error)', () => {
    const r = runScript(['--arch=arm64'], {
      SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST: 'linux',
      SCRIPT_JAIL_KERNEL_BUILD_DRY_RUN: '1',
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/arm64/);
    expect(r.stdout).toMatch(/(dry-run|DRY RUN)/i);
  });
});

describe('images/kernel/build.sh — host platform gating', () => {
  it('exits 2 on a Darwin host with a "use the release CI" message', () => {
    const r = runScript(['--arch=x86_64'], {
      SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST: 'darwin',
    });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/darwin|macOS|Linux container/i);
    expect(r.stderr).toMatch(/release|CI/i);
  });
});

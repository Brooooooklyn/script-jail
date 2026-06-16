// script-jail — test/action/config-override.test.ts
//
// Tests for `buildEffectiveConfig`.  Each test writes a user-config YAML to
// a fresh tmpdir, calls the helper with explicit overrides, and reads back
// the result to assert:
//   - spoof.platform / spoof.arch reflect the action input (override wins
//     over whatever was on disk)
//   - all other top-level keys are preserved verbatim
//   - the source file is never mutated
//   - the returned path is absolute and under the supplied workDir

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';
import { parse as parseYaml } from 'yaml';

import { buildEffectiveConfig } from '../../src/action/config-override.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let testDir: string;
let userConfigPath: string;
let workDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'script-jail-cfg-override-'));
  userConfigPath = join(testDir, '.script-jail.yml');
  workDir = join(testDir, 'work');
  mkdirSync(workDir, { recursive: true });
});

afterEach(() => {
  try { rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

const FULL_USER_YAML = `
protected:
  files:
    - ~/.ssh/**
    - $REPO/.env
  env:
    - NPM_TOKEN
    - GITHUB_TOKEN

spoof:
  platform: linux
  arch: x64

node_version: 20
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('buildEffectiveConfig', () => {
  it('overrides spoof.platform with the action input (darwin) and preserves siblings', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'darwin', spoofArch: 'arm64' },
      workDir,
    });

    expect(isAbsolute(result.configPath)).toBe(true);
    expect(result.configPath.startsWith(workDir)).toBe(true);
    expect(result.yarnrcPath).toBeUndefined();
    expect(result.pmFlagsPath).toBeUndefined();
    expect(result.pnpmArchPath).toBeUndefined();

    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({ platform: 'darwin', arch: 'arm64' });

    // Sibling keys preserved.
    expect(parsed['node_version']).toBe(20);
    expect(parsed['protected']).toEqual({
      files: ['~/.ssh/**', '$REPO/.env'],
      env: ['NPM_TOKEN', 'GITHUB_TOKEN'],
    });
  });

  it('overrides spoof.arch independently (linux + arm64)', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'linux', spoofArch: 'arm64' },
      workDir,
    });

    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({ platform: 'linux', arch: 'arm64' });
  });

  it('pins work_dir to workDirOverride (install:true cwd parity) and leaves it unset otherwise', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    // No override -> work_dir absent (guest schema default /work stands).
    const without = parseYaml(
      readFileSync(
        buildEffectiveConfig({
          userConfigPath,
          overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
          workDir,
        }).configPath,
        'utf8',
      ),
    ) as Record<string, unknown>;
    expect(without['work_dir']).toBeUndefined();

    // Override -> the runner-specific repoDir is written verbatim (it is
    // tokenized to $REPO in the lock, so this stays byte-stable).
    const repoDir = '/home/runner/work/myrepo/myrepo';
    const withOverride = parseYaml(
      readFileSync(
        buildEffectiveConfig({
          userConfigPath,
          overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
          workDir,
          workDirOverride: repoDir,
        }).configPath,
        'utf8',
      ),
    ) as Record<string, unknown>;
    expect(withOverride['work_dir']).toBe(repoDir);
    // Siblings still preserved alongside the pinned work_dir.
    expect(withOverride['node_version']).toBe(20);
  });

  it('never mutates the user source file', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');
    const before = readFileSync(userConfigPath, 'utf8');

    buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'win32', spoofArch: 'x64' },
      workDir,
    });

    const after = readFileSync(userConfigPath, 'utf8');
    expect(after).toBe(before);
  });

  it('adds a spoof block when the user config has none', () => {
    writeFileSync(userConfigPath, 'node_version: 20\n', 'utf8');

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'darwin', spoofArch: 'x64' },
      workDir,
    });

    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({ platform: 'darwin', arch: 'x64' });
    expect(parsed['node_version']).toBe(20);
  });

  it('preserves unknown sibling keys inside spoof block (forward-compat)', () => {
    writeFileSync(
      userConfigPath,
      'spoof:\n  platform: linux\n  arch: x64\n  future_field: keep_me\n',
      'utf8',
    );

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'darwin', spoofArch: 'arm64' },
      workDir,
    });

    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({
      platform: 'darwin',
      arch: 'arm64',
      future_field: 'keep_me',
    });
  });

  it('handles an empty/null YAML document by writing a config containing only spoof', () => {
    writeFileSync(userConfigPath, '', 'utf8');

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'darwin', spoofArch: 'arm64' },
      workDir,
    });

    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({ platform: 'darwin', arch: 'arm64' });
  });

  it('creates its own tmpdir when no workDir is supplied', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'darwin', spoofArch: 'x64' },
    });

    expect(isAbsolute(result.configPath)).toBe(true);
    // Sanity: the file exists and contains the override.
    const parsed = parseYaml(readFileSync(result.configPath, 'utf8')) as Record<string, unknown>;
    expect(parsed['spoof']).toEqual({ platform: 'darwin', arch: 'x64' });

    // Best-effort cleanup of the auto-created tmpdir.
    try {
      const parent = result.configPath.slice(0, result.configPath.lastIndexOf('/'));
      rmSync(parent, { recursive: true, force: true });
    } catch { /* ignore */ }
  });

  it('writes .yarnrc.yml to the workDir when yarnrcOverlay is provided', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const overlay =
      'supportedArchitectures:\n  os:\n    - linux\n  cpu:\n    - x64\n';
    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      workDir,
      yarnrcOverlay: overlay,
    });

    expect(result.yarnrcPath).toBeDefined();
    expect(isAbsolute(result.yarnrcPath as string)).toBe(true);
    expect((result.yarnrcPath as string).startsWith(workDir)).toBe(true);
    expect(readFileSync(result.yarnrcPath as string, 'utf8')).toBe(overlay);
  });

  it('writes pm-flags.json under etc/script-jail/ when pmFlagsJson is provided', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const flags = { extra_install_args: ['--cpu=x64', '--os=linux', '--libc=glibc'] };
    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      workDir,
      pmFlagsJson: flags,
    });

    expect(result.pmFlagsPath).toBeDefined();
    expect((result.pmFlagsPath as string).startsWith(workDir)).toBe(true);
    expect((result.pmFlagsPath as string)).toMatch(/etc\/script-jail\/pm-flags\.json$/);
    const parsed = JSON.parse(readFileSync(result.pmFlagsPath as string, 'utf8')) as Record<string, unknown>;
    expect(parsed).toEqual(flags);
  });

  it('writes pnpm-arch.json under etc/script-jail/ when pnpmArchOverlay is provided', () => {
    writeFileSync(userConfigPath, FULL_USER_YAML, 'utf8');

    const overlay =
      '{\n' +
      '  "supportedArchitectures": {\n' +
      '    "os": ["linux"],\n' +
      '    "cpu": ["x64"],\n' +
      '    "libc": ["glibc"]\n' +
      '  }\n' +
      '}\n';
    const result = buildEffectiveConfig({
      userConfigPath,
      overrides: { spoofPlatform: 'linux', spoofArch: 'x64' },
      workDir,
      pnpmArchOverlay: overlay,
    });

    expect(result.pnpmArchPath).toBeDefined();
    expect((result.pnpmArchPath as string).startsWith(workDir)).toBe(true);
    expect((result.pnpmArchPath as string)).toMatch(/etc\/script-jail\/pnpm-arch\.json$/);
    // Written verbatim — byte-stable hand-formatted JSON.
    expect(readFileSync(result.pnpmArchPath as string, 'utf8')).toBe(overlay);
  });
});

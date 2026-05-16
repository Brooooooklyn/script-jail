// Tests for src/guest/platform-spoof.cjs
// Forks child Node processes with NODE_OPTIONS=--require to test the preload.

import { describe, it, expect } from 'vitest';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(__dirname, '../../src/guest/platform-spoof.cjs');

/** Write a small CJS helper script to tmp and return its path. */
function writeChildScript(code: string): string {
  const dir = join(tmpdir(), 'npm-jar-test');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `child-${Date.now()}-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(path, `'use strict';\n${code}\n`);
  return path;
}

/** Fork a child that runs `code` with the platform-spoof preload applied.
 *  Returns parsed stdout JSON. */
async function runWithSpoof(
  code: string,
  env: Record<string, string>,
): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const script = writeChildScript(code);
    const child = fork(script, [], {
      env: {
        ...process.env,
        ...env,
        NODE_OPTIONS: `--require=${preloadPath}`,
      },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });

    let stdout = '';
    child.stdout?.on('data', (c: Buffer) => { stdout += c.toString(); });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Child exited with code ${String(code)}: ${stdout}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout.trim()) as Record<string, string>);
      } catch (e) {
        reject(new Error(`Failed to parse child stdout: ${stdout}`));
      }
    });
  });
}

const PROBE_CODE = `
const os = require('os');
process.stdout.write(JSON.stringify({
  platform: process.platform,
  arch: process.arch,
  osPlatform: os.platform(),
  osArch: os.arch(),
  osType: os.type(),
  osRelease: os.release(),
  osEndianness: os.endianness(),
}));
`;

describe('platform-spoof preload', () => {
  it('linux + x64 (no-op defaults): values should be overridden to linux/x64', async () => {
    const out = await runWithSpoof(PROBE_CODE, {
      NPM_JAR_SPOOF_PLATFORM: 'linux',
      NPM_JAR_SPOOF_ARCH: 'x64',
    });
    expect(out['platform']).toBe('linux');
    expect(out['arch']).toBe('x64');
    expect(out['osPlatform']).toBe('linux');
    expect(out['osArch']).toBe('x64');
    expect(out['osType']).toBe('Linux');
    expect(out['osRelease']).toBe('4.0.0');
  });

  it('darwin + arm64: overrides to darwin/arm64', async () => {
    const out = await runWithSpoof(PROBE_CODE, {
      NPM_JAR_SPOOF_PLATFORM: 'darwin',
      NPM_JAR_SPOOF_ARCH: 'arm64',
    });
    expect(out['platform']).toBe('darwin');
    expect(out['arch']).toBe('arm64');
    expect(out['osPlatform']).toBe('darwin');
    expect(out['osArch']).toBe('arm64');
    expect(out['osType']).toBe('Darwin');
    expect(out['osRelease']).toBe('19.0.0');
  });

  it('win32 + x64: overrides to win32/x64', async () => {
    const out = await runWithSpoof(PROBE_CODE, {
      NPM_JAR_SPOOF_PLATFORM: 'win32',
      NPM_JAR_SPOOF_ARCH: 'x64',
    });
    expect(out['platform']).toBe('win32');
    expect(out['arch']).toBe('x64');
    expect(out['osPlatform']).toBe('win32');
    expect(out['osType']).toBe('Windows_NT');
    expect(out['osRelease']).toBe('10.0.0');
  });

  it('endianness is LE for both x64 and arm64', async () => {
    for (const arch of ['x64', 'arm64'] as const) {
      const out = await runWithSpoof(PROBE_CODE, {
        NPM_JAR_SPOOF_PLATFORM: 'linux',
        NPM_JAR_SPOOF_ARCH: arch,
      });
      expect(out['osEndianness']).toBe('LE');
    }
  });

  it('no env vars → defaults to linux/x64', async () => {
    // Run without setting spoof env vars at all
    return new Promise<void>((resolve, reject) => {
      const script = writeChildScript(PROBE_CODE);
      const childEnv = { ...process.env };
      delete childEnv['NPM_JAR_SPOOF_PLATFORM'];
      delete childEnv['NPM_JAR_SPOOF_ARCH'];

      const child = fork(script, [], {
        env: { ...childEnv, NODE_OPTIONS: `--require=${preloadPath}` },
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      });

      let stdout = '';
      child.stdout?.on('data', (c: Buffer) => { stdout += c.toString(); });
      child.on('error', reject);
      child.on('exit', (code) => {
        if (code !== 0) { reject(new Error(`Child exited ${String(code)}`)); return; }
        const out = JSON.parse(stdout.trim()) as Record<string, string>;
        // defaults are linux/x64 — the preload doesn't break the process
        expect(out['platform']).toBe('linux');
        expect(out['arch']).toBe('x64');
        resolve();
      });
    });
  });

  it('overrides are visible in required modules loaded after the preload', async () => {
    // The preload modifies os module in-place; a module required later sees the patched values.
    const code = `
      const os = require('os');
      // Simulate a module that checks platform at load time
      const result = { platform: os.platform(), type: os.type() };
      process.stdout.write(JSON.stringify(result));
    `;
    const out = await runWithSpoof(code, {
      NPM_JAR_SPOOF_PLATFORM: 'darwin',
      NPM_JAR_SPOOF_ARCH: 'x64',
    });
    expect(out['platform']).toBe('darwin');
    expect(out['type']).toBe('Darwin');
  });
});

// Tests for src/guest/dlopen-block.cjs
// Forks child processes with the preload and checks that dlopen is blocked.

import { describe, it, expect } from 'vitest';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(__dirname, '../../src/guest/dlopen-block.cjs');

function writeChildScript(code: string): string {
  const dir = join(tmpdir(), 'script-jail-test');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `child-dlopen-${Date.now()}-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(path, `'use strict';\n${code}\n`);
  return path;
}

interface ChildResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  fd3Data?: string;
}

async function runWithBlock(
  code: string,
  env: Record<string, string | undefined> = {},
): Promise<ChildResult> {
  return new Promise((resolve, reject) => {
    const script = writeChildScript(code);

    // If extraFds is true, we set up an extra pipe on fd 3.
    // Node fork stdio: ['ignore','pipe','pipe','ipc'] — fd3 must be set differently.
    // For simplicity, we capture stderr which the child writes errors to.
    const child = fork(script, [], {
      env: {
        ...process.env,
        ...env,
        NODE_OPTIONS: `--require=${preloadPath}`,
      },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (c: Buffer) => { stdout += c.toString(); });
    child.stderr?.on('data', (c: Buffer) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('exit', (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });
  });
}

describe('dlopen-block preload', () => {
  it('process.dlopen throws with the expected message', async () => {
    const code = `
      try {
        process.dlopen({}, '/tmp/test.node');
        process.stdout.write(JSON.stringify({ threw: false }));
      } catch (e) {
        process.stdout.write(JSON.stringify({ threw: true, message: e.message }));
      }
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { threw: boolean; message: string };
    expect(out.threw).toBe(true);
    expect(out.message).toBe('script-jail: native addons are blocked at install time');
  });

  it('process.binding throws with the expected message', async () => {
    const code = `
      try {
        process.binding('fs');
        process.stdout.write(JSON.stringify({ threw: false }));
      } catch (e) {
        process.stdout.write(JSON.stringify({ threw: true, message: e.message }));
      }
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { threw: boolean; message: string };
    expect(out.threw).toBe(true);
    expect(out.message).toBe('script-jail: native addons are blocked at install time');
  });

  it('does not crash when SCRIPT_JAIL_LOG_FD is unset', async () => {
    const code = `
      try {
        process.dlopen({}, '/tmp/test.node');
      } catch (e) {
        process.stdout.write(JSON.stringify({ ok: true }));
      }
    `;
    const env: Record<string, string | undefined> = { ...process.env };
    delete env['SCRIPT_JAIL_LOG_FD'];
    const result = await runWithBlock(code, { SCRIPT_JAIL_LOG_FD: undefined });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
  });

  it('handles multiple dlopen calls each throwing', async () => {
    const code = `
      const errors = [];
      for (let i = 0; i < 3; i++) {
        try {
          process.dlopen({}, '/tmp/addon' + i + '.node');
        } catch (e) {
          errors.push(e.message);
        }
      }
      process.stdout.write(JSON.stringify({ count: errors.length, allSame: errors.every(m => m === errors[0]) }));
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { count: number; allSame: boolean };
    expect(out.count).toBe(3);
    expect(out.allSame).toBe(true);
  });

  it('does not crash when SCRIPT_JAIL_LOG_FD is an invalid (out-of-range) fd', async () => {
    // SCRIPT_JAIL_LOG_FD is read at preload load time. An invalid fd (e.g. 999)
    // causes writeSync to throw, which is caught internally. The throw from
    // process.dlopen still happens regardless of logging success.
    const code = `
      try {
        process.dlopen({}, '/tmp/my-addon.node');
      } catch (e) {
        // expected throw
      }
      process.stderr.write('DONE\\n');
    `;
    const result = await runWithBlock(code, { SCRIPT_JAIL_LOG_FD: '999' });
    // fd 999 is invalid but should not crash the process
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain('DONE');
  });

  it('process.dlopen is non-configurable after preload (cannot be redefined)', async () => {
    // After the preload runs, Object.defineProperty on process.dlopen should throw
    // TypeError because configurable: false prevents redefinition.
    const code = `
      try {
        Object.defineProperty(process, 'dlopen', { value: function() {} });
        process.stdout.write(JSON.stringify({ threw: false }));
      } catch (e) {
        process.stdout.write(JSON.stringify({ threw: true, name: e.constructor.name }));
      }
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { threw: boolean; name: string };
    expect(out.threw).toBe(true);
    expect(out.name).toBe('TypeError');
  });

  it('requiring the preload twice does not throw (idempotency)', async () => {
    // A child that requires the preload once explicitly (in addition to the NODE_OPTIONS
    // injection) must not throw a TypeError about redefining a non-configurable property.
    const code = `
      require(${JSON.stringify(preloadPath)});
      process.stdout.write(JSON.stringify({ ok: true }));
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
  });

  it('preload does not interfere with normal require calls', async () => {
    const code = `
      const path = require('path');
      const result = path.join('/a', 'b', 'c');
      process.stdout.write(JSON.stringify({ result }));
    `;
    const result = await runWithBlock(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { result: string };
    expect(out.result).toBe('/a/b/c');
  });
});

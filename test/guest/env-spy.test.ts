// Tests for src/guest/env-spy.cjs
// Forks child processes with the preload and checks that process.env reads
// are logged as JSONL events, and that protected names are hidden from the
// guest's view.

import { describe, it, expect } from 'vitest';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(__dirname, '../../src/guest/env-spy.cjs');

function writeChildScript(code: string): string {
  const dir = join(tmpdir(), 'script-jail-test');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `child-env-spy-${Date.now()}-${Math.random().toString(36).slice(2)}.cjs`);
  writeFileSync(path, `'use strict';\n${code}\n`);
  return path;
}

function freshLogFile(): string {
  const p = join(
    tmpdir(),
    `script-jail-events-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`,
  );
  writeFileSync(p, '');
  return p;
}

function freshProtectedFile(names: string[]): string {
  const p = join(
    tmpdir(),
    `script-jail-protected-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`,
  );
  writeFileSync(p, names.join('\n') + '\n');
  return p;
}

interface ChildResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function runWithSpy(
  code: string,
  env: Record<string, string | undefined> = {},
): Promise<ChildResult> {
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
    let stderr = '';
    child.stdout?.on('data', (c: Buffer) => { stdout += c.toString(); });
    child.stderr?.on('data', (c: Buffer) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('exit', (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });
  });
}

interface EnvReadLine {
  kind: string;
  name: string;
  pid: number;
  ts: number;
  hidden: boolean;
}

function readEnvReadLines(logFile: string): EnvReadLine[] {
  return readFileSync(logFile, 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((o) => o['kind'] === 'env_read') as unknown as EnvReadLine[];
}

describe('env-spy preload', () => {
  it('logs a process.env read as kind=env_read with the access name', async () => {
    const logFile = freshLogFile();
    const code = `
      const x = process.env.FOO;
      process.stdout.write(JSON.stringify({ value: x }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      FOO: 'bar',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { value: string };
    expect(out.value).toBe('bar');

    const lines = readEnvReadLines(logFile);
    const fooReads = lines.filter((l) => l.name === 'FOO');
    expect(fooReads.length).toBeGreaterThanOrEqual(1);
    expect(fooReads[0]!.hidden).toBe(false);
  });

  it('hides protected names: read returns undefined and is logged with hidden=true', async () => {
    const logFile = freshLogFile();
    const protectedFile = freshProtectedFile(['NPM_TOKEN']);
    const code = `
      const tok = process.env.NPM_TOKEN;
      // Treat the read as "undefined" explicitly so JSON survives.
      process.stdout.write(JSON.stringify({ tokIsUndefined: tok === undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedFile,
      NPM_TOKEN: 'super-secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { tokIsUndefined: boolean };
    expect(out.tokIsUndefined).toBe(true);

    const lines = readEnvReadLines(logFile);
    const tokenReads = lines.filter((l) => l.name === 'NPM_TOKEN');
    expect(tokenReads.length).toBeGreaterThanOrEqual(1);
    expect(tokenReads.every((l) => l.hidden === true)).toBe(true);
  });

  it('hides protected names from `in` and Object.keys / ownKeys', async () => {
    const logFile = freshLogFile();
    const protectedFile = freshProtectedFile(['NPM_TOKEN']);
    const code = `
      const has = 'NPM_TOKEN' in process.env;
      const keys = Object.keys(process.env);
      const descr = Object.getOwnPropertyDescriptor(process.env, 'NPM_TOKEN');
      process.stdout.write(JSON.stringify({
        has,
        included: keys.includes('NPM_TOKEN'),
        descrIsUndefined: descr === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedFile,
      NPM_TOKEN: 'super-secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as {
      has: boolean;
      included: boolean;
      descrIsUndefined: boolean;
    };
    expect(out.has).toBe(false);
    expect(out.included).toBe(false);
    expect(out.descrIsUndefined).toBe(true);
  });

  it('does not log when neither LOG_FILE nor LOG_FD is set', async () => {
    // Reads still happen; logging is silently skipped.
    const code = `
      const x = process.env.PATH;
      process.stdout.write(JSON.stringify({ ok: x !== undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: undefined,
      SCRIPT_JAIL_LOG_FD: undefined,
    });
    expect(result.exitCode).toBe(0);
  });

  it('does not crash when SCRIPT_JAIL_PROTECTED_ENV_FILE points to a missing path', async () => {
    const logFile = freshLogFile();
    const code = `
      const x = process.env.PATH;
      process.stdout.write(JSON.stringify({ ok: x !== undefined }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_FILE: '/nonexistent/path/protected.txt',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
    // Nothing protected — PATH read should be logged with hidden=false.
    const lines = readEnvReadLines(logFile);
    const pathReads = lines.filter((l) => l.name === 'PATH');
    expect(pathReads.length).toBeGreaterThanOrEqual(1);
    expect(pathReads.every((l) => l.hidden === false)).toBe(true);
  });

  it('requiring the preload twice does not throw (idempotency)', async () => {
    const code = `
      require(${JSON.stringify(preloadPath)});
      process.stdout.write(JSON.stringify({ ok: true }));
    `;
    const result = await runWithSpy(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { ok: boolean };
    expect(out.ok).toBe(true);
  });

  it('process.env Proxy is non-configurable (cannot be redefined)', async () => {
    const code = `
      try {
        Object.defineProperty(process, 'env', { value: {} });
        process.stdout.write(JSON.stringify({ threw: false }));
      } catch (e) {
        process.stdout.write(JSON.stringify({ threw: true, name: e.constructor.name }));
      }
    `;
    const result = await runWithSpy(code);
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { threw: boolean; name: string };
    expect(out.threw).toBe(true);
    expect(out.name).toBe('TypeError');
  });

  it('reads for unprotected names go through to the underlying value', async () => {
    const logFile = freshLogFile();
    const protectedFile = freshProtectedFile(['NPM_TOKEN']);
    const code = `
      const safe = process.env.SAFE_VAR;
      const tok = process.env.NPM_TOKEN;
      process.stdout.write(JSON.stringify({
        safe,
        tokHidden: tok === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedFile,
      SAFE_VAR: 'visible',
      NPM_TOKEN: 'secret',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { safe: string; tokHidden: boolean };
    expect(out.safe).toBe('visible');
    expect(out.tokHidden).toBe(true);
  });

  it('ignores comment lines (#) and blank lines in the protected-names file', async () => {
    const logFile = freshLogFile();
    const protectedFile = join(
      tmpdir(),
      `script-jail-protected-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`,
    );
    writeFileSync(
      protectedFile,
      '# comment line\n\nNPM_TOKEN\n# another comment\n  \nGITHUB_TOKEN\n',
    );
    const code = `
      const a = process.env.NPM_TOKEN;
      const b = process.env.GITHUB_TOKEN;
      process.stdout.write(JSON.stringify({
        aHidden: a === undefined,
        bHidden: b === undefined,
      }));
    `;
    const result = await runWithSpy(code, {
      SCRIPT_JAIL_LOG_FILE: logFile,
      SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedFile,
      NPM_TOKEN: 'x',
      GITHUB_TOKEN: 'y',
    });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { aHidden: boolean; bHidden: boolean };
    expect(out.aHidden).toBe(true);
    expect(out.bHidden).toBe(true);
  });

  it('symbol property access passes through without logging', async () => {
    const logFile = freshLogFile();
    const code = `
      const sym = Symbol.for('test-symbol');
      // Set and read a symbol key (not a string) — should NOT log env_read.
      const target = process.env;
      const v = target[sym];
      process.stdout.write(JSON.stringify({ vIsUndefined: v === undefined }));
    `;
    const result = await runWithSpy(code, { SCRIPT_JAIL_LOG_FILE: logFile });
    expect(result.exitCode).toBe(0);
    const out = JSON.parse(result.stdout) as { vIsUndefined: boolean };
    expect(out.vIsUndefined).toBe(true);
    // No env_read entry should reference a symbol — the preload skips non-string keys.
    const lines = readEnvReadLines(logFile);
    expect(lines.every((l) => typeof l.name === 'string')).toBe(true);
  });
});

import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';

import { parseFrames, type GuestFrame } from '../../shared/vsock-protocol.js';
import type { LauncherResult } from '../../shared/run-audit.js';

export function commandSucceeds(
  cmd: string,
  args: string[],
  opts: { env?: NodeJS.ProcessEnv } = {},
): boolean {
  const result = spawnSync(cmd, args, {
    stdio: 'ignore',
    env: opts.env,
  });
  return result.status === 0;
}

export function runCommand(
  cmd: string,
  args: string[],
  opts: { env?: NodeJS.ProcessEnv } = {},
): void {
  const result = spawnSync(cmd, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    env: opts.env,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(
      `${cmd} ${args.join(' ')} failed with exit ${result.status ?? 'unknown'}` +
        (detail ? `: ${detail}` : ''),
    );
  }
}

export async function runAgentProcess(input: {
  cmd: string;
  args: string[];
  env: NodeJS.ProcessEnv;
  cwd?: string;
  label: string;
  onFetchDone?: () => Promise<void>;
  stderr?: { write(s: string): unknown };
}): Promise<LauncherResult> {
  const child = spawn(input.cmd, input.args, {
    cwd: input.cwd,
    env: input.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  }) as ChildProcessWithoutNullStreams;

  const stderr = input.stderr ?? process.stderr;
  child.stderr.on('data', (chunk: Buffer) => {
    stderr.write(`[${input.label}:err] ${chunk.toString()}`);
  });

  const nonFatalWarnings: string[] = [];
  let finalYaml: string | null = null;
  let fatalError: Error | null = null;

  const exitPromise = new Promise<number>((resolve) => {
    child.on('close', (code) => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  });

  try {
    for await (const frame of parseFrames(child.stdout) as AsyncIterable<GuestFrame>) {
      if (frame.kind === 'event') continue;
      if (frame.kind === 'handshake') {
        if (frame.phase === 'fetch_done') {
          if (input.onFetchDone !== undefined) await input.onFetchDone();
          child.stdin.write('go\n');
        }
        continue;
      }
      if (frame.kind === 'error') {
        if (frame.fatal) {
          fatalError = new Error(`script-jail ${input.label} fatal: ${frame.message}`);
          child.kill('SIGTERM');
          break;
        }
        nonFatalWarnings.push(frame.message);
        continue;
      }
      if (frame.kind === 'final') {
        finalYaml = frame.yaml;
        break;
      }
    }
  } finally {
    child.stdin.end();
  }

  const exitCode = await exitPromise;
  if (fatalError !== null) throw fatalError;
  if (finalYaml === null) {
    const tail = nonFatalWarnings.length > 0
      ? ` Prior warnings: [${nonFatalWarnings.map((m) => JSON.stringify(m)).join(', ')}]`
      : '';
    throw new Error(
      `script-jail: ${input.label} session ended without a final frame ` +
        `(exit ${exitCode}).${tail}`,
    );
  }

  return { finalYaml, nonFatalWarnings };
}

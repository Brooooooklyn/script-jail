import { describe, expect, it } from 'vitest';

import { runSelectedBackend } from '../../../src/action/backend/select.js';
import { BackendUnavailableError, type AuditBackend, type BackendContext } from '../../../src/action/backend/types.js';

function backend(
  name: AuditBackend['name'],
  run: AuditBackend['run'],
): AuditBackend {
  return { name, run };
}

function ctx(): BackendContext {
  return {
    repoDir: '/repo',
    configPath: '/config.yml',
    extraRepoOverlayFiles: [],
    scratchDir: '/tmp/script-jail',
    pm: 'pnpm',
    hostArch: 'arm64',
    mode: 'check',
    imagesDir: '/images',
    runnerImage: 'ubuntu-24.04',
    arch: 'arm64',
    manifest: {
      repo: 'owner/repo',
      tag: 'v0.0.0',
      expected: { linux: {}, darwin: {} },
    },
    http: {
      download: async () => {},
    },
    selfTest: true,
  };
}

describe('runSelectedBackend', () => {
  it('auto tries firecracker, then docker, then bare on unavailable errors', async () => {
    const calls: string[] = [];
    const result = await runSelectedBackend({
      requested: 'auto',
      ctx: ctx(),
      warn: (msg) => { calls.push(`warn:${msg}`); },
      backends: {
        firecracker: backend('firecracker', async () => {
          calls.push('firecracker');
          throw new BackendUnavailableError('firecracker', 'no kvm');
        }),
        docker: backend('docker', async () => {
          calls.push('docker');
          throw new BackendUnavailableError('docker', 'no daemon');
        }),
        bare: backend('bare', async () => {
          calls.push('bare');
          return { finalYaml: 'ok\n', nonFatalWarnings: [] };
        }),
      },
    });

    expect(result.finalYaml).toBe('ok\n');
    expect(calls.filter((c) => !c.startsWith('warn:'))).toEqual([
      'firecracker',
      'docker',
      'bare',
    ]);
    expect(calls.filter((c) => c.startsWith('warn:'))).toHaveLength(2);
  });

  it('does not fall back after a backend starts and throws a runtime error', async () => {
    const calls: string[] = [];
    await expect(runSelectedBackend({
      requested: 'auto',
      ctx: ctx(),
      warn: () => {},
      backends: {
        firecracker: backend('firecracker', async () => {
          calls.push('firecracker');
          throw new Error('audit failed');
        }),
        docker: backend('docker', async () => {
          calls.push('docker');
          return { finalYaml: 'wrong\n', nonFatalWarnings: [] };
        }),
        bare: backend('bare', async () => {
          calls.push('bare');
          return { finalYaml: 'wrong\n', nonFatalWarnings: [] };
        }),
      },
    })).rejects.toThrow(/audit failed/);
    expect(calls).toEqual(['firecracker']);
  });

  it('explicit backend does not fall back when unavailable', async () => {
    await expect(runSelectedBackend({
      requested: 'docker',
      ctx: ctx(),
      warn: () => {},
      backends: {
        firecracker: backend('firecracker', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
        docker: backend('docker', async () => {
          throw new BackendUnavailableError('docker', 'no daemon');
        }),
        bare: backend('bare', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
      },
    })).rejects.toThrow(BackendUnavailableError);
  });
});

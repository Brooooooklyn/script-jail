import { describe, expect, it } from 'vitest';

import { runSelectedBackend, INSTALL_ALIGNED_BACKENDS } from '../../../src/action/backend/select.js';
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

  // codex round-4 (TMPDIR stale-callback guard): main.ts captures the auditing backend
  // from onBackendSelected to decide the host TMPDIR-parity value.  In the auto-fallback
  // case (FC unavailable → docker), onBackendSelected must end on the backend that
  // ACTUALLY ran (docker) — a stale 'firecracker' would make the host set TMPDIR while
  // the Docker guest had none (re-opening the presence oracle).
  it('onBackendSelected fires per attempt; the last call is the backend that runs', async () => {
    const selected: string[] = [];
    const result = await runSelectedBackend({
      requested: 'auto',
      ctx: ctx(),
      warn: () => {},
      onBackendSelected: (name) => { selected.push(name); },
      backends: {
        firecracker: backend('firecracker', async () => {
          throw new BackendUnavailableError('firecracker', 'no kvm');
        }),
        docker: backend('docker', async () => ({ finalYaml: 'ok\n', nonFatalWarnings: [] })),
        bare: backend('bare', async () => ({ finalYaml: 'wrong\n', nonFatalWarnings: [] })),
      },
    });
    expect(result.finalYaml).toBe('ok\n');
    // Both attempted, in order; docker is the LAST (the one that returned).
    expect(selected).toEqual(['firecracker', 'docker']);
    expect(selected[selected.length - 1]).toBe('docker');
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

  // Codex re-review (bare-backend staged-symlink escape): install:true must only run
  // on a repoDir-aligned backend (FC/docker). requireRepoDirAligned drops bare from
  // auto and throws on an explicit non-aligned backend — host scripts can never run
  // after a temp-staged audit.
  describe('requireRepoDirAligned (install:true)', () => {
    it('the allowlist contains exactly the repoDir-aligned backends', () => {
      expect([...INSTALL_ALIGNED_BACKENDS].sort()).toEqual(['docker', 'firecracker']);
      expect(INSTALL_ALIGNED_BACKENDS.has('bare')).toBe(false);
    });

    it('auto NEVER tries bare and never lands on it', async () => {
      const calls: string[] = [];
      const result = await runSelectedBackend({
        requested: 'auto',
        requireRepoDirAligned: true,
        ctx: ctx(),
        warn: () => {},
        backends: {
          firecracker: backend('firecracker', async () => {
            calls.push('firecracker');
            throw new BackendUnavailableError('firecracker', 'no kvm');
          }),
          docker: backend('docker', async () => {
            calls.push('docker');
            return { finalYaml: 'ok\n', nonFatalWarnings: [] };
          }),
          bare: backend('bare', async () => {
            calls.push('bare');
            return { finalYaml: 'BARE-RAN\n', nonFatalWarnings: [] };
          }),
        },
      });
      expect(result.finalYaml).toBe('ok\n'); // docker, not bare
      expect(calls).toEqual(['firecracker', 'docker']);
      expect(calls).not.toContain('bare');
    });

    it('auto with FC+docker both unavailable FAILS without trying bare', async () => {
      const calls: string[] = [];
      await expect(runSelectedBackend({
        requested: 'auto',
        requireRepoDirAligned: true,
        ctx: ctx(),
        warn: () => {},
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
            return { finalYaml: 'BARE-RAN\n', nonFatalWarnings: [] };
          }),
        },
      })).rejects.toThrow(/no audit backend available\. Tried firecracker, docker/);
      expect(calls).not.toContain('bare');
    });

    it('explicit bare THROWS and never runs the bare backend', async () => {
      const calls: string[] = [];
      await expect(runSelectedBackend({
        requested: 'bare',
        requireRepoDirAligned: true,
        ctx: ctx(),
        warn: () => {},
        backends: {
          firecracker: backend('firecracker', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
          docker: backend('docker', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
          bare: backend('bare', async () => {
            calls.push('bare');
            return { finalYaml: 'BARE-RAN\n', nonFatalWarnings: [] };
          }),
        },
      })).rejects.toThrow(/install: true` requires a repoDir-aligned backend/);
      expect(calls).toEqual([]); // bare.run never invoked
    });

    it('explicit firecracker still runs normally under install:true', async () => {
      const result = await runSelectedBackend({
        requested: 'firecracker',
        requireRepoDirAligned: true,
        ctx: ctx(),
        warn: () => {},
        backends: {
          firecracker: backend('firecracker', async () => ({ finalYaml: 'fc\n', nonFatalWarnings: [] })),
          docker: backend('docker', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
          bare: backend('bare', async () => ({ finalYaml: '', nonFatalWarnings: [] })),
        },
      });
      expect(result.finalYaml).toBe('fc\n');
    });

    it('WITHOUT the flag (pure-audit), auto still includes bare (unchanged behavior)', async () => {
      const calls: string[] = [];
      const result = await runSelectedBackend({
        requested: 'auto',
        // requireRepoDirAligned omitted → pure-audit path
        ctx: ctx(),
        warn: () => {},
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
            return { finalYaml: 'bare-ok\n', nonFatalWarnings: [] };
          }),
        },
      });
      expect(result.finalYaml).toBe('bare-ok\n');
      expect(calls).toEqual(['firecracker', 'docker', 'bare']);
    });
  });
});

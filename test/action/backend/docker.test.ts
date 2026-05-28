import { describe, expect, it } from 'vitest';

import { cleanupStagedDockerRepo } from '../../../src/action/backend/docker.js';

describe('cleanupStagedDockerRepo', () => {
  it('restores host ownership before removing the staged repo', () => {
    const calls: string[] = [];
    const env = { PATH: '/usr/bin' };

    cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { calls.push('cleanup'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      env,
      hostOwner: { uid: 1001, gid: 121 },
      run: (cmd, args, opts) => {
        calls.push(`${cmd} ${args.join(' ')}`);
        expect(opts?.env).toBe(env);
      },
    });

    expect(calls).toEqual([
      [
        'docker',
        'run',
        '--rm',
        '-v',
        '/tmp/stage/work:/work',
        'script-jail-rootfs:ubuntu-24.04-arm64',
        '/bin/sh',
        '-lc',
        'find /work -xdev -exec chown -h 1001:121 {} +',
      ].join(' '),
      'cleanup',
    ]);
  });

  it('does not mask the audit result when ownership restore or cleanup fails', () => {
    const warnings: string[] = [];

    expect(() => cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { throw new Error('rm failed'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      stderr: { write: (s) => { warnings.push(s); } },
      hostOwner: { uid: 1001, gid: 121 },
      run: () => { throw new Error('chown failed'); },
    })).not.toThrow();

    expect(warnings.join('')).toContain('failed to restore staged repo ownership: chown failed');
    expect(warnings.join('')).toContain('failed to remove staged repo: rm failed');
  });

  it('skips ownership restore when the host uid/gid is unavailable', () => {
    const calls: string[] = [];

    cleanupStagedDockerRepo({
      staged: {
        path: '/tmp/stage/work',
        cleanup: () => { calls.push('cleanup'); },
      },
      imageRef: 'script-jail-rootfs:ubuntu-24.04-arm64',
      hostOwner: null,
      run: () => { calls.push('run'); },
    });

    expect(calls).toEqual(['cleanup']);
  });
});

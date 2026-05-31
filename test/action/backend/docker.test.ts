import { describe, expect, it } from 'vitest';

import {
  cleanupStagedDockerRepo,
  resolveDockerImageRef,
} from '../../../src/action/backend/docker.js';
import { BackendUnavailableError } from '../../../src/action/backend/types.js';
import type { BackendContext } from '../../../src/action/backend/types.js';

const PLACEHOLDER_X64 =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_X64';
const PLACEHOLDER_ARM64 =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_UBUNTU_24_04_ARM64';
const REAL_REF =
  'ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:' + 'a'.repeat(64);

function makeCtx(over: {
  arch?: 'x64' | 'arm64';
  runnerImage?: string;
  selfTest?: boolean;
  dockerImages?: Record<string, Record<string, string>>;
}): BackendContext {
  return {
    selfTest: over.selfTest ?? false,
    arch: over.arch ?? 'x64',
    runnerImage: over.runnerImage ?? 'ubuntu-24.04',
    manifest: { dockerImages: over.dockerImages },
  } as unknown as BackendContext;
}

describe('resolveDockerImageRef', () => {
  it('downgrades a placeholder digest to the tag-only ref when allowTagFallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': PLACEHOLDER_X64 } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe('ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04');
    expect(r.warning).toMatch(/non-digest-pinned|placeholder/);
  });

  it('preserves the owner casing and arch suffix in the tag fallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ arch: 'arm64', dockerImages: { arm64: { 'ubuntu-24.04': PLACEHOLDER_ARM64 } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe('ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04-arm64');
  });

  it('returns the placeholder ref verbatim (no warning) when allowTagFallback is false (Action default)', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': PLACEHOLDER_X64 } } }),
    );
    expect(r.ref).toBe(PLACEHOLDER_X64);
    expect(r.warning).toBeUndefined();
  });

  it('returns a real digest ref verbatim even with allowTagFallback', () => {
    const r = resolveDockerImageRef(
      makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': REAL_REF } } }),
      { allowTagFallback: true },
    );
    expect(r.ref).toBe(REAL_REF);
    expect(r.warning).toBeUndefined();
  });

  it('throws BackendUnavailableError when the manifest has no entry, regardless of the flag', () => {
    expect(() => resolveDockerImageRef(makeCtx({ dockerImages: {} }), { allowTagFallback: true }))
      .toThrow(BackendUnavailableError);
    expect(() =>
      resolveDockerImageRef(makeCtx({ dockerImages: { x64: { 'ubuntu-24.04': '  ' } } })),
    ).toThrow(BackendUnavailableError);
  });

  it('returns the local self-test tag without consulting the manifest', () => {
    expect(resolveDockerImageRef(makeCtx({ selfTest: true })).ref).toBe(
      'script-jail-rootfs:ubuntu-24.04',
    );
    expect(resolveDockerImageRef(makeCtx({ selfTest: true, arch: 'arm64' })).ref).toBe(
      'script-jail-rootfs:ubuntu-24.04-arm64',
    );
  });
});

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

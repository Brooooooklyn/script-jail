import { describe, it, expect } from 'vitest';
import { render, type RenderInput } from '../../src/lock/render.js';
import type { PackageBlock, LifecycleBlock } from '../../src/lock/schema.js';

function emptyBlock(): LifecycleBlock {
  return {
    external_reads: [],
    escaped_writes: [],
    env_read: [],
    spawn_attempts: [],
    spawn_blocked: [],
    dlopen_attempts: [],
    network_attempts: [],
  };
}

function makePkg(stages: Partial<Record<string, LifecycleBlock>>): PackageBlock {
  return { lifecycle: stages };
}

const baseInput: RenderInput = {
  manager: 'pnpm',
  manager_lockfile_sha256: '4f2a1b3c',
  node_version: '20.19.0',
  generated_at: '2026-05-16T00:00:00Z',
  packages: new Map(),
};

describe('render', () => {
  describe('byte-stability', () => {
    it('produces byte-identical output for the same input (called twice)', () => {
      const packages = new Map<string, PackageBlock>([
        ['esbuild@0.21.5', makePkg({ postinstall: { ...emptyBlock(), external_reads: ['$CACHE/esbuild/bin'] } })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      const first = render(input);
      const second = render(input);
      expect(first).toBe(second);
    });

    it('produces byte-identical output even with complex data', () => {
      const packages = new Map<string, PackageBlock>([
        ['malicious@1.0.0', makePkg({
          postinstall: {
            external_reads: ['<HIDDEN> $HOME/.ssh/id_rsa'],
            escaped_writes: ['<CROSS_PACKAGE> $NODE_MODULES/debug/index.js'],
            env_read: ['<HIDDEN> NPM_TOKEN', 'HOME'],
            spawn_attempts: [],
            spawn_blocked: ['<ENOENT> bash -c echo hi'],
            dlopen_attempts: ['<BLOCKED> libssl.so'],
            network_attempts: ['<BLOCKED> connect 198.51.100.7:443'],
          },
        })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      expect(render(input)).toBe(render(input));
    });
  });

  describe('package ordering', () => {
    it('sorts packages ascending by id', () => {
      const packages = new Map<string, PackageBlock>([
        ['zod@3.0.0', makePkg({ install: emptyBlock() })],
        ['esbuild@0.21.5', makePkg({ install: emptyBlock() })],
        ['lodash@4.17.21', makePkg({ install: emptyBlock() })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      const out = render(input);
      const lines = out.split('\n');
      const pkgLines = lines.filter((l) => /^  \w/.test(l)).map((l) => l.trim().replace(':', ''));
      // Filter to actual pkg@version keys
      const pkgKeys = pkgLines.filter((l) => l.includes('@'));
      expect(pkgKeys).toEqual(['esbuild@0.21.5', 'lodash@4.17.21', 'zod@3.0.0']);
    });
  });

  describe('lifecycle stage ordering', () => {
    it('emits lifecycle stages in enum order: preinstall, install, postinstall, prepare', () => {
      const packages = new Map<string, PackageBlock>([
        ['foo@1.0.0', makePkg({
          prepare: emptyBlock(),
          postinstall: emptyBlock(),
          preinstall: emptyBlock(),
          install: emptyBlock(),
        })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      const out = render(input);
      const stageMatches = [...out.matchAll(/^\s+(preinstall|install|postinstall|prepare):/gm)];
      const found = stageMatches.map((m) => m[1]);
      expect(found).toEqual(['preinstall', 'install', 'postinstall', 'prepare']);
    });
  });

  describe('empty lists are still emitted', () => {
    it('includes all seven list fields even when empty', () => {
      const packages = new Map<string, PackageBlock>([
        ['empty-pkg@1.0.0', makePkg({ postinstall: emptyBlock() })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      const out = render(input);
      expect(out).toContain('external_reads:');
      expect(out).toContain('escaped_writes:');
      expect(out).toContain('env_read:');
      expect(out).toContain('spawn_attempts:');
      expect(out).toContain('spawn_blocked:');
      expect(out).toContain('dlopen_attempts:');
      expect(out).toContain('network_attempts:');
    });
  });

  describe('YAML shape', () => {
    it('contains schema_version, manager, etc. at the top level', () => {
      const out = render(baseInput);
      expect(out).toContain('schema_version: 1');
      expect(out).toContain('manager: pnpm');
      expect(out).toContain('manager_lockfile_sha256: 4f2a1b3c');
      expect(out).toContain('node_version: 20.19.0');
      expect(out).toContain('generated_at: 2026-05-16T00:00:00Z');
    });

    it('matches the reference YAML shape for a realistic package', () => {
      const packages = new Map<string, PackageBlock>([
        ['esbuild@0.21.5', makePkg({
          postinstall: {
            external_reads: ['$CACHE/esbuild/bin/<hash>'],
            escaped_writes: [],
            env_read: ['ESBUILD_BINARY_PATH', 'npm_config_arch'],
            spawn_attempts: ['node $PKG/install.js'],
            spawn_blocked: [],
            dlopen_attempts: [],
            network_attempts: [],
          },
        })],
      ]);
      const input: RenderInput = { ...baseInput, packages };
      const out = render(input);
      expect(out).toContain('esbuild@0.21.5:');
      expect(out).toContain('postinstall:');
      expect(out).toContain('$CACHE/esbuild/bin/<hash>');
      expect(out).toContain('ESBUILD_BINARY_PATH');
      expect(out).toContain('node $PKG/install.js');
    });
  });

  describe('empty packages map', () => {
    it('renders without error and includes packages key', () => {
      const out = render(baseInput);
      expect(out).toContain('packages:');
    });
  });

  describe('manager variants', () => {
    it('renders npm as manager', () => {
      const out = render({ ...baseInput, manager: 'npm' });
      expect(out).toContain('manager: npm');
    });
    it('renders yarn as manager', () => {
      const out = render({ ...baseInput, manager: 'yarn' });
      expect(out).toContain('manager: yarn');
    });
  });
});

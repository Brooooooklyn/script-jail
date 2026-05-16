// npm-jar — test/action/host-node-prefix.test.ts
//
// Unit tests for `resolveHostNodeExecPath` and `resolveHostNodePrefix`.
//
//   - `resolveHostNodeExecPath` resolves the first `node` in PATH (i.e. the
//     binary `actions/setup-node` placed), NOT `process.execPath` (which on
//     `runs.using: node20` actions is the runner's bundled Node).
//
//   - `resolveHostNodePrefix` wraps that resolution with the dirname-twice +
//     validation logic.  The validation rules were tightened in Task #12 fix:
//     accept toolcache/tmp paths; reject system-wide installs (/usr,
//     /usr/local, /opt/homebrew, /opt/local, /); fall back to requiring BOTH
//     `include/node/node.h` AND `share/doc/node` for anything else.
//
// Tests inject `fs`, `path`, `which`, and `execPath` so we never touch the
// host's real filesystem layout or PATH.

import { describe, it, expect } from 'vitest';
import { tmpdir } from 'node:os';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  chmodSync,
  symlinkSync,
  realpathSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  resolveHostNodeExecPath,
  resolveHostNodePrefix,
} from '../../src/action/host-node-prefix.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFs(existing: ReadonlyArray<string>): { existsSync(p: string): boolean } {
  const set = new Set(existing);
  return { existsSync: (p) => set.has(p) };
}

// ---------------------------------------------------------------------------
// resolveHostNodeExecPath
// ---------------------------------------------------------------------------

describe('resolveHostNodeExecPath', () => {
  it('returns the first node found by walking PATH segments', () => {
    // setup-node prepends its toolcache bin/ to PATH, so the first hit is what
    // we want — even if the runner's bundled-Node bin is later in PATH.
    const path = [
      '/opt/hostedtoolcache/node/20.11.0/x64/bin',
      '/runner/runners/2.300.0/externals/node20/bin',
      '/usr/bin',
    ].join(':');
    const which = (cmd: string, segments: string[]): string | null => {
      // Simulate exists-on-disk for the first two segments.
      for (const seg of segments) {
        if (seg === '/opt/hostedtoolcache/node/20.11.0/x64/bin') {
          return `${seg}/${cmd}`;
        }
      }
      return null;
    };
    expect(resolveHostNodeExecPath({ path, which })).toBe(
      '/opt/hostedtoolcache/node/20.11.0/x64/bin/node',
    );
  });

  it('skips PATH segments that do not contain node and falls through to the next', () => {
    const path = ['/empty/segment', '/opt/hostedtoolcache/node/22.4.0/x64/bin'].join(':');
    const which = (cmd: string, segments: string[]): string | null => {
      for (const seg of segments) {
        if (seg === '/opt/hostedtoolcache/node/22.4.0/x64/bin') {
          return `${seg}/${cmd}`;
        }
      }
      return null;
    };
    expect(resolveHostNodeExecPath({ path, which })).toBe(
      '/opt/hostedtoolcache/node/22.4.0/x64/bin/node',
    );
  });

  it('throws a clear setup-node-prompting error when no node is on PATH', () => {
    const path = ['/empty/segment', '/also/empty'].join(':');
    const which = (): string | null => null;
    expect(() => resolveHostNodeExecPath({ path, which })).toThrow(
      /no `node` was found on PATH/,
    );
    expect(() => resolveHostNodeExecPath({ path, which })).toThrow(
      /actions\/setup-node/,
    );
  });

  it('treats an empty PATH like a missing PATH (clear error)', () => {
    const which = (): string | null => null;
    expect(() => resolveHostNodeExecPath({ path: '', which })).toThrow(
      /no `node` was found on PATH/,
    );
  });

  it('uses a real fs-backed PATH walk by default (integration sanity)', () => {
    // Spin up a tmp PATH segment containing a fake executable `node`.  This
    // proves the default `which` implementation walks segments and only
    // accepts executable regular files.
    const tmpRoot = mkdtempSync(join(tmpdir(), 'npm-jar-pathwalk-'));
    try {
      const segA = join(tmpRoot, 'a-bin');
      const segB = join(tmpRoot, 'b-bin');
      mkdirSync(segA, { recursive: true });
      mkdirSync(segB, { recursive: true });
      // Only segB has `node`.  segA must be skipped.
      const nodeBin = join(segB, 'node');
      writeFileSync(nodeBin, '#!/bin/sh\n');
      chmodSync(nodeBin, 0o755);
      const path = [segA, segB].join(':');
      // On macOS, /tmp -> /private/tmp, so realpathSync resolves through it.
      // Compare against the realpath so the test is portable.
      expect(resolveHostNodeExecPath({ path })).toBe(realpathSync(nodeBin));
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('skips a directory named `node` in a PATH segment (real fs)', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'npm-jar-pathwalk-dir-'));
    try {
      const segA = join(tmpRoot, 'a-bin');
      const segB = join(tmpRoot, 'b-bin');
      mkdirSync(segA, { recursive: true });
      mkdirSync(segB, { recursive: true });
      // segA's `node` is a directory — must be skipped.
      mkdirSync(join(segA, 'node'));
      const nodeBin = join(segB, 'node');
      writeFileSync(nodeBin, '#!/bin/sh\n');
      chmodSync(nodeBin, 0o755);
      const path = [segA, segB].join(':');
      expect(resolveHostNodeExecPath({ path })).toBe(realpathSync(nodeBin));
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('skips a non-executable `node` file in a PATH segment (real fs)', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'npm-jar-pathwalk-noexec-'));
    try {
      const segA = join(tmpRoot, 'a-bin');
      const segB = join(tmpRoot, 'b-bin');
      mkdirSync(segA, { recursive: true });
      mkdirSync(segB, { recursive: true });
      // segA's `node` exists but has no executable bit — must be skipped.
      writeFileSync(join(segA, 'node'), 'not executable\n');
      chmodSync(join(segA, 'node'), 0o644);
      const nodeBin = join(segB, 'node');
      writeFileSync(nodeBin, '#!/bin/sh\n');
      chmodSync(nodeBin, 0o755);
      const path = [segA, segB].join(':');
      expect(resolveHostNodeExecPath({ path })).toBe(realpathSync(nodeBin));
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('follows a symlinked `node` to its real path (real fs)', () => {
    // setup-node sometimes resolves through symlinks; we must use the
    // realpath when deriving the prefix so a symlinked shim in one tree
    // can't be misclassified as living in that tree's `bin/`.
    const tmpRoot = mkdtempSync(join(tmpdir(), 'npm-jar-pathwalk-symlink-'));
    try {
      const realPrefix = join(tmpRoot, 'real-node-prefix');
      const realBinDir = join(realPrefix, 'bin');
      mkdirSync(realBinDir, { recursive: true });
      const realNode = join(realBinDir, 'node');
      writeFileSync(realNode, '#!/bin/sh\n');
      chmodSync(realNode, 0o755);

      const shimDir = join(tmpRoot, 'shim-bin');
      mkdirSync(shimDir, { recursive: true });
      symlinkSync(realNode, join(shimDir, 'node'));

      const path = [shimDir].join(':');
      // The resolver should return the realpath of the symlink target.
      expect(resolveHostNodeExecPath({ path })).toBe(realpathSync(realNode));
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// resolveHostNodePrefix
// ---------------------------------------------------------------------------

describe('resolveHostNodePrefix', () => {
  it('returns the dirname-twice prefix for a toolcache node', () => {
    const execPath = '/opt/hostedtoolcache/node/20.11.0/x64/bin/node';
    const fs = makeFs([execPath]);
    expect(
      resolveHostNodePrefix({
        path: '/opt/hostedtoolcache/node/20.11.0/x64/bin',
        which: () => execPath,
        fs,
      }),
    ).toBe('/opt/hostedtoolcache/node/20.11.0/x64');
  });

  it('also accepts a hostedtoolcache path on a different architecture', () => {
    const execPath = '/opt/hostedtoolcache/node/22.4.0/arm64/bin/node';
    const fs = makeFs([execPath]);
    expect(
      resolveHostNodePrefix({
        path: '/opt/hostedtoolcache/node/22.4.0/arm64/bin',
        which: () => execPath,
        fs,
      }),
    ).toBe('/opt/hostedtoolcache/node/22.4.0/arm64');
  });

  it('throws when the resolved node is the runner-bundled Node (externals)', () => {
    // The "GH runner's bundled Node" lives under
    // /runner/runners/<ver>/externals/node20/bin/node, NOT under hostedtoolcache.
    const execPath = '/runner/runners/2.300.0/externals/node20/bin/node';
    const fs = makeFs([execPath]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/runner/runners/2.300.0/externals/node20/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to mount the GitHub Actions runner's bundled Node/);
    expect(() =>
      resolveHostNodePrefix({
        path: '/runner/runners/2.300.0/externals/node20/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/actions\/setup-node/);
  });

  it('throws when the resolved node sits under /usr/local (system install)', () => {
    const execPath = '/usr/local/bin/node';
    const fs = makeFs([
      execPath,
      // Even with marker files, /usr/local is too dangerous to pack — it pulls
      // in unrelated binaries.
      '/usr/local/include/node/node.h',
      '/usr/local/share/doc/node',
    ]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/local/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack \/usr\/local — looks like a system-wide install/);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/local/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/actions\/setup-node/);
  });

  it('throws when the resolved node is /usr/bin/node', () => {
    const execPath = '/usr/bin/node';
    const fs = makeFs([
      execPath,
      '/usr/include/node/node.h',
      '/usr/share/doc/node',
    ]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack \/usr — looks like a system-wide install/);
  });

  it('throws when the resolved node is under /opt/homebrew', () => {
    const execPath = '/opt/homebrew/bin/node';
    const fs = makeFs([
      execPath,
      '/opt/homebrew/include/node/node.h',
      '/opt/homebrew/share/doc/node',
    ]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/opt/homebrew/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack \/opt\/homebrew — looks like a system-wide install/);
  });

  it('throws when the resolved node is under /opt/local (MacPorts)', () => {
    const execPath = '/opt/local/bin/node';
    const fs = makeFs([
      execPath,
      '/opt/local/include/node/node.h',
      '/opt/local/share/doc/node',
    ]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/opt/local/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack \/opt\/local — looks like a system-wide install/);
  });

  it('throws when the resolved node has prefix `/` (root)', () => {
    // This shouldn't happen in practice but the blocklist is explicit about
    // refusing to pack the root.
    const execPath = '/bin/node';
    const fs = makeFs([execPath, '/include/node/node.h', '/share/doc/node']);
    expect(() =>
      resolveHostNodePrefix({
        path: '/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack \/ — looks like a system-wide install/);
  });

  it('accepts a tmp-prefix path with BOTH marker files present', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'npm-jar-prefix-ok-'));
    try {
      const prefix = join(tmpRoot, 'node-prefix');
      mkdirSync(join(prefix, 'bin'), { recursive: true });
      mkdirSync(join(prefix, 'include', 'node'), { recursive: true });
      mkdirSync(join(prefix, 'share', 'doc', 'node'), { recursive: true });
      writeFileSync(join(prefix, 'bin', 'node'), '#!/bin/sh\n');
      writeFileSync(join(prefix, 'include', 'node', 'node.h'), '');
      // share/doc/node already created as a directory.
      const execPath = join(prefix, 'bin', 'node');
      expect(
        resolveHostNodePrefix({
          path: join(prefix, 'bin'),
          which: () => execPath,
        }),
      ).toBe(prefix);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('rejects a non-tmp prefix with only ONE marker file (header only)', () => {
    // Use a synthetic non-tmp, non-blocklisted, non-toolcache path so the
    // marker-file fallback is exercised.  The fs seam controls which files
    // appear to exist.
    const execPath = '/opt/custom-node/bin/node';
    const fs = makeFs([execPath, '/opt/custom-node/include/node/node.h']);
    expect(() =>
      resolveHostNodePrefix({
        path: '/opt/custom-node/bin',
        which: () => execPath,
        fs,
        // Pin tmpdir override + runner-tool-cache override to empty so the
        // synthetic path isn't accidentally accepted by either rule.
        runnerToolCache: undefined,
      }),
    ).toThrow(/does not appear to be a self-contained Node install/);
  });

  it('rejects a non-tmp prefix with only ONE marker file (docs only)', () => {
    const execPath = '/opt/custom-node/bin/node';
    const fs = makeFs([execPath, '/opt/custom-node/share/doc/node']);
    expect(() =>
      resolveHostNodePrefix({
        path: '/opt/custom-node/bin',
        which: () => execPath,
        fs,
        runnerToolCache: undefined,
      }),
    ).toThrow(/does not appear to be a self-contained Node install/);
  });

  it('accepts a non-tmp prefix with BOTH marker files (header + docs)', () => {
    const execPath = '/opt/custom-node/bin/node';
    const fs = makeFs([
      execPath,
      '/opt/custom-node/include/node/node.h',
      '/opt/custom-node/share/doc/node',
    ]);
    expect(
      resolveHostNodePrefix({
        path: '/opt/custom-node/bin',
        which: () => execPath,
        fs,
        runnerToolCache: undefined,
      }),
    ).toBe('/opt/custom-node');
  });

  it('accepts a path under RUNNER_TOOL_CACHE (self-hosted runner override)', () => {
    // self-hosted runners can override the toolcache root via this env var;
    // we should accept its descendants without requiring marker files.
    const execPath = '/custom/toolcache/node/20.11.0/x64/bin/node';
    const fs = makeFs([execPath]);
    expect(
      resolveHostNodePrefix({
        path: '/custom/toolcache/node/20.11.0/x64/bin',
        which: () => execPath,
        fs,
        runnerToolCache: '/custom/toolcache',
      }),
    ).toBe('/custom/toolcache/node/20.11.0/x64');
  });

  it('throws when PATH has no node at all', () => {
    const fs = makeFs([]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/empty/segment',
        which: () => null,
        fs,
      }),
    ).toThrow(/no `node` was found on PATH/);
  });

  // -------------------------------------------------------------------------
  // Hardening: the blocklist must also reject descendants of system roots,
  // and a misconfigured runnerToolCache must not unlock a system root.
  // -------------------------------------------------------------------------

  it('rejects a descendant of /usr (e.g. /usr/lib/node) even though prefix !== "/usr"', () => {
    // Without subtree-aware blocking, prefix `/usr/lib/node` would slip past
    // the equality check and be accepted via marker files.
    const execPath = '/usr/lib/node/bin/node';
    const fs = makeFs([
      execPath,
      '/usr/lib/node/include/node/node.h',
      '/usr/lib/node/share/doc/node',
    ]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/lib/node/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/refusing to pack/);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/lib/node/bin',
        which: () => execPath,
        fs,
      }),
    ).toThrow(/system-wide install/);
  });

  it('ignores RUNNER_TOOL_CACHE when it points at a blocklisted system root (/usr)', () => {
    // A misconfigured RUNNER_TOOL_CACHE=/usr must not unlock a /usr/.../node.
    const execPath = '/usr/lib/node/bin/node';
    const fs = makeFs([execPath]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/lib/node/bin',
        which: () => execPath,
        fs,
        runnerToolCache: '/usr',
      }),
    ).toThrow(/refusing to pack/);
  });

  it('ignores RUNNER_TOOL_CACHE when it sits INSIDE a blocklisted system root', () => {
    const execPath = '/usr/local/share/node/bin/node';
    const fs = makeFs([execPath]);
    expect(() =>
      resolveHostNodePrefix({
        path: '/usr/local/share/node/bin',
        which: () => execPath,
        fs,
        runnerToolCache: '/usr/local/share',
      }),
    ).toThrow(/refusing to pack/);
  });
});

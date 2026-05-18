// Integration test: each malicious-shaped fixture under test/fixtures/ has a
// golden `expected-events.json` (an array of AttributedEvent objects). For
// each fixture we feed those events through normalize() + render() and assert
// that the resulting YAML contains the expected attack-shape signature.
//
// In v2 these fixtures will be installed inside the real Firecracker VM and
// the *actual* event stream will be diffed against expected-events.json. In
// v1 the test exercises only the pure-JS normalize/render pipeline — no VM,
// no /dev/kvm, no root, runs on macOS and Linux alike.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AttributedEvent, type AttributedEvent as AttributedEventT } from '../../src/lock/schema.js';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

// Realistic in-VM roots. These must match the values the host uses to build
// the per-package `pkgDirs` map, otherwise tokenize() can't form $PKG.
const ROOTS = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.npm',
};

/** Load and zod-validate a fixture's expected events. */
function loadExpectedEvents(fixtureName: string): AttributedEventT[] {
  const path = join(FIXTURES_DIR, fixtureName, 'expected-events.json');
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  // Validate at the array boundary so a malformed fixture fails the test up
  // front with a useful zod error instead of crashing somewhere inside normalize().
  return raw.map((ev: unknown, i: number) => {
    const r = AttributedEvent.safeParse(ev);
    if (!r.success) {
      throw new Error(
        `fixture ${fixtureName}: event[${i}] failed validation: ${JSON.stringify(r.error.issues)}`,
      );
    }
    return r.data;
  });
}

/** Build a pkgDirs map covering every package referenced by the given events. */
function pkgDirsFor(events: AttributedEventT[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const ev of events) {
    if (out.has(ev.pkg)) continue;
    // pkg id is `<name>@<version>` — strip the version to get the install dir.
    const name = ev.pkg.split('@')[0]!;
    out.set(ev.pkg, `${ROOTS.nodeModules}/${name}`);
  }
  return out;
}

/** Pipe events through normalize → render → YAML. */
function renderFixtureYaml(fixtureName: string): string {
  const events = loadExpectedEvents(fixtureName);
  const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
  const packages = normalize(events, ctx);
  return render({
    manager: 'pnpm',
    manager_lockfile_sha256: 'deadbeef',
    node_version: '20.19.0',
    generated_at: '2026-05-16T00:00:00Z',
    packages,
  });
}

// One describe block per fixture: keeps failure output readable when a single
// fixture's expected signature drifts from what the pipeline produces.

describe('fixture: reads-home-ssh', () => {
  it('renders an <HIDDEN> $HOME/.ssh/id_rsa entry under external_reads', () => {
    const yaml = renderFixtureYaml('reads-home-ssh');
    expect(yaml).toContain('reads-home-ssh@1.0.0:');
    expect(yaml).toContain('postinstall:');
    expect(yaml).toContain('external_reads:');
    expect(yaml).toContain('<HIDDEN> $HOME/.ssh/id_rsa');
  });
});

describe('fixture: tries-dlopen', () => {
  it('renders a <BLOCKED> entry under dlopen_attempts', () => {
    const yaml = renderFixtureYaml('tries-dlopen');
    expect(yaml).toContain('tries-dlopen@1.0.0:');
    expect(yaml).toContain('dlopen_attempts:');
    // The filename was inside the package's own $PKG so it tokenizes to $PKG/evil.node.
    expect(yaml).toContain('<BLOCKED> $PKG/evil.node');
  });
});

describe('fixture: spawns-gcc', () => {
  it('renders <ENOENT> gcc -c evil.c under spawn_blocked', () => {
    const yaml = renderFixtureYaml('spawns-gcc');
    expect(yaml).toContain('spawns-gcc@1.0.0:');
    expect(yaml).toContain('spawn_blocked:');
    expect(yaml).toContain('<ENOENT> gcc -c evil.c');
  });
});

describe('fixture: reads-secret-env', () => {
  it('renders <HIDDEN> NPM_TOKEN under env_read', () => {
    const yaml = renderFixtureYaml('reads-secret-env');
    expect(yaml).toContain('reads-secret-env@1.0.0:');
    expect(yaml).toContain('env_read:');
    expect(yaml).toContain('<HIDDEN> NPM_TOKEN');
  });
});

describe('fixture: tries-network-egress', () => {
  it('renders <BLOCKED> connect 198.51.100.7:443 under network_attempts', () => {
    const yaml = renderFixtureYaml('tries-network-egress');
    expect(yaml).toContain('tries-network-egress@1.0.0:');
    expect(yaml).toContain('network_attempts:');
    expect(yaml).toContain('<BLOCKED> connect 198.51.100.7:443');
  });
});

describe('fixture: writes-into-repo', () => {
  it('renders $REPO/.bashrc under escaped_writes', () => {
    const yaml = renderFixtureYaml('writes-into-repo');
    expect(yaml).toContain('writes-into-repo@1.0.0:');
    expect(yaml).toContain('postinstall:');
    expect(yaml).toContain('escaped_writes:');
    expect(yaml).toContain('$REPO/.bashrc');
    // sanity: should NOT show the <CROSS_PACKAGE> prefix
    expect(yaml).not.toMatch(/<CROSS_PACKAGE>.*\.bashrc/);
  });
});

describe('fixture: cross-package-tampering', () => {
  it('renders <CROSS_PACKAGE> $NODE_MODULES/victim-package/index.js under escaped_writes', () => {
    const yaml = renderFixtureYaml('cross-package-tampering');
    expect(yaml).toContain('cross-package-tampering@1.0.0:');
    expect(yaml).toContain('postinstall:');
    expect(yaml).toContain('escaped_writes:');
    expect(yaml).toContain('<CROSS_PACKAGE> $NODE_MODULES/victim-package/index.js');
  });
});

describe('fixture: strips-ld-preload', () => {
  it('does not emit audit_bypass or env_tamper for a normal exec (envp_alloc_failed=false)', () => {
    const yaml = renderFixtureYaml('strips-ld-preload');
    expect(yaml).toContain('strips-ld-preload@1.0.0:');
    expect(yaml).toContain('postinstall:');
    // The fixture's exec event has envp_alloc_failed=false — re-injection
    // succeeded, so there is nothing to surface. Both optional lists must
    // be absent (we render them only when non-empty).
    expect(yaml).not.toContain('audit_bypass:');
    expect(yaml).not.toContain('env_tamper:');
  });
});

describe('fixture: unsets-ld-preload', () => {
  it('renders <REFUSED> unsetenv LD_PRELOAD and NODE_OPTIONS under env_tamper', () => {
    const yaml = renderFixtureYaml('unsets-ld-preload');
    expect(yaml).toContain('unsets-ld-preload@1.0.0:');
    expect(yaml).toContain('postinstall:');
    expect(yaml).toContain('env_tamper:');
    expect(yaml).toContain('<REFUSED> unsetenv LD_PRELOAD');
    expect(yaml).toContain('<REFUSED> unsetenv NODE_OPTIONS');
    // The exec event in the fixture has envp_alloc_failed=false, so the
    // audit_bypass list stays empty and must not be rendered.
    expect(yaml).not.toContain('audit_bypass:');
  });
});

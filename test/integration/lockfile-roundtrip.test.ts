// Integration test: feed every fixture's events through the full pipeline
// (normalize → render → YAML), then parse that YAML back and validate the
// resulting object against the Lock zod schema.
//
// This proves the lockfile we emit is shape-stable and validator-clean: any
// drift in renderer output that would break the zod schema fails here loud
// and early, instead of only manifesting when a host loads a committed
// .npm-jar.lock.yml from disk.

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

import {
  AttributedEvent,
  Lock,
  type AttributedEvent as AttributedEventT,
} from '../../src/lock/schema.js';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

const ROOTS = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.npm',
};

function listFixtures(): string[] {
  // Skip passive-companion fixtures (e.g. victim-package): those exist only to
  // make a path real on disk during real-VM runs and ship no expected-events.json
  // because they have no lifecycle hooks of their own.
  return readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .filter((d) => existsSync(join(FIXTURES_DIR, d.name, 'expected-events.json')))
    .map((d) => d.name)
    .sort();
}

function loadAllFixtureEvents(): AttributedEventT[] {
  const events: AttributedEventT[] = [];
  for (const f of listFixtures()) {
    const raw = JSON.parse(readFileSync(join(FIXTURES_DIR, f, 'expected-events.json'), 'utf8'));
    for (const ev of raw) events.push(AttributedEvent.parse(ev));
  }
  return events;
}

function pkgDirsFor(events: AttributedEventT[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const ev of events) {
    if (out.has(ev.pkg)) continue;
    const name = ev.pkg.split('@')[0]!;
    out.set(ev.pkg, `${ROOTS.nodeModules}/${name}`);
  }
  return out;
}

describe('lockfile roundtrip across all fixtures', () => {
  it('renders a single YAML that parses + validates against the Lock schema', () => {
    const events = loadAllFixtureEvents();
    expect(events.length).toBeGreaterThan(0);

    const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
    const packages = normalize(events, ctx);

    const yaml = render({
      manager: 'pnpm',
      manager_lockfile_sha256: 'cafef00d',
      node_version: '20.19.0',
      generated_at: '2026-05-16T00:00:00Z',
      packages,
    });

    // Round-trip: YAML string → JS object → zod-validated Lock.
    const parsed = parseYaml(yaml);
    const result = Lock.safeParse(parsed);
    if (!result.success) {
      // Surface the failure inline so a regression is debuggable from CI logs
      // without needing to re-run with `--inspect`.
      throw new Error(
        `Lock schema rejected rendered YAML: ${JSON.stringify(result.error.issues, null, 2)}\n\nYAML:\n${yaml}`,
      );
    }
    expect(result.success).toBe(true);

    // Sanity: every fixture's package id is present in the rendered lock.
    for (const f of listFixtures()) {
      expect(result.data.packages).toHaveProperty(`${f}@1.0.0`);
    }
  });

  it('produces byte-identical output when rendered twice', () => {
    // Determinism is a contract: two renders of the same events must match
    // exactly, otherwise diff-based change detection in CI is meaningless.
    const events = loadAllFixtureEvents();
    const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
    const packages = normalize(events, ctx);
    const input = {
      manager: 'pnpm' as const,
      manager_lockfile_sha256: 'cafef00d',
      node_version: '20.19.0',
      generated_at: '2026-05-16T00:00:00Z',
      packages,
    };
    expect(render(input)).toBe(render(input));
  });
});

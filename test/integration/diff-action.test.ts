// Integration test: exercise the action-side diff path end-to-end without
// booting a VM. We generate two lockfiles from the fixture event stream —
// "version A" with every fixture, "version B" with one fixture dropped —
// then run them through renderDiff() and assert the diff surfaces the
// missing package plus a GitHub Actions ::error annotation.

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AttributedEvent,
  type AttributedEvent as AttributedEventT,
} from '../../src/lock/schema.js';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';
import { renderDiff } from '../../src/action/diff.js';

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

function loadEvents(fixtureName: string): AttributedEventT[] {
  const raw = JSON.parse(
    readFileSync(join(FIXTURES_DIR, fixtureName, 'expected-events.json'), 'utf8'),
  );
  return raw.map((ev: unknown) => AttributedEvent.parse(ev));
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

function renderYaml(events: AttributedEventT[]): string {
  const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
  const packages = normalize(events, ctx);
  return render({
    manager: 'pnpm',
    // Hold every header field stable between version A and version B so the
    // ONLY diff is the dropped package — otherwise the test would also be
    // sensitive to e.g. generated_at drift.
    manager_lockfile_sha256: 'cafef00d',
    node_version: '20.19.0',
    generated_at: '2026-05-16T00:00:00Z',
    packages,
  });
}

describe('diff-action path: dropped fixture is surfaced', () => {
  // The fixture we drop in "version B". Picked because its package id sorts
  // away from the very first/last in the file, making the hunk land in the
  // middle of the YAML — a more realistic case than dropping the tail entry.
  const DROPPED = 'spawns-gcc';

  it('produces a non-empty unified diff identifying the dropped package', () => {
    const all = listFixtures();
    expect(all).toContain(DROPPED);

    const fullEvents = all.flatMap(loadEvents);
    const reducedEvents = all
      .filter((f) => f !== DROPPED)
      .flatMap(loadEvents);

    const committedYaml = renderYaml(fullEvents); // version A (committed)
    const generatedYaml = renderYaml(reducedEvents); // version B (new run, missing one pkg)

    expect(committedYaml).not.toBe(generatedYaml);

    const diff = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed: committedYaml,
      generated: generatedYaml,
    });

    expect(diff.match).toBe(false);
    expect(diff.unified).not.toBe('');
    // The dropped package's id must appear on a removed-line in the diff.
    // Removed lines in a unified diff are prefixed with `-` (but headers
    // also start with `---`, so we match the package id without anchoring).
    expect(diff.unified).toContain(`${DROPPED}@1.0.0`);
    // Confirm at least one annotation was produced.
    expect(diff.annotations.length).toBeGreaterThan(0);
    // GitHub Actions ::error syntax with the lockfile path.
    for (const ann of diff.annotations) {
      expect(ann).toMatch(/^::error file=\.script-jail\.lock\.yml,line=\d+::/);
    }
  });

  it('reports match=true when committed and generated are byte-equal', () => {
    // Sanity: if nothing changed between the two runs, the diff path must
    // not produce a false positive — otherwise CI would fail every run.
    const all = listFixtures().flatMap(loadEvents);
    const yaml = renderYaml(all);
    const diff = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed: yaml,
      generated: yaml,
    });
    expect(diff.match).toBe(true);
    expect(diff.unified).toBe('');
    expect(diff.annotations).toEqual([]);
  });
});

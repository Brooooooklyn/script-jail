// npm-jar — scripts/build-e2e-golden.ts
//
// Produces a REFERENCE `.npm-jar.lock.yml` by running the e2e test harness's
// normalize() + render() pipeline over every fixture's expected-events.json.
// The output is byte-identical to what the production guest agent would emit
// for the same merged event stream, save for two fields the harness pins:
//
//   - generated_at:           2026-05-16T00:00:00Z  (hardcoded in harness.ts)
//   - manager_lockfile_sha256: deadbeef             (placeholder in harness.ts)
//
// In a real Layer 2 VM run, both fields vary:
//   - generated_at = new Date().toISOString()                  (src/guest/agent.ts:666)
//   - manager_lockfile_sha256 = sha256 of the real lockfile    (src/guest/agent.ts:642)
//
// Because src/action/diff.ts:48 compares committed vs generated YAML BYTE-EXACT,
// no static golden file can stay in sync with a real run.  This script's output
// is therefore checked in for HUMAN REFERENCE only — to make it easy to see
// what shape the action emits over the 7 fixtures, and to give a stable target
// for marker-substring assertions in the Layer 2 workflow (Task #28).
//
// Regenerate workflow:
//   oxnode scripts/build-e2e-golden.ts > test/e2e/consumer/.npm-jar.lock.yml.reference
//
// (We do NOT name the file `.golden` because that name historically implies
//  byte-equality is asserted somewhere; this file is purely informational.)

import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import { normalize, type NormalizeContext } from '../src/lock/normalize.js';
import { render } from '../src/lock/render.js';
import { AttributedEvent, type AttributedEvent as AttributedEventT } from '../src/lock/schema.js';

// Fixtures in the same order the e2e harness drives them — order is irrelevant
// (render() sorts by package key), but consistent ordering keeps the
// intermediate event log diffable when debugging.
const FIXTURES = [
  'reads-home-ssh',
  'reads-secret-env',
  'spawns-gcc',
  'tries-dlopen',
  'tries-network-egress',
  'writes-into-repo',
  'cross-package-tampering',
] as const;

// Mirrored from test/e2e/harness.ts so the reference YAML is byte-identical
// to what fakeVmFactory().finalYaml produces for the same fixture set.
const ROOTS = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.npm',
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, '..', 'test', 'fixtures');

function loadExpectedEvents(fixtureName: string): AttributedEventT[] {
  const path = join(FIXTURES_DIR, fixtureName, 'expected-events.json');
  const raw = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (!Array.isArray(raw)) {
    throw new Error(`fixture ${fixtureName}: expected-events.json is not an array`);
  }
  return raw.map((ev: unknown, i: number): AttributedEventT => {
    const r = AttributedEvent.safeParse(ev);
    if (!r.success) {
      throw new Error(
        `fixture ${fixtureName}: event[${i}] failed validation: ${JSON.stringify(r.error.issues)}`,
      );
    }
    return r.data;
  });
}

function pkgDirsFor(events: ReadonlyArray<AttributedEventT>): Map<string, string> {
  const out = new Map<string, string>();
  for (const ev of events) {
    if (out.has(ev.pkg)) continue;
    const name = ev.pkg.split('@')[0]!;
    out.set(ev.pkg, `${ROOTS.nodeModules}/${name}`);
  }
  return out;
}

function main(): void {
  const events: AttributedEventT[] = [];
  for (const fx of FIXTURES) {
    events.push(...loadExpectedEvents(fx));
  }
  const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
  const packages = normalize(events, ctx);
  const yaml = render({
    // The fixtures use pnpm-shaped package ids; manager is metadata only.
    // We render with 'pnpm' here to match the harness's choice — keeps the
    // reference file byte-identical to harness output for the same inputs.
    manager: 'pnpm',
    manager_lockfile_sha256: 'deadbeef',
    node_version: '20.19.0',
    generated_at: '2026-05-16T00:00:00Z',
    packages,
  });
  process.stdout.write(yaml);
}

main();

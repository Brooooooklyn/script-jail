// script-jail — test/e2e/check-mismatch-fixture.test.ts
//
// mode=check "fixture drifted" scenario: the guest emits a different YAML
// than what the consumer committed.  Simulated by supplying a
// `finalYamlOverride` to fakeVmFactory so the fake guest emits a YAML
// independent of (and incompatible with) the fixtures' expected events.
//
// The committed file is the canonical (un-overridden) YAML; the guest emits
// the override.  main() must:
//   - exit with code 1
//   - print a unified diff to stdout (with `---` and `+++` headers)
//   - print at least one `::error file=` annotation

import { describe, it, expect } from 'vitest';

import {
  setUpConsumer,
  fakeVmFactory,
  runMain,
  type FixtureName,
} from './harness.js';

const ALL_7: ReadonlyArray<FixtureName> = [
  'reads-home-ssh',
  'reads-secret-env',
  'spawns-gcc',
  'tries-dlopen',
  'tries-network-egress',
  'writes-into-repo',
  'cross-package-tampering',
];

// A YAML that is parseable by the lockfile renderer's downstream consumers
// but unmistakably different from what the fixtures produce.  Inline rather
// than read from disk so the test is self-contained.
const DRIFTED_YAML =
  'schema_version: 1\n' +
  'manager: npm\n' +
  'manager_lockfile_sha256: deadbeef\n' +
  'node_version: 20.19.0\n' +
  'generated_at: 2026-05-16T00:00:00Z\n' +
  'packages:\n' +
  '  drifted-pkg@1.0.0:\n' +
  '    lifecycle:\n' +
  '      postinstall:\n' +
  '        external_reads:\n' +
  '          - "<HIDDEN> $HOME/.ssh/id_rsa"\n';

describe.sequential('e2e: check (guest YAML drifted from committed)', () => {
  it('exits 1, prints a unified diff and a ::error annotation', async () => {
    // The committed file: canonical YAML for the fixtures (no override).
    const canonicalFactory = fakeVmFactory({ fixtures: ALL_7 });

    const consumer = setUpConsumer({
      pm: 'npm',
      fixtures: ALL_7,
      committedLockYaml: canonicalFactory.finalYaml,
    });

    // The fake guest used for THIS run emits the drifted YAML instead.
    const driftedFactory = fakeVmFactory({
      fixtures: ALL_7,
      finalYamlOverride: DRIFTED_YAML,
    });

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: {
        config: consumer.configPath,
        lock: consumer.lockPath,
        mode: 'check',
      },
      deps: driftedFactory.deps,
    });

    expect(result.error).toBeUndefined();
    expect(result.exit?.code).toBe(1);

    // Unified-diff headers from `createTwoFilesPatch` (see src/action/diff.ts).
    expect(result.stdout).toContain('---');
    expect(result.stdout).toContain('+++');

    // At least one GitHub Actions error annotation pointing at the lockfile.
    expect(result.stdout).toMatch(/::error file=[^,]+,line=\d+::/);
  });
});

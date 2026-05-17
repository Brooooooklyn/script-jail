// npm-jar — test/e2e/check-mismatch-committed.test.ts
//
// mode=check "committed-file tampered" scenario: the guest emits the canonical
// YAML, but the committed file in the consumer was edited to drop a marker
// line.  main() must:
//   - exit with code 1
//   - emit a unified diff in stdout that references the removed line

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

describe.sequential('e2e: check (committed file tampered)', () => {
  it('exits 1 and the diff references the removed marker line', async () => {
    const factory = fakeVmFactory({ fixtures: ALL_7 });
    const canonical = factory.finalYaml;

    // Sanity: the canonical YAML must contain the marker we plan to remove.
    // (If render shape changes, the assert here flags it before we mangle.)
    expect(canonical).toContain('<HIDDEN> NPM_TOKEN');

    // Remove the NPM_TOKEN marker line, keeping the rest of the file
    // structurally intact.  `replace` strips just the first occurrence which
    // is what we want.  The line is rendered as a YAML sequence item, so its
    // shape is `          - "<HIDDEN> NPM_TOKEN"` (indent + dash + quoted).
    // We strip the entire physical line including its trailing newline.
    const tamperedRegex = /^[ \t]*-\s+["']?<HIDDEN> NPM_TOKEN["']?[ \t]*\n/m;
    const tampered = canonical.replace(tamperedRegex, '');
    expect(tampered).not.toBe(canonical);
    expect(tampered).not.toContain('<HIDDEN> NPM_TOKEN');

    const consumer = setUpConsumer({
      pm: 'npm',
      fixtures: ALL_7,
      committedLockYaml: tampered,
    });

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: {
        config: consumer.configPath,
        lock: consumer.lockPath,
        mode: 'check',
      },
      deps: factory.deps,
    });

    expect(result.error).toBeUndefined();
    expect(result.exit?.code).toBe(1);

    // The unified diff should show the missing line as an addition in the
    // generated (b/...) side.  We look for the `+` prefix on the marker.
    expect(result.stdout).toContain('<HIDDEN> NPM_TOKEN');
    expect(result.stdout).toMatch(/^\+.*<HIDDEN> NPM_TOKEN/m);
  });
});

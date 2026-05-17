// script-jail — test/e2e/check-match.test.ts
//
// mode=check happy path: the consumer ships a committed lockfile byte-equal
// to what the guest agent would emit.  main() should:
//   - print no `::error file=` annotation
//   - return cleanly without calling exitProcess
//   - leave the committed file untouched on disk

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

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

describe.sequential('e2e: check (matching committed lockfile)', () => {
  it('exits cleanly, prints no annotations, and preserves the committed file', async () => {
    // The harness's factory.finalYaml IS the YAML production would emit, so
    // we can plant it verbatim as the committed file without an intermediate
    // generate-then-check pipeline.
    const factory = fakeVmFactory({ fixtures: ALL_7 });
    const consumer = setUpConsumer({
      pm: 'npm',
      fixtures: ALL_7,
      committedLockYaml: factory.finalYaml,
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
    // Match path: main() returns without calling exitProcess.
    expect(result.exit).toBeNull();
    // No GitHub annotations on a clean match.
    expect(result.stdout).not.toContain('::error file=');

    // mode=check must not overwrite the committed file on a match.
    const onDisk = readFileSync(consumer.lockPath, 'utf8');
    expect(onDisk).toBe(factory.finalYaml);
  });
});

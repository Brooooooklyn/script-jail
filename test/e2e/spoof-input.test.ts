// script-jail — test/e2e/spoof-input.test.ts
//
// Verifies the input-wiring boundary introduced by Task #18: when the action
// is invoked with `INPUT_SPOOF-PLATFORM=darwin`, the value reaches
// buildEffectiveConfig() and is written into the per-run config file that
// main() feeds to makeOverlay().
//
// The on-host source `.script-jail.yml` is set to `spoof.platform: linux`; the
// override should win, producing `platform: darwin` in the effective config
// file under `${RUNNER_TEMP}/script-jail-images/config.yml`.

import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  setUpConsumer,
  fakeVmFactory,
  runMain,
  type FixtureName,
} from './harness.js';

const FIXTURES: ReadonlyArray<FixtureName> = ['reads-home-ssh'];

describe.sequential('e2e: spoof-platform input wiring', () => {
  it('writes the action input override into the effective config file', async () => {
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES });
    const factory = fakeVmFactory({ fixtures: FIXTURES });

    // Force RUNNER_TEMP to a directory we own so we can find the effective
    // config file deterministically.  main() joins this with
    // `script-jail-images/config.yml`.  We restore the prior value in `finally`.
    const ownedRunnerTemp = mkdtempSync(join(tmpdir(), 'script-jail-spoof-test-'));
    const priorRunnerTemp = process.env['RUNNER_TEMP'];
    process.env['RUNNER_TEMP'] = ownedRunnerTemp;

    try {
      const result = await runMain({
        consumerDir: consumer.consumerDir,
        inputs: {
          config: consumer.configPath,
          lock: consumer.lockPath,
          mode: 'update',
          spoofPlatform: 'darwin',
        },
        deps: factory.deps,
      });

      expect(result.error).toBeUndefined();
      expect(result.exit).toBeNull();

      const effectivePath = join(ownedRunnerTemp, 'script-jail-images', 'config.yml');
      const effective = readFileSync(effectivePath, 'utf8');

      // YAML `stringify` emits `platform: darwin` (no quotes for a bare
      // identifier).  We assert on the substring rather than parsing so the
      // test stays decoupled from key ordering.
      expect(effective).toContain('platform: darwin');
      // The action default for arch is `x64`; absence of an override means it
      // still lands in the effective file as the runtime default.
      expect(effective).toContain('arch: x64');
    } finally {
      if (priorRunnerTemp === undefined) {
        delete process.env['RUNNER_TEMP'];
      } else {
        process.env['RUNNER_TEMP'] = priorRunnerTemp;
      }
    }
  });
});

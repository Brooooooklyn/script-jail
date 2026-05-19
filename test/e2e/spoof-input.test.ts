// script-jail — test/e2e/spoof-input.test.ts
//
// Verifies the input-wiring boundary introduced by Task #18: when the action
// is invoked with `INPUT_SPOOF-PLATFORM=darwin`, the value reaches
// buildEffectiveConfig() and is written into the per-run config file that
// main() feeds to makeOverlay().
//
// The on-host source `.script-jail.yml` is set to `spoof.platform: linux`; the
// override should win, producing `platform: darwin` in the effective config
// file that the host hands to makeOverlay.  Post-Task-#21 runAudit allocates
// (and removes) a private mkdtemp scratch dir for the rewritten config, so we
// can no longer probe a fixed path under RUNNER_TEMP — we wrap makeOverlay
// instead and read the config at the path it was invoked with BEFORE
// overlay.cleanup() removes the scratch tree.

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
import type { OverlayInput } from '../../src/action/firecracker/overlay.js';

const FIXTURES: ReadonlyArray<FixtureName> = ['reads-home-ssh'];

describe.sequential('e2e: spoof-platform input wiring', () => {
  it('writes the action input override into the effective config file', async () => {
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES });
    const factory = fakeVmFactory({ fixtures: FIXTURES });

    // Force RUNNER_TEMP to a directory we own so the (post-Task-#21) mkdtemp
    // scratch dir lands in a path we can inspect during the run.  We restore
    // the prior value in `finally`.
    const ownedRunnerTemp = mkdtempSync(join(tmpdir(), 'script-jail-spoof-test-'));
    const priorRunnerTemp = process.env['RUNNER_TEMP'];
    process.env['RUNNER_TEMP'] = ownedRunnerTemp;

    let capturedConfigContents: string | null = null;

    // Wrap the harness's fake makeOverlay so we snapshot the effective
    // config's contents BEFORE the overlay's cleanup removes the scratch
    // dir runAudit allocated.  We assert on the snapshot below.
    const wrappedMakeOverlay = async (opts: OverlayInput) => {
      capturedConfigContents = readFileSync(opts.configPath, 'utf8');
      return factory.deps.makeOverlay(opts);
    };

    try {
      const result = await runMain({
        consumerDir: consumer.consumerDir,
        inputs: {
          config: consumer.configPath,
          lock: consumer.lockPath,
          mode: 'update',
          spoofPlatform: 'darwin',
        },
        deps: { ...factory.deps, makeOverlay: wrappedMakeOverlay as typeof factory.deps.makeOverlay },
      });

      expect(result.error).toBeUndefined();
      expect(result.exit).toBeNull();

      // YAML `stringify` emits `platform: darwin` (no quotes for a bare
      // identifier).  We assert on the substring rather than parsing so the
      // test stays decoupled from key ordering.
      expect(capturedConfigContents).not.toBeNull();
      expect(capturedConfigContents!).toContain('platform: darwin');
      // The action default for arch is `x64`; absence of an override means it
      // still lands in the effective file as the runtime default.
      expect(capturedConfigContents!).toContain('arch: x64');
    } finally {
      if (priorRunnerTemp === undefined) {
        delete process.env['RUNNER_TEMP'];
      } else {
        process.env['RUNNER_TEMP'] = priorRunnerTemp;
      }
    }
  });
});

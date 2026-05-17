// script-jail — test/e2e/bun-skipped.test.ts
//
// A consumer whose only lockfile is `bun.lock` must trigger the v1
// BunUnsupportedError handler in main(): emit a ::warning:: annotation and
// call exitProcess(0).  The VM should never boot, so the fake deps are not
// exercised — they only need to exist for the harness to call main().

import { describe, it, expect } from 'vitest';

import {
  setUpConsumer,
  fakeVmFactory,
  runMain,
} from './harness.js';

describe.sequential('e2e: bun consumer skipped with warning', () => {
  it('warns and exits 0 without touching the fake VM', async () => {
    const consumer = setUpConsumer({ pm: 'bun', fixtures: [] });
    // No fixtures: main() bails at detectPm before any guest event would be
    // consumed.  The factory still needs to be wired so the harness can pass
    // MainDeps; the fake VsockSession is simply never opened.
    const factory = fakeVmFactory({ fixtures: [] });

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
    expect(result.exit?.code).toBe(0);

    // The `warn` helper writes `::warning::<msg>\n` to stdout.  The exact
    // message comes from BunUnsupportedError in src/action/detect-pm.ts.
    expect(result.stdout).toContain('::warning::');
    expect(result.stdout).toContain('script-jail v1 does not support bun');
  });
});

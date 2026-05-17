// script-jail — test/e2e/generate.test.ts
//
// Layer 1 end-to-end test: drives main() with mode=update against all seven
// fixtures and asserts the resulting `.script-jail.lock.yml` contains every
// expected package id and attack-shape marker.
//
// Uses the harness from test/e2e/harness.ts; no real VM, no /dev/kvm.  The
// fake VsockSession replays each fixture's expected-events.json and emits a
// `final` frame containing the YAML that production normalize()+render()
// would have produced for the merged event stream.

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

// describe.sequential: the harness mutates process.env and the stdout/stderr
// write hooks.  Vitest interleaves tests within the same file by default; the
// snapshot/restore in the harness is safe across files (separate workers) but
// not across concurrent tests in the same file.  Forcing sequential execution
// keeps the env-var dance honest.
describe.sequential('e2e: generate (mode=update)', () => {
  it('runs to completion without firing exitProcess', async () => {
    const consumer = setUpConsumer({ pm: 'npm', fixtures: ALL_7 });
    const factory = fakeVmFactory({ fixtures: ALL_7 });

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: {
        config: consumer.configPath,
        lock: consumer.lockPath,
        mode: 'update',
      },
      deps: factory.deps,
    });

    expect(result.error).toBeUndefined();
    expect(result.exit).toBeNull();
    // Stdout from update mode is only @actions/core setOutput markers
    // (`::set-output ...` or `<<DELIMITER` heredoc shape, depending on the
    // env).  No diff annotations should appear.
    expect(result.stdout).not.toContain('::error file=');
  });

  it('writes a lockfile with the canonical header and all seven package keys', async () => {
    const consumer = setUpConsumer({ pm: 'npm', fixtures: ALL_7 });
    const factory = fakeVmFactory({ fixtures: ALL_7 });

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: {
        config: consumer.configPath,
        lock: consumer.lockPath,
        mode: 'update',
      },
      deps: factory.deps,
    });

    expect(result.error).toBeUndefined();
    expect(result.exit).toBeNull();

    const written = readFileSync(consumer.lockPath, 'utf8');

    // Header fields rendered by src/lock/render.ts.
    expect(written).toContain('schema_version: 1');
    // The harness renders with manager:'pnpm' (see harness.ts comment); the
    // generated file therefore carries the same manager field regardless of
    // the consumer's lockfile shape.  We assert presence of the key rather
    // than a specific value to stay decoupled from that harness choice.
    expect(written).toMatch(/^manager: (npm|pnpm|yarn)$/m);

    // Every fixture package id should appear as a top-level key under packages.
    expect(written).toContain('reads-home-ssh@1.0.0:');
    expect(written).toContain('reads-secret-env@1.0.0:');
    expect(written).toContain('spawns-gcc@1.0.0:');
    expect(written).toContain('tries-dlopen@1.0.0:');
    expect(written).toContain('tries-network-egress@1.0.0:');
    expect(written).toContain('writes-into-repo@1.0.0:');
    expect(written).toContain('cross-package-tampering@1.0.0:');
  });

  it('renders every expected attack-shape marker', async () => {
    const consumer = setUpConsumer({ pm: 'npm', fixtures: ALL_7 });
    const factory = fakeVmFactory({ fixtures: ALL_7 });

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: {
        config: consumer.configPath,
        lock: consumer.lockPath,
        mode: 'update',
      },
      deps: factory.deps,
    });

    expect(result.error).toBeUndefined();
    expect(result.exit).toBeNull();

    const written = readFileSync(consumer.lockPath, 'utf8');

    expect(written).toContain('<HIDDEN> $HOME/.ssh/id_rsa');
    expect(written).toContain('<HIDDEN> NPM_TOKEN');
    expect(written).toContain('<ENOENT> gcc');
    expect(written).toContain('<BLOCKED> $PKG/evil.node');
    // Network: any host:port — assert on the "<BLOCKED> connect " prefix.
    expect(written).toContain('<BLOCKED> connect ');
    expect(written).toContain('$REPO/.bashrc');
    expect(written).toContain('<CROSS_PACKAGE> $NODE_MODULES/victim-package/index.js');
  });
});

// script-jail — test/e2e/install-gating.test.ts
//
// Drives main() with `install: true` and asserts the drop-in install gating
// matrix.  The host install/run-scripts halves are injected as fakes (via the
// MainDeps seams) so no real package manager runs — we only verify WHICH half
// fires under each audit outcome:
//
//   committed == generated (match)  → part 1 runs, part 2 runs,  exit clean
//   committed != generated (drift)  → part 1 runs, part 2 SKIPPED, exit 1
//   no committed lock               → neither runs (fail-closed), exit 1
//   mode: update + install          → neither runs (forbidden),   exit 1
//   install: false (default)        → neither runs (audit only)

import { describe, it, expect } from 'vitest';

import { setUpConsumer, fakeVmFactory, runMain, type FixtureName } from './harness.js';
import type { MainDeps } from '../../src/main.js';

const FIXTURES: ReadonlyArray<FixtureName> = ['spawns-gcc', 'writes-into-repo'];

interface HostCaptures {
  installCalls: Array<{ pm: string; args: string[] }>;
  runCalls: Array<{ pm: string }>;
  hostSeams: Pick<MainDeps, 'hostInstallNoScripts' | 'hostRunScripts'>;
}

function makeHostCaptures(): HostCaptures {
  const installCalls: Array<{ pm: string; args: string[] }> = [];
  const runCalls: Array<{ pm: string }> = [];
  return {
    installCalls,
    runCalls,
    hostSeams: {
      hostInstallNoScripts: (pm, _repoDir, args) => {
        installCalls.push({ pm, args: [...args] });
      },
      hostRunScripts: (pm) => {
        runCalls.push({ pm });
      },
    },
  };
}

describe.sequential('e2e: drop-in install gating', () => {
  it('match → runs part 1 (no-scripts) AND part 2 (scripts), exits clean', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.error).toBeUndefined();
    expect(result.exit).toBeNull(); // clean match → no exitProcess
    expect(cap.installCalls).toEqual([{ pm: 'npm', args: [] }]);
    expect(cap.runCalls).toEqual([{ pm: 'npm' }]);
  });

  it('match WITH recorded egress → warns (ONLINE + IP) before running part 2', async () => {
    // The audited lock records a `<BLOCKED> connect 198.51.100.7:443`; part 2
    // runs ONLINE so that egress will succeed on the host. The action must
    // surface it loudly before running the scripts.
    const EGRESS: ReadonlyArray<FixtureName> = ['tries-network-egress'];
    const factory = fakeVmFactory({ fixtures: EGRESS });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: EGRESS, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.error).toBeUndefined();
    expect(result.exit).toBeNull(); // clean match
    expect(cap.runCalls).toEqual([{ pm: 'npm' }]); // part 2 still runs
    // The warning fired, naming the egress and the online caveat.
    expect(result.stdout).toMatch(/::warning::.*ONLINE/);
    expect(result.stdout).toContain('198.51.100.7:443');
    expect(result.stdout).toMatch(/host may resolve different addresses/i);
  });

  it('match with NO recorded egress → part 2 runs but no egress warning', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(cap.runCalls).toEqual([{ pm: 'npm' }]);
    expect(result.stdout).not.toMatch(/network egress attempt/);
  });

  it('threads `args` into part 1 (no-scripts install)', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true, args: '--omit=dev' },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(cap.installCalls).toEqual([{ pm: 'npm', args: ['--omit=dev'] }]);
  });

  it('drift → runs part 1 but SKIPS part 2; exits 1; no-scripts tree kept', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    // Commit a lock that differs from what the guest emits → drift.
    const consumer = setUpConsumer({
      pm: 'npm',
      fixtures: FIXTURES,
      committedLockYaml: factory.finalYaml + '# tampered\n',
    });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.exit).toEqual({ code: 1 });
    expect(cap.installCalls).toHaveLength(1); // part 1 (safe) still ran
    expect(cap.runCalls).toHaveLength(0); // part 2 never runs on drift
  });

  it('no committed lock + install → fail-closed before any install, exit 1', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES }); // no committedLockYaml
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.exit).toEqual({ code: 1 });
    expect(result.stdout).toMatch(/requires a committed lock/);
    expect(cap.installCalls).toHaveLength(0); // exited before part 1
    expect(cap.runCalls).toHaveLength(0);
  });

  it('mode: update + install → forbidden, exit 1, neither half runs', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'update', install: true },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.exit).toEqual({ code: 1 });
    expect(result.stdout).toMatch(/requires `mode: check`/);
    expect(cap.installCalls).toHaveLength(0);
    expect(cap.runCalls).toHaveLength(0);
  });

  it('install: false (default) → audit only, neither half runs', async () => {
    const factory = fakeVmFactory({ fixtures: FIXTURES });
    const consumer = setUpConsumer({ pm: 'npm', fixtures: FIXTURES, committedLockYaml: factory.finalYaml });
    const cap = makeHostCaptures();

    const result = await runMain({
      consumerDir: consumer.consumerDir,
      inputs: { config: consumer.configPath, lock: consumer.lockPath, mode: 'check' /* install omitted */ },
      deps: { ...factory.deps, ...cap.hostSeams },
    });

    expect(result.exit).toBeNull();
    expect(cap.installCalls).toHaveLength(0);
    expect(cap.runCalls).toHaveLength(0);
  });
});

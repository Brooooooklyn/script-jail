// Tests for src/guest/attribution.ts
// Uses vitest project: "guest" (see vitest.config.ts)
// All tests use a synthetic in-memory ProcReader — no /proc I/O.

import { describe, it, expect } from 'vitest';
import { Attribution } from '../../src/guest/attribution.js';
import type { ProcReader, AttributionResult } from '../../src/guest/attribution.js';

// ---------------------------------------------------------------------------
// Synthetic ProcReader factory
// ---------------------------------------------------------------------------

interface ProcSpec {
  ppid: number | null;
  /** null means the environ file is unreadable for this pid. */
  env?: Record<string, string> | null;
}

interface InstrumentedReader extends ProcReader {
  ppidCalls: number;
  environCalls: number;
}

function syntheticReader(
  spec: Record<number, ProcSpec>,
): InstrumentedReader {
  let ppidCalls = 0;
  let environCalls = 0;

  return {
    get ppidCalls() { return ppidCalls; },
    get environCalls() { return environCalls; },

    readPpid(pid: number): number | null {
      ppidCalls++;
      const entry = spec[pid];
      if (entry === undefined) return null;
      return entry.ppid;
    },

    readEnviron(pid: number): Map<string, string> | null {
      environCalls++;
      const entry = spec[pid];
      if (entry === undefined) return null;
      if (entry.env === null || entry.env === undefined) return null;
      return new Map(Object.entries(entry.env));
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function npmEnv(
  name: string,
  version: string | undefined,
  event: string,
): Record<string, string> {
  const e: Record<string, string> = {
    npm_package_name: name,
    npm_lifecycle_event: event,
  };
  if (version !== undefined) e['npm_package_version'] = version;
  return e;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Attribution', () => {
  // 1. Linear chain: 300 → 200 → 100 → 1; pid 200 has matching npm env
  it('linear chain: finds first matching ancestor', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: {} },
      200: { ppid: 100, env: npmEnv('esbuild', '0.21.5', 'postinstall') },
      100: { ppid: 1,   env: {} },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toEqual<AttributionResult>({
      pkg: 'esbuild@0.21.5',
      lifecycle: 'postinstall',
    });
  });

  // 2. Root pid is the lifecycle owner itself (no walk needed)
  it('root pid is itself the lifecycle owner', () => {
    const reader = syntheticReader({
      200: { ppid: 1, env: npmEnv('esbuild', '0.21.5', 'postinstall') },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(200)).toEqual<AttributionResult>({
      pkg: 'esbuild@0.21.5',
      lifecycle: 'postinstall',
    });
  });

  // 3. No ancestor matches — all walk to pid 1 with no npm vars
  it('no ancestor matches → null', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: {} },
      200: { ppid: 1,   env: { HOME: '/root' } },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // 4. npm_package_version missing → pkg is just the name
  it('missing npm_package_version → pkg without @version', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: {} },
      200: { ppid: 1,   env: npmEnv('esbuild', undefined, 'install') },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toEqual<AttributionResult>({
      pkg: 'esbuild',
      lifecycle: 'install',
    });
  });

  // 5. npm_lifecycle_event is not canonical (e.g. 'test') → skip that pid, keep walking
  it('non-canonical lifecycle_event is skipped; canonical ancestor wins', () => {
    const reader = syntheticReader({
      400: { ppid: 300, env: {} },
      300: { ppid: 200, env: npmEnv('myapp', '1.0.0', 'test') },   // not canonical
      200: { ppid: 1,   env: npmEnv('myapp', '1.0.0', 'prepare') }, // canonical
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(400)).toEqual<AttributionResult>({
      pkg: 'myapp@1.0.0',
      lifecycle: 'prepare',
    });
  });

  // 6. npm_lifecycle_event missing → keep walking
  it('missing npm_lifecycle_event is skipped; canonical ancestor wins', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: { npm_package_name: 'esbuild', npm_package_version: '0.21.5' } },
      200: { ppid: 1,   env: npmEnv('esbuild', '0.21.5', 'install') },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toEqual<AttributionResult>({
      pkg: 'esbuild@0.21.5',
      lifecycle: 'install',
    });
  });

  // 7. Each of the four canonical LifecycleStage values is recognised
  it.each([
    ['preinstall',  'preinstall']  as const,
    ['install',     'install']     as const,
    ['postinstall', 'postinstall'] as const,
    ['prepare',     'prepare']     as const,
  ])('recognises canonical lifecycle stage: %s', (event, expectedLifecycle) => {
    const reader = syntheticReader({
      100: { ppid: 1, env: npmEnv('pkg', '1.0.0', event) },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(100)).toEqual<AttributionResult>({
      pkg: 'pkg@1.0.0',
      lifecycle: expectedLifecycle,
    });
  });

  // 8. Chain hits pid 1 (init) → terminate, return null
  it('chain hits pid 1 → null', () => {
    const reader = syntheticReader({
      300: { ppid: 1, env: {} },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // 9. Chain hits pid 0 → terminate, return null
  it('chain hits pid 0 → null', () => {
    const reader = syntheticReader({
      300: { ppid: 0, env: {} },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // 10a. environ is null but ppid is readable → continue walking
  it('null environ for intermediate pid → continue walking via ppid', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: null },  // environ unreadable, but ppid is fine
      200: { ppid: 1,   env: npmEnv('esbuild', '0.21.5', 'postinstall') },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toEqual<AttributionResult>({
      pkg: 'esbuild@0.21.5',
      lifecycle: 'postinstall',
    });
  });

  // 10b. environ is null AND ppid is also null → terminate
  it('null environ AND null ppid → null', () => {
    const reader = syntheticReader({
      300: { ppid: null, env: null },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // 11. readPpid returns null → terminate walk
  it('null ppid terminates walk → null', () => {
    const reader = syntheticReader({
      300: { ppid: null, env: {} },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // 12. Caching: second call must not trigger any additional /proc reads
  it('caching: second attribute(samePid) issues no further reads', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: {} },
      200: { ppid: 1,   env: npmEnv('esbuild', '0.21.5', 'postinstall') },
    });
    const attr = new Attribution(reader);

    const first = attr.attribute(300);
    const ppidAfterFirst = reader.ppidCalls;
    const environAfterFirst = reader.environCalls;

    const second = attr.attribute(300);
    expect(second).toEqual(first);
    expect(reader.ppidCalls).toBe(ppidAfterFirst);
    expect(reader.environCalls).toBe(environAfterFirst);
  });

  // Audit-trust follow-up (Codex review of e22c79b, 2026-05-19):
  // `invalidate(pid)` drops the per-pid cache entry so the NEXT
  // `attribute(pid)` call re-walks /proc.  The phase-install
  // dispatcher calls this on every observed `+++ exited +++` strace
  // line to handle pid recycling: without it, a recycled pid's
  // subsequent attribution returns the dead generation's cached
  // result.
  it('invalidate(pid) drops cache → next attribute(pid) re-reads /proc', () => {
    // Stateful reader that returns one environ on first read of pid
    // 500 and a different environ on the next.  The pid's ppid stays
    // 1 in both cases so a single environ read is enough to terminate
    // the walk.
    let environReads = 0;
    const readerSpec: Record<number, ProcSpec> = {
      500: { ppid: 1, env: npmEnv('pkg-a', '1.0.0', 'install') },
    };
    const reader: ProcReader = {
      readPpid(pid: number): number | null {
        return readerSpec[pid]?.ppid ?? null;
      },
      readEnviron(pid: number): Map<string, string> | null {
        environReads += 1;
        if (pid === 500) {
          // First read → pkg-a; subsequent reads → pkg-b (recycled pid
          // whose new /proc/<pid>/environ has different npm vars).
          const env =
            environReads === 1
              ? npmEnv('pkg-a', '1.0.0', 'install')
              : npmEnv('pkg-b', '2.0.0', 'postinstall');
          return new Map(Object.entries(env));
        }
        const entry = readerSpec[pid];
        if (entry === undefined) return null;
        if (entry.env === null || entry.env === undefined) return null;
        return new Map(Object.entries(entry.env));
      },
    };

    const attr = new Attribution(reader);

    // First call → pkg-a (the cache is populated).
    expect(attr.attribute(500)).toEqual<AttributionResult>({
      pkg: 'pkg-a@1.0.0',
      lifecycle: 'install',
    });

    // Without invalidate, a second call would hit the cache and
    // return pkg-a — this is the exact bug `invalidate` exists to
    // fix.  Sanity-check the cache works as documented before
    // invalidating.
    expect(attr.attribute(500)).toEqual<AttributionResult>({
      pkg: 'pkg-a@1.0.0',
      lifecycle: 'install',
    });

    // Invalidate and call again — the reader is consulted afresh and
    // returns the recycled pid's NEW environ (pkg-b).
    attr.invalidate(500);
    expect(attr.attribute(500)).toEqual<AttributionResult>({
      pkg: 'pkg-b@2.0.0',
      lifecycle: 'postinstall',
    });
  });

  // Defensive: invalidate(pid) on a pid that was never cached is a
  // no-op (Map.delete on a missing key).  This ensures the dispatcher
  // can call invalidate() unconditionally on every exit line without
  // needing to gate on cache membership.
  it('invalidate(pid) on uncached pid is a no-op', () => {
    const reader = syntheticReader({
      600: { ppid: 1, env: npmEnv('pkg-x', '1.0.0', 'install') },
    });
    const attr = new Attribution(reader);
    // No prior attribute(600) call → cache is empty for pid 600.
    expect(() => attr.invalidate(600)).not.toThrow();
    // Subsequent attribute returns the expected result.
    expect(attr.attribute(600)).toEqual<AttributionResult>({
      pkg: 'pkg-x@1.0.0',
      lifecycle: 'install',
    });
  });

  // 13. Two pids sharing an ancestor
  // Terminal-result caching only (v1): each starting pid is cached separately.
  // The shared ancestor (200) may be re-read for the second starting pid (400)
  // because we only cache the terminal result per starting pid, not per
  // intermediate pid. This is documented as a known v1 limitation.
  it('two pids sharing an ancestor both resolve correctly', () => {
    const reader = syntheticReader({
      300: { ppid: 200, env: {} },
      400: { ppid: 200, env: {} },
      200: { ppid: 1,   env: npmEnv('shared-pkg', '2.0.0', 'install') },
    });
    const attr = new Attribution(reader);

    expect(attr.attribute(300)).toEqual<AttributionResult>({
      pkg: 'shared-pkg@2.0.0',
      lifecycle: 'install',
    });
    expect(attr.attribute(400)).toEqual<AttributionResult>({
      pkg: 'shared-pkg@2.0.0',
      lifecycle: 'install',
    });
  });

  // Extra: 'start' is not canonical — walk past it even when npm_package_name is set
  it("npm_lifecycle_event='start' is not canonical → walk past it", () => {
    const reader = syntheticReader({
      500: { ppid: 400, env: npmEnv('app', '1.0.0', 'start') },
      400: { ppid: 1,   env: {} },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(500)).toBeNull();
  });

  // Empty npm_package_name is rejected — would produce malformed pkg like '@1.2.3'
  it('empty npm_package_name is not treated as a match → null', () => {
    const reader = syntheticReader({
      300: { ppid: 1, env: { npm_package_name: '', npm_lifecycle_event: 'install', npm_package_version: '1.2.3' } },
    });
    const attr = new Attribution(reader);
    expect(attr.attribute(300)).toBeNull();
  });

  // TODO(v2): forged-env limitation — documents the current behaviour.
  // In v1 attribution trusts the environment of the observed process itself;
  // a subprocess that injects forged npm_* vars is accepted as-is.
  // A future trusted-root design would require attribution anchored to the
  // package-manager's own launch context rather than unchecked process env.
  it('forged npm env on the starting pid is accepted (v1 limitation, see attribution.ts:120)', () => {
    const reader = syntheticReader({
      // pid 600 is a child spawned by a malicious lifecycle script that set
      // npm_package_name to a different package ('victim-pkg').
      600: { ppid: 500, env: npmEnv('victim-pkg', '9.9.9', 'postinstall') },
      500: { ppid: 1,   env: npmEnv('attacker-pkg', '1.0.0', 'postinstall') },
    });
    const attr = new Attribution(reader);
    // v1 returns the forged env because the walk starts at pid 600, which
    // is the first ancestor checked. A trusted-root design would return
    // attacker-pkg (the real npm root) instead.
    expect(attr.attribute(600)).toEqual<AttributionResult>({
      pkg: 'victim-pkg@9.9.9',
      lifecycle: 'postinstall',
    });
  });
});

// ---------------------------------------------------------------------------
// Separate describe block: validate AttributionResult shape
// ---------------------------------------------------------------------------

describe('AttributionResult shape', () => {
  it('pkg fallback: only npm_package_name (no version) → no @ suffix', () => {
    const reader = syntheticReader({
      10: { ppid: 1, env: { npm_package_name: 'my-tool', npm_lifecycle_event: 'install' } },
    });
    const result = new Attribution(reader).attribute(10);
    expect(result).not.toBeNull();
    expect(result!.pkg).toBe('my-tool');
    expect(result!.pkg).not.toContain('@');
  });

  it('pkg with version: npm_package_name + npm_package_version → name@version', () => {
    const reader = syntheticReader({
      20: { ppid: 1, env: npmEnv('my-tool', '3.2.1', 'postinstall') },
    });
    const result = new Attribution(reader).attribute(20);
    expect(result).not.toBeNull();
    expect(result!.pkg).toBe('my-tool@3.2.1');
  });
});

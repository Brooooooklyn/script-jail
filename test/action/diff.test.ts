// script-jail — test/action/diff.test.ts
//
// Tests for renderDiff() — unified diff + GitHub Actions annotation formatter.

import { describe, it, expect } from 'vitest';

import {
  renderDiff,
  findAuditBypass,
  formatAuditBypassError,
  collectNetworkAttempts,
  formatEgressWarning,
} from '../../src/action/diff.js';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('renderDiff — match', () => {
  it('returns empty diff and match=true when inputs are byte-equal', () => {
    const content = 'line1\nline2\nline3\n';
    const r = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed: content,
      generated: content,
    });
    expect(r.match).toBe(true);
    expect(r.unified).toBe('');
    expect(r.annotations).toEqual([]);
  });

  it('returns match=true when both inputs are empty strings', () => {
    const r = renderDiff({
      lockPath: 'x.yml',
      committed: '',
      generated: '',
    });
    expect(r.match).toBe(true);
    expect(r.unified).toBe('');
    expect(r.annotations).toEqual([]);
  });
});

describe('renderDiff — single hunk', () => {
  it('produces one annotation pointing at the new-file start line', () => {
    const committed = 'a\nb\nc\nd\ne\n';
    const generated = 'a\nb\nC\nd\ne\n'; // line 3 changed (c → C)
    const r = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed,
      generated,
    });

    expect(r.match).toBe(false);
    expect(r.unified).not.toBe('');
    expect(r.unified).toContain('a/.script-jail.lock.yml');
    expect(r.unified).toContain('b/.script-jail.lock.yml');

    expect(r.annotations.length).toBe(1);
    const ann = r.annotations[0]!;
    expect(ann).toMatch(/^::error file=\.script-jail\.lock\.yml,line=\d+::/);
    expect(ann).toContain('lockfile drifted');
  });
});

describe('renderDiff — missing committed', () => {
  it('emits a "would be created" annotation at line 1', () => {
    const generated = 'line1\nline2\nline3\n';
    const r = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed: '',
      generated,
    });

    expect(r.match).toBe(false);
    expect(r.unified).not.toBe('');
    expect(r.annotations.length).toBe(1);
    const ann = r.annotations[0]!;
    expect(ann).toMatch(/^::error file=\.script-jail\.lock\.yml,line=1::/);
    expect(ann).toContain('lockfile missing');
    expect(ann).toContain('would be created');
    expect(ann).toMatch(/\(3 lines\)/);
  });

  it('counts a trailing-newline-free generated file correctly', () => {
    // "a\nb\nc" (no trailing \n) is 3 lines, not 2 or 4.  Off-by-one regression
    // guard for the countLines helper.
    const r = renderDiff({
      lockPath: 'x.yml',
      committed: '',
      generated: 'a\nb\nc',
    });
    expect(r.annotations.length).toBe(1);
    expect(r.annotations[0]).toMatch(/would be created \(3 lines\)/);
  });

  it('counts a single-line generated file with no newline as 1 line', () => {
    const r = renderDiff({
      lockPath: 'x.yml',
      committed: '',
      generated: 'only-line',
    });
    expect(r.annotations.length).toBe(1);
    expect(r.annotations[0]).toMatch(/would be created \(1 lines\)/);
  });

  it('counts a file with a trailing newline correctly', () => {
    // "a\nb\n" is 2 lines — the trailing \n does not create an empty third line.
    const r = renderDiff({
      lockPath: 'x.yml',
      committed: '',
      generated: 'a\nb\n',
    });
    expect(r.annotations.length).toBe(1);
    expect(r.annotations[0]).toMatch(/would be created \(2 lines\)/);
  });

  it('handles missing committed with empty generated (both empty → match)', () => {
    const r = renderDiff({ lockPath: 'x.yml', committed: '', generated: '' });
    expect(r.match).toBe(true);
    expect(r.annotations).toEqual([]);
  });
});

describe('renderDiff — multi-hunk', () => {
  it('produces one annotation per hunk', () => {
    // A long file with two non-adjacent changes — should produce 2 hunks.
    const committedLines: string[] = [];
    for (let i = 0; i < 30; i++) committedLines.push(`line${i}`);
    const committed = committedLines.join('\n') + '\n';

    const generatedLines = committedLines.slice();
    generatedLines[2] = 'CHANGED2';
    generatedLines[25] = 'CHANGED25';
    const generated = generatedLines.join('\n') + '\n';

    const r = renderDiff({
      lockPath: 'x.yml',
      committed,
      generated,
    });

    expect(r.match).toBe(false);
    expect(r.annotations.length).toBe(2);
    expect(r.annotations[0]).toMatch(/^::error file=x\.yml,line=\d+::/);
    expect(r.annotations[1]).toMatch(/^::error file=x\.yml,line=\d+::/);
  });
});

describe('renderDiff — determinism', () => {
  it('produces identical output for the same input across multiple calls', () => {
    const committed = 'a\nb\nc\n';
    const generated = 'a\nb\nC\n';

    const r1 = renderDiff({ lockPath: 'x.yml', committed, generated });
    const r2 = renderDiff({ lockPath: 'x.yml', committed, generated });

    expect(r1.unified).toBe(r2.unified);
    expect(r1.annotations).toEqual(r2.annotations);
    expect(r1.match).toBe(r2.match);
  });
});

describe('renderDiff — annotation format', () => {
  it('uses GitHub Actions ::error annotation syntax', () => {
    const r = renderDiff({
      lockPath: 'path/to/file.yml',
      committed: 'foo\n',
      generated: 'bar\n',
    });
    expect(r.annotations[0]).toMatch(/^::error file=path\/to\/file\.yml,line=\d+::/);
  });

  it('includes the line counts in the message', () => {
    const committed = 'a\n';
    const generated = 'a\nb\nc\n'; // 2 additions
    const r = renderDiff({ lockPath: 'x.yml', committed, generated });

    expect(r.annotations.length).toBe(1);
    // Pin the exact count so an off-by-one in the hunk walker is caught.
    expect(r.annotations[0]).toMatch(/2 lines added/);
    expect(r.annotations[0]).toMatch(/0 lines removed/);
  });

  it('reports both added and removed counts exactly', () => {
    // 5 → 5 lines but lines 2 and 4 differ → 2 removed, 2 added in a single hunk.
    const committed = 'a\nb\nc\nd\ne\n';
    const generated = 'a\nB\nc\nD\ne\n';
    const r = renderDiff({ lockPath: 'x.yml', committed, generated });

    expect(r.annotations.length).toBe(1);
    expect(r.annotations[0]).toMatch(/2 lines added/);
    expect(r.annotations[0]).toMatch(/2 lines removed/);
  });
});

// ---------------------------------------------------------------------------
// Volatile-field canonicalization (generated_at + manager_lockfile_sha256)
// ---------------------------------------------------------------------------

describe('renderDiff — volatile field canonicalization', () => {
  it('returns match=true when only generated_at differs', () => {
    const committed =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages: {}\n';
    const generated =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'generated_at: 2026-05-17T10:00:00.000Z\n' +
      'packages: {}\n';

    const r = renderDiff({ lockPath: '.script-jail.lock.yml', committed, generated });
    expect(r.match).toBe(true);
    expect(r.unified).toBe('');
    expect(r.annotations).toEqual([]);
  });

  it('returns match=true when only manager_lockfile_sha256 differs', () => {
    const committed =
      'schema_version: 1\n' +
      'manager_lockfile_sha256: "abc123"\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages: {}\n';
    const generated =
      'schema_version: 1\n' +
      'manager_lockfile_sha256: "def456"\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages: {}\n';

    const r = renderDiff({ lockPath: 'x.yml', committed, generated });
    expect(r.match).toBe(true);
    expect(r.unified).toBe('');
    expect(r.annotations).toEqual([]);
  });

  it('returns match=true when both volatile fields differ together', () => {
    const committed =
      'schema_version: 1\n' +
      'manager_lockfile_sha256: "abc123"\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages: {}\n';
    const generated =
      'schema_version: 1\n' +
      'manager_lockfile_sha256: "def456"\n' +
      'generated_at: 2026-05-17T10:00:00.000Z\n' +
      'packages: {}\n';

    const r = renderDiff({ lockPath: 'x.yml', committed, generated });
    expect(r.match).toBe(true);
  });

  it('still reports drift when a real semantic field differs', () => {
    // Volatile fields ALSO differ — canonicalization should not mask the
    // real `manager` change.
    const committed =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages: {}\n';
    const generated =
      'schema_version: 1\n' +
      'manager: pnpm\n' +
      'generated_at: 2026-05-17T10:00:00.000Z\n' +
      'packages: {}\n';

    const r = renderDiff({ lockPath: 'x.yml', committed, generated });
    expect(r.match).toBe(false);
    // The unified output uses the ORIGINAL strings (with real timestamps)
    // rather than the canonical sentinel, so reviewers see actual values.
    expect(r.unified).toContain('manager: npm');
    expect(r.unified).toContain('manager: pnpm');
    expect(r.unified).toContain('2026-05-17T09:00:00.000Z');
    expect(r.unified).toContain('2026-05-17T10:00:00.000Z');
  });

  it('does not touch values on indented lines that happen to share the key', () => {
    // A `generated_at` line inside a deeply nested key (hypothetical) must
    // NOT be canonicalized — the regex anchors to column 0.
    const committed =
      'packages:\n' +
      '  some-pkg@1.0.0:\n' +
      '    nested:\n' +
      '      generated_at: when-this-record-was-collected\n';
    const generated =
      'packages:\n' +
      '  some-pkg@1.0.0:\n' +
      '    nested:\n' +
      '      generated_at: a-different-collection-time\n';

    const r = renderDiff({ lockPath: 'x.yml', committed, generated });
    expect(r.match).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// audit_bypass scan (Finding B: defense-in-depth gate)
// ---------------------------------------------------------------------------

// Compose a minimal valid-shape lockfile YAML for the scan tests.  We hand-
// build the YAML rather than calling render() to keep the test independent
// of any future render-side reshuffling.
function lockfileWith(opts: {
  audit_bypass?: string[];
  network_attempts?: string[];
  pkgId?: string;
  stage?: string;
}): string {
  const pkgId = opts.pkgId ?? 'evil-pkg@1.0.0';
  const stage = opts.stage ?? 'postinstall';
  const bypass = opts.audit_bypass ?? [];
  const network = opts.network_attempts ?? [];
  const lines: string[] = [];
  lines.push('schema_version: 1');
  lines.push('manager: npm');
  lines.push('manager_lockfile_sha256: "abc"');
  lines.push('node_version: 20.0.0');
  lines.push('generated_at: 2026-05-17T09:00:00.000Z');
  lines.push('packages:');
  lines.push(`  ${pkgId}:`);
  lines.push('    lifecycle:');
  lines.push(`      ${stage}:`);
  lines.push('        external_reads: []');
  lines.push('        escaped_writes: []');
  lines.push('        env_read: []');
  lines.push('        spawn_attempts: []');
  lines.push('        spawn_blocked: []');
  lines.push('        dlopen_attempts: []');
  if (network.length > 0) {
    lines.push('        network_attempts:');
    for (const e of network) lines.push(`          - "${e}"`);
  } else {
    lines.push('        network_attempts: []');
  }
  if (bypass.length > 0) {
    lines.push('        audit_bypass:');
    for (const e of bypass) {
      // YAML quoting: just quote it — the `<` literal is safe in a quoted
      // scalar and parsers round-trip it cleanly.
      lines.push(`          - "${e}"`);
    }
  }
  return lines.join('\n') + '\n';
}

describe('findAuditBypass', () => {
  it('returns an empty list for a lockfile with no audit_bypass', () => {
    const yaml = lockfileWith({});
    expect(findAuditBypass(yaml)).toEqual([]);
  });

  it('returns each non-empty audit_bypass entry with pkg+stage attribution', () => {
    const yaml = lockfileWith({
      pkgId: 'evil@1.0.0',
      stage: 'postinstall',
      audit_bypass: ['<EXEC_FAIL_OPEN> /usr/bin/node'],
    });
    const r = findAuditBypass(yaml);
    expect(r.length).toBe(1);
    expect(r[0]).toEqual({
      packageId: 'evil@1.0.0',
      stage: 'postinstall',
      entry: '<EXEC_FAIL_OPEN> /usr/bin/node',
    });
  });

  it('returns multiple entries across packages and stages', () => {
    const yaml =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'manager_lockfile_sha256: "abc"\n' +
      'node_version: 20.0.0\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages:\n' +
      '  a@1.0.0:\n' +
      '    lifecycle:\n' +
      '      postinstall:\n' +
      '        external_reads: []\n' +
      '        escaped_writes: []\n' +
      '        env_read: []\n' +
      '        spawn_attempts: []\n' +
      '        spawn_blocked: []\n' +
      '        dlopen_attempts: []\n' +
      '        network_attempts: []\n' +
      '        audit_bypass:\n' +
      '          - "<EXEC_FAIL_OPEN> /usr/bin/node"\n' +
      '  b@2.0.0:\n' +
      '    lifecycle:\n' +
      '      prepare:\n' +
      '        external_reads: []\n' +
      '        escaped_writes: []\n' +
      '        env_read: []\n' +
      '        spawn_attempts: []\n' +
      '        spawn_blocked: []\n' +
      '        dlopen_attempts: []\n' +
      '        network_attempts: []\n' +
      '        audit_bypass:\n' +
      '          - "<EXEC_FAIL_OPEN> /bin/sh"\n';
    const r = findAuditBypass(yaml);
    expect(r.length).toBe(2);
    // findAuditBypass walks Object.entries — order is insertion order for
    // plain objects from YAML.parse on string keys, which is the YAML doc's
    // order.  Don't depend on the exact ordering across runs; assert
    // membership instead.
    const tuples = r.map((e) => `${e.packageId}|${e.stage}|${e.entry}`).sort();
    expect(tuples).toEqual([
      'a@1.0.0|postinstall|<EXEC_FAIL_OPEN> /usr/bin/node',
      'b@2.0.0|prepare|<EXEC_FAIL_OPEN> /bin/sh',
    ]);
  });

  it('returns an empty list for malformed YAML rather than throwing', () => {
    expect(findAuditBypass('not: [valid: yaml: at: all')).toEqual([]);
  });

  it('returns an empty list for an empty input', () => {
    expect(findAuditBypass('')).toEqual([]);
  });

  it('ignores audit_bypass entries that are not strings or are empty', () => {
    const yaml =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'manager_lockfile_sha256: "abc"\n' +
      'node_version: 20.0.0\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages:\n' +
      '  a@1.0.0:\n' +
      '    lifecycle:\n' +
      '      postinstall:\n' +
      '        external_reads: []\n' +
      '        escaped_writes: []\n' +
      '        env_read: []\n' +
      '        spawn_attempts: []\n' +
      '        spawn_blocked: []\n' +
      '        dlopen_attempts: []\n' +
      '        network_attempts: []\n' +
      '        audit_bypass:\n' +
      '          - ""\n' +
      '          - "<EXEC_FAIL_OPEN> /usr/bin/node"\n';
    const r = findAuditBypass(yaml);
    // The empty string is skipped; only the real entry surfaces.
    expect(r.length).toBe(1);
    expect(r[0]?.entry).toBe('<EXEC_FAIL_OPEN> /usr/bin/node');
  });
});

describe('formatAuditBypassError', () => {
  it('formats a single entry as a human-readable list', () => {
    const msg = formatAuditBypassError([
      {
        packageId: 'evil@1.0.0',
        stage: 'postinstall',
        entry: '<EXEC_FAIL_OPEN> /usr/bin/node',
      },
    ]);
    expect(msg).toContain('Audit envelope was bypassed');
    expect(msg).toContain('evil@1.0.0');
    expect(msg).toContain('postinstall');
    expect(msg).toContain('<EXEC_FAIL_OPEN> /usr/bin/node');
  });

  it('truncates long lists with a "(+N more)" tail', () => {
    const entries = Array.from({ length: 25 }, (_, i) => ({
      packageId: `pkg-${i}@1.0.0`,
      stage: 'postinstall',
      entry: `<EXEC_FAIL_OPEN> /bin/p${i}`,
    }));
    const msg = formatAuditBypassError(entries);
    expect(msg).toContain('(+15 more)');
  });
});

describe('collectNetworkAttempts', () => {
  it('returns an empty list for a lockfile with no network_attempts', () => {
    expect(collectNetworkAttempts(lockfileWith({}))).toEqual([]);
  });

  it('returns each entry with pkg+stage attribution', () => {
    const yaml = lockfileWith({
      pkgId: 'better-sqlite3@11.0.0',
      stage: 'postinstall',
      network_attempts: ['<BLOCKED> connect 198.51.100.7:443'],
    });
    expect(collectNetworkAttempts(yaml)).toEqual([
      {
        packageId: 'better-sqlite3@11.0.0',
        stage: 'postinstall',
        entry: '<BLOCKED> connect 198.51.100.7:443',
      },
    ]);
  });

  it('returns multiple entries across packages and stages', () => {
    const yaml =
      'schema_version: 1\n' +
      'manager: npm\n' +
      'manager_lockfile_sha256: "abc"\n' +
      'node_version: 20.0.0\n' +
      'generated_at: 2026-05-17T09:00:00.000Z\n' +
      'packages:\n' +
      '  a@1.0.0:\n' +
      '    lifecycle:\n' +
      '      postinstall:\n' +
      '        external_reads: []\n' +
      '        escaped_writes: []\n' +
      '        env_read: []\n' +
      '        spawn_attempts: []\n' +
      '        spawn_blocked: []\n' +
      '        dlopen_attempts: []\n' +
      '        network_attempts:\n' +
      '          - "<BLOCKED> connect 198.51.100.7:443"\n' +
      '          - "<BLOCKED> connect 203.0.113.9:80"\n' +
      '  b@2.0.0:\n' +
      '    lifecycle:\n' +
      '      prepare:\n' +
      '        external_reads: []\n' +
      '        escaped_writes: []\n' +
      '        env_read: []\n' +
      '        spawn_attempts: []\n' +
      '        spawn_blocked: []\n' +
      '        dlopen_attempts: []\n' +
      '        network_attempts:\n' +
      '          - "<BLOCKED> connect 192.0.2.5:443"\n';
    const tuples = collectNetworkAttempts(yaml)
      .map((e) => `${e.packageId}|${e.stage}|${e.entry}`)
      .sort();
    expect(tuples).toEqual([
      'a@1.0.0|postinstall|<BLOCKED> connect 198.51.100.7:443',
      'a@1.0.0|postinstall|<BLOCKED> connect 203.0.113.9:80',
      'b@2.0.0|prepare|<BLOCKED> connect 192.0.2.5:443',
    ]);
  });

  it('returns an empty list for malformed YAML or empty input (no throw)', () => {
    expect(collectNetworkAttempts('not: [valid: yaml: at: all')).toEqual([]);
    expect(collectNetworkAttempts('')).toEqual([]);
  });
});

describe('formatEgressWarning', () => {
  const entries = [
    { packageId: 'better-sqlite3@11.0.0', stage: 'postinstall', entry: '<BLOCKED> connect 198.51.100.7:443' },
    { packageId: 'esbuild@0.21.0', stage: 'postinstall', entry: '<BLOCKED> connect 203.0.113.9:443' },
  ];
  const noRoots = { manager: 'npm' as const, rootPackageIds: new Set<string>() };

  it('summary states ONLINE + count + the IP caveat (single line for the annotation)', () => {
    const { summary } = formatEgressWarning(entries, noRoots);
    expect(summary).not.toContain('\n');
    expect(summary).toContain('ONLINE');
    expect(summary).toContain('2 network egress attempt(s)');
    expect(summary).toMatch(/host may resolve different addresses/i);
  });

  it('detail lists each pkg+stage+entry on its own line', () => {
    const { detail } = formatEgressWarning(entries, noRoots);
    expect(detail).toContain('better-sqlite3@11.0.0 (postinstall)  <BLOCKED> connect 198.51.100.7:443');
    expect(detail).toContain('esbuild@0.21.0 (postinstall)  <BLOCKED> connect 203.0.113.9:443');
  });

  it('truncates the detail list past 20 entries with a "(+N more)" tail', () => {
    const many = Array.from({ length: 23 }, (_, i) => ({
      packageId: `pkg-${i}@1.0.0`,
      stage: 'postinstall',
      entry: `<BLOCKED> connect 198.51.100.${i}:443`,
    }));
    const { summary, detail } = formatEgressWarning(many, noRoots);
    expect(summary).toContain('23 network egress attempt(s)');
    expect(detail).toContain('(+3 more');
  });

  // --- root `prepare` partition: npm/yarn host rebuild does NOT run it -------

  const rootPrepare = {
    packageId: 'my-app@1.0.0',
    stage: 'prepare',
    entry: '<BLOCKED> connect 192.0.2.5:443',
  };
  const depPost = {
    packageId: 'better-sqlite3@11.0.0',
    stage: 'postinstall',
    entry: '<BLOCKED> connect 198.51.100.7:443',
  };
  const rootIds = new Set(['my-app', 'my-app@1.0.0']);

  it('npm: a root `prepare` egress is audited-only (excluded from the WILL-succeed count); a dep stays host-bound', () => {
    const { summary, detail } = formatEgressWarning([rootPrepare, depPost], {
      manager: 'npm',
      rootPackageIds: rootIds,
    });
    // Only the dep counts toward the host-bound "WILL now succeed" total.
    expect(summary).toContain('1 network egress attempt(s)');
    expect(summary).toContain('WILL now succeed');
    // The dep is host-bound, listed in the main block.
    expect(detail).toContain('better-sqlite3@11.0.0 (postinstall)  <BLOCKED> connect 198.51.100.7:443');
    // The root prepare is split into the audited-only block.
    expect(detail).toContain('audited in the sandbox; NOT run on the host (root `prepare`):');
    expect(detail).toContain('my-app@1.0.0 (prepare)  <BLOCKED> connect 192.0.2.5:443');
  });

  it('yarn: the same root `prepare` egress is audited-only', () => {
    const { summary, detail } = formatEgressWarning([rootPrepare, depPost], {
      manager: 'yarn',
      rootPackageIds: rootIds,
    });
    expect(summary).toContain('1 network egress attempt(s)');
    expect(detail).toContain('audited in the sandbox; NOT run on the host (root `prepare`):');
    expect(detail).toContain('my-app@1.0.0 (prepare)  <BLOCKED> connect 192.0.2.5:443');
  });

  it('pnpm: the same root `prepare` egress stays host-bound (rebuild --pending runs it)', () => {
    const { summary, detail } = formatEgressWarning([rootPrepare, depPost], {
      manager: 'pnpm',
      rootPackageIds: rootIds,
    });
    // Both entries are host-bound under pnpm.
    expect(summary).toContain('2 network egress attempt(s)');
    expect(summary).toContain('WILL now succeed');
    expect(detail).toContain('my-app@1.0.0 (prepare)  <BLOCKED> connect 192.0.2.5:443');
    // No audited-only block.
    expect(detail).not.toContain('audited in the sandbox; NOT run on the host');
  });

  it('a `prepare` egress whose pkg is NOT a root id stays host-bound (only the ROOT prepare is special)', () => {
    const nonRootPrepare = {
      packageId: 'some-dep@2.0.0',
      stage: 'prepare',
      entry: '<BLOCKED> connect 203.0.113.9:443',
    };
    const { summary, detail } = formatEgressWarning([nonRootPrepare], {
      manager: 'npm',
      rootPackageIds: rootIds,
    });
    expect(summary).toContain('1 network egress attempt(s)');
    expect(summary).toContain('WILL now succeed');
    expect(detail).toContain('some-dep@2.0.0 (prepare)  <BLOCKED> connect 203.0.113.9:443');
    expect(detail).not.toContain('audited in the sandbox; NOT run on the host');
  });

  it('host-bound empty + audited-only nonempty: summary must NOT claim host egress', () => {
    const { summary, detail } = formatEgressWarning([rootPrepare], {
      manager: 'npm',
      rootPackageIds: rootIds,
    });
    expect(summary).not.toContain('WILL now succeed');
    expect(summary).not.toContain('ONLINE');
    expect(summary).toMatch(/will NOT run on the host/i);
    expect(detail).toContain('audited in the sandbox; NOT run on the host (root `prepare`):');
    expect(detail).toContain('my-app@1.0.0 (prepare)  <BLOCKED> connect 192.0.2.5:443');
  });
});

// ---------------------------------------------------------------------------
// Defense-in-depth: lockfile equality is NOT success when audit_bypass is set.
// This asserts the invariant the check-mode gate in src/main.ts enforces:
// renderDiff() can still return match=true (because committed === generated),
// but findAuditBypass() MUST return a non-empty list and the action must
// hard-fail.  We exercise both functions in parallel here.
// ---------------------------------------------------------------------------

describe('audit_bypass + lockfile equality (Finding B)', () => {
  it('renderDiff matches when committed == generated, but findAuditBypass still flags the bypass', () => {
    const yaml = lockfileWith({
      audit_bypass: ['<EXEC_FAIL_OPEN> /usr/bin/node'],
    });
    const diff = renderDiff({
      lockPath: '.script-jail.lock.yml',
      committed: yaml,
      generated: yaml,
    });
    // The byte-equality path says "no drift" — exactly the silenced state
    // a malicious PR would commit.
    expect(diff.match).toBe(true);

    // But the standalone gate fires regardless, surfacing the bypass.
    const bypass = findAuditBypass(yaml);
    expect(bypass.length).toBeGreaterThan(0);
    expect(bypass[0]?.entry).toBe('<EXEC_FAIL_OPEN> /usr/bin/node');
  });
});

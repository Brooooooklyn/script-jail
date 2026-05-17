// script-jail — test/action/diff.test.ts
//
// Tests for renderDiff() — unified diff + GitHub Actions annotation formatter.

import { describe, it, expect } from 'vitest';

import { renderDiff } from '../../src/action/diff.js';

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

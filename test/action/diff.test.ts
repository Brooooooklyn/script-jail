// npm-jar — test/action/diff.test.ts
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
      lockPath: '.npm-jar.lock.yml',
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
      lockPath: '.npm-jar.lock.yml',
      committed,
      generated,
    });

    expect(r.match).toBe(false);
    expect(r.unified).not.toBe('');
    expect(r.unified).toContain('a/.npm-jar.lock.yml');
    expect(r.unified).toContain('b/.npm-jar.lock.yml');

    expect(r.annotations.length).toBe(1);
    const ann = r.annotations[0]!;
    expect(ann).toMatch(/^::error file=\.npm-jar\.lock\.yml,line=\d+::/);
    expect(ann).toContain('lockfile drifted');
  });
});

describe('renderDiff — missing committed', () => {
  it('emits a "would be created" annotation at line 1', () => {
    const generated = 'line1\nline2\nline3\n';
    const r = renderDiff({
      lockPath: '.npm-jar.lock.yml',
      committed: '',
      generated,
    });

    expect(r.match).toBe(false);
    expect(r.unified).not.toBe('');
    expect(r.annotations.length).toBe(1);
    const ann = r.annotations[0]!;
    expect(ann).toMatch(/^::error file=\.npm-jar\.lock\.yml,line=1::/);
    expect(ann).toContain('lockfile missing');
    expect(ann).toContain('would be created');
    expect(ann).toMatch(/3 lines/);
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
    expect(r.annotations[0]).toMatch(/added/);
  });
});

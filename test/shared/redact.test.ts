// script-jail — test/shared/redact.test.ts
//
// Unit tests for the shared credential-shape redactor.  These same regexes are
// exercised through the guest agent (redactSensitive) and the host install
// (part-1 captured output); here we test the pure functions in isolation.

import { describe, it, expect } from 'vitest';

import {
  redactCredentialShapes,
  maskExactValues,
  maskValueFragments,
  maskValueFragmentsWith,
  buildFragmentMatcher,
  type FragmentMatcher,
} from '../../src/shared/redact.js';

describe('redactCredentialShapes', () => {
  it('drops userinfo from a scheme://user:pass@host URL, keeping scheme + host', () => {
    const out = redactCredentialShapes('proxy=https://user:PASSWORDABCDEF@host:8080/path');
    expect(out).not.toContain('PASSWORDABCDEF');
    expect(out).not.toContain('user:');
    expect(out).toContain('https://<REDACTED:URL-CREDENTIALS>@host:8080/path');
  });

  it('drops userinfo from a SCHEME-RELATIVE //user:pass@host URL too (F3 parity)', () => {
    // The scheme-relative form is masked when it stands alone (at start-of-string
    // or after a safe delimiter), mirroring pm-commands' credential rejector.
    expect(redactCredentialShapes('registry=//user:PASSWORDABCDEF@npm.acme.internal/'))
      .toBe('registry=//<REDACTED:URL-CREDENTIALS>@npm.acme.internal/');
    expect(redactCredentialShapes('//user:PASSWORDABCDEF@host/')) // start-of-string
      .toBe('//<REDACTED:URL-CREDENTIALS>@host/');
    expect(redactCredentialShapes('see //user:PASSWORDABCDEF@host here')) // after space
      .toContain('//<REDACTED:URL-CREDENTIALS>@host');
  });

  it('does NOT mask a // that appears INSIDE a URL path (F7 false-positive guard)', () => {
    // A `//foo:bar@baz` deeper in a path is NOT userinfo (`new URL` reports an
    // empty username), so the scheme-relative rule — anchored to start / a safe
    // delimiter — must leave it untouched and not corrupt the diagnostic.
    expect(redactCredentialShapes('registry=https://host/path//foo:bar@baz'))
      .toBe('registry=https://host/path//foo:bar@baz');
    expect(redactCredentialShapes('a//b:c@d')).toBe('a//b:c@d');
    // The schemeful credential in the SAME string is still masked, the path // is not.
    expect(redactCredentialShapes('https://u:PASSWORDXYZ@host/x//y:z@w'))
      .toBe('https://<REDACTED:URL-CREDENTIALS>@host/x//y:z@w');
  });

  it('masks an npm rc _authToken= line value', () => {
    const out = redactCredentialShapes('//registry.npmjs.org/:_authToken=npmTokenABCDEFGH01234567');
    expect(out).not.toContain('npmTokenABCDEFGH01234567');
    expect(out).toContain('_authToken=<REDACTED>');
  });

  it('masks _auth= and _password= rc lines', () => {
    expect(redactCredentialShapes('_auth=YWJjOmRlZmdoaWprbA==')).toContain('_auth=<REDACTED>');
    expect(redactCredentialShapes('_password=hunter2hunter2')).toContain('_password=<REDACTED>');
  });

  it('masks a Bearer token, keeping the Bearer marker', () => {
    const out = redactCredentialShapes('Authorization: Bearer ABCDEFGH01234567890123456789');
    expect(out).not.toContain('ABCDEFGH01234567890123456789');
    expect(out).toContain('Bearer <REDACTED>');
  });

  it('masks an npm_ token literal (36+ chars)', () => {
    const tok = 'npm_' + 'A'.repeat(36);
    const out = redactCredentialShapes(`found token ${tok} in env`);
    expect(out).not.toContain(tok);
    expect(out).toContain('<REDACTED:NPM-TOKEN>');
  });

  it('masks a GitHub token literal (ghp_/gho_/ghs_/ghu_/ghr_ + 36+ chars)', () => {
    const tok = 'ghp_' + 'B'.repeat(36);
    const out = redactCredentialShapes(`token=${tok}`);
    expect(out).not.toContain(tok);
    expect(out).toContain('<REDACTED:GH-TOKEN>');
  });

  it('masks an AWS access key id (AKIA/ASIA + 16 upper-alnum)', () => {
    const out = redactCredentialShapes('AKIAIOSFODNN7EXAMPLE was here');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).toContain('<REDACTED:AWS-KEY>');
  });

  it('is line-local: a Bearer marker and token on separate lines is NOT masked', () => {
    const out = redactCredentialShapes('Authorization: Bearer\nTOKEN0123456789ABCDEF');
    // By the line-local contract, this is not a credential.
    expect(out).toContain('TOKEN0123456789ABCDEF');
  });

  it('is linear-time on a long contiguous [a-z0-9+.-] run (URL-creds ReDoS regression)', () => {
    // The URL-credentials scheme prefix used to be unbounded (`*`) with no
    // `://` tail, backtracking O(N) per start position → O(N²): 160 KB took
    // ~12 s.  Bounding the scheme to {0,31} drops the fixed path to ~12 ms.
    // A 200 KB contiguous class-char run has no `://`, so it matches NOTHING
    // and must be returned unchanged — and must finish well under the bound.
    const input = 'a'.repeat(200_000);
    const start = performance.now();
    const out = redactCredentialShapes(input);
    const elapsedMs = performance.now() - start;
    // (a) no `://` → no match → input returned unchanged.
    expect(out).toBe(input);
    // (b) generous wall-clock bound: fixed path is ~12 ms; ~2 s never flakes
    // under CI load yet still catches the multi-second O(N²) regression.
    expect(elapsedMs).toBeLessThan(2000);
  });
});

describe('maskExactValues', () => {
  it('masks each value with the supplied label', () => {
    const out = maskExactValues('a=SECRETVAL b=OTHERVAL', ['SECRETVAL', 'OTHERVAL'], 'REDACTED:USER-ARG');
    expect(out).toBe('a=<REDACTED:USER-ARG> b=<REDACTED:USER-ARG>');
  });

  it('uses the default label when none is given', () => {
    expect(maskExactValues('x=SECRETV', ['SECRETV'])).toBe('x=<REDACTED>');
  });

  it('skips values shorter than minLen (default 4)', () => {
    // "dev" is 3 chars — must NOT be masked, so "devDependencies" survives intact.
    const out = maskExactValues('installed devDependencies', ['dev']);
    expect(out).toBe('installed devDependencies');
  });

  it('honours a custom minLen', () => {
    expect(maskExactValues('aXY', ['XY'], 'R', 2)).toBe('a<R>');
    expect(maskExactValues('aXY', ['XY'], 'R', 3)).toBe('aXY');
  });

  it('masks longest-first so a substring value does not partially pre-mask', () => {
    // "SECRET" is a substring of "SECRETLONG".  Longest-first ensures the long
    // value is masked whole before the short one runs.
    const out = maskExactValues('val=SECRETLONG and SECRET', ['SECRET', 'SECRETLONG'], 'R');
    expect(out).toBe('val=<R> and <R>');
    // The long value must not be left as "<R>LONG" (partial pre-mask).
    expect(out).not.toContain('LONG');
  });

  it('dedupes identical values (masked once, idempotent output)', () => {
    const out = maskExactValues('SECRETV SECRETV', ['SECRETV', 'SECRETV'], 'R');
    expect(out).toBe('<R> <R>');
  });
});

describe('maskValueFragments', () => {
  const SECRET = 'npm_AB12cd34EF56gh78IJ90klMNopQRstUVwx'; // 38 chars, high-entropy

  it('masks a PREFIX of a declared value truncated mid-write (>= minFragment)', () => {
    // A concurrent newline truncated the secret at a prefix; exact masking would
    // miss it, fragment masking catches it.
    const prefix = SECRET.slice(0, 20);
    const out = maskValueFragments(`fetching with token ${prefix} now`, [SECRET], 'REDACTED:ENV');
    expect(out).not.toContain(prefix);
    expect(out).toBe('fetching with token <REDACTED:ENV> now');
  });

  it('masks a SUFFIX of a declared value (split on the previous line)', () => {
    const suffix = SECRET.slice(SECRET.length - 18);
    const out = maskValueFragments(`...${suffix} trailing`, [SECRET], 'REDACTED:ENV');
    expect(out).not.toContain(suffix);
    expect(out).toBe('...<REDACTED:ENV> trailing');
  });

  it('masks the WHOLE value too when called standalone', () => {
    expect(maskValueFragments(`tok=${SECRET}`, [SECRET], 'R')).toBe('tok=<R>');
  });

  it('does NOT mask a fragment shorter than the minFragment floor (default 8)', () => {
    const tiny = SECRET.slice(0, 7); // 7 < 8
    const out = maskValueFragments(`x ${tiny} y`, [SECRET], 'R');
    expect(out).toBe(`x ${tiny} y`); // too short to be a distinguishable secret fragment
  });

  it('does NOT mass-mask benign output when no fragment is present', () => {
    const out = maskValueFragments('installing devDependencies and building', [SECRET], 'R');
    expect(out).toBe('installing devDependencies and building');
  });

  it('skips values at or below the minFragment length (whole value is exact-masked elsewhere)', () => {
    // length-8 value with minFragment 8 → filtered out (length must be > floor).
    expect(maskValueFragments('abcd1234 here', ['abcd1234'], 'R')).toBe('abcd1234 here');
  });

  it('masks a MIDDLE slice (both ends torn) of a declared value (n-gram overlap)', () => {
    // A slice from the interior of the secret — neither a prefix nor a suffix —
    // is also fully covered by secret grams, so the whole run is masked.  This is
    // what the earlier prefix/suffix-extraction approach could not do.
    const middle = SECRET.slice(9, 31); // 22 interior chars
    const out = maskValueFragments(`x ${middle} y`, [SECRET], 'R');
    expect(out).not.toContain(middle);
    expect(out).toBe('x <R> y');
  });

  it('does NOT leak a shorter value tail when a longer value shares the gate prefix (F6 round-3 #1)', () => {
    // Two declared secrets share the first 8 chars.  The gram set is built from
    // EVERY value in ONE pass (cross-value, not per-value), so the longer value's
    // shared prefix grams can never consume a window and strand the shorter
    // value's longer leaked fragment — every window of the leaked fragment is a
    // gram of v2 and is masked.
    const v1 = 'abcdefgh' + 'X'.repeat(100);  // 108 chars
    const v2 = 'abcdefghSECRETTAILMORE';       // 22 chars, shares 'abcdefgh'
    const out = maskValueFragments('leak ' + v2.slice(0, 18), [v1, v2], 'R');
    expect(out).not.toContain('SECRETTAIL');
    expect(out).toBe('leak <R>');
  });

  it('masks a prefix AND suffix of a value LONGER than any scan window (F6 round-3 #2)', () => {
    // A >512-char secret is NOT excluded: every minFragment-window of the value
    // is a gram (no eligibility length cap, no scan window), so a prefix or suffix
    // leak of a long secret (key, JSON blob) is masked.
    const big = 'K'.repeat(600) + 'TAILTOKEN9'; // 610 chars
    expect(maskValueFragments('leak ' + big.slice(0, 20), [big], 'R')).toBe('leak <R>');
    expect(maskValueFragments('leak ' + big.slice(big.length - 20), [big], 'R')).toBe('leak <R>');
  });

  it('masks a fragment regardless of how many times it occurs (no occurrence cap to leak past)', () => {
    // The earlier extraction approach capped occurrences at 4096; the n-gram scan
    // has no per-occurrence accounting, so a leaked fragment is masked whether it
    // appears once or thousands of times — every occurrence is the same gram run.
    const frag = SECRET.slice(0, 16);
    const line = (frag + ' ').repeat(5000); // far past the old 4096 cap
    const out = maskValueFragments(line, [SECRET], 'R');
    expect(out).not.toContain(frag);
    expect(out).toBe(('<R> ').repeat(5000)); // each 16-char frag → <R>, single spaces preserved
  });

  it('is bounded on a pathological 1 MiB line repeating the gate prefix (no superlinear blowup)', () => {
    // 64 declared values (the protected.env cap), adversarial line repeating one
    // value's 8-char window.  The scan is O(|text| * minFragment) with a bounded
    // gram set — no dependence on occurrence count — so it stays well under bound.
    const vals = Array.from({ length: 64 }, (_, i) => (`V${i}_`).padEnd(8, 'z') + 'q'.repeat(504));
    const minP0 = vals[0]!.slice(0, 8);
    const line = (minP0 + ' ').repeat(Math.floor((1024 * 1024) / (minP0.length + 1)));
    const start = performance.now();
    maskValueFragments(line, vals, 'R');
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it('does NOT blackhole a large but OS-bounded declared set — full coverage, not fail-closed (review #7)', () => {
    // 64 declared values of 17 KB each ≈ 1.09 MiB total — a realistic upper bound
    // for a CI `protected.env` (several base64 certs / kubeconfigs).  This is well
    // under the 2^22 ceiling, so it must get FULL fragment coverage: a benign line
    // is UNTOUCHED (not masked to `<R>`) and a real fragment of one value IS
    // masked.  (Pre-fix the ~1M ceiling was reachable here and blackholed lines.)
    const vals = Array.from({ length: 64 }, (_, v) => {
      let a = (v * 2654435761) >>> 0;
      const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      let s = '';
      for (let i = 0; i < 17_000; i += 1) {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        s += alpha[((t ^ (t >>> 14)) >>> 0) % alpha.length];
      }
      return s;
    });
    const matcher = buildFragmentMatcher(vals);
    expect(matcher.capped).toBe(false); // under the ceiling → NOT fail-closed
    const benign = 'info: building project, installing devDependencies, done';
    expect(maskValueFragmentsWith(benign, matcher, 'R')).toBe(benign); // not blackholed
    const frag = vals[40]!.slice(100, 124); // a 24-char interior slice of a declared value
    expect(maskValueFragmentsWith(`leak ${frag} end`, matcher, 'R')).toBe('leak <R> end');
  });

  it('FAILS CLOSED (whole-text mask) when the matcher is capped, but passes short lines through', () => {
    // Direct test of the fail-closed behavior via a hand-built capped matcher —
    // the 2^22 ceiling is unreachable by OS-bounded inputs, so exercise the path
    // without allocating millions of grams.  A capped matcher masks the whole
    // line rather than risk leaking a later value's uncovered fragment; a line
    // too short to hold any fragment (< minFragment) is still returned unchanged.
    const capped: FragmentMatcher = { grams: new Set<string>(), capped: true, minFragment: 8 };
    expect(maskValueFragmentsWith('an ordinary diagnostic line', capped, 'R')).toBe('<R>');
    expect(maskValueFragmentsWith('short', capped, 'R')).toBe('short'); // < 8 chars → nothing to leak
  });
});

// script-jail — test/shared/redact.test.ts
//
// Unit tests for the shared credential-shape redactor.  These same regexes are
// exercised through the guest agent (redactSensitive) and the host install
// (part-1 captured output); here we test the pure functions in isolation.

import { describe, it, expect } from 'vitest';

import { redactCredentialShapes, maskExactValues } from '../../src/shared/redact.js';

describe('redactCredentialShapes', () => {
  it('drops userinfo from a scheme://user:pass@host URL, keeping scheme + host', () => {
    const out = redactCredentialShapes('proxy=https://user:PASSWORDABCDEF@host:8080/path');
    expect(out).not.toContain('PASSWORDABCDEF');
    expect(out).not.toContain('user:');
    expect(out).toContain('https://<REDACTED:URL-CREDENTIALS>@host:8080/path');
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

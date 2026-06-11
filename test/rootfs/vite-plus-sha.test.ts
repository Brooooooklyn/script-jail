// script-jail — test/rootfs/vite-plus-sha.test.ts
//
// Regression guard for the vite-plus (vp) tarball SHA trust chain that broke
// the v0.2.0 producer. Text/behaviour-level because the real fetch only runs
// inside a Linux docker build. Three layers:
//
//   1. The pinned constants: VITE_PLUS_SHA256 (linux) and VITE_PLUS_DARWIN_SHA256
//      (darwin) share x64/arm64 keys but MUST hold distinct 64-hex values, so a
//      producer that selected the wrong block ships visibly-wrong bytes.
//   2. scripts/print-vite-plus-sha.ts: the producer reads the LINUX sha via this
//      typed import, NOT a sed/regex text-parse. It must print the linux value,
//      never the darwin one, and fail closed on a bad/missing arch.
//   3. Dockerfile.base: fetch+verify is ONE retry unit, so a transient
//      wrong-bytes 200 retries instead of aborting the producer.
//
// Root cause this locks out: PR #8 added VITE_PLUS_DARWIN_SHA256; a bare
// `sed .../x64:/` then matched BOTH objects -> two-line VP_SHA256 -> sha256sum
// verified the linux tarball against the darwin hash (2399331b…) -> every
// producer run failed at the vp fetch step.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  VITE_PLUS_SHA256,
  VITE_PLUS_DARWIN_SHA256,
} from '../../src/rootfs/vite-plus.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../');
const HEX64 = /^[0-9a-f]{64}$/;

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runPrintScript(arch: string): RunResult {
  try {
    const stdout = execFileSync(
      join(repoRoot, 'node_modules/.bin/oxnode'),
      [join(repoRoot, 'scripts/print-vite-plus-sha.ts'), arch],
      { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

describe('vite-plus pinned SHA constants', () => {
  it('VITE_PLUS_SHA256 (linux) holds 64-hex x64 + arm64', () => {
    expect(VITE_PLUS_SHA256.x64).toMatch(HEX64);
    expect(VITE_PLUS_SHA256.arm64).toMatch(HEX64);
  });

  it('VITE_PLUS_DARWIN_SHA256 holds 64-hex x64 + arm64', () => {
    expect(VITE_PLUS_DARWIN_SHA256.x64).toMatch(HEX64);
    expect(VITE_PLUS_DARWIN_SHA256.arm64).toMatch(HEX64);
  });

  it('linux and darwin pins are DISTINCT per arch (a block mixup ships wrong bytes)', () => {
    expect(VITE_PLUS_SHA256.x64).not.toBe(VITE_PLUS_DARWIN_SHA256.x64);
    expect(VITE_PLUS_SHA256.arm64).not.toBe(VITE_PLUS_DARWIN_SHA256.arm64);
  });
});

describe('scripts/print-vite-plus-sha.ts (producer reads the LINUX pin)', () => {
  it('prints the linux x64 sha, never the darwin one', () => {
    const r = runPrintScript('x64');
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(VITE_PLUS_SHA256.x64);
    expect(r.stdout).not.toBe(VITE_PLUS_DARWIN_SHA256.x64);
  });

  it('prints the linux arm64 sha, never the darwin one', () => {
    const r = runPrintScript('arm64');
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(VITE_PLUS_SHA256.arm64);
    expect(r.stdout).not.toBe(VITE_PLUS_DARWIN_SHA256.arm64);
  });

  it('emits the sha ALONE on stdout (no banner/whitespace to pollute the build-arg)', () => {
    const r = runPrintScript('x64');
    expect(r.stdout).toMatch(HEX64); // anchored ^…$, so no leading/trailing noise
  });

  it('fails closed on an unknown arch (non-zero exit, empty stdout)', () => {
    const r = runPrintScript('darwin');
    expect(r.status).not.toBe(0);
    expect(r.stdout).toBe('');
  });

  it('fails closed on a missing arch arg', () => {
    const r = runPrintScript('');
    expect(r.status).not.toBe(0);
  });
});

describe('release-build.yml producer wiring', () => {
  const WF = readFileSync(
    join(repoRoot, '.github/workflows/release-build.yml'),
    'utf8',
  );

  it('reads vp shas via the typed print script (direct bin), not a sed text-parse', () => {
    expect(WF).toContain(
      './node_modules/.bin/oxnode scripts/print-vite-plus-sha.ts x64',
    );
    expect(WF).toContain(
      './node_modules/.bin/oxnode scripts/print-vite-plus-sha.ts arm64',
    );
    // The buggy unscoped text-parse must be gone…
    expect(WF).not.toContain('x64:[[:space:]]');
    // …and NOT via `pnpm exec`, whose "Done in …ms" banner pollutes stdout.
    expect(WF).not.toContain('pnpm exec oxnode scripts/print-vite-plus-sha');
  });

  it('re-validates each parsed sha is 64-hex before the build-arg', () => {
    expect(WF).toContain('case "${vp_sha_x64}" in *[!0-9a-f]*');
    expect(WF).toContain('case "${vp_sha_arm64}" in *[!0-9a-f]*');
    expect(WF).toContain('[ "${#vp_sha_x64}" = 64 ]');
    expect(WF).toContain('[ "${#vp_sha_arm64}" = 64 ]');
  });
});

describe('Dockerfile.base vp fetch+verify is one retry unit', () => {
  const DOCKERFILE = readFileSync(
    join(repoRoot, 'src/rootfs/Dockerfile.base'),
    'utf8',
  );

  it('verifies the sha INSIDE the retry loop (curl && sha256sum -c in one if)', () => {
    // curl and the checksum must be ANDed in one condition so a mismatch
    // retries rather than aborting on the first try.
    expect(DOCKERFILE).toMatch(
      /curl[\s\S]{0,160}-o \/tmp\/vp\.tgz[\s\S]{0,120}&&[\s\S]{0,80}sha256sum -c -; then/,
    );
  });

  it('deletes the partial tarball between attempts', () => {
    expect(DOCKERFILE).toMatch(/rm -f \/tmp\/vp\.tgz;/);
  });

  it('only fails after the loop exhausts (ok flag), not on the first mismatch', () => {
    expect(DOCKERFILE).toMatch(/\[ "\$ok" = 1 \] \|\|[\s\S]{0,80}exit 1/);
  });
});

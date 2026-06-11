// Tests for src/guest/proc-reader-macos.ts
// Uses vitest project: "guest" (see vitest.config.ts)
//
// MacOSProcReader shells out to the `sj-procinfo` helper via spawnSync; the
// constructor takes the helper path (falling back to SCRIPT_JAIL_PROCINFO_PATH),
// which is the injection seam.  We point it at tiny `#!/bin/sh` scripts in a
// temp dir, so every branch is exercised hermetically and the suite is
// OS-neutral (/bin/sh exists on both macOS and the Linux CI runner — the class
// itself never checks process.platform, so no skipIf gating is needed).

import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MacOSProcReader } from '../../src/guest/proc-reader-macos.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

let fakeRoot: string;
let helperCount = 0;

function makeRoot(): string {
  fakeRoot = mkdtempSync(join(tmpdir(), 'script-jail-procinfo-'));
  return fakeRoot;
}

/** Write an executable /bin/sh script standing in for the sj-procinfo helper. */
function makeHelper(body: string): string {
  const root = fakeRoot || makeRoot();
  const file = join(root, `sj-procinfo-${helperCount++}`);
  writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return file;
}

afterEach(() => {
  if (fakeRoot) {
    rmSync(fakeRoot, { recursive: true, force: true });
    fakeRoot = '';
  }
});

// ---------------------------------------------------------------------------
// readPpid — helper disabled (no spawn at all)
// ---------------------------------------------------------------------------

describe('MacOSProcReader.readPpid — helper unconfigured', () => {
  const ENV_KEY = 'SCRIPT_JAIL_PROCINFO_PATH';
  let savedEnv: string | undefined;

  beforeEach(() => {
    savedEnv = process.env[ENV_KEY];
    delete process.env[ENV_KEY];
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env[ENV_KEY];
    } else {
      process.env[ENV_KEY] = savedEnv;
    }
  });

  it('returns null immediately when constructed with an explicit null', () => {
    const reader = new MacOSProcReader(null);
    expect(reader.readPpid(1)).toBeNull();
  });

  it('returns null when SCRIPT_JAIL_PROCINFO_PATH is unset (env fallback)', () => {
    const reader = new MacOSProcReader();
    expect(reader.readPpid(1)).toBeNull();
  });

  it('returns null when SCRIPT_JAIL_PROCINFO_PATH is set but empty', () => {
    process.env[ENV_KEY] = '';
    const reader = new MacOSProcReader();
    expect(reader.readPpid(1)).toBeNull();
  });

  it('resolves the helper from SCRIPT_JAIL_PROCINFO_PATH when no arg is given', () => {
    process.env[ENV_KEY] = makeHelper('echo 42');
    const reader = new MacOSProcReader();
    expect(reader.readPpid(123)).toBe(42);
  });
});

// ---------------------------------------------------------------------------
// readPpid — helper spawn outcomes
// ---------------------------------------------------------------------------

describe('MacOSProcReader.readPpid — helper outcomes', () => {
  it('returns the ppid printed by the helper (pid forwarded as argv[1])', () => {
    // Echo the pid argument back, proving both arg passing and stdout parsing
    // (echo's trailing newline must be trimmed).
    const reader = new MacOSProcReader(makeHelper('printf "%s\\n" "$1"'));
    expect(reader.readPpid(777)).toBe(777);
  });

  it('returns null when the helper exits non-zero (pid gone / not permitted)', () => {
    // Parseable stdout must NOT win over a non-zero status.
    const reader = new MacOSProcReader(makeHelper('echo 99\nexit 3'));
    expect(reader.readPpid(100)).toBeNull();
  });

  it('returns null on unparseable stdout', () => {
    const reader = new MacOSProcReader(makeHelper('echo not-a-pid'));
    expect(reader.readPpid(100)).toBeNull();
  });

  it('returns null on empty stdout', () => {
    const reader = new MacOSProcReader(makeHelper('exit 0'));
    expect(reader.readPpid(100)).toBeNull();
  });

  it('returns null on a non-positive ppid (kernel pseudo-parent / garbage)', () => {
    expect(new MacOSProcReader(makeHelper('echo 0')).readPpid(100)).toBeNull();
    expect(new MacOSProcReader(makeHelper('echo -5')).readPpid(100)).toBeNull();
  });

  it('returns null (never throws) when the helper binary does not exist — ENOENT', () => {
    // spawnSync reports ENOENT via result.error with status null; the
    // status !== 0 guard turns that into a null without ever throwing.
    const reader = new MacOSProcReader(join(makeRoot(), 'no-such-sj-procinfo'));
    expect(reader.readPpid(100)).toBeNull();
  });

  it('returns null (never throws) when spawnSync itself throws — catch block', () => {
    // An empty-string command makes spawnSync throw ERR_INVALID_ARG_VALUE
    // synchronously (and '' is not null, so the early-return guard is passed),
    // exercising the catch block deterministically on every platform.
    const reader = new MacOSProcReader('');
    expect(reader.readPpid(100)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// readEnviron — always null on macOS (no /proc)
// ---------------------------------------------------------------------------

describe('MacOSProcReader.readEnviron', () => {
  it('always returns null — attribution leans on the shim event seed', () => {
    const reader = new MacOSProcReader(makeHelper('echo 1'));
    expect(reader.readEnviron(1)).toBeNull();
    expect(reader.readEnviron(99999)).toBeNull();
  });
});

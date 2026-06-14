// script-jail — test/action/host-install.test.ts
//
// Unit tests for the host drop-in install (part 1: no-scripts install;
// part 2: run lifecycle scripts).  A fake spawn is injected so no real
// package manager runs.

import { describe, it, expect } from 'vitest';

import { hostInstallNoScripts, hostRunScripts, type HostSpawn, type HostInstallIo } from '../../src/action/host-install.js';

interface Recorder {
  io: HostInstallIo;
  out: string[];
  warns: string[];
  calls: Array<{ cmd: string; args: string[]; cwd: string }>;
}

function makeRecorder(): Recorder {
  const out: string[] = [];
  const warns: string[] = [];
  return {
    out,
    warns,
    calls: [],
    io: {
      stdout: { write: (s: string) => { out.push(s); } },
      warn: (m: string) => { warns.push(m); },
    },
  };
}

function okSpawn(rec: Recorder): HostSpawn {
  return (cmd, args, cwd) => {
    rec.calls.push({ cmd, args, cwd });
    return { status: 0 };
  };
}

describe('hostInstallNoScripts (part 1)', () => {
  it('runs the FETCH_CMD with disable flags + sanitized user args, in repoDir', () => {
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--omit=dev'], rec.io, okSpawn(rec));
    expect(rec.calls).toEqual([
      { cmd: 'npm', args: ['ci', '--ignore-scripts', '--omit=dev'], cwd: '/repo' },
    ]);
  });

  it.each([
    ['npm', ['ci', '--ignore-scripts']],
    ['pnpm', ['install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store']],
    ['yarn', ['install', '--immutable', '--mode=skip-build']],
  ] as const)('uses the correct no-scripts base command for %s', (pm, base) => {
    const rec = makeRecorder();
    hostInstallNoScripts(pm, '/repo', [], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toEqual(base);
  });

  it('pins pnpm --store-dir to the repo (parity with the guest); npm/yarn get no store flag', () => {
    // The audited sandbox always links pnpm against `<repo>/.pnpm-store`; the
    // host must use the SAME store or the dependency layout diverges.  The flag
    // is rooted at the ACTUAL repoDir and appended AFTER user args.
    const rec = makeRecorder();
    hostInstallNoScripts('pnpm', '/myrepo', ['--omit=dev'], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toEqual([
      'install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false',
      '--omit=dev', '--store-dir=/myrepo/.pnpm-store',
    ]);
    // npm / yarn never get a --store-dir flag.
    for (const pm of ['npm', 'yarn'] as const) {
      const r = makeRecorder();
      hostInstallNoScripts(pm, '/myrepo', [], r.io, okSpawn(r));
      expect(r.calls[0]!.args.some((a) => a.startsWith('--store-dir'))).toBe(false);
    }
  });

  it('drops script-re-enabling args and warns using the canonical flag name (not raw user text)', () => {
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--no-ignore-scripts', '-D'], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts', '-D']);
    // Warning must name the canonical flag (safe constant), NOT the raw user token.
    const warn = rec.warns.join('\n');
    expect(warn).toMatch(/--ignore-scripts/);
    // Raw user token must NOT appear in the warning.
    expect(warn).not.toContain('--no-ignore-scripts');
  });

  it('drops the SPLIT boolean re-enabler `--ignore-scripts false` WITH its value token', () => {
    // Critical-finding regression at the host boundary: nopt consumes the next
    // token as the value, so `npm ci --ignore-scripts --ignore-scripts false`
    // runs postinstall. Both the flag AND its value must be stripped.
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--ignore-scripts', 'false', '-D'], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts', '-D']);
  });

  it('throws on a non-zero exit (no usable tree → fail the job)', () => {
    const rec = makeRecorder();
    const failSpawn: HostSpawn = () => ({ status: 1 });
    expect(() => hostInstallNoScripts('npm', '/repo', [], rec.io, failSpawn)).toThrow(/exited with code 1/);
  });

  it('throws when the process is killed by a signal', () => {
    const rec = makeRecorder();
    const sigSpawn: HostSpawn = () => ({ status: null, signal: 'SIGKILL' });
    expect(() => hostInstallNoScripts('npm', '/repo', [], rec.io, sigSpawn)).toThrow(/killed by SIGKILL/);
  });

  it('throws on a spawn-level error', () => {
    const rec = makeRecorder();
    const errSpawn: HostSpawn = () => ({ status: null, error: new Error('ENOENT npm') });
    expect(() => hostInstallNoScripts('npm', '/repo', [], rec.io, errSpawn)).toThrow(/could not spawn/);
  });

  it('does not echo credential-shaped user args to stdout, but still passes them to spawn', () => {
    // Regression guard: a user arg such as --//registry.npmjs.org/:_authToken=SECRET123
    // must NOT appear in the action log (GitHub masking only strips registered secrets).
    const credArg = '--//registry.npmjs.org/:_authToken=SECRET123';
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', [credArg], rec.io, okSpawn(rec));

    const logged = rec.out.join('');

    // 1. Secret value must not appear in the log.
    expect(logged).not.toContain('SECRET123');
    expect(logged).not.toContain(credArg);

    // 2. The command and fixed base args ARE still shown (diagnostic is useful).
    expect(logged).toContain('npm ci --ignore-scripts');

    // 3. The count of suppressed user args is shown.
    expect(logged).toMatch(/\+1 user install arg, not shown/);

    // 4. Spawn still received the full argv including the credential arg.
    expect(rec.calls[0]!.args).toContain(credArg);
  });

  it('shows plural "args" in the suffix when multiple user args are supplied', () => {
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--omit=dev', '--omit=peer'], rec.io, okSpawn(rec));
    const logged = rec.out.join('');
    expect(logged).toMatch(/\+2 user install args, not shown/);
  });

  it('omits the user-arg suffix entirely when no user args survive sanitization', () => {
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', [], rec.io, okSpawn(rec));
    const logged = rec.out.join('');
    expect(logged).not.toContain('user install arg');
  });

  // ── Surface #6a: runOrThrow error messages must not leak argv credentials ──

  it('#6a: non-zero exit error does not contain credential-shaped user args', () => {
    const credArg = '--//registry.npmjs.org/:_authToken=SECRET123';
    const rec = makeRecorder();
    const failSpawn: HostSpawn = (cmd, args, cwd) => {
      rec.calls.push({ cmd, args, cwd });
      return { status: 1 };
    };
    let thrown: Error | undefined;
    try {
      hostInstallNoScripts('npm', '/repo', [credArg], rec.io, failSpawn);
    } catch (e) {
      thrown = e as Error;
    }
    expect(thrown).toBeDefined();
    // Error must mention command + exit code (useful for diagnosis).
    expect(thrown!.message).toMatch(/exited with code 1/);
    expect(thrown!.message).toMatch(/npm/);
    // Secret must NOT appear in the error message.
    expect(thrown!.message).not.toContain('SECRET123');
    expect(thrown!.message).not.toContain(credArg);
    // Spawn still received the full real argv including the credential.
    expect(rec.calls[0]!.args).toContain(credArg);
  });

  it('#6a: signal-killed error does not contain credential-shaped user args', () => {
    const credArg = '--registry=https://user:SECRET_PASS@private.registry.example/';
    const rec = makeRecorder();
    const sigSpawn: HostSpawn = (cmd, args, cwd) => {
      rec.calls.push({ cmd, args, cwd });
      return { status: null, signal: 'SIGKILL' };
    };
    let thrown: Error | undefined;
    try {
      hostInstallNoScripts('npm', '/repo', [credArg], rec.io, sigSpawn);
    } catch (e) {
      thrown = e as Error;
    }
    expect(thrown).toBeDefined();
    // Error must mention signal (useful for diagnosis).
    expect(thrown!.message).toMatch(/killed by SIGKILL/);
    // Secret must NOT appear in the error message.
    expect(thrown!.message).not.toContain('SECRET_PASS');
    expect(thrown!.message).not.toContain(credArg);
    // Spawn still received the full real argv including the credential.
    expect(rec.calls[0]!.args).toContain(credArg);
  });

  // ── Surface #6b: dropped-arg warnings must not echo raw user tokens ──

  it('#6b: dropped joined flag with embedded secret does not appear in warnings', () => {
    // A user could supply --ignore-scripts=SECRET456 as an attempt to re-enable
    // scripts.  It is forbidden and dropped — but its raw text must not be logged.
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--ignore-scripts=SECRET456', '-D'], rec.io, okSpawn(rec));
    const warn = rec.warns.join('\n');
    // Secret must NOT appear in the warning.
    expect(warn).not.toContain('SECRET456');
    expect(warn).not.toContain('--ignore-scripts=SECRET456');
    // The canonical flag name (safe constant) IS mentioned.
    expect(warn).toMatch(/--ignore-scripts/);
    // The arg count is emitted.
    expect(warn).toMatch(/1 install arg/);
  });

  it('#6b: dropped bare flag + value token — value does not appear in warnings', () => {
    // `--ignore-scripts false` causes the value token "false" to be consumed.
    // That value slot could theoretically carry user-controlled text; verify it
    // is not echoed.
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--ignore-scripts', 'false', '-D'], rec.io, okSpawn(rec));
    const warn = rec.warns.join('\n');
    // The raw value token must NOT appear in the warning.
    expect(warn).not.toContain('"false"');
    // Two raw tokens are dropped (flag + value); count reflects that.
    expect(warn).toMatch(/2 install args/);
    // The canonical flag name is still shown.
    expect(warn).toMatch(/--ignore-scripts/);
  });

  it('#6b: warns once (combined) for multiple dropped groups', () => {
    // Two separate forbidden flags: one joined, one bare+value.
    const rec = makeRecorder();
    hostInstallNoScripts(
      'yarn', '/repo',
      ['--no-ignore-scripts', '--mode', 'update-lockfile', '-P'],
      rec.io, okSpawn(rec),
    );
    // Should produce exactly one warning (combined, not one per token).
    expect(rec.warns).toHaveLength(1);
    const warn = rec.warns[0]!;
    // Both canonical keys should appear.
    expect(warn).toMatch(/--ignore-scripts/);
    expect(warn).toMatch(/--mode/);
    // Raw user value "update-lockfile" must NOT appear.
    expect(warn).not.toContain('update-lockfile');
    // Total raw token count: 3 (--no-ignore-scripts, --mode, update-lockfile).
    expect(warn).toMatch(/3 install args/);
  });
});

describe('hostRunScripts (part 2)', () => {
  it.each([
    ['npm', ['rebuild', '--foreground-scripts']],
    ['pnpm', ['rebuild', '--pending', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store']],
    ['yarn', ['install', '--immutable']],
  ] as const)('runs the INSTALL_CMD for %s in repoDir', (pm, expected) => {
    const rec = makeRecorder();
    hostRunScripts(pm, '/repo', rec.io, okSpawn(rec));
    expect(rec.calls).toEqual([{ cmd: pm, args: expected, cwd: '/repo' }]);
  });

  it('throws on a non-zero exit', () => {
    const rec = makeRecorder();
    const failSpawn: HostSpawn = () => ({ status: 7 });
    expect(() => hostRunScripts('pnpm', '/repo', rec.io, failSpawn)).toThrow(/exited with code 7/);
  });
});

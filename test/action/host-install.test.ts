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

  it('drops script-re-enabling args and warns about each', () => {
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--no-ignore-scripts', '-D'], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts', '-D']);
    expect(rec.warns.join('\n')).toMatch(/--no-ignore-scripts/);
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

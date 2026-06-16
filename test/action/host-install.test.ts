// script-jail — test/action/host-install.test.ts
//
// Unit tests for the host drop-in install (part 1: no-scripts install;
// part 2: run lifecycle scripts).  A fake spawn is injected so no real
// package manager runs.

import { describe, it, expect } from 'vitest';
import { isAbsolute, join, delimiter } from 'node:path';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  symlinkSync,
  realpathSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';

import {
  hostInstallNoScripts,
  hostRunScripts,
  resolveGitFromPath,
  type HostSpawn,
  type HostStreamSpawn,
  type HostInstallIo,
} from '../../src/action/host-install.js';

interface Recorder {
  io: HostInstallIo;
  out: string[];
  errs: string[];
  warns: string[];
  calls: Array<{ cmd: string; args: string[]; cwd: string }>;
}

function makeRecorder(): Recorder {
  const out: string[] = [];
  const errs: string[] = [];
  const warns: string[] = [];
  return {
    out,
    errs,
    warns,
    calls: [],
    io: {
      stdout: { write: (s: string) => { out.push(s); } },
      stderr: { write: (s: string) => { errs.push(s); } },
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

/**
 * Stream-spawn fake for part 2 (`hostRunScripts` is async, line-forwarding).
 * Records the call, optionally replays scripted output lines through `onLine`
 * (so a redaction test can assert what reaches the job log), then resolves with
 * the exit disposition.
 */
function okStreamSpawn(
  rec: Recorder,
  lines: ReadonlyArray<{ stream: 'stdout' | 'stderr'; line: string }> = [],
): HostStreamSpawn {
  return async (cmd, args, cwd, _env, onLine) => {
    rec.calls.push({ cmd, args, cwd });
    for (const { stream, line } of lines) onLine(stream, line);
    return { status: 0, signal: null };
  };
}

/** Stream-spawn fake that records the env it was handed (part-2 variant). */
function envCapturingStreamSpawn(captured: Array<NodeJS.ProcessEnv>): HostStreamSpawn {
  return async (_cmd, _args, _cwd, env) => {
    captured.push(env);
    return { status: 0, signal: null };
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
    ['pnpm', ['install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store', '--ignore-pnpmfile']],
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
      '--omit=dev', '--store-dir=/myrepo/.pnpm-store', '--ignore-pnpmfile',
    ]);
    // npm / yarn never get a --store-dir flag.
    for (const pm of ['npm', 'yarn'] as const) {
      const r = makeRecorder();
      hostInstallNoScripts(pm, '/myrepo', [], r.io, okSpawn(r));
      expect(r.calls[0]!.args.some((a) => a.startsWith('--store-dir'))).toBe(false);
    }
  });

  it('neutralizes yarn startup-exec env on the host child; npm/pnpm get none; auth env preserved', async () => {
    // SECURITY: an inherited YARN_* (YARN_YARN_PATH / YARN_PLUGINS / YARN_RC_FILENAME /
    // YARN_ENABLE_CONSTRAINTS_CHECKS) would re-introduce the startup code-exec the
    // preflight blocks in .yarnrc.yml.  The host yarn child overrides all four;
    // registry-auth env (YARN_NPM_*) is preserved.
    function envCapture(): {
      spawn: HostSpawn;
      streamSpawn: HostStreamSpawn;
      env: () => NodeJS.ProcessEnv;
    } {
      let seen: NodeJS.ProcessEnv = {};
      return {
        spawn: (_c, _a, _cwd, env) => { seen = env; return { status: 0 }; },
        streamSpawn: async (_c, _a, _cwd, env) => { seen = env; return { status: 0, signal: null }; },
        env: () => seen,
      };
    }

    const prevAuth = process.env['YARN_NPM_AUTH_TOKEN'];
    process.env['YARN_NPM_AUTH_TOKEN'] = 'tok-preserve-me';
    try {
      // yarn part 1: all four neutralizers set, auth preserved.
      const y1 = envCapture();
      hostInstallNoScripts('yarn', '/repo', [], makeRecorder().io, y1.spawn);
      expect(y1.env()['YARN_IGNORE_PATH']).toBe('1');
      expect(y1.env()['YARN_RC_FILENAME']).toBe('.yarnrc.yml');
      expect(y1.env()['YARN_PLUGINS']).toBe('');
      expect(y1.env()['YARN_ENABLE_CONSTRAINTS_CHECKS']).toBe('false');
      expect(y1.env()['YARN_NPM_AUTH_TOKEN']).toBe('tok-preserve-me'); // auth survives

      // yarn part 2 (run-scripts) is hardened identically.
      const y2 = envCapture();
      await hostRunScripts('yarn', '/repo', makeRecorder().io, [], y2.streamSpawn);
      expect(y2.env()['YARN_IGNORE_PATH']).toBe('1');
      expect(y2.env()['YARN_PLUGINS']).toBe('');

      // npm / pnpm never get the yarn neutralizers (these keys are our additions).
      for (const pm of ['npm', 'pnpm'] as const) {
        const c = envCapture();
        hostInstallNoScripts(pm, '/repo', [], makeRecorder().io, c.spawn);
        expect(c.env()['YARN_RC_FILENAME']).toBeUndefined();
        expect(c.env()['YARN_PLUGINS']).toBeUndefined();
        expect(c.env()['YARN_ENABLE_CONSTRAINTS_CHECKS']).toBeUndefined();
      }
    } finally {
      if (prevAuth === undefined) delete process.env['YARN_NPM_AUTH_TOKEN'];
      else process.env['YARN_NPM_AUTH_TOKEN'] = prevAuth;
    }
  });

  it('hardens the pnpm host part-1 with --ignore-pnpmfile; npm/yarn get no such flag', () => {
    // SECURITY: pnpm executes a repo `.pnpmfile.cjs` (and relocated pnpmfiles) at
    // require-time during a no-scripts install, BEFORE the trust gate.
    // `--ignore-pnpmfile` is the robust host-only catch-all (a no-op for clean
    // repos, checksum-fail-closed for a committed pnpmfile).  Only pnpm gets it.
    const rec = makeRecorder();
    hostInstallNoScripts('pnpm', '/repo', [], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toContain('--ignore-pnpmfile');
    // It is the LAST flag (appended after the store-dir pin).
    expect(rec.calls[0]!.args.at(-1)).toBe('--ignore-pnpmfile');
    for (const pm of ['npm', 'yarn'] as const) {
      const r = makeRecorder();
      hostInstallNoScripts(pm, '/repo', [], r.io, okSpawn(r));
      expect(r.calls[0]!.args).not.toContain('--ignore-pnpmfile');
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

  it('a credential-shaped user arg is DROPPED (not on the allowlist), never logged, never spawned', () => {
    // A user arg such as --//registry.npmjs.org/:_authToken=SECRET123 is not a
    // dependency-selection flag, so the fail-closed allowlist drops it.  It must
    // appear in NEITHER the action log NOR the spawn argv (strictly safer than the
    // old keep-then-redact-the-log path — the credential never leaves the process).
    const credArg = '--//registry.npmjs.org/:_authToken=SECRET123';
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', [credArg], rec.io, okSpawn(rec));

    const logged = rec.out.join('');

    // 1. Secret value must not appear in the log.
    expect(logged).not.toContain('SECRET123');
    expect(logged).not.toContain(credArg);

    // 2. The command and fixed base args ARE still shown (diagnostic is useful).
    expect(logged).toContain('npm ci --ignore-scripts');

    // 3. No KEPT user args, so no "+N user install arg" suffix is emitted.
    expect(logged).not.toContain('user install arg');

    // 4. The dropped arg was reported in a warning by its grammar-derived key
    //    (here the canonical key of the bare-name flag), never its raw text.
    const warn = rec.warns.join('\n');
    expect(warn).not.toContain('SECRET123');
    expect(warn).not.toContain(credArg);
    expect(warn).toMatch(/not on the allowlist/);

    // 5. Spawn received ONLY the fixed base args — the credential never reached it.
    expect(rec.calls[0]!.args).not.toContain(credArg);
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
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

  // ── Captured part-1 PM output: redacted before it reaches the job log ──────
  // The PM's OWN diagnostics (warnings/errors) are captured (stdio pipe) and
  // run through the redactor before being written, closing the leak where the
  // package manager echoes a user-supplied secret back to the log.

  function captureSpawn(rec: Recorder, result: { status: number | null; signal?: NodeJS.Signals | null; stdout?: string; stderr?: string }): HostSpawn {
    return (cmd, args, cwd) => {
      rec.calls.push({ cmd, args, cwd });
      return result;
    };
  }

  it('a credential-free --registry is forwarded to spawn (private-registry mirror)', () => {
    // Owner decision: `--registry` is allowlisted so private-registry consumers
    // can point the install at their mirror.  It does NOT bypass the frozen-lock
    // root gate (a stale lock still errors), so a credential-FREE registry URL is
    // a safe SOURCE-only flag and is forwarded to spawn.
    const rec = makeRecorder();
    hostInstallNoScripts('npm', '/repo', ['--registry=https://npm.acme.internal/'], rec.io, okSpawn(rec));
    expect(rec.calls[0]!.args).toContain('--registry=https://npm.acme.internal/');
    // No drop warning — a clean registry is on the allowlist.
    expect(rec.warns.join('\n')).not.toMatch(/ignoring .* install arg/);
  });

  it('a --registry URL with inline credentials is DROPPED — never spawned, never logged (F1)', () => {
    // Registry AUTH must live in .npmrc/env.  An inline `user:pass@` URL would
    // otherwise be staged VERBATIM into the Phase-B-readable pm-flags.json sidecar
    // that the audited (untrusted) lifecycle scripts can read, so it is dropped at
    // the value level — the credential never reaches spawn or any log/warning.
    const credUrl = 'https://user:SECRET_PASS@npm.acme.internal/';
    const rec = makeRecorder();
    const spawn = captureSpawn(rec, {
      status: 0,
      stderr: `npm warn invalid config registry="${credUrl}" set in command line options\n`,
    });
    hostInstallNoScripts('npm', '/repo', [`--registry=${credUrl}`], rec.io, spawn);
    // Dropped — spawn got only the fixed base args; the secret never reached it.
    expect(rec.calls[0]!.args).not.toContain(`--registry=${credUrl}`);
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
    // The drop warning names registry but NEVER echoes the secret value.
    const warn = rec.warns.join('\n');
    expect(warn).toMatch(/--registry/);
    expect(warn).not.toContain('SECRET_PASS');
    // No KEPT user args, so no "+N user install arg" suffix is emitted.
    expect(rec.out.join('')).not.toContain('user install arg');
  });

  it('a credential-shaped user-arg is DROPPED (not on the allowlist) so it never reaches spawn', () => {
    const credArg = '--//registry.npmjs.org/:_authToken=SECRET123';
    const rec = makeRecorder();
    const spawn = captureSpawn(rec, {
      status: 0,
      stdout: `using something for auth\n`,
    });
    hostInstallNoScripts('npm', '/repo', [credArg], rec.io, spawn);
    // Dropped — never passed to spawn.
    expect(rec.calls[0]!.args).not.toContain(credArg);
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
    // The warning never echoes the raw token (only its grammar-derived key).
    const warn = rec.warns.join('\n');
    expect(warn).not.toContain('SECRET123');
    expect(warn).not.toContain(credArg);
  });

  it('redacts a credential SHAPE the PM emits that was NOT a user arg', () => {
    // The PM prints its own resolved npm_ token + a credentialed URL — neither
    // is a user arg, so redactCredentialShapes (not the value derivation) catches it.
    const npmTok = 'npm_' + 'A'.repeat(36);
    const rec = makeRecorder();
    const spawn = captureSpawn(rec, {
      status: 0,
      stdout: `resolved token ${npmTok}\n`,
      stderr: 'fetch https://user:HUNTER2PASSWORD@reg.example/pkg\n',
    });
    hostInstallNoScripts('npm', '/repo', [], rec.io, spawn);
    const logged = rec.out.join('');
    const erred = rec.errs.join('');
    expect(logged).not.toContain(npmTok);
    expect(logged).toContain('<REDACTED:NPM-TOKEN>');
    expect(erred).not.toContain('HUNTER2PASSWORD');
    expect(erred).toContain('<REDACTED:URL-CREDENTIALS>');
  });

  it('writes captured output even on failure (status !== 0) BEFORE throwing', () => {
    const rec = makeRecorder();
    const spawn = captureSpawn(rec, {
      status: 1,
      stdout: 'npm error something broke\n',
      stderr: 'npm warn registry config issue\n',
    });
    // No user args here — exercise the failure-still-flushes-output path with the
    // fixed base install (credential args are dropped before spawn anyway).
    expect(() => hostInstallNoScripts('npm', '/repo', [], rec.io, spawn)).toThrow(/exited with code 1/);
    // Output reached the sinks despite the throw.
    expect(rec.out.join('')).toContain('npm error something broke');
    expect(rec.errs.join('')).toContain('npm warn registry config issue');
  });

  it('does NOT mangle an unrelated word that contains a short user-arg value (minLen guard)', () => {
    // `--omit=dev` → value "dev" is 3 chars (< minLen 4), so it must not blank
    // out "devDependencies".  The WHOLE token --omit=dev IS masked though.
    const rec = makeRecorder();
    const spawn = captureSpawn(rec, {
      status: 0,
      stdout: 'pruned devDependencies; ran with --omit=dev\n',
    });
    hostInstallNoScripts('npm', '/repo', ['--omit=dev'], rec.io, spawn);
    const logged = rec.out.join('');
    expect(logged).toContain('devDependencies'); // unrelated word intact
    expect(logged).not.toContain('--omit=dev'); // whole token masked
  });

  // ── Surface #6a: runOrThrow error messages must not leak argv credentials ──

  it('#6a: non-zero exit error does not contain credential-shaped user args (which are dropped)', () => {
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
    // Under the allowlist the credential arg is DROPPED — spawn never saw it.
    expect(rec.calls[0]!.args).not.toContain(credArg);
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
  });

  it('#6a: signal-killed error does not contain credential-shaped user args (which are dropped)', () => {
    // A non-allowlisted credential-bearing flag (here `--auth`, NOT `--registry`,
    // which is now allowlisted) is dropped before spawn, so its URL-embedded
    // secret can never surface in the signal-killed error message.
    const credArg = '--auth=https://user:SECRET_PASS@private.registry.example/';
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
    // Under the allowlist the credential arg is DROPPED — spawn never saw it.
    expect(rec.calls[0]!.args).not.toContain(credArg);
    expect(rec.calls[0]!.args).toEqual(['ci', '--ignore-scripts']);
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
    ['pnpm', ['rebuild', '--pending', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store', '--config.ignore-pnpmfile=true']],
    ['yarn', ['install', '--immutable']],
  ] as const)('runs the INSTALL_CMD for %s in repoDir', async (pm, expected) => {
    const rec = makeRecorder();
    await hostRunScripts(pm, '/repo', rec.io, [], okStreamSpawn(rec));
    expect(rec.calls).toEqual([{ cmd: pm, args: expected, cwd: '/repo' }]);
  });

  it('hardens the pnpm host part-2 (`pnpm rebuild`) with --config.ignore-pnpmfile=true; npm/yarn get no such flag', async () => {
    // SECURITY (symmetric with part-1's --ignore-pnpmfile): `pnpm rebuild` loads
    // + executes a (possibly ANCESTOR) pnpmfile's top-level code on the runner
    // AFTER the trust gate, unaudited.  Part-2 rejects the bare `--ignore-pnpmfile`
    // flag, so the config-namespaced form suppresses it.  Only pnpm gets it.
    const rec = makeRecorder();
    await hostRunScripts('pnpm', '/repo', rec.io, [], okStreamSpawn(rec));
    expect(rec.calls[0]!.args).toContain('--config.ignore-pnpmfile=true');
    // It is the LAST flag (appended after the store-dir pin).
    expect(rec.calls[0]!.args.at(-1)).toBe('--config.ignore-pnpmfile=true');
    // And NOT the bare flag, which `pnpm rebuild` rejects ("Unknown option").
    expect(rec.calls[0]!.args).not.toContain('--ignore-pnpmfile');
    for (const pm of ['npm', 'yarn'] as const) {
      const r = makeRecorder();
      await hostRunScripts(pm, '/repo', r.io, [], okStreamSpawn(r));
      expect(r.calls[0]!.args).not.toContain('--config.ignore-pnpmfile=true');
    }
  });

  it('throws on a non-zero exit', async () => {
    const rec = makeRecorder();
    const failSpawn: HostStreamSpawn = async () => ({ status: 7, signal: null });
    await expect(hostRunScripts('pnpm', '/repo', rec.io, [], failSpawn)).rejects.toThrow(/exited with code 7/);
  });

  it('throws (kill signal) and (spawn error), with credential-free args in the message', async () => {
    const rec = makeRecorder();
    const sigSpawn: HostStreamSpawn = async () => ({ status: null, signal: 'SIGKILL' });
    await expect(hostRunScripts('npm', '/repo', rec.io, [], sigSpawn)).rejects.toThrow(/killed by SIGKILL/);
    const errSpawn: HostStreamSpawn = async () => ({ status: null, signal: null, error: new Error('ENOENT npm') });
    await expect(hostRunScripts('npm', '/repo', rec.io, [], errSpawn)).rejects.toThrow(/could not spawn "npm": ENOENT npm/);
  });

  it('REDACTS streamed lifecycle output: protected-env values + credential shapes never reach the job log (F6)', async () => {
    // SECURITY (adversarial-review F6): the host part-2 runs the AUDIT-TRUSTED
    // lifecycle scripts on the runner with the job env (NPM_TOKEN etc.).  A
    // trusted script can echo a secret; every streamed line is redacted before it
    // reaches the GitHub Actions log — exact protected-env values via
    // maskExactValues, plus credential SHAPES via redactCredentialShapes.
    const rec = makeRecorder();
    const SECRET = 'superSecretTokenValue1234';
    const prev = process.env['MY_DEPLOY_TOKEN'];
    process.env['MY_DEPLOY_TOKEN'] = SECRET;
    try {
      await hostRunScripts('npm', '/repo', rec.io, ['MY_DEPLOY_TOKEN'], okStreamSpawn(rec, [
        { stream: 'stdout', line: `echoing the env value ${SECRET} here` },
        { stream: 'stderr', line: 'fetching //user:hunter2hunter2@npm.acme.internal/' },
        { stream: 'stdout', line: 'Authorization: Bearer ABCDEFGH01234567890123456789' },
      ]));
      const all = rec.out.join('') + rec.errs.join('');
      // (a) the exact protected-env value is masked.
      expect(all).not.toContain(SECRET);
      expect(all).toContain('<REDACTED:ENV>');
      // (b) URL userinfo + Bearer token shapes are masked too.
      expect(all).not.toContain('hunter2hunter2');
      expect(all).toContain('//<REDACTED:URL-CREDENTIALS>@npm.acme.internal/');
      expect(all).not.toContain('ABCDEFGH01234567890123456789');
      expect(all).toContain('Bearer <REDACTED>');
    } finally {
      if (prev === undefined) delete process.env['MY_DEPLOY_TOKEN'];
      else process.env['MY_DEPLOY_TOKEN'] = prev;
    }
  });
});

// ---------------------------------------------------------------------------
// SECURITY (FIX 1): pin npm's git binary against a repo `.npmrc git=` override
// ---------------------------------------------------------------------------
//
// A repo `.npmrc` with `git=./evil` + a NON-GitHub git dependency makes
// `npm ci --ignore-scripts` invoke `./evil` on the runner during the PRE-TRUST
// part-1 install (`--ignore-scripts` disables lifecycle SCRIPTS, NOT which git
// binary npm runs).  An env `npm_config_git` BEATS the project `.npmrc`, so
// BOTH host spawns must set it.  Tests capture the env via the spawn seam.

/** A spawn fake that records the env it was handed. */
function envCapturingSpawn(captured: Array<NodeJS.ProcessEnv>): HostSpawn {
  return (_cmd, _args, _cwd, env) => {
    captured.push(env);
    return { status: 0 };
  };
}

describe('git-binary pin (npm_config_git) — repo .npmrc git= override defense', () => {
  it('part 1 (no-scripts install) sets npm_config_git to an ABSOLUTE path', () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    expect(envs).toHaveLength(1);
    const git = envs[0]!['npm_config_git'];
    expect(git).toBeDefined();
    // Absolute so a repo-placed `./git` in cwd can't shadow a bare `git`.  When
    // PATH-resolution fails the documented fallback is the bare literal `git`,
    // which still OVERRIDES the repo `.npmrc git=` entry; accept either.
    expect(git === 'git' || isAbsolute(git!)).toBe(true);
    // The pin MUST be present regardless of any (hypothetical) repo override.
    expect(git).not.toBe('');
  });

  it('part 2 (lifecycle scripts) ALSO sets npm_config_git (defense-in-depth)', async () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    await hostRunScripts('npm', '/repo', rec.io, [], envCapturingStreamSpawn(envs));
    expect(envs).toHaveLength(1);
    const git = envs[0]!['npm_config_git'];
    expect(git).toBeDefined();
    expect(git === 'git' || isAbsolute(git!)).toBe(true);
  });

  it('SKIPS a checkout-controlled PATH dir when resolving git (pre-trust RCE defense)', () => {
    // P1: a workflow may prepend a checkout dir to PATH; a PR-committed bin/git
    // must NOT be picked as the "trusted" git (npm invokes npm_config_git for
    // git: deps even under --ignore-scripts, BEFORE the audit gate).  git resolved
    // from inside $GITHUB_WORKSPACE/$SCRIPT_JAIL_REPO_DIR/cwd is rejected.
    const checkout = mkdtempSync(join(tmpdir(), 'sj-checkout-'));
    const binDir = join(checkout, 'bin');
    mkdirSync(binDir);
    const fakeGit = join(binDir, process.platform === 'win32' ? 'git.exe' : 'git');
    writeFileSync(fakeGit, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      // Checkout git FIRST on PATH — the pre-fix scan would have returned it.
      process.env['PATH'] = `${binDir}${delimiter}${origPath ?? ''}`;
      const resolved = resolveGitFromPath();
      // Must never be the PR-controlled checkout binary…
      expect(resolved).not.toBe(fakeGit);
      // …and anything it DID resolve must live OUTSIDE the checkout tree.
      if (resolved !== undefined) {
        expect(resolved.startsWith(checkout)).toBe(false);
        expect(isAbsolute(resolved)).toBe(true);
      }
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
    }
  });

  it('REJECTS a case-variant spelling of the checkout dir on a case-insensitive FS', () => {
    // P1 (case-insensitive bypass): on macOS APFS/HFS+ (and Windows NTFS),
    // `/work/Repo` and `/work/repo` are the SAME dir.  A lexical containment
    // test misses the case-variant; the realpath + case-fold canonicalization
    // must still reject it.  No-op assertion on a case-sensitive FS (Linux),
    // where the variant is a genuinely different, non-existent dir.
    const checkout = mkdtempSync(join(tmpdir(), 'sj-Checkout-'));
    const binDir = join(checkout, 'Bin');
    mkdirSync(binDir);
    const fakeGit = join(binDir, process.platform === 'win32' ? 'git.exe' : 'git');
    writeFileSync(fakeGit, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    const variantBin = binDir.toLowerCase();
    const caseInsensitive =
      variantBin !== binDir && existsSync(join(variantBin, process.platform === 'win32' ? 'git.exe' : 'git'));
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      if (!caseInsensitive) return; // FS folds no case — bypass class N/A here
      process.env['GITHUB_WORKSPACE'] = checkout;
      // Case-variant of the checkout bin FIRST — the lexical-only check let it pass.
      process.env['PATH'] = `${variantBin}${delimiter}${origPath ?? ''}`;
      const resolved = resolveGitFromPath();
      if (resolved !== undefined) {
        expect(realpathSync(resolved)).not.toBe(realpathSync(fakeGit));
        expect(realpathSync(resolved).toLowerCase().startsWith(realpathSync(checkout).toLowerCase())).toBe(
          false,
        );
      }
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
    }
  });

  it('REJECTS a PATH dir that SYMLINKS into the checkout (realpath defense)', () => {
    // P1 (symlink bypass): a runner-looking PATH entry that is actually a symlink
    // INTO the checkout has a lexical path outside it; realpath must resolve the
    // link and reject the real (checkout) target.
    if (process.platform === 'win32') return; // symlink perms differ on Windows runners
    const checkout = mkdtempSync(join(tmpdir(), 'sj-co-'));
    const cbin = join(checkout, 'bin');
    mkdirSync(cbin);
    const cgit = join(cbin, 'git');
    writeFileSync(cgit, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    const runner = mkdtempSync(join(tmpdir(), 'sj-rn-'));
    const symbin = join(runner, 'symbin');
    symlinkSync(cbin, symbin); // runner-located path → checkout/bin
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      process.env['PATH'] = `${symbin}${delimiter}${origPath ?? ''}`;
      const resolved = resolveGitFromPath();
      expect(resolved).not.toBe(join(symbin, 'git'));
      if (resolved !== undefined) {
        expect(realpathSync(resolved)).not.toBe(realpathSync(cgit));
      }
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
      rmSync(runner, { recursive: true, force: true });
    }
  });

  it('REJECTS a runner-dir git binary that SYMLINKS to a checkout git', () => {
    // P1 (symlinked binary bypass): the PATH dir is genuinely outside the
    // checkout, but the `git` inside it is a symlink whose real target lives in
    // the checkout — the candidate-level realpath check must catch it.
    if (process.platform === 'win32') return;
    const checkout = mkdtempSync(join(tmpdir(), 'sj-co-'));
    const cbin = join(checkout, 'bin');
    mkdirSync(cbin);
    const cgit = join(cbin, 'git');
    writeFileSync(cgit, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    const runner = mkdtempSync(join(tmpdir(), 'sj-rn-'));
    const rbin = join(runner, 'bin');
    mkdirSync(rbin);
    symlinkSync(cgit, join(rbin, 'git')); // runner dir, but git → checkout git
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      process.env['PATH'] = `${rbin}${delimiter}${origPath ?? ''}`;
      const resolved = resolveGitFromPath();
      if (resolved !== undefined) {
        expect(realpathSync(resolved)).not.toBe(realpathSync(cgit));
      }
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
      rmSync(runner, { recursive: true, force: true });
    }
  });

  it('preserves the inherited env (PATH/HOME etc.) by merging over process.env', () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    // PATH (set in every test env) must survive the merge.
    expect(envs[0]!['PATH']).toBe(process.env['PATH']);
  });
});

describe('host re-run env hygiene — drop sandbox-vs-host tells (install:true defense-in-depth)', () => {
  /** Run `body` with extra env vars set, restoring the prior values after. */
  async function withEnv(extra: Record<string, string>, body: () => void | Promise<void>): Promise<void> {
    const prior: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(extra)) {
      prior[k] = process.env[k];
      process.env[k] = v;
    }
    try {
      await body();
    } finally {
      for (const k of Object.keys(extra)) {
        if (prior[k] === undefined) delete process.env[k];
        else process.env[k] = prior[k];
      }
    }
  }

  it.each(['npm', 'pnpm', 'yarn'] as const)(
    'strips HOSTNAME / PWD / every SCRIPT_JAIL_* from the part-2 lifecycle env (%s)',
    async (pm) => {
      await withEnv(
        {
          HOSTNAME: 'fv-az-runner-123',
          PWD: '/home/runner/work/repo/repo',
          TERM: 'xterm',
          SCRIPT_JAIL_REPO_DIR: '/home/runner/work/repo/repo',
          SCRIPT_JAIL_CACHE_DIR: '/tmp/sj-cache',
          SCRIPT_JAIL_ACTION_ROOT: '/opt/action',
        },
        async () => {
          const rec = makeRecorder();
          const envs: Array<NodeJS.ProcessEnv> = [];
          await hostRunScripts(pm, '/repo', rec.io, [], envCapturingStreamSpawn(envs));
          const env = envs[0]!;
          // Sandbox tells that an env-sensitive payload could branch on are gone.
          expect(env['HOSTNAME']).toBeUndefined();
          expect(env['PWD']).toBeUndefined();
          expect(env['TERM']).toBeUndefined();
          for (const k of Object.keys(env)) {
            expect(k.startsWith('SCRIPT_JAIL_')).toBe(false);
          }
          // The security pins / inherited essentials still survive the strip.
          expect(env['npm_config_git']).toBeDefined();
          expect(env['PATH']).toBe(process.env['PATH']);
        },
      );
    },
  );

  it('also strips the tells from the part-1 no-scripts env', async () => {
    await withEnv({ HOSTNAME: 'fv-az-1', SCRIPT_JAIL_REPO_DIR: '/x' }, () => {
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
      const env = envs[0]!;
      expect(env['HOSTNAME']).toBeUndefined();
      expect(env['SCRIPT_JAIL_REPO_DIR']).toBeUndefined();
      expect(env['npm_config_git']).toBeDefined();
    });
  });

  it('keeps yarn neutralizers after the strip (hygiene runs before the pins)', async () => {
    await withEnv({ SCRIPT_JAIL_REPO_DIR: '/x' }, async () => {
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      await hostRunScripts('yarn', '/repo', rec.io, [], envCapturingStreamSpawn(envs));
      const env = envs[0]!;
      expect(env['YARN_IGNORE_PATH']).toBe('1');
      expect(env['YARN_PLUGINS']).toBe('');
      expect(env['YARN_ENABLE_CONSTRAINTS_CHECKS']).toBe('false');
    });
  });
});

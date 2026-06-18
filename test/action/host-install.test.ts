// script-jail — test/action/host-install.test.ts
//
// Unit tests for the host drop-in install (part 1: no-scripts install;
// part 2: run lifecycle scripts).  A fake spawn is injected so no real
// package manager runs.

import { describe, it, expect, afterEach } from 'vitest';
import { isAbsolute, join, delimiter } from 'node:path';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  chmodSync,
  rmSync,
  symlinkSync,
  realpathSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';

import {
  hostInstallNoScripts,
  hostRunScripts,
  isPathUnderCheckout,
  resolveGitFromPath,
  stripDangerousEnv,
  sanitizePathValue,
  SAFE_SYSTEM_PATH,
  streamSpawn,
  makeLineSink,
  HOST_PART2_POISON_MARKER,
  HOST_PART2_TRUNCATED_MARKER,
  HOST_PART2_DRAIN_GRACE_MS,
  resolveHostManagerLaunch,
  type HostSpawn,
  type HostStreamSpawn,
  type HostInstallIo,
  type HostManagerLaunch,
  type HostManagerLaunchResolver,
} from '../../src/action/host-install.js';
import { sanitizeInstallArgs } from '../../src/shared/pm-commands.js';

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

/**
 * Part-2 launch resolver that always returns `undefined` (= "standalone PM, bare-
 * launch is safe").  Injected into existing part-2 tests so they remain hermetic
 * regardless of the dev/CI machine's corepack cache: the COREPACK_ROOT-oracle
 * direct-launch is exercised by its OWN dedicated tests below.
 */
const bareLaunchResolver: HostManagerLaunchResolver = () => undefined;

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
    // SECURITY (codex idx-5): an INHERITED YARN_ENABLE_SCRIPTS=true beats a PR's
    // `.yarnrc.yml` `enableScripts: false` (env > rc, VERIFIED yarn 4.5.0), so the
    // clean-VM audit (no env) would record no scripts while the host runs them.
    // The host yarn child must DELETE it so the rc governs identically to the audit.
    const prevScripts = process.env['YARN_ENABLE_SCRIPTS'];
    process.env['YARN_ENABLE_SCRIPTS'] = 'true';
    try {
      // yarn part 1: all four neutralizers set, auth preserved, script-enable dropped.
      const y1 = envCapture();
      hostInstallNoScripts('yarn', '/repo', [], makeRecorder().io, y1.spawn);
      expect(y1.env()['YARN_IGNORE_PATH']).toBe('1');
      expect(y1.env()['YARN_RC_FILENAME']).toBe('.yarnrc.yml');
      expect(y1.env()['YARN_PLUGINS']).toBe('');
      expect(y1.env()['YARN_ENABLE_CONSTRAINTS_CHECKS']).toBe('false');
      expect(y1.env()['YARN_ENABLE_SCRIPTS']).toBeUndefined(); // inherited override dropped
      expect(y1.env()['YARN_NPM_AUTH_TOKEN']).toBe('tok-preserve-me'); // auth survives

      // yarn part 2 (run-scripts) is hardened identically.
      const y2 = envCapture();
      await hostRunScripts('yarn', '/repo', [], makeRecorder().io, [], y2.streamSpawn, bareLaunchResolver);
      expect(y2.env()['YARN_IGNORE_PATH']).toBe('1');
      expect(y2.env()['YARN_PLUGINS']).toBe('');
      expect(y2.env()['YARN_ENABLE_SCRIPTS']).toBeUndefined();

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
      if (prevScripts === undefined) delete process.env['YARN_ENABLE_SCRIPTS'];
      else process.env['YARN_ENABLE_SCRIPTS'] = prevScripts;
    }
  });

  it('mirrors the guest cache/store redirect into the host lifecycle child (value-blind-lock close)', async () => {
    // buildChildEnv (guest) injects npm_config_cache=<work_dir>/.npm-cache (npm) /
    // YARN_CACHE_FOLDER+YARN_GLOBAL_FOLDER=<work_dir>/.yarn-* (yarn) into EVERY
    // Phase-B lifecycle child.  On install:true FC/docker the guest work_dir is
    // pinned to repoDir, so the host install must set the SAME repoDir-relative
    // values — else a dep branching on the value (env-spy is value-blind) runs a
    // different branch on the trusted host than was audited.  Both host phases.
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
    const REPO = '/work/checkout';

    // npm: both phases set npm_config_cache=<repoDir>/.npm-cache (matches the guest
    // cacheRedirectEnv npm branch); yarn/pnpm keys NOT present for npm.
    const n1 = envCapture();
    hostInstallNoScripts('npm', REPO, [], makeRecorder().io, n1.spawn);
    expect(n1.env()['npm_config_cache']).toBe(`${REPO}/.npm-cache`);
    // npm_config_git is FETCH-phase only (part-1 clones git deps); present here,
    // ABSENT in part-2 below (== guest Phase B) — round-15 value-blind close.
    expect(n1.env()['npm_config_git']).toBeDefined();
    const n2 = envCapture();
    await hostRunScripts('npm', REPO, [], makeRecorder().io, [], n2.streamSpawn, bareLaunchResolver);
    expect(n2.env()['npm_config_cache']).toBe(`${REPO}/.npm-cache`);
    expect(n2.env()['npm_config_git']).toBeUndefined(); // fetch-only: no part-2 oracle
    expect(n2.env()['YARN_CACHE_FOLDER']).toBeUndefined();

    // yarn: both phases set the two folder redirects (matches the guest yarn branch).
    const yA = envCapture();
    hostInstallNoScripts('yarn', REPO, [], makeRecorder().io, yA.spawn);
    expect(yA.env()['YARN_CACHE_FOLDER']).toBe(`${REPO}/.yarn-cache`);
    expect(yA.env()['YARN_GLOBAL_FOLDER']).toBe(`${REPO}/.yarn-global`);
    const yB = envCapture();
    await hostRunScripts('yarn', REPO, [], makeRecorder().io, [], yB.streamSpawn, bareLaunchResolver);
    expect(yB.env()['YARN_CACHE_FOLDER']).toBe(`${REPO}/.yarn-cache`);
    expect(yB.env()['YARN_GLOBAL_FOLDER']).toBe(`${REPO}/.yarn-global`);
    expect(yB.env()['npm_config_cache']).toBeUndefined();

    // pnpm: NO env cache key here — store_dir parity is carried by the
    // --store-dir <repoDir>/.pnpm-store ARGUMENT (pnpmStoreDirArg), not env.
    const pB = envCapture();
    await hostRunScripts('pnpm', REPO, [], makeRecorder().io, [], pB.streamSpawn, bareLaunchResolver);
    expect(pB.env()['npm_config_cache']).toBeUndefined();
    expect(pB.env()['YARN_CACHE_FOLDER']).toBeUndefined();
  });

  it('drops the WHOLE inherited YARN_* config surface except auth (codex allowlist — YARN_INJECT_ENVIRONMENT_FILES etc.)', () => {
    // SECURITY: Yarn maps env->config and the surface is open-ended — enumerating
    // dangerous names is whack-a-mole (YARN_INJECT_ENVIRONMENT_FILES injects a .env
    // incl. NODE_OPTIONS into lifecycle subprocesses; *Folder/*Path redirects; ...).
    // hostInstallEnv keeps ONLY the scalar auth/registry YARN_* and drops every other
    // inherited YARN_*.  The clean-VM audit inherits no runner env, so this is parity-safe.
    let seen: NodeJS.ProcessEnv = {};
    const spawn: HostSpawn = (_c, _a, _cwd, env) => { seen = env; return { status: 0 }; };
    const dangerous = {
      YARN_INJECT_ENVIRONMENT_FILES: '.env.evil',
      YARN_GLOBAL_FOLDER: '/checkout/.yarn',
      YARN_CONSTRAINTS_PATH: '/checkout/c.cjs',
      YARN_YARN_PATH: '/checkout/evil.cjs', // yarnPath re-exec selector
      YARN_NETWORK_SETTINGS: '{}', // per-host config MAP
      YARN_ENABLE_STRICT_SSL: 'false', // weakens TLS
      // CASE-INSENSITIVE: yarn lower-cases the env key before matching `yarn_`
      // (VERIFIED 4.5.0), so lowercase/mixed-case dangerous forms must ALSO be dropped.
      yarn_enable_scripts: 'true',
      yarn_inject_environment_files: '.env.evil',
      Yarn_Global_Folder: '/checkout/.yarn',
    };
    const auth = {
      YARN_NPM_AUTH_TOKEN: 'tok',
      YARN_NPM_AUTH_IDENT: 'ident',
      YARN_NPM_REGISTRY_SERVER: 'https://reg.example/',
      YARN_NPM_ALWAYS_AUTH: 'true',
      yarn_npm_auth_token: 'lower-tok', // lowercase auth: yarn honours it, so it must survive
    };
    const prior: Record<string, string | undefined> = {};
    for (const k of [...Object.keys(dangerous), ...Object.keys(auth)]) prior[k] = process.env[k];
    try {
      Object.assign(process.env, dangerous, auth);
      hostInstallNoScripts('yarn', '/repo', [], makeRecorder().io, spawn);
      // Every non-auth inherited YARN_* dropped (any case).  EXCEPTION: the
      // canonical YARN_GLOBAL_FOLDER is RE-SET to a trusted repoDir-relative
      // cache-parity pin (value-blind-lock close, lifecycleCacheParityEnv), so it
      // is no longer undefined — the PR's /checkout value is still NOT honored
      // (trusted value wins), and the mixed-case inherited form stays dropped.
      for (const k of Object.keys(dangerous)) {
        if (k === 'YARN_GLOBAL_FOLDER') continue;
        expect(seen[k]).toBeUndefined();
      }
      expect(seen['YARN_GLOBAL_FOLDER']).toBe('/repo/.yarn-global'); // trusted pin, NOT PR /checkout/.yarn
      expect(seen['YARN_CACHE_FOLDER']).toBe('/repo/.yarn-cache'); // trusted cache-parity pin
      expect(seen['YARN_NPM_AUTH_TOKEN']).toBe('tok'); // auth/registry preserved
      expect(seen['YARN_NPM_AUTH_IDENT']).toBe('ident');
      expect(seen['YARN_NPM_REGISTRY_SERVER']).toBe('https://reg.example/');
      expect(seen['YARN_NPM_ALWAYS_AUTH']).toBe('true');
      expect(seen['yarn_npm_auth_token']).toBe('lower-tok'); // lowercase auth preserved (allowlist is case-insensitive)
      expect(seen['YARN_IGNORE_PATH']).toBe('1'); // pins re-applied on top of the sweep
      expect(seen['YARN_PLUGINS']).toBe('');
    } finally {
      for (const [k, v] of Object.entries(prior)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('keeps yarn pure-routing proxy/tuning + TLS-material env, still drops weakening + config-map keys (round-13/14)', () => {
    // VERIFIED yarn 4.9.1: YARN_HTTP_PROXY->httpProxy / YARN_HTTPS_PROXY->httpsProxy
    // (yarn IGNORES unprefixed HTTP_PROXY), YARN_HTTP_TIMEOUT/RETRY + YARN_NETWORK_CONCURRENCY
    // are ints, and YARN_HTTPS_{CA,CERT,KEY}_FILE_PATH are PEM file paths read as TLS
    // MATERIAL only (readFile -> got, never exec) — all KEPT (the TLS file paths match
    // npm's already-kept cafile/certfile/keyfile).  Still DROPPED: YARN_NETWORK_SETTINGS
    // (config MAP), YARN_ENABLE_STRICT_SSL / YARN_UNSAFE_HTTP_WHITELIST (weaken TLS), and
    // exec/folder keys.
    let seen: NodeJS.ProcessEnv = {};
    const spawn: HostSpawn = (_c, _a, _cwd, env) => { seen = env; return { status: 0 }; };
    const keep = {
      YARN_HTTP_PROXY: 'http://proxy.local:8080/',
      YARN_HTTPS_PROXY: 'http://proxy.local:8443/',
      YARN_HTTP_TIMEOUT: '120000',
      YARN_HTTP_RETRY: '5',
      YARN_NETWORK_CONCURRENCY: '8',
      YARN_HTTPS_CA_FILE_PATH: '/etc/ssl/ca.pem', // PEM CA, read as TLS material
      YARN_HTTPS_CERT_FILE_PATH: '/etc/ssl/client.pem', // PEM client cert
      YARN_HTTPS_KEY_FILE_PATH: '/etc/ssl/client.key', // PEM client key
    };
    const drop = {
      YARN_NETWORK_SETTINGS: '{"//host":{"enableNetwork":true}}', // config MAP
      YARN_ENABLE_STRICT_SSL: 'false', // weakens TLS
      YARN_UNSAFE_HTTP_WHITELIST: '*.evil.example', // weakens cleartext guard
      YARN_YARN_PATH: '/checkout/evil.cjs', // yarnPath re-exec selector
      YARN_GLOBAL_FOLDER: '/checkout/.yarn', // folder redirect
    };
    const prior: Record<string, string | undefined> = {};
    for (const k of [...Object.keys(keep), ...Object.keys(drop)]) prior[k] = process.env[k];
    try {
      Object.assign(process.env, keep, drop);
      hostInstallNoScripts('yarn', '/repo', [], makeRecorder().io, spawn);
      for (const [k, v] of Object.entries(keep)) expect(seen[k]).toBe(v); // routing keys survive
      // dangerous/weakening dropped — EXCEPT YARN_GLOBAL_FOLDER, which is re-set to
      // a trusted repoDir-relative cache-parity pin (the PR's /checkout/.yarn is
      // still rejected; the trusted value wins).  See lifecycleCacheParityEnv.
      for (const k of Object.keys(drop)) {
        if (k === 'YARN_GLOBAL_FOLDER') continue;
        expect(seen[k]).toBeUndefined();
      }
      expect(seen['YARN_GLOBAL_FOLDER']).toBe('/repo/.yarn-global'); // trusted pin, NOT PR /checkout/.yarn
    } finally {
      for (const [k, v] of Object.entries(prior)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('drops inherited COREPACK_* version-steering, re-pins only the download prompt (codex corepack skew)', () => {
    // SECURITY: COREPACK_ENABLE_PROJECT_SPEC=0 makes corepack IGNORE the repo's
    // packageManager field and run a DIFFERENT pm VERSION than the clean-VM audit
    // (VERIFIED corepack 0.35.0). The audit inherits no COREPACK_*, so the host must
    // drop the whole family (any case) and re-pin only COREPACK_ENABLE_DOWNLOAD_PROMPT.
    const inherited = {
      COREPACK_ENABLE_PROJECT_SPEC: '0',
      COREPACK_ENABLE_STRICT: '0',
      COREPACK_DEFAULT_TO_LATEST: '1',
      corepack_enable_project_spec: '0', // lowercase form also dropped
    };
    const prior: Record<string, string | undefined> = {};
    for (const k of Object.keys(inherited)) prior[k] = process.env[k];
    try {
      Object.assign(process.env, inherited);
      // Sweep is unconditional (corepack shims pnpm + yarn); npm ignores COREPACK_* anyway.
      for (const pm of ['npm', 'pnpm', 'yarn'] as const) {
        let seen: NodeJS.ProcessEnv = {};
        const spawn: HostSpawn = (_c, _a, _cwd, env) => { seen = env; return { status: 0 }; };
        hostInstallNoScripts(pm, '/repo', [], makeRecorder().io, spawn);
        for (const k of Object.keys(inherited)) expect(seen[k]).toBeUndefined();
        expect(seen['COREPACK_ENABLE_DOWNLOAD_PROMPT']).toBe('0'); // re-pinned after the sweep
      }
    } finally {
      for (const [k, v] of Object.entries(prior)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('round-17f [critical]: host pins COREPACK_ENV_FILE=0 (part-1 AND part-2) so a repo .corepack.env cannot reintroduce COREPACK_HOME', async () => {
    // corepack loads a PROJECT `.corepack.env` (cwd=repoDir) at startup unless
    // COREPACK_ENV_FILE=0; its loader spreads `...process.env` LAST so process.env WINS
    // over the file (VERIFIED corepack 0.35.0 corepack.cjs:13556).  stripDangerousEnv
    // drops the inherited COREPACK_HOME (corepack_ family) → UNSET → a repo `.corepack.env`
    // with COREPACK_HOME=<checkout>/evil would REPOPULATE it inside the bare corepack shim,
    // and host part-1 (`hostInstallNoScripts`, cwd=repoDir, BEFORE the trust gate) would
    // exec a PR-planted cache entry.  Pinning =0 makes the host ignore the file.  An
    // INHERITED COREPACK_ENV_FILE (attacker-chosen filename) is ALSO overridden to '0' (it
    // is in the corepack_ family → stripped → re-pinned), and part-2 stays in lockstep.
    const prevEnvFile = process.env['COREPACK_ENV_FILE'];
    try {
      process.env['COREPACK_ENV_FILE'] = '.corepack.env.evil'; // attacker-chosen filename, must be overridden
      for (const pm of ['npm', 'pnpm', 'yarn'] as const) {
        // part-1 (fetch): the [critical] surface — bare corepack shim at cwd=repoDir.
        let fetchEnv: NodeJS.ProcessEnv = {};
        const spawn: HostSpawn = (_c, _a, _cwd, env) => {
          fetchEnv = env;
          return { status: 0 };
        };
        hostInstallNoScripts(pm, '/repo', [], makeRecorder().io, spawn);
        expect(fetchEnv['COREPACK_ENV_FILE']).toBe('0');
        // part-2 (scripts): host==audit lockstep.
        const spawnEnvs: Array<NodeJS.ProcessEnv> = [];
        await hostRunScripts(pm, '/repo', [], makeRecorder().io, [], envCapturingStreamSpawn(spawnEnvs), bareLaunchResolver);
        expect(spawnEnvs[0]?.['COREPACK_ENV_FILE']).toBe('0');
      }
    } finally {
      if (prevEnvFile === undefined) delete process.env['COREPACK_ENV_FILE'];
      else process.env['COREPACK_ENV_FILE'] = prevEnvFile;
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
    ['npm', ['rebuild', '--foreground-scripts', '--no-node-options']],
    ['pnpm', ['rebuild', '--pending', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store', '--config.ignore-pnpmfile=true', '--config.script-shell=/bin/sh']],
    ['yarn', ['install', '--immutable']],
  ] as const)('runs the INSTALL_CMD for %s in repoDir', async (pm, expected) => {
    const rec = makeRecorder();
    await hostRunScripts(pm, '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
    expect(rec.calls).toEqual([{ cmd: pm, args: expected, cwd: '/repo' }]);
  });

  it('hardens the pnpm host part-2 (`pnpm rebuild`) with --config.ignore-pnpmfile=true; npm/yarn get no such flag', async () => {
    // SECURITY (symmetric with part-1's --ignore-pnpmfile): `pnpm rebuild` loads
    // + executes a (possibly ANCESTOR) pnpmfile's top-level code on the runner
    // AFTER the trust gate, unaudited.  Part-2 rejects the bare `--ignore-pnpmfile`
    // flag, so the config-namespaced form suppresses it.  Only pnpm gets it.
    const rec = makeRecorder();
    await hostRunScripts('pnpm', '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
    expect(rec.calls[0]!.args).toContain('--config.ignore-pnpmfile=true');
    // Appended after the store-dir pin, alongside the #26 script-shell pin (last).
    expect(rec.calls[0]!.args.at(-1)).toBe('--config.script-shell=/bin/sh');
    // And NOT the bare flag, which `pnpm rebuild` rejects ("Unknown option").
    expect(rec.calls[0]!.args).not.toContain('--ignore-pnpmfile');
    for (const pm of ['npm', 'yarn'] as const) {
      const r = makeRecorder();
      await hostRunScripts(pm, '/repo', [], r.io, [], okStreamSpawn(r), bareLaunchResolver);
      expect(r.calls[0]!.args).not.toContain('--config.ignore-pnpmfile=true');
    }
  });

  describe('#19 npm-only user-arg splice (fidelity parity)', () => {
    it('npm part-2 splices the sanitized dep-selection args (after base, before store-dir)', async () => {
      const rec = makeRecorder();
      await hostRunScripts('npm', '/repo', ['--omit=dev', '-D'], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      // npm has no store-dir; the base carries --no-node-options (#43, shared
      // INSTALL_CMD) before the spliced user args.
      expect(rec.calls[0]!.args).toEqual(['rebuild', '--foreground-scripts', '--no-node-options', '--omit=dev', '-D']);
      // Lockstep invariant: the spliced suffix is exactly sanitizeInstallArgs(args).kept
      // (the trailing tokens — store-dir/host-hardening are empty for npm).
      const { kept } = sanitizeInstallArgs(['--omit=dev', '-D']);
      expect(rec.calls[0]!.args.slice(-kept.length)).toEqual(kept);
    });

    it('npm part-2 DROPS a script-re-enabling / unsafe arg (same allowlist as part-1)', async () => {
      const rec = makeRecorder();
      // `--ignore-scripts false` and a positional are NOT on the allowlist → dropped.
      await hostRunScripts('npm', '/repo', ['--ignore-scripts', 'false', '--omit=dev'], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      expect(rec.calls[0]!.args).toEqual(['rebuild', '--foreground-scripts', '--no-node-options', '--omit=dev']);
      expect(rec.calls[0]!.args).not.toContain('--ignore-scripts');
    });

    it('pnpm/yarn part-2 splice NO user args (rebuild rejects them; dep-group state lives in the tree)', async () => {
      for (const [pm, expected] of [
        ['pnpm', ['rebuild', '--pending', '--config.side-effects-cache=false', '--store-dir=/repo/.pnpm-store', '--config.ignore-pnpmfile=true', '--config.script-shell=/bin/sh']],
        ['yarn', ['install', '--immutable']],
      ] as const) {
        const rec = makeRecorder();
        await hostRunScripts(pm, '/repo', ['--omit=dev', '--prod'], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
        expect(rec.calls[0]!.args).toEqual(expected);
        expect(rec.calls[0]!.args).not.toContain('--omit=dev');
        expect(rec.calls[0]!.args).not.toContain('--prod');
      }
    });

    it('no-args npm part-2 splices no user args (base + the --no-node-options hardening only)', async () => {
      const rec = makeRecorder();
      await hostRunScripts('npm', '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      expect(rec.calls[0]!.args).toEqual(['rebuild', '--foreground-scripts', '--no-node-options']);
    });

    it('does NOT echo raw user tokens in the banner — count-only suffix', async () => {
      const rec = makeRecorder();
      await hostRunScripts('npm', '/repo', ['--omit=dev'], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      const banner = rec.out.join('');
      // The args still go to spawn (asserted above); the BANNER must not echo them.
      expect(banner).not.toContain('--omit=dev');
      expect(banner).toMatch(/\+1 user install arg, not shown/);
    });
  });

  it('throws on a non-zero exit', async () => {
    const rec = makeRecorder();
    const failSpawn: HostStreamSpawn = async () => ({ status: 7, signal: null });
    await expect(hostRunScripts('pnpm', '/repo', [], rec.io, [], failSpawn, bareLaunchResolver)).rejects.toThrow(/exited with code 7/);
  });

  it('throws (kill signal) and (spawn error), with credential-free args in the message', async () => {
    const rec = makeRecorder();
    const sigSpawn: HostStreamSpawn = async () => ({ status: null, signal: 'SIGKILL' });
    await expect(hostRunScripts('npm', '/repo', [], rec.io, [], sigSpawn, bareLaunchResolver)).rejects.toThrow(/killed by SIGKILL/);
    const errSpawn: HostStreamSpawn = async () => ({ status: null, signal: null, error: new Error('ENOENT npm') });
    await expect(hostRunScripts('npm', '/repo', [], rec.io, [], errSpawn, bareLaunchResolver)).rejects.toThrow(/could not spawn "npm": ENOENT npm/);
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
      await hostRunScripts('npm', '/repo', [], rec.io, ['MY_DEPLOY_TOKEN'], okStreamSpawn(rec, [
        { stream: 'stdout', line: `echoing the env value ${SECRET} here` },
        { stream: 'stderr', line: 'fetching //user:hunter2hunter2@npm.acme.internal/' },
        { stream: 'stdout', line: 'Authorization: Bearer ABCDEFGH01234567890123456789' },
      ]), bareLaunchResolver);
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

  it('REDACTS a PREFIX of a protected secret truncated mid-write on the shared pipe (F6 round-3)', async () => {
    // A concurrent writer's newline can truncate a secret to a prefix on the
    // shared pipe; exact masking misses a prefix, so the onLine redactor also
    // runs maskValueFragments.  Assert a 20-char prefix of a declared secret is
    // masked end-to-end through hostRunScripts.
    const rec = makeRecorder();
    const SECRET = 'npm_AB12cd34EF56gh78IJ90klMNopQRstUVwx'; // high-entropy, 38 chars
    const PREFIX = SECRET.slice(0, 20);
    const prev = process.env['MY_DEPLOY_TOKEN'];
    process.env['MY_DEPLOY_TOKEN'] = SECRET;
    try {
      await hostRunScripts('npm', '/repo', [], rec.io, ['MY_DEPLOY_TOKEN'], okStreamSpawn(rec, [
        { stream: 'stdout', line: `leaked fragment ${PREFIX} on a truncated line` },
      ]), bareLaunchResolver);
      const all = rec.out.join('') + rec.errs.join('');
      expect(all).not.toContain(PREFIX);
      expect(all).toContain('<REDACTED:ENV>');
    } finally {
      if (prev === undefined) delete process.env['MY_DEPLOY_TOKEN'];
      else process.env['MY_DEPLOY_TOKEN'] = prev;
    }
  });

  it('FAILS LOUD (throws before streaming) when protected.env exceeds the redactor budget (review #8)', async () => {
    // A protected.env so large the fragment matcher caps must NOT silently
    // blackhole the job log: hostRunScripts throws an actionable config error
    // up front, before any line is streamed.  (Only reachable with > 2 MiB of
    // declared values on a high-`ulimit` runner; a single 2.1 MiB var here.)
    const rec = makeRecorder();
    let spawned = false;
    const spySpawn: HostStreamSpawn = (cmd, args, cwd, env, onLine) => {
      spawned = true;
      return okStreamSpawn(rec)(cmd, args, cwd, env, onLine);
    };
    const prev = process.env['MY_DEPLOY_TOKEN'];
    process.env['MY_DEPLOY_TOKEN'] = 'x'.repeat(2 * 1024 * 1024 + 100); // > 2 MiB chars
    try {
      await expect(
        hostRunScripts('npm', '/repo', [], rec.io, ['MY_DEPLOY_TOKEN'], spySpawn, bareLaunchResolver),
      ).rejects.toThrow(/more distinct secret material than the host lifecycle-log redactor/);
      expect(spawned).toBe(false); // never entered streaming
      expect(rec.out.join('') + rec.errs.join('')).not.toContain('xxxxxxxx'); // log not blanked/streamed
    } finally {
      if (prev === undefined) delete process.env['MY_DEPLOY_TOKEN'];
      else process.env['MY_DEPLOY_TOKEN'] = prev;
    }
  });
});

// ---------------------------------------------------------------------------
// SECURITY: host part-2 direct-launch closes the COREPACK_ROOT value-blind oracle
// ---------------------------------------------------------------------------
//
// The guest audit runs `node <cached-entry>` (no COREPACK_ROOT in the lifecycle
// child); host part-2 must do the SAME, or a corepack shim on the runner sets
// COREPACK_ROOT and a dep can branch benign-in-audit / evil-on-host (env-spy is
// value-blind).  These tests cover the rewrite (resolver → node+entry launch) and
// the self-contained resolveHostManagerLaunch decision tree.
describe('host part-2 direct-launch (COREPACK_ROOT oracle close)', () => {
  // Build a temp corepack cache with one version dir for a PM and the entry file.
  function makeCache(pm: 'pnpm' | 'yarn', version: string): { cacheRoot: string; verDir: string; cleanup: () => void } {
    const cacheRoot = mkdtempSync(join(tmpdir(), `sj-corepack-${pm}-`));
    const verDir = join(cacheRoot, 'v1', pm, version);
    mkdirSync(verDir, { recursive: true });
    if (pm === 'pnpm') {
      writeFileSync(join(verDir, '.corepack'), JSON.stringify({ bin: { pnpm: './bin/pnpm.cjs' } }));
      mkdirSync(join(verDir, 'bin'), { recursive: true });
      writeFileSync(join(verDir, 'bin', 'pnpm.cjs'), '// pnpm entry\n');
    } else {
      writeFileSync(join(verDir, '.corepack'), JSON.stringify({ bin: ['yarn', 'yarnpkg'] }));
      writeFileSync(join(verDir, 'yarn.js'), '// yarn entry\n');
    }
    return { cacheRoot, verDir, cleanup: () => rmSync(cacheRoot, { recursive: true, force: true }) };
  }

  it('corepack-managed pnpm → direct-launch (node + cached pnpm.cjs entry, finalArgs unchanged)', async () => {
    const { cacheRoot, verDir, cleanup } = makeCache('pnpm', '10.34.3');
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-pnpm-'));
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3+sha512.abc' }));
    try {
      const rec = makeRecorder();
      const resolver: HostManagerLaunchResolver = (pm, rd, env) =>
        // PATH:'' so "managed" is driven deterministically by the seeded cache
        // (machine-independent): the real sanitized PATH would resolve THIS host's
        // own pnpm/yarn, whose corepack-shim-vs-standalone status varies per runner
        // (and a confirmed-standalone bin now correctly bare-launches, codex round-17).
        // Shim-on-PATH → managed detection is covered by the `(b)`/`(b2)` tests.
        resolveHostManagerLaunch(pm, rd, { ...env, COREPACK_HOME: cacheRoot, PATH: '' });
      await hostRunScripts('pnpm', repoDir, [], rec.io, [], okStreamSpawn(rec), resolver);
      const call = rec.calls[0]!;
      expect(call.cmd).toBe(process.execPath); // launched via node
      // argv = [entry, ...finalArgs]; finalArgs is the SAME audited pnpm rebuild argv.
      expect(call.args[0]).toBe(join(verDir, 'bin', 'pnpm.cjs'));
      expect(call.args.slice(1)).toEqual([
        'rebuild', '--pending', '--config.side-effects-cache=false',
        `--store-dir=${repoDir}/.pnpm-store`, '--config.ignore-pnpmfile=true', '--config.script-shell=/bin/sh',
      ]);
    } finally {
      cleanup();
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('corepack-managed yarn → direct-launch (node + cached yarn.js, yarn install --immutable)', async () => {
    const { cacheRoot, verDir, cleanup } = makeCache('yarn', '4.9.1');
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-yarn-'));
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'yarn@4.9.1' }));
    try {
      const rec = makeRecorder();
      const resolver: HostManagerLaunchResolver = (pm, rd, env) =>
        // PATH:'' so "managed" is driven deterministically by the seeded cache
        // (machine-independent): the real sanitized PATH would resolve THIS host's
        // own pnpm/yarn, whose corepack-shim-vs-standalone status varies per runner
        // (and a confirmed-standalone bin now correctly bare-launches, codex round-17).
        // Shim-on-PATH → managed detection is covered by the `(b)`/`(b2)` tests.
        resolveHostManagerLaunch(pm, rd, { ...env, COREPACK_HOME: cacheRoot, PATH: '' });
      await hostRunScripts('yarn', repoDir, [], rec.io, [], okStreamSpawn(rec), resolver);
      const call = rec.calls[0]!;
      expect(call.cmd).toBe(process.execPath);
      expect(call.args).toEqual([join(verDir, 'yarn.js'), 'install', '--immutable']);
    } finally {
      cleanup();
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('npm → direct-launch (node + node-bundled npm-cli.js) with kept user args (#19)', async () => {
    // The real resolver resolves node-bundled npm-cli.js from process.execPath; on
    // a normal node toolchain it exists → direct-launch.  We assert against the
    // real resolveHostManagerLaunch (npm path is self-contained, no cache needed).
    const launch = resolveHostManagerLaunch('npm', '/repo', process.env);
    if (launch === undefined) {
      // Unusual node layout (no bundled npm-cli.js) — npm falls back to bare, which
      // sets no COREPACK_ROOT.  Skip the direct-launch assertion on such a runner.
      return;
    }
    const rec = makeRecorder();
    await hostRunScripts('npm', '/repo', ['--omit=dev'], rec.io, [], okStreamSpawn(rec));
    const call = rec.calls[0]!;
    expect(call.cmd).toBe(process.execPath);
    expect(call.args[0]).toBe(launch.entry);
    // #19: npm part-2 keeps the sanitized dep-selection user args after the base;
    // #43: --no-node-options is in the shared base (direct-launch carries it too).
    expect(call.args.slice(1)).toEqual(['rebuild', '--foreground-scripts', '--no-node-options', '--omit=dev']);
  });

  it('standalone PM (resolver → undefined) → bare-launch unchanged (regression guard)', async () => {
    const rec = makeRecorder();
    const resolver: HostManagerLaunchResolver = () => undefined;
    await hostRunScripts('pnpm', '/repo', [], rec.io, [], okStreamSpawn(rec), resolver);
    const call = rec.calls[0]!;
    expect(call.cmd).toBe('pnpm'); // bare name, NOT node
    expect(call.args).toEqual([
      'rebuild', '--pending', '--config.side-effects-cache=false',
      '--store-dir=/repo/.pnpm-store', '--config.ignore-pnpmfile=true', '--config.script-shell=/bin/sh',
    ]);
    // No direct-launch note in the banner when bare-launching.
    expect(rec.out.join('')).not.toContain('launched directly via node');
  });

  it('corepack-managed-but-unresolvable → hostRunScripts REJECTS (fail closed, mentions corepack)', async () => {
    // Managed is driven HERE by the CACHE (an unrelated version dir present), NOT
    // the shim probe (PATH:'' makes that a no-op); the PINNED dir is absent → must
    // THROW, never bare-launch (re-opening the oracle).  The shim-probe arm is
    // exercised on its own by 'isCorepackShim arm alone' below.
    const rec = makeRecorder();
    let spawned = false;
    const spy: HostStreamSpawn = async (cmd, args, cwd, env, onLine) => {
      spawned = true;
      return okStreamSpawn(rec)(cmd, args, cwd, env, onLine);
    };
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-cache-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-unres-'));
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@99.0.0' }));
    try {
      // Seed one UNRELATED version dir so the cache "has a version"
      // (corepackManaged=true) while the PINNED dir (pnpm@99.0.0) is absent → the
      // resolver must fail closed, never bare-launch.  PATH:'' so the shim probe is
      // a no-op and managed is driven purely by cacheHasAnyVersion.
      mkdirSync(join(emptyCache, 'v1', 'pnpm', '1.2.3'), { recursive: true });
      const resolver: HostManagerLaunchResolver = (pm, rd) =>
        resolveHostManagerLaunch(pm, rd, { COREPACK_HOME: emptyCache, PATH: '' });
      await expect(
        hostRunScripts('pnpm', repoDir, [], rec.io, [], spy, resolver),
      ).rejects.toThrow(/corepack/i);
      expect(spawned).toBe(false); // never spawned anything
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('resolveHostManagerLaunch unit: pinned version wins over a second cache dir', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-multi-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-multi-'));
    try {
      // Two pnpm version dirs in the cache.
      for (const v of ['10.34.3', '11.1.2']) {
        const vd = join(cacheRoot, 'v1', 'pnpm', v);
        mkdirSync(join(vd, 'bin'), { recursive: true });
        writeFileSync(join(vd, '.corepack'), JSON.stringify({ bin: { pnpm: './bin/pnpm.cjs' } }));
        writeFileSync(join(vd, 'bin', 'pnpm.cjs'), '// entry\n');
      }
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@11.1.2' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot });
      expect(launch).toBeDefined();
      expect(launch!.entry).toBe(join(cacheRoot, 'v1', 'pnpm', '11.1.2', 'bin', 'pnpm.cjs'));
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('resolveHostManagerLaunch unit: pinned-absent + managed → throws', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-absent-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-absent-'));
    try {
      // Cache HAS a version (managed) but NOT the pinned one.
      mkdirSync(join(cacheRoot, 'v1', 'pnpm', '10.34.3'), { recursive: true });
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@11.1.2' }));
      expect(() => resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /pinned version dir .* is absent/,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('resolveHostManagerLaunch unit: no pin + single cache dir → that dir', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-single-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-nopin-'));
    try {
      const vd = join(cacheRoot, 'v1', 'pnpm', '10.34.3');
      mkdirSync(join(vd, 'bin'), { recursive: true });
      writeFileSync(join(vd, '.corepack'), JSON.stringify({ bin: { pnpm: './bin/pnpm.cjs' } }));
      writeFileSync(join(vd, 'bin', 'pnpm.cjs'), '// entry\n');
      // package.json without a packageManager pin.
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot });
      expect(launch!.entry).toBe(join(vd, 'bin', 'pnpm.cjs'));
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('resolveHostManagerLaunch unit: no pin + multiple cache dirs → throws (ambiguous)', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-ambig-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-ambig-'));
    try {
      for (const v of ['10.34.3', '11.1.2']) mkdirSync(join(cacheRoot, 'v1', 'pnpm', v), { recursive: true });
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      expect(() => resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /expected exactly one pnpm version dir, found 2/,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('direct-launched child env carries NO COREPACK_HOME / COREPACK_ROOT (env parity)', async () => {
    // stripDangerousEnv drops the corepack_ family; assert the directly-launched
    // lifecycle child env has neither var even when both are set on the action.
    const { cacheRoot, cleanup } = makeCache('pnpm', '10.34.3');
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-envparity-'));
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3' }));
    const prevRoot = process.env['COREPACK_ROOT'];
    const prevHome = process.env['COREPACK_HOME'];
    process.env['COREPACK_ROOT'] = '/opt/corepack';
    process.env['COREPACK_HOME'] = cacheRoot;
    try {
      const envs: Array<NodeJS.ProcessEnv> = [];
      const resolver: HostManagerLaunchResolver = (pm, rd, env) =>
        // PATH:'' so "managed" is driven deterministically by the seeded cache
        // (machine-independent): the real sanitized PATH would resolve THIS host's
        // own pnpm/yarn, whose corepack-shim-vs-standalone status varies per runner
        // (and a confirmed-standalone bin now correctly bare-launches, codex round-17).
        // Shim-on-PATH → managed detection is covered by the `(b)`/`(b2)` tests.
        resolveHostManagerLaunch(pm, rd, { ...env, COREPACK_HOME: cacheRoot, PATH: '' });
      await hostRunScripts('pnpm', repoDir, [], makeRecorder().io, [], envCapturingStreamSpawn(envs), resolver);
      expect(envs[0]!['COREPACK_HOME']).toBeUndefined();
      expect(envs[0]!['COREPACK_ROOT']).toBeUndefined();
    } finally {
      if (prevRoot === undefined) delete process.env['COREPACK_ROOT']; else process.env['COREPACK_ROOT'] = prevRoot;
      if (prevHome === undefined) delete process.env['COREPACK_HOME']; else process.env['COREPACK_HOME'] = prevHome;
      cleanup();
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('banner shows the LOGICAL pm (pnpm rebuild ...), not the node/entry path', async () => {
    const { cacheRoot, cleanup } = makeCache('pnpm', '10.34.3');
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-banner-'));
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3' }));
    try {
      const rec = makeRecorder();
      const resolver: HostManagerLaunchResolver = (pm, rd, env) =>
        // PATH:'' so "managed" is driven deterministically by the seeded cache
        // (machine-independent): the real sanitized PATH would resolve THIS host's
        // own pnpm/yarn, whose corepack-shim-vs-standalone status varies per runner
        // (and a confirmed-standalone bin now correctly bare-launches, codex round-17).
        // Shim-on-PATH → managed detection is covered by the `(b)`/`(b2)` tests.
        resolveHostManagerLaunch(pm, rd, { ...env, COREPACK_HOME: cacheRoot, PATH: '' });
      await hostRunScripts('pnpm', repoDir, [], rec.io, [], okStreamSpawn(rec), resolver);
      const banner = rec.out.join('');
      expect(banner).toContain('pnpm rebuild --pending');
      expect(banner).not.toContain(process.execPath); // no node path
      expect(banner).not.toContain('pnpm.cjs'); // no entry path
      expect(banner).toContain('launched directly via node to bypass corepack');
    } finally {
      cleanup();
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('HostManagerLaunch type is shaped {node,entry}', () => {
    const l: HostManagerLaunch = { node: '/n', entry: '/e' };
    expect(l).toEqual({ node: '/n', entry: '/e' });
  });

  // -------------------------------------------------------------------------
  // FIX 6: REAL-resolver coverage (round-1 gap: branches were only simulated
  // with a `() => undefined` stub).  These drive resolveHostManagerLaunch's
  // arms directly with on-disk temp fixtures.
  // -------------------------------------------------------------------------

  // (a) standalone (non-shim PM on PATH + EMPTY corepack cache) → undefined.
  for (const pm of ['pnpm', 'yarn'] as const) {
    it(`(a) standalone ${pm}: empty cache + a non-shim ${pm} on PATH → resolves to undefined (bare-launch safe)`, () => {
      const emptyCache = mkdtempSync(join(tmpdir(), `sj-empty-${pm}-`));
      const binDir = mkdtempSync(join(tmpdir(), `sj-bin-${pm}-`));
      const repoDir = mkdtempSync(join(tmpdir(), `sj-repo-standalone-${pm}-`));
      try {
        // A standalone PM script whose bytes do NOT contain `corepack.cjs`.  Mode
        // 0755 so resolveBareOnPath (which models execvp's X_OK) finds it on PATH.
        writeFileSync(join(binDir, pm), '#!/usr/bin/env node\n// standalone, not a corepack shim\n');
        chmodSync(join(binDir, pm), 0o755);
        writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
        const launch = resolveHostManagerLaunch(pm, repoDir, { COREPACK_HOME: emptyCache, PATH: binDir });
        expect(launch).toBeUndefined();
      } finally {
        rmSync(emptyCache, { recursive: true, force: true });
        rmSync(binDir, { recursive: true, force: true });
        rmSync(repoDir, { recursive: true, force: true });
      }
    });
  }

  // (b) shim-driven managed: empty cache + a `pnpm` whose content contains
  // `corepack.cjs` on PATH → the isCorepackShim arm ALONE flips managed=true, so
  // with an empty cache the resolver fails closed (not undefined).  This proves the
  // shim probe is what flips it (the cache is empty), unlike the cache-driven tests.
  it('(b) shim on PATH (corepack.cjs signature) + empty cache → managed → fails closed (shim arm alone)', () => {
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-shim-'));
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-shim-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-shim-'));
    try {
      // The verified corepack shim signature: require('./lib/corepack.cjs').runMain
      writeFileSync(
        join(binDir, 'pnpm'),
        "#!/usr/bin/env node\nrequire('./lib/corepack.cjs').runMain(['pnpm', ...process.argv.slice(2)]);\n",
      );
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds it
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      // Empty cache + no pin → managed (shim) but unresolvable → throws.
      expect(() =>
        resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: emptyCache, PATH: binDir }),
      ).toThrow(/corepack-managed pnpm/i);
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('(b2) shim on PATH + seeded single cache version → resolves (managed, shim arm + cache)', () => {
    const { cacheRoot, verDir, cleanup } = makeCache('pnpm', '10.34.3');
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-shim2-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-shim2-'));
    try {
      writeFileSync(
        join(binDir, 'pnpm'),
        "#!/usr/bin/env node\nrequire('./lib/corepack.cjs').runMain(['pnpm']);\n",
      );
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds it
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot, PATH: binDir });
      expect(launch!.entry).toBe(join(verDir, 'bin', 'pnpm.cjs'));
    } finally {
      cleanup();
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (c) npm fail-closed via the new execPath seam (Fix 2).
  it('(c) npm fail-closed: a fake toolchain with no npm-cli.js → THROWS (mirrors the guest)', () => {
    const fakeToolchain = mkdtempSync(join(tmpdir(), 'sj-fake-node-'));
    // execPath layout is <root>/bin/node; toolchainRoot = dirname(dirname(execPath)).
    const fakeBin = join(fakeToolchain, 'bin');
    mkdirSync(fakeBin, { recursive: true });
    const fakeExecPath = join(fakeBin, 'node');
    writeFileSync(fakeExecPath, '#!/bin/sh\n'); // exists but lib/node_modules/npm absent
    try {
      expect(() => resolveHostManagerLaunch('npm', '/repo', {}, fakeExecPath)).toThrow(
        /refuses to bare-launch npm.*npm-cli\.js not found/s,
      );
    } finally {
      rmSync(fakeToolchain, { recursive: true, force: true });
    }
  });

  it('(c2) npm direct-launch: a fake toolchain WITH npm-cli.js → {node,entry} (execPath seam)', () => {
    const fakeToolchain = mkdtempSync(join(tmpdir(), 'sj-fake-node-ok-'));
    const fakeBin = join(fakeToolchain, 'bin');
    const npmDir = join(fakeToolchain, 'lib', 'node_modules', 'npm', 'bin');
    mkdirSync(fakeBin, { recursive: true });
    mkdirSync(npmDir, { recursive: true });
    const fakeExecPath = join(fakeBin, 'node');
    writeFileSync(fakeExecPath, '#!/bin/sh\n');
    const cli = join(npmDir, 'npm-cli.js');
    writeFileSync(cli, '// npm-cli\n');
    try {
      const launch = resolveHostManagerLaunch('npm', '/repo', {}, fakeExecPath);
      expect(launch).toEqual({ node: fakeExecPath, entry: cli });
    } finally {
      rmSync(fakeToolchain, { recursive: true, force: true });
    }
  });

  // (d) the failClosed sub-branches.
  it('(d) yarn version dir present but no yarn.js → throws', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-noyarnjs-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-noyarnjs-'));
    try {
      mkdirSync(join(cacheRoot, 'v1', 'yarn', '4.9.1'), { recursive: true }); // no yarn.js
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'yarn@4.9.1' }));
      expect(() => resolveHostManagerLaunch('yarn', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /yarn\.js not found at/,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('(d) pnpm .corepack bin is an ARRAY + no package.json bin → readHostPnpmBinRel null → throws', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-arrbin-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-arrbin-'));
    try {
      const vd = join(cacheRoot, 'v1', 'pnpm', '10.34.3');
      mkdirSync(vd, { recursive: true });
      // .corepack bin is an ARRAY (no path map) and package.json has NO bin map.
      writeFileSync(join(vd, '.corepack'), JSON.stringify({ bin: ['pnpm'] }));
      writeFileSync(join(vd, 'package.json'), JSON.stringify({ name: 'pnpm' }));
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3' }));
      expect(() => resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /could not read the pnpm entry path/,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('(d) pnpm .corepack rel points at a MISSING file → throws (pnpm entry not found)', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-missrel-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-missrel-'));
    try {
      const vd = join(cacheRoot, 'v1', 'pnpm', '10.34.3');
      mkdirSync(vd, { recursive: true });
      // rel is readable but the file it points at does not exist.
      writeFileSync(join(vd, '.corepack'), JSON.stringify({ bin: { pnpm: './bin/pnpm.cjs' } }));
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3' }));
      expect(() => resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /pnpm entry not found at/,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (e) REGRESSION-LOCK the isCorepackShim tightening: a standalone PM whose bytes
  // contain the bare `corepack` substring AND `runMain` (the two OLD over-broad
  // tokens) but NOT `corepack.cjs` must NOT be classified a shim — so with an empty
  // cache + no pin it resolves to undefined (bare-launch), NOT a fail-closed throw.
  // If a future edit re-broadens isCorepackShim to match `corepack`/`runMain`, this
  // flips to a throw and the test fails — guarding a legit standalone consumer.
  it('(e) standalone PM whose bytes contain bare `corepack`/`runMain` (not `corepack.cjs`) → undefined (tightening locked)', () => {
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-tighten-'));
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-tighten-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-tighten-'));
    try {
      // Contains 'corepack' and 'runMain' but NOT the literal 'corepack.cjs'.
      writeFileSync(
        join(binDir, 'pnpm'),
        '#!/usr/bin/env node\n// standalone pnpm; mentions corepack in a help string and calls runMain()\nrunMain();\n',
      );
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds it
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: emptyCache, PATH: binDir });
      expect(launch).toBeUndefined();
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (e) readHostPnpmBinRel package.json-bin FALLBACK success path (no `.corepack`):
  // a version dir with NO `.corepack` but a `package.json` bin.pnpm + the entry on
  // disk → resolves via the fallback (the round-1 tests only hit the `.corepack`
  // source or the null-miss branch, never the package.json SUCCESS).
  it('(e) pnpm no `.corepack` but package.json bin.pnpm present → resolves via fallback', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-pkgbin-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-pkgbin-'));
    try {
      const vd = join(cacheRoot, 'v1', 'pnpm', '10.34.3');
      mkdirSync(join(vd, 'bin'), { recursive: true });
      // NO .corepack file — only package.json carries the bin map.
      writeFileSync(join(vd, 'package.json'), JSON.stringify({ name: 'pnpm', bin: { pnpm: './bin/pnpm.cjs' } }));
      writeFileSync(join(vd, 'bin', 'pnpm.cjs'), '// pnpm entry\n');
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.34.3' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot });
      expect(launch!.entry).toBe(join(vd, 'bin', 'pnpm.cjs'));
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (e) no-pin + the `v1/<pm>/` dir EXISTS but is EMPTY (zero version subdirs) →
  // fail closed with "found 0".  Distinct from the readdir-ERROR branch (where
  // `v1/<pm>/` is absent): here managed is driven by the shim probe (the empty dir
  // makes cacheHasAnyVersion false), and the zero-length versionDirs hits the
  // `!== 1` throw.
  it('(e) no pin + empty `v1/<pm>/` dir (shim-driven managed) → throws (found 0)', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-zerodir-'));
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-zerodir-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-zerodir-'));
    try {
      mkdirSync(join(cacheRoot, 'v1', 'pnpm'), { recursive: true }); // exists, EMPTY (zero version dirs)
      writeFileSync(
        join(binDir, 'pnpm'),
        "#!/usr/bin/env node\nrequire('./lib/corepack.cjs').runMain(['pnpm']);\n", // shim → managed
      );
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds the shim
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' })); // no packageManager pin
      expect(() =>
        resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot, PATH: binDir }),
      ).toThrow(/expected exactly one pnpm version dir, found 0/);
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (f) codex round-17 [medium]: a CONFIRMED-standalone PM on the sanitized PATH must
  // bare-launch (undefined) EVEN WHEN the runner's corepack cache holds a (stale)
  // version of that PM — a leftover `~/.cache/node/corepack` entry from an unrelated
  // prior job must NOT hijack (no-pin) a proven standalone install.  Before the fix
  // `cacheHasAnyVersion` OR'd this to managed → returned node + the stale cached entry.
  it('(f) standalone PM on PATH + stale cache version + NO pin → undefined (cache does not hijack)', () => {
    const { cacheRoot, cleanup } = makeCache('pnpm', '10.34.3'); // stale cached corepack pnpm
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-standalone-stale-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-standalone-stale-'));
    try {
      // A standalone pnpm (NOT a corepack.cjs shim) on the PATH the child would use.
      writeFileSync(join(binDir, 'pnpm'), '#!/usr/bin/env node\n// standalone pnpm, not a corepack shim\n');
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds it
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' })); // NO packageManager pin
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot, PATH: binDir });
      expect(launch).toBeUndefined(); // bare-launch the standalone PM, NOT the stale cached entry
    } finally {
      cleanup();
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (f) and a PINNED standalone consumer whose pin is NOT in the (stale) cache must
  // also bare-launch, NOT fail closed — the PATH binary is a confirmed standalone PM,
  // so the pin/throw path is never reached.
  it('(f) standalone PM on PATH + pinned version absent from a stale cache → undefined (no fail-closed break)', () => {
    const { cacheRoot, cleanup } = makeCache('pnpm', '10.34.3'); // cache holds 10.34.3 only
    const binDir = mkdtempSync(join(tmpdir(), 'sj-bin-standalone-pin-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-standalone-pin-'));
    try {
      writeFileSync(join(binDir, 'pnpm'), '#!/usr/bin/env node\n// standalone pnpm, not a corepack shim\n');
      chmodSync(join(binDir, 'pnpm'), 0o755); // executable so resolveBareOnPath (X_OK) finds it
      // Pin a DIFFERENT version that is absent from the cache.
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@11.1.2' }));
      const launch = resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot, PATH: binDir });
      expect(launch).toBeUndefined(); // standalone → bare-launch; never reaches the pinned-absent throw
    } finally {
      cleanup();
      rmSync(binDir, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (g) codex round-17c [medium]: a readable but NON-EXECUTABLE `pnpm` (mode 0644)
  // earlier on PATH must NOT mask a LATER executable corepack shim.  execvp skips the
  // non-exec hit and execs the later shim, so resolveBareOnPath must too (access X_OK)
  // — otherwise the non-exec file would be classified "confirmed standalone" →
  // bare-launch → the child execs the shim → COREPACK_ROOT re-opens.  With the fix the
  // resolver inspects the executable shim → managed → fails closed on an empty cache
  // (never bare-launch).  Before the fix this returned undefined (no throw).
  it('(g) non-executable non-shim PM before an executable corepack shim on PATH → managed (X_OK precedence)', () => {
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-xok-'));
    const dir1 = mkdtempSync(join(tmpdir(), 'sj-xok-nonexec-')); // first hit: 0644, non-shim
    const dir2 = mkdtempSync(join(tmpdir(), 'sj-xok-shim-')); // later hit: executable shim
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-xok-'));
    try {
      const nonExec = join(dir1, 'pnpm');
      writeFileSync(nonExec, '#!/usr/bin/env node\n// readable non-shim standalone, but NOT executable\n');
      chmodSync(nonExec, 0o644); // no execute bit → execvp would skip it
      const shim = join(dir2, 'pnpm');
      writeFileSync(shim, "#!/usr/bin/env node\nrequire('./lib/corepack.cjs').runMain(['pnpm']);\n");
      chmodSync(shim, 0o755); // executable corepack shim → what the child actually execs
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' })); // no pin
      // The non-exec dir1/pnpm must NOT win: resolver skips it, finds the executable
      // shim in dir2 → managed → empty cache → fails closed (NOT undefined/bare-launch).
      expect(() =>
        resolveHostManagerLaunch('pnpm', repoDir, {
          COREPACK_HOME: emptyCache,
          PATH: `${dir1}${delimiter}${dir2}`,
        }),
      ).toThrow(/corepack-managed pnpm/i);
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(dir1, { recursive: true, force: true });
      rmSync(dir2, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (h) codex round-17d [medium]: a DIRECTORY named `pnpm` earlier on PATH passes
  // both existence and access(X_OK) (a dir is "searchable"), but execvp does NOT exec
  // it — it keeps scanning and runs the LATER standalone.  resolveBareOnPath must
  // model that (statSync().isFile()) and skip the directory; otherwise the dir is
  // returned, isCorepackShim readFileSync's it → EISDIR → fail-safe "managed", and a
  // confirmed-standalone install is wrongly refused (empty cache → throw) or hijacked
  // (stale cache → direct-launch the cached PM) while spawn actually runs the
  // standalone.  Verified empirically: spawn('pnpm') with PATH=dir:standalone runs the
  // standalone.
  it('(h) executable DIRECTORY named pnpm before a standalone PM on PATH → undefined (dir skipped, bare-launch)', () => {
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-dir-'));
    const dir1 = mkdtempSync(join(tmpdir(), 'sj-dir-hit-')); // first hit: a DIRECTORY named pnpm
    const dir2 = mkdtempSync(join(tmpdir(), 'sj-dir-standalone-')); // later hit: standalone file
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-dir-'));
    try {
      mkdirSync(join(dir1, 'pnpm')); // a directory named pnpm (mode 0755 by default → X_OK passes)
      const standalone = join(dir2, 'pnpm');
      writeFileSync(standalone, '#!/usr/bin/env node\n// standalone pnpm, not a corepack shim\n');
      chmodSync(standalone, 0o755);
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' })); // no pin
      const launch = resolveHostManagerLaunch('pnpm', repoDir, {
        COREPACK_HOME: emptyCache,
        PATH: `${dir1}${delimiter}${dir2}`,
      });
      expect(launch).toBeUndefined(); // dir skipped → standalone confirmed → bare-launch
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(dir1, { recursive: true, force: true });
      rmSync(dir2, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (h) mirror: a DIRECTORY named pnpm before an executable corepack shim must NOT mask
  // the shim — the resolver skips the dir, finds the shim → managed → fails closed.
  it('(h) executable DIRECTORY named pnpm before a corepack shim on PATH → managed (shim still detected)', () => {
    const emptyCache = mkdtempSync(join(tmpdir(), 'sj-empty-dirshim-'));
    const dir1 = mkdtempSync(join(tmpdir(), 'sj-dirshim-hit-')); // first hit: a DIRECTORY named pnpm
    const dir2 = mkdtempSync(join(tmpdir(), 'sj-dirshim-shim-')); // later hit: executable shim
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-dirshim-'));
    try {
      mkdirSync(join(dir1, 'pnpm'));
      const shim = join(dir2, 'pnpm');
      writeFileSync(shim, "#!/usr/bin/env node\nrequire('./lib/corepack.cjs').runMain(['pnpm']);\n");
      chmodSync(shim, 0o755);
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' })); // no pin
      expect(() =>
        resolveHostManagerLaunch('pnpm', repoDir, {
          COREPACK_HOME: emptyCache,
          PATH: `${dir1}${delimiter}${dir2}`,
        }),
      ).toThrow(/corepack-managed pnpm/i);
    } finally {
      rmSync(emptyCache, { recursive: true, force: true });
      rmSync(dir1, { recursive: true, force: true });
      rmSync(dir2, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (i) codex round-17e [high]: an injected LOCALAPPDATA must NOT steer corepackCacheRoot
  // on a non-win32 host.  corepack consults LOCALAPPDATA ONLY on win32; the action runs
  // only on Linux/macOS, so the resolver must ignore it there (else a PR/runner-set
  // LOCALAPPDATA pointing at a checkout-controlled cache makes host part-2 direct-launch a
  // planted entry).  Plant a v1/pnpm/99.99.99 cache under LOCALAPPDATA and pin 99.99.99
  // (a version never in the real ~/.cache) with NO XDG_CACHE_HOME: pre-fix the resolver
  // used LOCALAPPDATA and returned the planted entry; post-fix it uses ~/.cache, misses,
  // and fails closed.  (win32 is never a host for this action, so skip there.)
  it.skipIf(process.platform === 'win32')(
    '(i) injected LOCALAPPDATA does NOT steer corepackCacheRoot on a non-win32 host (fail-closed, planted cache ignored)',
    () => {
      const laaCache = mkdtempSync(join(tmpdir(), 'sj-laa-cache-'));
      const repoDir = mkdtempSync(join(tmpdir(), 'sj-laa-repo-'));
      try {
        const vd = join(laaCache, 'node', 'corepack', 'v1', 'pnpm', '99.99.99');
        mkdirSync(join(vd, 'bin'), { recursive: true });
        writeFileSync(join(vd, 'package.json'), JSON.stringify({ name: 'pnpm', bin: { pnpm: './bin/pnpm.cjs' } }));
        writeFileSync(join(vd, 'bin', 'pnpm.cjs'), '// PLANTED pnpm entry under LOCALAPPDATA\n');
        writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ packageManager: 'pnpm@99.99.99' }));
        let entry: string | undefined;
        let threw = false;
        try {
          // NO XDG_CACHE_HOME, empty PATH → the only PM signal is the planted LOCALAPPDATA cache.
          const launch = resolveHostManagerLaunch('pnpm', repoDir, { LOCALAPPDATA: laaCache, PATH: '' });
          entry = launch?.entry;
        } catch {
          threw = true; // ~/.cache has no pnpm@99.99.99 → pinned-absent fail-closed throw
        }
        // Either way, the planted LOCALAPPDATA entry must NEVER be the resolved launch.
        expect(entry?.startsWith(laaCache)).not.toBe(true);
        expect(threw || entry === undefined).toBe(true);
      } finally {
        rmSync(laaCache, { recursive: true, force: true });
        rmSync(repoDir, { recursive: true, force: true });
      }
    },
  );

  // (e) Fix-1 wiring: hostRunScripts feeds the resolver the CHILD env (sanitized
  // PATH, COREPACK_HOME/XDG_CACHE_HOME stripped), NOT raw process.env.
  it('(e) hostRunScripts passes the resolver the sanitized child env (no checkout PATH, no COREPACK_HOME/XDG_CACHE_HOME)', async () => {
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-fix1-'));
    // A checkout-controlled dir + a benign system dir on PATH; sanitizePathValue
    // must drop the checkout dir from the env the resolver sees.
    const checkoutDir = join(repoDir, 'evil-bin');
    mkdirSync(checkoutDir, { recursive: true });
    const prevPath = process.env['PATH'];
    const prevCk = process.env['COREPACK_HOME'];
    const prevXdg = process.env['XDG_CACHE_HOME'];
    const prevRepoDir = process.env['SCRIPT_JAIL_REPO_DIR'];
    // checkoutRoots() derives the checkout tree from SCRIPT_JAIL_REPO_DIR /
    // GITHUB_WORKSPACE / cwd (NOT the repoDir arg), so mark repoDir as the checkout
    // root for sanitizePathValue to drop `checkoutDir` under it.
    process.env['SCRIPT_JAIL_REPO_DIR'] = repoDir;
    process.env['PATH'] = `${checkoutDir}${delimiter}/usr/bin`;
    process.env['COREPACK_HOME'] = '/tmp/raw-corepack-home';
    process.env['XDG_CACHE_HOME'] = '/tmp/raw-xdg-cache';
    let capturedEnv: NodeJS.ProcessEnv | undefined;
    const capturingResolver: HostManagerLaunchResolver = (_pm, _rd, env) => {
      capturedEnv = env;
      return undefined; // bare-launch (don't care about the launch here)
    };
    try {
      const rec = makeRecorder();
      await hostRunScripts('pnpm', repoDir, [], rec.io, [], okStreamSpawn(rec), capturingResolver);
      expect(capturedEnv).toBeDefined();
      // PATH sanitized: the checkout dir is gone, the system dir survives.
      const seenPath = capturedEnv!['PATH'] ?? '';
      expect(seenPath.split(delimiter)).not.toContain(checkoutDir);
      expect(seenPath.split(delimiter)).toContain('/usr/bin');
      // corepack_/xdg_ families stripped → resolver reads the DEFAULT cache root.
      expect(capturedEnv!['COREPACK_HOME']).toBeUndefined();
      expect(capturedEnv!['XDG_CACHE_HOME']).toBeUndefined();
    } finally {
      if (prevPath === undefined) delete process.env['PATH']; else process.env['PATH'] = prevPath;
      if (prevCk === undefined) delete process.env['COREPACK_HOME']; else process.env['COREPACK_HOME'] = prevCk;
      if (prevXdg === undefined) delete process.env['XDG_CACHE_HOME']; else process.env['XDG_CACHE_HOME'] = prevXdg;
      if (prevRepoDir === undefined) delete process.env['SCRIPT_JAIL_REPO_DIR']; else process.env['SCRIPT_JAIL_REPO_DIR'] = prevRepoDir;
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it('(e2) Fix-1: the resolver env and the spawn env are the SAME object (one childEnv)', async () => {
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-fix1b-'));
    try {
      let resolverEnv: NodeJS.ProcessEnv | undefined;
      const capturingResolver: HostManagerLaunchResolver = (_pm, _rd, env) => {
        resolverEnv = env;
        return undefined;
      };
      const spawnEnvs: Array<NodeJS.ProcessEnv> = [];
      await hostRunScripts(
        'pnpm', repoDir, [], makeRecorder().io, [], envCapturingStreamSpawn(spawnEnvs), capturingResolver,
      );
      expect(resolverEnv).toBeDefined();
      expect(spawnEnvs[0]).toBe(resolverEnv); // identical reference → inspected == executed
    } finally {
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  // (f) Fix-5: the no-pin multi-version throw recommends pinning packageManager.
  it('(f) no-pin + multiple cache dirs → throw message recommends pinning "packageManager"', () => {
    const cacheRoot = mkdtempSync(join(tmpdir(), 'sj-cache-multinopin-'));
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-multinopin-'));
    try {
      for (const v of ['10.34.3', '11.1.2']) mkdirSync(join(cacheRoot, 'v1', 'pnpm', v), { recursive: true });
      writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ name: 'x' }));
      expect(() => resolveHostManagerLaunch('pnpm', repoDir, { COREPACK_HOME: cacheRoot })).toThrow(
        /found 2 .*pin "packageManager"/s,
      );
    } finally {
      rmSync(cacheRoot, { recursive: true, force: true });
      rmSync(repoDir, { recursive: true, force: true });
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

  it('part 2 (lifecycle scripts) does NOT set npm_config_git (value-blind-lock close, round-15)', async () => {
    // npm_config_git defeats a repo `.npmrc git=<pwn>` during git-DEPENDENCY CLONE,
    // which happens ONLY in part-1 (fetch).  `npm rebuild` (part-2) never clones, so
    // the pin is irrelevant — and SETTING it in part-2 was a value-blind oracle: the
    // host lifecycle child saw npm_config_git=<abs> while the guest Phase B child
    // (never pins git) saw it ABSENT, letting a dep branch host-vs-audit while the
    // value-blind lock matched.  Part-2 must now leave it ABSENT == guest Phase B.
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    await hostRunScripts('npm', '/repo', [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
    expect(envs).toHaveLength(1);
    expect(envs[0]!['npm_config_git']).toBeUndefined();
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

  it('SKIPS a DIRECTORY named git earlier on PATH and continues to the real binary (#38, execvp file-type)', () => {
    // A directory named `git` passes existsSync (and even access(X_OK) as a
    // *searchable* dir), but execvp does NOT exec it — it keeps scanning PATH.
    // resolveGitFromPath modeled only existence, so it returned the directory and
    // pinned it as npm_config_git, breaking a git: dep install that would otherwise
    // fall through to the real git later on PATH.  Mirrors resolveBareOnPath
    // (round-17d).  Both candidate dirs live OUTSIDE the checkout (GITHUB_WORKSPACE
    // points elsewhere) so the containment guards do not interfere.
    const gitName = process.platform === 'win32' ? 'git.exe' : 'git';
    const early = mkdtempSync(join(tmpdir(), 'sj-gitdir-'));
    mkdirSync(join(early, gitName)); // a DIRECTORY, not a file
    const real = mkdtempSync(join(tmpdir(), 'sj-realgit-'));
    const realGit = join(real, gitName);
    writeFileSync(realGit, '#!/bin/sh\necho real\n', { mode: 0o755 });
    const ws = mkdtempSync(join(tmpdir(), 'sj-ws-'));
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = ws;
      process.env['PATH'] = `${early}${delimiter}${real}`;
      expect(resolveGitFromPath()).toBe(realGit);
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(early, { recursive: true, force: true });
      rmSync(real, { recursive: true, force: true });
      rmSync(ws, { recursive: true, force: true });
    }
  });

  it('SKIPS a NON-EXECUTABLE git earlier on PATH and continues to the real binary (#38, execvp X_OK)', () => {
    // A readable but non-executable `git` (mode 0644) is skipped by execvp, which
    // keeps scanning PATH.  existsSync alone returned it; access(X_OK) (the exact
    // predicate execvp uses) makes the scan fall through to the real git.  On win32
    // X_OK degrades to existence, so this class is non-applicable there.
    if (process.platform === 'win32') return;
    const early = mkdtempSync(join(tmpdir(), 'sj-gitnox-'));
    writeFileSync(join(early, 'git'), '#!/bin/sh\necho nope\n', { mode: 0o644 }); // NOT executable
    const real = mkdtempSync(join(tmpdir(), 'sj-realgit-'));
    const realGit = join(real, 'git');
    writeFileSync(realGit, '#!/bin/sh\necho real\n', { mode: 0o755 });
    const ws = mkdtempSync(join(tmpdir(), 'sj-ws-'));
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = ws;
      process.env['PATH'] = `${early}${delimiter}${real}`;
      expect(resolveGitFromPath()).toBe(realGit);
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(early, { recursive: true, force: true });
      rmSync(real, { recursive: true, force: true });
      rmSync(ws, { recursive: true, force: true });
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

  it('REJECTS a checkout PATH dir that SYMLINKS OUT to a system dir (symlink-out / lexical defense, #24)', () => {
    // P1 (#24): `$GITHUB_WORKSPACE/tools -> <outside dir>` has its REAL path OUTSIDE
    // the checkout, so realpath-only containment KEEPS it — but the PR controls that
    // symlink and can repoint it to a dir of malicious binaries in trusted host
    // part-2.  The lexical-spelling check must drop it (its spelling is inside the
    // checkout), in BOTH resolveGitFromPath and sanitizePathValue.
    if (process.platform === 'win32') return;
    const checkout = mkdtempSync(join(tmpdir(), 'sj-co24-'));
    const outside = mkdtempSync(join(tmpdir(), 'sj-sys24-'));
    writeFileSync(join(outside, 'git'), '#!/bin/sh\necho hi\n', { mode: 0o755 });
    const tools = join(checkout, 'tools');
    symlinkSync(outside, tools); // checkout-lexical dir → outside-checkout REAL dir
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      // resolveGitFromPath must NOT trust the git in the symlink-out checkout dir
      process.env['PATH'] = `${tools}${delimiter}/usr/bin${delimiter}/bin`;
      expect(resolveGitFromPath()).not.toBe(join(tools, 'git'));
      // sanitizePathValue must DROP the symlink-out checkout dir but keep system dirs
      expect(sanitizePathValue(`${tools}${delimiter}/usr/bin${delimiter}/bin`)).toBe(
        `/usr/bin${delimiter}/bin`,
      );
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('isPathUnderCheckout REJECTS a symlink-OUT path spelled under the checkout (round-12 #24 sibling: VZ-helper gate)', () => {
    // The exported guard backs the pre-trust SCRIPT_JAIL_VM_BIN VZ-helper gate
    // (resolveScriptJailVmBinary).  It MUST reject the same symlink-out class the
    // PATH/git sanitizers do: `$GITHUB_WORKSPACE/tools -> <outside>` realpaths
    // OUTSIDE the checkout, so a realpath-only guard wrongly ACCEPTS
    // `$GITHUB_WORKSPACE/tools/script-jail-vm` even though the symlink is
    // PR-controlled.  The lexical arm must drop it on its under-checkout spelling.
    if (process.platform === 'win32') return;
    const checkout = mkdtempSync(join(tmpdir(), 'sj-vmco-'));
    const outside = mkdtempSync(join(tmpdir(), 'sj-vmout-'));
    const tools = join(checkout, 'tools');
    symlinkSync(outside, tools); // checkout-lexical dir → outside-checkout REAL dir
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      // symlink-OUT path spelled under the checkout → rejected (lexical arm).
      expect(isPathUnderCheckout(join(tools, 'script-jail-vm'))).toBe(true);
      // a genuinely-outside path is still accepted (not over-broad).
      expect(isPathUnderCheckout(join(outside, 'script-jail-vm'))).toBe(false);
      // a plain checkout-resident path is rejected (realpath arm, unchanged).
      expect(isPathUnderCheckout(join(checkout, 'bin', 'script-jail-vm'))).toBe(true);
    } finally {
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('preserves the inherited env (HOME etc.) and the SYSTEM PATH entries by merging over process.env', () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    // PATH survives the merge, but it is now SANITIZED ([5]+[9]): any entry whose
    // real path is under a checkout root (process.cwd() is always one) is dropped
    // so a checkout-placed bin/<tool> cannot shadow the bare-name PM/tool lookup.
    // Under vitest, PATH is prefixed with `./node_modules/.bin` + `<cwd>/node_modules/.bin`
    // (both under cwd) — those are correctly dropped; the system dirs survive in order.
    const before = process.env['PATH']!.split(delimiter);
    const after = envs[0]!['PATH']!.split(delimiter);
    const cwd = realpathSync(process.cwd());
    const survivors = before.filter(
      (p) => p !== '' && !realpathSafe(p).startsWith(cwd),
    );
    expect(after).toEqual(survivors);
    // The cwd-resident node_modules/.bin entries vitest injects ARE dropped.
    expect(after.some((p) => realpathSafe(p).startsWith(cwd))).toBe(false);
    // A genuine system dir survives.
    expect(after).toContain('/usr/bin');
  });
});

/** realpath that falls back to the lexical path when the entry does not exist. */
function realpathSafe(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

describe('home ~/.npmrc script-shell defense (#26)', () => {
  const shell = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';

  it('part-1 pins npm_config_script_shell to the system shell for npm', () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    expect(envs[0]?.['npm_config_script_shell']).toBe(shell);
  });

  it('part-2 npm rebuild env also pins npm_config_script_shell (the post-trust path)', async () => {
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    await hostRunScripts('npm', '/repo', [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
    expect(envs[0]?.['npm_config_script_shell']).toBe(shell);
  });

  it('does NOT pin npm_config_script_shell for pnpm/yarn (npm-scoped)', () => {
    for (const pm of ['pnpm', 'yarn'] as const) {
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      hostInstallNoScripts(pm, '/repo', [], rec.io, envCapturingSpawn(envs));
      expect(envs[0]?.['npm_config_script_shell']).toBeUndefined();
    }
  });

  it('part-2 pnpm rebuild appends --config.script-shell=/bin/sh (sibling, kept with ignore-pnpmfile)', async () => {
    const rec = makeRecorder();
    await hostRunScripts('pnpm', '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
    expect(rec.calls[0]?.args).toContain('--config.script-shell=/bin/sh');
    expect(rec.calls[0]?.args).toContain('--config.ignore-pnpmfile=true');
  });

  it('part-2 does NOT add the pnpm script-shell flag for npm/yarn', async () => {
    for (const pm of ['npm', 'yarn'] as const) {
      const rec = makeRecorder();
      await hostRunScripts(pm, '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      expect(rec.calls[0]?.args).not.toContain('--config.script-shell=/bin/sh');
    }
  });

  // #43 — npm re-derives `node-options` from the home AND project npmrc and exports
  // it to lifecycle scripts as the child NODE_OPTIONS *and* the npm_config_node_options
  // env value.  --no-node-options neutralizes both.  It rides the SHARED INSTALL_CMD.npm
  // (NOT a host-only flag) so host part-2 and guest Phase B carry it byte-identically —
  // a host-only flag would diverge npm_config_node_options (value-blind oracle).  Here
  // we assert the host part-2 path surfaces it right after the base; guest lockstep is
  // covered by the INSTALL_CMD + phase-install tests.
  it('part-2 npm rebuild carries --no-node-options from the shared base (#43 node-options close)', async () => {
    const rec = makeRecorder();
    await hostRunScripts('npm', '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
    expect(rec.calls[0]?.args).toContain('--no-node-options');
    // In the base, immediately after --foreground-scripts (before any user args).
    expect(rec.calls[0]?.args.slice(0, 3)).toEqual(['rebuild', '--foreground-scripts', '--no-node-options']);
  });

  it('part-2 does NOT add --no-node-options for pnpm/yarn (npm-scoped)', async () => {
    for (const pm of ['pnpm', 'yarn'] as const) {
      const rec = makeRecorder();
      await hostRunScripts(pm, '/repo', [], rec.io, [], okStreamSpawn(rec), bareLaunchResolver);
      expect(rec.calls[0]?.args).not.toContain('--no-node-options');
    }
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
          await hostRunScripts(pm, '/repo', [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
          const env = envs[0]!;
          // Sandbox tells that an env-sensitive payload could branch on are gone.
          expect(env['HOSTNAME']).toBeUndefined();
          expect(env['PWD']).toBeUndefined();
          expect(env['TERM']).toBeUndefined();
          for (const k of Object.keys(env)) {
            expect(k.startsWith('SCRIPT_JAIL_')).toBe(false);
          }
          // The security pins / inherited essentials still survive the strip.
          // (npm_config_git is now fetch/part-1 only — round-15 value-blind close —
          // so part-2 asserts a phase-stable pin instead.)
          expect(env['COREPACK_ENABLE_DOWNLOAD_PROMPT']).toBe('0');
          expect(env['npm_config_git']).toBeUndefined();
          // PATH survives but is SANITIZED ([5]+[9]): cwd-resident entries (the
          // vitest node_modules/.bin prefixes) are dropped; system dirs survive.
          expect(env['PATH']).toBeDefined();
          expect(env['PATH']!.split(delimiter)).toContain('/usr/bin');
          const cwd = realpathSync(process.cwd());
          expect(env['PATH']!.split(delimiter).some((p) => realpathSafe(p).startsWith(cwd))).toBe(false);
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
      await hostRunScripts('yarn', '/repo', [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
      const env = envs[0]!;
      expect(env['YARN_IGNORE_PATH']).toBe('1');
      expect(env['YARN_PLUGINS']).toBe('');
      expect(env['YARN_ENABLE_CONSTRAINTS_CHECKS']).toBe('false');
    });
  });
});

// ---------------------------------------------------------------------------
// SECURITY/RELIABILITY (adversarial-review F6, Finding 2): the async streaming
// part-2 runner must (A) never hang when a detached descendant holds the
// inherited pipe open after the package manager exits, and (B) never buffer an
// unterminated line without bound (OOM).
// ---------------------------------------------------------------------------

describe('makeLineSink (part-2 bounded line splitter)', () => {
  function collect(): { lines: Array<{ which: string; line: string }>; onLine: (which: 'stdout' | 'stderr', line: string) => void } {
    const lines: Array<{ which: string; line: string }> = [];
    return { lines, onLine: (which, line) => { lines.push({ which, line }); } };
  }

  it('forwards each COMPLETE line and holds a partial until finalize (EOF)', () => {
    const { lines, onLine } = collect();
    const sink = makeLineSink('stdout', onLine);
    sink.onData(Buffer.from('alpha\nbeta\npar'));
    expect(lines.map((l) => l.line)).toEqual(['alpha', 'beta']);
    sink.onData(Buffer.from('tial\n'));
    expect(lines.map((l) => l.line)).toEqual(['alpha', 'beta', 'partial']);
    // A final unterminated line is forwarded ONLY on finalize(EOF).
    sink.onData(Buffer.from('last-no-newline'));
    expect(lines).toHaveLength(3);
    sink.finalize(true); // stream reached EOF → the complete trailing line forwards
    expect(lines.map((l) => l.line)).toEqual(['alpha', 'beta', 'partial', 'last-no-newline']);
  });

  it('DROPS a trailing partial on a NON-EOF finalize (grace path) — emits only a marker (F6 round-2)', () => {
    const { lines, onLine } = collect();
    const sink = makeLineSink('stdout', onLine);
    sink.onData(Buffer.from('complete\nsuperSecretFragmentNoNewline'));
    expect(lines.map((l) => l.line)).toEqual(['complete']); // partial still held
    sink.finalize(false); // pipe still open at grace close → fragment must NOT leak
    expect(lines).toEqual([
      { which: 'stdout', line: 'complete' },
      { which: 'stdout', line: HOST_PART2_TRUNCATED_MARKER },
    ]);
    // The raw mid-write fragment is never forwarded.
    expect(lines.some((l) => l.line.includes('superSecretFragment'))).toBe(false);
  });

  it('emits NO marker on a NON-EOF finalize when there is no pending partial', () => {
    const { lines, onLine } = collect();
    const sink = makeLineSink('stdout', onLine);
    sink.onData(Buffer.from('one\ntwo\n')); // both complete, pending empty
    sink.finalize(false);
    expect(lines.map((l) => l.line)).toEqual(['one', 'two']); // no spurious marker
  });

  it('SPLITTER forwards a concurrent-newline-completed prefix (redaction is downstream) (F6 round-3)', () => {
    // stdout/stderr are ONE shared pipe; the sink cannot tell "writer A prefix +
    // writer B newline" from "writer A whole line", so it forwards the prefix as
    // a line.  This is correct for the SPLITTER (it does not redact) — the line
    // is redacted DOWNSTREAM in hostRunScripts.onLine, which now masks declared
    // secret PREFIX/SUFFIX fragments (maskValueFragments, F6 round-3 hardening),
    // not just the whole value.  Only an arbitrary-MIDDLE deliberate split
    // remains the irreducible LINE-LOCAL residual (same as guest), bounded by the
    // PRIMARY env_read audit gate.  Assert the splitter scope honestly so a
    // future change can't silently shift it.
    const { lines, onLine } = collect();
    const sink = makeLineSink('stdout', onLine);
    sink.onData(Buffer.from('writerA-prefix'));       // writer A, no newline
    sink.onData(Buffer.from('\nwriterB-line\n'));     // writer B supplies the newline
    expect(lines.map((l) => l.line)).toEqual(['writerA-prefix', 'writerB-line']);
  });

  it('does NOT corrupt a multibyte char split across chunk boundaries (StringDecoder)', () => {
    const { lines, onLine } = collect();
    const sink = makeLineSink('stdout', onLine);
    const euro = Buffer.from('€', 'utf8'); // 3 bytes: e2 82 ac
    sink.onData(euro.subarray(0, 2)); // first 2 bytes — incomplete codepoint
    sink.onData(Buffer.concat([euro.subarray(2), Buffer.from('\n')])); // last byte + newline
    expect(lines).toEqual([{ which: 'stdout', line: '€' }]);
  });

  it('POISONS an oversized unterminated line (no OOM, never forwarded raw), then resumes', () => {
    const { lines, onLine } = collect();
    const cap = 64;
    const sink = makeLineSink('stderr', onLine, cap);
    sink.onData(Buffer.from('X'.repeat(cap + 50))); // > cap, no newline
    // Exactly one fixed marker; the raw oversized content is NOT forwarded.
    expect(lines).toEqual([{ which: 'stderr', line: HOST_PART2_POISON_MARKER }]);
    // Further oversized bytes (still no newline) do NOT emit more markers.
    sink.onData(Buffer.from('Y'.repeat(cap + 10)));
    expect(lines).toHaveLength(1);
    // A newline ends the poisoned line; subsequent lines forward normally.
    sink.onData(Buffer.from('tail-of-poison\nclean-line\n'));
    expect(lines).toEqual([
      { which: 'stderr', line: HOST_PART2_POISON_MARKER },
      { which: 'stderr', line: 'clean-line' },
    ]);
    // The oversized bytes never appear in any forwarded line.
    expect(lines.some((l) => l.line.includes('X') || l.line.includes('Y'))).toBe(false);
  });
});

describe('streamSpawn (part-2 real-child integration)', () => {
  function collect(): { lines: Array<{ which: string; line: string }>; onLine: (which: 'stdout' | 'stderr', line: string) => void } {
    const lines: Array<{ which: string; line: string }> = [];
    return { lines, onLine: (which, line) => { lines.push({ which, line }); } };
  }

  it('forwards stdout/stderr lines and resolves with the child exit code', async () => {
    const { lines, onLine } = collect();
    const script = 'const fs=require("node:fs"); fs.writeSync(1,"out-line\\n"); fs.writeSync(2,"err-line\\n"); process.exit(3);';
    const r = await streamSpawn(process.execPath, ['-e', script], process.cwd(), process.env, onLine);
    expect(r.status).toBe(3);
    expect(lines).toContainEqual({ which: 'stdout', line: 'out-line' });
    expect(lines).toContainEqual({ which: 'stderr', line: 'err-line' });
  });

  it('does NOT hang when a detached descendant holds the inherited pipe (F6 Claim A regression)', async () => {
    const { lines, onLine } = collect();
    // Child writes a line, spawns a DETACHED grandchild that inherits
    // stdout/stderr and outlives the grace window, then exits 0.  The pipe never
    // EOFs; streamSpawn must resolve off the child's `exit` (after the bounded
    // grace), NOT hang until the descendant dies.
    const holderMs = HOST_PART2_DRAIN_GRACE_MS * 6;
    const script =
      'const cp=require("node:child_process");' +
      'const fs=require("node:fs");' +
      `const g=cp.spawn(process.execPath,["-e","setTimeout(()=>{}, ${holderMs})"],{stdio:["ignore","inherit","inherit"],detached:true});` +
      'g.unref();' +
      'fs.writeSync(1,"line-before-exit\\n");' +
      'process.exit(0);';
    const start = Date.now();
    const r = await streamSpawn(process.execPath, ['-e', script], process.cwd(), process.env, onLine);
    const elapsed = Date.now() - start;
    expect(r.status).toBe(0);
    // Resolved via the grace path — well under the descendant's lifetime.
    expect(elapsed).toBeLessThan(HOST_PART2_DRAIN_GRACE_MS + 4_000);
    expect(elapsed).toBeLessThan(holderMs);
    // The line written before the child exited was still forwarded.
    expect(lines).toContainEqual({ which: 'stdout', line: 'line-before-exit' });
  }, 20_000);

  it('resolves with an error when the binary does not exist (no hang)', async () => {
    const { onLine } = collect();
    const r = await streamSpawn('definitely-not-a-real-binary-xyz', [], process.cwd(), process.env, onLine);
    expect(r.error).toBeInstanceOf(Error);
    expect(r.status).toBeNull();
  });

  it('does NOT forward a mid-write fragment when a descendant holds the pipe past grace (F6 round-2)', async () => {
    const { lines, onLine } = collect();
    // Child writes a complete line, then spawns a DETACHED grandchild that
    // inherits stdout and writes a SECRET FRAGMENT with NO trailing newline and
    // holds the pipe open past the grace window, then the child exits 0.  The
    // fragment is an unterminated partial on a non-EOF stream — it must be DROPPED
    // (only the fixed marker emitted), never forwarded raw, or exact-value
    // redaction (which needs the WHOLE value) would miss it and leak the prefix.
    const SECRET_FRAGMENT = 'superSecretFragmentNoNewline';
    const holderMs = HOST_PART2_DRAIN_GRACE_MS * 6;
    const script =
      'const cp=require("node:child_process");' +
      'const fs=require("node:fs");' +
      `const g=cp.spawn(process.execPath,["-e","const fs=require('fs'); fs.writeSync(1,'${SECRET_FRAGMENT}'); setTimeout(()=>{}, ${holderMs});"],{stdio:["ignore","inherit","inherit"],detached:true});` +
      'g.unref();' +
      'fs.writeSync(1,"complete-line\\n");' +
      // give the grandchild a beat to write its fragment before the child exits
      'setTimeout(()=>process.exit(0), 200);';
    const start = Date.now();
    const r = await streamSpawn(process.execPath, ['-e', script], process.cwd(), process.env, onLine);
    const elapsed = Date.now() - start;
    expect(r.status).toBe(0);
    expect(elapsed).toBeLessThan(holderMs); // resolved via grace, not the holder's lifetime
    // The complete line forwarded; the raw fragment did NOT.
    expect(lines).toContainEqual({ which: 'stdout', line: 'complete-line' });
    expect(lines.some((l) => l.line.includes(SECRET_FRAGMENT))).toBe(false);
    // The grace-truncation marker stands in for the dropped fragment.
    expect(lines).toContainEqual({ which: 'stdout', line: HOST_PART2_TRUNCATED_MARKER });
  }, 20_000);
});

// ---------------------------------------------------------------------------
// SECURITY: strip INHERITED loader/config env vars + sanitize PATH
// ---------------------------------------------------------------------------
//
// The host PM child inherits the runner env; the Firecracker/Docker audit
// reconstructs its env from scratch (it never inherits the runner env).  So an
// inherited LOADER / TOOL-RESOLUTION / CONFIG-LOCATING var the host honours but
// the audit never saw is a divergence — a clean trusted lock would authorize
// unaudited host behaviour (pre-trust RCE in part-1, or host/audit config
// drift).  hostInstallEnv() must drop these and sanitize PATH so a
// checkout-controlled dir cannot shadow the bare-name PM/tool resolution.  Both
// host phases build their env via hostInstallEnv(), so both are covered.
describe('host env hardening — strip dangerous loader/config vars + sanitize PATH', () => {
  // Snapshot/restore the whole env so a test that mutates process.env can't
  // bleed into the next (the dangerous vars below would poison other suites).
  const ENV_SNAPSHOT = { ...process.env };
  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (!(k in ENV_SNAPSHOT)) delete process.env[k];
    }
    for (const [k, v] of Object.entries(ENV_SNAPSHOT)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  // Every dangerous var, including a lowercase npm_config_* spelling (npm reads
  // its config case-insensitively) and a UN-prefixed npm_config_* form.
  const DANGEROUS_PRESENT: Record<string, string> = {
    NODE_OPTIONS: '--require ./ci/evil.js',
    NODE_REPL_EXTERNAL_MODULE: './ci/evil.js',
    LD_PRELOAD: './ci/evil.so',
    LD_AUDIT: './ci/audit.so',
    LD_LIBRARY_PATH: './ci/lib',
    DYLD_INSERT_LIBRARIES: './ci/evil.dylib',
    DYLD_LIBRARY_PATH: './ci/lib',
    DYLD_FORCE_FLAT_NAMESPACE: '1',
    GIT_SSH_COMMAND: './ci/ssh',
    GIT_SSH: './ci/ssh',
    GIT_PROXY_COMMAND: './ci/proxy',
    GIT_EXTERNAL_DIFF: './ci/diff',
    NPM_CONFIG_SCRIPT_SHELL: './ci/shell',
    NPM_CONFIG_USERCONFIG: './ci/.npmrc',
    NPM_CONFIG_GLOBALCONFIG: './ci/global.npmrc',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    // case-insensitive npm_config_* matching: a lowercase spelling npm ALSO
    // honours must be stripped too.
    npm_config_script_shell: './ci/lower-shell',
    // SEPARATOR aliases ([F1], verified npm 11.13.0): npm honours the HYPHEN form
    // of every config key too, which an exact-name set misses.
    'npm_config_script-shell': './ci/hyphen-shell',
    'npm_config_ignore-scripts': 'true',
    // native-build tool selectors: npm config + bare toolchain env node-gyp reads.
    npm_config_python: './ci/py',
    'npm_config_node-gyp': './ci/gyp',
    PYTHON: './ci/python',
    CC: './ci/cc',
    CXX: './ci/cxx',
    MAKE: './ci/make',
    // git config/template injection (exec under the pinned git).
    GIT_CONFIG_GLOBAL: './ci/gitconfig',
    GIT_CONFIG_SYSTEM: './ci/gitsystem',
    GIT_CONFIG_COUNT: '1',
    GIT_TEMPLATE_DIR: './ci/template',
    // git EXEC selectors verified to run checkout code pre-trust (codex round 2).
    GIT_EXEC_PATH: './core', // VERIFIED: runs checkout core/git-remote-https
    GIT_CONFIG_PARAMETERS: "'core.sshCommand=./ci/ssh'", // VERIFIED: runs ./ci/ssh
    GIT_PAGER: './ci/pager',
    GIT_EDITOR: './ci/editor',
    GIT_ASKPASS: './ci/askpass',
    SSH_ASKPASS: './ci/askpass',
    // node-gyp native-build selectors (codex round 2, verified checkout exec).
    NODE_GYP_FORCE_PYTHON: './ci/fake-python', // node_gyp_ family prefix
    PYTHONPATH: './ci/pypath', // python family prefix (sitecustomize exec)
    PYTHONHOME: './ci/pyhome',
    npm_config_make: './ci/fake-make', // npm_config_* canonical key `make`
    npm_package_config_node_gyp_python: './ci/pkg-python', // npm_package_config_ family
    // node module-search + shell/lang startup hooks.
    NODE_PATH: './ci/nodepath',
    BASH_ENV: './ci/bashenv',
    ZDOTDIR: './ci/zdot',
    PERL5LIB: './ci/perl',
    RUBYOPT: '-r./ci/ruby',
    // GNU make startup/config selectors (codex round 3, verified make exec).
    MAKEFLAGS: '--eval=$(shell touch /tmp/evil)',
    MAKEFILES: './ci/evil.mk',
    GNUMAKEFLAGS: '--eval=$(info x)',
    // corepack executable-cache + config selectors (codex round 3): a checkout
    // COREPACK_HOME makes a pnpm/yarn corepack shim run a PR-planted PM binary.
    COREPACK_HOME: './ci/.corepack',
    COREPACK_ENV_FILE: './ci/corepack.env',
    COREPACK_NPM_REGISTRY: 'http://evil.invalid',
    COREPACK_INTEGRITY_KEYS: '{}',
    // TLS trust file (MITM the host fetch).
    NODE_EXTRA_CA_CERTS: './ci/ca.pem',
  };

  it.each(['npm', 'pnpm', 'yarn'] as const)(
    'strips EVERY dangerous loader/config var from the part-1 env (%s)',
    (pm) => {
      for (const [k, v] of Object.entries(DANGEROUS_PRESENT)) process.env[k] = v;
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      hostInstallNoScripts(pm, '/repo', [], rec.io, envCapturingSpawn(envs));
      const env = envs[0]!;
      for (const k of Object.keys(DANGEROUS_PRESENT)) {
        // npm_config_script_shell is REPLACED by the #26 safe pin for npm (the
        // inherited dangerous value is defeated by OVERRIDE, not deletion); the
        // uppercase + hyphen spellings and every other dangerous var are still
        // dropped outright.  COREPACK_ENV_FILE is likewise defeated by OVERRIDE
        // (re-pinned to '0', round-17f) — an inherited custom filename can't make
        // corepack load a repo `.corepack.env`; asserted below.
        if (k === 'npm_config_script_shell' || k === 'COREPACK_ENV_FILE') continue;
        expect(env[k]).toBeUndefined();
      }
      // round-17f: the inherited dangerous COREPACK_ENV_FILE is OVERRIDDEN to '0'
      // (process.env wins over the file → corepack never loads repo `.corepack.env`).
      expect(env['COREPACK_ENV_FILE']).toBe('0');
      if (pm === 'npm') {
        expect(env['npm_config_script_shell']).toBe(
          process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
        );
      } else {
        expect(env['npm_config_script_shell']).toBeUndefined();
      }
      // The security pins still survive the strip.
      expect(env['npm_config_git']).toBeDefined();
      if (pm === 'yarn') {
        expect(env['YARN_IGNORE_PATH']).toBe('1');
        expect(env['YARN_PLUGINS']).toBe('');
      }
    },
  );

  it.each(['npm', 'pnpm', 'yarn'] as const)(
    'strips EVERY dangerous loader/config var from the part-2 lifecycle env (%s)',
    async (pm) => {
      for (const [k, v] of Object.entries(DANGEROUS_PRESENT)) process.env[k] = v;
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      await hostRunScripts(pm, '/repo', [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
      const env = envs[0]!;
      for (const k of Object.keys(DANGEROUS_PRESENT)) {
        // See part-1: npm_config_script_shell + COREPACK_ENV_FILE are OVERRIDDEN
        // (the #26 safe pin / the round-17f '0' pin), not deleted; other spellings +
        // vars are dropped outright.
        if (k === 'npm_config_script_shell' || k === 'COREPACK_ENV_FILE') continue;
        expect(env[k]).toBeUndefined();
      }
      // round-17f: part-2 keeps COREPACK_ENV_FILE='0' in lockstep with part-1.
      expect(env['COREPACK_ENV_FILE']).toBe('0');
      if (pm === 'npm') {
        expect(env['npm_config_script_shell']).toBe(
          process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
        );
      } else {
        expect(env['npm_config_script_shell']).toBeUndefined();
      }
      // npm_config_git is fetch/part-1 only (round-15 value-blind close): part-2
      // lifecycle children must NOT see it (== guest Phase B, which never pins git).
      expect(env['npm_config_git']).toBeUndefined();
      if (pm === 'yarn') {
        expect(env['YARN_IGNORE_PATH']).toBe('1');
        expect(env['YARN_PLUGINS']).toBe('');
      }
    },
  );

  it('does NOT strip legit env: git behaviour flags, registry/auth, NODE_ENV/ENV, build vars', () => {
    // Family/enumerated stripping must not over-reach: restricting git flags, the
    // registry + auth tokens the host legitimately ADDS over the audit, NODE_ENV
    // (not a loader var), POSIX `ENV` (an env-NAME, not the sh startup hook for
    // `sh -c`), and arbitrary build vars all survive.
    const KEEP: Record<string, string> = {
      GIT_ALLOW_PROTOCOL: 'https', // restricts, never weakens
      GIT_TERMINAL_PROMPT: '0', // behaviour flag (blanket GIT_* would wrongly drop it)
      CI: 'true',
      NODE_ENV: 'production', // NOT NODE_OPTIONS/NODE_PATH — must be kept
      ENV: 'production', // not the interactive-sh startup file for `sh -c`
      NODE_AUTH_TOKEN: 'tok-keep-me',
      npm_config_registry: 'https://registry.npmjs.org/',
      'npm_config_//registry.npmjs.org/:_authToken': 'npm-auth-keep',
      HTTPS_PROXY: 'http://proxy.internal:8080',
      MY_UNRELATED_VAR: 'value-keep-me',
    };
    for (const [k, v] of Object.entries(KEEP)) process.env[k] = v;
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    const env = envs[0]!;
    for (const [k, v] of Object.entries(KEEP)) expect(env[k]).toBe(v);
  });

  it('stripDangerousEnv (shared with the bare backend agent spawn): drops selectors + sanitizes PATH, keeps SCRIPT_JAIL_/noise/legit', () => {
    // The Linux bare backend applies this to the env it spawns the audit AGENT
    // with (it inherits the runner env, unlike the clean-VM guest).  It must drop
    // the dangerous selectors + sanitize PATH, but NOT strip SCRIPT_JAIL_* / noise
    // (the agent reads some) and NOT add the npm/yarn install pins.
    const checkout = mkdtempSync(join(tmpdir(), 'sj-bare-'));
    const binDir = join(checkout, 'bin');
    mkdirSync(binDir);
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout; // makes binDir a checkout root
      const out = stripDangerousEnv({
        NODE_OPTIONS: '--require ./x',
        GIT_SSH_COMMAND: './ssh',
        GIT_EXEC_PATH: './core',
        COREPACK_HOME: './cp',
        LD_PRELOAD: './x.so',
        PYTHONPATH: './py',
        MAKEFLAGS: '--eval=$(shell x)',
        'npm_config_script-shell': './sh',
        // must be PRESERVED by stripDangerousEnv (handled elsewhere / agent needs):
        SCRIPT_JAIL_CONFIG_PATH: '/cfg.yml',
        HOSTNAME: 'runner-1',
        NODE_ENV: 'production',
        NODE_AUTH_TOKEN: 'tok',
        npm_config_registry: 'https://registry.npmjs.org/',
        PATH: `/usr/bin${delimiter}${binDir}`,
      });
      for (const k of ['NODE_OPTIONS', 'GIT_SSH_COMMAND', 'GIT_EXEC_PATH', 'COREPACK_HOME', 'LD_PRELOAD', 'PYTHONPATH', 'MAKEFLAGS', 'npm_config_script-shell']) {
        expect(out[k]).toBeUndefined();
      }
      expect(out['SCRIPT_JAIL_CONFIG_PATH']).toBe('/cfg.yml'); // NOT dropped here
      expect(out['HOSTNAME']).toBe('runner-1'); // noise handled by hostInstallEnv, not this
      expect(out['NODE_ENV']).toBe('production');
      expect(out['NODE_AUTH_TOKEN']).toBe('tok');
      expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
      expect(out['npm_config_git']).toBeUndefined(); // no install pins added
      expect(out['PATH']).toBe('/usr/bin'); // checkout binDir dropped
    } finally {
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
    }
  });

  it('stripDangerousEnv drops NPM_CONFIG_PREFIX (codex idx-21 — prefix derives globalconfig)', () => {
    // VERIFIED npm 11.13.0: npm derives `globalconfig` as `{prefix}/etc/npmrc`, so an
    // inherited NPM_CONFIG_PREFIX pointing at a checkout dir whose `etc/npmrc` declares
    // `script-shell=<pwn>` makes `npm rebuild --foreground-scripts` exec the attacker
    // shell.  `prefix` must be dropped in EVERY npm_config alias form (case + separator),
    // exactly like userconfig/globalconfig, while unrelated npm_config_* survive.
    const out = stripDangerousEnv({
      NPM_CONFIG_PREFIX: '/checkout/fakeprefix', // upper form (NPM_CONFIG_*)
      npm_config_prefix: '/checkout/fakeprefix', // lower form (npm_config_*)
      npm_config_registry: 'https://registry.npmjs.org/',
      npm_config_userconfig: '/checkout/.npmrc',
      npm_config_globalconfig: '/checkout/npmrc',
    });
    expect(out['NPM_CONFIG_PREFIX']).toBeUndefined();
    expect(out['npm_config_prefix']).toBeUndefined();
    expect(out['npm_config_userconfig']).toBeUndefined();
    expect(out['npm_config_globalconfig']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/'); // unrelated key survives
  });

  it('stripDangerousEnv drops NPM_CONFIG_NODE_OPTIONS (round-4 — node loader alias for NODE_OPTIONS)', () => {
    // VERIFIED npm 11.13.0: npm passes the `node-options` config to the node that runs
    // lifecycle scripts, so an inherited `NPM_CONFIG_NODE_OPTIONS='--require ./hook.js'`
    // preloads hook.js in the script child — smuggling the SAME loader the raw
    // NODE_OPTIONS strip blocks, just via the npm_config alias.  It must be dropped in
    // EVERY npm_config alias form (case + `-`/`_` separator), like script-shell/prefix.
    const out = stripDangerousEnv({
      NODE_OPTIONS: '--require /checkout/raw-hook.js', // raw form (already covered)
      NPM_CONFIG_NODE_OPTIONS: '--require /checkout/hook.js', // upper form (NPM_CONFIG_*)
      npm_config_node_options: '--require /checkout/hook.js', // lower underscore form
      'npm_config_node-options': '--require /checkout/hook.js', // lower hyphen form
      npm_config_registry: 'https://registry.npmjs.org/',
    });
    expect(out['NODE_OPTIONS']).toBeUndefined();
    expect(out['NPM_CONFIG_NODE_OPTIONS']).toBeUndefined();
    expect(out['npm_config_node_options']).toBeUndefined();
    expect(out['npm_config_node-options']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/'); // unrelated key survives
  });

  it('stripDangerousEnv drops plain PREFIX/DESTDIR (round-5 — npm globalPrefix→npmrc redirect, no npm_config_)', () => {
    // VERIFIED npm 11.13.0 (@npmcli/config loadGlobalPrefix): npm derives globalConfig =
    // `{globalPrefix}/etc/npmrc` and reads PLAIN `PREFIX`/`DESTDIR` (NOT npm_config_*) to
    // set globalPrefix.  `PREFIX=<dir>` + `<dir>/etc/npmrc` with `script-shell=<pwn>` (and
    // `DESTDIR=<dir>` via `<dir>{nodePrefix}/etc/npmrc`) makes `npm rebuild
    // --foreground-scripts` exec the attacker shell — the same redirect-then-exec class as
    // the denied npm_config_prefix, but it bypasses the npm_config_* canon because these
    // are bare env names.  Both must be dropped; unrelated plain env survives.
    const out = stripDangerousEnv({
      PREFIX: '/checkout/evil-prefix', // → {PREFIX}/etc/npmrc
      DESTDIR: '/checkout', // → {DESTDIR}{nodePrefix}/etc/npmrc
      npm_config_prefix: '/checkout/evil-prefix', // the npm_config alias (already covered)
      npm_config_registry: 'https://registry.npmjs.org/',
      CI: 'true', // unrelated benign plain env survives
    });
    expect(out['PREFIX']).toBeUndefined();
    expect(out['DESTDIR']).toBeUndefined();
    expect(out['npm_config_prefix']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
    expect(out['CI']).toBe('true');
  });

  it('stripDangerousEnv drops LOCALAPPDATA (round-17e — corepack win32 cache selector, COREPACK_HOME class)', () => {
    // codex round-17e [high]: LOCALAPPDATA is corepack's win32-ONLY executable-cache-root
    // selector (= the COREPACK_HOME class).  The action runs only on Linux/macOS runners
    // (never win32), where no PM reads it, so dropping it is inert on every real host AND
    // closes (a) a planted-cache redirect of corepackCacheRoot and (b) the value-blind
    // env_read parity (the clean-VM/guest audit never carries LOCALAPPDATA).
    const out = stripDangerousEnv({
      LOCALAPPDATA: '/checkout/evil-cache', // → would steer corepackCacheRoot to a planted v1/<pm>/…
      COREPACK_HOME: '/checkout/evil-cache', // its already-dropped sibling (corepack_ family)
      npm_config_registry: 'https://registry.npmjs.org/',
      CI: 'true', // unrelated benign plain env survives
    });
    expect(out['LOCALAPPDATA']).toBeUndefined();
    expect(out['COREPACK_HOME']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
    expect(out['CI']).toBe('true');
  });

  it('stripDangerousEnv drops dangerous pnpm_config_* (own namespace — round-9, allowlist)', () => {
    // VERIFIED pnpm 11.1.2: pnpm reads `scriptShell` from its OWN `pnpm_config_*` env
    // namespace (NOT npm_config_*), so `PNPM_CONFIG_SCRIPT_SHELL` / `pnpm_config_script_shell`
    // set the lifecycle-script interpreter and EXEC on `pnpm install`/`pnpm rebuild`
    // (PWNED_PNPM_CFG_SHELL_RAN).  pnpm_config_* is now an ALLOWLIST (registry/auth/TLS/
    // proxy only — see PM_CONFIG_AUTH_SCALARS), so EVERY exec/interpreter/hook key is
    // dropped (script_shell, shell_emulator, scripts_prepend_node_path, pnpmfile/
    // global_pnpmfile) while registry + per-registry auth survive.
    const out = stripDangerousEnv({
      PNPM_CONFIG_SCRIPT_SHELL: '/checkout/evil-sh', // upper form
      pnpm_config_script_shell: '/checkout/evil-sh', // lower snake form
      'pnpm_config_script-shell': '/checkout/evil-sh', // lower hyphen form (canonicalized)
      pnpm_config_global_pnpmfile: '/checkout/evil.cjs', // pnpm hook file
      PNPM_CONFIG_SHELL_EMULATOR: 'true', // interpreter switch (sh → JS emulator) — VERIFIED diverges
      pnpm_config_shell_emulator: 'true',
      pnpm_config_scripts_prepend_node_path: 'true', // round-11 PATH-node selector — dropped by allowlist
      pnpm_config_registry: 'https://registry.npmjs.org/', // auth/registry — preserved
      'pnpm_config_//registry.npmjs.org/:_authToken': 'tok', // auth — preserved
    });
    expect(out['PNPM_CONFIG_SCRIPT_SHELL']).toBeUndefined();
    expect(out['pnpm_config_script_shell']).toBeUndefined();
    expect(out['pnpm_config_script-shell']).toBeUndefined();
    expect(out['pnpm_config_global_pnpmfile']).toBeUndefined();
    expect(out['PNPM_CONFIG_SHELL_EMULATOR']).toBeUndefined();
    expect(out['pnpm_config_shell_emulator']).toBeUndefined();
    expect(out['pnpm_config_scripts_prepend_node_path']).toBeUndefined();
    expect(out['pnpm_config_registry']).toBe('https://registry.npmjs.org/');
    expect(out['pnpm_config_//registry.npmjs.org/:_authToken']).toBe('tok');
  });

  it('stripDangerousEnv drops npm_config_/pnpm_config_ scripts_prepend_node_path (round-11 — pnpm honors npm_config_ form)', () => {
    // VERIFIED pnpm 10.34.3/11.1.2: pnpm prepends the running-node dir to the
    // lifecycle-script PATH when `scripts-prepend-node-path` is set, changing which
    // bare-name `node` a script resolves — and it honors the `npm_config_` env FORM at
    // install time (the `pnpm_config_`/`PNPM_CONFIG_` form is NOT read on install), so
    // the WORKING attack var is `npm_config_scripts_prepend_node_path`.  npm 11 IGNORES
    // the key ("Unknown env config"), so dropping it is a no-op on npm and closes the
    // live pnpm vector.  The allowlist drops it in EVERY case/separator form.
    const out = stripDangerousEnv({
      npm_config_scripts_prepend_node_path: 'true', // the form pnpm actually honors
      'npm_config_scripts-prepend-node-path': 'true', // hyphen alias
      NPM_CONFIG_SCRIPTS_PREPEND_NODE_PATH: 'true', // upper form
      npm_config_registry: 'https://registry.npmjs.org/', // auth — preserved
    });
    expect(out['npm_config_scripts_prepend_node_path']).toBeUndefined();
    expect(out['npm_config_scripts-prepend-node-path']).toBeUndefined();
    expect(out['NPM_CONFIG_SCRIPTS_PREPEND_NODE_PATH']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
  });

  it('stripDangerousEnv preserves pnpm proxy spellings http_proxy/no_proxy (round-12 — pnpm canonical http-proxy/no-proxy)', () => {
    // VERIFIED pnpm 11.1.2 reads `pnpm_config_http_proxy` -> `http-proxy` / `pnpm_config_no_proxy`
    // -> `no-proxy` (its canonical proxy keys, DISTINCT from npm's proxy/noproxy); pnpm 10.34.3
    // reads the SAME via the `npm_config_` form.  Dropping them broke a pnpm install behind an
    // HTTP-only proxy / needing a no-proxy bypass.  Both are pure network config (no exec), so
    // the allowlist keeps them in BOTH namespaces + case forms; npm ignores them (harmless).
    const out = stripDangerousEnv({
      pnpm_config_http_proxy: 'http://proxy.local:8080/', // pnpm 11 form
      PNPM_CONFIG_HTTP_PROXY: 'http://proxy.local:8080/',
      pnpm_config_no_proxy: 'localhost,.internal',
      PNPM_CONFIG_NO_PROXY: 'localhost,.internal',
      npm_config_http_proxy: 'http://proxy.local:8080/', // pnpm 10 form (via npm_config_)
      npm_config_no_proxy: 'localhost,.internal',
      'npm_config_http-proxy': 'http://proxy.local:8080/', // hyphen alias
      'pnpm_config_no-proxy': 'localhost,.internal',
      pnpm_config_script_shell: '/checkout/evil', // still dropped (not auth) — control
    });
    expect(out['pnpm_config_http_proxy']).toBe('http://proxy.local:8080/');
    expect(out['PNPM_CONFIG_HTTP_PROXY']).toBe('http://proxy.local:8080/');
    expect(out['pnpm_config_no_proxy']).toBe('localhost,.internal');
    expect(out['PNPM_CONFIG_NO_PROXY']).toBe('localhost,.internal');
    expect(out['npm_config_http_proxy']).toBe('http://proxy.local:8080/');
    expect(out['npm_config_no_proxy']).toBe('localhost,.internal');
    expect(out['npm_config_http-proxy']).toBe('http://proxy.local:8080/');
    expect(out['pnpm_config_no-proxy']).toBe('localhost,.internal');
    expect(out['pnpm_config_script_shell']).toBeUndefined(); // control: exec key still dropped
  });

  it('stripDangerousEnv preserves npm/pnpm network binding + fetch tuning (round-13 — local_address, maxsockets, fetch-*)', () => {
    // VERIFIED npm 11.13.0 + pnpm 11.1.2/10.34.3: these are pure network DATA (a
    // validated IP, ints) needed by multi-homed / internal / slow registries to REACH
    // the registry; the clean-VM audit inherits none, so the host must be able to set
    // them.  None selects an exec/loader/config-FILE.  network_concurrency is pnpm-only
    // (npm ignores it as Unknown env config — harmless to keep).
    const out = stripDangerousEnv({
      npm_config_local_address: '10.0.0.5',
      'npm_config_local-address': '10.0.0.5', // hyphen alias
      pnpm_config_local_address: '10.0.0.5',
      npm_config_maxsockets: '4',
      npm_config_fetch_timeout: '60000',
      npm_config_fetch_retries: '5',
      'npm_config_fetch-retry-factor': '2',
      npm_config_fetch_retry_mintimeout: '1000',
      npm_config_fetch_retry_maxtimeout: '60000',
      pnpm_config_network_concurrency: '8', // pnpm-only
      npm_config_cache: '/checkout/.npm', // control: path redirect still dropped
    });
    expect(out['npm_config_local_address']).toBe('10.0.0.5');
    expect(out['npm_config_local-address']).toBe('10.0.0.5');
    expect(out['pnpm_config_local_address']).toBe('10.0.0.5');
    expect(out['npm_config_maxsockets']).toBe('4');
    expect(out['npm_config_fetch_timeout']).toBe('60000');
    expect(out['npm_config_fetch_retries']).toBe('5');
    expect(out['npm_config_fetch-retry-factor']).toBe('2');
    expect(out['npm_config_fetch_retry_mintimeout']).toBe('1000');
    expect(out['npm_config_fetch_retry_maxtimeout']).toBe('60000');
    expect(out['pnpm_config_network_concurrency']).toBe('8');
    expect(out['npm_config_cache']).toBeUndefined(); // control: non-network key still dropped
  });

  it('stripDangerousEnv npm_config_/pnpm_config_ is an ALLOWLIST: benign non-auth keys dropped, full auth surface preserved', () => {
    // The decisive posture shift (round-11): the config-via-env key space is an open,
    // per-release-growing set of exec/interpreter/loader/config-FILE selectors that a
    // denylist could not bound (a new one surfaced each round).  We now KEEP only the
    // small, stable registry/auth/TLS/proxy surface and DROP everything else — even a
    // benign-looking config key (loglevel/cache/fund/…), because the clean-VM audit
    // inherited NONE of them, so the host must run with PM defaults for parity.
    const out = stripDangerousEnv({
      // benign-but-non-auth npm config keys — DROPPED (would have survived the old denylist):
      npm_config_loglevel: 'silly',
      npm_config_cache: '/checkout/.npm-cache', // path redirect — definitely drop
      npm_config_fund: 'false',
      npm_config_audit: 'false',
      'npm_config_save-exact': 'true',
      // full auth/registry/TLS/proxy surface — PRESERVED:
      npm_config_registry: 'https://registry.npmjs.org/',
      npm_config_email: 'me@example.com',
      npm_config__auth: 'YmFzZTY0', // legacy base64 basic auth
      npm_config_ca: '-----BEGIN CERTIFICATE-----',
      npm_config_cafile: '/etc/ssl/ca.pem',
      npm_config_cert: '-----BEGIN CERTIFICATE-----',
      npm_config_certfile: '/etc/ssl/client-cert.pem',
      npm_config_key: '-----BEGIN PRIVATE KEY-----',
      npm_config_keyfile: '/etc/ssl/client-key.pem',
      'npm_config_strict-ssl': 'true', // hyphen alias of strict_ssl
      npm_config_proxy: 'http://proxy.local:8080/',
      'npm_config_https-proxy': 'http://proxy.local:8080/',
      npm_config_noproxy: 'localhost,.internal',
      // dynamic auth forms — PRESERVED VERBATIM (no -→_ canon):
      'npm_config_//registry.npmjs.org/:_authToken': 'tok',
      'npm_config_//npm.pkg.github.com/:_password': 'pw',
      'npm_config_//registry.example.com/:certfile': '/etc/ssl/c.pem',
      'npm_config_@my-org:registry': 'https://npm.my-org.dev/', // hyphen in scope — must NOT canon to @my_org
    });
    // dropped (allowlist excludes non-auth):
    for (const k of [
      'npm_config_loglevel', 'npm_config_cache', 'npm_config_fund',
      'npm_config_audit', 'npm_config_save-exact',
    ]) {
      expect(out[k]).toBeUndefined();
    }
    // preserved scalars (incl. hyphen aliases):
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
    expect(out['npm_config_email']).toBe('me@example.com');
    expect(out['npm_config__auth']).toBe('YmFzZTY0');
    expect(out['npm_config_ca']).toBe('-----BEGIN CERTIFICATE-----');
    expect(out['npm_config_cafile']).toBe('/etc/ssl/ca.pem');
    expect(out['npm_config_cert']).toBe('-----BEGIN CERTIFICATE-----');
    expect(out['npm_config_certfile']).toBe('/etc/ssl/client-cert.pem');
    expect(out['npm_config_key']).toBe('-----BEGIN PRIVATE KEY-----');
    expect(out['npm_config_keyfile']).toBe('/etc/ssl/client-key.pem');
    expect(out['npm_config_strict-ssl']).toBe('true');
    expect(out['npm_config_proxy']).toBe('http://proxy.local:8080/');
    expect(out['npm_config_https-proxy']).toBe('http://proxy.local:8080/');
    expect(out['npm_config_noproxy']).toBe('localhost,.internal');
    // preserved dynamic forms (verbatim — hyphen in scope intact):
    expect(out['npm_config_//registry.npmjs.org/:_authToken']).toBe('tok');
    expect(out['npm_config_//npm.pkg.github.com/:_password']).toBe('pw');
    expect(out['npm_config_//registry.example.com/:certfile']).toBe('/etc/ssl/c.pem');
    expect(out['npm_config_@my-org:registry']).toBe('https://npm.my-org.dev/');
  });

  it('stripDangerousEnv preserves npm replace_registry_host (round-14 — mirror host rewrite, pure routing)', () => {
    // VERIFIED npm 11.13.0 honors both separators (no Unknown-env warning); pure registry
    // routing (rewrites tarball host/port/protocol/path, integrity hash still pins bytes),
    // needed for a mirror where the lockfile pins non-default public hosts.
    const out = stripDangerousEnv({
      npm_config_replace_registry_host: 'always',
      'npm_config_replace-registry-host': 'always', // hyphen alias
      pnpm_config_replace_registry_host: 'always', // pnpm: no consumer, harmless keep
      npm_config_cache: '/checkout/.npm', // control: still dropped
    });
    expect(out['npm_config_replace_registry_host']).toBe('always');
    expect(out['npm_config_replace-registry-host']).toBe('always');
    expect(out['pnpm_config_replace_registry_host']).toBe('always');
    expect(out['npm_config_cache']).toBeUndefined();
  });

  it('stripDangerousEnv (shared, no pm) applies the YARN_* + COREPACK_* policy — bare-agent==host parity (round-14 [high])', () => {
    // The bare/mac-bare AUDIT agents spawn via stripDangerousEnv (NOT hostInstallEnv), so
    // the YARN_* allowlist + COREPACK_* family drop MUST live in the shared sanitizer or
    // the audit honors PR-controlled exec/version selectors the host install strips.
    // VERIFIED: stripDangerousEnv now drops non-allowlisted YARN_* (incl. YARN_YARN_PATH
    // re-exec selector) + EVERY COREPACK_* (incl. the version-steering flags), while
    // keeping the yarn auth/routing/TLS allowlist.
    const out = stripDangerousEnv({
      // dangerous YARN_* — dropped by the shared sanitizer (no pm gate):
      YARN_YARN_PATH: '/checkout/evil.cjs', // re-exec selector
      YARN_PLUGINS: '/checkout/p.cjs',
      YARN_RC_FILENAME: '/checkout/.yarnrc.yml',
      YARN_INJECT_ENVIRONMENT_FILES: '.env.evil',
      YARN_NETWORK_SETTINGS: '{}',
      yarn_yarn_path: '/checkout/evil.cjs', // lowercase form also dropped
      // COREPACK_* — entire family dropped (exec selectors + version steering):
      COREPACK_HOME: '/checkout/.corepack',
      COREPACK_ENABLE_PROJECT_SPEC: '0', // version-steering flag (was NOT dropped before)
      COREPACK_DEFAULT_TO_LATEST: '1',
      COREPACK_ENABLE_STRICT: '0',
      COREPACK_ENABLE_DOWNLOAD_PROMPT: '1', // dropped here; callers re-pin =0 after
      // allowlisted yarn keys — survive:
      YARN_NPM_AUTH_TOKEN: 'tok',
      YARN_HTTP_PROXY: 'http://proxy.local:8080/',
      YARN_HTTPS_CA_FILE_PATH: '/etc/ssl/ca.pem',
    });
    for (const k of [
      'YARN_YARN_PATH', 'YARN_PLUGINS', 'YARN_RC_FILENAME', 'YARN_INJECT_ENVIRONMENT_FILES',
      'YARN_NETWORK_SETTINGS', 'yarn_yarn_path',
      'COREPACK_HOME', 'COREPACK_ENABLE_PROJECT_SPEC', 'COREPACK_DEFAULT_TO_LATEST',
      'COREPACK_ENABLE_STRICT', 'COREPACK_ENABLE_DOWNLOAD_PROMPT',
    ]) {
      expect(out[k]).toBeUndefined();
    }
    expect(out['YARN_NPM_AUTH_TOKEN']).toBe('tok');
    expect(out['YARN_HTTP_PROXY']).toBe('http://proxy.local:8080/');
    expect(out['YARN_HTTPS_CA_FILE_PATH']).toBe('/etc/ssl/ca.pem');
  });

  it('stripDangerousEnv drops the XDG_* family + PNPM_HOME (pnpm config→scriptShell, round-8)', () => {
    // VERIFIED pnpm 11.1.2: pnpm reads its GLOBAL config from `$XDG_CONFIG_HOME/pnpm/
    // config.yaml`, so an inherited `XDG_CONFIG_HOME=<checkout>/.config` lets a PR commit
    // `.config/pnpm/config.yaml` `scriptShell:` that the host `pnpm rebuild --pending` execs
    // — unseen by the clean-VM audit (which inherits no XDG_*).  The whole XDG family is
    // dropped for parity (npm/yarn don't read XDG; pnpm falls back to the HOME-based default
    // the HOME gate keeps outside the checkout).  PNPM_HOME (pnpm's global bin/exec dir) is
    // dropped too — the audit inherits none.  Unrelated env survives.
    const out = stripDangerousEnv({
      XDG_CONFIG_HOME: '/checkout/.config', // pnpm global config → scriptShell exec
      XDG_DATA_HOME: '/checkout/.local/share', // store/data (family parity)
      XDG_CACHE_HOME: '/checkout/.cache',
      XDG_STATE_HOME: '/checkout/.local/state',
      PNPM_HOME: '/checkout/.pnpm-home',
      npm_config_registry: 'https://registry.npmjs.org/',
      CI: 'true',
    });
    expect(out['XDG_CONFIG_HOME']).toBeUndefined();
    expect(out['XDG_DATA_HOME']).toBeUndefined();
    expect(out['XDG_CACHE_HOME']).toBeUndefined();
    expect(out['XDG_STATE_HOME']).toBeUndefined();
    expect(out['PNPM_HOME']).toBeUndefined();
    expect(out['npm_config_registry']).toBe('https://registry.npmjs.org/');
    expect(out['CI']).toBe('true');
  });

  it('pins COREPACK_ENABLE_DOWNLOAD_PROMPT=0 (overriding inherited), so stripping COREPACK_HOME cannot hang', () => {
    // We strip an inherited COREPACK_HOME (executable-cache attack); to ensure a
    // resulting cache re-download cannot block on a prompt, the prompt flag is
    // force-pinned off — overriding whatever the runner inherited.
    process.env['COREPACK_HOME'] = './ci/.corepack';
    process.env['COREPACK_ENABLE_DOWNLOAD_PROMPT'] = '1'; // inherited "on"
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('pnpm', '/repo', [], rec.io, envCapturingSpawn(envs));
    const env = envs[0]!;
    expect(env['COREPACK_HOME']).toBeUndefined();
    expect(env['COREPACK_ENABLE_DOWNLOAD_PROMPT']).toBe('0');
  });

  it('the git BINARY stays pinned (npm_config_git) even when GIT_SSH_COMMAND is stripped', () => {
    // The transport-command override is removed, but the pinned git binary —
    // set AFTER the strip loop — must remain (a value that OVERRIDES the repo
    // .npmrc git= entry).
    process.env['GIT_SSH_COMMAND'] = './ci/ssh';
    const rec = makeRecorder();
    const envs: Array<NodeJS.ProcessEnv> = [];
    hostInstallNoScripts('npm', '/repo', [], rec.io, envCapturingSpawn(envs));
    const env = envs[0]!;
    expect(env['GIT_SSH_COMMAND']).toBeUndefined();
    const git = env['npm_config_git'];
    expect(git).toBeDefined();
    expect(git === 'git' || isAbsolute(git!)).toBe(true);
  });

  it('SANITIZES PATH: drops a checkout-under entry, keeps a system entry IN ORDER', () => {
    // [5]+[9]: the workflow prepends a checkout dir to PATH and the PR commits
    // bin/<tool> there; that PR-controlled dir must be dropped from the child
    // PATH while the inherited system dirs survive — in their original order.
    const checkout = mkdtempSync(join(tmpdir(), 'sj-path-'));
    const binDir = join(checkout, 'bin');
    mkdirSync(binDir);
    const sysA = '/usr/bin';
    const sysB = '/bin';
    const origPath = process.env['PATH'];
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      // checkout bin FIRST, then two system dirs (preserve relative order),
      // plus an empty segment (== cwd) which must also be dropped.
      process.env['PATH'] = `${binDir}${delimiter}${sysA}${delimiter}${sysB}${delimiter}`;
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      hostInstallNoScripts('npm', checkout, [], rec.io, envCapturingSpawn(envs));
      const resultPath = envs[0]!['PATH'];
      expect(resultPath).toBeDefined();
      const parts = resultPath!.split(delimiter);
      // checkout dir dropped, empty segment dropped, system dirs survive in order.
      expect(parts).toEqual([sysA, sysB]);
      expect(parts.some((p) => p.startsWith(checkout))).toBe(false);
      // PATH is NOT emptied — system entries remain.
      expect(parts.length).toBeGreaterThan(0);
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
    }
  });

  it('SANITIZES PATH: drops EVERY non-absolute entry (cwd != repoDir oracle, [F2])', () => {
    // A relative PATH entry is resolved by exec lookup against the CHILD cwd
    // (=repoDir), not the action's process.cwd().  A `../evil` can look OUTSIDE
    // the checkout at sanitize time yet resolve INTO repoDir at exec when they
    // differ (e.g. SCRIPT_JAIL_REPO_DIR subdir).  We drop ALL non-absolute
    // entries, so neither `../evil` nor a bare relative dir survives.
    const sysA = '/usr/bin';
    const origPath = process.env['PATH'];
    try {
      // repoDir (3rd arg) is a subdir; the relative entries are the attack.
      process.env['PATH'] = `../evil${delimiter}relbin${delimiter}.${delimiter}${sysA}`;
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      hostInstallNoScripts('npm', '/repo/packages/app', [], rec.io, envCapturingSpawn(envs));
      const parts = envs[0]!['PATH']!.split(delimiter);
      // Only the absolute system dir survives; every relative entry is dropped.
      expect(parts).toEqual([sysA]);
      expect(parts.some((p) => !isAbsolute(p))).toBe(false);
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
    }
  });

  it('NEVER yields an empty PATH when every segment is dropped ([F3] cwd-search defense)', () => {
    // An empty PATH ("") is a SINGLE zero-length entry → execvp/spawnSync resolve
    // it against the CWD, so a bare-name host exec would run a PR-committed
    // `./tool` from the checkout.  If EVERY inherited segment is checkout-relative
    // (or non-absolute), the sanitized PATH must fall back to a trusted system
    // PATH, never "".
    const checkout = mkdtempSync(join(tmpdir(), 'sj-allpath-'));
    const binA = join(checkout, 'bin');
    const binB = join(checkout, 'tools');
    mkdirSync(binA);
    mkdirSync(binB);
    const origWs = process.env['GITHUB_WORKSPACE'];
    try {
      process.env['GITHUB_WORKSPACE'] = checkout;
      // every entry is either checkout-under or non-absolute (relative / empty)
      const allDropped = `${binA}${delimiter}${binB}${delimiter}./node_modules/.bin${delimiter}`;
      expect(sanitizePathValue(allDropped)).toBe(SAFE_SYSTEM_PATH);
      const out = stripDangerousEnv({ PATH: allDropped, NODE_OPTIONS: './x' });
      expect(out['PATH']).toBe(SAFE_SYSTEM_PATH);
      expect(out['PATH']).not.toBe('');
      // an already-empty inherited PATH also never passes '' through
      expect(sanitizePathValue('')).toBe(SAFE_SYSTEM_PATH);
      // a genuinely-absent PATH stays unset (caller deletes it → execvp's own
      // system default, which does NOT search the cwd) — not synthesized.
      expect(sanitizePathValue(undefined)).toBeUndefined();
    } finally {
      if (origWs === undefined) delete process.env['GITHUB_WORKSPACE'];
      else process.env['GITHUB_WORKSPACE'] = origWs;
      rmSync(checkout, { recursive: true, force: true });
    }
  });

  it('SANITIZES PATH via SCRIPT_JAIL_REPO_DIR checkout root too (part-2 lifecycle env)', async () => {
    // checkoutRoots() also honours $SCRIPT_JAIL_REPO_DIR (a repo root that can be
    // a subdir of the checkout).  A PATH entry under it must drop in part-2 too.
    const repoDir = mkdtempSync(join(tmpdir(), 'sj-repo-'));
    const binDir = join(repoDir, 'tools');
    mkdirSync(binDir);
    const origPath = process.env['PATH'];
    const origRepo = process.env['SCRIPT_JAIL_REPO_DIR'];
    try {
      process.env['SCRIPT_JAIL_REPO_DIR'] = repoDir;
      process.env['PATH'] = `${binDir}${delimiter}/usr/bin`;
      const rec = makeRecorder();
      const envs: Array<NodeJS.ProcessEnv> = [];
      await hostRunScripts('npm', repoDir, [], rec.io, [], envCapturingStreamSpawn(envs), bareLaunchResolver);
      const parts = envs[0]!['PATH']!.split(delimiter);
      expect(parts.some((p) => p.startsWith(repoDir))).toBe(false);
      expect(parts).toContain('/usr/bin');
    } finally {
      if (origPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = origPath;
      if (origRepo === undefined) delete process.env['SCRIPT_JAIL_REPO_DIR'];
      else process.env['SCRIPT_JAIL_REPO_DIR'] = origRepo;
      rmSync(repoDir, { recursive: true, force: true });
    }
  });
});

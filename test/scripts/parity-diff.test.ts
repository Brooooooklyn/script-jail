// script-jail — test/scripts/parity-diff.test.ts
//
// These tests drive the workflow script through oxnode so they exercise the
// same parser, canonicalizer, and exit-code contract as parity-test.yml.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

// Every test here spawns `oxnode scripts/parity-diff.ts` as a child process; the
// first spawn in a fresh vitest worker pays a one-time oxnode/swc init cost that
// can exceed the 5s default.  The work itself is ~150ms (verified), so raise the
// per-test ceiling rather than mask a real hang.
vi.setConfig({ testTimeout: 20_000, hookTimeout: 20_000 });

const repoRoot = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const SCRIPT = join(repoRoot, 'scripts/parity-diff.ts');
const OXNODE = join(repoRoot, 'node_modules/.bin/oxnode');

const tempDirs: string[] = [];

afterAll(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function makeWorkspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'script-jail-parity-diff-'));
  tempDirs.push(dir);
  return dir;
}

function runParityDiff(
  left: string,
  right: string,
  extraArgs: ReadonlyArray<string> = [],
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    OXNODE,
    [
      SCRIPT,
      '--left', left,
      '--right', right,
      '--left-label', 'linux-backend',
      '--right-label', 'macos-arm64-vz',
      ...extraArgs,
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 10_000,
    },
  );

  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

const COMMON_LOCK_PREFIX = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "canonicalized-away"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
`;

// A header + two non-divergent package blocks, each carrying the waived spawn
// that belongs to it.  The git-config probe is reconciled ONLY under
// simple-git-hooks and the native self-verify ONLY under esbuild — package
// scoping (finding #3), so each waived spawn must sit under its real package.
const PARITY_HEADER = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "x"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
`;

describe('scripts/parity-diff.ts', () => {
  it('filters known backend read/env/network noise and package-scoped benign spawns', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    // Linux: ambient env/read/network noise + the strace-visible git-config form.
    const leftEsbuild = `  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads:
          - $HOME/.cache/puppeteer
        escaped_writes: []
        env_read:
          - HOSTNAME
          - PATH
          - SCRIPT_JAIL_CONFIG_PATH
          - SCRIPT_JAIL_CONNECTION
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts:
          - <BLOCKED> connect 168.63.129.16:53
`;
    const leftSgh = `  simple-git-hooks@2.13.1:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - sh -c git config --local core.hooksPath
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    // macOS-bare: different ambient env, the esbuild native self-verify, and the
    // SIP `<AUDIT_BLIND>` framing of the SAME git-config action.
    const rightEsbuild = `  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read:
          - PATH
          - POSIXLY_CORRECT
          - TERM
        spawn_attempts:
          - $PKG/bin/esbuild --version
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    const rightSgh = `  simple-git-hooks@2.13.1:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - <AUDIT_BLIND> git config --local core.hooksPath
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;

    writeFileSync(left, PARITY_HEADER + leftEsbuild + leftSgh, 'utf8');
    writeFileSync(right, PARITY_HEADER + rightEsbuild + rightSgh, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('keeps arbitrary spawn divergence visible', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
        spawn_attempts:
          - $PKG/bin/other --version
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$PKG/bin/other --version');
    expect(result.stderr).toBe('');
  });

  it('keeps writes to read-filtered paths visible', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX.replace(
        'escaped_writes: []',
        'escaped_writes:\n          - $HOME/.cache/puppeteer',
      )}        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$HOME/.cache/puppeteer');
    expect(result.stderr).toBe('');
  });

  it('collapses lists that become empty after parity-only filtering', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    writeFileSync(
      left,
      `${COMMON_LOCK_PREFIX}        env_read: []
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );
    writeFileSync(
      right,
      `${COMMON_LOCK_PREFIX}        env_read:
          - POSIXLY_CORRECT
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`,
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('strips intrinsically divergent packages (quoted + unquoted keys) from both sides', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    // `@swc/core` (quoted key) and `unrs-resolver` (unquoted key) are both in
    // PARITY_DIVERGENT_PACKAGES, so `stripDivergentPackages` drops their blocks
    // from BOTH locks before comparison — even though their contents differ
    // wildly per platform.  esbuild sits between them and is platform-invariant,
    // so it stays under strict byte comparison.  This exercises the hand-written
    // `parsePackageKeyAtIndent2` against both the quoted and unquoted key forms.
    const header = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "x"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
`;
    const esbuildBlock = `  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    // Linux: native binding loads → real shell-outs + ldd probe.
    const leftSwc = `  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads:
          - /usr/bin/ldd
        escaped_writes: []
        env_read:
          - SWC_DEBUG
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    const leftUnrs = `  unrs-resolver@1.11.1:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - dirname $PKG/node_modules/.bin/napi-postinstall
          - uname
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    // macOS-bare: wasm fallback npm spawn / napi-postinstall short-circuits.
    // The spawn must be the EXACT allowlisted form — the danger check
    // (collectDivergentDangers) flags any unapproved spawn inside @swc, so a
    // truncated `npm install @swc/wasm` would (correctly) fail the gate.
    const rightSwc = `  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - npm install --no-save --loglevel=error --prefer-offline --no-audit --progress=false @swc/wasm@1.15.33
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    const rightUnrs = `  unrs-resolver@1.11.1:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;

    writeFileSync(left, header + leftSwc + esbuildBlock + leftUnrs, 'utf8');
    writeFileSync(right, header + rightSwc + esbuildBlock + rightUnrs, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('still surfaces a real divergence inside a NON-divergent package adjacent to stripped ones', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');

    // Guard: stripping must be NARROW.  @swc is dropped, but a genuine esbuild
    // spawn divergence right after it must still fail the gate.
    const header = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "x"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
`;
    const swc = `  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    const esbuild = (spawn: string) => `  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - ${spawn}
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;

    writeFileSync(left, header + swc + esbuild('node install.js'), 'utf8');
    writeFileSync(right, header + swc + esbuild('node EVIL.js'), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('node EVIL.js');
    expect(result.stderr).toBe('');
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Adversarial coverage.  The divergent-package blocks (@swc/core, puppeteer,
// unrs-resolver) are excluded from the byte comparison, and several env / read /
// network / spawn entries are reconciled as host noise.  These suites prove the
// exclusion + the filters can NEVER launder a real one-sided escape into a clean
// (exit 0) result — every dangerous signal still FAILS the gate.
// ───────────────────────────────────────────────────────────────────────────

const LOCK_HEADER = `schema_version: 1
manager: pnpm
manager_lockfile_sha256: "x"
node_version: 24.15.0
generated_at: 2026-05-28T00:00:00.000Z
packages:
`;

// A platform-invariant package, byte-identical on both sides.  It survives the
// divergent-package strip and anchors the byte comparison, so a danger test
// fails on the danger FINDING, not on an "empty lock" coincidence.
const INVARIANT_ESBUILD = `  esbuild@0.28.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read:
          - PATH
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;

const POSTINSTALL_FIELD_ORDER = [
  'external_reads',
  'escaped_writes',
  'env_read',
  'spawn_attempts',
  'spawn_blocked',
  'dlopen_attempts',
  'network_attempts',
  'audit_bypass',
  'env_tamper',
] as const;

// Render a postinstall fields block (8-space indent) from per-field item lists.
// Defaults model a clean install; `overrides` inject the field under test.
// Fields absent from BOTH defaults and overrides are omitted (parsed as []).
function postinstallFields(overrides: Record<string, string[]>): string {
  const defaults: Record<string, string[]> = {
    external_reads: [],
    escaped_writes: [],
    env_read: [],
    spawn_attempts: ['node postinstall.js'],
    spawn_blocked: [],
    dlopen_attempts: [],
    network_attempts: [],
  };
  const merged: Record<string, string[]> = { ...defaults, ...overrides };
  const lines: string[] = [];
  for (const field of POSTINSTALL_FIELD_ORDER) {
    const items = merged[field];
    if (items === undefined) continue;
    if (items.length === 0) {
      lines.push(`        ${field}: []`);
    } else {
      lines.push(`        ${field}:`);
      for (const item of items) lines.push(`          - ${item}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

// A full lock: invariant esbuild + one @swc/core (divergent) block carrying the
// given postinstall fields.  @swc is quoted because its key starts with `@`.
function swcDivergentLock(fields: string): string {
  return `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
${fields}`;
}

// A full lock with a single NON-divergent package block (used for the finding
// #2/#3/#4 filter regressions, where the block DOES enter byte comparison).
function singlePackageLock(pkgKey: string, fields: string): string {
  return `${LOCK_HEADER}  ${pkgKey}:
    lifecycle:
      postinstall:
${fields}`;
}

describe('scripts/parity-diff.ts — divergent-package danger check (adversarial review finding #1)', () => {
  // The benign @swc block (clean install).  Used as the LEFT side so each test
  // is a realistic ONE-SIDED escape that appears only on the macOS backend and
  // would be laundered by a blind whole-block strip.
  const benign = swcDivergentLock(postinstallFields({}));

  const cases: ReadonlyArray<{ name: string; fields: Record<string, string[]>; needle: string }> = [
    { name: 'non-events-file escaped write', fields: { escaped_writes: ['$HOME/.bashrc'] }, needle: '$HOME/.bashrc' },
    { name: '<HIDDEN> secret env read', fields: { env_read: ['<HIDDEN> NPM_TOKEN'] }, needle: '<HIDDEN> NPM_TOKEN' },
    // Round-5: a credential-bearing env NAME the producer's protected set did NOT
    // cover surfaces RAW (no `<HIDDEN>` prefix); it must still fail closed.
    { name: 'raw (unhidden) NPM_TOKEN env read', fields: { env_read: ['NPM_TOKEN'] }, needle: 'NPM_TOKEN' },
    { name: 'raw AWS_SECRET_ACCESS_KEY env read', fields: { env_read: ['AWS_SECRET_ACCESS_KEY'] }, needle: 'AWS_SECRET_ACCESS_KEY' },
    { name: 'raw GIT_TOKEN env read', fields: { env_read: ['GIT_TOKEN'] }, needle: 'GIT_TOKEN' },
    { name: 'raw NODE_AUTH_TOKEN env read', fields: { env_read: ['NODE_AUTH_TOKEN'] }, needle: 'NODE_AUTH_TOKEN' },
    // Round-6: case-insensitive + npm `_auth`/`_authToken` + PAT + docker-auth
    // forms.  Each previously slipped past the case-sensitive uppercase matcher.
    { name: 'lower-case github_token env read', fields: { env_read: ['github_token'] }, needle: 'github_token' },
    { name: 'npm_config__authToken env read', fields: { env_read: ['npm_config__authToken'] }, needle: 'npm_config__authToken' },
    {
      name: 'per-registry npm :_authToken env read',
      fields: { env_read: ['npm_config_//registry.npmjs.org/:_authToken'] },
      needle: 'npm_config_//registry.npmjs.org/:_authToken',
    },
    { name: 'npm_config__auth env read', fields: { env_read: ['npm_config__auth'] }, needle: 'npm_config__auth' },
    { name: 'GITHUB_PAT (personal access token) env read', fields: { env_read: ['GITHUB_PAT'] }, needle: 'GITHUB_PAT' },
    { name: 'DOCKER_AUTH_CONFIG env read', fields: { env_read: ['DOCKER_AUTH_CONFIG'] }, needle: 'DOCKER_AUTH_CONFIG' },
    // Round-7: categorical token/affix coverage — AUTHORIZATION header, npm `_auth`
    // single-underscore aliases, compact PRIVATEKEY, and a `*_KEY` token form.
    { name: 'AUTHORIZATION header env read', fields: { env_read: ['AUTHORIZATION'] }, needle: 'AUTHORIZATION' },
    { name: 'HTTP_AUTHORIZATION env read', fields: { env_read: ['HTTP_AUTHORIZATION'] }, needle: 'HTTP_AUTHORIZATION' },
    { name: 'NPM_AUTH env read', fields: { env_read: ['NPM_AUTH'] }, needle: 'NPM_AUTH' },
    { name: 'NPM_CONFIG_AUTH env read', fields: { env_read: ['NPM_CONFIG_AUTH'] }, needle: 'NPM_CONFIG_AUTH' },
    { name: 'compact PRIVATEKEY env read', fields: { env_read: ['GITHUB_PRIVATEKEY'] }, needle: 'GITHUB_PRIVATEKEY' },
    { name: 'SERVICE_ACCOUNT_KEY env read', fields: { env_read: ['SERVICE_ACCOUNT_KEY'] }, needle: 'SERVICE_ACCOUNT_KEY' },
    { name: 'BEARER_TOKEN env read', fields: { env_read: ['BEARER_TOKEN'] }, needle: 'BEARER_TOKEN' },
    // Round-8: MySQL-family password var that abbreviates to `_PWD` (not PASSWORD).
    { name: 'MYSQL_PWD env read', fields: { env_read: ['MYSQL_PWD'] }, needle: 'MYSQL_PWD' },
    { name: 'sensitive credential file read', fields: { external_reads: ['$HOME/.ssh/id_rsa'] }, needle: '$HOME/.ssh/id_rsa' },
    // Round-6: cloud-CLI / GPG credential stores the file matcher previously missed.
    {
      name: 'gcloud application-default credentials file read',
      fields: { external_reads: ['$HOME/.config/gcloud/application_default_credentials.json'] },
      needle: '$HOME/.config/gcloud/application_default_credentials.json',
    },
    {
      name: 'azure accessTokens file read',
      fields: { external_reads: ['$HOME/.azure/accessTokens.json'] },
      needle: '$HOME/.azure/accessTokens.json',
    },
    {
      name: 'gnupg private-key file read',
      fields: { external_reads: ['$HOME/.gnupg/private-keys-v1.d/key.key'] },
      needle: '$HOME/.gnupg/private-keys-v1.d/key.key',
    },
    // Round-7: package-manager credential stores the producer does not hide by default.
    {
      name: 'git-credentials file read',
      fields: { external_reads: ['$HOME/.git-credentials'] },
      needle: '$HOME/.git-credentials',
    },
    { name: 'pypirc file read', fields: { external_reads: ['$HOME/.pypirc'] }, needle: '$HOME/.pypirc' },
    {
      name: 'cargo credentials file read',
      fields: { external_reads: ['$HOME/.cargo/credentials.toml'] },
      needle: '$HOME/.cargo/credentials.toml',
    },
    {
      name: 'composer auth.json file read',
      fields: { external_reads: ['$REPO/auth.json'] },
      needle: '$REPO/auth.json',
    },
    {
      name: 'NuGet config file read',
      fields: { external_reads: ['$HOME/.config/NuGet/NuGet.Config'] },
      needle: '$HOME/.config/NuGet/NuGet.Config',
    },
    {
      name: 'PEM private-key file read (suffix match)',
      fields: { external_reads: ['$HOME/secrets/server.pem'] },
      needle: '$HOME/secrets/server.pem',
    },
    {
      name: 'PKCS12 cert file read (suffix match)',
      fields: { external_reads: ['$HOME/certs/client.p12'] },
      needle: '$HOME/certs/client.p12',
    },
    {
      name: 'dotenv secret file read (segment match)',
      fields: { external_reads: ['$REPO/.env.local'] },
      needle: '$REPO/.env.local',
    },
    { name: 'non-resolver blocked connect', fields: { network_attempts: ['<BLOCKED> connect 8.8.8.8:443'] }, needle: '<BLOCKED> connect 8.8.8.8:443' },
    { name: 'succeeded (un-blocked) connect', fields: { network_attempts: ['connect 8.8.8.8:443'] }, needle: 'connect 8.8.8.8:443' },
    { name: 'dlopen of a native library', fields: { dlopen_attempts: ['/tmp/evil.so'] }, needle: '/tmp/evil.so' },
    { name: 'audit bypass', fields: { audit_bypass: ['raw-syscall openat'] }, needle: 'raw-syscall openat' },
    { name: 'env tamper', fields: { env_tamper: ['unset SCRIPT_JAIL_MACOS_AUDIT_OPS'] }, needle: 'unset SCRIPT_JAIL_MACOS_AUDIT_OPS' },
    { name: 'unapproved extra spawn', fields: { spawn_attempts: ['node postinstall.js', 'curl http://evil.example'] }, needle: 'curl http://evil.example' },
    { name: 'unapproved blocked spawn', fields: { spawn_blocked: ['bash -c id'] }, needle: 'bash -c id' },
  ];

  for (const c of cases) {
    it(`FAILS on a one-sided ${c.name} hidden inside a stripped @swc/core block`, () => {
      const dir = makeWorkspace();
      const left = join(dir, 'linux.yml');
      const right = join(dir, 'macos.yml');
      writeFileSync(left, benign, 'utf8');
      writeFileSync(right, swcDivergentLock(postinstallFields(c.fields)), 'utf8');

      const result = runParityDiff(left, right);

      // The comparable text is byte-equal (both @swc blocks are stripped, and
      // esbuild is identical) — only the danger finding fails the gate.
      expect(result.status).toBe(1);
      expect(result.stdout).toContain('DANGER');
      expect(result.stdout).toContain(c.needle);
      // Finding #4: prove the danger path is the SOLE reason for exit 1.  If the
      // comparable text had diverged, parity-diff would print a unified diff
      // BEFORE the danger block — assert no diff markers leaked, so exit 1 came
      // purely from the danger finding (not an incidental text difference).
      expect(result.stdout).not.toMatch(/^@@ /m);
      expect(result.stdout).not.toMatch(/^--- /m);
      expect(result.stdout).not.toMatch(/^\+\+\+ /m);
      expect(result.stderr).toBe('');
    });
  }

  it('NEGATIVE CONTROL: the same fixtures with the dangerous value removed exit 0', () => {
    // Pair for the danger loop: identical benign @swc block on BOTH sides, so
    // the only thing that ever flipped the gate above was the danger finding.
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, benign, 'utf8');
    writeFileSync(right, benign, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('PASSES when a divergent package\'s only connect is a host-resolver :53 lookup (load-bearing waiver, finding F2)', () => {
    // @swc/core's postinstall spawns a nested `npm install @swc/wasm`, which does
    // a live registry DNS lookup on the ONLINE macOS-bare backend → `connect
    // 127.0.0.1:53` (loopback mDNSResponder), folded into @swc's block by
    // attribution.  On OFFLINE Linux the same lookup is `<BLOCKED>`.  The resolver
    // waiver in collectDivergentDangers must reconcile both (strip `<BLOCKED> `,
    // then allowlist) → exit 0.  This is load-bearing: removing it false-fails the
    // macOS-bare CI leg.  The paired 8.8.8.8 danger cases above prove a
    // NON-resolver connect still fails, so this is not a blanket network waiver.
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(
      left,
      swcDivergentLock(postinstallFields({ network_attempts: ['<BLOCKED> connect 127.0.0.1:53'] })),
      'utf8',
    );
    writeFileSync(
      right,
      swcDivergentLock(postinstallFields({ network_attempts: ['connect 127.0.0.1:53'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
  });

  it('PASSES when a divergent package reads only benign (non-credential) env names', () => {
    // Guard against an over-broad sensitive-env pattern: config-ish names a
    // divergent package legitimately reads (AWS_REGION, NPM_CONFIG_*, PUPPETEER_*,
    // *_PROXY, NODE_TLS_REJECT_UNAUTHORIZED) must NOT trip the round-5 check.
    // Round-6 precision cases included here: case-insensitive matching plus the
    // npm `_auth` boundary must NOT trip `…UNAUTHORIZED` (contains "AUTH"), any
    // `*_PATH` (contains "PAT"), or the deprecated single-underscore
    // `npm_config_always_auth` config FLAG (not a credential).
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, benign, 'utf8');
    writeFileSync(
      right,
      swcDivergentLock(
        postinstallFields({
          env_read: [
            'AWS_REGION',
            'HTTPS_PROXY',
            'NODE_TLS_REJECT_UNAUTHORIZED',
            'NPM_CONFIG_REGISTRY',
            'PUPPETEER_CACHE_DIR',
            'npm_config_always_auth',
            'npm_config_user_agent',
            'PUPPETEER_EXECUTABLE_PATH',
            'core.hooksPath',
            'PWD',
            'OLDPWD',
          ],
        }),
      ),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('PASSES when a divergent package reads only benign (non-credential) files', () => {
    // Guard the segment/suffix-aware file matcher against over-broad substrings:
    // the cargo registry CACHE (`/.cargo/registry/…`, not `/.cargo/credentials`),
    // a generic configstore JSON, and a benign `node_modules` lockfile must NOT
    // trip — only the specific credential stores / key-file suffixes do.
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, benign, 'utf8');
    writeFileSync(
      right,
      swcDivergentLock(
        postinstallFields({
          external_reads: [
            '$HOME/.cargo/registry/index/github.com-1ecc6299db9ec823/foo',
            '$HOME/.config/configstore/update-notifier-npm.json',
            '$REPO/node_modules/.package-lock.json',
            '$REPO/.environment',
            '$REPO/node_modules/dotenv/lib/main.js',
          ],
        }),
      ),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('FAILS on a forged events-file-shaped escaped write in a divergent package (round-9)', () => {
    // The agent's own events-file write is dropped at the PRODUCER, so a current
    // lock never carries it.  parity-diff therefore does NOT waive the tokenized
    // `$TMPDIR/<hash>/<hash>.jsonl` path — it is FORGEABLE (tokenize() collapses any
    // long TMPDIR segment to `<hash>`), so a package could otherwise launder a
    // one-sided TMPDIR escape behind it.  It is now fully default-deny.
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, benign, 'utf8');
    writeFileSync(
      right,
      swcDivergentLock(postinstallFields({ escaped_writes: ['$TMPDIR/<hash>/<hash>.jsonl'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('$TMPDIR/<hash>/<hash>.jsonl');
    expect(result.stderr).toBe('');
  });

  it('PASSES when both sides carry only allowlisted divergent spawns', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({ spawn_attempts: ['node postinstall.js'] })), 'utf8');
    writeFileSync(
      right,
      swcDivergentLock(
        postinstallFields({
          spawn_attempts: [
            'npm install --no-save --loglevel=error --prefer-offline --no-audit --progress=false @swc/wasm@1.15.33',
          ],
        }),
      ),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('reports a divergent package on BOTH sides when each hides a different escape', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({ external_reads: ['$HOME/.aws/credentials'] })), 'utf8');
    writeFileSync(right, swcDivergentLock(postinstallFields({ env_read: ['<HIDDEN> AWS_SECRET_ACCESS_KEY'] })), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('$HOME/.aws/credentials');
    expect(result.stdout).toContain('<HIDDEN> AWS_SECRET_ACCESS_KEY');
    expect(result.stderr).toBe('');
  });
});

describe('scripts/parity-diff.ts — asymmetric validation (--source-of-truth)', () => {
  // Linux is the single source of truth (the lockfile is generated there);
  // macOS/Windows VALIDATE against it as a SUBSET.  A divergent package present in
  // the source-of-truth lock but ABSENT on the validated platform is safe (it
  // legitimately did less — e.g. puppeteer/unrs-resolver early-exit on Darwin); a
  // divergent package present on the VALIDATED side yet absent from the source of
  // truth still fails.  `LOCK_HEADER + INVARIANT_ESBUILD` is the same lock without
  // the @swc/core block, i.e. @swc absent on that side.
  const withSwc = swcDivergentLock(postinstallFields({}));
  const withoutSwc = `${LOCK_HEADER}${INVARIANT_ESBUILD}`;

  it('SAFE: divergent package present in source-of-truth (left) but absent on the validated side → exit 0', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, withSwc, 'utf8'); // linux = source of truth: @swc present
    writeFileSync(right, withoutSwc, 'utf8'); // macos = validated: @swc absent (early-exit)

    const result = runParityDiff(left, right, ['--source-of-truth', 'left']);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  it('FAILS: divergent package present on the VALIDATED side but absent from the source of truth → exit 1', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, withoutSwc, 'utf8'); // linux = source of truth: @swc absent
    writeFileSync(right, withSwc, 'utf8'); // macos = validated: @swc present (NOT in truth)

    const result = runParityDiff(left, right, ['--source-of-truth', 'left']);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('divergent_presence');
    expect(result.stderr).toBe('');
  });

  it('SYMMETRIC DEFAULT (no flag): a one-sided divergent package still fails either direction', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, withSwc, 'utf8');
    writeFileSync(right, withoutSwc, 'utf8');

    const result = runParityDiff(left, right); // no --source-of-truth → symmetric

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('divergent_presence');
    expect(result.stderr).toBe('');
  });

  it('rejects an invalid --source-of-truth value (exit 2)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'linux.yml');
    const right = join(dir, 'macos.yml');
    writeFileSync(left, withSwc, 'utf8');
    writeFileSync(right, withSwc, 'utf8');

    const result = runParityDiff(left, right, ['--source-of-truth', 'middle']);

    expect(result.status).toBe(2);
  });
});

describe('scripts/parity-diff.ts — exact-match filter regressions (findings #2/#3/#4)', () => {
  // #2: a SUCCEEDED connect to a NON-resolver host in a byte-compared package
  // must surface.  Stripping `<BLOCKED> ` reconciles resolver noise across the
  // offline-Linux / online-macOS split, but a non-allowlisted host is absent from
  // PARITY_ONLY_NETWORK_ATTEMPTS, so it survives the strip+filter and diffs.
  it('surfaces a one-sided succeeded connect (finding #2)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ network_attempts: ['connect 8.8.8.8:443'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('connect 8.8.8.8:443');
    expect(result.stderr).toBe('');
  });

  // Observe-only reconciliation (the core of the round-10 revert): the SAME
  // connect is recorded `<BLOCKED> connect …` on Linux (Phase B offline via
  // `unshare -n`) and `connect …` on macOS-bare (online, shim forwards + records
  // the true result).  Stripping `<BLOCKED> ` from connect entries on both sides
  // reduces them to the identical `connect <host>:<port>`, so one committed lock
  // satisfies both backends → exit 0.
  it('reconciles a connect blocked on Linux and online on macOS (observe-only strip)', () => {
    const dir = makeWorkspace();
    const linux = join(dir, 'linux.yml');
    const macos = join(dir, 'macos.yml');
    writeFileSync(
      linux,
      singlePackageLock('got@14.0.0', postinstallFields({ network_attempts: ['<BLOCKED> connect 8.8.8.8:443'] })),
      'utf8',
    );
    writeFileSync(
      macos,
      singlePackageLock('got@14.0.0', postinstallFields({ network_attempts: ['connect 8.8.8.8:443'] })),
      'utf8',
    );

    const result = runParityDiff(linux, macos);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
  });

  // Round-9: the producer drops its OWN events-file write (Fix C / shim
  // `path_is_audit_log`) and the committed baseline was regenerated without it, so
  // parity-diff must NOT waive the tokenized `$TMPDIR/<hash>/<hash>.jsonl` path —
  // it is FORGEABLE (tokenize() collapses any long TMPDIR segment to `<hash>`), so
  // waiving it on a BYTE-COMPARED package would let a one-sided TMPDIR escape
  // vanish from the comparison.  A forged events-file-shaped write must fail.
  it('FAILS on a forged events-file-shaped write on a byte-compared package (round-9)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('esbuild@0.28.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('esbuild@0.28.0', postinstallFields({ escaped_writes: ['$TMPDIR/<hash>/<hash>.jsonl'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$TMPDIR/<hash>/<hash>.jsonl');
    expect(result.stderr).toBe('');
  });

  // Any other one-sided escaped write on a byte-compared package also fails.
  it('still fails on a non-events one-sided escaped write on a byte-compared package', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('esbuild@0.28.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('esbuild@0.28.0', postinstallFields({ escaped_writes: ['$HOME/.bashrc'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$HOME/.bashrc');
    expect(result.stderr).toBe('');
  });

  // #2 (benign): a host-resolver `<BLOCKED>` entry is still reconciled.
  it('filters a one-sided benign blocked-resolver connect (finding #2)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(
      left,
      singlePackageLock('got@14.0.0', postinstallFields({ network_attempts: ['<BLOCKED> connect 127.0.0.1:53'] })),
      'utf8',
    );
    writeFileSync(right, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  // #3: exact-name env filtering — the prefix families (GIT_*, DYLD_*) are NOT
  // blanket-filtered, so a one-sided credential / novel sandbox probe surfaces.
  it('surfaces one-sided GIT_TOKEN + a novel DYLD_* read (finding #3)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({ env_read: ['PATH'] })), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ env_read: ['DYLD_NEW_PROBE', 'GIT_TOKEN', 'PATH'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('GIT_TOKEN');
    expect(result.stdout).toContain('DYLD_NEW_PROBE');
    expect(result.stderr).toBe('');
  });

  // #3 (benign): the EXACT allowlisted injection name is still reconciled.
  it('filters the exact DYLD_INSERT_LIBRARIES name (finding #3)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({ env_read: ['PATH'] })), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ env_read: ['DYLD_INSERT_LIBRARIES', 'PATH'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  // #4: a one-sided global git-config read is no longer package-agnostically
  // filtered — it can expose credential helpers / URL rewrites, so it surfaces.
  it('surfaces a one-sided $HOME/.gitconfig read (finding #4)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ external_reads: ['$HOME/.gitconfig'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$HOME/.gitconfig');
    expect(result.stderr).toBe('');
  });

  // #4 (benign): the puppeteer cache root read is still reconciled.
  it('filters a one-sided $HOME/.cache/puppeteer read (finding #4)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(
      left,
      singlePackageLock('got@14.0.0', postinstallFields({ external_reads: ['$HOME/.cache/puppeteer'] })),
      'utf8',
    );
    writeFileSync(right, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  // #3 (scoped spawn): the esbuild self-verify waiver applies ONLY inside
  // esbuild — an unrelated package reading the same spawn one-sided surfaces.
  it('does NOT launder the esbuild self-verify spawn for a different package (finding #3)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ spawn_attempts: ['$PKG/bin/esbuild --version', 'node postinstall.js'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('$PKG/bin/esbuild --version');
    expect(result.stderr).toBe('');
  });

  // #3 (scoped spawn, positive): the SAME spawn inside esbuild IS reconciled.
  it('waives the esbuild self-verify spawn inside the esbuild package (finding #3)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('esbuild@0.28.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('esbuild@0.28.0', postinstallFields({ spawn_attempts: ['$PKG/bin/esbuild --version', 'node postinstall.js'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });

  // #3 (scoped spawn): the simple-git-hooks git-config waiver does not apply to
  // a different package either.
  it('does NOT launder the git-config probe for a different package (finding #3)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    writeFileSync(
      right,
      singlePackageLock('got@14.0.0', postinstallFields({ spawn_attempts: ['node postinstall.js', 'sh -c git config --local core.hooksPath'] })),
      'utf8',
    );

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('git config --local core.hooksPath');
    expect(result.stderr).toBe('');
  });
});

describe('scripts/parity-diff.ts — schema validation fail-closed (finding #2)', () => {
  it('FAILS closed when a watched field is a malformed (non-array) shape', () => {
    // The #2 evasion: a divergent package whose external_reads is an OBJECT, not
    // a list.  The old asList() coerced it to "[object Object]" (matching no
    // danger pattern) while the line stripper still dropped the block.  Schema
    // validation now rejects the shape up front → danger → exit 1.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    // Hand-write the malformed block (postinstallFields only emits arrays).
    const malformed = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads:
          secret: $HOME/.ssh/id_rsa
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, malformed, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('schema');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed when a lock is not valid YAML', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    writeFileSync(right, 'this: : : not valid yaml\n  - [unbalanced\n', 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on a one-sided UNKNOWN field inside a stripped divergent block', () => {
    // The unknown-field fail-open: an extra (schema-unrecognised) field inside a
    // @swc/core block.  The canonical permissive schema would strip it and the
    // field walk never sees it, while the line stripper drops the whole block —
    // laundering the one-sided `$HOME/.ssh/id_rsa` to exit 0.  The strict parity
    // schema rejects the unknown key up front → schema danger → exit 1.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    const withUnknownField = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
        secret_reads:
          - $HOME/.ssh/id_rsa
`;
    writeFileSync(right, withUnknownField, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('schema');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on an unknown sibling key in a package entry (next to lifecycle)', () => {
    // Strictness also covers the package-entry object: a key other than
    // `lifecycle` (e.g. a stray `metadata:` sibling inside the package) must not
    // ride along inside a stripped block.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    const withSibling = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    note: $HOME/.aws/credentials
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, withSibling, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('schema');
    expect(result.stderr).toBe('');
  });
});

describe('scripts/parity-diff.ts — strict top-level + structural fail-closed (AST rewrite)', () => {
  it('FAILS closed on an unknown top-level section (finding #4: full byte coverage)', () => {
    // A future/hostile sibling top-level section carries a key that LOOKS like a
    // divergent package.  Under the AST rewrite the whole lock is re-rendered
    // from the strict-validated structure, so an unknown top-level section is
    // rejected up front (ParityLock is `.strict()` at the top level) — it can
    // never be silently dropped from BOTH renders and laundered to exit 0.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    const base = `${LOCK_HEADER}${INVARIANT_ESBUILD}`;
    const meta = (note: string) => `metadata:
  "@swc/core@1.15.33":
    note: ${note}
`;
    writeFileSync(left, base + meta('benign'), 'utf8');
    writeFileSync(right, base + meta('EXFILTRATED'), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('schema');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on a YAML anchor/alias construct (cannot mask cross-package drift)', () => {
    // Codex round-3 finding #1: a line-based stripper saw `*block` as an opaque
    // token while the parser expanded it, so an alias could splice one package's
    // content into another behind a stripped divergent region.  The AST rewrite
    // rejects ANY anchor or alias up front — render.ts never emits either, so a
    // conformant lock has neither.  A valid alias always has a preceding anchor
    // (forward aliases are a parse error), so the anchor is what trips first here;
    // the rejection — not which feature name fires — is the contract.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    const aliased = `${LOCK_HEADER}  esbuild@0.28.0: &block
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node install.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
  got@14.0.0: *block
`;
    writeFileSync(right, aliased, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toMatch(/anchor|alias/);
    expect(result.stderr).toBe('');
  });

  it('FAILS closed when a YAML anchor is used (even without an alias)', () => {
    // Anchors are the prerequisite for aliases and render.ts never emits them, so
    // the gate rejects an anchored node up front rather than reason about whether
    // a matching alias exists.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    const anchored = `${LOCK_HEADER}  got@14.0.0: &anchor
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, anchored, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('anchor');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on an explicit !!merge tag (merge resolves before validation)', () => {
    // Adversarial review round-4: `structuralReject` originally matched only the
    // literal string key '<<', but `!!merge <<` makes the key value a Symbol —
    // slipping past — and `toJS()` then APPLIES the merge, letting an explicit
    // safe field override merged dangerous content before the danger walk runs.
    // Non-string keys are now rejected, which catches the Symbol merge key.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    const merged = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        !!merge <<: { external_reads: ["$HOME/.ssh/id_rsa"] }
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, merged, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on a non-string mapping key (JS projection collision)', () => {
    // Adversarial review round-4: a numeric `1:` and a quoted `"1":` are distinct
    // YAML keys (no duplicate-key error) but collapse to the same JS property in
    // `toJS()`, silently dropping the loser's content before any scan.  The
    // dangerous `1:` stage here would never reach the danger walk; non-string
    // keys are now rejected up front.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, swcDivergentLock(postinstallFields({})), 'utf8');
    const collide = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      1:
        external_reads:
          - $HOME/.ssh/id_rsa
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
      "1":
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, collide, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on a "__proto__" package key (render.ts drops it via the prototype setter)', () => {
    // Adversarial review round-4 follow-up: `__proto__` is a string key (so it
    // passes the non-string check), but render.ts builds `packages[k] = …` on a
    // plain object, so `k === "__proto__"` hits the prototype setter and the
    // package vanishes from the re-render on BOTH sides — a one-sided escape
    // hidden under it would be laundered to exit 0.  It is now rejected up front.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('esbuild@0.28.0', postinstallFields({})), 'utf8');
    const proto = `${LOCK_HEADER}${INVARIANT_ESBUILD}  __proto__:
    lifecycle:
      postinstall:
        external_reads:
          - $HOME/.ssh/id_rsa
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, proto, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('__proto__');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed on a package key containing a TAB (forged package→stage composite)', () => {
    // The symmetric-presence check joins `${pkg}\t${stage}` into one Set token.
    // A package key with an embedded TAB could forge a composite that collides
    // with a real `pkg\tstage` pair.  render.ts never emits a control char in a
    // key, so the gate rejects it structurally up front (rather than relying on
    // the multi-composite design's emergent fail-closed behaviour).
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('puppeteer@1.0.0', postinstallFields({})), 'utf8');
    // A divergent (puppeteer@) key whose name embeds a TAB then a stage name.
    const tabKey = `${LOCK_HEADER}  "puppeteer@1.0.0\tpostinstall":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts: []
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(right, tabKey, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('control character');
    expect(result.stderr).toBe('');
  });

  it('FAILS closed when a mandatory lifecycle list field is missing (no defaulting)', () => {
    // Adversarial review round-4: the parity schema reused `LifecycleBlock`, which
    // `.default([])`s every field, so a lock missing an always-rendered field
    // (e.g. network_attempts) was accepted, defaulted, and re-rendered to match a
    // lock that carried it.  The parity lifecycle schema now REQUIRES the seven
    // always-rendered fields.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    writeFileSync(left, singlePackageLock('got@14.0.0', postinstallFields({})), 'utf8');
    const missingField = `${LOCK_HEADER}  got@14.0.0:
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
`;
    writeFileSync(right, missingField, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('schema');
    expect(result.stderr).toBe('');
  });
});

describe('scripts/parity-diff.ts — symmetric divergent-package presence (finding #3)', () => {
  it('FAILS when a divergent package is present on only ONE side', () => {
    // Codex round-3 finding #3: a divergent package is excluded from the byte
    // comparison, so if it appears on one side only, both sides end up without
    // the block and the comparison silently passes.  A one-sided divergent
    // package is a resolution desync — the symmetric-presence check fails it even
    // though the comparable (esbuild-only) text is byte-equal.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    // LEFT carries @swc (divergent) + esbuild; RIGHT carries esbuild only.
    const withSwc = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(left, withSwc, 'utf8');
    writeFileSync(right, `${LOCK_HEADER}${INVARIANT_ESBUILD}`, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('@swc/core@1.15.33');
    // The comparable text (esbuild only) is byte-equal — exit 1 comes purely from
    // the one-sided presence, not a diff.
    expect(result.stdout).not.toMatch(/^@@ /m);
    expect(result.stderr).toBe('');
  });

  it('FAILS when a divergent package has an empty lifecycle on one side (round-5)', () => {
    // Round-5: presence tracked only package KEYS, so an excluded package whose
    // lifecycle was replaced with `{}` on one side passed against a normal block
    // on the other (the package is dropped before render, so byte-equal).  The
    // check now tracks package+stage, so the missing `postinstall` fails closed.
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    const withPostinstall = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      postinstall:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    const emptyLifecycle = `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle: {}
`;
    writeFileSync(left, withPostinstall, 'utf8');
    writeFileSync(right, emptyLifecycle, 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('postinstall');
    expect(result.stdout).not.toMatch(/^@@ /m);
    expect(result.stderr).toBe('');
  });

  it('FAILS when a divergent package runs a different lifecycle stage on each side (round-5)', () => {
    const dir = makeWorkspace();
    const left = join(dir, 'a.yml');
    const right = join(dir, 'b.yml');
    const swcStage = (stage: string) => `${LOCK_HEADER}${INVARIANT_ESBUILD}  "@swc/core@1.15.33":
    lifecycle:
      ${stage}:
        external_reads: []
        escaped_writes: []
        env_read: []
        spawn_attempts:
          - node postinstall.js
        spawn_blocked: []
        dlopen_attempts: []
        network_attempts: []
`;
    writeFileSync(left, swcStage('postinstall'), 'utf8');
    writeFileSync(right, swcStage('preinstall'), 'utf8');

    const result = runParityDiff(left, right);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('DANGER');
    expect(result.stdout).toContain('@swc/core@1.15.33');
    expect(result.stderr).toBe('');
  });
});

// script-jail — test/cli/provision-node-mac.test.ts
//
// Unit tests for the macOS-native Node provisioning module.  Everything
// external is injected through the module's OWN seams (`http.download` and
// `runCommand` on ProvisionNodeMacInput) — no real network, no real codesign,
// no real vp.  The fake runCommand materializes exactly the on-disk artifacts
// each step expects (tar extract → package/vp, vp env install → js_runtime
// bin/node) so every later error branch is reachable in isolation.

import { afterEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  defaultProvisionCacheDir,
  provisionNodeMac,
  type ProvisionNodeMacInput,
} from '../../src/cli/provision-node-mac.js';

let scratch: string | undefined;

afterEach(() => {
  if (scratch !== undefined) {
    rmSync(scratch, { recursive: true, force: true });
    scratch = undefined;
  }
});

function tempDir(): string {
  scratch = mkdtempSync(join(tmpdir(), 'script-jail-provision-test-'));
  return scratch;
}

// ---------------------------------------------------------------------------
// defaultProvisionCacheDir
// ---------------------------------------------------------------------------

describe('defaultProvisionCacheDir', () => {
  it('returns SCRIPT_JAIL_CACHE_DIR verbatim when set', () => {
    expect(defaultProvisionCacheDir({ SCRIPT_JAIL_CACHE_DIR: '/custom/cache' }))
      .toBe('/custom/cache');
  });

  it('falls back to <tmpdir>/script-jail-cache when the env var is unset', () => {
    expect(defaultProvisionCacheDir({})).toBe(join(tmpdir(), 'script-jail-cache'));
  });

  it('falls back to <tmpdir>/script-jail-cache when the env var is empty', () => {
    expect(defaultProvisionCacheDir({ SCRIPT_JAIL_CACHE_DIR: '' }))
      .toBe(join(tmpdir(), 'script-jail-cache'));
  });

  it('default produces paths the darwin normalizer drops as toolchain noise', () => {
    // The lock normalizer (src/lock/normalize.ts) drops provisioned-toolchain
    // reads only when the path contains the `/script-jail-cache/` SEGMENT.
    // Anything provisioned under the default root must therefore carry it —
    // this is the local-vs-CI lockfile-divergence regression guard.
    const nested = join(defaultProvisionCacheDir({}), 'script-jail-node-mac', 'node');
    expect(nested).toContain('/script-jail-cache/');
  });
});

// ---------------------------------------------------------------------------
// provisionNodeMac — error paths via the http/runCommand seams
// ---------------------------------------------------------------------------

// What the fake runCommand should materialize / fail.  Each test flips ONE
// dimension; the defaults walk the happy path up to the branch under test.
interface FakeToolchainOptions {
  /** tar -xzf: create package/vp under the extract dir (default true). */
  extractVp?: boolean;
  /** vp env install: throw a non-zero-exit error. */
  failVpInstall?: boolean;
  /** vp env install: lay out js_runtime/node/<x>/bin/node (default true). */
  installNode?: boolean;
  /** corepack enable: throw a non-zero-exit error. */
  failCorepack?: boolean;
  /** any codesign call: throw a non-zero-exit error. */
  failCodesign?: boolean;
  /** codesign calls matching this predicate: throw a non-zero-exit error. */
  failCodesignWhen?: (args: string[]) => boolean;
}

interface FakeRunCommand {
  run: NonNullable<ProvisionNodeMacInput['runCommand']>;
  calls: Array<{ cmd: string; args: string[] }>;
}

function makeFakeRunCommand(opts: FakeToolchainOptions = {}): FakeRunCommand {
  const calls: FakeRunCommand['calls'] = [];
  const run: FakeRunCommand['run'] = (cmd, args, runOpts = {}) => {
    calls.push({ cmd, args });

    if (cmd === 'tar') {
      // tar -xzf <tgz> -C <extractDir> — mirror the real extraction layout.
      if (opts.extractVp === false) return;
      const extractDir = args[args.indexOf('-C') + 1]!;
      mkdirSync(join(extractDir, 'package'), { recursive: true });
      writeFileSync(join(extractDir, 'package', 'vp'), '#!/bin/sh\n');
      return;
    }

    if (args[0] === 'env' && args[1] === 'install') {
      if (opts.failVpInstall === true) {
        throw new Error(`${cmd} ${args.join(' ')} failed with exit 1: boom`);
      }
      if (opts.installNode === false) return;
      // Same tree vp lays out: <VP_HOME>/js_runtime/.../bin/node (+ corepack).
      const vpHome = runOpts.env?.['VP_HOME'];
      if (typeof vpHome !== 'string') throw new Error('test: VP_HOME not set');
      const binDir = join(vpHome, 'js_runtime', 'node', 'v-test', 'bin');
      mkdirSync(binDir, { recursive: true });
      writeFileSync(join(binDir, 'node'), 'fake-node-binary');
      writeFileSync(join(binDir, 'corepack'), 'fake-corepack');
      return;
    }

    if (args[0] === 'enable') {
      if (opts.failCorepack === true) {
        throw new Error(`${cmd} enable failed with exit 1: corepack boom`);
      }
      return;
    }

    if (cmd === 'codesign') {
      if (opts.failCodesign === true || opts.failCodesignWhen?.(args) === true) {
        throw new Error(`codesign ${args.join(' ')} failed with exit 1: sign boom`);
      }
      return;
    }
  };
  return { run, calls };
}

// download() that "succeeds": writes a placeholder tgz (never actually read —
// extraction is the fake runCommand's tar branch).
const fakeDownloadOk: NonNullable<ProvisionNodeMacInput['http']>['download'] =
  async (_url, destPath) => {
    writeFileSync(destPath, 'fake-vp-tgz');
  };

/** Path of the resign-marker for the provision root `nodePath` lives under. */
function markerPathFor(cacheDir: string, nodePath: string): string {
  const rootName = nodePath.split('/script-jail-node-mac/')[1]!.split('/')[0]!;
  return join(cacheDir, 'script-jail-node-mac', rootName, 'resign-marker.json');
}

function readMarkerFile(cacheDir: string, nodePath: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(markerPathFor(cacheDir, nodePath), 'utf8'),
  ) as Record<string, unknown>;
}

function makeInput(
  dir: string,
  fake: FakeRunCommand,
  over: Partial<ProvisionNodeMacInput> = {},
): ProvisionNodeMacInput {
  // Bundled shell-shim sources exist by default; tests override to exercise
  // the missing-binary branch.
  const macBashPath = join(dir, 'images', 'bash-arm64');
  const macCoreutilsPath = join(dir, 'images', 'coreutils-arm64');
  mkdirSync(join(dir, 'images'), { recursive: true });
  if (!existsSync(macBashPath)) writeFileSync(macBashPath, 'fake-bash');
  if (!existsSync(macCoreutilsPath)) writeFileSync(macCoreutilsPath, 'fake-coreutils');
  return {
    arch: 'arm64',
    cacheDir: join(dir, 'cache'),
    http: { download: fakeDownloadOk },
    runCommand: fake.run,
    macBashPath,
    macCoreutilsPath,
    ...over,
  };
}

describe('provisionNodeMac — error paths', () => {
  it('rejects when the vp tarball SHA-256 does not match', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand();
    const input = makeInput(dir, fake, {
      http: {
        download: async (url, _destPath, expectedDigest) => {
          throw new Error(`SHA-256 mismatch for ${url}: expected ${expectedDigest}, got deadbeef`);
        },
      },
    });

    await expect(provisionNodeMac(input)).rejects.toThrow(/SHA-256 mismatch/);
    // Nothing past the download may run (no tar, no vp, no codesign).
    expect(fake.calls).toEqual([]);
  });

  it('rejects when the extracted tarball has no package/vp binary', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand({ extractVp: false });

    await expect(provisionNodeMac(makeInput(dir, fake)))
      .rejects.toThrow(/vp binary not found at .*package\/vp/);
  });

  it('rejects when `vp env install` exits non-zero', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand({ failVpInstall: true });

    await expect(provisionNodeMac(makeInput(dir, fake)))
      .rejects.toThrow(/env install .* failed with exit 1/);
  });

  it('rejects when no bin/node exists under js_runtime after install', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand({ installNode: false });

    await expect(provisionNodeMac(makeInput(dir, fake)))
      .rejects.toThrow(/vp produced no Node toolchain under .*js_runtime/);
  });

  it('rejects when `corepack enable` exits non-zero', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand({ failCorepack: true });

    await expect(provisionNodeMac(makeInput(dir, fake)))
      .rejects.toThrow(/corepack enable failed with exit 1/);
  });

  it('rejects when the codesign re-sign fails', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand({ failCodesign: true });

    await expect(provisionNodeMac(makeInput(dir, fake)))
      .rejects.toThrow(/codesign .* failed with exit 1/);
    // The resign-marker must NOT exist — a failed provision is never reusable.
    const markers = fake.calls.filter((c) => c.cmd === 'codesign');
    expect(markers.length).toBeGreaterThan(0);
  });

  it('rejects when a bundled shell-shim binary is missing', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand();
    const input = makeInput(dir, fake);
    rmSync(input.macBashPath);

    await expect(provisionNodeMac(input))
      .rejects.toThrow(/bundled shell-shim binary not found at /);
  });
});

describe('provisionNodeMac — success path (all seams green)', () => {
  it('provisions, re-signs, stages shims, and writes the resign-marker last', async () => {
    const dir = tempDir();
    const fake = makeFakeRunCommand();
    const input = makeInput(dir, fake);

    const out = await provisionNodeMac(input);

    expect(out.nodePath).toBe(join(out.nodeBinDir, 'node'));
    expect(out.nodePath.startsWith(input.cacheDir)).toBe(true);
    expect(out.nodePath).toContain('/script-jail-node-mac/');
    // Pre-re-sign SHA-256 of the exact bytes the fake vp installed.
    expect(out.preResignSha256).toMatch(/^[a-f0-9]{64}$/);
    // Staged + (fake-)re-signed multi-call binaries under the FIXED names the
    // shim's sip_redirect_target expects.
    expect(readFileSync(join(out.shellShimDir, 'bash'), 'utf8')).toBe('fake-bash');
    expect(readFileSync(join(out.shellShimDir, 'coreutils'), 'utf8')).toBe('fake-coreutils');
    // The resign-marker (the fast-path reuse gate) tracks ONLY the node half:
    // schema version + toolchain paths + pre-re-sign sha.  toEqual (not
    // toMatchObject) pins the FULL simplified schema — the staged shims are
    // restaged from the bundled sources on every call, so no shim state may
    // creep back into the marker as a write-only field.
    expect(readMarkerFile(input.cacheDir, out.nodePath)).toEqual({
      version: 3,
      nodeBinDir: out.nodeBinDir,
      nodePath: out.nodePath,
      preResignSha256: out.preResignSha256,
    });
    // node + bash + coreutils each get the 3-step codesign dance
    // (remove-signature / force-sign / verify) = 9 codesign invocations.
    expect(fake.calls.filter((c) => c.cmd === 'codesign')).toHaveLength(9);
  });
});

// ---------------------------------------------------------------------------
// provisionNodeMac — cache fast path (node cached, shims ALWAYS restaged)
// ---------------------------------------------------------------------------
//
// The marker tracks ONLY the node half (schema v3).  Staged shim bytes are
// never trusted: every call — node-cache hits included — restages bash +
// coreutils from the current bundled sources.  These tests pin that contract
// from both sides: a node-cache hit must OVERWRITE whatever is staged (wrong
// bytes AND missing files), and only an unusable marker (garbage / missing
// node fields / stale schema version) tears the node half down.

describe('provisionNodeMac — cache fast path (node cached, shims always restaged)', () => {
  it('node-cache hit: shims are restaged from the bundled sources, node is not re-provisioned', async () => {
    const dir = tempDir();
    const first = await provisionNodeMac(makeInput(dir, makeFakeRunCommand()));

    // Sentinel staged bash with WRONG bytes — the on-disk marker matches the
    // current bundled sources perfectly, which under the old sha-coherency
    // design let this sentinel survive the fast path.  It must be overwritten.
    writeFileSync(join(first.shellShimDir, 'bash'), 'sentinel-staged-bash');
    // And a MISSING staged file: same restage branch, other failure shape.
    rmSync(join(first.shellShimDir, 'coreutils'));

    const fake2 = makeFakeRunCommand();
    const second = await provisionNodeMac(makeInput(dir, fake2));

    expect(second).toEqual(first);
    expect(readFileSync(join(first.shellShimDir, 'bash'), 'utf8')).toBe('fake-bash');
    expect(readFileSync(join(first.shellShimDir, 'coreutils'), 'utf8')).toBe('fake-coreutils');
    // Node is NOT re-provisioned: no download/extract/vp/corepack, and the
    // cached binary + its pre-re-sign sha survive untouched.
    expect(fake2.calls.filter((c) => c.cmd === 'tar')).toHaveLength(0);
    expect(fake2.calls.filter((c) => c.args[0] === 'env')).toHaveLength(0);
    expect(fake2.calls.filter((c) => c.args[0] === 'enable')).toHaveLength(0);
    expect(readFileSync(second.nodePath, 'utf8')).toBe('fake-node-binary');
    // 1 node `codesign --verify` (first external call) + 2 × (remove-signature
    // / force-sign / verify) for the restaged shims = 7 codesigns total.
    expect(fake2.calls[0]).toEqual({ cmd: 'codesign', args: ['--verify', first.nodePath] });
    expect(fake2.calls.filter((c) => c.cmd === 'codesign')).toHaveLength(7);
  });

  it('idempotent: consecutive fast-path runs restage every time and pick up changed bundled sources', async () => {
    const dir = tempDir();
    const input = makeInput(dir, makeFakeRunCommand());
    const first = await provisionNodeMac(input);

    // First fast-path run after the slow path.
    const fake2 = makeFakeRunCommand();
    const second = await provisionNodeMac(makeInput(dir, fake2));
    expect(second).toEqual(first);

    // A bundled-binary fix lands AFTER the cache was populated (the minOS-fix
    // scenario).  Nothing caches staged shims, so the NEXT fast-path run must
    // serve the NEW source bytes — a crash mid-restage heals the same way.
    writeFileSync(input.macBashPath, 'fake-bash-minos-fixed');
    writeFileSync(input.macCoreutilsPath, 'fake-coreutils-minos-fixed');

    const fake3 = makeFakeRunCommand();
    const third = await provisionNodeMac(makeInput(dir, fake3));

    expect(third).toEqual(first);
    expect(readFileSync(join(third.shellShimDir, 'bash'), 'utf8'))
      .toBe('fake-bash-minos-fixed');
    expect(readFileSync(join(third.shellShimDir, 'coreutils'), 'utf8'))
      .toBe('fake-coreutils-minos-fixed');
    // Both fast-path runs: shims restaged (7 codesigns), node untouched.
    for (const fake of [fake2, fake3]) {
      expect(fake.calls.filter((c) => c.cmd === 'tar')).toHaveLength(0);
      expect(fake.calls.filter((c) => c.args[0] === 'env')).toHaveLength(0);
      expect(fake.calls.filter((c) => c.args[0] === 'enable')).toHaveLength(0);
      expect(fake.calls.filter((c) => c.cmd === 'codesign')).toHaveLength(7);
    }
    expect(readFileSync(third.nodePath, 'utf8')).toBe('fake-node-binary');
    expect(third.preResignSha256).toBe(first.preResignSha256);
  });

  it('rebuilds from scratch on a garbage marker (fail-closed: node half unprovable)', async () => {
    const dir = tempDir();
    const input = makeInput(dir, makeFakeRunCommand());
    const first = await provisionNodeMac(input);
    writeFileSync(markerPathFor(input.cacheDir, first.nodePath), 'not json {');

    const fake2 = makeFakeRunCommand();
    const second = await provisionNodeMac(makeInput(dir, fake2));

    // Full slow path: vp re-extracted, node reinstalled, fresh v3 marker.
    expect(fake2.calls.filter((c) => c.cmd === 'tar')).toHaveLength(1);
    expect(fake2.calls.filter((c) => c.args[0] === 'env')).toHaveLength(1);
    expect(second.preResignSha256).toBe(first.preResignSha256);
    expect(readMarkerFile(input.cacheDir, second.nodePath)['version']).toBe(3);
  });

  it('rebuilds from scratch on a marker missing required node fields', async () => {
    const dir = tempDir();
    const input = makeInput(dir, makeFakeRunCommand());
    const first = await provisionNodeMac(input);
    // Right schema version, but the node half is unusable without nodeBinDir
    // and preResignSha256 → unparseable → full teardown + rebuild.
    writeFileSync(
      markerPathFor(input.cacheDir, first.nodePath),
      JSON.stringify({ version: 3, nodePath: first.nodePath }),
    );

    const fake2 = makeFakeRunCommand();
    const second = await provisionNodeMac(makeInput(dir, fake2));

    expect(fake2.calls.filter((c) => c.cmd === 'tar')).toHaveLength(1);
    expect(fake2.calls.filter((c) => c.args[0] === 'env')).toHaveLength(1);
    expect(second.preResignSha256).toBe(first.preResignSha256);
  });

  it('rebuilds from scratch on a stale-schema marker (version gate guards node-half semantics)', async () => {
    const dir = tempDir();
    const input = makeInput(dir, makeFakeRunCommand());
    const first = await provisionNodeMac(input);
    // A v2-era marker: node fields valid, but written under the retired
    // schema (version 2 + shim-source shas).  The exact-version gate treats
    // it as unparseable rather than guessing at field semantics.
    writeFileSync(
      markerPathFor(input.cacheDir, first.nodePath),
      JSON.stringify({
        version: 2,
        nodeBinDir: first.nodeBinDir,
        nodePath: first.nodePath,
        preResignSha256: first.preResignSha256,
        bashSourceSha256: 'irrelevant',
        coreutilsSourceSha256: 'irrelevant',
      }),
    );

    const fake2 = makeFakeRunCommand();
    const second = await provisionNodeMac(makeInput(dir, fake2));

    expect(fake2.calls.filter((c) => c.cmd === 'tar')).toHaveLength(1);
    expect(fake2.calls.filter((c) => c.args[0] === 'env')).toHaveLength(1);
    // Fresh marker carries the simplified v3 schema only.
    expect(readMarkerFile(input.cacheDir, second.nodePath)).toEqual({
      version: 3,
      nodeBinDir: second.nodeBinDir,
      nodePath: second.nodePath,
      preResignSha256: second.preResignSha256,
    });
  });
});

// ---------------------------------------------------------------------------
// provisionNodeMac — atomic shim restage (copy/sign a temp, rename into place)
// ---------------------------------------------------------------------------
//
// The restage runs over a LIVE shim dir that a concurrent audit may be
// exec'ing from, so each file must be replaced atomically: the full copy +
// chmod + re-sign sequence targets a same-dir temp file and only a successful
// sequence renames it over the destination.  These tests pin both halves of
// that contract: a mid-sequence failure must leave the old generation byte-
// identical (and no temp litter), and a successful restage must never have
// codesigned the destination path directly.

describe('provisionNodeMac — atomic shim restage', () => {
  it('failed shim re-sign leaves the live destination byte-identical and no temp leftovers', async () => {
    const dir = tempDir();
    const first = await provisionNodeMac(makeInput(dir, makeFakeRunCommand()));

    // An old but VALID generation is live at both destinations.
    writeFileSync(join(first.shellShimDir, 'bash'), 'old-valid-bash-sentinel');
    writeFileSync(join(first.shellShimDir, 'coreutils'), 'old-valid-coreutils-sentinel');

    // The restage's ad-hoc SIGN step fails for shim-dir files (mid-sequence:
    // --remove-signature on the temp already succeeded).  The node fast-path
    // `codesign --verify` matches neither condition and still succeeds.
    const fake2 = makeFakeRunCommand({
      failCodesignWhen: (args) =>
        args.includes('--sign') && args[args.length - 1]!.includes('/shell-shim/'),
    });
    await expect(provisionNodeMac(makeInput(dir, fake2)))
      .rejects.toThrow(/codesign .* failed with exit 1/);

    // The destinations were NEVER touched — not truncated, not half-replaced —
    // and the failed temp file was cleaned up (no *.tmp litter for the shim's
    // fixed-name redirect dir).
    expect(readFileSync(join(first.shellShimDir, 'bash'), 'utf8'))
      .toBe('old-valid-bash-sentinel');
    expect(readFileSync(join(first.shellShimDir, 'coreutils'), 'utf8'))
      .toBe('old-valid-coreutils-sentinel');
    expect(readdirSync(first.shellShimDir).sort()).toEqual(['bash', 'coreutils']);
  });

  it('restage codesigns the temp path (never the destination) and the live file only transitions old → new', async () => {
    const dir = tempDir();
    const first = await provisionNodeMac(makeInput(dir, makeFakeRunCommand()));
    const destBash = join(first.shellShimDir, 'bash');
    const destCoreutils = join(first.shellShimDir, 'coreutils');
    writeFileSync(destBash, 'old-valid-bash-sentinel');

    // Snapshot the LIVE bash destination at every codesign call: it must only
    // ever hold a complete generation (old sentinel or new source bytes).
    const fake2 = makeFakeRunCommand();
    const liveBashSnapshots: string[] = [];
    const wrapped: NonNullable<ProvisionNodeMacInput['runCommand']> = (cmd, args, runOpts) => {
      if (cmd === 'codesign') liveBashSnapshots.push(readFileSync(destBash, 'utf8'));
      return fake2.run(cmd, args, runOpts);
    };
    await provisionNodeMac(makeInput(dir, fake2, { runCommand: wrapped }));

    // Every restage codesign targeted a uniquely-named SAME-DIR temp file,
    // never the live destination.
    const shimCodesigns = fake2.calls.filter(
      (c) => c.cmd === 'codesign' && c.args[c.args.length - 1]!.includes('/shell-shim/'),
    );
    expect(shimCodesigns).toHaveLength(6);
    for (const call of shimCodesigns) {
      const target = call.args[call.args.length - 1]!;
      expect(target).toMatch(/\/\.(bash|coreutils)\.\d+\.\d+\.tmp$/);
      expect(target).not.toBe(destBash);
      expect(target).not.toBe(destCoreutils);
    }
    // The sign step pins the identifier to the FINAL basename (codesign would
    // otherwise infer it from the temp filename).
    const signs = shimCodesigns.filter((c) => c.args.includes('--sign'));
    expect(signs.map((c) => c.args[c.args.indexOf('--identifier') + 1]))
      .toEqual(['bash', 'coreutils']);
    // The live file only ever held complete generations, transitioning
    // old-bytes → new-bytes exactly once (no truncated intermediate state).
    // bash is renamed into place before the coreutils restage, so the
    // transition lands strictly inside the snapshot sequence.
    const firstNew = liveBashSnapshots.indexOf('fake-bash');
    expect(firstNew).toBeGreaterThan(0);
    expect(liveBashSnapshots.slice(0, firstNew)
      .every((s) => s === 'old-valid-bash-sentinel')).toBe(true);
    expect(liveBashSnapshots.slice(firstNew)
      .every((s) => s === 'fake-bash')).toBe(true);
    // Post-success: destinations carry the bundled source bytes, temp gone.
    expect(readFileSync(destBash, 'utf8')).toBe('fake-bash');
    expect(readFileSync(destCoreutils, 'utf8')).toBe('fake-coreutils');
    expect(readdirSync(first.shellShimDir).sort()).toEqual(['bash', 'coreutils']);
  });
});

// ---------------------------------------------------------------------------
// provisionNodeMac — pre-trust env threading (codex round-5 [critical])
// ---------------------------------------------------------------------------
//
// Provisioning runs ON THE HOST before any audit trust gate.  The module is
// policy-agnostic: the caller (mac-bare backend) hands it a SANITIZED `env`, and
// provisionNodeMac must thread THAT env to every host spawn — vp, corepack, and
// the bare-name `tar`/`codesign`/`xattr` system tools — never reaching for
// `process.env` itself.  If it leaked the raw runner env, a checkout-prepended
// PATH could shadow a PR-committed `tar`/`codesign`/`xattr` and an inherited
// NODE_OPTIONS/DYLD_* could inject into the Node-based vp/corepack pre-trust.

describe('provisionNodeMac — threads the injected env to every host spawn', () => {
  it('every spawn (incl. the now-seam-routed xattr) gets input.env, not process.env', async () => {
    const dir = tempDir();
    const inner = makeFakeRunCommand();
    const captured: Array<{ cmd: string; args: string[]; env: NodeJS.ProcessEnv | undefined }> = [];
    // SENTINEL is absent from the real process.env, so its presence in a spawn's
    // env PROVES the call used the injected env, not an inherited process.env.
    const SENTINEL = 'SJ_PROVISION_ENV_SENTINEL';
    const run: NonNullable<ProvisionNodeMacInput['runCommand']> = (cmd, args, opts = {}) => {
      captured.push({ cmd, args, env: opts.env });
      return inner.run(cmd, args, opts);
    };
    const input = makeInput(dir, inner, {
      runCommand: run,
      env: { [SENTINEL]: '1', PATH: '/usr/bin:/bin' },
    });

    await provisionNodeMac(input);

    const tar = captured.filter((c) => c.cmd === 'tar');
    const vp = captured.filter((c) => c.args[0] === 'env' && c.args[1] === 'install');
    const corepack = captured.filter((c) => c.args[0] === 'enable');
    const codesign = captured.filter((c) => c.cmd === 'codesign');
    const xattr = captured.filter((c) => c.cmd === 'xattr');

    expect(tar.length).toBeGreaterThan(0);
    expect(vp.length).toBeGreaterThan(0);
    expect(corepack.length).toBeGreaterThan(0);
    expect(codesign.length).toBeGreaterThan(0);
    // xattr is now routed through the runCommand seam (was a raw spawnSync), so
    // it is BOTH observable here AND receives the sanitized env.
    expect(xattr.length).toBeGreaterThan(0);

    for (const c of [...tar, ...vp, ...corepack, ...codesign, ...xattr]) {
      expect(c.env?.[SENTINEL]).toBe('1');
    }
    // corepack PATH prepends nodeBinDir to the INJECTED PATH (/usr/bin:/bin), so
    // the system dirs survive and no raw inherited PATH segment creeps in.
    expect(corepack[0]!.env?.['PATH']).toMatch(/:\/usr\/bin:\/bin$/);
  });

  it('an empty inherited PATH never becomes a trailing cwd segment ([F3] codex round-6)', async () => {
    const dir = tempDir();
    const inner = makeFakeRunCommand();
    const captured: Array<{ cmd: string; args: string[]; env: NodeJS.ProcessEnv | undefined }> = [];
    const run: NonNullable<ProvisionNodeMacInput['runCommand']> = (cmd, args, opts = {}) => {
      captured.push({ cmd, args, env: opts.env });
      return inner.run(cmd, args, opts);
    };
    // PATH='' is what stripDangerousEnv would never now emit, but provisioning
    // must self-defend: corepack's PATH must NOT end with ':' (a zero-length
    // entry = cwd search) — it falls back to a trusted system PATH instead.
    const input = makeInput(dir, inner, { runCommand: run, env: { PATH: '' } });

    await provisionNodeMac(input);

    const corepack = captured.find((c) => c.args[0] === 'enable');
    expect(corepack).toBeDefined();
    const path = corepack!.env?.['PATH'] ?? '';
    expect(path.endsWith(':')).toBe(false);
    expect(path.endsWith('/usr/bin:/bin:/usr/sbin:/sbin')).toBe(true);
    // nodeBinDir (== dirname of the corepack cmd) is prepended ahead of it.
    const nodeBinDir = corepack!.cmd.slice(0, corepack!.cmd.lastIndexOf('/'));
    expect(path.startsWith(`${nodeBinDir}:`)).toBe(true);
  });
});

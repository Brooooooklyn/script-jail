// script-jail — test/e2e/mac-parity.test.ts
//
// Two macOS-guarded parity suites:
//
//  1. VZ host-runner parity (describe.runIf(isMac && kernel+rootfs present)) —
//     drives the macOS VZ CLI against committed fixtures and compares the
//     produced `.script-jail.lock.yml` to the Linux-CI golden.  Needs the VZ
//     kernel + rootfs artifacts on the host; still an `it.todo` scaffold until
//     the integration harness can boot script-jail-vm against committed
//     fixtures.  KEPT as-is (the committed VZ fixture path the parity workflow
//     relies on).
//
//  2. macOS-bare fake-orchestrator parity (describe.runIf(isMac &&
//     macBareArtifactsPresent)) — exercises the macOS-bare event pipeline
//     WITHOUT a real install or VM.  It injects a FAKE orchestrator: a canned
//     StraceRunner that replays a hand-written shim JSONL sequence (the exact
//     wire format the Mach-O shim + env-spy emit), drives the real
//     `runInstallPhaseMacos` dispatcher → frames → `normalize(os:'darwin')` →
//     `render`, and asserts the rendered lockfile reconciles with the
//     equivalent Linux lockfile after `scripts/parity-diff.ts` canonicalization
//     (the SAME gate parity-test.yml runs in CI).  This mirrors the
//     StraceRunner test-impl seam used throughout test/guest/phase-install.ts;
//     it never spawns a real install and never loads the dylib.
//
// We intentionally use `describe.runIf` rather than guarding every `it` —
// vitest reports the whole describe as "skipped" with the parent name, which
// is the most informative outcome when the host is not a Mac / artifacts are
// absent.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { resolveArtifacts } from '../../src/shared/artifacts.js';
import { runInstallPhaseMacos } from '../../src/guest/phase-install-macos.js';
import type { StraceRunner, LineSource } from '../../src/guest/phase-install.js';
import { Emitter } from '../../src/guest/emit.js';
import { Attribution } from '../../src/guest/attribution.js';
import type { ProcReader } from '../../src/guest/attribution.js';
import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';
import type { AttributedEvent, PackageBlock } from '../../src/lock/schema.js';

const isMac = process.platform === 'darwin';
const repoRoot = process.cwd();
const hostArch: 'x64' | 'arm64' = process.arch === 'arm64' ? 'arm64' : 'x64';

const artifacts = resolveArtifacts({
  repoRoot,
  hostArch,
  ubuntuMajor: '24.04',
});

// ---------------------------------------------------------------------------
// Suite 1 — VZ host-runner parity (kernel + rootfs gated).  Unchanged.
// ---------------------------------------------------------------------------

const kernelPresent = existsSync(artifacts.kernelPath);
const rootfsPresent = existsSync(artifacts.rootfsPath);
const canRunVz = isMac && kernelPresent && rootfsPresent;

if (!canRunVz) {
  // Diagnostic so the vitest output explains why the suite is skipped — far
  // more useful than the default "no tests to run".  Emitted at import time
  // so it shows up before the describe-skip.
  // eslint-disable-next-line no-console
  console.warn(
    '[mac-parity:vz] suite skipped: ' +
      (!isMac
        ? `host is ${process.platform}, not darwin`
        : !kernelPresent
          ? `kernel artifact missing at ${artifacts.kernelPath}`
          : `rootfs artifact missing at ${artifacts.rootfsPath} (run \`pnpm build --runner-image=ubuntu-24.04${hostArch === 'arm64' ? ' --arch=arm64' : ''}\` to produce it)`),
  );
}

describe.runIf(canRunVz)('macOS VZ host runner parity', () => {
  // Each fixture below has a Linux-CI golden in test/fixtures/<name>/
  // expected-events.json; the parity test confirms the macOS CLI produces
  // the same lockfile. Filled in once the integration harness can execute
  // script-jail-vm against committed fixtures.

  it.todo(
    'reads-secret-env fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'tries-dlopen fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'reads-home-ssh fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'tries-network-egress fixture: produces lockfile byte-equal to Linux-CI golden',
  );
});

// ---------------------------------------------------------------------------
// Suite 2 — macOS-bare fake-orchestrator parity (dylib gated).
// ---------------------------------------------------------------------------

const macShimDylibPresent = existsSync(artifacts.macShimDylibPath);
const canRunBare = isMac && macShimDylibPresent;

if (isMac && !canRunBare) {
  // eslint-disable-next-line no-console
  console.warn(
    `[mac-parity:bare] suite skipped: Mach-O shim missing at ${artifacts.macShimDylibPath} ` +
      '(run `pnpm build` on an Apple Silicon mac, or fetch the release dylib).',
  );
}

// Tokenize roots the macOS orchestrator passes for a bare run: $HOME / $TMPDIR
// (realpath) / pnpm cache.  Mirrors the Linux roots so a tokenized path is
// byte-identical cross-OS (the whole point of the one-lock reconciliation).
const ROOTS = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/Users/runner',
  tmp: '/tmp',
  cache: '/Users/runner/.cache/pnpm',
};

const PKG_ID = 'evil-pkg@1.0.0';
const PKG_DIR = '/work/node_modules/evil-pkg';
const INSTALL_PID = 100;

/** A ProcReader that yields null for every pid — the macOS contract. */
const NULL_PROC_READER: ProcReader = {
  readPpid() { return null; },
  readEnviron() { return null; },
};

/**
 * A StraceRunner that replays pre-canned shim JSONL records.  Mirrors the
 * `cannedStraceRunner` seam in test/guest/phase-install.ts but pins every line
 * to `source:'shim'` — on macOS the Mach-O shim is the sole event source, so
 * `runInstallPhaseMacos` only ever sees 'shim' lines.
 */
function cannedShimRunner(lines: string[]): StraceRunner {
  return {
    async *run(): AsyncIterable<{ pid: number; line: string; source: LineSource }> {
      for (const line of lines) {
        const pid = (JSON.parse(line) as { pid: number }).pid;
        yield { pid, line, source: 'shim' };
      }
    },
    getExitCode() { return 0; },
    getTamperReason() { return null; },
    recordTamper() { /* canned runner: no events file to audit */ },
    getRootPid() { return null; },
  };
}

/**
 * Drive `runInstallPhaseMacos` against a canned shim JSONL sequence and collect
 * the emitted AttributedEvents (same frame shape `agent.ts` writes).
 */
async function collectMacosFrames(lines: string[]): Promise<AttributedEvent[]> {
  const collected: AttributedEvent[] = [];
  const pt = new PassThrough();
  pt.on('data', (chunk: Buffer) => {
    for (const l of chunk.toString().split('\n')) {
      if (!l.trim()) continue;
      const parsed = JSON.parse(l) as Record<string, unknown>;
      if (parsed['kind'] === 'event') {
        collected.push({
          raw: parsed['raw'] as AttributedEvent['raw'],
          pkg: parsed['pkg'] as string,
          lifecycle: parsed['lifecycle'] as AttributedEvent['lifecycle'],
        });
      }
    }
  });

  await runInstallPhaseMacos({
    manager: 'pnpm',
    cwd: '/work',
    env: { PATH: '/usr/bin' },
    strace: cannedShimRunner(lines),
    attribution: new Attribution(NULL_PROC_READER),
    emitter: new Emitter(pt),
  });

  return collected;
}

function renderLock(packages: Map<string, PackageBlock>): string {
  return render({
    manager: 'pnpm',
    manager_lockfile_sha256: '',
    node_version: '24.15.0',
    generated_at: '2026-06-07T00:00:00.000Z',
    packages,
  });
}

/**
 * Run scripts/parity-diff.ts as a subprocess — the SAME entry point
 * parity-test.yml invokes — over two lockfile paths.  Returns the exit status
 * (0 = parity holds after canonicalization, 1 = diverged).
 */
function runParityDiff(left: string, right: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    join(repoRoot, 'node_modules/.bin/oxnode'),
    [
      join(repoRoot, 'scripts/parity-diff.ts'),
      '--left', left,
      '--right', right,
      '--left-label', 'linux',
      '--right-label', 'macos-bare',
    ],
    { cwd: repoRoot, encoding: 'utf8', timeout: 30_000 },
  );
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

describe.runIf(canRunBare)('macOS bare fake-orchestrator parity', () => {
  // A canned shim JSONL sequence for one synthetic postinstall on `evil-pkg`:
  //   - exec `node` carrying the in-process npm lifecycle env → seeds
  //     attribution for pid 100 AND begins the Node-bootstrap window.
  //   - node_startup_done → ends the bootstrap window (drops Node's own
  //     bootstrap reads) so the escaped events below surface.
  //   - a hidden env_read of NPM_TOKEN  → `<HIDDEN> NPM_TOKEN`.
  //   - a write outside the package dir → an escaped write.
  //   - a read of a dyld system framework → dropped by the darwin noise filter.
  //   - a connect attempt → recorded WITHOUT a prefix on macOS (online,
  //     observe-only); the Linux side records `<BLOCKED>` (offline Phase B).
  const SHIM_LINES = [
    JSON.stringify({
      kind: 'exec', prog: '/usr/local/bin/node', argv0: 'node',
      envp_alloc_failed: false, pid: INSTALL_PID, ts: 1,
      npm_package_name: 'evil-pkg', npm_package_version: '1.0.0',
      npm_lifecycle_event: 'postinstall',
    }),
    JSON.stringify({
      kind: 'node_startup_done', pid: INSTALL_PID, ts: 2,
      npm_package_name: 'evil-pkg', npm_package_version: '1.0.0',
      npm_lifecycle_event: 'postinstall',
    }),
    JSON.stringify({ kind: 'env_read', name: 'NPM_TOKEN', pid: INSTALL_PID, ts: 3, hidden: true }),
    JSON.stringify({ kind: 'write', path: '/work/escaped.txt', pid: INSTALL_PID, ts: 4, hidden: false }),
    // macOS-only system noise: a dyld framework read the shim observes during
    // the install.  Must be dropped by normalize(os:'darwin').
    JSON.stringify({ kind: 'read', path: '/System/Library/Frameworks/Foundation.framework/Foundation', pid: INSTALL_PID, ts: 5, hidden: false }),
  ];

  // The connect line differs only in `result` between the two backends.
  const macosConnect = JSON.stringify({ kind: 'connect', host: '198.51.100.7', port: 443, result: 'ok', pid: INSTALL_PID, ts: 6 });
  const linuxConnect = JSON.stringify({ kind: 'connect', host: '198.51.100.7', port: 443, result: 'blocked', pid: INSTALL_PID, ts: 6 });

  const tmpDirs: string[] = [];
  function workspace(): string {
    const dir = mkdtempSync(join(tmpdir(), 'mac-parity-bare-'));
    tmpDirs.push(dir);
    return dir;
  }

  it('macOS-bare frames render a lockfile that reconciles with the Linux golden after parity-diff canonicalization', async () => {
    // --- macOS side: real runInstallPhaseMacos dispatcher, connect=ok --------
    const macosFrames = await collectMacosFrames([...SHIM_LINES, macosConnect]);
    const darwinCtx: NormalizeContext = {
      roots: ROOTS,
      pkgDirs: new Map([[PKG_ID, PKG_DIR]]),
      os: 'darwin',
    };
    const macosLock = renderLock(normalize(macosFrames, darwinCtx));

    // The macOS lock must carry the escaped events and DROP the dyld noise.
    expect(macosLock).toContain('evil-pkg@1.0.0:');
    expect(macosLock).toContain('<HIDDEN> NPM_TOKEN');
    expect(macosLock).toContain('$REPO/escaped.txt');
    expect(macosLock).toContain('connect 198.51.100.7:443');
    expect(macosLock).not.toContain('<BLOCKED>'); // online → no prefix on macOS
    expect(macosLock).not.toContain('Foundation.framework'); // dyld noise dropped

    // --- Linux golden: same logical events, connect=blocked, os:'linux' ------
    // The same frames drive the Linux normalize path; only the connect result
    // (offline Phase B → blocked) and the absence of the macOS noise prefixes
    // differ.  (The dyld read is not a Linux-shaped path, so we omit it from
    // the Linux frame stream — the Linux shim would never observe it.)
    const linuxFrames = await collectMacosFrames([...SHIM_LINES.filter((l) => !l.includes('Foundation.framework')), linuxConnect]);
    const linuxCtx: NormalizeContext = {
      roots: ROOTS,
      pkgDirs: new Map([[PKG_ID, PKG_DIR]]),
      os: 'linux',
    };
    const linuxLock = renderLock(normalize(linuxFrames, linuxCtx));

    // Sanity: the Linux lock records the blocked connect (the faithful
    // per-host signal we do NOT weaken inside normalize).
    expect(linuxLock).toContain('<BLOCKED> connect 198.51.100.7:443');

    // --- Reconcile via parity-diff.ts (the CI gate) --------------------------
    const dir = workspace();
    const leftPath = join(dir, 'linux.yml');
    const rightPath = join(dir, 'macos-bare.yml');
    writeFileSync(leftPath, linuxLock, 'utf8');
    writeFileSync(rightPath, macosLock, 'utf8');

    const diff = runParityDiff(leftPath, rightPath);
    if (diff.status !== 0) {
      // Surface the divergence so a failure is actionable.
      // eslint-disable-next-line no-console
      console.error('[mac-parity:bare] parity-diff stdout:\n' + diff.stdout + '\nstderr:\n' + diff.stderr);
    }
    expect(diff.status).toBe(0);

    rmSync(dir, { recursive: true, force: true });
    tmpDirs.length = 0;
  });
});

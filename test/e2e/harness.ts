// script-jail — test/e2e/harness.ts
//
// Layer 1 end-to-end test harness.  Drives src/main.ts in-process by:
//   1. Materialising a temp consumer project on disk (setUpConsumer).
//   2. Synthesising a partial MainDeps bundle whose fake VsockSession replays
//      one or more fixtures' expected events (fakeVmFactory).
//   3. Calling main() with INPUT_* env vars wired, capturing stdout / stderr /
//      exit code (runMain).
//
// The harness is purely additive: no src/ changes.  Tests that consume it
// supply the fixtures by name; the harness computes the same final-frame YAML
// the production guest agent would emit by running the host's normalize() +
// render() pipeline over the merged expected events.  That keeps host- and
// guest-side rendering byte-identical without coupling the harness to the
// guest implementation.
//
// File lives under test/e2e/ but is NOT picked up by the existing vitest
// projects: their `include` patterns target `*.test.ts`, and harness.ts ends
// in `.ts`.  When the e2e project is wired in a follow-up task it must use
// a glob that excludes this file (e.g. include `test/e2e/**/*.test.ts` only).

import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalize, type NormalizeContext } from '../../src/lock/normalize.js';
import { render } from '../../src/lock/render.js';
import { AttributedEvent, type AttributedEvent as AttributedEventT } from '../../src/lock/schema.js';

import type { GuestFrame, VsockSession } from '../../src/action/firecracker/vsock.js';
import type { VmHandle, FirecrackerApiClient } from '../../src/action/firecracker/launch.js';
import type { OverlayResult } from '../../src/action/firecracker/overlay.js';
import type { MainDeps } from '../../src/main.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type FixtureName =
  | 'reads-home-ssh'
  | 'reads-secret-env'
  | 'spawns-gcc'
  | 'tries-dlopen'
  | 'tries-network-egress'
  | 'writes-into-repo'
  | 'cross-package-tampering';

export interface SetUpConsumerInput {
  pm: 'npm' | 'pnpm' | 'yarn' | 'bun';
  /** Fixtures to declare as file: deps in the consumer's package.json. */
  fixtures: ReadonlyArray<FixtureName>;
  /**
   * Optional lockfile contents.  When provided, written verbatim to the
   * consumer's .script-jail.lock.yml — used by check-* tests to plant a specific
   * committed lockfile.
   */
  committedLockYaml?: string;
}

export interface SetUpConsumerResult {
  /** Absolute path to the consumer dir (in os.tmpdir(); OS auto-cleans). */
  consumerDir: string;
  /** Absolute path to the consumer's .script-jail.lock.yml. */
  lockPath: string;
  /** Absolute path to the consumer's .script-jail.yml config. */
  configPath: string;
}

export interface FakeVmFactoryInput {
  /** Same fixtures as passed to setUpConsumer — drives the event stream. */
  fixtures: ReadonlyArray<FixtureName>;
  /**
   * Optional override of the final YAML.  When omitted, the harness computes
   * it by running normalize() + render() over the merged events.  Pass a
   * specific string when a test needs to replay a tampered final frame.
   */
  finalYamlOverride?: string;
  /**
   * Optional: inject additional GuestFrame frames between fetch_done and
   * install_done.  Used by error-path tests.  Frames are yielded in array
   * order.
   */
  extraFrames?: ReadonlyArray<GuestFrame>;
}

export interface FakeVmFactoryResult {
  /** Partial MainDeps suitable for spreading into runMain({...}). */
  deps: Required<Pick<
    MainDeps,
    | 'validateManifest'
    | 'preFetchArtifacts'
    | 'ensureBinaries'
    | 'makeOverlay'
    | 'launchVm'
    | 'openVsockSession'
    | 'teardown'
  >>;
  /** The YAML the fake guest will send in its `final` frame. */
  finalYaml: string;
  /** Captured calls to sendGo (incremented each invocation). */
  goCount: () => number;
}

export interface RunMainInput {
  consumerDir: string;
  inputs: {
    config: string;
    lock: string;
    mode: 'check' | 'update';
    spoofPlatform?: 'linux' | 'darwin' | 'win32';
    spoofArch?: 'x64' | 'arm64';
    cacheFirecracker?: boolean;
  };
  /** Deps from fakeVmFactory().deps — call sites typically pass exactly this. */
  deps: MainDeps;
}

export interface ExitCalled {
  /** Code passed to process.exit (via the injected exitProcess). */
  code: number;
}

export interface RunMainResult {
  exit: ExitCalled | null;
  /** Stdout captured during the call (write() interceptions). */
  stdout: string;
  /** Stderr captured during the call. */
  stderr: string;
  /** Thrown error if main() rejected without calling exitProcess. */
  error?: unknown;
}

// ---------------------------------------------------------------------------
// Fixture YAML computation
// ---------------------------------------------------------------------------
//
// Mirrors the helpers in test/integration/fixtures.test.ts so the YAML the
// harness's fake guest emits is byte-identical to what the integration test
// already validates per-fixture.  Deliberately COPIED (not imported) from the
// integration test: importing would create a cross-project dependency the
// existing test wasn't designed to support, and the helpers are small enough
// that the duplication has negligible maintenance cost.

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, '..', 'fixtures');

// Realistic in-VM roots.  Must match the values the host would use to build
// the per-package `pkgDirs` map so tokenize() can form $PKG.  Mirrored from
// test/integration/fixtures.test.ts.
const ROOTS = {
  repo: '/work',
  nodeModules: '/work/node_modules',
  home: '/root',
  tmp: '/tmp',
  cache: '/root/.npm',
};

function loadExpectedEvents(fixtureName: string): AttributedEventT[] {
  const path = join(FIXTURES_DIR, fixtureName, 'expected-events.json');
  const raw = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (!Array.isArray(raw)) {
    throw new Error(
      `harness: fixture ${fixtureName} expected-events.json is not an array`,
    );
  }
  return raw.map((ev: unknown, i: number): AttributedEventT => {
    const r = AttributedEvent.safeParse(ev);
    if (!r.success) {
      throw new Error(
        `harness: fixture ${fixtureName}: event[${i}] failed validation: ${JSON.stringify(r.error.issues)}`,
      );
    }
    return r.data;
  });
}

function pkgDirsFor(events: ReadonlyArray<AttributedEventT>): Map<string, string> {
  const out = new Map<string, string>();
  for (const ev of events) {
    if (out.has(ev.pkg)) continue;
    // pkg id is `<name>@<version>`; strip the version to get the install dir.
    const name = ev.pkg.split('@')[0]!;
    out.set(ev.pkg, `${ROOTS.nodeModules}/${name}`);
  }
  return out;
}

function renderFixturesYaml(fixtures: ReadonlyArray<FixtureName>): string {
  const events: AttributedEventT[] = [];
  for (const fx of fixtures) {
    events.push(...loadExpectedEvents(fx));
  }
  const ctx: NormalizeContext = { roots: ROOTS, pkgDirs: pkgDirsFor(events) };
  const packages = normalize(events, ctx);
  return render({
    // The harness consumer fixtures use pnpm-shaped IDs, so we render with
    // manager:'pnpm' regardless of the consumer's pm — the manager field is
    // metadata in the lockfile, not semantically tied to the events here.
    manager: 'pnpm',
    manager_lockfile_sha256: 'deadbeef',
    node_version: '20.19.0',
    generated_at: '2026-05-16T00:00:00Z',
    packages,
  });
}

// ---------------------------------------------------------------------------
// setUpConsumer
// ---------------------------------------------------------------------------

const LOCK_FILES_BY_PM: Readonly<Record<SetUpConsumerInput['pm'], { readonly file: string; readonly contents: (consumerName: string) => string }>> = {
  npm: {
    file: 'package-lock.json',
    contents: (n) =>
      JSON.stringify(
        { name: n, lockfileVersion: 3, requires: true, packages: {} },
        null,
        2,
      ) + '\n',
  },
  pnpm: { file: 'pnpm-lock.yaml', contents: () => '' },
  yarn: { file: 'yarn.lock', contents: () => '' },
  bun: { file: 'bun.lock', contents: () => '' },
};

// Default .script-jail.yml mirrors the canonical repo config.  Kept inline rather
// than read from the repo root so the harness has no implicit dependency on
// the action's own config file shape evolving.  When the canonical defaults
// change, update this string in lockstep with the project root .script-jail.yml.
const DEFAULT_SCRIPT_JAIL_YML = `# script-jail config (test-harness defaults).
protected:
  files:
    - ~/.ssh/**
    - ~/.aws/**
    - ~/.npmrc
    - ~/.netrc
    - ~/.gnupg/**
    - $REPO/.env
    - $REPO/.env.*
  env:
    - NPM_TOKEN
    - NODE_AUTH_TOKEN
    - GITHUB_TOKEN
    - GH_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN
    - SSH_AUTH_SOCK

spoof:
  platform: linux
  arch: x64

node_version: 20
`;

export function setUpConsumer(input: SetUpConsumerInput): SetUpConsumerResult {
  const consumerDir = mkdtempSync(join(tmpdir(), 'script-jail-e2e-'));
  const consumerName = `script-jail-e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // ---- package.json -------------------------------------------------------
  // Use ABSOLUTE `file:` URIs to the fixture dirs — the consumer lives in
  // os.tmpdir(), so any relative `../../test/fixtures/<name>` path would
  // escape into nowhere.  Real consumer projects routinely use absolute
  // `file:` deps for vendored packages, so this matches production shape.
  const dependencies: Record<string, string> = {};
  for (const fx of input.fixtures) {
    dependencies[fx] = `file:${join(FIXTURES_DIR, fx)}`;
  }
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify(
      {
        name: consumerName,
        version: '0.0.0',
        private: true,
        dependencies,
      },
      null,
      2,
    ) + '\n',
    'utf8',
  );

  // ---- PM-specific lockfile ----------------------------------------------
  const lock = LOCK_FILES_BY_PM[input.pm];
  writeFileSync(join(consumerDir, lock.file), lock.contents(consumerName), 'utf8');

  // ---- .script-jail.yml ------------------------------------------------------
  const configPath = join(consumerDir, '.script-jail.yml');
  writeFileSync(configPath, DEFAULT_SCRIPT_JAIL_YML, 'utf8');

  // ---- optional pre-planted lockfile -------------------------------------
  const lockPath = join(consumerDir, '.script-jail.lock.yml');
  if (input.committedLockYaml !== undefined) {
    writeFileSync(lockPath, input.committedLockYaml, 'utf8');
  }

  return { consumerDir, lockPath, configPath };
}

// ---------------------------------------------------------------------------
// fakeVmFactory
// ---------------------------------------------------------------------------

function makeFakeApiClient(): FirecrackerApiClient {
  return {
    put: async () => {},
    patch: async () => {},
  };
}

function makeFakeVmHandle(): VmHandle {
  return {
    pid: 0,
    apiClient: makeFakeApiClient(),
    kill: async () => {},
    waitForExit: async () => 0,
  };
}

function makeFakeOverlay(workDir: string): OverlayResult {
  // The paths returned here are never read by the fakes — `launchVm` and
  // `teardown` are both stubbed.  We point them at workDir so a sloppy fake
  // that did try to stat() them wouldn't blow up on `/dev/null/fake-*`.
  return {
    rootfsCopyPath: join(workDir, 'rootfs.ext4'),
    repoDiskPath: join(workDir, 'repo.ext4'),
    scratchDiskPath: join(workDir, 'scratch.ext4'),
    sjtmpDiskPath: join(workDir, 'sjtmp.ext4'),
    workDir,
    cleanup: async () => {},
  };
}

export function fakeVmFactory(input: FakeVmFactoryInput): FakeVmFactoryResult {
  const events: AttributedEventT[] = [];
  for (const fx of input.fixtures) {
    events.push(...loadExpectedEvents(fx));
  }
  const finalYaml = input.finalYamlOverride ?? renderFixturesYaml(input.fixtures);
  const extraFrames: ReadonlyArray<GuestFrame> = input.extraFrames ?? [];

  let goCallCount = 0;

  const fakeSession: VsockSession = {
    // The async generator yields events → fetch_done → extras → install_done
    // → final, then RETURNS so the `for await` loop in main() exits cleanly
    // and the `finally`-block teardown runs.
    events: (async function* (): AsyncGenerator<GuestFrame, void, undefined> {
      for (const ev of events) {
        yield { kind: 'event', event: ev };
      }
      yield { kind: 'handshake', phase: 'fetch_done' };
      for (const ex of extraFrames) {
        yield ex;
      }
      yield { kind: 'handshake', phase: 'install_done' };
      yield { kind: 'final', yaml: finalYaml };
    })(),
    sendGo: async () => {
      goCallCount += 1;
    },
    close: async () => {},
  };

  // openVsockSession is async (Promise<VsockSession>) per its real signature.
  const fakeOpenVsockSession = async (
    _udsPath: string,
    _port: number,
  ): Promise<VsockSession> => fakeSession;

  // launchVm returns a Promise<VmHandle>.
  const fakeLaunchVm = async (): Promise<VmHandle> => makeFakeVmHandle();

  // makeOverlay returns a Promise<OverlayResult>.  We resolve a workDir under
  // os.tmpdir() so the fake paths look plausible to a casual debugger trace.
  const fakeMakeOverlay = async (): Promise<OverlayResult> => {
    const workDir = mkdtempSync(join(tmpdir(), 'script-jail-fake-overlay-'));
    return makeFakeOverlay(workDir);
  };

  // ensureBinaries returns a Promise<DownloadResult>.  Paths are not opened
  // by anything downstream once launchVm is stubbed, so /dev/null shape is
  // fine here.
  const fakeEnsureBinaries = async () => ({
    firecrackerPath: '/dev/null/fake-fc',
    vmlinuxPath: '/dev/null/fake-vmlinux',
  });

  // No-ops: signatures must accept the real arg shapes so MainDeps type-checks.
  const noopValidateManifest = (_m: unknown): void => {};
  const noopPreFetchArtifacts = async (): Promise<void> => {};
  const noopTeardown = async (): Promise<void> => {};

  // Casts: the production functions carry richer parameter types than the
  // fakes need; the harness explicitly opts in to MainDeps' looser shape.
  const deps: FakeVmFactoryResult['deps'] = {
    validateManifest: noopValidateManifest as unknown as Required<MainDeps>['validateManifest'],
    preFetchArtifacts: noopPreFetchArtifacts as unknown as Required<MainDeps>['preFetchArtifacts'],
    ensureBinaries: fakeEnsureBinaries as unknown as Required<MainDeps>['ensureBinaries'],
    makeOverlay: fakeMakeOverlay as unknown as Required<MainDeps>['makeOverlay'],
    launchVm: fakeLaunchVm as unknown as Required<MainDeps>['launchVm'],
    openVsockSession: fakeOpenVsockSession as unknown as Required<MainDeps>['openVsockSession'],
    teardown: noopTeardown as unknown as Required<MainDeps>['teardown'],
  };

  return {
    deps,
    finalYaml,
    goCount: () => goCallCount,
  };
}

// ---------------------------------------------------------------------------
// runMain
// ---------------------------------------------------------------------------

/** Sentinel thrown by the injected exitProcess so main() short-circuits. */
class ExitCalledSignal extends Error {
  constructor(code: number) {
    super(`ExitCalled(${code})`);
    this.name = 'ExitCalledSignal';
    (this as ExitCalledSignal & { code: number }).code = code;
  }
}

interface ExitCalledSignal {
  code: number;
}

// ---- Environment snapshot helpers -----------------------------------------

const TRACKED_ENV_KEYS: ReadonlyArray<string> = [
  'SCRIPT_JAIL_REPO_DIR',
  'GITHUB_WORKSPACE',
  'INPUT_CONFIG',
  'INPUT_LOCK',
  'INPUT_MODE',
  'INPUT_SPOOF-PLATFORM',
  'INPUT_SPOOF-ARCH',
  'INPUT_CACHE-FIRECRACKER',
  'ImageOS',
  'RUNNER_TEMP',
];

function snapshotEnv(keys: ReadonlyArray<string>): Map<string, string | undefined> {
  const out = new Map<string, string | undefined>();
  for (const k of keys) {
    out.set(k, process.env[k]);
  }
  return out;
}

function restoreEnv(snapshot: Map<string, string | undefined>): void {
  for (const [k, v] of snapshot.entries()) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

// ---- Module import (deferred + guarded) -------------------------------------
//
// src/main.ts has a top-level `main().catch(...)` call that fires the moment
// the module is loaded.  We CANNOT let the default invocation run real work,
// so before the first import we:
//   1. Stub `process.exit` to throw an ExitCalledSignal (caught by main()'s
//      own .catch, which calls exitProcess(1) — also stubbed).
//   2. Suppress stderr writes during the import (the .catch writes the stack
//      trace from the default main() call there).
//   3. Restore both AFTER `await import()` resolves.
//
// We also pre-set env vars so the default invocation falls through quickly
// (parseInputs picks safe defaults; the real launchVm would throw on macOS
// but that throw is captured by the .catch and converted to a stubbed exit).

interface MainModule {
  main: (deps: MainDeps) => Promise<void>;
}

let mainModule: MainModule | null = null;

async function loadMain(): Promise<(deps: MainDeps) => Promise<void>> {
  if (mainModule !== null) return mainModule.main;

  // ---- Pre-import guards --------------------------------------------------
  const origExit = process.exit;
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  const origStdoutWrite = process.stdout.write.bind(process.stdout);

  // Snapshot the env keys we may set so the import can't permanently leak.
  const envSnapshot = snapshotEnv(TRACKED_ENV_KEYS);

  // Stub process.exit so the top-level `.catch(... process.exit(1))` is
  // converted into a thrown sentinel rather than killing the test runner.
  // The throw is swallowed by the awaiting Promise; we ignore that rejection.
  (process as unknown as { exit: (code?: number) => never }).exit = ((
    code?: number,
  ): never => {
    throw new ExitCalledSignal(code ?? 0);
  }) as (code?: number) => never;

  // Mute stdout/stderr during import — the default main() invocation may
  // write a stack trace and we don't want it polluting test output.
  process.stderr.write = (() => true) as typeof process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;

  // Set env so the default main() invocation can't even reach launchVm.
  // INPUT_MODE=invalid_mode_for_harness_import → parseInputs throws → caught
  // by main()'s .catch → stubbed exit.  Whole flow takes microseconds.
  process.env['INPUT_MODE'] = '__script_jail_e2e_harness_load__';

  // Suppress the inevitable unhandled rejection from the default main()'s
  // .catch chain firing the stubbed exit.  We attach the handler BEFORE the
  // import and remove it once microtasks have drained.
  const swallowUnhandled = (reason: unknown): void => {
    if (reason instanceof ExitCalledSignal) return;
    // Anything else we don't recognise — re-emit so a genuine bug isn't lost.
    process.emit('unhandledRejection', reason, Promise.reject(reason));
  };
  process.on('unhandledRejection', swallowUnhandled);

  try {
    mainModule = (await import('../../src/main.js')) as unknown as MainModule;
  } finally {
    // Yield once so the top-level main().catch() Promise chain settles
    // before we restore the global stubs.
    await new Promise<void>((r) => setImmediate(r));

    process.off('unhandledRejection', swallowUnhandled);
    process.stderr.write = origStderrWrite as typeof process.stderr.write;
    process.stdout.write = origStdoutWrite as typeof process.stdout.write;
    (process as unknown as { exit: typeof origExit }).exit = origExit;
    restoreEnv(envSnapshot);
  }

  if (mainModule === null) {
    throw new Error('harness: failed to load src/main.js');
  }
  return mainModule.main;
}

// ---- runMain ---------------------------------------------------------------

export async function runMain(input: RunMainInput): Promise<RunMainResult> {
  const main = await loadMain();

  const envSnapshot = snapshotEnv(TRACKED_ENV_KEYS);

  let stdoutBuf = '';
  let stderrBuf = '';
  const origStdoutWrite = process.stdout.write.bind(process.stdout);
  const origStderrWrite = process.stderr.write.bind(process.stderr);

  // Capture write calls into local buffers.  We accept any of the overloaded
  // signatures of write(buf, [encoding], [cb]) by coercing the first arg.
  const captureStdout = ((chunk: unknown, ...rest: unknown[]): boolean => {
    stdoutBuf +=
      typeof chunk === 'string'
        ? chunk
        : (chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8') : String(chunk));
    // Honour the callback overload form if present.
    const maybeCb = rest[rest.length - 1];
    if (typeof maybeCb === 'function') (maybeCb as (err?: Error | null) => void)();
    return true;
  }) as typeof process.stdout.write;

  const captureStderr = ((chunk: unknown, ...rest: unknown[]): boolean => {
    stderrBuf +=
      typeof chunk === 'string'
        ? chunk
        : (chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8') : String(chunk));
    const maybeCb = rest[rest.length - 1];
    if (typeof maybeCb === 'function') (maybeCb as (err?: Error | null) => void)();
    return true;
  }) as typeof process.stderr.write;

  // ---- Wire env -----------------------------------------------------------
  // src/main.ts:140 prefers SCRIPT_JAIL_REPO_DIR over process.cwd() and
  // GITHUB_WORKSPACE because GitHub Actions silently ignores step-level
  // overrides of GITHUB_WORKSPACE.  The harness keeps GITHUB_WORKSPACE in
  // sync for backwards compatibility with code that still reads it.
  process.env['SCRIPT_JAIL_REPO_DIR'] = input.consumerDir;
  process.env['GITHUB_WORKSPACE'] = input.consumerDir;
  process.env['INPUT_CONFIG'] = input.inputs.config;
  process.env['INPUT_LOCK'] = input.inputs.lock;
  process.env['INPUT_MODE'] = input.inputs.mode;
  if (input.inputs.spoofPlatform !== undefined) {
    process.env['INPUT_SPOOF-PLATFORM'] = input.inputs.spoofPlatform;
  } else {
    delete process.env['INPUT_SPOOF-PLATFORM'];
  }
  if (input.inputs.spoofArch !== undefined) {
    process.env['INPUT_SPOOF-ARCH'] = input.inputs.spoofArch;
  } else {
    delete process.env['INPUT_SPOOF-ARCH'];
  }
  if (input.inputs.cacheFirecracker !== undefined) {
    process.env['INPUT_CACHE-FIRECRACKER'] = String(input.inputs.cacheFirecracker);
  } else {
    delete process.env['INPUT_CACHE-FIRECRACKER'];
  }

  // detectRunnerImage requires ImageOS or a parseable /etc/os-release.  On
  // macOS dev hosts the latter is absent; set ImageOS to ubuntu24 so the
  // harness works on any platform.
  process.env['ImageOS'] = 'ubuntu24';

  // RUNNER_TEMP keeps maybeClearCache + the images-dir build inside a known
  // tmp tree rather than the test runner's RUNNER_TEMP (which may not exist
  // outside CI).
  if (process.env['RUNNER_TEMP'] === undefined || process.env['RUNNER_TEMP'] === '') {
    process.env['RUNNER_TEMP'] = mkdtempSync(join(tmpdir(), 'script-jail-runner-temp-'));
  }

  // ---- Install captures + injected deps -----------------------------------
  process.stdout.write = captureStdout;
  process.stderr.write = captureStderr;

  let exit: ExitCalled | null = null;
  let error: unknown = undefined;

  // exitProcess fake — throws a sentinel so main() short-circuits cleanly.
  const exitProcess: (code: number) => never = (code: number): never => {
    throw new ExitCalledSignal(code);
  };

  try {
    await main({ ...input.deps, exitProcess });
  } catch (e: unknown) {
    if (e instanceof ExitCalledSignal) {
      exit = { code: e.code };
    } else {
      error = e;
    }
  } finally {
    process.stdout.write = origStdoutWrite;
    process.stderr.write = origStderrWrite;
    restoreEnv(envSnapshot);
  }

  const result: RunMainResult = {
    exit,
    stdout: stdoutBuf,
    stderr: stderrBuf,
  };
  if (error !== undefined) result.error = error;
  return result;
}

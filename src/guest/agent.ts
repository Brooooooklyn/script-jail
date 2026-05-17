// script-jail — agent.ts
// Guest orchestrator. Runs inside the Firecracker microVM.
//
// Flow:
//   1. Read + validate /etc/script-jail/config.yml
//   2. Detect package manager from lockfile presence
//   3. Build env dict for child processes
//   4. Connect to host via vsock (or injected Connection in tests)
//   5. Phase A (fetch, network on) → emit handshake "fetch_done"
//   6. Wait for host "go" signal
//   7. Phase B (install, network off, strace) → emit handshake "install_done"
//   8. Normalize + render → emitFinalLockfile
//   9. Exit

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createServer, type Server, type Socket } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import { PassThrough, Writable } from 'node:stream';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

import { Attribution } from './attribution.js';
import { LinuxProcReader } from './proc-reader.js';
import { Emitter } from './emit.js';
import { runFetchPhase, type Spawner } from './phase-fetch.js';
import { runInstallPhase, type StraceRunner } from './phase-install.js';
import { ProtectedPathsMatcher } from './protected-paths.js';
import { normalize, type NormalizeContext } from '../lock/normalize.js';
import { render } from '../lock/render.js';
import type { Readable } from 'node:stream';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

const AgentConfig = z.object({
  protected: z.object({
    files: z.array(z.string()).default([]),
    env: z.array(z.string()).default([]),
  }).default({ files: [], env: [] }),
  spoof: z.object({
    platform: z.enum(['linux', 'darwin', 'win32']).default('linux'),
    arch: z.enum(['x64', 'arm64']).default('x64'),
  }).default({ platform: 'linux', arch: 'x64' }),
  node_version: z.string().default(''),
  manager_lockfile_sha256: z.string().default(''),
  /** Absolute path to the lockfile inside the VM (used to detect manager). */
  lockfile_path: z.string().default(''),
  /** Where packages are installed inside the VM. Default: /work */
  work_dir: z.string().default('/work'),
  /** Log fd number. Default: 3 */
  log_fd: z.number().int().default(3),
  /** Per-package dirs for normalize context, keyed by pkg@version */
  pkg_dirs: z.record(z.string(), z.string()).default({}),
  /** Package manager override. Auto-detected from lockfile if not set. */
  manager: z.enum(['npm', 'pnpm', 'yarn']).optional(),
});

type AgentConfig = z.infer<typeof AgentConfig>;

// ---------------------------------------------------------------------------
// Connection abstraction
// ---------------------------------------------------------------------------

export interface Connection {
  readable: Readable;
  writable: Writable;
  close(): void;
}

/**
 * Production connection via Linux vsock.
 *
 * Node has no native AF_VSOCK support, so the data path in the VM is:
 *   Firecracker -> AF_VSOCK port 10242 (socat in guest, see init.sh)
 *                  -> TCP 127.0.0.1:10243 (this listener)
 *
 * The guest agent LISTENS — Firecracker, via socat, makes the inbound
 * connection — so we open a TCP server on the loopback, await the first
 * (and only) inbound connection, then stop accepting.  Use the static
 * `listen()` factory; the constructor is internal.
 */
export class LinuxVsockConnection implements Connection {
  readonly readable: Readable;
  readonly writable: Writable;
  private readonly sock: Socket;
  private readonly server: Server;

  private constructor(server: Server, sock: Socket) {
    this.server = server;
    this.sock = sock;
    this.readable = sock;
    this.writable = sock;
  }

  /**
   * Bind a TCP listener on 127.0.0.1:<port>, wait for the single inbound
   * connection from the socat AF_VSOCK->TCP bridge, then stop listening
   * (one-shot).  Resolves once the host's connection has been accepted.
   */
  static async listen(port: number): Promise<LinuxVsockConnection> {
    const server = createServer();
    return new Promise<LinuxVsockConnection>((resolve, reject) => {
      const onError = (err: Error): void => {
        server.removeListener('connection', onConnection);
        reject(err);
      };
      const onConnection = (sock: Socket): void => {
        server.removeListener('error', onError);
        // One-shot: stop accepting further connections.  Existing accepted
        // socket stays open; `server.close()` only stops the listener.
        server.close();
        resolve(new LinuxVsockConnection(server, sock));
      };
      server.once('error', onError);
      server.once('connection', onConnection);
      server.listen(port, '127.0.0.1');
    });
  }

  close(): void {
    this.sock.destroy();
    this.server.close();
  }
}

/** In-memory connection for tests. */
export class MemoryConnection implements Connection {
  readonly readable: Readable;
  readonly writable: Writable;

  constructor(readable: Readable, writable: Writable) {
    this.readable = readable;
    this.writable = writable;
  }

  close(): void {
    // Nothing to close for an in-memory stream.
  }
}

// ---------------------------------------------------------------------------
// Production Spawner (Phase A only)
// ---------------------------------------------------------------------------

/** Production spawner wrapping node:child_process.spawn. Used for Phase A only.
 *  Phase B install is driven exclusively by the StraceRunner. */
export class LinuxSpawner implements Spawner {
  async spawn(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: opts.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

      child.on('error', reject);
      child.on('close', (code) => {
        resolve({ exitCode: code ?? 1, stdout, stderr });
      });
    });
  }
}

// ---------------------------------------------------------------------------
// Production StraceRunner
// ---------------------------------------------------------------------------

/**
 * Production strace runner.
 *
 * NOTE (v1 limitation): The production impl uses strace -o <basePath> which
 * writes per-pid files. A complete production impl would tail those files
 * while the traced processes are alive. This skeleton collects strace's own
 * stderr output (diagnostic messages only) and emits no per-pid syscall lines.
 *
 * TODO(v2): Implement per-pid file tailing:
 *   - After spawning strace, watch basePath.* files with inotify/fs.watch.
 *   - Tail each file as it grows, parsing lines and yielding (pid, line).
 *   - Also open fd 3 as a pipe to merge LD_PRELOAD JSONL records.
 *   - Fail the phase if strace itself exits with a non-zero code.
 *   - Use the per-pid file suffix as pid (reliable vs. strace's -P mode).
 */
export class LinuxStraceRunner implements StraceRunner {
  private _exitCode = 0;

  getExitCode(): number {
    return this._exitCode;
  }

  async *run(
    cmd: string,
    args: string[],
    opts: { env: NodeJS.ProcessEnv; cwd: string; basePath: string },
  ): AsyncIterable<{ pid: number; line: string }> {
    // strace -ff: follow forks, write per-pid files <basePath>.<pid>
    const straceArgs = [
      '-ff',
      '-e', 'trace=openat,execve,connect,readlinkat,statx,renameat2,unlinkat,faccessat2',
      '-o', opts.basePath,
      cmd,
      ...args,
    ];

    const collectedLines: string[] = [];

    const child = spawn('strace', straceArgs, {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Collect any strace diagnostic output from stderr.
    // Per-pid syscall lines go to the -o files; this only catches strace errors.
    child.stderr?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) {
        if (line.trim()) collectedLines.push(line);
      }
    });

    await new Promise<void>((resolve) => {
      child.on('close', (code) => { this._exitCode = code ?? 1; resolve(); });
      child.on('error', () => { this._exitCode = 1; resolve(); });
    });

    // TODO(v2): tail per-pid strace output files here instead.
    // For now yield any diagnostic lines collected from stderr.
    const pidMatch = /^(\d+)\s+/;
    for (const line of collectedLines) {
      const m = pidMatch.exec(line);
      const pid = m ? parseInt(m[1] ?? '0', 10) : 0;
      yield { pid, line };
    }
  }
}

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

function detectManager(cwd: string): 'npm' | 'pnpm' | 'yarn' {
  if (existsSync(`${cwd}/pnpm-lock.yaml`)) return 'pnpm';
  if (existsSync(`${cwd}/yarn.lock`)) return 'yarn';
  return 'npm';
}

// ---------------------------------------------------------------------------
// Wait for host "go" signal
// ---------------------------------------------------------------------------

/**
 * Wait for the host to send the exact string "go\n" on the control stream.
 * Rejects on EOF, stream error, or if any line other than "go" is received.
 * This prevents an accidental or malformed control line from advancing the
 * agent to Phase B prematurely.
 *
 * TODO(v2): add a configurable timeout so the agent doesn't hang indefinitely
 * if the host disconnects without sending the signal.
 */
async function waitForGo(readable: Readable): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const rl = createInterface({ input: readable, crlfDelay: Infinity });

    const cleanup = (): void => {
      rl.removeListener('line', onLine);
      rl.removeListener('close', onClose);
      rl.close();
    };

    const onLine = (line: string): void => {
      const trimmed = line.trim();
      if (trimmed === 'go') {
        cleanup();
        resolve();
      } else {
        cleanup();
        reject(new Error(`script-jail agent: unexpected control signal from host: ${JSON.stringify(trimmed)}`));
      }
    };

    const onClose = (): void => {
      cleanup();
      reject(new Error('script-jail agent: host closed connection before sending "go" signal'));
    };

    rl.on('line', onLine);
    rl.on('close', onClose);
    readable.on('error', (err: Error) => {
      cleanup();
      reject(err);
    });
  });
}

// ---------------------------------------------------------------------------
// Build env dict for child processes
// ---------------------------------------------------------------------------

function buildChildEnv(
  baseEnv: NodeJS.ProcessEnv,
  config: AgentConfig,
  protectedEnvFilePath: string,
): NodeJS.ProcessEnv {
  const preloads = [
    '/usr/local/lib/script-jail/dlopen-block.cjs',
    '/usr/local/lib/script-jail/platform-spoof.cjs',
  ];

  return {
    ...baseEnv,
    LD_PRELOAD: '/lib/libscriptjail.so',
    SCRIPT_JAIL_LOG_FD: String(config.log_fd),
    SCRIPT_JAIL_PROTECTED_ENV_FILE: protectedEnvFilePath,
    SCRIPT_JAIL_SPOOF_PLATFORM: config.spoof.platform,
    SCRIPT_JAIL_SPOOF_ARCH: config.spoof.arch,
    NODE_OPTIONS: [
      ...(baseEnv['NODE_OPTIONS'] ? [baseEnv['NODE_OPTIONS']] : []),
      ...preloads.map((p) => `--require=${p}`),
    ].join(' '),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Signature subset of `node:dns.lookup` we actually use: a single hostname
 * argument with a node-style (err, _address) callback.  Exposed as its own
 * type so tests can inject a deterministic fake without depending on the
 * runtime DNS resolver.
 */
export type DnsLookupFn = (
  hostname: string,
  callback: (err: NodeJS.ErrnoException | null) => void,
) => void;

export interface AgentInput {
  configPath?: string;
  connection: Connection;
  /** Used for Phase A (fetch) only. Defaults to LinuxSpawner. */
  spawner?: Spawner;
  /** Used for Phase B (install under strace). Defaults to LinuxStraceRunner. */
  strace?: StraceRunner;
  /**
   * Override for the running Node's version string.  Defaults to
   * `process.version` (e.g. "v20.11.0").  The leading "v" is stripped before
   * being written into the rendered lockfile so the field contains a plain
   * dotted version.  Exposed as an injection seam so tests don't drift across
   * CI Node versions.
   */
  nodeVersion?: string;
  /**
   * Optional override for the DNS lookup used by `verifyOffline()` after the
   * host's `go` signal.  Defaults to `node:dns.lookup`.  Tests inject a fake
   * to deterministically exercise both "lookup fails → offline" and "lookup
   * succeeds → fatal" branches without touching the network.
   */
  dnsLookup?: DnsLookupFn;
  /**
   * Optional override for the guest-side network drop.  Production runs
   * `ip link set eth0 down` (busybox `ip` applet on Ubuntu 22.04/24.04) via
   * the agent's `Spawner`.  Tests inject a stub to assert call ordering and
   * exercise the "command failed" branch without touching the VM's networking.
   */
  dropEth0?: () => Promise<void>;
  /**
   * Per-call override for the DNS-probe timeout in milliseconds.  Defaults
   * to 2000ms.  Exposed primarily so tests can shorten it for the
   * "lookup hangs forever → treated as offline" case.
   */
  verifyOfflineTimeoutMs?: number;
}

/**
 * Confirm Phase B truly has no network by asking the resolver to look up a
 * well-known registry host, with a bounded timeout.  Returns:
 *   - `true`  — lookup failed (e.g. ENOTFOUND / ECONNREFUSED) → network is
 *               disabled as expected, safe to continue.
 *   - `true`  — lookup hung past `timeoutMs` → after we dropped eth0 the
 *               resolver will typically retry until it times out; counting
 *               that as "offline" is correct AND prevents the agent from
 *               stalling forever.
 *   - `false` — lookup succeeded within the timeout → the interface drop did
 *               not take effect and any `connect ok` events in Phase B would
 *               be FALSE NEGATIVES.  Caller MUST abort with a fatal error.
 */
async function verifyOfflineWithTimeout(
  lookup: DnsLookupFn,
  timeoutMs = 2000,
): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    new Promise<boolean>((resolve) => {
      lookup('registry.npmjs.org', (err) => {
        if (timer !== undefined) clearTimeout(timer);
        resolve(err !== null);
      });
    }),
    new Promise<boolean>((resolve) => {
      timer = setTimeout(() => { resolve(true); }, timeoutMs);
    }),
  ]);
}

/**
 * Drop the eth0 network interface from inside the guest using busybox's
 * `ip` applet (present on the Ubuntu 22.04/24.04 rootfs).  Falls back to the
 * traditional `ifconfig eth0 down` for rootfs variants that ship net-tools
 * but no `ip`.
 *
 * Both invocations are best-effort: a missing interface (e.g. a Phase B-only
 * test rig) is non-fatal — `verifyOfflineWithTimeout` is the final gate.
 *
 * Returns the spawn result of whichever command succeeded, or the last
 * failure if neither worked.
 */
async function defaultDropEth0(spawner: Spawner, env: NodeJS.ProcessEnv): Promise<void> {
  const tries: Array<{ cmd: string; args: string[] }> = [
    { cmd: 'ip', args: ['link', 'set', 'eth0', 'down'] },
    { cmd: 'ifconfig', args: ['eth0', 'down'] },
  ];

  let lastErr: Error | null = null;
  for (const { cmd, args } of tries) {
    try {
      const res = await spawner.spawn(cmd, args, { env, cwd: '/' });
      if (res.exitCode === 0) return;
      lastErr = new Error(`${cmd} ${args.join(' ')} exited with code ${res.exitCode}: ${res.stderr}`);
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }
  throw lastErr ?? new Error('script-jail agent: dropEth0 failed for unknown reason');
}

export async function main(input: AgentInput): Promise<void> {
  const configPath = input.configPath ?? '/etc/script-jail/config.yml';

  // 1. Read + validate config
  let rawConfig: unknown;
  try {
    const text = readFileSync(configPath, 'utf8');
    rawConfig = parseYaml(text);
  } catch (err) {
    throw new Error(`script-jail agent: failed to read config at ${configPath}: ${String(err)}`);
  }

  const config = AgentConfig.parse(rawConfig);

  // 2. Build emitter pointing at the vsock connection
  const emitter = new Emitter(input.connection.writable);

  // 3. Detect package manager
  const manager = config.manager ?? detectManager(config.work_dir);

  // 4. Write protected-env file to a temp location
  const protectedEnvPath = '/tmp/script-jail-protected.txt';
  writeFileSync(protectedEnvPath, config.protected.env.join('\n') + '\n', 'utf8');

  // 5. Build child environment
  const childEnv = buildChildEnv(process.env, config, protectedEnvPath);

  // 6. Set up spawner (Phase A) and strace runner (Phase B)
  const spawner: Spawner = input.spawner ?? new LinuxSpawner();
  const straceRunner: StraceRunner = input.strace ?? new LinuxStraceRunner();

  // 7. Attribution (reads /proc; real ProcReader in production)
  const attribution = new Attribution(new LinuxProcReader());

  // 8. Phase A: fetch (network on, no strace)
  const fetchResult = await runFetchPhase({
    manager,
    cwd: config.work_dir,
    env: childEnv,
    spawner,
  });

  if (!fetchResult.ok) {
    emitter.emitError(`Phase A (fetch) failed: ${fetchResult.stderr}`, true);
    input.connection.close();
    process.exit(1);
  }

  emitter.emitHandshake('fetch_done');

  // 9. Wait for host "go" signal (exact string "go\n" required)
  try {
    await waitForGo(input.connection.readable);
  } catch (err) {
    emitter.emitError(String(err), true);
    input.connection.close();
    process.exit(1);
  }

  // 9b. Before verifying offline, drop the eth0 interface from inside the
  //     guest.  We use guest-side control because Firecracker's host-side
  //     rate-limiter API treats `size: 0` as "rate limiter disabled" (i.e.
  //     unlimited), not "no bandwidth" — making host-side disabling a no-op
  //     across versions.  `ip link set eth0 down` (busybox) authoritatively
  //     removes the interface from the routing table.
  //
  //     Failure here (e.g. no eth0 interface on a Phase B-only test rig) is
  //     surfaced as a non-fatal error frame but we continue: the DNS probe
  //     immediately below is the real gate.
  try {
    if (input.dropEth0) {
      await input.dropEth0();
    } else {
      await defaultDropEth0(spawner, childEnv);
    }
  } catch (err) {
    emitter.emitError(
      `script-jail agent: failed to drop eth0 from inside the guest: ${String(err)}`,
      false,
    );
  }

  // 9c. Sanity check: confirm the interface drop actually killed network
  //     access.  If DNS still resolves *within the timeout* the audit would
  //     silently produce false-negative `connect ok` events for any
  //     postinstall script that talks to the network — abort fatally.
  //     A hung lookup is treated as offline (the resolver retries until it
  //     times out once the interface is down).
  //
  //     We `return` after `process.exit(1)` so tests that stub out
  //     `process.exit` don't fall through to Phase B; in production
  //     `process.exit` terminates the process and the return is unreached.
  const lookupFn: DnsLookupFn = input.dnsLookup ?? dnsLookup;
  const offline = await verifyOfflineWithTimeout(
    lookupFn,
    input.verifyOfflineTimeoutMs,
  );
  if (!offline) {
    emitter.emitError(
      'Phase B aborted: DNS still resolves after dropping eth0 — ' +
        'network was not disabled, audit results would be unreliable.',
      true,
    );
    input.connection.close();
    process.exit(1);
    return;
  }

  // 10. Phase B: install (network off, under strace, StraceRunner owns the process)
  const collectedEvents: import('../lock/schema.js').AttributedEvent[] = [];

  // Wrap the emitter to also collect events for normalize.
  const collectingEmitter = new Emitter(
    new (class extends Writable {
      override _write(chunk: Buffer, _enc: string, cb: () => void): void {
        const line = chunk.toString();
        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(line) as Record<string, unknown>;
        } catch {
          // Malformed line from a trusted internal writer — skip silently.
          cb();
          return;
        }
        if (frame['kind'] === 'event') {
          // Re-emit to the real emitter
          input.connection.writable.write(line);
          // Collect for normalize
          collectedEvents.push({
            raw: frame['raw'] as import('../lock/schema.js').RawEvent,
            pkg: frame['pkg'] as string,
            lifecycle: frame['lifecycle'] as import('../lock/schema.js').LifecycleStage,
          });
        } else {
          input.connection.writable.write(line);
        }
        cb();
      }
    })()
  );

  // Tokenize roots used by BOTH the install-phase protected-paths matcher and
  // the post-phase normalize step. Defined once so both stages agree on what
  // `$HOME`, `$REPO`, etc. resolve to.
  const roots = {
    repo: config.work_dir,
    nodeModules: `${config.work_dir}/node_modules`,
    home: '/root',
    tmp: '/tmp',
    cache: '/root/.cache/pnpm',
  };

  const protectedPaths = new ProtectedPathsMatcher({
    patterns: config.protected.files,
    roots,
  });

  const installResult = await runInstallPhase({
    manager,
    cwd: config.work_dir,
    env: childEnv,
    strace: straceRunner,
    attribution,
    emitter: collectingEmitter,
    straceBasePath: '/tmp/script-jail-strace/strace.out',
    protectedPaths,
  });

  // 11. If install failed, emit error and abort — do NOT emit a final lockfile
  //     for a failed install, which would give the host a partial/untrusted artifact.
  if (installResult.exitCode !== 0) {
    emitter.emitError(
      `Phase B (install) failed with exit code ${installResult.exitCode}`,
      true,
    );
    input.connection.close();
    process.exitCode = installResult.exitCode;
    return;
  }

  emitter.emitHandshake('install_done');

  // 12. Normalize + render
  const pkgDirs = new Map(Object.entries(config.pkg_dirs));

  const ctx: NormalizeContext = { roots, pkgDirs };

  let yaml: string;
  try {
    const packages = normalize(collectedEvents, ctx);

    // Compute lockfile SHA256 if path is known.
    let sha256 = config.manager_lockfile_sha256;
    if (!sha256 && config.lockfile_path) {
      try {
        const lockfileContent = readFileSync(config.lockfile_path);
        sha256 = createHash('sha256').update(lockfileContent).digest('hex');
      } catch {
        sha256 = '';
      }
    }

    // Task #12: the lockfile's `node_version` reflects the Node binary the
    // audit *actually ran against* — i.e. the runner's Node, packed onto the
    // host-node disk and mounted at /opt/host-node.  We source it from the
    // running process (process.version, e.g. "v20.11.0") and strip the
    // leading "v" for canonical YAML output.  `config.node_version` is
    // retained in the schema for backwards compatibility but no longer
    // authoritative.
    const rawNodeVersion = input.nodeVersion ?? process.version;
    const nodeVersion = rawNodeVersion.replace(/^v/, '');

    yaml = render({
      manager,
      manager_lockfile_sha256: sha256,
      node_version: nodeVersion,
      generated_at: new Date().toISOString(),
      packages,
    });
  } catch (err) {
    emitter.emitError(`normalize/render failed: ${String(err)}`, true);
    input.connection.close();
    process.exitCode = 1;
    return;
  }

  emitter.emitFinalLockfile(yaml);
  input.connection.close();
}

// ---------------------------------------------------------------------------
// Entrypoint (when run directly)
// ---------------------------------------------------------------------------

const isMain =
  typeof process.argv[1] === 'string' &&
  process.argv[1].endsWith('agent.js');

if (isMain) {
  // Production: `nodeVersion` is intentionally omitted from main()'s input so
  // the renderer captures `process.version` of the running interpreter — which
  // is the host-mounted Node at /opt/host-node, picked up via PATH by init.sh.
  // That's the entire point of the host-Node mount (Task #12).
  //
  // The TCP port here (10243) is the guest-side endpoint of the socat
  // AF_VSOCK<->TCP bridge configured in src/rootfs/init.sh.  The host still
  // talks to Firecracker's UDS at vsock port 10242 (see src/main.ts) — socat
  // listens on AF_VSOCK 10242 inside the VM and forwards to TCP 10243 here.
  LinuxVsockConnection.listen(10243)
    .then((conn) => main({ connection: conn }))
    .catch((err: unknown) => {
      const pt = new PassThrough();
      const em = new Emitter(pt);
      em.emitError(String(err), true);
      process.exit(1);
    });
}

// Re-export PassThrough for use in tests if needed.
export { PassThrough };

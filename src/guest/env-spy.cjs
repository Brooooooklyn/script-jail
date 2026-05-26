// @ts-check
// script-jail — env-spy.cjs
// NODE_OPTIONS=--require preload: replaces process.env with a Proxy that logs
// every read and hides values for names in the protected list.
//
// Why this exists:
//   The LD_PRELOAD env-shim (src/shim/src/lib.rs) wraps libc getenv and
//   secure_getenv.  That catches getenv calls from C code (Node itself, libuv,
//   etc.) but NOT `process.env.X` reads from JavaScript — Node parses
//   environ[] at startup into an in-memory Map and serves all `process.env`
//   access from there without re-entering libc.  Without this preload, the
//   most common attacker pattern (`const tok = process.env.NPM_TOKEN`) is
//   undetectable.
//
// Env vars (resolved at load time, before the Proxy is installed):
//   SCRIPT_JAIL_PROTECTED_ENV_NAMES — comma-separated list of protected
//                                    env-var names.  Names appearing here
//                                    are hidden (the Proxy's `get` returns
//                                    undefined) and the read is logged with
//                                    `hidden: true`.  Entries starting with
//                                    '#' and empty entries are skipped, and
//                                    whitespace around entries is stripped
//                                    (mirrors the Rust shim parser).
//
//                                    Finding 4 (audit-trust): this used to
//                                    be SCRIPT_JAIL_PROTECTED_ENV_FILE
//                                    pointing at /tmp/script-jail-protected.txt;
//                                    a same-UID lifecycle script could
//                                    truncate that file before spawning a
//                                    child and weaken the list.  The Rust
//                                    shim's STICKY_VARS re-injects the env
//                                    var on every exec, so descendants
//                                    cannot strip the list either.
//   SCRIPT_JAIL_LOG_FILE           — preferred sink for JSONL events (one
//                                    line per env access), opened once with
//                                    O_APPEND so concurrent writers don't
//                                    race on file offset.
//   SCRIPT_JAIL_LOG_FD             — legacy fd fallback (used by tests that
//                                    wire a pipe directly via fork()).
//
// SECURITY NOTES:
//   - The Proxy is installed as a non-configurable, non-writable property,
//     so `delete process.env` or `process.env = {}` cannot restore the
//     original.  User code can still construct a new Proxy and replace
//     process.env on a fresh property, but that defeats only its own
//     `process.env.X` reads — by then it's already had a chance to be
//     audited.
//   - The recursion guard (`inLog`) protects against the read inside
//     `resolveLogFd` triggering infinite recursion through the Proxy.
//
// This file is deliberately plain CommonJS (no build step needed).

'use strict';

const fs = require('node:fs');

// Audit-trust Finding 4 (high, 2026-05-18): capture every fs / process
// function reference we depend on AT PRELOAD MODULE LOAD TIME, before any
// lifecycle JS can run.  All subsequent uses must reference these LOCAL
// bindings — never `fs.writeSync` / `process.exit` directly, because those
// are mutable property slots that lifecycle JS can monkeypatch BEFORE
// triggering audit events.
//
// Concrete attack: a lifecycle script that runs `require('fs').writeSync =
// () => {}` (or `process.exit = () => {}`) before reading
// `process.env.NPM_TOKEN` would otherwise neutralise both the env_read
// audit line and the fail-closed exit (`emitAuditFdLostAndExit`) — the
// access would happen invisibly with no record.  By holding the original
// callable references in `const` slots scoped to this module, the
// monkeypatch only affects the public fs.writeSync slot, not our captures.
//
// The `process.exit` capture uses `.bind(process)` because some Node
// internals branch on `this`; binding ensures the call site doesn't have
// to remember to pass the receiver.
const _writeSync = fs.writeSync;
const _openSync = fs.openSync;
const _closeSync = fs.closeSync;
const _processExit = process.exit.bind(process);
const _stderrWrite =
  process.stderr && typeof process.stderr.write === 'function'
    ? process.stderr.write.bind(process.stderr)
    : null;
const NODE_STARTUP_DONE_ENV = 'SCRIPT_JAIL_NODE_STARTUP_DONE';
// LOAD-BEARING: phase-install.ts watches this exact absolute path in the
// per-pid strace stream. The open is intentionally expected to fail with
// ENOENT; the syscall is only a same-pid ordering marker for file-read
// filtering.
const NODE_STARTUP_DONE_STRACE_PATH = '/tmp/script-jail-node-startup-done';

// Idempotency: a single Node process may --require this preload multiple
// times (NODE_OPTIONS inheritance + nested invocations).  Skip re-wrapping
// when we already own process.env in this process.
const SENTINEL = Symbol.for('script-jail.env-spy.installed');
// @ts-expect-error: stamping a Symbol on `process` is fine at runtime.
if (process[SENTINEL]) return;
// @ts-expect-error: stamping a Symbol on `process` is fine at runtime.
process[SENTINEL] = true;

// ── Read protected name list ────────────────────────────────────────────────
// Reads happen on the ORIGINAL process.env (no Proxy yet), so no recursion.
//
// Finding 4 (audit-trust): the list ships inline as a comma-separated env
// var (SCRIPT_JAIL_PROTECTED_ENV_NAMES), captured by the parent agent
// before any audited code runs and re-injected by the Rust shim's
// STICKY_VARS on every exec.  This eliminates the previous /tmp file path
// that same-UID lifecycle scripts could overwrite.  Parsing here matches
// the Rust shim's `load_protect_list_from_bytes` rules: ',' or '\n'
// separators, leading/trailing whitespace stripped, '#'-prefixed and
// empty entries skipped.
const protectedNames = new Set();
{
  const raw = process.env['SCRIPT_JAIL_PROTECTED_ENV_NAMES'];
  if (raw) {
    for (const part of raw.split(/[,\n]/)) {
      const name = part.trim();
      if (!name || name.startsWith('#')) continue;
      protectedNames.add(name);
    }
  }
}

// ── Resolve log destination ONCE, before installing Proxy ────────────────────
// Pre-resolving avoids a recursive Proxy entry from inside the get-handler's
// own logEnvRead implementation.
//
// Audit-trust Finding 4 (2026-05-18): we capture the file PATH separately
// from the cached fd so write failures (EBADF after a malicious lifecycle
// script closes the fd via /proc/self/fd/) can reopen the same file and
// retry.  Without this, an attacker that scans /proc/self/fd for descriptors
// pointing at the events file and `close()`s them would silence every
// subsequent env_read entry from this process — the try/catch below would
// eat the EBADF and the audit trail would be missing exactly the events the
// attacker cared about.
const logFilePath = process.env['SCRIPT_JAIL_LOG_FILE'] || null;
let logFd = -1;
{
  if (logFilePath) {
    try {
      logFd = _openSync(logFilePath, 'a');
    } catch {
      logFd = -1;
    }
  }
  if (logFd < 0) {
    const fdStr = process.env['SCRIPT_JAIL_LOG_FD'];
    if (fdStr) {
      const fd = parseInt(fdStr, 10);
      if (isFinite(fd) && fd >= 0) logFd = fd;
    }
  }
}

/**
 * Emit a single audit_fd_lost env_tamper line and exit non-zero.  Called
 * when the cached events-file fd is closed underneath us AND the reopen
 * retry fails — at that point the audit trail is unrecoverably broken in
 * this process, so the safest action is to stop running and let the agent's
 * post-install normalize/diff pipeline surface this as `audit_bypass` via
 * the env_tamper event (the host-side `findAuditBypass` scan reads
 * audit_bypass + env_tamper from the rendered lockfile and fails the diff).
 *
 * We do NOT route through the Proxy / process.env reads — the line is
 * written via a freshly-opened fd path so even a wholesale fd-table wipe
 * cannot eat this final signal.  If even that open fails, abort with a
 * non-zero exit so the lifecycle script's child sees a hard failure.
 *
 * @param {string} reason — debug detail, surfaced in the JSONL line.
 */
function emitAuditFdLostAndExit(reason) {
  const ts = Number(process.hrtime.bigint() / 1_000_000n);
  const line = JSON.stringify({
    kind: 'env_tamper',
    op: 'audit_fd_lost',
    refused: true,
    reason,
    pid: process.pid,
    ts,
  }) + '\n';
  // Best-effort write via a fresh open: bypasses any cached-fd table the
  // attacker may have tampered with.  If logFilePath is null we lose the
  // event but still exit hard so the user can correlate the missing audit
  // line with a non-zero exit.
  if (logFilePath) {
    try {
      const fd = _openSync(logFilePath, 'a');
      try { _writeSync(fd, line); } catch { /* swallowed; we exit below */ }
      try { _closeSync(fd); } catch { /* swallowed; we exit below */ }
    } catch { /* swallowed; we exit below */ }
  }
  // Write a human-readable line to stderr so an interactive run also
  // surfaces the failure.  process.exit with a non-zero code propagates
  // through npm/pnpm/yarn's lifecycle-script handling to the install
  // command's exit code, which the agent then treats as a fatal install
  // failure.  We use 91 (an uncommon code) so accidentally-overlapping
  // exit codes from user code don't collide with this signal.
  //
  // Finding 4: route through the captured stderr write reference and the
  // captured process.exit reference so a lifecycle script that
  // monkeypatched `process.stderr.write = () => {}` or `process.exit = () => {}`
  // before triggering an audit-loss event cannot silence this final signal.
  if (_stderrWrite !== null) {
    try {
      _stderrWrite(
        `script-jail/env-spy: fatal — cached events-file fd is unusable and reopen failed (${reason}); aborting to avoid silent audit loss\n`,
      );
    } catch { /* ignored */ }
  }
  _processExit(91);
}

/**
 * Write one JSONL audit line to the cached sink.
 *
 * Audit-trust Finding 4 (2026-05-18): on EBADF (or any other write
 * failure that comes from a closed/invalid fd) we re-open the events file
 * by path and retry once.  If the reopen path is unset (logFilePath ===
 * null — only happens in test setups that use SCRIPT_JAIL_LOG_FD without a
 * file path) or the reopen itself fails, we treat the audit chain as
 * unrecoverably broken and emit a fail-closed signal via
 * `emitAuditFdLostAndExit` before exiting non-zero.
 *
 * The recovery is bounded to a SINGLE retry per failed write: if the
 * reopened fd also fails immediately, that is the unrecoverable-tamper
 * path and we exit hard.  This avoids any infinite-retry loop a hostile
 * script could induce by repeatedly re-closing the fd.
 *
 * @param {string} line
 */
function writeAuditLine(line) {
  if (logFd < 0) return;
  try {
    _writeSync(logFd, line);
    return;
  } catch { /* fall through to recovery */ }

  // Recovery only applies to the SCRIPT_JAIL_LOG_FILE branch — that's the
  // production channel and we know the path so we can reopen.  The legacy
  // SCRIPT_JAIL_LOG_FD-only path (used by some unit tests with a pipe fd)
  // has no path to reopen; a write failure there is non-fatal and
  // silently dropped, matching the pre-Finding-4 behaviour.
  if (logFilePath === null) return;

  const oldLogFd = logFd;
  let newFd;
  try {
    newFd = _openSync(logFilePath, 'a');
  } catch (openErr) {
    emitAuditFdLostAndExit(
      `reopen of ${logFilePath} failed: ${
        (openErr && openErr.code) || 'unknown'
      }`,
    );
    return;
  }
  // Codex pass 52 finding 3 (high, 2026-05-19) — fd-slot reuse on
  // EBADF recovery.  When a hostile lifecycle script closes our cached
  // log fd via /proc/self/fd/<N>, the kernel frees fd slot N.  Our
  // immediate writeSync EBADFs; recovery calls openSync(logFilePath,
  // 'a') and the kernel's "lowest free fd" allocator returns slot N
  // (the slot we just lost).  If we then closeSync(oldLogFd) — i.e.
  // closeSync(N) — we close the JUST-OPENED fresh fd, and the retry
  // write fails again with EBADF.  Production hits emitAuditFdLost
  // AndExit and exits 91 even though the recovery succeeded.
  //
  // Fix: detect the slot-reuse case BEFORE the cleanup close.  When
  // `newFd === oldLogFd`, the kernel has already replaced the slot
  // contents with our newly-opened file — no cleanup needed, the slot
  // is live and valid.  In every other case we still close the stale
  // numeric fd defensively (best-effort) to avoid leaking fds when an
  // attacker repeatedly tampers.
  if (newFd !== oldLogFd) {
    try { _closeSync(oldLogFd); } catch { /* ignored */ }
  }
  logFd = newFd;
  try {
    _writeSync(logFd, line);
  } catch (retryErr) {
    emitAuditFdLostAndExit(
      `retry write after reopen failed: ${
        (retryErr && retryErr.code) || 'unknown'
      }`,
    );
  }
}

/**
 * Emit one JSONL env_read line for a single property access.
 *
 * @param {string} name
 * @param {boolean} hidden
 */
function logEnvRead(name, hidden) {
  const ts = Number(process.hrtime.bigint() / 1_000_000n);
  writeAuditLine(JSON.stringify({
    kind: 'env_read',
    name,
    pid: process.pid,
    ts,
    hidden,
  }) + '\n');
}

function signalNodeStartupDone() {
  try {
    // The Rust shim's setenv/putenv wrappers consume this assignment as a
    // process-local signal and do not need the marker to remain visible in
    // the lifecycle environment.
    origEnv[NODE_STARTUP_DONE_ENV] = '1';
    delete origEnv[NODE_STARTUP_DONE_ENV];
  } catch {
    // If the marker cannot be set, the shim keeps the startup filter active.
    // That is fail-quiet for unprotected runtime noise; protected reads are
    // still hidden and reported by the Rust shim.
  }

  try {
    // Make the same boundary visible in the strace channel.  The dispatcher
    // filters same-pid file reads before this marker as Node bootstrap noise.
    const markerFd = _openSync(NODE_STARTUP_DONE_STRACE_PATH, 'r');
    try { _closeSync(markerFd); } catch { /* ignored */ }
  } catch {
    // Expected path: the marker file does not exist.  The failed openat is the
    // signal we need because strace records it in-order with this pid's reads.
  }
}

// ── Install the Proxy ────────────────────────────────────────────────────────
// CRITICAL: when forwarding to `target`, we MUST pass `target` (not the Proxy)
// as the receiver argument to Reflect.get / Reflect.set.  process.env is a
// special "EnvironmentVariableNamespace" object whose property reads are
// implemented as host-side accessors in Node's C++ layer; those accessors use
// `this` (the receiver) to find the underlying environment store.  When the
// receiver is our Proxy instead of the original env, Node can't locate the
// store and reads silently return wrong values, which makes child_process
// spawn fail with no diagnostic output.  Equivalently, `target[prop]` works
// (the legacy member-access form passes `target` as the receiver).
const origEnv = process.env;

const envProxy = new Proxy(origEnv, {
  get(target, prop) {
    // Non-string keys (Symbols, etc.) pass through without logging.
    if (typeof prop !== 'string') {
      return Reflect.get(target, prop, target);
    }
    const hidden = protectedNames.has(prop);
    logEnvRead(prop, hidden);
    if (hidden) return undefined;
    return Reflect.get(target, prop, target);
  },
  set(target, prop, value) {
    return Reflect.set(target, prop, value, target);
  },
  has(target, prop) {
    if (typeof prop === 'string' && protectedNames.has(prop)) return false;
    return Reflect.has(target, prop);
  },
  ownKeys(target) {
    const keys = Reflect.ownKeys(target);
    return keys.filter(
      (k) => typeof k !== 'string' || !protectedNames.has(k),
    );
  },
  getOwnPropertyDescriptor(target, prop) {
    if (typeof prop === 'string' && protectedNames.has(prop)) return undefined;
    return Reflect.getOwnPropertyDescriptor(target, prop);
  },
});

try {
  Object.defineProperty(process, 'env', {
    value: envProxy,
    writable: false,
    configurable: false,
    enumerable: true,
  });
} catch {
  // Some Node builds may have non-configurable process.env (unlikely).
  // Falling through silently is the safest option: the libc env-shim still
  // catches getenv calls from C code, and the absence of the JS Proxy just
  // means a known gap rather than an audit failure.
}

signalNodeStartupDone();

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

const fs = require('fs');

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
let logFd = -1;
{
  const filePath = process.env['SCRIPT_JAIL_LOG_FILE'];
  if (filePath) {
    try {
      logFd = fs.openSync(filePath, 'a');
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
 * Emit one JSONL env_read line for a single property access.
 * @param {string} name
 * @param {boolean} hidden
 */
function logEnvRead(name, hidden) {
  if (logFd < 0) return;
  const ts = Number(process.hrtime.bigint() / 1_000_000n);
  const line = JSON.stringify({
    kind: 'env_read',
    name,
    pid: process.pid,
    ts,
    hidden,
  }) + '\n';
  try {
    fs.writeSync(logFd, line);
  } catch {
    // Logging failure must never affect user code.
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

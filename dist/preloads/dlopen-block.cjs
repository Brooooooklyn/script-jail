// @ts-check
// script-jail — dlopen-block.cjs
// NODE_OPTIONS=--require preload: replaces process.dlopen with a function that
// throws before any native addon can load, and emits a JSONL audit line.
//
// Env vars (checked in order, first match wins):
//   SCRIPT_JAIL_LOG_FILE — absolute path to a JSONL events file. Each call
//                          appends one line via O_APPEND (atomic for writes
//                          smaller than PIPE_BUF on regular files).  Required
//                          in production because npm spawns lifecycle node
//                          processes with `stdio: 'inherit'` which only
//                          propagates fds 0-2 — fd 3 is closed in the child.
//   SCRIPT_JAIL_LOG_FD   — integer fd open for writing; legacy fd-3 path,
//                          kept for tests that wire a pipe directly.
//                          If neither is set, the throw still happens
//                          (no logging).
//
// SECURITY NOTES:
//   - This preload blocks the documented process.dlopen and process.binding APIs.
//     It does NOT — and need not — block internalBinding('process_methods').dlopen
//     because the agent prepends `--no-addons` to NODE_OPTIONS (and to the sticky
//     SCRIPT_JAIL_NODE_OPTIONS the Rust shim re-injects across exec).  --no-addons
//     disables native-addon loading at the V8 level, so even
//     `node --expose-internals` cannot reach a working dlopen via internalBinding.
//     This preload remains as defense-in-depth and as the channel that emits the
//     blocked-attempt events for `process.dlopen` callers that don't trip on the
//     engine flag (e.g. attempts caught before V8 boots the addon loader).
//   - Properties are defined as non-configurable, non-writable to prevent
//     user code from restoring the originals via Object.defineProperty or delete.
//
// This file is deliberately plain CommonJS (no build step needed).

'use strict';

const fs = require('node:fs');

// Audit-trust Finding 4 (high, 2026-05-18): capture every fs / process
// function reference we depend on AT PRELOAD MODULE LOAD TIME, before any
// lifecycle JS can run.  All subsequent uses must reference these LOCAL
// bindings — never `fs.writeSync` / `process.exit` directly, because those
// are mutable property slots that lifecycle JS can monkeypatch BEFORE
// triggering audit events.  See env-spy.cjs for the long-form rationale.
const _writeSync = fs.writeSync;
const _openSync = fs.openSync;
const _closeSync = fs.closeSync;
const _processExit = process.exit.bind(process);
const _stderrWrite =
  process.stderr && typeof process.stderr.write === 'function'
    ? process.stderr.write.bind(process.stderr)
    : null;

// Audit-trust Finding 5 (high, 2026-05-19): snapshot the events-file path
// and fallback fd string AT PRELOAD MODULE LOAD TIME, before lifecycle JS
// can run.  Previously `resolveLogFd` read process.env.SCRIPT_JAIL_LOG_FILE
// on the first dlopen call, which means a lifecycle script could mutate
// `process.env.SCRIPT_JAIL_LOG_FILE = '/dev/null'` (or delete it) before
// triggering its own dlopen attempt and silently redirect the audit signal.
// The dlopen itself is still blocked, but the audit line — which the host-
// side diff uses to surface the attempt — disappears.  Same fix shape as
// env-spy.cjs (commit b56b9975 / Finding 4): bind the originals into local
// `const` slots scoped to this module.
//
// NOTE: we read through the original `process.env` here.  At preload module
// load time, no other preload has installed a Proxy yet (the agent orders
// --require so dlopen-block runs before env-spy), so this read is a normal
// host-side environment access and cannot be redirected through user JS.
const _logFilePath = process.env['SCRIPT_JAIL_LOG_FILE'] || '';
const _logFdRaw = process.env['SCRIPT_JAIL_LOG_FD'] || '';

const BLOCKED_MSG = 'script-jail: native addons are blocked at install time';

/**
 * Cached fd for the events file.  Resolved lazily on first call; -1 means
 * "tried and failed" (don't retry).  Module-local, shared across all logDlopen
 * invocations in this process.
 *
 * Audit-trust Finding 4 (2026-05-18): we additionally remember the file
 * PATH (cachedFilePath) so that on EBADF (a lifecycle script close()'d our
 * fd via /proc/self/fd/) the next logDlopen call can reopen by path and
 * retry once.  Without the reopen, an attacker that closes the fd silences
 * every subsequent dlopen audit event from this process.
 * @type {number | null}
 */
let cachedFileFd = null;
/** @type {string | null} */
let cachedFilePath = null;

/**
 * Resolve the output fd for this process.  Prefers SCRIPT_JAIL_LOG_FILE (one
 * append-mode open per process, cached); falls back to SCRIPT_JAIL_LOG_FD.
 *
 * Finding 5: both env vars are captured at module load into `_logFilePath`
 * / `_logFdRaw`; this function MUST NOT read `process.env.SCRIPT_JAIL_*`
 * directly, or a lifecycle script that mutates those slots before its own
 * dlopen attempt can redirect (or null out) the audit destination.
 *
 * @returns {number} fd to write to, or -1 if no destination is configured
 */
function resolveLogFd() {
  if (_logFilePath !== '') {
    cachedFilePath = _logFilePath;
    if (cachedFileFd !== null) return cachedFileFd;
    try {
      cachedFileFd = _openSync(_logFilePath, 'a');
    } catch {
      cachedFileFd = -1;
    }
    return cachedFileFd;
  }
  if (_logFdRaw === '') return -1;
  const fd = parseInt(_logFdRaw, 10);
  if (!isFinite(fd) || fd < 0) return -1;
  return fd;
}

/**
 * Emit a fail-closed env_tamper signal and exit non-zero.  Called when the
 * cached events-file fd is unusable AND the reopen retry fails — at that
 * point the audit trail is unrecoverably broken in this process, so the
 * safest action is to stop running and let the agent's post-install
 * normalize/diff pipeline surface this as `audit_bypass` via the
 * env_tamper event.  Matches the symmetric behaviour in env-spy.cjs.
 *
 * @param {string} reason
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
  if (cachedFilePath) {
    try {
      const fd = _openSync(cachedFilePath, 'a');
      try { _writeSync(fd, line); } catch { /* ignored */ }
      try { _closeSync(fd); } catch { /* ignored */ }
    } catch { /* ignored */ }
  }
  // Finding 4: route through the captured stderr write reference and
  // captured process.exit reference so a lifecycle script that monkeypatched
  // `process.stderr.write` or `process.exit` before triggering an
  // audit-loss event cannot silence this final signal.
  if (_stderrWrite !== null) {
    try {
      _stderrWrite(
        `script-jail/dlopen-block: fatal — cached events-file fd is unusable and reopen failed (${reason}); aborting to avoid silent audit loss\n`,
      );
    } catch { /* ignored */ }
  }
  _processExit(91);
}

/**
 * Write a JSONL audit line to the resolved log destination.
 *
 * Audit-trust Finding 4 (2026-05-18): on write failure (e.g. EBADF after a
 * lifecycle script closed our cached fd), we re-open the events file by
 * path and retry once.  If the path is unknown (only SCRIPT_JAIL_LOG_FD
 * was set) or the reopen itself fails, we treat the audit chain as
 * unrecoverably broken and exit non-zero via emitAuditFdLostAndExit so
 * the agent's post-install gate aborts before producing a misleadingly-
 * clean lockfile.
 *
 * @param {string} filename
 */
function logDlopen(filename) {
  const fd = resolveLogFd();
  if (fd < 0) return;

  const ts = Number(process.hrtime.bigint() / 1_000_000n);
  const line = JSON.stringify({
    kind: 'dlopen',
    filename,
    result: 'blocked',
    pid: process.pid,
    ts,
  }) + '\n';

  let firstErr;
  try {
    _writeSync(fd, line);
    return;
  } catch (err) {
    firstErr = err;
  }

  // Recovery only applies to the SCRIPT_JAIL_LOG_FILE branch — that's the
  // production channel and we know the path so we can reopen.  Tests (and
  // the legacy code path) use SCRIPT_JAIL_LOG_FD pointing at a pipe / a
  // possibly-bogus fd; for those callers a write failure is non-fatal
  // (matching the pre-Finding-4 behaviour) so we silently swallow.
  if (cachedFilePath === null) {
    // Legacy SCRIPT_JAIL_LOG_FD path; no file to reopen.  Logging failure
    // here must never affect user code.
    return;
  }
  let newFd;
  try {
    newFd = _openSync(cachedFilePath, 'a');
  } catch (openErr) {
    emitAuditFdLostAndExit(
      `reopen of ${cachedFilePath} failed: ${
        (openErr && openErr.code) || 'unknown'
      }`,
    );
    return;
  }
  if (cachedFileFd !== null && cachedFileFd >= 0) {
    try { _closeSync(cachedFileFd); } catch { /* ignored */ }
  }
  cachedFileFd = newFd;
  try {
    _writeSync(newFd, line);
  } catch (retryErr) {
    emitAuditFdLostAndExit(
      `retry write after reopen failed: ${
        (retryErr && retryErr.code) || 'unknown'
      }`,
    );
  }
}

function blockedDlopen(/** @type {any} */ _module, filename) {
  logDlopen(typeof filename === 'string' ? filename : String(filename));
  throw new Error(BLOCKED_MSG);
}

function blockedBinding(/** @type {string} */ _name) {
  throw new Error(BLOCKED_MSG);
}

// Idempotency guard: if already installed (configurable === false), skip re-install.
// This prevents TypeError when a child process requires this preload a second time
// via NODE_OPTIONS after the parent already applied it.
const dlopenDesc = Object.getOwnPropertyDescriptor(process, 'dlopen');
if (dlopenDesc && dlopenDesc.configurable === false) return;

// Define as non-configurable and non-writable to resist override by user code.
// This prevents `delete process.dlopen` or `process.dlopen = origDlopen` from
// restoring the original. Note: Object.defineProperty itself can still be called
// by code running in the same realm — VM-level enforcement via --no-addons is
// the reliable barrier (see TODO above).
Object.defineProperty(process, 'dlopen', {
  value: blockedDlopen,
  writable: false,
  configurable: false,
  enumerable: false,
});

// Defense-in-depth: also block process.binding for native binding access.
// process.binding is an internal Node API that exposes C++ bindings; lifecycle
// scripts should not need it, and blocking it closes an additional escalation path.
Object.defineProperty(process, 'binding', {
  value: blockedBinding,
  writable: false,
  configurable: false,
  enumerable: false,
});

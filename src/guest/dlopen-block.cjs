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
//     It does NOT block internalBinding('process_methods').dlopen, which requires
//     --expose-internals to access. To fully prevent native addons, the VM must
//     also enforce --no-addons at the Node launcher level or via seccomp.
//     TODO(v2): Add --no-addons to NODE_OPTIONS in agent.ts to make native addon
//     loading fail at the engine level before reaching any JS preload code.
//   - Properties are defined as non-configurable, non-writable to prevent
//     user code from restoring the originals via Object.defineProperty or delete.
//
// This file is deliberately plain CommonJS (no build step needed).

'use strict';

const fs = require('fs');

const BLOCKED_MSG = 'script-jail: native addons are blocked at install time';

/**
 * Cached fd for the events file.  Resolved lazily on first call; -1 means
 * "tried and failed" (don't retry).  Module-local, shared across all logDlopen
 * invocations in this process.
 * @type {number | null}
 */
let cachedFileFd = null;

/**
 * Resolve the output fd for this process.  Prefers SCRIPT_JAIL_LOG_FILE (one
 * append-mode open per process, cached); falls back to SCRIPT_JAIL_LOG_FD.
 * @returns {number} fd to write to, or -1 if no destination is configured
 */
function resolveLogFd() {
  const filePath = process.env['SCRIPT_JAIL_LOG_FILE'];
  if (filePath !== undefined && filePath !== '') {
    if (cachedFileFd !== null) return cachedFileFd;
    try {
      cachedFileFd = fs.openSync(filePath, 'a');
    } catch {
      cachedFileFd = -1;
    }
    return cachedFileFd;
  }
  const fdStr = process.env['SCRIPT_JAIL_LOG_FD'];
  if (fdStr === undefined || fdStr === '') return -1;
  const fd = parseInt(fdStr, 10);
  if (!isFinite(fd) || fd < 0) return -1;
  return fd;
}

/**
 * Write a JSONL audit line to the resolved log destination.
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

  try {
    fs.writeSync(fd, line);
  } catch {
    // Logging failure must never prevent the throw below.
  }
}

function blockedDlopen(/** @type {any} */ _module, filename) {
  logDlopen(typeof filename === 'string' ? filename : String(filename));
  throw new Error(BLOCKED_MSG);
}

function blockedBinding(/** @type {string} */ _name) {
  throw new Error(BLOCKED_MSG);
}

// Diagnostic: emit a one-shot loaded marker as soon as this preload runs,
// regardless of whether the idempotency guard then short-circuits.  Surfaces
// as an env_read of `__SCRIPT_JAIL_DLOPEN_PRELOAD_LOADED__` in the lockfile
// when the preload is actually being --require'd by Node.  Cheap noise that
// pays for itself: without it, "no dlopen events" could mean either the
// preload didn't load or the wrap didn't fire, and those are very different
// bugs to chase.
try {
  const fd = resolveLogFd();
  if (fd >= 0) {
    const ts = Number(process.hrtime.bigint() / 1_000_000n);
    fs.writeSync(fd, JSON.stringify({
      kind: 'env_read',
      name: '__SCRIPT_JAIL_DLOPEN_PRELOAD_LOADED__',
      pid: process.pid,
      ts,
      hidden: false,
    }) + '\n');
  }
} catch {
  // Diagnostic only — never let logging failure block install.
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

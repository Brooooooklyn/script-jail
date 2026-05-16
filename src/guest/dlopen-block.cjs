// @ts-check
// npm-jar — dlopen-block.cjs
// NODE_OPTIONS=--require preload: replaces process.dlopen with a function that
// throws before any native addon can load, and emits a JSONL audit line.
//
// Env vars:
//   NPM_JAR_LOG_FD — integer fd open for writing; JSONL audit lines go here.
//                    If unset or invalid, the throw still happens (no logging).
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

const BLOCKED_MSG = 'npm-jar: native addons are blocked at install time';

/**
 * Write a JSONL audit line to NPM_JAR_LOG_FD.
 * @param {string} filename
 */
function logDlopen(filename) {
  const fdStr = process.env['NPM_JAR_LOG_FD'];
  if (fdStr === undefined || fdStr === '') return;
  const fd = parseInt(fdStr, 10);
  if (!isFinite(fd) || fd < 0) return;

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

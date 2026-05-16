// npm-jar — src/action/host-node-prefix.ts
//
// Resolves the runner's Node installation prefix from `process.execPath` so the
// host can pack the runner's Node into a small ext4 attached to the VM at
// /opt/host-node (Task #12 — the guest mounts it read-only and prepends its
// `bin` to PATH).
//
// Why this exists:
//   The rootfs no longer bundles a Node binary.  Whichever Node the user's
//   workflow set up (via `actions/setup-node` or a self-hosted runner's pre-
//   installed Node) is the Node the audit runs against.  That keeps results
//   1:1 with what the user shipped in CI.
//
// Validation:
//   `process.execPath` for the action-runner's Node is typically something
//   like `/opt/hostedtoolcache/node/<ver>/x64/bin/node`.  Two `dirname` calls
//   up gives the install prefix (`/opt/.../x64`).  But on a self-hosted runner
//   `execPath` could be `/usr/local/bin/node`, in which case the prefix is
//   `/usr/local` — packing that whole tree would be a disaster.  We refuse to
//   proceed unless one of these signals is true:
//
//     1. The execPath is under `/opt/hostedtoolcache/` (the path
//        `actions/setup-node` plants its Node trees in).
//     2. The prefix contains `include/node/node.h` (Node's C header — only
//        present in a standalone Node install).
//     3. The prefix contains `share/doc/node` (Node's docs dir — also only
//        present in standalone installs).
//
//   If none of those hold, we throw with a message that points the user at
//   `actions/setup-node`, which is the simplest fix.
//
// `fs` is an injection seam so unit tests don't depend on the host's actual
// filesystem layout.

import { existsSync as realExistsSync } from 'node:fs';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface HostNodePrefixFs {
  existsSync(p: string): boolean;
}

// ---------------------------------------------------------------------------
// resolveHostNodePrefix
// ---------------------------------------------------------------------------

const HOSTED_TOOLCACHE_PREFIX = '/opt/hostedtoolcache/';

/**
 * Resolve the runner's Node install prefix from `execPath`.
 *
 * @param execPath - Absolute path to the `node` binary (i.e. `process.execPath`).
 * @param fs - Optional fs seam (defaults to `node:fs.existsSync`).
 * @throws Error if the resolved prefix does not look like a self-contained
 *         Node install — see file-level docs for the validation rules.
 */
export function resolveHostNodePrefix(
  execPath: string,
  fs: HostNodePrefixFs = { existsSync: realExistsSync },
): string {
  // Two dirname calls up: `/opt/.../x64/bin/node` → `/opt/.../x64`.
  const prefix = dirname(dirname(execPath));

  // Signal 1: under hostedtoolcache — actions/setup-node's standard layout.
  if (execPath.startsWith(HOSTED_TOOLCACHE_PREFIX)) {
    return prefix;
  }

  // Signal 2: include/node/node.h — present only in standalone Node installs.
  if (fs.existsSync(join(prefix, 'include', 'node', 'node.h'))) {
    return prefix;
  }

  // Signal 3: share/doc/node — also a standalone-install marker.
  if (fs.existsSync(join(prefix, 'share', 'doc', 'node'))) {
    return prefix;
  }

  throw new Error(
    `npm-jar: process.execPath does not appear to be a self-contained Node install (${execPath}). ` +
    'Use actions/setup-node before calling this action.',
  );
}

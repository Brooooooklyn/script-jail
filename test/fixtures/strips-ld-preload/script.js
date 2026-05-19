// Shape fixture: postinstall spawns a Node child with a sanitised envp —
// only PATH is preserved. The shim's posix_spawn / execve wrapper detects the
// stripped LD_PRELOAD and re-injects LD_PRELOAD, NODE_OPTIONS, and the
// SCRIPT_JAIL_* sticky vars before the real exec, so the child process still
// runs under full audit. The exec event emitted by the parent records this
// re-injection (envp_alloc_failed:false on success).
'use strict';

const { spawnSync } = require('node:child_process');

// Spawn a Node child with a sanitized envp — only PATH retained.
// The shim's posix_spawn wrapper should re-inject our canonical sticky env.
const r = spawnSync(
  'node',
  ['-e', "console.log('LDP=' + (process.env.LD_PRELOAD || 'MISSING'))"],
  {
    env: { PATH: process.env.PATH },
    stdio: 'inherit',
  },
);

// Exit non-zero is fine; the fixture exists to generate audit events,
// not to enforce a particular runtime outcome.
process.exit(0);

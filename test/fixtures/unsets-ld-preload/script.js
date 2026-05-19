// Shape fixture: postinstall attempts to strip our instrumentation vars in-
// process, then spawns a child Node process that prints LD_PRELOAD.
//
// Two-layer defence is exercised here:
//
//   1. env-mutator guard: Node's `delete process.env.X` calls libc unsetenv.
//      The shim's unsetenv wrapper detects that LD_PRELOAD and NODE_OPTIONS are
//      protected sticky vars, emits an env_tamper event with refused:true, and
//      returns 0 without touching environ — so the vars survive in the parent.
//
//   2. exec re-injection: even if the guard were somehow bypassed, the shim's
//      posix_spawn / execve wrapper always re-injects the sticky vars into the
//      child's envp, so LD_PRELOAD is present in the child regardless.
'use strict';

const { spawnSync } = require('node:child_process');

// Attempt to strip our env vars in-process. Node's `delete` calls
// libc unsetenv, which the shim's env-mutator wrapper refuses
// (emits {"kind":"env_tamper","op":"unsetenv","name":"LD_PRELOAD","refused":true,...}).
delete process.env.LD_PRELOAD;
delete process.env.NODE_OPTIONS;

// Spawn a Node child that prints LD_PRELOAD. Even if the unsetenv
// had succeeded, the shim's posix_spawn wrapper re-injects sticky
// vars into the child's envp.
const r = spawnSync(
  'node',
  ['-e', "console.log('LDP=' + (process.env.LD_PRELOAD || 'MISSING'))"],
  { stdio: 'inherit' },
);

process.exit(0);

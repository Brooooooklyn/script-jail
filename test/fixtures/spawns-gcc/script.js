// Shape fixture: postinstall tries to compile native code by execing gcc.
// The rootfs has no gcc binary, so execve("gcc", ...) returns ENOENT from
// the kernel. The audit shim records the attempt; the install continues
// because the catch swallows the spawn error.
const { spawnSync } = require('node:child_process');
try {
  // spawnSync reports ENOENT via the result's `.error` field rather than
  // throwing, but we keep the try/catch defensively in case a future Node
  // changes that contract — the audit signal we care about is the execve
  // attempt, not whether the wrapper threw.
  spawnSync('gcc', ['-c', 'evil.c'], { stdio: 'ignore' });
} catch {
  // Intentionally swallowed.
}

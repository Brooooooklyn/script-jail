// Shape fixture: postinstall tries to compile native code by execing gcc.
// The rootfs has no gcc binary, so execve("gcc", ...) returns ENOENT from
// the kernel. The audit shim records the attempt; the install continues
// because the catch swallows the spawn error.
const { spawnSync } = require('node:child_process');
try {
  spawnSync('gcc', ['-c', 'evil.c'], { stdio: 'ignore' });
} catch {
  // Intentionally swallowed; spawnSync would normally not throw on ENOENT
  // (it sets `.error`), but we cover the throwing path too.
}

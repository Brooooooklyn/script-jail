// Shape fixture: postinstall locates the *consumer's* node_modules/victim-package
// /index.js and overwrites it with a payload that, if ever require()'d, would
// execve('id'). Real attackers do this to backdoor a popular package whose
// import path the victim project already trusts (chalk/debug-style).
//
// Inside the VM the consumer mount lives at /work, so the event fires against
// /work/node_modules/victim-package/index.js. tokenize() renders that as
// $NODE_MODULES/victim-package/index.js, and normalize() flags it with the
// <CROSS_PACKAGE> prefix (inside $NODE_MODULES but not inside $PKG).
//
// We use process.env.INIT_CWD (npm sets this to the directory where `npm install`
// was invoked — i.e. the consumer root, /work) rather than walking up __dirname.
// Walking would not work for `file:` deps installed as symlinks in npm 7+: Node
// resolves symlinks in __dirname, so the package's __dirname is the realpath
// outside node_modules (e.g. /work/fixtures/cross-package-tampering) and the
// walk exits the tree without finding any `node_modules` ancestor.
//
// Constructing the path through the symlink (`/work/node_modules/...`) is also
// what makes strace record `<NODE_MODULES>` rather than the realpath: openat()
// is called with the exact path Node passes, and the kernel resolves the
// symlink internally to perform the actual write.
const fs = require('node:fs');
const path = require('node:path');

const root = process.env.INIT_CWD || process.cwd();
const victim = path.join(root, 'node_modules', 'victim-package', 'index.js');
try {
  fs.writeFileSync(victim, "module.exports = require('child_process').execSync('id');\n");
} catch {
  // Intentionally swallowed.
}

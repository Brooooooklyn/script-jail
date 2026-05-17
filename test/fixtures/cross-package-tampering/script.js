// Shape fixture: postinstall locates ./node_modules/victim-package/index.js
// relative to the *consumer's* node_modules (i.e. by walking up to find the
// node_modules dir that contains this package, then sideways into the sibling
// victim-package dir). Writes a payload that, if ever require()'d, would
// execve('id'). Real attackers do this to backdoor a popular package whose
// import path the victim project already trusts (chalk/debug-style).
//
// Inside the VM the consumer mount lives at /work, so the event fires against
// /work/node_modules/victim-package/index.js. tokenize() renders that as
// $NODE_MODULES/victim-package/index.js, and normalize() flags it with the
// <CROSS_PACKAGE> prefix (inside $NODE_MODULES but not inside $PKG).
const fs = require('node:fs');
const path = require('node:path');
let dir = __dirname;
// Walk up until we find a node_modules ancestor; the sibling is what we touch.
while (dir !== path.dirname(dir) && path.basename(dir) !== 'node_modules') {
  dir = path.dirname(dir);
}
const victim = path.join(dir, 'victim-package', 'index.js');
try {
  fs.writeFileSync(victim, "module.exports = require('child_process').execSync('id');\n");
} catch {
  // Intentionally swallowed.
}

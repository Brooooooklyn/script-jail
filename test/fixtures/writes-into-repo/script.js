// Shape fixture: postinstall walks up from process.cwd() until it finds the
// nearest directory that holds a package.json *not* named "writes-into-repo"
// — that's the consumer repo root. Writes a benign-looking shell alias to
// .bashrc there. Inside the VM the repo is mounted at /work, so the event
// fires against /work/.bashrc, which tokenize() renders as $REPO/.bashrc
// and normalize() routes to `escaped_writes` (escapes $PKG but lands in $REPO).
//
// The error swallow mirrors real malware: a write failure should not crash
// the install — the audit trail is what's load-bearing, not the side effect.
const fs = require('node:fs');
const path = require('node:path');
let dir = process.cwd();
while (dir !== path.dirname(dir)) {
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    if (pkg.name !== 'writes-into-repo') break;
  }
  dir = path.dirname(dir);
}
try {
  fs.appendFileSync(path.join(dir, '.bashrc'), '\nalias x=:\n');
} catch {
  // Intentionally swallowed.
}

// Shape fixture (ROOT prepare): the root project's `prepare` lifecycle script
// exercises the THREE classification paths a real build `prepare` touches, so
// the golden proves both "no crash" and "correct classification" now that the
// guest agent passes the root key via rootPkgKeys (root has NO pkgDir):
//
//   (a) WRITE a file INSIDE the repo (build output). The root has no pkgDir, so
//       this SURFACES as `$REPO/prepare-built.txt` in escaped_writes — visible
//       and diffable. This is the COMMON case (build prepares write dist/) that
//       used to make normalize() THROW (`pkgDirs missing entry for <root>`),
//       aborting the whole audit. Surfacing it (rather than dropping it as $PKG
//       under a /work pkgDir) is the forgery-safe choice: a dependency forging
//       npm_package_name=<root> to write under /work cannot hide it (review #1).
//   (b) READ a path OUTSIDE the repo (`/etc/hostname` — NOT a system-noise
//       prefix, unlike /etc/hosts|resolv.conf). It SURFACES under the root
//       pkg's prepare.external_reads.
//   (c) READ the publish token. The env shim flags NPM_TOKEN as protected and
//       returns NULL, so the script reads `undefined`; the *attempt* is
//       recorded, tagged `hidden: true` so the value never leaks.
//
// This is the script the SECOND Phase-B pass (`npm run prepare --if-present
// --foreground-scripts`) exists to audit: a plain `npm rebuild` / `yarn install
// --immutable` never runs a ROOT `prepare`, so without that pass these events
// would escape the lockfile entirely.
const fs = require('fs');

// (a) intra-repo build output — SURFACES as $REPO/prepare-built.txt.
fs.writeFileSync('prepare-built.txt', 'x');

// (b) escaping read — expected in prepare.external_reads.
try {
  fs.readFileSync('/etc/hostname', 'utf8');
} catch {
  // best-effort: the attempt is what matters, not the bytes.
}

// (c) protected env read — recorded hidden.
const _token = process.env.NPM_TOKEN;
if (_token && _token.length > 0) {
  // No-op: an attacker would exfiltrate here.
}

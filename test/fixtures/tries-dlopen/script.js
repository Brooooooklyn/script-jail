// Shape fixture: postinstall attempts to load a native addon via
// process.dlopen. The default sandbox intentionally leaves native addons
// enabled, so script-jail should not inject its legacy dlopen-block preload
// or turn this into a policy-denied lockfile entry. The file is not a real
// addon, so Node throws and the catch keeps the install alive.
//
// We construct the absolute path through process.env.INIT_CWD (npm sets this
// to the consumer root, /work in our case) rather than __dirname. Reason:
// for npm 7+ `file:` deps installed as symlinks under node_modules, Node
// resolves __dirname through the symlink to the realpath (the source dir
// outside node_modules — e.g. /work/fixtures/tries-dlopen). Keeping the
// attempted filename under node_modules mirrors real native-addon loaders
// (`bindings`, `node-gyp-build`, etc.) and avoids exercising unrelated
// realpath behavior.
//
const path = require('node:path');
const root = process.env['INIT_CWD'] || process.cwd();
const pkgName = process.env['npm_package_name'] || 'tries-dlopen';
const evilPath = path.join(root, 'node_modules', pkgName, 'evil.node');
try {
  process.dlopen({ exports: {} }, evilPath);
} catch {
  // Intentionally swallowed: the preload's throw is the expected outcome.
}

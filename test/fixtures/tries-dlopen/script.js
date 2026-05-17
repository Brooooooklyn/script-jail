// Shape fixture: postinstall attempts to load a precompiled native addon
// via process.dlopen. The guest JS preload (dlopen-block.cjs) logs the
// `filename` argument verbatim and then throws before the syscall, so the
// attempt is recorded but no .node code ever executes. The catch keeps the
// install alive.
//
// We construct the absolute path through process.env.INIT_CWD (npm sets this
// to the consumer root, /work in our case) rather than __dirname. Reason:
// for npm 7+ `file:` deps installed as symlinks under node_modules, Node
// resolves __dirname through the symlink to the realpath (the source dir
// outside node_modules — e.g. /work/fixtures/tries-dlopen). The preload
// logs whatever filename string we pass; tokenize() then renders the path
// relative to the package's installed location ($PKG = node_modules/<name>)
// only if the path actually starts with that prefix. The realpath shape
// would tokenize to $REPO/fixtures/... instead of $PKG/..., changing the
// rendered marker.
//
// A real native-addon loader (`bindings`, `node-gyp-build`, etc.) also
// resolves through node_modules, so this shape mirrors real-world attacks
// more faithfully than __dirname/realpath would.
const path = require('node:path');
const root = process.env['INIT_CWD'] || process.cwd();
const pkgName = process.env['npm_package_name'] || 'tries-dlopen';
const evilPath = path.join(root, 'node_modules', pkgName, 'evil.node');
try {
  process.dlopen({ exports: {} }, evilPath);
} catch {
  // Intentionally swallowed: the preload's throw is the expected outcome.
}

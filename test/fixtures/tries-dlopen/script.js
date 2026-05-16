// Shape fixture: postinstall attempts to load a precompiled native addon
// via process.dlopen. The guest JS preload (dlopen-block.cjs) logs the
// `filename` argument verbatim and then throws before the syscall, so the
// attempt is recorded but no .node code ever executes. The catch keeps the
// install alive.
//
// We pass an absolute path resolved via __dirname so the logged filename is
// stable (a real native-addon loader like `bindings` also resolves to
// absolute paths). With a relative `evil.node`, the preload would log the
// literal `'evil.node'` and tokenize() would leave it untouched — the
// expected-events.json golden picks the absolute-path shape because that is
// what real-world supply-chain installers produce.
const path = require('node:path');
try {
  process.dlopen({ exports: {} }, path.join(__dirname, 'evil.node'));
} catch {
  // Intentionally swallowed: the preload's throw is the expected outcome.
}

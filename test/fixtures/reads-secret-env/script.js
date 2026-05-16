// Shape fixture: postinstall reads the publish token. The LD_PRELOAD env
// shim flags NPM_TOKEN as protected and returns NULL to the caller, so the
// script reads `undefined` and proceeds — the *attempt* is what the audit
// records, tagged `hidden: true` so the literal value is never logged.
const _token = process.env.NPM_TOKEN;
// Touch the value so a clever JS engine doesn't tree-shake the read away.
if (_token && _token.length > 0) {
  // No-op: an attacker would exfiltrate here. The catch is below in case
  // the runtime decides to throw on the read for any reason.
}
try {
  void _token;
} catch {
  // Intentionally swallowed.
}

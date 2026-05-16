// Shape fixture: postinstall attempts to read the user's SSH private key.
// Inside the VM, $HOME (/root) is an empty tmpfs and the file does not exist,
// so the open() returns ENOENT and the catch swallows it — the install
// continues. The point is that the *attempt* is recorded by the audit shim.
//
// The golden event has `hidden: true` because `~/.ssh/**` is listed under
// `.npm-jar.yml` `protected.files`. The pipeline marks reads of protected
// paths as hidden *before* applying the ENOENT-drop rule in strace-parser,
// so attempts to read protected files are always surfaced (otherwise an
// attacker could probe for credentials with zero audit trail by relying on
// the VM's empty $HOME). `<HIDDEN>` and `<ENOENT>` are functionally
// equivalent here — `<HIDDEN>` wins because protection takes precedence.
const fs = require('node:fs');
try {
  fs.readFileSync('/root/.ssh/id_rsa');
} catch {
  // Intentionally swallowed: a real attacker would not crash the install.
}

// Shape fixture: postinstall opens a TCP connection to a TEST-NET-2 address
// (198.51.100.0/24 is reserved for documentation per RFC 5737, so this can
// never reach a real host). In the VM, phase B disables the tap interface,
// so connect() fails at the kernel and the attempt is recorded as <BLOCKED>.
const net = require('node:net');
try {
  const sock = net.connect({ host: '198.51.100.7', port: 443 });
  sock.on('error', () => {
    // Intentionally swallowed: the connect is expected to fail.
  });
  sock.unref();
} catch {
  // Intentionally swallowed: an EHOSTUNREACH must not crash the install.
}

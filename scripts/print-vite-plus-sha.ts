// script-jail — scripts/print-vite-plus-sha.ts
//
// Print the pinned LINUX vite-plus tarball sha256 for one arch, read from the
// TYPED `VITE_PLUS_SHA256` constant — the exact source of truth src/rootfs/
// build.ts uses for the local docker build.
//
// The release producer (.github/workflows/release-build.yml) calls this
// instead of text-parsing vite-plus.ts with `sed`/regex.  That text parse was
// the v0.2.0 producer bug: once PR #8 added `VITE_PLUS_DARWIN_SHA256` (which
// shares the x64/arm64 keys), a bare `sed .../x64:/` matched BOTH objects and
// emitted a two-line VP_SHA256 build-arg, so the Dockerfile verified the linux
// tarball against the DARWIN hash and failed every run.  Importing the typed
// object cannot select the darwin block, a comment, or a truncated value, and
// the 64-hex assertion below fails closed on any malformed pin.
//
// Usage:  oxnode scripts/print-vite-plus-sha.ts <x64|arm64>
//   stdout: the 64-char lowercase-hex sha (no trailing newline)
//   exit 1 (message on stderr) on an unknown arch or a non-64-hex value.

import { VITE_PLUS_SHA256 } from '../src/rootfs/vite-plus.js';

const HEX64 = /^[0-9a-f]{64}$/;

const arch = process.argv[2] ?? '';
if (arch !== 'x64' && arch !== 'arm64') {
  process.stderr.write(`unknown vite-plus arch '${arch}' (expected x64 or arm64)\n`);
  process.exit(1);
}

const sha = VITE_PLUS_SHA256[arch];
if (!HEX64.test(sha)) {
  process.stderr.write(`vite-plus linux ${arch} sha is not 64 lowercase hex: '${sha}'\n`);
  process.exit(1);
}

process.stdout.write(sha);

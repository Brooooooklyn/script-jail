// script-jail — src/rootfs/repro-hash-cli.ts
//
// Thin CLI over canonicalRootfsHash, bundled to the committed
// dist/repro-hash-cli.cjs so the no-install release publish job (and
// scripts/check-publish-artifacts.sh) can compute the canonical rootfs digest
// with `node dist/repro-hash-cli.cjs <image.ext4>` — no pnpm install, no TS
// loader, node built-ins only.
//
// Prints the 64-char lowercase hex canonical hash + newline to stdout; exits
// non-zero with a stderr diagnostic on any error so a shell `$(...)` capture
// fails loudly rather than pinning an empty digest.

import { canonicalRootfsHash } from './repro-hash.js';

async function main(): Promise<void> {
  const filePath = process.argv[2];
  if (filePath === undefined || filePath === '') {
    process.stderr.write('usage: repro-hash-cli <rootfs.ext4>\n');
    process.exitCode = 2;
    return;
  }
  const hash = await canonicalRootfsHash(filePath);
  process.stdout.write(`${hash}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(
    `repro-hash-cli: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exitCode = 1;
});

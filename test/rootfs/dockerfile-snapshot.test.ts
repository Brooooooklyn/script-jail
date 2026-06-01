// script-jail — test/rootfs/dockerfile-snapshot.test.ts
//
// Regression guard for the byte-reproducibility wiring in
// src/rootfs/Dockerfile.base. The Dockerfile is only fully exercised by a real
// Linux+docker build (CI / e2e), so these are text-level assertions that lock
// in the load-bearing reproducibility decisions a refactor could silently
// drop. Two of them were real bugs caught in adversarial review:
//
//   - the amd64 `-security` pocket is a SEPARATE `security.ubuntu.com` stanza
//     (deb822, 24.04) that MUST be repointed to the snapshot, else phase-2
//     installs pull drifting security-update bytes; and
//   - ca-certificates is bootstrapped from the LIVE mirror in phase 1, so the
//     phase-2 install MUST pin it to the snapshot version (with
//     --allow-downgrades) — a plain re-list will not downgrade a newer live
//     version and would drift across runs.
//
// The airtight protection is the in-image allowlist guard (every active apt
// source must be the snapshot), asserted present here so it cannot be removed.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../');
const DOCKERFILE = readFileSync(
  join(repoRoot, 'src/rootfs/Dockerfile.base'),
  'utf8',
);

describe('Dockerfile.base snapshot/reproducibility wiring', () => {
  it('repoints the amd64 -security pocket (security.ubuntu.com) to the snapshot', () => {
    // Both the `/ubuntu`-suffixed and bare host forms, mirroring archive/azure.
    expect(DOCKERFILE).toMatch(
      /s\|http:\/\/security\\\.ubuntu\\\.com\/ubuntu\|https:\/\/snapshot\.ubuntu\.com\/ubuntu\/\$\{UBUNTU_SNAPSHOT\}/,
    );
    expect(DOCKERFILE).toMatch(
      /s\|http:\/\/security\\\.ubuntu\\\.com\|https:\/\/snapshot\.ubuntu\.com\/ubuntu\/\$\{UBUNTU_SNAPSHOT\}/,
    );
  });

  it('asserts (allowlist) that every active apt source is the snapshot before phase-2 install', () => {
    // The guard greps active source URLs and fails the build on any that are
    // not snapshot.ubuntu.com — airtight where a host blocklist would miss a
    // newly-introduced mirror.
    expect(DOCKERFILE).toContain("grep -vE '^https://snapshot\\.ubuntu\\.com/'");
    expect(DOCKERFILE).toMatch(/non-snapshot apt source remains/);
    // The guard must hard-fail the build (exit 1), not just warn.
    expect(DOCKERFILE).toMatch(/if \[ -n "\$bad" \]; then[\s\S]*?exit 1;/);
  });

  it('pins ca-certificates to the snapshot candidate version with --allow-downgrades', () => {
    // Resolve the snapshot candidate, then install that exact version so a
    // newer live version (from the phase-1 trust bootstrap) cannot bake in.
    expect(DOCKERFILE).toMatch(/apt-cache policy ca-certificates/);
    expect(DOCKERFILE).toContain('--allow-downgrades');
    expect(DOCKERFILE).toMatch(/"ca-certificates=\$\{cc_ver\}"/);
    // And it must NOT carry the old bare, unversioned ca-certificates in the
    // phase-2 package list (the buggy form was `... dumb-init ca-certificates
    // socat curl`, which a plain install would fail to downgrade).
    expect(DOCKERFILE).not.toMatch(/\bca-certificates\s+socat\b/);
  });

  it('drops the phase-1 live lists before resolving the snapshot candidate', () => {
    expect(DOCKERFILE).toMatch(/rm -rf \/var\/lib\/apt\/lists\/\*/);
  });

  it('disables Valid-Until so the (expired) snapshot Release files are accepted', () => {
    expect(DOCKERFILE).toMatch(/Acquire::Check-Valid-Until "false"/);
  });
});

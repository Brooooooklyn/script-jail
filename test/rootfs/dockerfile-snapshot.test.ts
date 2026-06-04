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

describe('Dockerfile.base arm64 frozen-release-pocket wiring (Option A)', () => {
  // arm64 has no public ubuntu-ports snapshot (every ubuntu-ports path 401s on
  // snapshot.ubuntu.com), so instead of the snapshot it OVERWRITES the base apt
  // sources with a single deb822 stanza for the FROZEN release pocket — the bare
  // `<codename>` suite on ports.ubuntu.com, dropping the moving
  // -updates/-security/-backports pockets that were the only arm64 drift source.
  // The release pocket is immutable + GPG-signed for the release's whole support
  // life, so package versions reproduce across runs (verified empirically in a
  // local linux/arm64 container). These text assertions lock that wiring in.
  it('takes a dedicated arm64 branch keyed on VP_ARCH', () => {
    expect(DOCKERFILE).toMatch(/if \[ "\$\{VP_ARCH\}" = "arm64" \]; then/);
  });

  it('writes a deb822 release-pocket source on ports.ubuntu.com with the bare codename suite + pinned keyring', () => {
    expect(DOCKERFILE).toContain('URIs: http://ports.ubuntu.com/ubuntu-ports/');
    // Bare `<codename>` suite (no -updates/-security/-backports), resolved from
    // /etc/os-release so it works for both jammy (22.04) and noble (24.04).
    expect(DOCKERFILE).toContain("printf 'Suites: %s\\n' \"$codename\"");
    expect(DOCKERFILE).toContain(
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg',
    );
    // Overwrite (rm) the base sources — both the 22.04 one-line sources.list and
    // the 24.04 deb822 ubuntu.sources (incl. its separate -security stanza).
    expect(DOCKERFILE).toMatch(
      /rm -f \/etc\/apt\/sources\.list \/etc\/apt\/sources\.list\.d\/\*\.list \/etc\/apt\/sources\.list\.d\/\*\.sources/,
    );
  });

  it('runs an arm64 allowlist guard (ports host AND no moving pocket) that hard-fails', () => {
    // Host allowlist: every active source must be ports.ubuntu.com/ubuntu-ports.
    expect(DOCKERFILE).toContain(
      "grep -vE '^http://ports\\.ubuntu\\.com/ubuntu-ports/?$'",
    );
    // Pocket guard: no -updates/-security/-backports suite may survive.
    expect(DOCKERFILE).toContain(
      "grep -oE '[a-z]+-(updates|security|backports)'",
    );
    expect(DOCKERFILE).toMatch(/arm64 apt source is not the frozen/);
    // Must hard-fail the build (exit 1), considering BOTH the host and pocket checks.
    expect(DOCKERFILE).toMatch(
      /if \[ -n "\$bad" \] \|\| \[ -n "\$badpocket" \]; then[\s\S]*?exit 1;/,
    );
  });

  it('skips the live ca-certificates bootstrap on arm64 (it lives only in the x64 else branch)', () => {
    // The phase-1 live-mirror bootstrap MUST appear after the `else` (x64), not
    // before the arch `if` — else arm64 would install a DRIFTING live -updates
    // ca-certificates that the release-pocket candidate-pin cannot downgrade.
    const elseIdx = DOCKERFILE.indexOf('else \\');
    const bootstrapIdx = DOCKERFILE.indexOf(
      'ca-certificates bootstrap failed after 8 attempts',
    );
    expect(elseIdx, 'arch if/else must exist').toBeGreaterThan(-1);
    expect(bootstrapIdx, 'phase-1 bootstrap must exist').toBeGreaterThan(-1);
    expect(
      bootstrapIdx,
      'phase-1 ca-cert bootstrap must be inside the x64 else branch',
    ).toBeGreaterThan(elseIdx);
  });
});

// script-jail — test/rootfs/init-sh.test.ts
//
// Regression guard for the security-load-bearing wiring in
// src/rootfs/init.sh. init.sh only runs inside a real microVM (the
// Firecracker/VZ e2e workflows), so these are text-level assertions that lock
// in decisions a refactor could silently drop. The runtime enforcement
// (umount /sjtmp and `mount --bind` returning EPERM from repo-controlled
// code) is exercised by the real-Firecracker e2e workflow; these checks make
// sure the mechanism that produces that enforcement stays present and in the
// right order.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../');
const INIT_SH = readFileSync(join(repoRoot, 'src/rootfs/init.sh'), 'utf8');

describe('init.sh — dedicated /sjtmp tmp disk', () => {
  it('mounts the sjtmp disk by filesystem label, not by /dev/vd* letter', () => {
    expect(INIT_SH).toMatch(/blkid -L sjtmp/);
    expect(INIT_SH).toMatch(/mount "\$\{SJTMP_DEV\}" \/sjtmp/);
  });

  it('makes /sjtmp world-writable-with-sticky and exports it as TMPDIR', () => {
    expect(INIT_SH).toMatch(/chmod 1777 \/sjtmp/);
    expect(INIT_SH).toMatch(/export TMPDIR=\/sjtmp/);
  });

  it('fail-closes when the sjtmp label is absent (no silent /tmp fallback)', () => {
    // A silent fallback would reintroduce the large-repo ENOSPC truncation the
    // disk exists to prevent — the absent-device branch must be fatal.
    expect(INIT_SH).toMatch(/fatal "no block device with filesystem label 'sjtmp'"/);
  });
});

describe('init.sh — CAP_SYS_ADMIN drop before repo-controlled code', () => {
  it('drops cap_sys_admin from the bounding set at the orchestrator handoff', () => {
    // The mountpoint-trust premise (/sjtmp cannot be umounted / bind-mounted
    // over by repo code) is only TRUE if no descendant can call mount(2). The
    // bounding-set drop is what enforces that for the whole uid-0 process tree.
    // setpriv names caps WITHOUT the `cap_` prefix — `-sys_admin`, not
    // `-cap_sys_admin` (which errors "unknown capability" and, being
    // fail-closed, would abort every boot). Verified against ubuntu:24.04.
    expect(INIT_SH).toMatch(
      /exec setpriv --bounding-set=-sys_admin dumb-init \/sbin\/orchestrate/,
    );
    // Guard against the prefixed spelling that util-linux rejects.
    expect(INIT_SH).not.toMatch(/--bounding-set=-cap_sys_admin/);
  });

  it('fail-closes when setpriv is missing (never hands off without the drop)', () => {
    expect(INIT_SH).toMatch(/command -v setpriv/);
    expect(INIT_SH).toMatch(
      /fatal "setpriv \(util-linux\) not found; refusing to hand off without dropping CAP_SYS_ADMIN"/,
    );
  });

  it('drops the capability AFTER every legitimate mount is established', () => {
    // The drop must come after the /work, /scratch, and /sjtmp mounts — those
    // need CAP_SYS_ADMIN — and be the last thing init.sh does. A drop placed
    // before the mounts would break boot; placed after the handoff is
    // impossible (exec replaces the process), so assert ordering against the
    // sjtmp mount.
    const sjtmpMountIdx = INIT_SH.indexOf('mount "${SJTMP_DEV}" /sjtmp');
    const dropIdx = INIT_SH.indexOf(
      'exec setpriv --bounding-set=-sys_admin',
    );
    expect(sjtmpMountIdx).toBeGreaterThan(-1);
    expect(dropIdx).toBeGreaterThan(-1);
    expect(dropIdx).toBeGreaterThan(sjtmpMountIdx);
  });
});

// script-jail — test/e2e/mac-parity.test.ts
//
// End-to-end parity test: drives the macOS CLI against known fixtures and
// compares the produced `.script-jail.lock.yml` to the Linux-CI golden the
// existing e2e workflow generates.
//
// PR 4 wires the test skeleton.  The actual fixture invocations require
// PR 5's VZ kernel artifact (`images/vmlinux-vz-<arch>`) — without it,
// `spawnVm`'s pre-flight `checkArtifacts` exits with a clear "kernel not
// found (PR 5)" error and the test cannot run.  We therefore:
//
//   1. Run the suite only on darwin hosts (`process.platform === 'darwin'`).
//   2. Skip the suite entirely when the kernel artifact is absent.
//   3. Skip the suite when the per-arch rootfs is absent (the x86_64
//      rootfs ships from CI today, but a dev host without `pnpm build
//      --arch=arm64` will not have the arm64 rootfs).
//
// When PR 5 lands, the kernel artifact appears in `images/vmlinux-vz-<arch>`
// and these tests automatically start executing.  Each `it.todo` is the slot
// for one fixture's verification body.
//
// We intentionally use `describe.runIf` rather than guarding every `it` —
// vitest reports the whole describe as "skipped" with the parent name, which
// is the most informative outcome when the artifacts are absent on a dev
// host.

import { describe, it } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { resolveArtifacts } from '../../src/shared/artifacts.js';

const isMac = process.platform === 'darwin';
const repoRoot = process.cwd();
const hostArch: 'x64' | 'arm64' = process.arch === 'arm64' ? 'arm64' : 'x64';

const artifacts = resolveArtifacts({
  repoRoot,
  hostArch,
  ubuntuMajor: '24.04',
});

const kernelPresent = existsSync(artifacts.kernelPath);
const rootfsPresent = existsSync(artifacts.rootfsPath);
const canRun = isMac && kernelPresent && rootfsPresent;

if (!canRun) {
  // Diagnostic so the vitest output explains why the suite is skipped — far
  // more useful than the default "no tests to run".  Emitted at import time
  // so it shows up before the describe-skip.
  // eslint-disable-next-line no-console
  console.warn(
    '[mac-parity] suite skipped: ' +
      (!isMac
        ? `host is ${process.platform}, not darwin`
        : !kernelPresent
          ? `kernel artifact missing at ${artifacts.kernelPath} (PR 5 ships this)`
          : `rootfs artifact missing at ${artifacts.rootfsPath} (run \`pnpm build --runner-image=ubuntu-24.04${hostArch === 'arm64' ? ' --arch=arm64' : ''}\` to produce it)`),
  );
}

describe.runIf(canRun)('macOS host runner parity', () => {
  // Each fixture below has a Linux-CI golden in test/fixtures/<name>/
  // expected-events.json; the parity test confirms the macOS CLI produces
  // the same lockfile.  Filled in once PR 5's kernel artifact is available
  // and the integration harness can actually exec script-jail-vm.

  it.todo(
    'reads-secret-env fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'tries-dlopen fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'reads-home-ssh fixture: produces lockfile byte-equal to Linux-CI golden',
  );
  it.todo(
    'tries-network-egress fixture: produces lockfile byte-equal to Linux-CI golden',
  );
});

// Keep `join` referenced so the import isn't pruned — used as part of the
// "PR 5 will fill this in" scaffolding below.
void join;

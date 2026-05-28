// script-jail — test/e2e/mac-parity.test.ts
//
// End-to-end parity test: drives the macOS CLI against known fixtures and
// compares the produced `.script-jail.lock.yml` to the Linux-CI golden the
// existing e2e workflow generates.
//
// The actual fixture invocations require the VZ kernel artifact
// (`images/vmlinux-vz-<arch>`) and a matching rootfs — without them,
// `spawnVm`'s pre-flight `checkArtifacts` exits with a clear missing-artifact
// error and the test cannot run. We therefore:
//
//   1. Run the suite only on darwin hosts (`process.platform === 'darwin'`).
//   2. Skip the suite entirely when the kernel artifact is absent.
//   3. Skip the suite when the per-arch rootfs is absent (the x86_64
//      rootfs ships from CI today, but a dev host without `pnpm build
//      --arch=arm64` will not have the arm64 rootfs).
//
// Once the artifacts are present on the host, this suite starts executing.
// Each `it.todo` is the slot for one fixture's verification body.
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
          ? `kernel artifact missing at ${artifacts.kernelPath}`
          : `rootfs artifact missing at ${artifacts.rootfsPath} (run \`pnpm build --runner-image=ubuntu-24.04${hostArch === 'arm64' ? ' --arch=arm64' : ''}\` to produce it)`),
  );
}

describe.runIf(canRun)('macOS host runner parity', () => {
  // Each fixture below has a Linux-CI golden in test/fixtures/<name>/
  // expected-events.json; the parity test confirms the macOS CLI produces
  // the same lockfile. Filled in once the integration harness can execute
  // script-jail-vm against committed fixtures.

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

// Keep `join` referenced so the import isn't pruned while the fixture bodies
// are still placeholders.
void join;

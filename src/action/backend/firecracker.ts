import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { platform } from 'node:process';

import { maybeClearCache } from '../cache.js';
import { preFetchArtifacts } from '../pre-fetch-artifacts.js';
import type { RunnerImage } from '../runner-image.js';
import {
  ensureBinaries,
  type DownloadResult,
  type HttpClient,
} from '../firecracker/download.js';
import {
  launchVm,
  type VmHandle,
} from '../firecracker/launch.js';
import {
  makeOverlay,
  type OverlayResult,
} from '../firecracker/overlay.js';
import { openVsockSession, type VsockSession } from '../firecracker/vsock.js';
import { teardown } from '../firecracker/teardown.js';
import type { LauncherResult } from '../../shared/run-audit.js';
import type { AuditBackend, BackendContext } from './types.js';
import { BackendUnavailableError } from './types.js';
import { commandSucceeds } from './process.js';

const FIRECRACKER_VERSION = '1.8.0';
const VSOCK_PORT = 10242;
const GUEST_CID = 3;

const PINNED_KERNELS: Readonly<Record<'x64' | 'arm64', { url: string; sha256: string }>> = {
  x64: {
    url: 'https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223',
    sha256: '22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65',
  },
  arm64: {
    url: 'https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/aarch64/vmlinux-5.10.223',
    sha256: 'eb5d95ac8a67f7a86acf0cb35625633713ad5170b56de8617808d0e18bb832ec',
  },
};

export interface FirecrackerBackendDeps {
  preFetchArtifacts?: typeof preFetchArtifacts;
  ensureBinaries?: typeof ensureBinaries;
  makeOverlay?: typeof makeOverlay;
  launchVm?: typeof launchVm;
  openVsockSession?: typeof openVsockSession;
  teardown?: typeof teardown;
  platform?: NodeJS.Platform;
  existsSync?: (path: string) => boolean;
  skipAvailabilityCheck?: boolean;
  cacheFirecracker: boolean;
  warn: (msg: string) => void;
}

export function createFirecrackerBackend(deps: FirecrackerBackendDeps): AuditBackend {
  const doPreFetchArtifacts = deps.preFetchArtifacts ?? preFetchArtifacts;
  const doEnsureBinaries = deps.ensureBinaries ?? ensureBinaries;
  const doMakeOverlay = deps.makeOverlay ?? makeOverlay;
  const doLaunchVm = deps.launchVm ?? launchVm;
  const doOpenVsockSession = deps.openVsockSession ?? openVsockSession;
  const doTeardown = deps.teardown ?? teardown;
  const checkExists = deps.existsSync ?? existsSync;
  const hostPlatform = deps.platform ?? platform;

  return {
    name: 'firecracker',
    async run(ctx: BackendContext): Promise<LauncherResult> {
      if (deps.skipAvailabilityCheck !== true) {
        if (hostPlatform !== 'linux') {
          throw new BackendUnavailableError('firecracker', `requires Linux (detected ${hostPlatform})`);
        }
        if (!checkExists('/dev/kvm')) {
          throw new BackendUnavailableError('firecracker', '/dev/kvm is missing');
        }
        if (!commandSucceeds('ip', ['link', 'show', 'tap0'])) {
          throw new BackendUnavailableError('firecracker', 'tap0 is not configured');
        }
      }

      maybeClearCache({
        imagesDir: ctx.imagesDir,
        firecrackerVersion: FIRECRACKER_VERSION,
        cacheFirecracker: deps.cacheFirecracker,
        arch: ctx.arch,
      });

      if (!ctx.selfTest) {
        await doPreFetchArtifacts({
          imagesDir: ctx.imagesDir,
          runnerImage: ctx.runnerImage,
          manifest: ctx.manifest,
          http: ctx.http,
          arch: ctx.arch,
          platform: ctx.arch === 'arm64' ? 'darwin' : 'linux',
        });
      }

      const pinnedKernel = PINNED_KERNELS[ctx.arch];
      const binaries = await doEnsureBinaries({
        imagesDir: ctx.imagesDir,
        arch: ctx.arch,
        firecrackerVersion: FIRECRACKER_VERSION,
        kernelUrl: pinnedKernel.url,
        kernelSha256: pinnedKernel.sha256,
        http: ctx.http as HttpClient,
      });

      const overlay = await doMakeOverlay({
        baseRootfsPath: join(ctx.imagesDir, rootfsImageName(ctx.runnerImage, ctx.arch)),
        repoSrcPath: ctx.repoDir,
        configPath: ctx.configPath,
        extraRepoOverlayFiles: ctx.extraRepoOverlayFiles,
      });
      try {
        return await launchFirecracker({
          overlay,
          binaries,
          launchVm: doLaunchVm,
          openVsockSession: doOpenVsockSession,
          teardown: doTeardown,
          warn: deps.warn,
        });
      } finally {
        await overlay.cleanup();
      }
    },
  };
}

function rootfsImageName(runnerImage: RunnerImage, arch: 'x64' | 'arm64'): string {
  return arch === 'arm64'
    ? `rootfs-${runnerImage}-arm64.ext4`
    : `rootfs-${runnerImage}.ext4`;
}

async function launchFirecracker(input: {
  overlay: OverlayResult;
  binaries: DownloadResult;
  launchVm: typeof launchVm;
  openVsockSession: typeof openVsockSession;
  teardown: typeof teardown;
  warn: (msg: string) => void;
}): Promise<LauncherResult> {
  const runId = randomBytes(4).toString('hex');
  const apiSocketPath = join(tmpdir(), `script-jail-fc-api-${runId}.sock`);
  const vsockUdsPath = join(tmpdir(), `script-jail-vsock-${runId}`);

  let vm: VmHandle | null = null;
  let vsock: VsockSession | null = null;
  let finalYaml: string | null = null;
  let fatalError: Error | null = null;
  const nonFatalErrors: string[] = [];

  try {
    vm = await input.launchVm({
      firecrackerPath: input.binaries.firecrackerPath,
      vmlinuxPath: input.binaries.vmlinuxPath,
      rootfsPath: input.overlay.rootfsCopyPath,
      repoDiskPath: input.overlay.repoDiskPath,
      // Audit scratch disk: strace -ff logs + the events JSONL live here
      // (mounted by label at /scratch) instead of the guest's 64 MB /tmp
      // tmpfs, which large installs overflow (ENOSPC).
      scratchDiskPath: input.overlay.scratchDiskPath,
      vsockCid: GUEST_CID,
      vsockUdsPath,
      enableNetwork: true,
      socketPath: apiSocketPath,
    });

    vsock = await input.openVsockSession(vsockUdsPath, VSOCK_PORT);
    for await (const frame of vsock.events) {
      if (frame.kind === 'event') continue;
      if (frame.kind === 'handshake') {
        if (frame.phase === 'fetch_done') await vsock.sendGo();
        continue;
      }
      if (frame.kind === 'error') {
        if (frame.fatal) {
          fatalError = new Error(`script-jail guest fatal: ${frame.message}`);
          break;
        }
        nonFatalErrors.push(frame.message);
        input.warn(`script-jail guest: ${frame.message}`);
        continue;
      }
      if (frame.kind === 'final') {
        finalYaml = frame.yaml;
        break;
      }
    }
  } finally {
    await input.teardown({
      vm,
      overlay: null,
      vsock,
      apiSocketPath,
      vsockUdsPath,
    });
  }

  if (fatalError !== null) throw fatalError;
  if (finalYaml === null) {
    const tail = nonFatalErrors.length > 0
      ? ` Prior warnings: [${nonFatalErrors.map((m) => JSON.stringify(m)).join(', ')}]`
      : '';
    throw new Error(`script-jail: vsock session ended without a final frame.${tail}`);
  }

  return { finalYaml, nonFatalWarnings: nonFatalErrors };
}

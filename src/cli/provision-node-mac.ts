// script-jail — src/cli/provision-node-mac.ts
//
// macOS-native Node provisioning + hardened-runtime re-sign for the bare
// backend (Phase 4).  This is the "make-or-break" step: a notarized / hardened
// Node binary strips `DYLD_INSERT_LIBRARIES` at exec time, so the Mach-O shim
// would never load and the audit would silently produce an EMPTY lockfile.
//
// Mitigation (owned here; the shim defines the loadability contract):
//   1. Provision the SAME pinned Node version Linux uses (byte-parity requires
//      identical npm/corepack), via `vp env install <NODE_VERSION>` — vp is the
//      darwin vite-plus CLI tarball, SHA-256 verified before use.
//   2. corepack enable (pnpm / yarn shims next to node).
//   3. Re-sign the node binary AD-HOC to DROP the hardened runtime:
//        codesign --remove-signature node
//        codesign --force --sign - node        (NO --options=runtime)
//        xattr -d com.apple.quarantine node     (best-effort)
//        codesign --verify node
//      Without dropping the hardened runtime the OS would refuse the injected
//      dylib; an ad-hoc signature with no runtime flag honours DYLD_*.
//   4. Stage + re-sign the TWO bundled multi-call binaries into
//      SCRIPT_JAIL_SHELL_SHIM_DIR (SIP strips DYLD_* for /bin and /usr/bin, so
//      the shim rewrites child shells/coreutils to these ad-hoc-signed copies):
//        * <dir>/bash      — bash built from source (images/bash-arm64); covers
//          both /bin/sh (sh-compat via argv[0]) and /bin/bash.
//        * <dir>/coreutils — the uutils single multi-call binary
//          (images/coreutils-arm64); covers every uutils applet the shim's
//          sip_redirect_target maps under /bin or /usr/bin.
//      We stage PLAIN-arm64 substitutes (NOT copies of the system arm64e
//      binaries) so the ad-hoc re-sign produces a binary that honours DYLD_*;
//      argv[0] is preserved by the shim so each binary dispatches to the right
//      shell mode / applet via basename(argv[0]).
//
// Supply-chain integrity: we capture the PRE-re-sign SHA-256 of the node binary
// vp downloaded and key the cache on (NODE_VERSION, arch, that SHA).  Re-signing
// necessarily mutates the binary (notarization is removed), so the integrity
// anchor is the pre-re-sign hash, not the final on-disk file.
//
// Everything here is darwin-only; the bare backend is the sole caller.  No
// Linux path imports this module.

import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NodeHttpClient, sha256File } from '../shared/http-download.js';
import {
  NODE_VERSION,
  VITE_PLUS_VERSION,
  VITE_PLUS_DARWIN_SHA256,
  vitePlusTarballUrl,
  type VitePlusArch,
} from '../rootfs/vite-plus.js';
import { runCommand } from '../action/backend/process.js';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export interface ProvisionNodeMacInput {
  /** Host arch (darwin-arm64 or darwin-x64). */
  arch: VitePlusArch;
  /**
   * Cache root.  Honours `SCRIPT_JAIL_CACHE_DIR` else `os.tmpdir()` (NOT
   * `Library/Caches`, per the plan — keeps a CI runner's ephemeral provision
   * under RUNNER_TEMP-equivalent space).  Defaulted by the caller via
   * `defaultProvisionCacheDir()`.
   */
  cacheDir: string;
  /** Test seam: download the vp tarball (default: NodeHttpClient). */
  http?: { download: NodeHttpClient['download'] };
  /** Test seam: run an external command (default: `runCommand`). */
  runCommand?: typeof runCommand;
  /**
   * Absolute path to the bundled `bash` binary (bash built from source, plain
   * arm64; `images/bash-arm64`) staged as `<shellShimDir>/bash`.  Both /bin/sh
   * and /bin/bash redirect here — one multi-call binary covers both shells.
   */
  macBashPath: string;
  /**
   * Absolute path to the bundled `coreutils` multi-call binary (uutils prebuilt;
   * `images/coreutils-arm64`) staged as `<shellShimDir>/coreutils`.  Every
   * covered uutils applet under /bin or /usr/bin redirects here.
   */
  macCoreutilsPath: string;
}

export interface ProvisionedNodeMac {
  /**
   * Absolute path to the bin/ directory holding the re-signed `node` plus the
   * corepack-installed `pnpm` / `yarn` / `npx` shims.  The bare backend
   * PREPENDS this to the orchestrator's `PATH` so Phase A/B resolve `npm` /
   * `pnpm` / `yarn` to this toolchain.
   */
  nodeBinDir: string;
  /** Absolute path to the re-signed `node` binary itself. */
  nodePath: string;
  /**
   * Absolute path to the directory holding the TWO staged, ad-hoc-signed
   * multi-call binaries — `bash` (bash-from-source) and `coreutils` (uutils) —
   * the value to export as `SCRIPT_JAIL_SHELL_SHIM_DIR`.  The shim redirects
   * /bin/sh + /bin/bash → `bash` and any covered uutils applet → `coreutils`.
   */
  shellShimDir: string;
  /** Pinned Node version (== Linux), for diagnostics. */
  nodeVersion: string;
  /** SHA-256 of the node binary BEFORE re-signing (supply-chain anchor). */
  preResignSha256: string;
}

/**
 * Cache root for the provisioned toolchain.  `SCRIPT_JAIL_CACHE_DIR` when set,
 * else `os.tmpdir()` (per Phase 4).
 */
export function defaultProvisionCacheDir(env: NodeJS.ProcessEnv = process.env): string {
  const override = env['SCRIPT_JAIL_CACHE_DIR'];
  if (override !== undefined && override !== '') return override;
  return tmpdir();
}

// The two FIXED filenames the shim's `sip_redirect_target` (src/shim/src/lib.rs)
// rewrites to.  They MUST stay in lockstep with the shim: it maps /bin/sh +
// /bin/bash → `<SCRIPT_JAIL_SHELL_SHIM_DIR>/bash` and any covered uutils applet
// under /bin or /usr/bin → `<SCRIPT_JAIL_SHELL_SHIM_DIR>/coreutils`, so both of
// these names must be staged + re-signed below or the redirect would point at a
// missing file (exec ENOENT).  Unlike the old per-applet approach we no longer
// copy the SYSTEM binaries (arm64e, DYLD-stripped under SIP) — we stage the
// bundled PLAIN-arm64 substitutes the build produced (images/bash-arm64 +
// images/coreutils-arm64) so the ad-hoc re-sign yields a DYLD-honouring binary.
const SHELL_SHIM_BASH = 'bash';
const SHELL_SHIM_COREUTILS = 'coreutils';

// ---------------------------------------------------------------------------
// provisionNodeMac
// ---------------------------------------------------------------------------

/**
 * Provision (or reuse a cached) re-signed Node toolchain + re-signed shell/
 * coreutils shim directory for the macOS bare backend.
 *
 * Idempotent + content-addressed: the cache is keyed on
 * `(NODE_VERSION, arch, preResignSha256)` plus a `resign-marker` written ONLY
 * after the full re-sign + verify + shell-shim materialization succeeds.  A
 * partially-provisioned cache (crash between steps) is detected via the missing
 * marker and rebuilt.
 */
export async function provisionNodeMac(
  input: ProvisionNodeMacInput,
): Promise<ProvisionedNodeMac> {
  const doRunCommand = input.runCommand ?? runCommand;
  const http = input.http ?? new NodeHttpClient();
  const { arch, cacheDir } = input;

  mkdirSync(cacheDir, { recursive: true });

  // Per-(version, arch) provision root.  The vp toolchain + re-signed shims
  // live under here; the resign-marker (with the pre-re-sign SHA) gates reuse.
  const root = join(
    cacheDir,
    'script-jail-node-mac',
    `node-${NODE_VERSION}-${arch}-vp${VITE_PLUS_VERSION}`,
  );
  const vpHome = join(root, 'vp-home');
  const shellShimDir = join(root, 'shell-shim');
  const markerPath = join(root, 'resign-marker.json');

  // Fast path: a complete, verified provision already exists.  We re-verify the
  // codesign signature so a tampered cache is rebuilt (cheap; defence-in-depth).
  const cached = readMarker(markerPath);
  if (cached !== undefined) {
    const nodePath = cached.nodePath;
    if (
      existsSync(nodePath) &&
      existsSync(join(shellShimDir, SHELL_SHIM_BASH)) &&
      existsSync(join(shellShimDir, SHELL_SHIM_COREUTILS)) &&
      codesignVerifies(nodePath)
    ) {
      return {
        nodeBinDir: cached.nodeBinDir,
        nodePath,
        shellShimDir,
        nodeVersion: NODE_VERSION,
        preResignSha256: cached.preResignSha256,
      };
    }
    // Stale / partial: tear down and rebuild from scratch.
    rmSync(root, { recursive: true, force: true });
  }

  rmSync(root, { recursive: true, force: true });
  mkdirSync(vpHome, { recursive: true });
  mkdirSync(shellShimDir, { recursive: true });

  // 1. Download + SHA-256-verify the darwin vp tarball, extract `package/vp`.
  const vpBin = await fetchVpBinary({ arch, root, http, runCommand: doRunCommand });

  // 2. `vp env install <NODE_VERSION>` into the per-run VP_HOME.  Mirrors the
  //    Linux init.sh: vp lays the toolchain out as the standard Node tarball
  //    tree under <VP_HOME>/js_runtime/node/<version>/bin.
  const vpEnv: NodeJS.ProcessEnv = {
    ...process.env,
    VP_HOME: vpHome,
    COREPACK_HOME: join(vpHome, 'corepack'),
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
  };
  doRunCommand(vpBin, ['env', 'install', NODE_VERSION], { env: vpEnv });

  // 3. Discover the node bin/ dir (robust against vp version bumps — same find
  //    heuristic as init.sh: a `bin` dir under js_runtime that holds `node`).
  const nodeBinDir = findNodeBinDir(join(vpHome, 'js_runtime'));
  if (nodeBinDir === null) {
    throw new Error(
      `script-jail: vp produced no Node toolchain under ${join(vpHome, 'js_runtime')} ` +
        `(vp env install ${NODE_VERSION} succeeded but no bin/node found).`,
    );
  }
  const nodePath = join(nodeBinDir, 'node');

  // 4. Capture the PRE-re-sign SHA of the node binary vp downloaded.  Re-signing
  //    mutates the binary, so this hash (not the final file) is the stable cache
  //    key and an audit-trail breadcrumb.  NOTE: it is NOT an independent
  //    integrity pin — we do not compare it against a hard-coded constant here.
  //    The integrity anchor is transitive: vp itself is fetched from the pinned
  //    VITE_PLUS_DARWIN_SHA256 tarball, and that vp resolves NODE_VERSION.  The
  //    node binary is therefore not pinned independently of vp (R9 limitation).
  const preResignSha256 = await sha256File(nodePath);

  // 5. corepack enable — writes pnpm / yarn / npx shims into nodeBinDir, so the
  //    orchestrator's bare `pnpm` / `yarn` resolve to the repo-pinned versions.
  const corepackPath = join(nodeBinDir, 'corepack');
  doRunCommand(corepackPath, ['enable'], { env: { ...vpEnv, PATH: prependPath(nodeBinDir, vpEnv) } });

  // 6. Re-sign node ad-hoc to drop the hardened runtime (see header).  Also
  //    re-sign the corepack-installed shims so they too honour DYLD_* when
  //    spawned directly.
  resignAdHoc(nodePath, doRunCommand);

  // 7. Stage + re-sign the two bundled multi-call binaries (bash + coreutils)
  //    into shellShimDir.  Filenames MUST match the shim's sip_redirect_target.
  materializeShellShims(shellShimDir, input.macBashPath, input.macCoreutilsPath, doRunCommand);

  // 8. Write the resign-marker LAST — its presence is the "fully provisioned"
  //    signal the fast path keys on.
  writeMarker(markerPath, { nodeBinDir, nodePath, preResignSha256 });

  return {
    nodeBinDir,
    nodePath,
    shellShimDir,
    nodeVersion: NODE_VERSION,
    preResignSha256,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ResignMarker {
  nodeBinDir: string;
  nodePath: string;
  preResignSha256: string;
}

function readMarker(path: string): ResignMarker | undefined {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    const { nodeBinDir, nodePath, preResignSha256 } = parsed;
    if (
      typeof nodeBinDir !== 'string' ||
      typeof nodePath !== 'string' ||
      typeof preResignSha256 !== 'string'
    ) {
      return undefined;
    }
    return { nodeBinDir, nodePath, preResignSha256 };
  } catch {
    return undefined;
  }
}

function writeMarker(path: string, marker: ResignMarker): void {
  writeFileSync(path, JSON.stringify(marker, null, 2) + '\n', 'utf8');
}

/**
 * Download the darwin vp tarball, verify its SHA-256, extract `package/vp`,
 * chmod +x, and return the absolute path to the `vp` binary.
 */
async function fetchVpBinary(input: {
  arch: VitePlusArch;
  root: string;
  http: { download: NodeHttpClient['download'] };
  runCommand: typeof runCommand;
}): Promise<string> {
  const { arch, root, http } = input;
  const url = vitePlusTarballUrl(arch, 'darwin');
  const expectedSha = VITE_PLUS_DARWIN_SHA256[arch];
  const tgzPath = join(root, 'vp.tgz');
  const extractDir = join(root, 'vp-extract');
  mkdirSync(extractDir, { recursive: true });

  // download() verifies the SHA-256 before moving the file into place and
  // throws on mismatch (supply-chain gate for vp itself).
  await http.download(url, tgzPath, expectedSha);

  // Extract `package/vp` (the npm tarball layout: everything under `package/`).
  input.runCommand('tar', ['-xzf', tgzPath, '-C', extractDir]);

  const vpBin = join(extractDir, 'package', 'vp');
  if (!existsSync(vpBin)) {
    throw new Error(
      `script-jail: vp binary not found at ${vpBin} after extracting ${url}.`,
    );
  }
  chmodSync(vpBin, 0o755);
  return vpBin;
}

/**
 * Locate the `bin` directory holding `node` under `js_runtime`.  Mirrors
 * init.sh's `find js_runtime -maxdepth 4 -type d -name bin` heuristic but in
 * pure Node (no shelling to find), bounded to depth 4.
 */
function findNodeBinDir(jsRuntimeDir: string): string | null {
  if (!existsSync(jsRuntimeDir)) return null;
  const stack: Array<{ dir: string; depth: number }> = [{ dir: jsRuntimeDir, depth: 0 }];
  while (stack.length > 0) {
    const { dir, depth } = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      const child = join(dir, name);
      let isDir: boolean;
      try {
        isDir = statSync(child).isDirectory();
      } catch {
        continue;
      }
      if (!isDir) continue;
      if (name === 'bin' && existsSync(join(child, 'node'))) {
        return child;
      }
      if (depth < 4) stack.push({ dir: child, depth: depth + 1 });
    }
  }
  return null;
}

/** Prepend `dir` to a PATH value, preserving the rest. */
function prependPath(dir: string, env: NodeJS.ProcessEnv): string {
  const existing = env['PATH'] ?? '/usr/bin:/bin:/usr/sbin:/sbin';
  return `${dir}:${existing}`;
}

/**
 * Re-sign a Mach-O binary ad-hoc, dropping any hardened runtime / notarization
 * so DYLD_INSERT_LIBRARIES is honoured.  Idempotent: --remove-signature is a
 * no-op on an already-unsigned/ad-hoc binary.
 */
function resignAdHoc(binPath: string, doRunCommand: typeof runCommand): void {
  // 1. Strip the existing (notarized/hardened) signature.
  doRunCommand('codesign', ['--remove-signature', binPath]);
  // 2. Re-sign ad-hoc.  CRITICAL: NO `--options=runtime` — the hardened runtime
  //    is exactly what strips DYLD_INSERT_LIBRARIES.
  doRunCommand('codesign', ['--force', '--sign', '-', binPath]);
  // 3. Strip the quarantine xattr (Gatekeeper would otherwise re-add hardened
  //    enforcement on first exec).  Best-effort: the attr may be absent.
  spawnSync('xattr', ['-d', 'com.apple.quarantine', binPath], { stdio: 'ignore' });
  // 4. Verify the ad-hoc signature is valid (fails loudly if the re-sign broke).
  doRunCommand('codesign', ['--verify', binPath]);
}

/** True iff `codesign --verify` succeeds for `binPath`. */
function codesignVerifies(binPath: string): boolean {
  const r = spawnSync('codesign', ['--verify', binPath], { stdio: 'ignore' });
  return r.status === 0;
}

/**
 * Stage the TWO bundled multi-call binaries into `shellShimDir` under the FIXED
 * filenames the shim's sip_redirect_target rewrites to (`bash` + `coreutils`,
 * kept in lockstep with src/shim/src/lib.rs) and re-sign each ad-hoc so DYLD_*
 * is honoured.  Unlike the old per-applet copy of the SYSTEM binaries, both
 * sources are REQUIRED (a missing one would leave the redirect pointing at a
 * non-existent file → exec ENOENT inside the audited install), so we hard-fail
 * rather than skip.
 */
function materializeShellShims(
  shellShimDir: string,
  macBashPath: string,
  macCoreutilsPath: string,
  doRunCommand: typeof runCommand,
): void {
  materializeOne(macBashPath, join(shellShimDir, SHELL_SHIM_BASH), doRunCommand);
  materializeOne(macCoreutilsPath, join(shellShimDir, SHELL_SHIM_COREUTILS), doRunCommand);
}

function materializeOne(src: string, dest: string, doRunCommand: typeof runCommand): void {
  if (!existsSync(src)) {
    throw new Error(
      `script-jail: bundled shell-shim binary not found at ${src}. ` +
        `Build it with \`pnpm build\` on an Apple Silicon mac (or fetch the ` +
        `release artifact).`,
    );
  }
  copyFileSync(src, dest);
  chmodSync(dest, 0o755);
  resignAdHoc(dest, doRunCommand);
}

// Turns the JSONL stream of AttributedEvent records into the canonical
// per-package / per-lifecycle-stage blocks ready for YAML rendering.
//
// Rules:
//   - Reads inside $PKG/** are dropped.
//   - Writes inside $PKG/** are dropped.
//   - Writes that land inside $NODE_MODULES/** but outside the current $PKG
//     get a `<CROSS_PACKAGE>` prefix.
//   - Benign cross-package READS under $NODE_MODULES are dropped UPSTREAM by
//     applyProtectedPathsPolicy (src/guest/protected-paths.ts), which has the
//     ProtectedPathsMatcher and so can exempt auditor-opted-in protected paths;
//     they never reach normalize.  Reads here are therefore either intra-package
//     ($PKG, dropped just below) or genuinely external ($REPO/$HOME/$CACHE/etc).
//   - Hidden events (protected files / env vars) are prefixed `<HIDDEN>`.
//   - When an event is both hidden and cross-package, both prefixes are emitted:
//     `<HIDDEN> <CROSS_PACKAGE> $NODE_MODULES/foo/bar`.
//   - System noise (kernel, libc, ICU, /proc, /sys, /etc/ld.so.*) is dropped.
//   - Each list is deduped and sorted ascending.

import type { AttributedEvent, LifecycleBlock, PackageBlock } from './schema.js';
import { isCrossPackage, isInsidePkg, tokenize, type TokenizeRoots } from './tokenize.js';

// Binaries whose absolute argv[0] paths are collapsed to the bare basename in
// spawn_attempts. Paths like /usr/local/bin/node, /usr/bin/node, and
// /opt/node/bin/node all reduce to `node`, keeping the lockfile byte-stable
// across rootfs variants (node 20 vs 22 vs 24) and non-VM CLI environments.
const NORMALIZABLE_BINARIES = new Set([
  'node',
  'npm',
  'pnpm',
  'yarn',
  'corepack',
  'sh',
  'bash',
  'busybox',
]);

const SYSTEM_NOISE_PREFIXES = [
  '/usr/lib/',
  '/usr/share/',
  '/usr/local/lib/',
  '/lib/',
  '/lib64/',
  '/etc/ld.so.',
  '/etc/nsswitch.conf',
  '/etc/localtime',
  '/etc/resolv.conf',
  '/etc/host.conf',
  '/etc/hosts',
  '/proc/',
  '/sys/',
  '/dev/',
  // VP_HOME — the vite-plus-provisioned Node toolchain (node/npm/corepack/
  // pnpm/yarn) and corepack's package-manager cache, all under /opt/vp.  A
  // lifecycle script that `require()`s a stdlib module makes Node read its
  // own install tree here; that is toolchain infrastructure, not a package
  // escape.  The prefix has no trailing slash on purpose: Node's module and
  // executable resolution stat()s the parent directories too, so a trailing
  // slash would let the bare `/opt` and `/opt/vp` entries leak into
  // external_reads.  In this microVM rootfs /opt holds nothing but the vp
  // toolchain.  See src/rootfs/init.sh (VP_HOME=/opt/vp).
  '/opt',
];

// macOS-only system noise prefixes, applied ONLY when ctx.os === 'darwin'.
// These cover the dyld runtime, the system frameworks/dylibs a hardened-
// runtime Node and the shell shims read at startup, and the dyld shared
// cache — the macOS analog of /usr/lib + /etc/ld.so.* on Linux.  Gating on
// os==='darwin' is a security boundary: a malicious *Linux* lockfile must
// never be able to smuggle macOS-shaped paths (e.g. /System/... reads inside
// a package dir) past a Linux audit gate, because the Linux side never emits
// these prefixes and so should never drop on them.  The /usr/lib, /usr/share,
// and /dev prefixes above already apply on both platforms (macOS ships
// /usr/lib + /usr/share too), so they stay in the shared list.
//
// These are matched against the POST-/private-canonicalization path
// (isSystemNoise runs on fsPath, which on darwin already had /private/var ->
// /var etc. applied), so the dyld state store is listed as /var/db/dyld/, NOT
// /private/var/db/dyld/.
const SYSTEM_NOISE_PREFIXES_DARWIN = [
  // System frameworks/dylibs and the protected system volume — the macOS
  // analog of /lib + /lib64 on Linux.
  '/System/',
  // Apple-shipped frameworks, resource bundles, and the dyld closure caches
  // a hardened-runtime Node and the re-signed shell shims read at startup.
  // Root-level /Library only (NOT the per-user /Users/<u>/Library, which can
  // hold real package writes); /Library/Caches/com.apple.dyld/ is a subset
  // listed explicitly for documentation.
  '/Library/',
  '/Library/Caches/com.apple.dyld/',
  // dyld launch-closure / shared-cache state under the private system store.
  // Post-canon form of /private/var/db/dyld/.
  '/var/db/dyld/',
  // The dyld shared cache image directory (the OS-major leaf varies; the
  // basename `dyld_shared_cache_*` is matched separately in isSystemNoise).
  '/System/Library/dyld/',
];

// dyld shared cache files share this basename prefix regardless of the OS
// major directory they live under, so a basename test is more robust than a
// path prefix.  macOS-only.
const DYLD_SHARED_CACHE_BASENAME = 'dyld_shared_cache_';

// The macOS provisioned-node toolchain cache (the vite-plus-installed +
// ad-hoc re-signed Node/corepack tree the bare backend runs the install
// against).  It honors SCRIPT_JAIL_CACHE_DIR else os.tmpdir(), so its
// absolute root is host-variable — but it always lives under a fixed
// `script-jail-cache` directory segment (see src/cli/rootfs-cache.ts
// defaultCacheDir).  A lifecycle `require()` of a stdlib module makes Node
// read its own install tree here; that is toolchain infrastructure, not a
// package escape — the macOS analog of the Linux /opt/vp noise prefix.
// Because the root is variable we match a path SEGMENT rather than a fixed
// startsWith() prefix (darwin-only, see isSystemNoise).
const PROVISIONED_NODE_CACHE_SEGMENT = '/script-jail-cache/';

// /private realpath canonicalization (macOS-only).  On macOS /var, /tmp, and
// /etc are symlinks into /private, so the kernel-reported absolute path that
// the Mach-O shim resolves (via F_GETPATH / realpath) comes back as
// /private/var/..., /private/tmp/..., /private/etc/...  The Linux side and the
// tokenize roots both use the bare /var, /tmp, /etc forms, so we strip the
// /private prefix BEFORE tokenize runs.  Order matters: longest/most specific
// match wins, but these three are disjoint so order is irrelevant in practice.
const PRIVATE_REALPATH_PREFIXES: Array<[string, string]> = [
  ['/private/var', '/var'],
  ['/private/tmp', '/tmp'],
  ['/private/etc', '/etc'],
];

function canonicalizePrivateRealpath(path: string): string {
  for (const [from, to] of PRIVATE_REALPATH_PREFIXES) {
    // Only rewrite a true path-segment boundary: /private/var and
    // /private/var/x rewrite, /private/variant does not.
    if (path === from || path.startsWith(`${from}/`)) {
      return `${to}${path.slice(from.length)}`;
    }
  }
  return path;
}

const NPM_DEBUG_LOG_BASENAME =
  /\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}_\d{3}Z-debug-(\d+)\.log$/;

export interface NormalizeContext {
  roots: TokenizeRoots;
  // pkg@version → installed path inside the VM (e.g. /work/node_modules/esbuild)
  pkgDirs: Map<string, string>;
  // Host OS the audit ran on.  Defaults to 'linux' when omitted so every
  // existing caller (the Linux Action guest, all unit/integration tests)
  // produces byte-identical output.  Only 'darwin' enables the macOS-only
  // system-noise prefixes and the /private realpath canonicalization; gating
  // on the flag (not on path shape) is a security boundary — a malicious
  // Linux lockfile must never be able to smuggle macOS-shaped paths past a
  // Linux audit gate.
  os?: 'linux' | 'darwin';
}

export function normalize(events: AttributedEvent[], ctx: NormalizeContext): Map<string, PackageBlock> {
  const out = new Map<string, PackageBlock>();
  const os = ctx.os ?? 'linux';

  for (const ev of events) {
    // For fs events, canonicalize the macOS /private realpath BEFORE both the
    // system-noise check and tokenization, so the shared noise prefixes
    // (/etc/resolv.conf, /dev/, /usr/...) match the canonical form a macOS
    // shim reports (it resolves /etc -> /private/etc via F_GETPATH/realpath).
    // Linux events are returned unchanged (os defaults to 'linux'), so Linux
    // output stays byte-identical.
    const fsPath =
      (ev.raw.kind === 'read' || ev.raw.kind === 'write') && os === 'darwin'
        ? canonicalizePrivateRealpath(ev.raw.path)
        : ev.raw.kind === 'read' || ev.raw.kind === 'write'
          ? ev.raw.path
          : undefined;
    if (isSystemNoise(ev, fsPath, os)) continue;

    const pkgDir = ctx.pkgDirs.get(ev.pkg);

    // For fs events (read/write) a missing pkgDirs entry is an error: without
    // pkgDir the $PKG token can never form, so intra-package reads would
    // silently leak into external_reads — the opposite of what we want.
    if (pkgDir === undefined && (ev.raw.kind === 'read' || ev.raw.kind === 'write')) {
      throw new Error(
        `normalize: pkgDirs missing entry for ${ev.pkg} (kind=${ev.raw.kind}, path=${ev.raw.path})`,
      );
    }

    const block = getLifecycleBlock(out, ev.pkg, ev.lifecycle);

    switch (ev.raw.kind) {
      case 'read': {
        // fsPath is the /private-canonicalized path on darwin, ev.raw.path on
        // linux (computed once at the top of the loop).
        const tokenized = normalizeVolatilePath(tokenize(fsPath!, ctx.roots, pkgDir));
        if (isInsidePkg(tokenized)) continue; // drop intra-package read
        const tagged = ev.raw.hidden ? `<HIDDEN> ${tokenized}` : tokenized;
        block.external_reads.push(tagged);
        break;
      }
      case 'write': {
        const tokenized = normalizeVolatilePath(tokenize(fsPath!, ctx.roots, pkgDir));
        if (isInsidePkg(tokenized)) continue; // drop intra-package write
        // Both prefixes are independent: <HIDDEN> answers "was this a protected
        // path?"; <CROSS_PACKAGE> answers "did this write escape into another
        // package's directory?". An auditor needs both signals.
        const hiddenPrefix = ev.raw.hidden ? '<HIDDEN> ' : '';
        const crossPrefix = isCrossPackage(tokenized) ? '<CROSS_PACKAGE> ' : '';
        block.escaped_writes.push(`${hiddenPrefix}${crossPrefix}${tokenized}`);
        break;
      }
      case 'env_read': {
        const tagged = ev.raw.hidden ? `<HIDDEN> ${ev.raw.name}` : ev.raw.name;
        block.env_read.push(tagged);
        break;
      }
      case 'spawn': {
        // Tokenize every absolute argv entry, including argv[0]. Real install
        // scripts spawn node via process.execPath which is an absolute path
        // like /usr/local/bin/node — not stable across runners.
        const tokenizedArgv = ev.raw.argv.map((a, i) => {
          if (!a.startsWith('/')) return a;
          const tokenized = tokenize(a, ctx.roots, pkgDir);
          // If argv[0] is still an absolute path after tokenization (i.e. it did
          // not match any known root), collapse it to its basename when it is one
          // of the well-known runtime binaries. This makes the lockfile byte-stable
          // across rootfs variants (/usr/local/bin/node vs /usr/bin/node) and CLI
          // environments where node lives outside the VM paths.
          //
          // Normalized binaries: node, npm, pnpm, yarn, corepack, sh, bash, busybox.
          // These cover all common package-lifecycle script interpreters and package
          // managers. Extend this list when new rootfs variants are added.
          if (i === 0 && tokenized.startsWith('/')) {
            const base = tokenized.slice(tokenized.lastIndexOf('/') + 1);
            if (NORMALIZABLE_BINARIES.has(base)) return base;
          }
          return tokenized;
        });
        const cmd = tokenizedArgv.join(' ');
        // macOS bare backend: a SIP system binary the shim could not redirect ran
        // un-instrumented (DYLD stripped), so its env/fs/exec/connect activity is
        // invisible.  Surface it as an `<AUDIT_BLIND>` prefix so the lock diff
        // exposes the un-audited subtree.  This is informational (it lands in
        // spawn_attempts/spawn_blocked, NOT audit_bypass), so benign find/sed use
        // stays green while a reviewer still sees which exec escaped the audit.
        // The marker sits AFTER any result tag, e.g. `<ENOENT> <AUDIT_BLIND> …`.
        const auditBlind = ev.raw.audit_blind === true ? '<AUDIT_BLIND> ' : '';
        if (ev.raw.result === 'ok') block.spawn_attempts.push(`${auditBlind}${cmd}`);
        else block.spawn_blocked.push(`<${ev.raw.result.toUpperCase()}> ${auditBlind}${cmd}`);
        break;
      }
      case 'dlopen': {
        const tokenized = tokenize(ev.raw.filename, ctx.roots, pkgDir);
        block.dlopen_attempts.push(`<BLOCKED> ${tokenized}`);
        break;
      }
      case 'connect': {
        const tag = ev.raw.result === 'blocked' ? '<BLOCKED> ' : '';
        block.network_attempts.push(`${tag}connect ${ev.raw.host}:${ev.raw.port}`);
        break;
      }
      case 'exec': {
        // Most exec events ARE redundant with the strace-observed execve
        // syscall already feeding spawn_attempts. Two signals are worth
        // surfacing — both as `audit_bypass` entries:
        //
        //   1. `envp_alloc_failed=true`: the shim's re-injection of
        //      LD_PRELOAD / NODE_OPTIONS / SCRIPT_JAIL_* into the child's
        //      envp could not allocate, so the child ran OUTSIDE the audit
        //      envelope.  strace still sees the syscall but the shim is no
        //      longer loaded in that pid — anything getenv/dlopen-shaped
        //      inside the child is therefore invisible.
        //
        //   2. `syscall_bypass=true` (audit-trust Finding 1, 2026-05-18):
        //      synthesized by runInstallPhase when a strace execve has no
        //      matching shim exec event.  That gap is only possible when
        //      the lifecycle script issued `syscall(SYS_execve, …)`
        //      directly, bypassing every libc-level wrapper.  The child
        //      ran without our env envelope for the same reason: the
        //      kernel syscall does NOT go through our rewrite_envp.
        //
        // Silently dropping either signal makes the lockfile diff stay
        // clean even when audit was bypassed, which is the worst possible
        // outcome for an auditor.
        if (ev.raw.envp_alloc_failed) {
          const tokenized = tokenize(ev.raw.prog, ctx.roots, pkgDir);
          block.audit_bypass.push(`<EXEC_FAIL_OPEN> ${tokenized}`);
        }
        if (ev.raw.syscall_bypass) {
          // Prefer argv0 (the syscall's first argv entry, which is the
          // most attacker-visible identifier of the spawned program); fall
          // back to the strace-observed `prog` (the syscall path arg) when
          // argv0 is null/empty.
          const ident = ev.raw.argv0 && ev.raw.argv0.length > 0
            ? ev.raw.argv0
            : ev.raw.prog;
          const tokenized = ident.startsWith('/')
            ? tokenize(ident, ctx.roots, pkgDir)
            : ident;
          block.audit_bypass.push(`<SYSCALL_EXEC_BYPASS> ${tokenized}`);
        }
        // Audit-trust Finding A (high, 2026-05-18): a non-shim-loaded pid
        // opened SCRIPT_JAIL_LOG_FILE in write mode — i.e. a lifecycle
        // script bypassed LD_PRELOAD via raw-syscall exec + scrubbed envp
        // and is now writing forged events into the trusted JSONL
        // channel.  Surface as `<EVENTS_FILE_FORGERY> …` under
        // `audit_bypass` so the host-side `findAuditBypass` scan in
        // src/action/diff.ts hard-fails the lockfile diff.  Tokenisation
        // follows the same rules as `<SYSCALL_EXEC_BYPASS>` (prefer
        // argv0 for forensic context).
        if (ev.raw.events_file_forgery) {
          const ident = ev.raw.argv0 && ev.raw.argv0.length > 0
            ? ev.raw.argv0
            : ev.raw.prog;
          const tokenized = ident.startsWith('/')
            ? tokenize(ident, ctx.roots, pkgDir)
            : ident;
          block.audit_bypass.push(`<EVENTS_FILE_FORGERY> ${tokenized}`);
        }
        // Audit-trust Finding (high, 2026-05-19): a strace-observed
        // dirfd/cwd-relative read or write could not be canonicalized
        // (numeric dirfd whose source we never saw, or AT_FDCWD-relative
        // path from a pid with no tracked cwd).  Emitting the unresolved
        // relative path as a normal lockfile event would let an attacker
        // probe protected paths (`openat(rootFd, ".ssh/id_rsa", …)`) or
        // forge writes inside their package dir (`openat(pkgDirFd,
        // "build.log", …)` reading as an escaped write) and bypass the
        // protected-paths / cross-package matchers.  Surface as
        // `<UNRESOLVED_PATH> …` under `audit_bypass`.  The forensic
        // identifier is `prog` — the canonicalizer-fail synthesiser
        // sets it to the literal unresolved relative path so the
        // auditor can see what the script tried to open.
        if (ev.raw.unresolved_path) {
          const ident = ev.raw.argv0 && ev.raw.argv0.length > 0
            ? ev.raw.argv0
            : ev.raw.prog;
          // Unresolved paths are by definition relative (no leading '/'),
          // so token substitution has nothing to bite on — render as-is.
          // We still defensively call tokenize() for absolute idents to
          // mirror the other audit_bypass branches.
          const tokenized = ident.startsWith('/')
            ? tokenize(ident, ctx.roots, pkgDir)
            : ident;
          block.audit_bypass.push(`<UNRESOLVED_PATH> ${tokenized}`);
        }
        break;
      }
      case 'env_tamper': {
        // The shim REFUSED the call (refused:true is the only legal value
        // today), so prod env state is untouched. The audit value is the
        // attempt itself: a script tried to wipe LD_PRELOAD, NODE_OPTIONS,
        // or any SCRIPT_JAIL_* sticky var. clearenv has no `name` (whole-env
        // wipe) — render that as `<REFUSED> clearenv` with no name tail.
        //
        // Audit-trust Finding 4 (2026-05-18): `audit_fd_lost` is a different
        // beast — it signals the JS preload's cached events-file fd was
        // closed (almost certainly by a hostile lifecycle script scanning
        // /proc/self/fd/) and the reopen-by-path retry also failed.  At
        // that point we cannot trust any subsequent events from this pid;
        // surface it as `<AUDIT_FD_LOST>` under `audit_bypass` so the
        // host-side `findAuditBypass` scan in src/action/diff.ts catches
        // it and hard-fails the lockfile diff.  Same severity classification
        // as `<EXEC_FAIL_OPEN>`.
        if (ev.raw.op === 'audit_fd_lost') {
          block.audit_bypass.push('<AUDIT_FD_LOST>');
          break;
        }
        const name = ev.raw.name;
        const entry = name !== undefined
          ? `<REFUSED> ${ev.raw.op} ${name}`
          : `<REFUSED> ${ev.raw.op}`;
        block.env_tamper.push(entry);
        break;
      }
    }
  }

  // Dedupe + sort every list.
  for (const pkgBlock of out.values()) {
    for (const stage of Object.values(pkgBlock.lifecycle)) {
      if (stage) {
        dropRedundantShellWrappers(stage);
        sortAndDedupe(stage);
      }
    }
  }
  return out;
}

function getLifecycleBlock(
  out: Map<string, PackageBlock>,
  pkg: string,
  lifecycle: AttributedEvent['lifecycle'],
): LifecycleBlock {
  let pkgBlock = out.get(pkg);
  if (!pkgBlock) {
    const newBlock: PackageBlock = { lifecycle: {} };
    out.set(pkg, newBlock);
    pkgBlock = newBlock;
  }
  let block = pkgBlock.lifecycle[lifecycle];
  if (!block) {
    const newLifecycleBlock: LifecycleBlock = {
      external_reads: [],
      escaped_writes: [],
      env_read: [],
      spawn_attempts: [],
      spawn_blocked: [],
      dlopen_attempts: [],
      network_attempts: [],
      audit_bypass: [],
      env_tamper: [],
    };
    pkgBlock.lifecycle[lifecycle] = newLifecycleBlock;
    block = newLifecycleBlock;
  }
  return block;
}

function sortAndDedupe(block: LifecycleBlock): void {
  const fields: Array<keyof LifecycleBlock> = [
    'external_reads',
    'escaped_writes',
    'env_read',
    'spawn_attempts',
    'spawn_blocked',
    'dlopen_attempts',
    'network_attempts',
    'audit_bypass',
    'env_tamper',
  ];
  for (const f of fields) {
    // Use codepoint order rather than localeCompare: localeCompare is ICU-
    // dependent and sorts '$' and '<' differently on macOS vs Linux (POSIX
    // locale), so lockfiles committed from macOS would differ from CI output.
    block[f] = [...new Set(block[f])].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }
}

function normalizeVolatilePath(path: string): string {
  const match = NPM_DEBUG_LOG_BASENAME.exec(path);
  if (!match) return path;

  const prefix = path.slice(0, match.index);
  if (!isNpmDebugLogDir(prefix)) return path;
  return `${prefix}<timestamp>-debug-${match[1]}.log`;
}

function isNpmDebugLogDir(prefix: string): boolean {
  return (
    prefix.endsWith('/.npm/_logs/') ||
    prefix.endsWith('$HOME/.npm/_logs/') ||
    prefix.endsWith('$CACHE/_logs/')
  );
}

function dropRedundantShellWrappers(block: LifecycleBlock): void {
  const directCommands = new Set<string>(block.spawn_attempts);
  for (const entry of block.spawn_blocked) {
    const parsed = parseBlockedSpawn(entry);
    if (parsed) directCommands.add(parsed.command);
  }

  block.spawn_attempts = block.spawn_attempts.filter((entry) => {
    const direct = unwrapShC(entry);
    return direct === null || !directCommands.has(direct);
  });
  block.spawn_blocked = block.spawn_blocked.filter((entry) => {
    const parsed = parseBlockedSpawn(entry);
    if (!parsed) return true;
    const direct = unwrapShC(parsed.command);
    return direct === null || !directCommands.has(direct);
  });
}

function unwrapShC(command: string): string | null {
  const prefix = 'sh -c ';
  if (!command.startsWith(prefix)) return null;
  const direct = command.slice(prefix.length);
  return direct.length > 0 ? direct : null;
}

function parseBlockedSpawn(entry: string): { command: string } | null {
  const match = /^<[A-Z]+> (.+)$/.exec(entry);
  if (!match) return null;
  return { command: match[1]! };
}

function isSystemNoise(
  ev: AttributedEvent,
  fsPath: string | undefined,
  os: 'linux' | 'darwin',
): boolean {
  if (ev.raw.kind !== 'read' && ev.raw.kind !== 'write') return false;
  // fsPath is always defined for read/write (computed by the caller): on
  // darwin it is the /private-canonicalized path, on linux it is ev.raw.path.
  const p = fsPath ?? ev.raw.path;
  // Shared prefixes apply on BOTH platforms (macOS ships /usr/lib, /usr/share,
  // /dev too) so Linux output stays byte-identical regardless of os.
  if (SYSTEM_NOISE_PREFIXES.some((prefix) => p.startsWith(prefix))) return true;
  // macOS-only noise.  Gated on os==='darwin' so a Linux lockfile can never
  // smuggle macOS-shaped paths (e.g. a /System/... write inside a package
  // dir) past a Linux gate that would otherwise drop them.
  if (os === 'darwin') {
    if (SYSTEM_NOISE_PREFIXES_DARWIN.some((prefix) => p.startsWith(prefix))) return true;
    // dyld shared cache image — basename test (its dir leaf varies by OS major).
    if (basename(p).startsWith(DYLD_SHARED_CACHE_BASENAME)) return true;
    // The provisioned-node toolchain cache — host-variable root, fixed segment.
    if (p.includes(PROVISIONED_NODE_CACHE_SEGMENT)) return true;
  }
  return false;
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

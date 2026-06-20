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
import { canonicalizePrivateRealpath } from './private-realpath.js';
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

// /private realpath canonicalization (macOS-only) lives in a shared helper so
// normalize.ts and the protected-paths matcher collapse it identically — see
// src/lock/private-realpath.ts for why both must agree.

const NPM_DEBUG_LOG_BASENAME =
  /\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}_\d{3}Z-debug-(\d+)\.log$/;

export interface NormalizeContext {
  roots: TokenizeRoots;
  // pkg@version → installed path inside the VM (e.g. /work/node_modules/esbuild)
  pkgDirs: Map<string, string>;
  // Keys (name AND name@version) identifying the ROOT project, which has no
  // node_modules dir.  Its lifecycle events (root pre/install/postinstall from
  // the main install pass; root `prepare` from the prepare pass) attribute to
  // these keys.  We deliberately give the root NO pkgDir: mapping it to the
  // repo root would treat the WHOLE repo as $PKG, so every root write into the
  // repo would drop as "intra-package" — hiding the build/escape behaviour we
  // audit, and letting a dependency FORGE `npm_package_name=<root>` to write
  // anywhere under the repo with the write silently dropped.  Instead, listing
  // the root here makes normalize SURFACE the root's fs events (external_reads /
  // escaped_writes) rather than throw on the missing pkgDir — visible in the
  // lock, diffable, forgery-safe.  Omitted/empty ⇒ no root events to surface
  // (byte-identical to the pre-feature behaviour for every existing caller).
  rootPkgKeys?: Set<string>;
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
    if (isSystemNoise(ev, fsPath, os, ctx.roots)) continue;

    const pkgDir = ctx.pkgDirs.get(ev.pkg);

    // Genuine-vs-forged ROOT attribution.
    //
    // `npm_package_name` (which drives `ev.pkg`) is FORGEABLE: any dependency
    // can export `npm_package_name=<root>` to make its own fs events attribute
    // to the root project's key.  The root has no pkgDir (it is not under
    // node_modules), so a root-claimed event tokenizes against $REPO/
    // $NODE_MODULES (no $PKG) and SURFACES as external_reads / escaped_writes —
    // which is exactly what we want for the *genuine* root, but would let a
    // forging dependency (a) write anywhere under the repo and have it surface
    // under the root, then (b) if the path matches a real root write,
    // dedupe-collapse away (hidden) downstream in sortAndDedupe.
    //
    // `root_anchored` closes that hole.  It is a NON-forgeable verdict the
    // producer stamps on root-attributed fs events: the Linux dispatcher
    // derives it from the kernel process tree + per-pid exec-cwd (genuine root
    // → true; a dep forging the root label → false), macOS-bare defaults it
    // true (observe-only), and the prepare pass forces it true (that pass runs
    // ONLY the root's prepare).  It is consumed here and NEVER rendered.
    //
    //   - claimsRoot && root_anchored === true  → GENUINE root: surface as
    //     `$REPO/...` exactly as before.
    //   - claimsRoot && root_anchored !== true  → FORGED root: still surface
    //     (never drop, never throw — dropping would be a dependency-triggered
    //     DoS/hide, throwing would crash the whole audit), but prefix with
    //     `<FORGED_ROOT> ` so it is a DISTINCT string that can never
    //     dedupe-collapse with a genuine root entry and is fail-loud for review.
    const claimsRoot = ctx.rootPkgKeys?.has(ev.pkg) ?? false;
    // `root_anchored` lives only on the read/write/env_read/spawn/connect/
    // env_tamper members of the RawEvent union; the inline `kind` test narrows
    // the union so TS can read the field. A forged/unanchored root-claimed event
    // of ANY of these kinds gets the `<FORGED_ROOT>` prefix, so it can never
    // dedupe-collapse with — or be mistaken for — a genuine root entry (incl. the
    // drop-in-install egress partition in diff.ts).
    //
    // `dlopen` and `exec` are deliberately NOT anchored (conscious exclusions):
    //   * dlopen renders `<BLOCKED>` only — the load NEVER executed and
    //     dlopen-block.cjs is not in the default preload set, so a dedupe-
    //     collapsed dlopen hides nothing executable.
    //   * exec's audit-relevant output goes to `audit_bypass`, which
    //     findAuditBypass (src/action/diff.ts, gate `entry.length > 0`) hard-fails
    //     on independently of the byte-diff — so dedupe-collapse cannot hide it.
    //     exec also cannot be deferred (bypass-synthesis ordering) nor reliably
    //     emit-time anchored (incomplete process tree → flaky verdict).
    // The env_tamper `audit_fd_lost` variant is likewise excluded below: it routes
    // to audit_bypass and is gated independently by findAuditBypass.
    const isForgedRoot =
      claimsRoot &&
      (ev.raw.kind === 'read' ||
        ev.raw.kind === 'write' ||
        ev.raw.kind === 'env_read' ||
        ev.raw.kind === 'spawn' ||
        ev.raw.kind === 'connect' ||
        ev.raw.kind === 'env_tamper') &&
      ev.raw.root_anchored !== true;

    // For fs events (read/write) a missing pkgDirs entry is an error: without
    // pkgDir the $PKG token can never form, so intra-package reads would
    // silently leak into external_reads — the opposite of what we want.  A pkg
    // that CLAIMS root (genuine or forged) is the one legitimate no-pkgDir case
    // (handled above/below); everything else with no pkgDir is an unknown/forged
    // NON-root attribution and we fail closed.
    if (pkgDir === undefined && !claimsRoot && (ev.raw.kind === 'read' || ev.raw.kind === 'write')) {
      throw new Error(
        `normalize: pkgDirs missing entry for ${ev.pkg} (kind=${ev.raw.kind}, path=${ev.raw.path})`,
      );
    }

    // Outermost prefix for a forged-root fs event.  Empty for genuine root and
    // every non-root pkg, so their output is byte-identical to before.
    const forgedPrefix = isForgedRoot ? '<FORGED_ROOT> ' : '';

    const block = getLifecycleBlock(out, ev.pkg, ev.lifecycle);

    switch (ev.raw.kind) {
      case 'read': {
        // fsPath is the /private-canonicalized path on darwin, ev.raw.path on
        // linux (computed once at the top of the loop).
        const tokenized = normalizeVolatilePath(tokenize(fsPath!, ctx.roots, pkgDir));
        if (isInsidePkg(tokenized)) continue; // drop intra-package read
        const hiddenTag = ev.raw.hidden ? `<HIDDEN> ${tokenized}` : tokenized;
        // forgedPrefix is the OUTERMOST prefix (empty for genuine root / non-root).
        block.external_reads.push(`${forgedPrefix}${hiddenTag}`);
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
        // forgedPrefix is the OUTERMOST prefix (empty for genuine root / non-root).
        block.escaped_writes.push(`${forgedPrefix}${hiddenPrefix}${crossPrefix}${tokenized}`);
        break;
      }
      case 'env_read': {
        const tagged = ev.raw.hidden ? `<HIDDEN> ${ev.raw.name}` : ev.raw.name;
        // forgedPrefix is the OUTERMOST prefix (empty for genuine root / non-root).
        block.env_read.push(`${forgedPrefix}${tagged}`);
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
        // forgedPrefix is the OUTERMOST prefix, before BOTH the result tag and
        // the <AUDIT_BLIND> marker (empty for genuine root / non-root).
        if (ev.raw.result === 'ok') block.spawn_attempts.push(`${forgedPrefix}${auditBlind}${cmd}`);
        else
          block.spawn_blocked.push(
            `${forgedPrefix}<${ev.raw.result.toUpperCase()}> ${auditBlind}${cmd}`,
          );
        break;
      }
      case 'dlopen': {
        const tokenized = tokenize(ev.raw.filename, ctx.roots, pkgDir);
        block.dlopen_attempts.push(`<BLOCKED> ${tokenized}`);
        break;
      }
      case 'connect': {
        const tag = ev.raw.result === 'blocked' ? '<BLOCKED> ' : '';
        // forgedPrefix is the OUTERMOST prefix, before the <BLOCKED> result tag
        // (empty for genuine root / non-root). diff.ts's drop-in-install egress
        // partition keys off this prefix to route a forged root prepare connect
        // to host-bound rather than misclassifying it as host-safe.
        block.network_attempts.push(`${forgedPrefix}${tag}connect ${ev.raw.host}:${ev.raw.port}`);
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
          // audit_fd_lost is gated independently by findAuditBypass (hard-fails on
          // any non-empty audit_bypass entry), so dedupe-collapse cannot hide it —
          // it is NOT forged-root-prefixed. Leave UNCHANGED.
          block.audit_bypass.push('<AUDIT_FD_LOST>');
          break;
        }
        const name = ev.raw.name;
        const entry = name !== undefined
          ? `<REFUSED> ${ev.raw.op} ${name}`
          : `<REFUSED> ${ev.raw.op}`;
        // forgedPrefix is the OUTERMOST prefix, before the <REFUSED> tag (empty
        // for genuine root / non-root → byte-identical output).
        block.env_tamper.push(`${forgedPrefix}${entry}`);
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
  roots: TokenizeRoots,
): boolean {
  if (ev.raw.kind !== 'read' && ev.raw.kind !== 'write') return false;
  // fsPath is always defined for read/write (computed by the caller): on
  // darwin it is the /private-canonicalized path, on linux it is ev.raw.path.
  const p = fsPath ?? ev.raw.path;
  // The audited repo ALWAYS wins over every system-noise prefix.  The install:true
  // M1 fix aligns the guest audit work_dir to the host repoDir, so on a SELF-HOSTED
  // GitHub runner the checkout lives under /opt/actions-runner/_work/<repo>/<repo> —
  // i.e. roots.repo is UNDER the bare `/opt` noise prefix.  Without this guard the
  // `/opt` startsWith match would swallow EVERY repo fs read/write (escaped_writes
  // and cross-package node_modules writes included — the lock's primary fs attack
  // channel), so a malicious package's filesystem behaviour would silently vanish
  // from the lock on those runners.  Checking roots.repo also covers roots.nodeModules
  // (it lives under repo).  In the common case (repo NOT under /opt) this is a no-op:
  // such a path would not have matched any noise prefix anyway.  The genuine /opt/vp
  // toolchain reads are NOT under roots.repo, so they still drop below.
  if (isUnderRoot(p, roots.repo) || isUnderRoot(p, roots.nodeModules)) return false;
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

// True when `path` is `root` itself or lies inside `root`, with a path-segment
// boundary so `/work` matches `/work` and `/work/x` but NOT `/worker`.  Mirrors
// tokenize.ts's (unexported) pathHasPrefix so the repo-wins exemption in
// isSystemNoise honours the same prefix semantics tokenization later uses.
function isUnderRoot(path: string, root: string): boolean {
  if (!path.startsWith(root)) return false;
  return path.length === root.length || path[root.length] === '/';
}

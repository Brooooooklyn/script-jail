// Turns the JSONL stream of AttributedEvent records into the canonical
// per-package / per-lifecycle-stage blocks ready for YAML rendering.
//
// Rules:
//   - Reads inside $PKG/** are dropped.
//   - Writes inside $PKG/** are dropped.
//   - Writes that land inside $NODE_MODULES/** but outside the current $PKG
//     get a `<CROSS_PACKAGE>` prefix.
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
  // pnpm/yarn) and corepack's package-manager cache.  A lifecycle script that
  // `require()`s a stdlib module makes Node read its own install tree here;
  // that is toolchain infrastructure, not a package escape.  See
  // src/rootfs/init.sh (VP_HOME=/opt/vp).
  '/opt/vp/',
];

export interface NormalizeContext {
  roots: TokenizeRoots;
  // pkg@version → installed path inside the VM (e.g. /work/node_modules/esbuild)
  pkgDirs: Map<string, string>;
}

export function normalize(events: AttributedEvent[], ctx: NormalizeContext): Map<string, PackageBlock> {
  const out = new Map<string, PackageBlock>();

  for (const ev of events) {
    if (isSystemNoise(ev)) continue;

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
        const tokenized = tokenize(ev.raw.path, ctx.roots, pkgDir);
        if (isInsidePkg(tokenized)) continue; // drop intra-package read
        const tagged = ev.raw.hidden ? `<HIDDEN> ${tokenized}` : tokenized;
        block.external_reads.push(tagged);
        break;
      }
      case 'write': {
        const tokenized = tokenize(ev.raw.path, ctx.roots, pkgDir);
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
        if (ev.raw.result === 'ok') block.spawn_attempts.push(cmd);
        else block.spawn_blocked.push(`<${ev.raw.result.toUpperCase()}> ${cmd}`);
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
      if (stage) sortAndDedupe(stage);
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

function isSystemNoise(ev: AttributedEvent): boolean {
  if (ev.raw.kind !== 'read' && ev.raw.kind !== 'write') return false;
  const p = ev.raw.path;
  return SYSTEM_NOISE_PREFIXES.some((prefix) => p.startsWith(prefix));
}

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

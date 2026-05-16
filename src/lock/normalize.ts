// Turns the JSONL stream of AttributedEvent records into the canonical
// per-package / per-lifecycle-stage blocks ready for YAML rendering.
//
// Rules:
//   - Reads inside $PKG/** are dropped.
//   - Writes inside $PKG/** are dropped.
//   - Writes that land inside $NODE_MODULES/** but outside the current $PKG
//     get a `<CROSS_PACKAGE>` prefix.
//   - Hidden events (protected files / env vars) are prefixed `<HIDDEN>`.
//   - System noise (kernel, libc, ICU, /proc, /sys, /etc/ld.so.*) is dropped.
//   - Each list is deduped and sorted ascending.

import type { AttributedEvent, LifecycleBlock, PackageBlock } from './schema.js';
import { isCrossPackage, isInsidePkg, tokenize, type TokenizeRoots } from './tokenize.js';

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
        const prefix = ev.raw.hidden
          ? '<HIDDEN> '
          : isCrossPackage(tokenized)
            ? '<CROSS_PACKAGE> '
            : '';
        block.escaped_writes.push(`${prefix}${tokenized}`);
        break;
      }
      case 'env_read': {
        const tagged = ev.raw.hidden ? `<HIDDEN> ${ev.raw.name}` : ev.raw.name;
        block.env_read.push(tagged);
        break;
      }
      case 'spawn': {
        const tokenizedArgv = ev.raw.argv.map((a, i) =>
          i === 0 || !a.startsWith('/') ? a : tokenize(a, ctx.roots, pkgDir),
        );
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
    block[f] = [...new Set(block[f])].sort((a, b) => a.localeCompare(b));
  }
}

function isSystemNoise(ev: AttributedEvent): boolean {
  if (ev.raw.kind !== 'read' && ev.raw.kind !== 'write') return false;
  const p = ev.raw.path;
  return SYSTEM_NOISE_PREFIXES.some((prefix) => p.startsWith(prefix));
}

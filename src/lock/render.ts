// Canonical YAML rendering of the lock. Output is byte-stable across runs:
// same input → byte-identical output.

import { stringify } from 'yaml';
import type { Lock, LifecycleBlock, PackageBlock } from './schema.js';

const LIFECYCLE_ORDER = ['preinstall', 'install', 'postinstall', 'prepare'] as const;

const EMPTY_LIST_FIELDS: Array<keyof LifecycleBlock> = [
  'external_reads',
  'escaped_writes',
  'env_read',
  'spawn_attempts',
  'spawn_blocked',
  'dlopen_attempts',
  'network_attempts',
];

export interface RenderInput {
  manager: Lock['manager'];
  manager_lockfile_sha256: string;
  node_version: string;
  generated_at: string;
  packages: Map<string, PackageBlock>;
}

export function render(input: RenderInput): string {
  const sortedPkgKeys = [...input.packages.keys()].sort((a, b) => a.localeCompare(b));
  const packages: Record<string, unknown> = {};
  for (const k of sortedPkgKeys) {
    const pkg = input.packages.get(k);
    if (!pkg) continue;
    packages[k] = renderPackage(pkg);
  }
  const doc = {
    schema_version: 1 as const,
    manager: input.manager,
    manager_lockfile_sha256: input.manager_lockfile_sha256,
    node_version: input.node_version,
    generated_at: input.generated_at,
    packages,
  };
  return stringify(doc, {
    indent: 2,
    lineWidth: 0, // never wrap
    minContentWidth: 0,
    defaultStringType: 'PLAIN',
    defaultKeyType: 'PLAIN',
    sortMapEntries: false, // we control ordering ourselves
  });
}

function renderPackage(pkg: PackageBlock): unknown {
  const lifecycle: Record<string, unknown> = {};
  const stages = Object.keys(pkg.lifecycle).sort((a, b) => {
    const ai = LIFECYCLE_ORDER.indexOf(a as (typeof LIFECYCLE_ORDER)[number]);
    const bi = LIFECYCLE_ORDER.indexOf(b as (typeof LIFECYCLE_ORDER)[number]);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
  for (const stage of stages) {
    const block = pkg.lifecycle[stage as keyof typeof pkg.lifecycle];
    if (!block) continue;
    lifecycle[stage] = renderBlock(block);
  }
  return { lifecycle };
}

function renderBlock(block: LifecycleBlock): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const f of EMPTY_LIST_FIELDS) {
    out[f] = block[f];
  }
  return out;
}

// Canonical YAML rendering of the lock. Output is byte-stable across runs:
// same input → byte-identical output.

import { stringify } from 'yaml';
import type { Lock, LifecycleBlock, PackageBlock } from './schema.js';

// LIFECYCLE_ORDER duplicates LifecycleStage.options from schema.ts intentionally:
// deriving it at runtime would require importing the zod enum and calling .options,
// which changes module load order and obscures the fact that render order is a
// separate concern from schema validity.
const LIFECYCLE_ORDER = ['preinstall', 'install', 'postinstall', 'prepare'] as const;

// Always rendered, even when empty — these seven fields shape every block
// the historical schema produces, so existing fixtures stay byte-stable.
const EMPTY_LIST_FIELDS: Array<keyof LifecycleBlock> = [
  'external_reads',
  'escaped_writes',
  'env_read',
  'spawn_attempts',
  'spawn_blocked',
  'dlopen_attempts',
  'network_attempts',
];

// Rendered only when non-empty. These signals are rare (a successful audit
// run produces neither), and emitting them as empty lists would churn every
// existing fixture without adding information. Order matches the order they
// were added to LifecycleBlock — append, do not reorder, to keep diffs
// across schema-change PRs minimal.
const OPTIONAL_LIST_FIELDS: Array<keyof LifecycleBlock> = [
  'audit_bypass',
  'env_tamper',
];

export interface RenderInput {
  manager: Lock['manager'];
  manager_lockfile_sha256: string;
  node_version: string;
  generated_at: string;
  packages: Map<string, PackageBlock>;
}

export function render(input: RenderInput): string {
  // Codepoint order rather than localeCompare: localeCompare is ICU-dependent
  // and produces different byte sequences on macOS vs Linux POSIX locale.
  const sortedPkgKeys = [...input.packages.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
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
  // Optional fields are appended after the always-rendered seven, in the
  // order declared in OPTIONAL_LIST_FIELDS. Skip empties so existing
  // fixtures keep their current byte layout when no exec/tamper signal is
  // present (the common case).
  for (const f of OPTIONAL_LIST_FIELDS) {
    const v = block[f];
    if (v.length > 0) out[f] = v;
  }
  return out;
}

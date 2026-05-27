// script-jail — src/guest/apply-pnpm-arch.ts
//
// Merges an optional `supportedArchitectures` block into the repo's root
// package.json before pnpm resolves dependencies.
//
// Why this exists:
//   pnpm does NOT accept `--cpu/--os/--libc` on the CLI — `pnpm install
//   --cpu=x64` fails with "Unknown options: 'cpu', 'os', 'libc'".  pnpm's
//   real override mechanism is a `pnpm.supportedArchitectures` block in the
//   repo's root `package.json`.
//
//   Empirically verified on pnpm 9.15.0:
//     * `pnpm fetch` reads the `pnpm` config block out of package.json even
//       though it ignores the dependency manifest — so the block must be in
//       place BEFORE Phase A (`pnpm fetch`), which is where pnpm picks the
//       platform variants to download into the content-addressed store.
//     * `.npmrc` `supported-architectures.*` and a `pnpm-workspace.yaml`
//       `supportedArchitectures` block are NOT honoured on pnpm 9.x.
//     * Adding the block does NOT invalidate `--frozen-lockfile` and does
//       NOT mutate the lockfile — it is a resolution preference, not part of
//       the lockfile's manifest-equality check.
//
// The repo disk is mounted READ-WRITE at /work inside the VM, and the repo
// copy is a fresh disposable per-run clone, so editing package.json in place
// is safe — it never touches the developer's working tree, and package.json
// is an audit INPUT, not the byte-stable lockfile OUTPUT.
//
// Defensive: every step degrades silently.  A missing overlay file (the
// normal case under same-arch parity), a missing/unreadable/malformed
// package.json, or a malformed overlay all fall through to "no merge".

import * as fs from 'node:fs';
import * as path from 'node:path';

import { z } from 'zod';

/** Absolute path inside the VM where init.sh lands the overlay file. */
export const PNPM_ARCH_PATH = '/etc/script-jail/pnpm-arch.json';

// The overlay carries only the `supportedArchitectures` object.  We keep the
// schema permissive about the inner arrays' contents (pnpm validates them)
// but require the three keys the CLI writes so a truncated file is rejected.
const PnpmArchSchema = z.object({
  supportedArchitectures: z.object({
    os: z.array(z.string()),
    cpu: z.array(z.string()),
    libc: z.array(z.string()),
  }),
});

export interface ApplyPnpmArchInput {
  /** Repo root inside the VM (config.work_dir, normally `/work`). */
  cwd: string;
  /**
   * Override for the overlay file path.  Defaults to PNPM_ARCH_PATH.
   * Exposed so unit tests can point at a temp file.
   */
  overlayPath?: string;
}

export interface ApplyPnpmArchResult {
  /** True when the overlay was found, valid, and merged into package.json. */
  applied: boolean;
}

/**
 * Read `<overlayPath>` and, if present and valid, merge its
 * `supportedArchitectures` object into `<cwd>/package.json` under the `pnpm`
 * key.  Returns `{ applied: false }` on any missing-file / parse / write
 * failure — never throws.
 *
 * The merge preserves every other key in package.json and every sibling key
 * inside an existing `pnpm` block; it only sets `pnpm.supportedArchitectures`
 * when an explicit overlay file is present.
 */
export function applyPnpmArchOverlay(
  input: ApplyPnpmArchInput,
): ApplyPnpmArchResult {
  const overlayPath = input.overlayPath ?? PNPM_ARCH_PATH;

  let supportedArchitectures: unknown;
  try {
    const raw = fs.readFileSync(overlayPath, 'utf8');
    const parsed = PnpmArchSchema.safeParse(JSON.parse(raw));
    if (!parsed.success) return { applied: false };
    supportedArchitectures = parsed.data.supportedArchitectures;
  } catch {
    // ENOENT (the normal action path), malformed JSON, EACCES — no merge.
    return { applied: false };
  }

  const pkgJsonPath = path.join(input.cwd, 'package.json');
  let pkg: Record<string, unknown>;
  let original: string;
  try {
    original = fs.readFileSync(pkgJsonPath, 'utf8');
    const parsed: unknown = JSON.parse(original);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      // A non-object package.json is malformed; leave it untouched.
      return { applied: false };
    }
    pkg = { ...(parsed as Record<string, unknown>) };
  } catch {
    // No package.json (or unreadable / malformed) — nothing to merge into.
    return { applied: false };
  }

  // Preserve any sibling keys inside an existing `pnpm` block (e.g.
  // `overrides`, `peerDependencyRules`) — we only force the architecture
  // filter.
  const existingPnpm =
    pkg['pnpm'] !== null &&
    typeof pkg['pnpm'] === 'object' &&
    !Array.isArray(pkg['pnpm'])
      ? (pkg['pnpm'] as Record<string, unknown>)
      : {};

  pkg['pnpm'] = { ...existingPnpm, supportedArchitectures };

  // Re-serialise with 2-space indent + trailing newline.  package.json is an
  // audit input, not the byte-stable lockfile, so reformatting it inside the
  // disposable VM copy is harmless.
  try {
    fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  } catch {
    return { applied: false };
  }

  return { applied: true };
}

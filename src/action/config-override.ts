// npm-jar — src/action/config-override.ts
//
// Builds a per-run effective copy of the user's npm-jar config YAML with the
// action's `spoof-platform` and `spoof-arch` inputs applied as overrides.
//
// Why this exists:
//   The guest agent reads `spoof.platform` / `spoof.arch` from
//   /etc/npm-jar/config.yml and exports them as NPM_JAR_SPOOF_PLATFORM /
//   NPM_JAR_SPOOF_ARCH for the platform-spoof preload (see
//   src/guest/agent.ts buildChildEnv + src/guest/platform-spoof.cjs).
//   The action also advertises `spoof-platform` / `spoof-arch` inputs and
//   users supplying them expect the input to win over whatever is on disk.
//
// Approach:
//   Parse the user's YAML, mutate `spoof.platform` / `spoof.arch`, serialize
//   the result, write it to a per-run temp file, and return the temp path.
//   The caller (main.ts) passes the returned path into makeOverlay() so the
//   override lands inside the VM's repo disk.  The user's source file on the
//   host is never modified.
//
// We intentionally preserve every other key verbatim — `protected.files`,
// `protected.env`, `node_version`, etc.  The `yaml` library round-trips
// scalars/maps/sequences cleanly; the only field we touch is `spoof`.

import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

import type { SpoofArch, SpoofPlatform } from './inputs.js';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface ConfigOverrides {
  spoofPlatform: SpoofPlatform;
  spoofArch: SpoofArch;
}

export interface BuildEffectiveConfigInput {
  /** Absolute path to the user's npm-jar config YAML on the host. */
  userConfigPath: string;
  /** Action-input overrides to apply on top of the YAML. */
  overrides: ConfigOverrides;
  /**
   * Optional per-run work directory.  If omitted a fresh mkdtemp dir is
   * created under os.tmpdir().  Tests inject a deterministic dir.
   */
  workDir?: string;
}

/**
 * Read the user's config YAML, apply spoof overrides from action inputs,
 * write a per-run config file to `workDir` (or a fresh tmpdir), and return
 * its absolute path.
 *
 * The user's source file is never modified.  The returned path is intended
 * for `makeOverlay({ configPath })` so the override lands in the VM's
 * config disk at /etc/npm-jar/config.yml.
 */
export function buildEffectiveConfig(input: BuildEffectiveConfigInput): string {
  const text = readFileSync(input.userConfigPath, 'utf8');

  // parseYaml returns `unknown` (could be null for an empty file, a scalar,
  // or a mapping).  We coerce to a plain object so the override step is
  // type-safe; if the user wrote `null` or a non-mapping top-level node we
  // start from an empty object and overlay our spoof block onto it.
  const parsed = parseYaml(text) as unknown;
  const config: Record<string, unknown> =
    parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? { ...(parsed as Record<string, unknown>) }
      : {};

  // Merge spoof block: preserve any sibling keys the user may have added
  // (forward-compat) but force platform/arch to the action input values.
  const existingSpoof =
    config['spoof'] !== null &&
    typeof config['spoof'] === 'object' &&
    !Array.isArray(config['spoof'])
      ? (config['spoof'] as Record<string, unknown>)
      : {};

  config['spoof'] = {
    ...existingSpoof,
    platform: input.overrides.spoofPlatform,
    arch: input.overrides.spoofArch,
  };

  const outDir =
    input.workDir ?? mkdtempSync(join(tmpdir(), 'npm-jar-config-'));
  const outPath = join(outDir, 'config.yml');

  // stringifyYaml emits a trailing newline; the agent's parseYaml handles
  // either form, so we don't need to massage the output.
  writeFileSync(outPath, stringifyYaml(config), 'utf8');
  return outPath;
}

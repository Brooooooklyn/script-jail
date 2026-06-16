// script-jail — src/action/config-override.ts
//
// Builds a per-run effective copy of the user's script-jail config YAML with
// the action's `spoof-platform` and `spoof-arch` inputs applied as overrides,
// plus optional package-manager sidecar files.  The default same-arch parity
// path does not create these sidecars, but the plumbing stays here for tests
// and future explicit override modes:
//
//   - .yarnrc.yml          (yarnrcOverlay)     — Yarn Berry supportedArchitectures
//   - etc/script-jail/pm-flags.json (pmFlagsJson)     — npm extra install args
//   - etc/script-jail/pnpm-arch.json (pnpmArchOverlay) — pnpm supportedArchitectures
//
// The sidecar files live in the same `workDir` as the rewritten config so the
// caller can hand the whole bag to `makeOverlay({ extraRepoOverlayFiles: … })`
// and have them land on the repo disk inside the VM.
//
// Why this exists:
//   The guest agent reads `spoof.platform` / `spoof.arch` from
//   /etc/script-jail/config.yml and exports them as SCRIPT_JAIL_SPOOF_PLATFORM /
//   SCRIPT_JAIL_SPOOF_ARCH for the platform-spoof preload (see
//   src/guest/agent.ts buildChildEnv + src/guest/platform-spoof.cjs).
//   The action also advertises `spoof-platform` / `spoof-arch` inputs and
//   users supplying them expect them to win over whatever is on disk.
//
//   If a caller supplies per-PM sidecar payloads, we materialise them here so
//   they travel with the effective config into the VM overlay.
//
// Approach:
//   Parse the user's YAML, mutate `spoof.platform` / `spoof.arch`, serialize
//   the result, write it to a per-run temp file, and (optionally) write the
//   yarnrc / pm-flags sidecars under the same workDir.  Return all three
//   paths so the caller can pass them into `makeOverlay`.  The user's source
//   file on the host is never modified.
//
// We intentionally preserve every other key verbatim — `protected.files`,
// `protected.env`, `node_version`, etc.  The `yaml` library round-trips
// scalars/maps/sequences cleanly; the only field we touch is `spoof`.

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
  /** Absolute path to the user's script-jail config YAML on the host. */
  userConfigPath: string;
  /** Action-input overrides to apply on top of the YAML. */
  overrides: ConfigOverrides;
  /**
   * Optional per-run work directory.  If omitted a fresh mkdtemp dir is
   * created under os.tmpdir().  Tests inject a deterministic dir.
   */
  workDir?: string;
  /**
   * Optional override for the guest audit `work_dir` (the cwd the lifecycle
   * scripts run at).  Set for `install: true` to the real host repoDir so the
   * sandbox audit runs at the SAME absolute path as the host re-run, closing a
   * `process.cwd()` detection oracle (FC/docker; bare/mac-bare re-pin work_dir
   * to their staged path via `rewriteConfigWorkDir`, so this is overridden
   * there — the cwd parity is a documented residual for those backends).  When
   * undefined the guest schema default (`/work`) stands.  The literal value
   * never reaches the lock — it is tokenized to `$REPO` (src/lock/tokenize.ts).
   */
  workDirOverride?: string;
  /**
   * Optional `.yarnrc.yml` content to materialize alongside the config.
   * Optional Yarn Berry `supportedArchitectures` override.  Written verbatim
   * to `<workDir>/.yarnrc.yml`.
   */
  yarnrcOverlay?: string;
  /**
   * Optional `etc/script-jail/pm-flags.json` payload.  Read by the guest
   * (`src/guest/phase-fetch.ts`).  Two channels:
   *   * `extra_install_args` — npm-only arch hints (`--cpu/--os/--libc`),
   *     appended to `npm ci` only (pnpm/yarn reject these CLI flags).
   *   * `user_install_args`  — developer install flags (the action `args`
   *     input), appended to ALL THREE managers' fetch command.
   * Written verbatim (after JSON.stringify) to
   * `<workDir>/etc/script-jail/pm-flags.json`.
   */
  pmFlagsJson?: { extra_install_args: string[]; user_install_args?: string[] };
  /**
   * Optional `etc/script-jail/pnpm-arch.json` content.  Provided by the
   * Optional pnpm `supportedArchitectures` override.  The guest
   * (`src/guest/apply-pnpm-arch.ts`) merges it into the repo's root
   * `package.json` under the `pnpm` key before Phase A.
   * Written verbatim to `<workDir>/etc/script-jail/pnpm-arch.json`.
   */
  pnpmArchOverlay?: string;
}

export interface BuildEffectiveConfigResult {
  /** Absolute path to the rewritten config YAML.  Always present. */
  configPath: string;
  /** Absolute path to the .yarnrc.yml sidecar, if `yarnrcOverlay` was supplied. */
  yarnrcPath?: string;
  /** Absolute path to the pm-flags.json sidecar, if `pmFlagsJson` was supplied. */
  pmFlagsPath?: string;
  /** Absolute path to the pnpm-arch.json sidecar, if `pnpmArchOverlay` was supplied. */
  pnpmArchPath?: string;
}

/**
 * Read the user's config YAML, apply spoof overrides from action inputs,
 * write a per-run config file to `workDir` (or a fresh tmpdir), and return
 * its absolute path along with any sidecar paths.
 *
 * The user's source file is never modified.  The returned paths are intended
 * for `makeOverlay({ configPath, extraRepoOverlayFiles })` so the overrides
 * land on the VM's repo disk.
 */
export function buildEffectiveConfig(
  input: BuildEffectiveConfigInput,
): BuildEffectiveConfigResult {
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

  // `install: true` cwd parity (FC/docker): pin the guest audit cwd to the real
  // host repoDir so `process.cwd()` matches the uninstrumented host re-run.
  // bare/mac-bare overwrite this with their staged path downstream.  Tokenized
  // to `$REPO` in the lock, so the runner-specific value is byte-stable.
  if (input.workDirOverride !== undefined) {
    config['work_dir'] = input.workDirOverride;
  }

  const outDir =
    input.workDir ?? mkdtempSync(join(tmpdir(), 'script-jail-config-'));
  const configPath = join(outDir, 'config.yml');

  // stringifyYaml emits a trailing newline; the agent's parseYaml handles
  // either form, so we don't need to massage the output.
  writeFileSync(configPath, stringifyYaml(config), 'utf8');

  const result: BuildEffectiveConfigResult = { configPath };

  if (input.yarnrcOverlay !== undefined) {
    const yarnrcPath = join(outDir, '.yarnrc.yml');
    writeFileSync(yarnrcPath, input.yarnrcOverlay, 'utf8');
    result.yarnrcPath = yarnrcPath;
  }

  if (input.pmFlagsJson !== undefined) {
    const pmFlagsPath = join(outDir, 'etc', 'script-jail', 'pm-flags.json');
    mkdirSync(dirname(pmFlagsPath), { recursive: true });
    // Pretty-print so the file is reviewable on disk; the guest's parser
    // doesn't care either way (JSON.parse handles whitespace).
    writeFileSync(pmFlagsPath, JSON.stringify(input.pmFlagsJson, null, 2) + '\n', 'utf8');
    result.pmFlagsPath = pmFlagsPath;
  }

  if (input.pnpmArchOverlay !== undefined) {
    const pnpmArchPath = join(outDir, 'etc', 'script-jail', 'pnpm-arch.json');
    mkdirSync(dirname(pnpmArchPath), { recursive: true });
    // Written verbatim — the content is already hand-formatted deterministic
    // JSON in src/cli/arch-flags.ts.
    writeFileSync(pnpmArchPath, input.pnpmArchOverlay, 'utf8');
    result.pnpmArchPath = pnpmArchPath;
  }

  return result;
}

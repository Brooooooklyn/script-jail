// script-jail — src/action/install-preflight.ts
//
// Pre-trust fail-closed preconditions for `install: true`.
//
// Drop-in install runs a no-scripts package-manager install on the GitHub
// runner (host part-1, hostInstallNoScripts) BEFORE the trust gate.  Some
// package managers EXECUTE repo-controlled CONFIG files during that "no-scripts"
// install — independently of lifecycle scripts — which would run arbitrary PR
// code on the runner before the audit has decided anything.  `--ignore-scripts`
// / `--mode=skip-build` do NOT stop these config hooks.  This module detects
// them statically so main() can refuse `install: true` before spending an audit.
//
// SCOPE: relevant ONLY to `install: true`.  In pure-audit mode (install off) the
// host never installs; these hooks run ONLY inside the sandbox, where they are
// AUDITED by design (the sandbox is the enforcement boundary — see
// src/rootfs/init.sh).  So this gate is wired exclusively into the install
// precondition block in main.ts.
//
// Manager coverage (empirically verified against pnpm 10.34/11.1 + yarn Berry 4.16):
//   * pnpm — a repo `.pnpmfile.cjs` (and config-RELOCATED pnpmfiles) execute at
//     `require` time during `pnpm install --frozen-lockfile --ignore-scripts`.
//     DEFENSE IN DEPTH: the host fetch ALSO passes `--ignore-pnpmfile`
//     (host-install.ts), a robust catch-all with no path-enumeration gap that
//     suppresses every pnpmfile variant; this static reject is the clean, early
//     UX message for the known config sources (and a backstop if the flag ever
//     regresses).  Relocation sources confirmed: `.npmrc` `pnpmfile=` /
//     `global-pnpmfile=` (pnpm <=10), `pnpm-workspace.yaml` `pnpmfile:` (all
//     versions) and `configDependencies:`.
//   * yarn (Berry) — `.yarnrc.yml` `yarnPath` (re-execs a repo binary), `plugins`
//     (loads repo modules at startup), and `enableConstraintsChecks: true` (runs
//     repo `yarn.config.cjs` via the install-time validate hook) all execute
//     during `yarn install --immutable --mode=skip-build`.  NO single yarn flag
//     suppresses all three, so this reject IS the enforcement for yarn.  Classic
//     `.yarnrc` `yarn-path` is NOT honored under Berry, so it is not a vector.
//   * npm — the only known pre-trust config exec (the `git` BINARY selected for a
//     non-GitHub git dep) is already neutralized by the `npm_config_git` pin in
//     host-install.ts.  Nothing left to detect here.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

import type { Manager } from '../shared/pm-commands.js';

/**
 * Returns a human-readable reason string when `install: true` must be REFUSED
 * because the repo declares config that would execute code on the runner during
 * the pre-trust host no-scripts install; null when safe to proceed.
 */
export function detectPreTrustConfigExec(repoDir: string, manager: Manager): string | null {
  if (manager === 'pnpm') return detectPnpmfile(repoDir);
  if (manager === 'yarn') return detectYarnStartupExec(repoDir);
  return null;
}

const PNPM_GUIDANCE =
  ' would run unaudited on the runner BEFORE the audit decides anything. ' +
  '`install: true` cannot trust a tree built by a pnpmfile. Remove the pnpmfile, ' +
  'or audit without `install` (the sandbox still records the pnpmfile there).';

function detectPnpmfile(repoDir: string): string | null {
  // Default pnpmfile.  Only `.pnpmfile.cjs` (leading dot) is a pnpm default;
  // `pnpmfile.cjs` without the dot is NOT auto-loaded (verified) — do not flag it.
  if (existsSync(join(repoDir, '.pnpmfile.cjs'))) {
    return 'a repo `.pnpmfile.cjs`' + PNPM_GUIDANCE;
  }
  // `.npmrc` relocation: `pnpmfile=` / `global-pnpmfile=` point pnpm at a repo
  // file it executes (live on pnpm <=10; pnpm 11 ignores these from project
  // `.npmrc`, but the host `--ignore-pnpmfile` backstop covers that gap anyway).
  const npmrc = tryReadFile(join(repoDir, '.npmrc'));
  if (npmrc !== null && npmrcHasPnpmfileKey(npmrc)) {
    return 'a repo `.npmrc` `pnpmfile`/`global-pnpmfile` override' + PNPM_GUIDANCE;
  }
  // `pnpm-workspace.yaml` relocation: `pnpmfile:` (all versions) or a
  // `configDependencies:` injection both point pnpm at repo-controlled code.
  const ws = tryReadFile(join(repoDir, 'pnpm-workspace.yaml'));
  if (ws !== null) {
    let parsed: unknown;
    try {
      parsed = parseYaml(ws);
    } catch {
      // Unparseable workspace file: cannot prove it declares no pnpmfile. Fail closed.
      return 'an unparseable `pnpm-workspace.yaml` (cannot prove no `pnpmfile`)' + PNPM_GUIDANCE;
    }
    if (isRecord(parsed) && ('pnpmfile' in parsed || 'configDependencies' in parsed)) {
      return 'a repo `pnpm-workspace.yaml` `pnpmfile`/`configDependencies`' + PNPM_GUIDANCE;
    }
  }
  // Root `package.json` `pnpm.configDependencies` (pnpm 10) injects an
  // attacker-published config package that pnpm FETCHES + extracts during the
  // install — BEFORE the trust gate, and NOT suppressed by `--ignore-pnpmfile`
  // (the fetch/extract happens in config bootstrap, outside that guard; on pnpm
  // 10 even `--frozen-lockfile` is no defense).  `pnpm.pnpmfile` is not honored
  // from package.json on current pnpm, but is rejected for defense in depth.
  const pkgJson = tryReadFile(join(repoDir, 'package.json'));
  if (pkgJson !== null) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(pkgJson) as unknown;
    } catch {
      // Unparseable root package.json: cannot prove it declares no pnpm config. Fail closed.
      return 'an unparseable root `package.json` (cannot prove no `pnpm.configDependencies`)' + PNPM_GUIDANCE;
    }
    if (isRecord(parsed) && isRecord(parsed['pnpm'])) {
      const pnpmField = parsed['pnpm'];
      if ('configDependencies' in pnpmField || 'pnpmfile' in pnpmField) {
        return 'a repo `package.json` `pnpm.configDependencies`/`pnpm.pnpmfile`' + PNPM_GUIDANCE;
      }
    }
  }
  return null;
}

const YARN_GUIDANCE =
  ' executes repo-controlled code on the runner at `yarn install` startup, ' +
  'BEFORE the audit decides anything. `install: true` cannot run that pre-trust. ' +
  'Remove it, or audit without `install` (the sandbox still records it there).';

function detectYarnStartupExec(repoDir: string): string | null {
  // Berry reads ONLY `.yarnrc.yml`; classic `.yarnrc` `yarn-path` is ignored
  // under corepack/Berry (verified), so it is not a vector and is not checked.
  const content = tryReadFile(join(repoDir, '.yarnrc.yml'));
  if (content === null) return null;
  let parsed: unknown;
  try {
    parsed = parseYaml(content);
  } catch {
    // Present but unparseable: cannot prove it declares no startup exec. Fail closed.
    return 'a present-but-unparseable `.yarnrc.yml` (cannot prove no `yarnPath`/`plugins`)' + YARN_GUIDANCE;
  }
  if (!isRecord(parsed)) return null; // empty / scalar yaml declares nothing
  if (typeof parsed['yarnPath'] === 'string' && parsed['yarnPath'].length > 0) {
    return 'a repo `.yarnrc.yml` `yarnPath`' + YARN_GUIDANCE;
  }
  if (Array.isArray(parsed['plugins']) && parsed['plugins'].length > 0) {
    return 'a repo `.yarnrc.yml` `plugins` entry' + YARN_GUIDANCE;
  }
  // `enableConstraintsChecks: true` runs `yarn.config.cjs`/`.js` via the
  // install-time validate hook — only when that config file actually exists
  // (without it the hook no-ops), so require both to avoid over-firing.
  if (
    isTruthyYamlBool(parsed['enableConstraintsChecks']) &&
    (existsSync(join(repoDir, 'yarn.config.cjs')) || existsSync(join(repoDir, 'yarn.config.js')))
  ) {
    return 'a repo `.yarnrc.yml` `enableConstraintsChecks` with a `yarn.config.cjs`' + YARN_GUIDANCE;
  }
  return null;
}

/** Read a file, or null on any error (ENOENT etc.). */
function tryReadFile(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** YAML boolean `true`, tolerating a quoted `"true"` string. */
function isTruthyYamlBool(v: unknown): boolean {
  return v === true || v === 'true';
}

/**
 * Scan `.npmrc` (ini grammar) for a `pnpmfile=` / `global-pnpmfile=` key.
 * Comments (`;`/`#`) are stripped; only the key before `=` matters, so a value
 * that itself contains a comment char cannot hide the key.
 */
function npmrcHasPnpmfileKey(content: string): boolean {
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/[;#].*$/, '').trim();
    if (line === '') continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    if (key === 'pnpmfile' || key === 'global-pnpmfile') return true;
  }
  return false;
}

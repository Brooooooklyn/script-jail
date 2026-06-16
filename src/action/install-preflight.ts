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
//   * pnpm — a repo default pnpmfile (`.pnpmfile.mjs`, the preferred default on
//     pnpm 11.x, tried first; or `.pnpmfile.cjs`, the fallback) and
//     config-RELOCATED pnpmfiles execute at `require` time during
//     `pnpm install --frozen-lockfile --ignore-scripts`.
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

import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';

import type { Manager } from '../shared/pm-commands.js';
import { unsupportedAltRootManifest } from '../shared/root-manifest.js';

/**
 * Returns a human-readable reason string when `install: true` must be REFUSED
 * because the repo declares config that would execute code on the runner during
 * the pre-trust host no-scripts install; null when safe to proceed.
 *
 * `workspaceRoot` (GITHUB_WORKSPACE on the runner) bounds the ancestor scans:
 * when `repoDir` is a SUBDIRECTORY of the checkout, yarn (and pnpm's
 * `configDependencies`) walk UP parent directories at install startup, so the
 * preflight must inspect every dir from `repoDir` up to and INCLUDING the
 * workspace root — but NEVER above it (parent dirs / `~` are runner-owned, not
 * PR-controlled).  When omitted, undefined, or when `repoDir` is OUTSIDE the
 * workspace (e2e: SCRIPT_JAIL_REPO_DIR points at a runner-temp consumer dir),
 * only `repoDir` itself is scanned — byte-identical to the pre-ancestor-scan
 * behavior and the common `repoDir === workspaceRoot` consumer case.
 */
export function detectPreTrustConfigExec(
  repoDir: string,
  manager: Manager,
  workspaceRoot?: string,
): string | null {
  if (manager === 'pnpm') return detectPnpmfile(repoDir, workspaceRoot);
  if (manager === 'yarn') return detectYarnStartupExec(repoDir, workspaceRoot);
  return null;
}

/**
 * The list of directories to inspect for repo-controlled config, ordered from
 * `repoDir` UP to (and including) `workspaceRoot`.  Boundary rules:
 *   * `workspaceRoot` undefined/empty → only `repoDir` (non-action / local).
 *   * `repoDir` NOT inside `workspaceRoot` (e.g. an outside runner-temp consumer
 *     dir) → only `repoDir`; its ancestors are runner-owned, not PR-controlled.
 *   * otherwise walk via `dirname` from `repoDir` up, STOPPING after the dir
 *     equal to `workspaceRoot`; never above it.  FS-root safety guards the loop.
 *   * common `repoDir === workspaceRoot` → exactly one dir (`repoDir`).
 *
 * Both paths are resolved to their REAL (symlink-free) form first, so a
 * symlinked `repoDir` walks the same ancestor chain Yarn/pnpm actually read on
 * disk (a lexical-only walk could diverge from the real cwd and miss a real
 * PR-controlled ancestor — or inspect the wrong parent chain).
 */
function scanDirs(repoDir: string, workspaceRoot?: string): string[] {
  const repo = realpathOrResolve(repoDir);
  if (workspaceRoot === undefined || workspaceRoot === '') return [repo];
  const root = realpathOrResolve(workspaceRoot);
  // Separator-aware containment: `relative()` of '' means repo === root; a normal
  // relative path means repo is a DESCENDANT.  Only a result of exactly '..',
  // one that starts with '..' + path separator, or an absolute path means repo is
  // genuinely OUTSIDE root.  A bare `.startsWith('..')` is WRONG: it misclassifies
  // a sibling-named child like `<root>/..pkg/app` (rel `..pkg/app`) as outside and
  // would skip the PR-controlled ancestors between it and root.
  const rel = relative(root, repo);
  const outside = rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel);
  if (outside) return [repo];
  const dirs: string[] = [];
  let cur = repo;
  // Walk up to and including `root`.  Stop at `root`, and guard the FS root.
  for (;;) {
    dirs.push(cur);
    if (cur === root) break;
    const parent = dirname(cur);
    if (parent === cur) break; // FS-root safety (should not trigger: repo is under root)
    cur = parent;
  }
  return dirs;
}

/**
 * Resolve a path to its real (symlink-free) absolute form so the ancestor walk
 * matches the actual files Yarn/pnpm read on disk.  Falls back to a lexical
 * `resolve()` when the path does not exist yet (realpathSync throws ENOENT) so
 * non-existent inputs behave exactly as the pre-realpath code did.
 */
function realpathOrResolve(p: string): string {
  const abs = resolve(p);
  try {
    return realpathSync(abs);
  } catch {
    return abs;
  }
}

const PNPM_GUIDANCE =
  ' would run unaudited on the runner BEFORE the audit decides anything. ' +
  '`install: true` cannot trust a tree built by a pnpmfile. Remove the pnpmfile, ' +
  'or audit without `install` (the sandbox still records the pnpmfile there).';

function detectPnpmfile(repoDir: string, workspaceRoot?: string): string | null {
  // First, the full set of repoDir checks (byte-identical to before).  These
  // include the pnpmfile vectors — kept as the clean early UX message even
  // though the host `--ignore-pnpmfile` already backstops every pnpmfile variant.
  const atRepo = detectPnpmConfigInRepoDir(repoDir);
  if (atRepo !== null) return atRepo;
  // Then the ANCESTOR scan — but ONLY for `configDependencies`.  Unlike the
  // pnpmfile vectors (which `--ignore-pnpmfile` suppresses regardless of which
  // directory pnpm found them in — see host-install.ts), a `configDependencies:`
  // declared in an ANCESTOR `pnpm-workspace.yaml`/`package.json` within the
  // checkout is FETCHED + EXTRACTED during the pre-trust install (pnpm's
  // workspace-root discovery walks UP) and is NOT covered by `--ignore-pnpmfile`
  // (the fetch/extract runs in config bootstrap, outside that guard).  Mirror the
  // repoDir `configDependencies` reject up the ancestor chain, bounded to the
  // workspace.  (The other pnpm sources need no ancestor scan: pnpmfiles are
  // backstopped, and an alt root manifest only matters at the project root pnpm
  // picks, already handled at repoDir.)
  const ancestors = scanDirs(repoDir, workspaceRoot);
  for (let i = 1; i < ancestors.length; i++) {
    const reason = detectPnpmConfigDepsInDir(ancestors[i]!);
    if (reason !== null) return reason;
  }
  return null;
}

/** The repoDir-only checks: pnpmfile variants + configDependencies + alt manifest. */
function detectPnpmConfigInRepoDir(repoDir: string): string | null {
  // Default pnpmfile.  pnpm auto-loads TWO default pnpmfiles (both leading-dot):
  // `.pnpmfile.mjs` (the PREFERRED default on pnpm 11.x — tried first) and
  // `.pnpmfile.cjs` (the fallback when no `.mjs` exists).  Verified against the
  // pinned pnpm 11.1.2: under `if (!config.ignorePnpmfile)` it resolves
  // `.pnpmfile.mjs` first and only falls back to `.pnpmfile.cjs` when the `.mjs`
  // is absent — so a repo shipping ONLY a `.pnpmfile.mjs` is a live vector and
  // must be flagged.  Dot-less `pnpmfile.cjs`/`pnpmfile.mjs` and a `.pnpmfile.js`
  // (no .mjs/.cjs ext) are NOT pnpm defaults (verified) — do not flag them.
  // Check `.mjs` first, mirroring pnpm's own resolution order.
  if (existsSync(join(repoDir, '.pnpmfile.mjs'))) {
    return 'a repo `.pnpmfile.mjs`' + PNPM_GUIDANCE;
  }
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
  // pnpm 10 also reads `pnpm.configDependencies` (and lifecycle scripts) from a
  // `package.yaml` / `package.json5` root manifest when there is NO package.json
  // — slipping the configDependencies fetch and the nameless-root lifecycle past
  // the package.json-only checks above.  We do not parse those formats (no JSON5
  // parser; parsing alone would not make the rest of the pipeline format-aware),
  // so fail closed on that exact shape.  `install: true` needs a package.json we
  // can fully reason about; the repo can still audit without `install`.
  const altManifest = unsupportedAltRootManifest(repoDir);
  if (altManifest !== null) {
    return `a repo \`${altManifest}\` root manifest with no \`package.json\` (pnpm reads ` +
      'its `pnpm.configDependencies` and lifecycle scripts, which script-jail cannot vet ' +
      'pre-trust); `install: true` requires a `package.json`. Audit without `install`, ' +
      'or convert the root manifest to `package.json`.';
  }
  return null;
}

/**
 * ANCESTOR-only check: a `configDependencies` declaration in an ancestor
 * `pnpm-workspace.yaml` or `package.json` `pnpm.configDependencies`.  pnpm
 * discovers the workspace root by walking UP, so an ancestor declaration is
 * fetched + extracted pre-trust (NOT suppressed by `--ignore-pnpmfile`).  We do
 * NOT re-check the ancestor pnpmfile vectors (backstopped) here.  Unparseable
 * ancestor config fails closed (cannot prove it declares no configDependencies).
 */
function detectPnpmConfigDepsInDir(dir: string): string | null {
  const ws = tryReadFile(join(dir, 'pnpm-workspace.yaml'));
  if (ws !== null) {
    let parsed: unknown;
    try {
      parsed = parseYaml(ws);
    } catch {
      return `an ancestor (\`${dir}\`) unparseable \`pnpm-workspace.yaml\` (cannot prove no \`configDependencies\`)` + PNPM_GUIDANCE;
    }
    if (isRecord(parsed) && 'configDependencies' in parsed) {
      return `an ancestor (\`${dir}\`) \`pnpm-workspace.yaml\` \`configDependencies\`` + PNPM_GUIDANCE;
    }
  }
  const pkgJson = tryReadFile(join(dir, 'package.json'));
  if (pkgJson !== null) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(pkgJson) as unknown;
    } catch {
      return `an ancestor (\`${dir}\`) unparseable \`package.json\` (cannot prove no \`pnpm.configDependencies\`)` + PNPM_GUIDANCE;
    }
    if (isRecord(parsed) && isRecord(parsed['pnpm']) && 'configDependencies' in parsed['pnpm']) {
      return `an ancestor (\`${dir}\`) \`package.json\` \`pnpm.configDependencies\`` + PNPM_GUIDANCE;
    }
  }
  return null;
}

const YARN_GUIDANCE =
  ' executes repo-controlled code on the runner at `yarn install` startup, ' +
  'BEFORE the audit decides anything. `install: true` cannot run that pre-trust. ' +
  'Remove it, or audit without `install` (the sandbox still records it there).';

function detectYarnStartupExec(repoDir: string, workspaceRoot?: string): string | null {
  // Berry walks UP from the install cwd and loads `.yarnrc.yml` from EACH
  // ancestor dir at startup, so a `plugins:`/`yarnPath` in a parent rc within the
  // checkout executes repo code pre-trust even when repoDir's own rc is clean.
  // Scan every dir from repoDir up to (and including) the workspace root; the
  // common repoDir===workspaceRoot case scans exactly repoDir (unchanged).
  const repo = resolve(repoDir);
  for (const dir of scanDirs(repoDir, workspaceRoot)) {
    const reason = detectYarnStartupExecInDir(dir, dir === repo);
    if (reason !== null) return reason;
  }
  return null;
}

/**
 * Apply the yarn startup-exec checks to a SINGLE directory's `.yarnrc.yml`.
 * `atRepoDir` controls whether the error message names the ancestor dir (for a
 * clear diagnostic when the offending rc is NOT the repo's own).
 */
function detectYarnStartupExecInDir(dir: string, atRepoDir: boolean): string | null {
  // Berry reads ONLY `.yarnrc.yml`; classic `.yarnrc` `yarn-path` is ignored
  // under corepack/Berry (verified), so it is not a vector and is not checked.
  const content = tryReadFile(join(dir, '.yarnrc.yml'));
  if (content === null) return null;
  // For an ancestor rc, name the dir so the user can find the offending file.
  const where = atRepoDir ? 'a repo' : `an ancestor (\`${dir}\`)`;
  let parsed: unknown;
  try {
    parsed = parseYaml(content);
  } catch {
    // Present but unparseable: cannot prove it declares no startup exec. Fail closed.
    return `${where} present-but-unparseable \`.yarnrc.yml\` (cannot prove no \`yarnPath\`/\`plugins\`)` + YARN_GUIDANCE;
  }
  if (!isRecord(parsed)) return null; // empty / scalar yaml declares nothing
  if (typeof parsed['yarnPath'] === 'string' && parsed['yarnPath'].length > 0) {
    return `${where} \`.yarnrc.yml\` \`yarnPath\`` + YARN_GUIDANCE;
  }
  if (Array.isArray(parsed['plugins']) && parsed['plugins'].length > 0) {
    return `${where} \`.yarnrc.yml\` \`plugins\` entry` + YARN_GUIDANCE;
  }
  // `enableConstraintsChecks` runs `yarn.config.cjs` via the install-time validate
  // hook — only when that config file actually exists (without it the hook
  // no-ops), so require both to avoid over-firing.  The filename is `yarn.config.cjs`
  // ONLY: yarn Berry's `loadUserConfig()` hardcodes that literal (verified across
  // 4.5.0–4.16.0) — `yarn.config.js`/`.mjs` are NEVER loaded, so an inert `.js`
  // must not trip this gate.  Yarn coerces several representations to enabled
  // (true / "true" / 1 / "1"); rather than enumerate them, fail closed for
  // ANYTHING that is not DEFINITELY false (matches yarn's own behavior, which
  // throws on unrecognized values — refusing is the safe direction).  Yarn
  // resolves `yarn.config.cjs` from the rc's PROJECT ROOT (the dir holding the
  // enabling rc), so check it in the SAME dir as the rc that enabled the hook.
  if (
    isNotDefinitelyFalse(parsed['enableConstraintsChecks']) &&
    existsSync(join(dir, 'yarn.config.cjs'))
  ) {
    return `${where} \`.yarnrc.yml\` \`enableConstraintsChecks\` with a \`yarn.config.cjs\`` + YARN_GUIDANCE;
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

/**
 * True unless the parsed value is one yarn DEFINITELY treats as false (or is
 * absent).  Used so `enableConstraintsChecks` is rejected for every enabling
 * representation yarn accepts (true / "true" / 1 / "1", and the values yarn
 * errors on) without enumerating them — only an explicit false/0/empty/null
 * disables the constraints hook.
 */
function isNotDefinitelyFalse(v: unknown): boolean {
  return !(
    v === false ||
    v === 'false' ||
    v === 0 ||
    v === '0' ||
    v === null ||
    v === '' ||
    v === undefined
  );
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

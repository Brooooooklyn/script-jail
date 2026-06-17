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
 * Read the consumer config's declared `protected.env` secret NAMES, used by the
 * host part-2 redactor (`hostRunScripts`) to mask those env values out of the
 * trusted-script lifecycle output before it reaches the job log.  Best-effort: a
 * missing / malformed config or absent field yields `[]` (no exact-value masking;
 * credential-SHAPE redaction still applies).  Matches the guest schema default
 * (`protected.env` defaults to `[]`), so host and sandbox mask the same names.
 */
export function readProtectedEnvNames(configPath: string): string[] {
  try {
    const raw = parseYaml(readFileSync(configPath, 'utf8')) as
      | { protected?: { env?: unknown } }
      | null;
    const env = raw?.protected?.env;
    if (!Array.isArray(env)) return [];
    return env.filter((e): e is string => typeof e === 'string' && e.length > 0);
  } catch {
    return [];
  }
}

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
 * Returns a reason when `install: true` must be REFUSED because the runner's
 * `$HOME` resolves UNDER the checkout (PR-controlled), null otherwise.
 *
 * SECURITY: every package manager loads config from `$HOME` at startup, BEFORE
 * the trust gate and independent of `--ignore-scripts`/`--mode=skip-build`:
 * `$HOME/.yarnrc.yml` `plugins:`/`yarnPath` run repo code at yarn config-load
 * (VERIFIED yarn 4.5.0: a HOME-rc `plugins:` entry executes during
 * `yarn install --immutable --mode=skip-build` even with the `YARN_PLUGINS=''` /
 * `YARN_IGNORE_PATH=1` pins — those govern the ENV plugin source, not the rc-file
 * cascade), and `$HOME/.npmrc` is npm's DEFAULT userconfig (a `script-shell=<pwn>`
 * there runs on `npm rebuild`).  `hostInstallEnv` preserves `HOME` verbatim and
 * the clean-VM audit uses a DIFFERENT `HOME`, so it never sees a PR-committed home
 * config — unaudited host RCE.  The `repoDir`->`workspaceRoot` ancestor scan does
 * NOT cover a `$HOME` that is a sibling/non-ancestor checkout path (e.g.
 * `$GITHUB_WORKSPACE/.home`).  A checkout-relative `$HOME` has no legitimate
 * install use (the runner's real home is outside the checkout), so fail closed.
 *
 * A RELATIVE `$HOME` is refused outright (BEFORE the containment test).  The PM
 * expands `~/.npmrc` against ITS OWN cwd — the host install/rebuild spawns the PM
 * with `cwd=repoDir` — whereas this preflight runs in the action process whose
 * `cwd` need NOT equal `repoDir` (subdir install: action at `$GITHUB_WORKSPACE`,
 * `repoDir=$GITHUB_WORKSPACE/pkg`).  Resolving a relative `$HOME` here against the
 * action `cwd` therefore lands on a DIFFERENT path than the PM sees, so the
 * containment test can pass while npm reads `repoDir/../.home/.npmrc` =
 * `$GITHUB_WORKSPACE/.home/.npmrc` (PR-controlled) and execs its `script-shell`
 * (VERIFIED npm 11.13.0).  A real runner `$HOME` is always absolute, so failing
 * closed on a non-absolute value closes the cwd-resolution mismatch with no
 * legitimate loss.
 */
export function detectCheckoutRelativeHome(
  homeDir: string | undefined,
  repoDir: string,
  workspaceRoot?: string,
): string | null {
  if (homeDir === undefined || homeDir === '') return null;
  if (!isAbsolute(homeDir)) {
    return (
      `HOME (\`${homeDir}\`) is a RELATIVE path. Each package manager expands ` +
      `\`~/.npmrc\` (and \`~/.yarnrc.yml\`) against ITS OWN working directory — the host ` +
      `install runs the PM with \`cwd=repoDir\` — so a relative HOME can resolve INTO the ` +
      `checkout (e.g. \`../.home\` -> \`$GITHUB_WORKSPACE/.home/.npmrc\` for a subdir repo) and ` +
      `execute a PR-committed home config on the runner BEFORE the audit decides anything, ` +
      `unseen by the sandbox. Set HOME to an ABSOLUTE path outside the checkout for the ` +
      `script-jail step, or audit without \`install\`.`
    );
  }
  const home = realpathOrResolve(homeDir);
  const roots = [realpathOrResolve(repoDir)];
  if (workspaceRoot !== undefined && workspaceRoot !== '') roots.push(realpathOrResolve(workspaceRoot));
  for (const root of roots) {
    if (isPathUnder(home, root)) {
      return (
        `HOME (\`${homeDir}\`) resolves under the checkout (\`${root}\`). Package managers ` +
        `load config from \`$HOME\` at startup (\`$HOME/.yarnrc.yml\` plugins / \`$HOME/.npmrc\` ` +
        `script-shell), so a PR-committed home config would execute on the runner BEFORE the ` +
        `audit decides anything — unseen by the sandbox, which uses a different HOME. Set HOME ` +
        `to a path OUTSIDE the checkout for the script-jail step, or audit without \`install\`.`
      );
    }
  }
  return null;
}

/**
 * Returns a human-readable reason when `install: true` must be REFUSED because
 * the consumer config declares a `work_dir` that DIVERGES from the host install
 * cwd; null when aligned (default `/work`, unset, or explicitly `/work`).
 *
 * SECURITY: `work_dir` is a consumer-settable config-FILE field with NO clamp
 * (guest schema default `/work`).  For Firecracker/Docker the consumer's config
 * (work_dir intact) reaches the guest verbatim, so the guest audits at
 * `cwd=config.work_dir` (e.g. `/work/packages/app`) — while host part-1 install
 * and host part-2 lifecycle rebuild ALWAYS run at the repoDir ROOT (mounted as
 * `/work`).  The whole repoDir is staged at `/work`, so a benign SUBPROJECT can
 * audit clean (trusted=true) while host part-2 then runs UN-AUDITED repo-ROOT
 * lifecycle scripts on the runner.  Fail closed BEFORE the audit.  (bare /
 * mac-bare are immune — `rewriteConfigWorkDir` discards work_dir there — but we
 * cannot know the backend at this point and the FC/docker exposure is real, so
 * refuse unconditionally; the fix for a real subproject is to point script-jail
 * at the subproject root via SCRIPT_JAIL_REPO_DIR, not to set work_dir.)
 */
export function detectInstallWorkDirDivergence(configPath: string): string | null {
  if (!existsSync(configPath)) return null; // absent config => default work_dir '/work'
  let parsed: unknown;
  try {
    parsed = parseYaml(readFileSync(configPath, 'utf8'));
  } catch {
    return null; // malformed config handled elsewhere
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const wd = (parsed as Record<string, unknown>)['work_dir'];
  if (wd === undefined) return null; // unset => default '/work'
  if (typeof wd !== 'string' || wd === '/work') return null; // staged repo root => aligned
  return (
    `config sets work_dir to '${wd}', but \`install: true\` runs the host install/rebuild at the ` +
    `repository root (mounted as /work in the sandbox). The guest would audit '${wd}' while the ` +
    `runner installs and runs lifecycle scripts at the repo root, so a clean lock for that subdir ` +
    `would authorize unaudited repo-root scripts. Remove work_dir (or set it to '/work') when using \`install\`, ` +
    `or run script-jail at the subproject root via SCRIPT_JAIL_REPO_DIR.`
  );
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

/**
 * True when `child` IS `root` or is nested under it.  Both MUST already be
 * realpath'd (so symlinks/case resolve identically on both sides).  Separator-aware
 * (mirrors `scanDirs`' containment): a `relative()` of `''` means equal; a normal
 * relative path means descendant; only `'..'`, a `'..'+sep` prefix, or an absolute
 * result means `child` is genuinely OUTSIDE `root`.
 */
function isPathUnder(child: string, root: string): boolean {
  if (child === root) return true;
  const rel = relative(root, child);
  if (rel === '') return true;
  return !(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel));
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
  // picks, already handled at repoDir.)  The reason ancestor pnpmfiles need no
  // scan is twofold: (1) BOTH host halves suppress the pnpmfile on the runner —
  // part-1 `--ignore-pnpmfile` and part-2 `pnpm rebuild --config.ignore-pnpmfile=true`
  // (host-install.ts) — so an ancestor pnpmfile never EXECUTES on the runner;
  // and (2) the sandbox stages ONLY repoDir (overlay.ts:170 / stage.ts:26) and
  // runs pnpm at /work, so an ancestor pnpmfile above repoDir is never present
  // in the guest and cannot rewrite the audited graph (nor be mis-audited).  An
  // ancestor pnpmfile thus neither runs unaudited on the runner nor diverges the
  // audit; if staging ever included workspaceRoot, ancestor pnpmfiles would need
  // scanning.
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
  // realpath (not lexical resolve) so `dir === repo` matches the realpath'd dirs
  // scanDirs returns (a symlinked repoDir would otherwise never match and every
  // dir would mislabel as an ancestor).
  const repo = realpathOrResolve(repoDir);
  const chain = scanDirs(repoDir, workspaceRoot);
  // The `enableConstraintsChecks` hook loads `yarn.config.cjs` from yarn's PROJECT
  // ROOT, which can be repoDir, an INTERMEDIATE workspace root between repoDir and
  // workspaceRoot, or the workspace root itself (VERIFIED yarn 4.5.0: running from a
  // workspace member loads the intermediate project root's config — neither repoDir
  // nor the enabling rc's dir).  Fail closed for every shape: when constraints are
  // enabled at ANY scanned rc, refuse if a `yarn.config.cjs` exists ANYWHERE in the
  // repoDir->workspaceRoot chain — a superset of yarn's real project root.
  const hasYarnConfig = chain.some((d) => existsSync(join(d, 'yarn.config.cjs')));
  for (const dir of chain) {
    const reason = detectYarnStartupExecInDir(dir, dir === repo, hasYarnConfig);
    if (reason !== null) return reason;
  }
  return null;
}

/**
 * Apply the yarn startup-exec checks to a SINGLE directory's `.yarnrc.yml`.
 * `atRepoDir` controls whether the error message names the ancestor dir (for a
 * clear diagnostic when the offending rc is NOT the repo's own).  `hasYarnConfig`
 * is whether a `yarn.config.cjs` exists ANYWHERE in the repoDir->workspaceRoot
 * chain — precomputed by the caller because yarn loads it from its project root,
 * which may be any dir in that chain, not just the rc's own dir.
 */
function detectYarnStartupExecInDir(dir: string, atRepoDir: boolean, hasYarnConfig: boolean): string | null {
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
  // throws on unrecognized values — refusing is the safe direction).  The enabling
  // FLAG cascades down from ANY ancestor `.yarnrc.yml` (Berry's rc cascade), and the
  // `yarn.config.cjs` it runs is loaded from yarn's PROJECT ROOT — repoDir, an
  // intermediate workspace root, or the workspace root.  `hasYarnConfig` (computed by
  // the caller over the whole chain) is true when any of those dirs holds the file,
  // so this fails closed for every shape.  (Requires the FLAG too: without a config
  // file the hook no-ops, so flag-only must not over-fire.)
  if (isNotDefinitelyFalse(parsed['enableConstraintsChecks']) && hasYarnConfig) {
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

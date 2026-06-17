// script-jail — src/action/host-install.ts
//
// The drop-in install on the GitHub-Actions runner (NOT the sandbox).  Two
// halves, mirroring the guest's two-phase split, so the host's node_modules is
// "the thing the sandbox audited":
//
//   part 1  hostInstallNoScripts  — package-manager install with EVERY
//           lifecycle script disabled (FETCH_CMD).  Always safe: no untrusted
//           code runs.  Populates the REAL repoDir/node_modules.
//
//   part 2  hostRunScripts        — runs the deferred lifecycle scripts
//           (INSTALL_CMD).  The caller MUST gate this on a clean audit
//           (runAudit's `trusted`), so it only ever runs scripts whose
//           behaviour matches the committed, reviewed lock.
//
// SECURITY NOTES
//   * Both halves spawn the package manager with an argv array and `shell:false`
//     — developer `args` are NEVER interpreted by a shell (no injection).
//   * `sanitizeInstallArgs` strips any arg that would re-enable scripts during
//     part 1; the FETCH_CMD disable flag always wins.
//   * Part 2 runs ONLINE with full host access (the runner has no netns sever).
//     This is inherent — real postinstalls fetch prebuilt binaries — so a
//     `connect` the sandbox recorded as `<BLOCKED>` WILL succeed here.  Trust
//     derives from the reviewed lock, not from host isolation.  See docs.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { delimiter, isAbsolute, join, resolve, sep } from 'node:path';
import type { Readable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

import {
  FETCH_CMD,
  INSTALL_CMD,
  pnpmStoreDirArg,
  sanitizeInstallArgs,
  type Manager,
} from '../shared/pm-commands.js';
import { buildFragmentMatcher, deriveSensitiveValues, maskExactValues, maskValueFragmentsWith, redactCredentialShapes } from '../shared/redact.js';

// ---------------------------------------------------------------------------
// SECURITY: pin npm's `git` config to the trusted runner git
// ---------------------------------------------------------------------------
//
// npm's `git` CONFIG selects the git BINARY npm invokes for git operations
// (clone / ls-remote) and is read from the project `.npmrc` in repoDir.  When
// the lockfile carries a NON-GitHub git dependency (git+https://gitlab.com/…,
// git+ssh://, git+file://; GitHub deps use the codeload HTTPS tarball and never
// trigger git), `npm ci --ignore-scripts` INVOKES that configured git to fetch
// the dep.  `--ignore-scripts` does NOT prevent this — it disables lifecycle
// SCRIPTS, which is orthogonal to which git binary runs.  So a PR that commits
// `.npmrc` with `git=./evil` + a non-GitHub git dep would execute `./evil` on
// the runner during the pre-trust host part-1, BEFORE the trust gate.
//
// npm config precedence: an `npm_config_git` ENV var BEATS the project
// `.npmrc`, so injecting it into the child env defeats the override.  We
// resolve the ABSOLUTE path of the trusted runner git ONCE (an absolute path so
// a repo-placed `./git` in cwd cannot shadow a bare `git`).  If it can't be
// resolved we fall back to the bare literal `git` — still a value that
// OVERRIDES (and thus defeats) the repo `.npmrc git=` entry; npm then resolves
// it via PATH like any other command.  npm-specific but harmless for
// pnpm/yarn (they ignore `npm_config_git`).
let RESOLVED_TRUSTED_GIT: string | undefined;
function trustedGitPath(): string {
  if (RESOLVED_TRUSTED_GIT !== undefined) return RESOLVED_TRUSTED_GIT;
  RESOLVED_TRUSTED_GIT = resolveGitFromPath() ?? 'git';
  return RESOLVED_TRUSTED_GIT;
}

// Default filesystems on macOS (APFS/HFS+) and Windows (NTFS) are
// case-INSENSITIVE: `/work/Repo` and `/work/repo` are the SAME directory, so a
// purely lexical containment test (`abs.startsWith(root + sep)`) misses a
// case-variant spelling of a checkout dir.  Case-fold on those platforms.
const CASE_INSENSITIVE_FS = process.platform === 'darwin' || process.platform === 'win32';

/**
 * Canonicalize a path for containment comparison:
 *   1. resolve to absolute, then
 *   2. follow symlinks to the REAL on-disk target via `realpathSync` — so a
 *      runner-looking PATH entry that is actually a symlink INTO the checkout
 *      (or a checkout-resident `git` symlink) cannot slip past the test, and a
 *      case-insensitive FS returns the canonical on-disk casing, then
 *   3. lower-case on a case-insensitive FS so a different-case spelling of the
 *      same dir still matches.
 * Falls back to a lexical `resolve` when the path does not exist (`realpathSync`
 * throws `ENOENT`) — a non-existent dir cannot host a real `git` anyway.
 */
function canonicalForCompare(p: string): string {
  let abs: string;
  try {
    abs = realpathSync(resolve(p));
  } catch {
    abs = resolve(p);
  }
  return CASE_INSENSITIVE_FS ? abs.toLowerCase() : abs;
}

/**
 * Directories a PR author can write into (the checkout tree): `$GITHUB_WORKSPACE`
 * (where actions/checkout places the PR), `$SCRIPT_JAIL_REPO_DIR` (an explicit
 * repo root, possibly a subdir of the checkout), and the process cwd.
 * Canonicalized (realpath + case-fold) so the containment test below is robust
 * to symlinks and case-variant spellings; de-duplicated implicitly by the test.
 */
function checkoutRoots(): string[] {
  const roots: string[] = [];
  for (const v of [
    process.env['GITHUB_WORKSPACE'],
    process.env['SCRIPT_JAIL_REPO_DIR'],
    process.cwd(),
  ]) {
    if (v !== undefined && v !== '') roots.push(canonicalForCompare(v));
  }
  return roots;
}

/**
 * True when `p`'s REAL path (symlinks resolved, case-folded on case-insensitive
 * filesystems) is a checkout root or nested under one (PR-controlled).  `roots`
 * MUST already be `canonicalForCompare`-canonicalized so both sides compare in
 * the same space.
 */
function isUnderCheckout(p: string, roots: ReadonlyArray<string>): boolean {
  const abs = canonicalForCompare(p);
  for (const root of roots) {
    if (abs === root || abs.startsWith(root + sep)) return true;
  }
  return false;
}

/**
 * True when `p`'s REAL path is a checkout root or nested under one
 * (`$GITHUB_WORKSPACE` / `$SCRIPT_JAIL_REPO_DIR` / `process.cwd()`).  EXPORTED so
 * other pre-trust host-exec sites (e.g. the VZ helper-binary override) can reject
 * a checkout-controlled path with the SAME symlink/case-robust containment test
 * the PATH/git sanitizers use, instead of re-implementing it.
 */
export function isPathUnderCheckout(p: string): boolean {
  return isUnderCheckout(p, checkoutRoots());
}

/**
 * Scan `process.env.PATH` for the first executable named `git`/`git.exe`
 * OUTSIDE the checkout tree and return its ABSOLUTE path.  Returns `undefined`
 * when none is found (caller falls back to the bare literal).
 *
 * SECURITY (pre-trust RCE defense): host part-1 runs BEFORE the audit trust gate
 * and exports the resolved value as `npm_config_git`, which npm invokes to clone
 * `git:` dependencies EVEN under `--ignore-scripts`.  A workflow that prepends a
 * checkout-controlled dir to PATH (e.g. `echo "$GITHUB_WORKSPACE/bin" >> $GITHUB_PATH`)
 * would otherwise let a PR-committed `bin/git` be picked as the "trusted" git and
 * run on the runner before anything is gated.  So we SKIP every candidate whose
 * REAL path is inside the checkout — both at the PATH-dir level and at the
 * resolved-binary level (`isUnderCheckout` realpaths + case-folds, so a
 * symlinked PATH entry pointing into the checkout, a checkout-resident `git`
 * symlink, and a case-variant spelling on a case-insensitive runner FS are all
 * rejected).  The `isAbsolute` check additionally rejects a relative entry
 * (e.g. `.`).
 *
 * RESIDUAL (pathological, documented): if NO git exists on PATH outside the
 * checkout, the caller falls back to the bare literal `git`, which npm then
 * resolves via the inherited PATH (could pick the checkout git).  This requires a
 * runner with no system git anywhere on PATH — which cannot complete a git-dep
 * install regardless — so it is self-defeating, not a usable vector.
 */
export function resolveGitFromPath(): string | undefined {
  const pathVar = process.env['PATH'];
  if (pathVar === undefined || pathVar === '') return undefined;
  const names = process.platform === 'win32' ? ['git.exe', 'git.cmd', 'git'] : ['git'];
  const roots = checkoutRoots();
  for (const dir of pathVar.split(delimiter)) {
    if (dir === '') continue;
    // SECURITY: never resolve the "trusted" git from a checkout-controlled PATH
    // entry (cheap dir-level reject) — see the function note above.
    if (isUnderCheckout(dir, roots)) continue;
    for (const name of names) {
      const candidate = join(dir, name);
      // Only accept an ABSOLUTE candidate so a relative PATH entry (e.g. `.`)
      // can't point npm at a repo-placed shadow binary.
      if (!isAbsolute(candidate) || !existsSync(candidate)) continue;
      // SECURITY: the git BINARY itself may be a symlink whose real target lives
      // in the checkout even when its PATH dir does not — re-check the resolved
      // candidate's real path before trusting it.
      if (isUnderCheckout(candidate, roots)) continue;
      return candidate;
    }
  }
  return undefined;
}

/**
 * Child env for the host PM spawns: the inherited environment plus the
 * `npm_config_git` pin (see the security note above) and, for yarn, the
 * startup-exec env neutralizers below.  MERGES over `process.env` so PATH /
 * HOME / registry auth are preserved.
 *
 * SECURITY (yarn): Yarn Berry maps env vars to config, so an INHERITED `YARN_*`
 * can re-introduce exactly the startup code-exec the preflight blocks in
 * `.yarnrc.yml`:
 *   * `YARN_YARN_PATH` re-execs a repo binary as "yarn",
 *   * `YARN_PLUGINS` loads a repo module at startup,
 *   * `YARN_RC_FILENAME` redirects yarn to an ALTERNATE repo rc that declares
 *     yarnPath/plugins — dodging the preflight, which inspects only `.yarnrc.yml`,
 *   * `YARN_ENABLE_CONSTRAINTS_CHECKS` runs a repo `yarn.config.cjs`.
 * The host process inherits `process.env`, so we override these four on the yarn
 * child to neutralize every inherited-ENV vector (verified against Yarn Berry
 * 4.x).  Registry auth flows through UNRELATED keys (`YARN_NPM_AUTH_TOKEN` /
 * `YARN_NPM_REGISTRY_SERVER`) and is preserved.  This mirrors the `npm_config_git`
 * pin (a config-redirect defense) and is HOST-ONLY: the SANDBOX keeps repo config
 * so the hooks are AUDITED there (the enforcement boundary).  `YARN_IGNORE_PATH=1`
 * kills yarnPath from BOTH the file and the env; `YARN_RC_FILENAME` is forced to
 * the preflight-vetted default so an env redirect cannot dodge the static reject.
 *
 * SCOPE: `YARN_PLUGINS=''` governs only the ENV plugin source, NOT the rc-file
 * `plugins:` cascade — Berry still loads a `plugins:` entry from a PARENT-dir or
 * `~/.yarnrc.yml` even under this env (the rc loop runs unconditionally when
 * `useRc`).  Parent dirs ABOVE the checkout and `~` are runner-owned (out of the
 * PR-author threat model: actions/checkout confines a PR to `$GITHUB_WORKSPACE`).
 * But repoDir is NOT always the checkout root: with `SCRIPT_JAIL_REPO_DIR` it can
 * be a SUBDIRECTORY of the checkout, in which case the PR-controlled ancestor rc
 * files BETWEEN repoDir and `$GITHUB_WORKSPACE` ARE in scope — so the preflight
 * (install-preflight.ts) now scans every `.yarnrc.yml` from repoDir up to and
 * including `$GITHUB_WORKSPACE`, rejecting an ancestor `plugins:`/`yarnPath`
 * before this env is ever used.  The repo's own `.yarnrc.yml plugins:` is
 * likewise rejected there.
 */
/**
 * Env-var names that betray the sandbox-vs-host split to a lifecycle script.
 * Stripped from the host re-run so its env-var view matches what the SANDBOX
 * audited (the guest's `sanitizeLifecycleBaseEnv` strips the same noise +
 * unknown SCRIPT_JAIL_* from the audited child).
 *
 * DEFENSE-IN-DEPTH, NOT A COMPLETE ORACLE CLOSE: this aligns only the env-VAR
 * layer.  An environment-sensitive payload can still distinguish the audit from
 * the host via signals env-stripping cannot touch — `os.hostname()`/`uname()`
 * (syscalls, no backend hooks them), the audit-only instrument env the guest
 * MUST carry (`LD_PRELOAD`, `NODE_OPTIONS` preloads), and container/VM marker
 * files (`/.dockerenv`, `/etc/script-jail/config.yml`, microVM `/proc`).
 * `process.cwd()` is handled separately by the work_dir cwd-parity (M1).
 */
const HOST_INSTALL_STRIP_ENV_NAMES = new Set([
  'HOSTNAME', // os.hostname() syscall still differs; this only aligns the env var
  'PWD', // process.cwd() ignores PWD, but a script may read it directly
  'COLS',
  'LINES',
  'POSIXLY_CORRECT',
  'TERM',
]);

// ---------------------------------------------------------------------------
// SECURITY: strip INHERITED loader/config env vars that enable pre-trust code
// execution or host-vs-audit config divergence
// ---------------------------------------------------------------------------
//
// This is a SEPARATE category from HOST_INSTALL_STRIP_ENV_NAMES above (which is
// sandbox-tell NOISE only).  The names below are LOADER / TOOL-RESOLUTION /
// CONFIG-LOCATING env vars that the host package-manager child HONORS but the
// Firecracker/Docker audit NEVER saw — the audit reconstructs its env from
// scratch (it does NOT inherit the runner env) and injects only its own
// instrumentation `LD_PRELOAD` / `NODE_OPTIONS`.  So any inherited var of this
// shape is an ASYMMETRY: a clean, trusted lock would authorize unaudited host
// behaviour.  Both host phases build their child env via hostInstallEnv(), so
// stripping here covers part-1 (PRE-TRUST, no-scripts install) AND part-2
// (POST-TRUST lifecycle scripts).
//
// Threat (fork pull_request): the owner's workflow `env:` block (base-branch,
// trusted) legitimately sets a CHECKOUT-RELATIVE loader/config var, and the PR
// author supplies the file it points at inside `$GITHUB_WORKSPACE`.  Examples:
//   [13] NODE_OPTIONS=--require ./ci/x.js   → RCE in the Node-based PM child,
//        part-1, BEFORE the trust gate.  NODE_REPL_EXTERNAL_MODULE same class.
//   [17] LD_PRELOAD=./ci/x.so / LD_AUDIT    → native pre-trust RCE.  The guest
//        never inherits these (it builds env from scratch), so this is the
//        host/guest asymmetry.  DYLD_* analogs: the host `bare` backend runs on
//        macOS too.
//   [19] GIT_SSH_COMMAND=./ci/ssh           → pre-trust exec for git+ssh deps;
//        `npm ci --ignore-scripts` STILL invokes git for git: dependencies.
//        (GIT_ALLOW_PROTOCOL is deliberately NOT stripped — it RESTRICTS, never
//        weakens; and the git BINARY stays pinned via npm_config_git, set AFTER
//        this loop — we only drop the transport-COMMAND overrides here.)
//   [18] NPM_CONFIG_SCRIPT_SHELL=./ci/shell → part-2 `npm rebuild` runs the
//        wrapper shell.
//   [22] NPM_CONFIG_USERCONFIG / _GLOBALCONFIG → host loads a PR-controlled
//        npmrc the audit never read (config-locating redirect).
//   [16] NPM_CONFIG_IGNORE_SCRIPTS=true     → part-2 skips the scripts the audit
//        expects → an unbuilt tree (self-DoS / divergence).
//
// npm AND pnpm read config via the `npm_config_*` / `pnpm_config_*` env namespaces
// CASE-INSENSITIVELY and with EITHER separator (`NPM_CONFIG_SCRIPT_SHELL`,
// `npm_config_script_shell`, `npm_config_script-shell` all set `script-shell`), so
// these namespaces are matched by a CANONICALIZED-key check in isDangerousEnvName
// (see isAllowedPmConfigKey below), not by exact name.  Those two namespaces use an
// ALLOWLIST (keep registry/auth/TLS/proxy only; drop everything else) — see the
// rationale on PM_CONFIG_AUTH_SCALARS.  The OS loader/tool vars (LD_*/DYLD_*/
// NODE_OPTIONS/GIT_*/PYTHON/CC/…) are case-SENSITIVE on Linux/macOS — exact-name
// match — though we also fold case, a cheap defensive catch-all that cannot widen
// the match beyond these names.
//
// WHY A DENYLIST, NOT AN ALLOWLIST: the host MUST run the package's REAL
// lifecycle scripts with a realistic env, so arbitrary owner/workflow vars
// (build flags, non-secret config, registry auth tokens) have to pass through;
// an env allowlist would break legitimate native/build scripts.  The dangerous
// surface is specifically binary/shell/library/config-FILE *selectors*, matched
// by whole FAMILY where possible (prefix) so future additions are covered without
// name-enumeration, plus the canonicalized npm_config_* slice and an enumerated
// git-exec set.  Residual: a NOVEL selector outside every family/set (or a future
// npm exec key); the SANDBOX (the enforcement boundary, which audits whatever it
// is given) is the real backstop.  Defense-in-depth, not a complete oracle close
// — mirrors the npm_config_git pin rationale.
//
// PARITY MAKES FAMILY-STRIPPING SAFE: the Firecracker/Docker guest audits inside
// a CLEAN VM env — `sanitizeLifecycleBaseEnv` (src/guest/agent.ts) runs over the
// VM's own process.env, which never contains the runner's GIT_*/LD_*/PYTHON*/
// NODE_OPTIONS.  So anything that PASSED the audit was built WITHOUT these vars;
// dropping the whole family on the host only brings it to parity and cannot break
// a build the audit approved.  The host legitimately ADDS only secrets/registry/
// proxy (tokens, npm_config_//registry/:_authToken, HTTP(S)_PROXY) — none of which
// are tool/loader/config-FILE *selectors* — so those keep flowing.  That lets us
// match by PREFIX FAMILY (robust to future additions) instead of chasing every
// individual name, plus an enumerated git-exec set (git's exec surface is stable
// and documented; blanket GIT_* is avoided so behaviour flags like
// GIT_TERMINAL_PROMPT can't be dropped and hang a clone).

// Exact loader/tool/config-FILE SELECTOR names not already caught by a family
// prefix below.  Lower-cased; matched case-insensitively.
const HOST_INSTALL_DANGEROUS_ENV_NAMES = new Set(
  [
    // [13] Node loader hooks + module search + TLS trust (Node-based PM child).
    'NODE_OPTIONS',
    'NODE_REPL_EXTERNAL_MODULE',
    'NODE_EXTRA_CA_CERTS',
    'NODE_PATH', // adds require() search dirs → a checkout-relative one loads PR code
    // npm's globalconfig is `{globalPrefix}/etc/npmrc`, and npm derives globalPrefix
    // from PLAIN (non-npm_config_*) env in loadGlobalPrefix(): `PREFIX` sets it
    // directly and `PREFIX`-less `DESTDIR` prepends to the node-derived prefix
    // (@npmcli/config/lib/index.js:327-339).  VERIFIED npm 11.13.0: `PREFIX=<dir>`
    // (or `DESTDIR=<dir>`) with `<dir>/etc/npmrc` (resp. `<dir>{nodePrefix}/etc/npmrc`)
    // declaring `script-shell=<pwn>` makes `npm rebuild --foreground-scripts` exec the
    // attacker shell — the SAME npmrc-redirect-then-exec class as the denied
    // npm_config_prefix, but reached via plain env so the npm_config_* canon misses it.
    // (HOME → `~/.npmrc` is the analogous userconfig vector, gated separately by
    // install-preflight.ts:detectCheckoutRelativeHome; XDG_CONFIG_HOME is NOT an npmrc
    // locator in npm 11.13.0 — verified inert.)
    'PREFIX',
    'DESTDIR',
    // [19] Git EXEC/config-FILE selectors (git+ssh|https deps; --ignore-scripts
    // does NOT stop git being invoked).  Enumerated (not blanket GIT_*) so benign
    // behaviour flags such as GIT_TERMINAL_PROMPT/GIT_ALLOW_PROTOCOL are preserved.
    // The git BINARY itself stays pinned via npm_config_git.
    'GIT_SSH_COMMAND',
    'GIT_SSH',
    'GIT_PROXY_COMMAND',
    'GIT_EXTERNAL_DIFF',
    'GIT_PAGER',
    'GIT_EDITOR',
    'GIT_ASKPASS', // verified-class: git invokes the askpass program by path
    'SSH_ASKPASS',
    'GIT_EXEC_PATH', // VERIFIED: GIT_EXEC_PATH=./core runs checkout core/git-remote-https
    'GIT_TEMPLATE_DIR', // clone hooks dir
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_SYSTEM',
    'GIT_CONFIG_COUNT', // gates inline GIT_CONFIG_KEY_*/VALUE_*; dropping it makes them inert
    'GIT_CONFIG_PARAMETERS', // VERIFIED: ='core.sshCommand=./ssh' runs ./ssh on ssh:// clone
    // Native-build TOOL selectors honored by node-gyp/gyp/make (checkout-relative
    // interpreter/compiler/linker runs during a native `npm rebuild`).  PYTHON* and
    // node-gyp* are caught by the family prefixes below.  Stripping forces the
    // system toolchain auto-detect — the same default the clean-VM audit used.
    'CC',
    'CXX',
    'CPP',
    'LINK',
    'LD',
    'AR',
    'AS',
    'MAKE',
    // GNU make startup/config env (consumed before any target): MAKEFLAGS
    // ='--eval=$(shell …)' runs a command at make startup, MAKEFILES=/path
    // evaluates a makefile pre-target (both VERIFIED).  node-gyp invokes make.
    'MAKEFLAGS',
    'GNUMAKEFLAGS',
    'MAKEFILES',
    // Corepack EXEC/config selectors: a pnpm/yarn bare command is commonly a
    // corepack shim, and COREPACK_HOME is its executable CACHE — a checkout-
    // relative one (VERIFIED with corepack 0.35.0) makes corepack run a PR-planted
    // bin/pnpm.cjs in host part-1.  COREPACK_ENV_FILE loads env from a file;
    // COREPACK_NPM_REGISTRY / COREPACK_INTEGRITY_KEYS / COREPACK_ROOT can redirect
    // or unsign the downloaded PM.  Behaviour flags (COREPACK_ENABLE_*) are NOT
    // here — they don't select an executable, and the download-prompt flag is
    // re-pinned below so stripping the cache can't trigger an interactive hang.
    'COREPACK_HOME',
    'COREPACK_ENV_FILE',
    'COREPACK_NPM_REGISTRY',
    'COREPACK_INTEGRITY_KEYS',
    'COREPACK_ROOT',
    // pnpm's global bin / executable dir (also where `pnpm setup` puts pnpm on
    // PATH).  Not a config-file locator and NOT auto-prepended to a lifecycle
    // script's PATH (both VERIFIED pnpm 11.1.2 — only XDG_CONFIG_HOME relocates the
    // readable config), but it IS passed verbatim to lifecycle children and the
    // clean-VM audit inherits none, so drop it for parity: a checkout-relative
    // PNPM_HOME never reaches the host pnpm or a script that reads it.
    'PNPM_HOME',
    // Shell / interpreter startup hooks that run on a NON-interactive spawn.
    // (POSIX `$ENV` is sourced only by INTERACTIVE sh, not `sh -c`, and `ENV` is a
    // common legit "environment name" var, so it is deliberately NOT stripped.)
    'BASH_ENV', // bash -c sources it
    'ZDOTDIR', // zsh startup dir
    'PERL5LIB',
    'RUBYOPT',
    'RUBYLIB',
  ].map((n) => n.toLowerCase()),
);

// Whole env-var FAMILIES (matched by lower-cased prefix) that are pure loader /
// path / interpreter selectors — none have a legit INHERITED-install use the
// clean-VM audit lacked, so dropping the family is parity-safe and closes future
// additions without name-enumeration.
const HOST_INSTALL_DANGEROUS_ENV_PREFIXES = [
  'ld_', // ELF dynamic loader: LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH / …
  'dyld_', // macOS dyld analogs (the host bare backend runs on macOS)
  'python', // PYTHON / PYTHONPATH / PYTHONHOME / PYTHONSTARTUP (sitecustomize exec)
  'node_gyp_', // NODE_GYP_FORCE_PYTHON, … (VERIFIED node-gyp interpreter selector)
  // XDG base-dir family.  pnpm locates its GLOBAL config at
  // `$XDG_CONFIG_HOME/pnpm/{config.yaml,rc}` (VERIFIED pnpm 11.1.2: an inherited
  // `XDG_CONFIG_HOME=<checkout>/.config` makes the host pnpm read a PR-committed
  // `.config/pnpm/config.yaml` whose `scriptShell:` then runs an attacker shell on
  // `pnpm rebuild --pending` — npm & yarn do NOT read XDG for config, verified).
  // The clean-VM audit inherits NO XDG_*, so the host must run without them too;
  // dropping the whole family is parity-safe (config/data/state/cache all default
  // to the runner's real HOME, which the HOME gate keeps outside the checkout) and
  // forecloses any future XDG-located PM config.
  'xdg_',
  // npm re-derives npm_package_config_* from the AUDITED package.json; an INHERITED
  // one for a key absent from package.json would pass through to node-gyp
  // (e.g. npm_package_config_node_gyp_python), so drop inherited ones — npm re-adds
  // the legit values from the package.json the sandbox already audited.
  'npm_package_config_',
];

// The `npm_config_*` AND `pnpm_config_*` env namespaces are governed by an
// ALLOWLIST: keep ONLY registry-location / auth / TLS-material / proxy keys, drop
// EVERYTHING else.  Both PMs read these namespaces case-insensitively and with
// either separator (`NPM_CONFIG_SCRIPT_SHELL` / `npm_config_script_shell` /
// `npm_config_script-shell` all set `script-shell`), so the match canonicalizes
// the key (lowercase + `-`→`_`) for the fixed scalar names below.
//
// WHY AN ALLOWLIST, NOT A DENYLIST: the config-via-env key space is an open,
// per-release-growing set of exec / interpreter / loader / config-FILE selectors,
// and a denylist of them was PROVEN LEAKY — adversarial review surfaced a new one
// EACH round (`script_shell` → `shell_emulator` → `scripts_prepend_node_path`),
// across BOTH namespaces.  `scripts_prepend_node_path` also showed the per-namespace
// denylist was STRUCTURALLY wrong: pnpm honors that key at install time via the
// `npm_config_` form (VERIFIED pnpm 10.34.3/11.1.2 — it prepends a chosen node dir
// to the lifecycle-script PATH, changing which `node` runs scripts), so a
// pnpm-namespace denylist entry never even covered the working vector.  npm 11
// IGNORES it ("Unknown env config"), so the allowlist drop is a no-op on npm and
// closes the live pnpm vector.  The auth/registry/TLS/proxy surface, by contrast,
// is SMALL, STABLE, and contains no exec selector, so it can be enumerated soundly.
// This mirrors the YARN_* allowlist posture in hostInstallEnv (yarn's env->config
// space is likewise open-ended).
//
// PARITY MAKES DROP-THE-REST SAFE: the Firecracker/Docker guest audits in a CLEAN
// VM env with NO inherited `npm_config_*`/`pnpm_config_*`, so whatever PASSED the
// audit was built with PM defaults for every non-auth key; dropping them on the
// host only brings it to parity.  The host legitimately ADDS only registry/auth/
// TLS/proxy (registry URL, tokens, `//registry/:_authToken`, CA/cert), which the
// allowlist keeps.  VERIFIED (npm 11.13.0 + pnpm): every key below is env-settable
// and is registry/auth/TLS material — none selects an exec, loader, interpreter, or
// a config FILE to discover-and-interpret.  ca/cafile/cert/certfile/key/keyfile are
// PEM material read as TLS data, never executed.
//
// Fixed scalar keys (canonical underscore form; matched after `-`→`_`).
const PM_CONFIG_AUTH_SCALARS = new Set([
  'registry', // default registry URL
  '_auth', // legacy single-registry base64 basic auth
  'email', // legacy auth identity
  'ca', // inline PEM CA (string/array) — data, not a path
  'cafile', // PEM CA file path — read as cert DATA, never interpreted
  'cert', // inline PEM client cert (deprecated → certfile)
  'certfile', // PEM client-cert file path — TLS material
  'key', // inline PEM client key (deprecated → keyfile)
  'keyfile', // PEM client-key file path — TLS material
  'strict_ssl', // TLS verification toggle
  'proxy', // HTTP(S) proxy URL (npm + pnpm)
  'https_proxy', // HTTPS proxy URL (npm + pnpm)
  'noproxy', // proxy-bypass host list — npm's canonical key
  // pnpm's canonical proxy spellings are `http-proxy` / `no-proxy` (DISTINCT from
  // npm's `proxy` / `noproxy`).  VERIFIED pnpm 11.1.2 reads `pnpm_config_http_proxy`
  // -> `http-proxy` (feeds ProxyAgent) and `pnpm_config_no_proxy` -> `no-proxy`
  // (feeds checkNoProxy); pnpm 10.34.3 reads the SAME via the `npm_config_` form.
  // Without these a pnpm install behind an HTTP-only proxy (or needing a no-proxy
  // bypass for an internal registry) fails on the host.  Pure network config (URL /
  // host list), no exec.  npm treats both as "Unknown env config" (ignores — harmless).
  'http_proxy', // pnpm `http-proxy`
  'no_proxy', // pnpm `no-proxy`
]);

/**
 * True when an `npm_config_*` / `pnpm_config_*` key — the part AFTER the namespace
 * prefix, already LOWERCASED — is an ALLOWED registry/auth/TLS/proxy key that must
 * survive into the host PM child.  Everything else (exec / interpreter / loader /
 * config-FILE / behaviour selectors: script_shell, shell_emulator,
 * scripts_prepend_node_path, node_options, prefix, userconfig, ignore_scripts,
 * pnpmfile, …) is dangerous (dropped).
 */
function isAllowedPmConfigKey(slice: string): boolean {
  // Per-registry auth/TLS: `//host/:_authToken`, `//host/:_password`,
  // `//host/:certfile`, … — these ONLY carry per-registry credentials / registry
  // settings, never an exec.  The host segment + suffix can contain `-`/`.`, so
  // match the `//` prefix VERBATIM (do NOT canonicalize `-`→`_`).
  // SOUNDNESS (VERIFIED npm 11.13.0 + pnpm 10.34.3/11.1.2): keeping these verbatim
  // cannot smuggle an exec.  npm has NO tokenHelper; pnpm's `tokenHelper` and ALL
  // per-registry (`//host/:KEY`) settings are read ONLY from the npmrc INI source,
  // NEVER from the env namespace this gate filters (proven: `//host/:_authToken` via
  // ENV → registry saw auth=null; via ~/.npmrc → Bearer token).  And a per-registry
  // behaviour key like `//host/:script-shell` is INERT — the control
  // `npm_config_script_shell` exec'd a lifecycle script, the `//host/:`/`@scope:`
  // forms did NOT — the prefix genuinely scopes it.
  if (slice.startsWith('//')) return true;
  // Scoped registry / scoped auth: `@scope:registry`, `@scope:_authToken`, …  The
  // scope segment may contain `-` (VERIFIED: canonicalizing `-`→`_` mis-targets the
  // scope — `@my-org:registry` ≠ `@my_org:registry`), so match the RAW key.  Scoped
  // behaviour keys (`@scope:script-shell`/`:node-options`) are inert too (VERIFIED).
  if (slice.startsWith('@') && slice.includes(':')) return true;
  // Fixed scalar keys (canonicalize `-`→`_`; these contain no scope/host segment).
  return PM_CONFIG_AUTH_SCALARS.has(slice.replace(/-/g, '_'));
}

// The ONLY inherited `YARN_*` env kept on the host yarn child (allowlist — every
// other YARN_* config is dropped; see hostInstallEnv).  These four are the scalar
// auth/registry settings a private-registry install needs and that the env->config
// transform can actually set (VERIFIED yarn 4.5.0: map settings npmScopes/
// npmRegistries are NOT flat-env-settable, so per-scope auth lives in the rc, not
// env).  None is a path/exec/inject vector.
const YARN_ENV_ALLOW = new Set([
  'YARN_NPM_AUTH_TOKEN',
  'YARN_NPM_AUTH_IDENT',
  'YARN_NPM_REGISTRY_SERVER',
  'YARN_NPM_ALWAYS_AUTH',
]);

/**
 * True when `name` is a dangerous loader/tool/config-FILE selector env var to
 * strip from the host PM children.  Matched on the LOWERCASED name: (1) a whole
 * dangerous FAMILY by prefix, (2) the `pnpm_config_*` and `npm_config_*` namespaces
 * by ALLOWLIST — dangerous UNLESS the key is registry/auth/TLS/proxy
 * (isAllowedPmConfigKey), so any exec/interpreter/loader/config-FILE/behaviour key
 * (script_shell, shell_emulator, scripts_prepend_node_path, prefix, …) is dropped
 * while registry/auth tokens survive, (3) the enumerated exact set.
 */
function isDangerousEnvName(name: string): boolean {
  const lower = name.toLowerCase();
  for (const prefix of HOST_INSTALL_DANGEROUS_ENV_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }
  // pnpm_config_* must be tested BEFORE npm_config_* — `pnpm_config_x` does not
  // start with `npm_config_`, but keep them as distinct branches for clarity.
  // pnpm ALSO honors the `npm_config_` form at install time (e.g.
  // npm_config_scripts_prepend_node_path), so BOTH namespaces use the same allowlist.
  if (lower.startsWith('pnpm_config_')) {
    return !isAllowedPmConfigKey(lower.slice('pnpm_config_'.length));
  }
  if (lower.startsWith('npm_config_')) {
    return !isAllowedPmConfigKey(lower.slice('npm_config_'.length));
  }
  return HOST_INSTALL_DANGEROUS_ENV_NAMES.has(lower);
}

/**
 * Fixed trusted system PATH used whenever sanitization would otherwise yield an
 * empty (cwd-searching) PATH.  Covers both Linux and macOS system tool
 * locations; matches the literal both `prependPath` fallbacks already use.
 */
export const SAFE_SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';

/**
 * SECURITY ([5]+[9]): rebuild a PATH value dropping every entry whose REAL path
 * (symlinks resolved, case-folded on a case-insensitive FS) is a checkout root
 * or nested under one (PR-controlled).  The PM is spawned by BARE NAME and
 * lifecycle scripts spawn tools (`node`, `sh`, `make`, …) by bare name, so if
 * the owner's workflow prepended a checkout dir to PATH (e.g.
 * `echo "$GITHUB_WORKSPACE/bin" >> $GITHUB_PATH`) and the PR committed
 * `bin/<tool>`, that PR-controlled binary would be resolved on the runner — and
 * ONLY on the runner; the sandbox audit never inherits this PATH.  Reuses the
 * same canonicalForCompare/checkoutRoots/isUnderCheckout helpers as the
 * npm_config_git resolver so the containment test is symlink/case robust.
 *
 * Order of the surviving (system) entries is PRESERVED.  The result is NEVER the
 * empty string — see SAFE_SYSTEM_PATH below — and only `undefined` when the
 * source had no PATH at all (caller then leaves PATH unset → execvp's built-in
 * system default, which does NOT search the cwd).
 *
 * SECURITY ([F2], non-absolute entries): we drop EVERY non-absolute segment, not
 * just empties.  A relative PATH entry is resolved by the OS exec lookup against
 * the CHILD's cwd (`=repoDir`), but our containment test resolves it against the
 * action's `process.cwd()`.  When those differ (e.g. `SCRIPT_JAIL_REPO_DIR` is a
 * subdir), a `../x` entry can look outside the checkout here yet resolve INTO the
 * checkout at exec time.  A CI runner PATH is all-absolute, so dropping relative
 * entries is safe and closes the cwd-mismatch hole outright.
 */
export function sanitizePathValue(pathVar: string | undefined): string | undefined {
  if (pathVar === undefined) return undefined;
  const roots = checkoutRoots();
  const kept: string[] = [];
  for (const dir of pathVar.split(delimiter)) {
    // Drop empty ('' = cwd) and ANY non-absolute entry: it is resolved against
    // the child's cwd (=repoDir) at exec, which our check can't model, and a
    // `../x` can resolve into the checkout there.  Then drop checkout-under dirs.
    if (!isAbsolute(dir)) continue;
    if (isUnderCheckout(dir, roots)) continue;
    kept.push(dir);
  }
  // SECURITY ([F3], codex round-6): NEVER return ''.  A POSIX PATH of "" (and a
  // trailing/empty segment) is a SINGLE zero-length entry, which execvp /
  // spawnSync resolve against the CURRENT DIRECTORY — so a bare-name host exec
  // (`git`/`tar`/`codesign`/…) would run a PR-committed `./tool` from the
  // checkout cwd, re-opening the exact hole dropping checkout dirs is meant to
  // close (verified empirically).  When every inherited segment was dropped (or
  // the input was already ''), substitute a fixed trusted system PATH.
  return kept.length === 0 ? SAFE_SYSTEM_PATH : kept.join(delimiter);
}

/**
 * Drop the dangerous loader/tool/config-FILE selector env vars
 * (`isDangerousEnvName`) and sanitize PATH.  EXPORTED so the Linux `bare` backend
 * can apply the SAME policy to the env it spawns the audit AGENT with.
 *
 * Why the bare backend needs it: the Firecracker/Docker guest audits in a CLEAN VM
 * env (it never inherits the runner env), but the bare backend runs the agent
 * directly ON THE HOST with the inherited runner env.  Without this, the bare audit
 * would honour a checkout-relative loader/config var (NODE_OPTIONS, GIT_, PYTHON,
 * COREPACK_HOME, …) that the
 * hardened host install no longer does — breaking the host==audit parity this
 * hardening relies on (Codex round-3 finding), and an inherited NODE_OPTIONS could
 * even inject code into the agent process itself before the audit envelope.  Does
 * NOT drop the sandbox-tell noise or SCRIPT_JAIL_* (the agent reads some) and does
 * NOT add the npm/yarn install pins (those are install-child specific).
 */
export function stripDangerousEnv(srcEnv: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(srcEnv)) {
    if (value === undefined) continue;
    if (isDangerousEnvName(name)) continue;
    env[name] = value;
  }
  // SECURITY ([5]+[9]): sanitize PATH so a checkout-controlled dir cannot shadow
  // bare-name PM/tool resolution.
  const sanitizedPath = sanitizePathValue(srcEnv['PATH']);
  if (sanitizedPath === undefined) delete env['PATH'];
  else env['PATH'] = sanitizedPath;
  return env;
}

function hostInstallEnv(pm: Manager): NodeJS.ProcessEnv {
  // Drop dangerous selectors + sanitize PATH (shared with the bare backend), THEN
  // drop the sandbox-tell noise + SCRIPT_JAIL_* knobs, THEN layer the security pins
  // on top so a stripped name can never accidentally remove a pin.
  const env = stripDangerousEnv(process.env);
  for (const name of Object.keys(env)) {
    // Sandbox-tell NOISE + every SCRIPT_JAIL_* host knob (REPO_DIR, CACHE_DIR,
    // ACTION_ROOT, …): audit-absent tells, unused by the package manager.
    if (HOST_INSTALL_STRIP_ENV_NAMES.has(name) || name.startsWith('SCRIPT_JAIL_')) {
      delete env[name];
    }
  }
  env['npm_config_git'] = trustedGitPath();
  // SECURITY (parity): drop EVERY inherited COREPACK_* (case-insensitive), then
  // re-pin only the download-prompt.  A behaviour flag like
  // `COREPACK_ENABLE_PROJECT_SPEC=0` makes corepack IGNORE the repo's
  // `packageManager` field and run a DIFFERENT pm VERSION than the clean-VM audit
  // (VERIFIED corepack 0.35.0) — a host!=audit identity/semantics skew, not just the
  // download/registry/cache knobs already in the dangerous-name list.  The audit
  // inherits no COREPACK_*, so stripping the family keeps host==audit; the version
  // is governed by the repo's `packageManager`, never by inherited env.
  for (const name of Object.keys(env)) {
    if (name.toUpperCase().startsWith('COREPACK_')) delete env[name];
  }
  // Corepack must not block on an interactive download prompt (match the audit:
  // docker.ts / init.sh / mac-bare set this) — especially since we just stripped any
  // inherited COREPACK_HOME, which could force a cache re-download.
  env['COREPACK_ENABLE_DOWNLOAD_PROMPT'] = '0';
  if (pm === 'yarn') {
    // SECURITY (parity, ALLOWLIST): Yarn maps env -> config (`YARN_<UPPER_SNAKE>` ->
    // camelCase flat key, VERIFIED yarn 4.5.0) and ENV BEATS the rc file.  That
    // config surface is open-ended and grows per release — `injectEnvironmentFiles`
    // (injects a .env, incl. NODE_OPTIONS, into lifecycle subprocesses), `*Folder`
    // path redirects, `constraintsPath`, TLS/proxy paths, `enableScripts`, … — so
    // enumerating dangerous names is whack-a-mole (each fix surfaces the next).  The
    // clean-VM audit inherits NO runner env, so DROP EVERY inherited `YARN_*` except
    // the scalar auth/registry keys a private-registry install genuinely needs; that
    // keeps host==audit by construction.  (Per-scope `npmScopes`/`npmRegistries` are
    // MAP settings, NOT flat-env-settable in 4.5.0 — yarn errors on them — so the
    // four scalars below are the entire env-settable auth surface; rc-file auth is
    // unaffected.)  Sweep FIRST, then layer the explicit pins so the sweep can't
    // clobber them.  CASE-INSENSITIVE: yarn lower-cases the env key before its
    // `yarn_` match (VERIFIED 4.5.0: `yarn_enable_scripts`/`yarn_inject_environment_files`
    // are honoured), so compare the upper-cased name against the (upper-cased) allowlist.
    for (const name of Object.keys(env)) {
      const upper = name.toUpperCase();
      if (upper.startsWith('YARN_') && !YARN_ENV_ALLOW.has(upper)) delete env[name];
    }
    env['YARN_IGNORE_PATH'] = '1';
    env['YARN_RC_FILENAME'] = '.yarnrc.yml';
    env['YARN_PLUGINS'] = '';
    env['YARN_ENABLE_CONSTRAINTS_CHECKS'] = 'false';
    // YARN_ENABLE_SCRIPTS is intentionally NOT re-set: the sweep dropped any inherited
    // value (it is not in the allowlist), so the rc governs host part-2 IDENTICALLY to
    // the audit — rc-true still builds, rc-false still skips (env must not beat rc).
  }
  return env;
}

/** Minimal sink so the module is testable without touching the real streams. */
export interface HostInstallIo {
  stdout: { write(s: string): void };
  stderr: { write(s: string): void };
  warn(msg: string): void;
}

/**
 * Injectable process runner (tests pass a fake).  Returns the child's exit
 * status (`null` when killed by a signal) and any spawn-level error.
 *
 * A capturing runner additionally returns the child's `stdout`/`stderr` as
 * strings so the caller can redact them before writing to the job log
 * (`undefined` ⇒ the runner inherited the streams live, nothing to redact).
 */
export type HostSpawn = (
  cmd: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) => {
  status: number | null;
  signal?: NodeJS.Signals | null;
  error?: Error | undefined;
  stdout?: string;
  stderr?: string;
};

// 64 MiB capture cap: verbose installs (npm/pnpm/yarn debug spew) can be large;
// the default 1 MiB maxBuffer would truncate and surface ENOBUFS instead of the
// real exit status, losing the diagnostic we need on failure.
const CAPTURE_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * Part-1 runner: inherit stdin, but CAPTURE stdout+stderr so they can be piped
 * through the redactor before reaching the job log.  Part 1 takes the user
 * `args`, so the PM's own diagnostics may echo a user-supplied secret back —
 * inheriting them live would leak (e.g. `npm warn invalid config
 * registry="SECRET"`).  `shell:false` keeps args as discrete argv items.
 */
const captureSpawn: HostSpawn = (cmd, args, cwd, env) => {
  const r = spawnSync(cmd, args, {
    cwd,
    // SECURITY: `env` carries the `npm_config_git` pin so a repo `.npmrc git=`
    // cannot redirect npm's git binary during the PRE-TRUST part-1 install
    // (see hostInstallEnv() / trustedGitPath()).
    env,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    encoding: 'utf8',
    maxBuffer: CAPTURE_MAX_BUFFER,
  });
  return {
    status: r.status,
    signal: r.signal,
    error: r.error,
    stdout: typeof r.stdout === 'string' ? r.stdout : '',
    stderr: typeof r.stderr === 'string' ? r.stderr : '',
  };
};

/**
 * Part 1 — install dependencies on the host with lifecycle scripts disabled.
 * Throws on spawn failure or a non-zero exit (no usable tree → fail the job).
 */
export function hostInstallNoScripts(
  pm: Manager,
  repoDir: string,
  args: ReadonlyArray<string>,
  io: HostInstallIo,
  spawn: HostSpawn = captureSpawn,
): void {
  const { kept, dropped, droppedKeys } = sanitizeInstallArgs(args);
  // SECURITY: never log raw `dropped` tokens — they may carry credential values
  // (e.g. `--registry=SECRET`, a positional path).  Log only the grammar-derived
  // reasons (droppedKeys) — canonical flag names or the literal `<positional>` —
  // which are well-known constants, never user-supplied text.
  if (droppedKeys.length > 0) {
    const n = dropped.length; // raw token count (flag + consumed value tokens)
    const keys = droppedKeys.join(', ');
    io.warn(
      `script-jail: ignoring ${n} install arg${n === 1 ? '' : 's'} (${keys}) — ` +
        `not on the allowlist of dependency-selection flags, or carrying an ` +
        `unsafe value (e.g. an inline-credential --registry URL). Only flags ` +
        `that filter the lockfile-pinned tree (plus a credential-free ` +
        `--registry) are forwarded; anything that could redirect the ` +
        `lock/root/output/source, re-enable lifecycle scripts, or carry an ` +
        `inline credential is dropped.`,
    );
  }
  const base = FETCH_CMD[pm];
  // SECURITY (host part-1 ONLY): pnpm executes a repo `.pnpmfile.cjs` (and
  // config-relocated pnpmfiles) at `require` time during `pnpm install
  // --ignore-scripts`, BEFORE the trust gate — `--ignore-scripts` does NOT stop
  // it.  `--ignore-pnpmfile` is a robust catch-all (no path-enumeration gap) that
  // suppresses EVERY pnpmfile variant; for a repo that legitimately ships a
  // pnpmfile its committed `pnpmfileChecksum` then makes this `--frozen-lockfile`
  // install abort (fail closed).  This is a HOST-ONLY deviation from the shared
  // FETCH_CMD: the SANDBOX fetch keeps the pnpmfile so the hook is AUDITED there
  // (the enforcement boundary).  Repos that ship a pnpmfile are already refused
  // install upstream (install-preflight.ts), so for the clean repos that reach
  // here this flag is a no-op and the host/sandbox trees still match byte-for-byte.
  const hostHardening = pm === 'pnpm' ? ['--ignore-pnpmfile'] : [];
  // Order mirrors the guest fetch phase: <fixed args> <user args> <store-dir>.
  // The pnpm `--store-dir` pin is appended last so the host links against the
  // same repo-local store the audited sandbox used (see pnpmStoreDirArg).
  const finalArgs = [...base.args, ...kept, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  // SECURITY: safeDisplayArgs is used for the banner AND error messages.  It
  // contains ONLY the fixed base args + store-dir (no user-supplied tokens).
  // A count-only suffix documents that user args exist without echoing them.
  const safeBaseArgs = [...base.args, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  const userArgSuffix =
    kept.length > 0
      ? ` (+${kept.length} user install arg${kept.length === 1 ? '' : 's'}, not shown)`
      : '';
  io.stdout.write(
    `[script-jail] host install (lifecycle scripts disabled): ${base.cmd} ${safeBaseArgs.join(' ')}${userArgSuffix}\n`,
  );
  // Pass safeBaseArgs (without user tokens) as displayArgs so that error
  // messages (signal / non-zero exit) never expose credentials.
  const safeDisplayArgs = kept.length > 0
    ? [...safeBaseArgs, `(+${kept.length} user install arg${kept.length === 1 ? '' : 's'}, not shown)`]
    : safeBaseArgs;
  // The PM's OWN captured stdout/stderr is run through the redactor before it
  // reaches the job log (the user args this part takes can be echoed back by
  // the PM — e.g. `npm warn invalid config registry="SECRET"`).  Written
  // REGARDLESS of exit status: the user needs to see PM output, especially on
  // failure.  Redaction is LOG-ONLY — the real `args` already went to spawn.
  const sensitive = deriveSensitiveValues(kept);
  const onOutput = (stdout: string, stderr: string): void => {
    if (stdout.length > 0) io.stdout.write(redactCaptured(stdout, sensitive));
    if (stderr.length > 0) io.stderr.write(redactCaptured(stderr, sensitive));
  };
  runOrThrow(base.cmd, finalArgs, repoDir, hostInstallEnv(pm), spawn, 'no-scripts install', io, safeDisplayArgs, onOutput);
}

/** Mask user-arg values first (exact), then catch credential SHAPES. */
function redactCaptured(text: string, sensitive: readonly string[]): string {
  let red = maskExactValues(text, sensitive, 'REDACTED:USER-ARG');
  red = redactCredentialShapes(red);
  return red;
}

/**
 * Async streaming runner for part 2.  Spawns the child with piped stdout/stderr,
 * forwards each COMPLETE line through `onLine` (LIVE, line-buffered progress —
 * the install can run long), and resolves with the exit disposition.  Unlike the
 * old `stdio:'inherit'`, the lifecycle output passes through a redactor at the
 * call site so a trusted script can't echo a secret to the job log raw
 * (adversarial-review F6).  The trace itself is unaffected — this is the host
 * runner; the sandbox audit already ran.
 */
export type HostStreamSpawn = (
  cmd: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  onLine: (stream: 'stdout' | 'stderr', line: string) => void,
) => Promise<{ status: number | null; signal: NodeJS.Signals | null; error?: Error }>;

/**
 * Cap on a single UNTERMINATED line buffered in the action process.  A trusted
 * lifecycle script that writes a huge run of bytes with no newline would
 * otherwise grow `pending` without bound and OOM the runner (adversarial-review
 * F6, Claim B).  Mirrors the guest's `PHASE_B_STDOUT_PENDING_MAX_BYTES` (1 MiB):
 * an unterminated line over this bound is poisoned (one fixed marker, then bytes
 * dropped until the next newline) — never forwarded raw, so a secret split
 * across the cap cannot leak.
 */
export const HOST_PART2_MAX_LINE_BYTES = 1_048_576;

/** Fixed (credential-free) marker emitted when an unterminated line is poisoned. */
export const HOST_PART2_POISON_MARKER = '[script-jail] (oversized output line truncated)';

/**
 * Fixed (credential-free) marker emitted when the grace window closes while a
 * pipe is still open (a detached descendant holds fd1/fd2).  The pending bytes
 * are an UNTERMINATED, mid-write fragment on a NON-EOF stream — possibly the
 * prefix of a secret the descendant is still writing.  Exact-value redaction
 * only matches a COMPLETE declared value, so this TRAILING fragment is DROPPED
 * (only this marker emitted), never forwarded raw (adversarial-review F6 round-2).
 *
 * SCOPE (important — do NOT over-read this): this drops only the fragment that
 * is STILL PENDING (no newline yet) when the grace window closes.  It does NOT,
 * and on a shared pipe CANNOT, mask a secret that a concurrent writer's newline
 * completes into a "line" mid-stream: stdout/stderr are one fd shared by the pm
 * and every descendant, so "writer A's prefix + writer B's '\n'" is
 * indistinguishable from "writer A's whole line" at the reader.  A secret
 * interleaved/split across a newline on the shared pipe is therefore matched
 * per-line only — the same irreducible LINE-LOCAL residual the guest forwarders
 * carry (see src/shared/redact.ts LINE-LOCAL CONTRACT + attachStdoutTailCollector).
 * This redactor is DEFENSE-IN-DEPTH; the PRIMARY protection is the env_read
 * audit gate: a script cannot obtain a protected value to leak (whole or
 * fragmented) without a recorded env_read that fails the PR pre-trust, so host
 * part-2 never runs for it (adversarial-review F6 round-3, verified).
 */
export const HOST_PART2_TRUNCATED_MARKER = '[script-jail] (trailing output dropped — pipe held open past grace)';

/**
 * Grace window after the DIRECT child exits before `streamSpawn` resolves even
 * if the pipe never reaches EOF (adversarial-review F6, Claim A).  With
 * `stdio:['inherit','pipe','pipe']` a detached descendant that inherits fd1/fd2
 * keeps the pipe write-end open, so the read-end never EOFs and a `'close'`/
 * `'end'`-gated resolve would hang until the CI job timeout — triggerable even
 * by a benign postinstall that starts a background daemon.  The OS pipe buffer
 * is small, so already-buffered output is delivered well within this window;
 * the timer only matters when a descendant holds the pipe, where finishing
 * promptly is the correct behaviour (the install/rebuild is already done).
 */
export const HOST_PART2_DRAIN_GRACE_MS = 2_000;

/**
 * Per-stream bounded line splitter.  `StringDecoder` buffers an incomplete
 * multibyte sequence across chunk boundaries (so a redacted token is never split
 * mid-codepoint); complete lines are forwarded whole through `onLine`; an
 * unterminated line over the byte cap is poisoned.  `finalize(streamEnded)`
 * forwards a final unterminated partial line ONLY on genuine EOF; on the grace
 * path (still-open pipe) it drops the trailing fragment (see
 * HOST_PART2_TRUNCATED_MARKER for the scope of that drop).
 */
export function makeLineSink(
  which: 'stdout' | 'stderr',
  onLine: (stream: 'stdout' | 'stderr', line: string) => void,
  maxBytes: number = HOST_PART2_MAX_LINE_BYTES,
): { onData: (chunk: Buffer) => void; finalize: (streamEnded: boolean) => void } {
  const decoder = new StringDecoder('utf8');
  let pending = '';
  let poisoned = false; // sticky for the CURRENT oversized unterminated line
  const onData = (chunk: Buffer): void => {
    pending += decoder.write(chunk);
    let nl: number;
    while ((nl = pending.indexOf('\n')) !== -1) {
      const line = pending.slice(0, nl);
      pending = pending.slice(nl + 1);
      // A newline ends the (dropped) oversized line; reset and resume normally.
      if (poisoned) { poisoned = false; continue; }
      onLine(which, line);
    }
    // `pending` now holds no newline.  Bound it: an oversized unterminated line
    // is poisoned once (never forwarded raw) and its bytes dropped until a '\n'.
    if (poisoned) {
      pending = '';
    } else if (pending.length > maxBytes) {
      onLine(which, HOST_PART2_POISON_MARKER);
      pending = '';
      poisoned = true;
    }
  };
  // Finalize the stream.  `streamEnded` distinguishes the two teardown paths:
  //   * true  — the stream emitted `end` (genuine EOF): the trailing `pending`
  //     is a COMPLETE line (EOF-terminated), fully written, so redaction at the
  //     call site sees the whole value → forward it.
  //   * false — the grace window closed while the pipe is STILL OPEN (a detached
  //     descendant holds it, possibly mid-write): `pending` is a fragment that
  //     exact-value redaction cannot match → DROP it, emit only the fixed marker
  //     (adversarial-review F6 round-2).
  const finalize = (streamEnded: boolean): void => {
    pending += decoder.end();
    if (poisoned) { pending = ''; poisoned = false; return; }
    if (pending.length === 0) return;
    onLine(which, streamEnded ? pending : HOST_PART2_TRUNCATED_MARKER);
    pending = '';
  };
  return { onData, finalize };
}

export const streamSpawn: HostStreamSpawn = (cmd, args, cwd, env, onLine) =>
  new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      // fd0 inherits stdin; fd1/fd2 piped so each line can be redacted before it
      // reaches the job log.  shell:false — argv is passed verbatim, never parsed.
      child = spawn(cmd, args, { cwd, env, stdio: ['inherit', 'pipe', 'pipe'], shell: false });
    } catch (error) {
      resolve({ status: null, signal: null, error: error as Error });
      return;
    }
    // Per-stream state: its sink + whether it reached natural EOF (`end`).  The
    // `ended` flag decides how its trailing partial line is finalized (forward on
    // EOF, drop+marker on the grace path) — see makeLineSink.finalize.
    const sinks = {
      stdout: { sink: makeLineSink('stdout', onLine, HOST_PART2_MAX_LINE_BYTES), stream: child.stdout, ended: false },
      stderr: { sink: makeLineSink('stderr', onLine, HOST_PART2_MAX_LINE_BYTES), stream: child.stderr, ended: false },
    };
    child.stdout?.on('data', sinks.stdout.sink.onData);
    child.stderr?.on('data', sinks.stderr.sink.onData);

    // Resolve disposition off the DIRECT child's `exit` (fires the moment the pm
    // process terminates, regardless of any descendant still holding the inherited
    // pipe) — NOT `close`, which waits for pipe EOF and would hang on a held pipe.
    let exit: { status: number | null; signal: NodeJS.Signals | null; error?: Error } | null = null;
    let settled = false;
    let graceTimer: NodeJS.Timeout | null = null;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      if (graceTimer !== null) clearTimeout(graceTimer);
      // Finalize each sink with its OWN EOF state: a stream that ended forwards
      // its complete trailing line; a still-open stream (grace path) drops its
      // mid-write fragment and emits only a fixed marker.  Then stop reading so a
      // descendant holding the pipe can't keep this process alive.
      for (const s of [sinks.stdout, sinks.stderr]) {
        s.sink.finalize(s.ended);
        s.stream?.destroy();
      }
      resolve(exit ?? { status: null, signal: null });
    };
    // Finish promptly once BOTH pipes reach natural EOF (the common case: no
    // descendant holds them) — clears the grace timer so there is no added
    // latency.  `ends` counts the wired streams down to 0.
    let ends = 0;
    const wireEnd = (s: { stream: Readable | null; ended: boolean }): void => {
      if (s.stream == null) return;
      ends += 1;
      s.stream.on('end', () => { s.ended = true; ends -= 1; if (ends === 0 && exit !== null) finish(); });
    };
    wireEnd(sinks.stdout);
    wireEnd(sinks.stderr);
    child.on('error', (error) => { exit = { status: null, signal: null, error }; finish(); });
    child.on('exit', (status, signal) => {
      exit ??= { status, signal };
      // Pipes already drained → resolve now; else start the bounded grace window.
      if (ends === 0) finish();
      else {
        graceTimer = setTimeout(finish, HOST_PART2_DRAIN_GRACE_MS);
        graceTimer.unref?.();
      }
    });
  });

/**
 * Part 2 — run the lifecycle scripts part 1 deferred.  The caller MUST have
 * confirmed the audit is `trusted` before calling this.  Throws on failure.
 *
 * SECURITY (adversarial-review F6): these are the REAL (audit-trusted) lifecycle
 * scripts, run on the runner with the job env (which may carry NPM_TOKEN /
 * NODE_AUTH_TOKEN / registry auth).  A script can print to stdout/stderr, so —
 * symmetric with the sandbox Phase-B tail and host part-1 capture — every line is
 * redacted before it reaches the job log: exact `protectedEnvNames` values
 * (`maskExactValues`, minLen=1 for declared secrets) plus credential SHAPES
 * (`redactCredentialShapes`).
 *
 * The env_read audit gate remains the PRIMARY protection and this is
 * DEFENSE-IN-DEPTH.  Two residuals are accepted-by-design, both bounded by that
 * gate: (1) redaction is per-COMPLETE-LINE + exact-value, so a secret a writer
 * splits across a newline — or that a concurrent writer's newline completes on
 * the shared stdout/stderr pipe — is matched per-line only (the irreducible
 * LINE-LOCAL residual the guest forwarders also carry; see redact.ts); (2) the
 * env-read shim/Proxy do not see a raw `environ[]` walk (documented gap).  In
 * BOTH cases a script cannot obtain a protected value to leak without a recorded
 * env_read that fails the PR pre-trust, so host part-2 never runs for it — the
 * redactor only hardens the ACCIDENTAL-echo case for already-approved scripts.
 */
export async function hostRunScripts(
  pm: Manager,
  repoDir: string,
  io: HostInstallIo,
  protectedEnvNames: readonly string[] = [],
  spawn: HostStreamSpawn = streamSpawn,
): Promise<void> {
  const cmd = INSTALL_CMD[pm];
  // SECURITY (host part-2, symmetric with part-1's --ignore-pnpmfile): `pnpm
  // rebuild` LOADS + EXECUTES a (possibly ANCESTOR workspace-root) `.pnpmfile`'s
  // top-level code on the runner, AFTER the trust gate, unaudited (the sandbox
  // staged only repoDir, so an ancestor pnpmfile was never audited).  Part-2
  // `pnpm rebuild` REJECTS the bare `--ignore-pnpmfile` flag ("Unknown option",
  // exit 1 — would break every clean install), so suppress the pnpmfile via the
  // config-namespaced form (same style as the existing
  // `--config.side-effects-cache=false`).  HOST-ONLY: the guest Phase B keeps
  // the pnpmfile so the hook is AUDITED at the enforcement boundary, so this
  // lives here, NOT in the shared INSTALL_CMD.
  const hostHardening = pm === 'pnpm' ? ['--config.ignore-pnpmfile=true'] : [];
  // Same store-dir pin as part 1 / the guest install phase: pnpm must relink
  // against the repo-local store, not the runner default (parity).
  const finalArgs = [...cmd.args, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  io.stdout.write(`[script-jail] host lifecycle scripts (audit matched): ${cmd.cmd} ${finalArgs.join(' ')}\n`);
  // Exact secret values to mask: the declared protected.env names' values in the
  // host env.  minLen=1 (mask every NON-EMPTY declared value, longest-first):
  // the `maskExactValues` default >=4-char floor is a heuristic for the
  // ARG-derived path (don't blank out "dev" from `--omit=dev`), but a user who
  // names an env var in `protected.env` has explicitly declared it a SECRET —
  // honour that regardless of length, or a 1-3 char declared secret echoed by a
  // trusted post-trust script would reach the job log raw (adversarial-review
  // F6, Finding 1).  Empty values (length 0) are still skipped by the >=1 floor,
  // so an unset/blank protected var never mass-masks the output.
  const sensitive = protectedEnvNames
    .map((name) => process.env[name])
    .filter((v): v is string => typeof v === 'string');
  // Build the fragment gram matcher ONCE, before streaming: a large
  // `protected.env` would otherwise pay an O(sum |V|) rebuild on EVERY emitted
  // line (and a reachable-large set would blackhole every line) — review #7.
  const fragMatcher = buildFragmentMatcher(sensitive);
  // FAIL LOUD, not silent: if the declared secret material exceeds what the
  // redactor can index, a per-line capped matcher would mask EVERY line whole —
  // blackholing the job log.  Refuse up front with an actionable error instead
  // of silently streaming a blanked log (adversarial-review review #8).  This is
  // only reachable with a very large `protected.env` on a high-`ulimit` runner.
  if (fragMatcher.capped) {
    throw new Error(
      'script-jail: protected.env declares more distinct secret material than the host ' +
        'lifecycle-log redactor can safely index (> 2 MiB of values). Refusing to stream ' +
        'host lifecycle output — redacting per line against an incomplete secret index ' +
        'would either leak a torn secret fragment or blank every line. Reduce protected.env.',
    );
  }
  const onLine = (stream: 'stdout' | 'stderr', line: string): void => {
    let safe = maskExactValues(line, sensitive, 'REDACTED:ENV', 1);
    // Also mask a declared secret that leaks as a FRAGMENT — a prefix/suffix
    // (e.g. a concurrent writer's newline truncating it mid-write on the shared
    // pipe) OR a middle slice (both ends torn).  Exact masking only matches the
    // whole value; the n-gram overlap design covers any fragment >= the
    // high-entropy floor (adversarial-review F6 round-3 hardening).  ONE
    // cross-value matcher so a longer value's shared gram can't strand a shorter
    // value's leaked fragment.
    safe = maskValueFragmentsWith(safe, fragMatcher, 'REDACTED:ENV');
    safe = redactCredentialShapes(safe);
    (stream === 'stdout' ? io.stdout : io.stderr).write(`${safe}\n`);
  };
  const r = await spawn(cmd.cmd, finalArgs, repoDir, hostInstallEnv(pm), onLine);
  // finalArgs is credential-free (no user args), so it is safe to show in errors.
  if (r.error !== undefined) {
    throw new Error(`script-jail: host lifecycle-script run could not spawn "${cmd.cmd}": ${r.error.message}`);
  }
  if (r.signal != null) {
    throw new Error(`script-jail: host lifecycle-script run (\`${cmd.cmd} ${finalArgs.join(' ')}\`) was killed by ${r.signal}`);
  }
  if (r.status !== 0) {
    throw new Error(
      `script-jail: host lifecycle-script run (\`${cmd.cmd} ${finalArgs.join(' ')}\`) exited with code ${r.status ?? 'null'}`,
    );
  }
  io.stdout.write(`[script-jail] host lifecycle-script run complete\n`);
}

/**
 * Spawn `cmd args` in `cwd` and throw a descriptive error on failure.
 *
 * SECURITY: error messages MUST NOT interpolate the real `args` when the caller
 * passes user-controlled tokens (e.g. registry auth tokens).  Instead the caller
 * supplies a separate `displayArgs` whose text is safe to expose in the GitHub
 * Actions log.  The real `args` are passed to `spawn` unchanged — only the
 * human-readable error messages use `displayArgs`.
 *
 * `displayArgs` MUST be set to a credential-free representation.  For
 * `hostInstallNoScripts` that means the fixed base args + a count-only suffix
 * for any user args; for `hostRunScripts` (no user args) it is identical to
 * `args`.
 */
function runOrThrow(
  cmd: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  spawn: HostSpawn,
  label: string,
  io: HostInstallIo,
  displayArgs: string[],
  onOutput?: (stdout: string, stderr: string) => void,
): void {
  const r = spawn(cmd, args, cwd, env);
  // Surface captured output (redacted by the caller's closure) BEFORE any
  // error/throw check, so the PM's own diagnostics reach the log even when the
  // run failed.  A live-inheriting runner returns no stdout/stderr → no-op.
  if (onOutput !== undefined && (r.stdout !== undefined || r.stderr !== undefined)) {
    onOutput(r.stdout ?? '', r.stderr ?? '');
  }
  if (r.error !== undefined) {
    // spawn-level failure: never had an argv in a shell — no leak path here.
    throw new Error(`script-jail: host ${label} could not spawn "${cmd}": ${r.error.message}`);
  }
  if (r.signal != null) {
    // Use displayArgs (safe), NOT args (may contain credentials).
    throw new Error(`script-jail: host ${label} (\`${cmd} ${displayArgs.join(' ')}\`) was killed by ${r.signal}`);
  }
  if (r.status !== 0) {
    // Use displayArgs (safe), NOT args (may contain credentials).
    throw new Error(
      `script-jail: host ${label} (\`${cmd} ${displayArgs.join(' ')}\`) exited with code ${r.status ?? 'null'}`,
    );
  }
  io.stdout.write(`[script-jail] host ${label} complete\n`);
}

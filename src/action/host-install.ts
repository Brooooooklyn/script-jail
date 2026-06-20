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
import {
  accessSync,
  constants as fsConstants,
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, isAbsolute, join, resolve, sep } from 'node:path';
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
 * LEXICAL canonicalization for containment: resolve to absolute + case-fold on a
 * case-insensitive FS, but DO **NOT** follow symlinks.  Pairs with
 * `canonicalForCompare` (which realpaths) to close the symlink-OUT bypass: a PATH
 * entry whose LEXICAL spelling is inside the checkout but whose symlink TARGET is a
 * system dir (e.g. `$GITHUB_WORKSPACE/tools -> /usr/bin`) passes the realpath-only
 * containment test (its real path is outside the checkout) yet is PR-controlled —
 * the PR can repoint that symlink to a dir of malicious binaries in trusted host
 * part-2, AFTER the audit.  Comparing the lexical spelling against a LEXICAL roots
 * set (both resolved without realpath, same case space) catches it; comparing a
 * lexical entry against the realpath roots would miss when a checkout-root ancestor
 * is itself a symlink (e.g. macOS `/tmp -> /private/tmp`), so the two sets are kept
 * separate.
 */
function lexicalForCompare(p: string): string {
  const abs = resolve(p);
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
 * The same checkout roots as `checkoutRoots`, but canonicalized LEXICALLY (no
 * realpath) so a symlink-OUT PATH entry (lexically inside the checkout, target
 * outside) is caught.  Kept as a SEPARATE set from the realpath roots — see
 * `lexicalForCompare`.
 */
function checkoutRootsLexical(): string[] {
  const roots: string[] = [];
  for (const v of [
    process.env['GITHUB_WORKSPACE'],
    process.env['SCRIPT_JAIL_REPO_DIR'],
    process.cwd(),
  ]) {
    if (v !== undefined && v !== '') roots.push(lexicalForCompare(v));
  }
  return roots;
}

/**
 * True when `p`'s LEXICAL spelling (resolve only, NO symlink follow, case-folded
 * on case-insensitive FS) is a checkout root or nested under one.  `lexRoots` MUST
 * be `checkoutRootsLexical()` (lexically canonicalized) so both sides compare in
 * the same space.  Catches the symlink-OUT bypass that `isUnderCheckout` (realpath)
 * misses.
 */
function isLexicallyUnderCheckout(p: string, lexRoots: ReadonlyArray<string>): boolean {
  const abs = lexicalForCompare(p);
  for (const root of lexRoots) {
    if (abs === root || abs.startsWith(root + sep)) return true;
  }
  return false;
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
 * True when `p` is a checkout root or nested under one (`$GITHUB_WORKSPACE` /
 * `$SCRIPT_JAIL_REPO_DIR` / `process.cwd()`).  EXPORTED so other pre-trust
 * host-exec sites (e.g. the VZ helper-binary override in
 * {@link resolveScriptJailVmBinary}) can reject a checkout-controlled path with
 * the SAME symlink/case-robust containment test the PATH/git sanitizers use,
 * instead of re-implementing it.
 *
 * Checks BOTH containment spaces, exactly like `resolveGitFromPath` /
 * `sanitizePathValue` (round-12 finding #24): the REAL path (symlinks resolved)
 * AND the LEXICAL spelling (resolve-only, no symlink follow).  The realpath test
 * alone MISSES the symlink-OUT bypass — a path spelled under the checkout
 * (`$GITHUB_WORKSPACE/tools/script-jail-vm`) via a committed symlink
 * (`tools -> <outside>`) realpaths OUTSIDE the checkout, so a realpath-only guard
 * would accept it even though the symlink itself is PR-controlled.  The lexical
 * arm rejects it on the under-checkout SPELLING regardless of the link target.
 */
export function isPathUnderCheckout(p: string): boolean {
  return (
    isUnderCheckout(p, checkoutRoots()) ||
    isLexicallyUnderCheckout(p, checkoutRootsLexical())
  );
}

/**
 * A TRUSTED host temp root for the `install: true` Firecracker-parity `TMPDIR`
 * (threaded into {@link hostInstallEnv} as `hostTmpdir`).  The Firecracker guest
 * lifecycle child has `TMPDIR=/sjtmp` (a dedicated VM disk, absolute, outside any
 * checkout); to close the value-blind PRESENCE oracle the host re-run must also have
 * `TMPDIR` present.
 *
 * SECURITY (codex round-4 [high]): do NOT derive this from `os.tmpdir()`.  `os.tmpdir()`
 * honors the AMBIENT `process.env.TMPDIR`/`TMP`/`TEMP`, which a malicious workflow `env:`
 * (or a fork PR's workflow) sets on the action process.  Threading that value into the
 * TRUSTED host lifecycle child would let an attacker point `TMPDIR` UNDER the checkout
 * (or set a relative value resolved against `cwd=repoDir`), redirecting every
 * `$TMPDIR`-spelled tempfile WRITE the post-trust scripts make INTO the repo tree — a
 * write the audit (guest `/sjtmp`) never saw and which can dedupe-collapse with a genuine
 * root write.  So this IGNORES the ambient names entirely and uses a FIXED system temp
 * (`/tmp`), realpath-canonicalized (defeats a symlinked `/tmp`) and asserted absolute +
 * outside-checkout.  It THROWS — fail closed, refusing the host re-run rather than running
 * it with an unsafe or divergent temp — if `/tmp` cannot be validated.  Only the PRESENCE
 * closes the oracle; the value differing from `/sjtmp` is the documented accepted residual
 * (a script must branch on `TMPDIR`'s VALUE, and `/sjtmp` cannot exist on the host).
 */
export function trustedHostTmpdir(): string {
  let canonical: string;
  try {
    // Fixed `/tmp` (NOT os.tmpdir()): the canonical POSIX temp, independent of the
    // attacker-controllable TMPDIR/TMP/TEMP names.  realpathSync resolves a symlinked
    // `/tmp` so a `/tmp -> <checkout>/x` redirect is caught by the under-checkout test.
    canonical = realpathSync('/tmp');
  } catch (err) {
    throw new Error(
      `script-jail: \`install: true\` could not resolve a trusted host temp directory ` +
        `(/tmp): ${(err as Error).message}`,
    );
  }
  if (!isAbsolute(canonical) || isPathUnderCheckout(canonical)) {
    throw new Error(
      `script-jail: \`install: true\` refuses host temp "${canonical}" — it must be an ` +
        `absolute path outside the checkout (TMPDIR parity with the Firecracker audit).`,
    );
  }
  return canonical;
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
  const lexRoots = checkoutRootsLexical();
  for (const dir of pathVar.split(delimiter)) {
    if (dir === '') continue;
    // SECURITY: never resolve the "trusted" git from a checkout-controlled PATH
    // entry (cheap dir-level reject) — see the function note above.  Reject by BOTH
    // the realpath (symlink-IN) and the lexical spelling (symlink-OUT: a
    // `$GITHUB_WORKSPACE/tools -> /usr/bin` dir is PR-controlled and repointable).
    if (isUnderCheckout(dir, roots)) continue;
    if (isLexicallyUnderCheckout(dir, lexRoots)) continue;
    for (const name of names) {
      const candidate = join(dir, name);
      // Only accept an ABSOLUTE candidate so a relative PATH entry (e.g. `.`)
      // can't point npm at a repo-placed shadow binary.
      if (!isAbsolute(candidate)) continue;
      // MODEL execvp (mirror resolveBareOnPath, codex round-17c/17d, #38): npm execs
      // `npm_config_git` exactly as the OS resolves a bare name, so only a regular,
      // EXECUTABLE file is a real hit.  A DIRECTORY or a NON-EXECUTABLE file named
      // `git` earlier on PATH is skipped by execvp (it keeps scanning), but plain
      // `existsSync` returned it and pinned it as npm_config_git — breaking a git-dep
      // install that would otherwise fall through to the real git later on PATH.
      // statSync follows symlinks (symlink-to-file kept, symlink-to-dir skipped); a
      // missing/broken candidate throws → skip; access(X_OK) is the exact predicate
      // execvp uses (on win32 — Linux-gated host — it degrades to existence, which
      // the `.exe/.cmd` name list already covers).
      let st;
      try {
        st = statSync(candidate);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      try {
        accessSync(candidate, fsConstants.X_OK);
      } catch {
        continue;
      }
      // SECURITY: the git BINARY itself may be a symlink whose real target lives
      // in the checkout even when its PATH dir does not — re-check the resolved
      // candidate's real path (symlink-IN) AND its lexical spelling (symlink-OUT)
      // before trusting it.
      if (isUnderCheckout(candidate, roots)) continue;
      if (isLexicallyUnderCheckout(candidate, lexRoots)) continue;
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
 * VALUE-BLIND ENV-READ ORACLE — why the install-aligned host re-run env is an
 * ALLOWLIST, not a denylist (idx 25 / codex follow-up).
 *
 * The Firecracker/Docker guest audits inside a CLEAN env reconstructed from
 * scratch (FC `init.sh` exports a fixed set; Docker forwards only the two
 * SCRIPT_JAIL_* control vars via `-e`; the guest agent's `sanitizeLifecycleBaseEnv`
 * never carries the runner's ambient env).  So the guest lifecycle child's env-NAME
 * set is small and fixed: PATH/HOME/TMPDIR + the package manager's own derived
 * `npm_*` + instrumentation.  The host re-run, by contrast, inherits the runner's
 * `process.env` — which on a real GitHub runner holds GITHUB_*, RUNNER_*, and ANY
 * var the owner's workflow `env:` block set.
 *
 * The lock records env-read NAMES only (value-blind), and an attacker controls
 * which branch (NAME present vs absent) is the evil one.  So ANY name present for
 * the host child but absent for the guest child is an oracle: a dependency reads it,
 * branches benign in the audit (absent), then takes the evil branch on the trusted
 * host (present), under a matching clean lock — the catastrophic false-negative.
 * A DENYLIST can NEVER close this — a workflow can set an arbitrary var, so the
 * dangerous set is unbounded.  The only complete close is an ALLOWLIST: keep only
 * names the guest lifecycle child also has, drop everything else ambient
 * (GITHUB_*, RUNNER_*, NODE_ENV, CI, LANG, arbitrary `env:`).
 *
 * Host-side ONLY: this allowlist lives in hostInstallEnv (the install-aligned
 * path).  It is intentionally NOT in stripDangerousEnv (shared with the bare/mac-bare
 * AGENT, which legitimately inherits ambient env — there the audit IS the host, the
 * backend is not install-aligned).  NOT a complete oracle close beyond the env layer:
 * `os.hostname()`/`uname()` syscalls, the audit-only instrument env the guest MUST
 * carry (`LD_PRELOAD`, `NODE_OPTIONS`), and container/VM marker files remain
 * out-of-band tells; `process.cwd()` is handled by the work_dir cwd-parity (M1).
 */
// Base ambient names the guest lifecycle child ALSO has, so the host re-run keeps
// them in BOTH phases for parity.  PATH is already sanitized by
// stripDangerousEnv/sanitizePathValue; HOME is the runner's real, outside-checkout
// HOME (both guest backends export HOME).
//
// TMPDIR is DELIBERATELY NOT here: the two install-aligned guest backends already
// DISAGREE on it — Firecracker exports TMPDIR=/sjtmp into the lifecycle child (an
// ENOSPC mitigation in src/rootfs/init.sh) while Docker exports none — so no
// host-side rule can match both at once.  Dropping it (a Linux runner sets no TMPDIR
// by default, so this is usually a no-op) gives full parity with the Docker guest
// (both absent) and prevents a workflow-set TMPDIR becoming a host-present/guest-absent
// oracle.  RESIDUAL vs the Firecracker guest (/sjtmp present, host absent): irreducible
// from the host while guest code is frozen — same accepted class as the guest's other
// injected tells (LD_PRELOAD/SCRIPT_JAIL_*); Firecracker is the enforcement boundary,
// the proper close is guest-side (filter TMPDIR from the lifecycle child / attribution).
const HOST_INSTALL_KEEP_BASE_ENV_NAMES = new Set(['PATH', 'HOME']);

// Non-namespaced registry-auth / proxy / git-behaviour env the host install
// legitimately ADDS over the clean-VM audit.  Each carries credentials / routing /
// restrict-only behaviour — no exec/loader/config-FILE selector.  Matched
// case-insensitively.  FETCH-PHASE ONLY (see isHostInstallParityKeepName): part-1
// (--ignore-scripts) needs them to reach a private/proxied registry or a git: dep and
// runs NO lifecycle script, so there is no env-read oracle there.  The guest lifecycle
// child has NONE of these (verified: the runner's auth is never forwarded into the
// VM/container — private-registry auth rides the staged repoDir/.npmrc, not the env),
// so the SCRIPT phase (part-2) MUST drop them to equal the guest Phase B.
const HOST_INSTALL_KEEP_AUTH_ENV_NAMES = new Set(
  [
    'NODE_AUTH_TOKEN',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NO_PROXY',
    'GIT_ALLOW_PROTOCOL', // restricts the git transport set, never weakens
    'GIT_TERMINAL_PROMPT', // behaviour flag (prevents an interactive clone hang)
  ].map((n) => n.toLowerCase()),
);

/**
 * True when an env NAME (already filtered through stripDangerousEnv) must SURVIVE
 * into the install-aligned host PM child.  PHASE-AWARE ALLOWLIST (see the oracle note
 * above).
 *
 * BOTH phases keep the guest base (PATH/HOME).  The registry/auth/TLS/proxy surface —
 * the non-namespaced auth/proxy/git pins AND the npm_config_* / pnpm_config_* / yarn_*
 * survivors (stripDangerousEnv already dropped every key in those namespaces except
 * the registry/auth/TLS/proxy allowlist) — is kept ONLY in the FETCH phase: part-1
 * runs no lifecycle script (no oracle) but needs it to reach a private/proxied
 * registry; the clean-VM guest lifecycle child has NONE of it, so the SCRIPT phase
 * (part-2) drops it so host part-2 == guest Phase B (all absent).  Mirrors the
 * fetch-only scoping of the npm_config_git pin.  Everything else ambient (GITHUB_*,
 * RUNNER_*, NODE_ENV, CI, LANG, TMPDIR, SCRIPT_JAIL_*, arbitrary workflow `env:`) is
 * dropped in BOTH phases.  The COREPACK_* / cache / script-shell pins are layered on
 * AFTER this filter, so they are unaffected by it.
 */
function isHostInstallParityKeepName(name: string, phase: 'fetch' | 'scripts'): boolean {
  if (HOST_INSTALL_KEEP_BASE_ENV_NAMES.has(name)) return true;
  // The credential/routing surface is fetch-only — part-2's lifecycle child must
  // match the guest Phase B, which never has any of it.
  if (phase === 'scripts') return false;
  const lower = name.toLowerCase();
  if (HOST_INSTALL_KEEP_AUTH_ENV_NAMES.has(lower)) return true;
  return (
    lower.startsWith('npm_config_') ||
    lower.startsWith('pnpm_config_') ||
    lower.startsWith('yarn_')
  );
}

// ---------------------------------------------------------------------------
// SECURITY: strip INHERITED loader/config env vars that enable pre-trust code
// execution or host-vs-audit config divergence
// ---------------------------------------------------------------------------
//
// This is a SEPARATE category from the hostInstallEnv parity ALLOWLIST above (which
// keeps only the guest-parity names).  The names below are LOADER / TOOL-RESOLUTION /
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
    // (Corepack EXEC/config selectors AND its version-steering behaviour flags are
    // dropped by the `corepack_` FAMILY prefix below — see that entry.)
    // LOCALAPPDATA is corepack's win32-ONLY cache-root selector (= the COREPACK_HOME
    // executable-cache class, just platform-scoped).  The action only runs on
    // Linux/macOS runners (never win32), where neither corepack nor any PM reads it,
    // so dropping it is functionally inert on every real host AND closes two things:
    // (a) round-17e — a PR/runner-set LOCALAPPDATA must never steer corepackCacheRoot
    // to a planted cache (corepackCacheRoot now also ignores it off-win32), and
    // (b) the value-blind env_read parity — the clean-VM/guest audit never carries
    // LOCALAPPDATA, so the host lifecycle child must not either (else a dep reading
    // process.env.LOCALAPPDATA gets a host-present/audit-absent oracle NAME).
    'LOCALAPPDATA',
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
  // Corepack family — a pnpm/yarn bare command is commonly a corepack shim.  Two
  // dangerous sub-classes, BOTH dropped here so the SHARED sanitizer (every backend
  // AGENT spawn AND the host install) applies one parity policy:
  //   EXEC/config selectors — COREPACK_HOME (executable CACHE; a checkout-relative
  //     one makes corepack run a PR-planted bin/pnpm.cjs — VERIFIED corepack 0.35.0),
  //     COREPACK_ENV_FILE (loads env from a file), COREPACK_NPM_REGISTRY /
  //     COREPACK_INTEGRITY_KEYS / COREPACK_ROOT (redirect/unsign the downloaded PM).
  //   VERSION-STEERING flags — COREPACK_ENABLE_PROJECT_SPEC=0 makes corepack IGNORE
  //     the repo's `packageManager` and run a DIFFERENT pm VERSION (VERIFIED corepack
  //     0.35.0: yarn 3.8.7 pin -> 4.5.0), a host-vs-audit (and bare-audit-vs-host)
  //     SEMANTICS skew; COREPACK_DEFAULT_TO_LATEST / COREPACK_ENABLE_STRICT likewise.
  // The clean-VM audit inherits NO COREPACK_*, so dropping the whole family keeps
  // host==audit AND bare-audit==host.  The ONE flag a spawn legitimately needs,
  // COREPACK_ENABLE_DOWNLOAD_PROMPT=0 (avoid an interactive hang on an uncached PM
  // download), is RE-PINNED by every corepack-running caller AFTER this strip
  // (hostInstallEnv, backend/bare.ts, backend/mac-bare.ts, backend/docker.ts,
  // rootfs/init.sh, cli/provision-node-mac.ts) — never relied on as an inherited
  // pass-through.
  'corepack_',
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
  // npm-only: rewrites the HOST of lockfile-pinned tarball URLs to the configured
  // `registry` (VERIFIED npm 11.13.0 honors both separators, no Unknown-env warning).
  // Needed for a mirror where the lockfile pins NON-default public hosts but an
  // egress-locked runner must funnel all fetches through one internal registry, else
  // the host install fails after a clean audit.  PURE routing — pacote/arborist
  // rewrite only host/port/protocol/path and STILL verify the integrity hash against
  // the fetched bytes (no exec/loader/config-FILE).  pnpm has no consumer (zero dist
  // refs on 10.34.3/11.1.2) → harmless no-op there, like the other npm-only scalars.
  'replace_registry_host',
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
  // Network binding + fetch tuning — pure data (a validated IP, an int), never an
  // exec/loader/config-FILE selector.  VERIFIED env-settable on npm 11.13.0 + pnpm
  // 11.1.2 (pnpm_config_ form) + pnpm 10.34.3 (npm_config_ form): multi-homed /
  // internal-registry / slow-registry installs legitimately need these to REACH the
  // registry, and the clean-VM audit inherits none, so the host must be able to too.
  // `network_concurrency` is pnpm-only (npm ignores as "Unknown env config" — no-op).
  'local_address', // source IP for a multi-homed runner (npm validates it as an IP)
  'maxsockets', // connection pool size
  'fetch_timeout', // request timeout (ms)
  'fetch_retries', // retry count for a flaky internal registry
  'fetch_retry_factor',
  'fetch_retry_mintimeout',
  'fetch_retry_maxtimeout',
  'network_concurrency', // pnpm-only request concurrency
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
// other YARN_* config is dropped; see hostInstallEnv).  Yarn maps `YARN_<UPPER_SNAKE>`
// -> camelCase config and ENV BEATS the rc, over an open-ended, per-release-growing
// surface — so the keep-list is restricted to scalar auth/registry + pure-ROUTING
// network settings a private/internal-registry or proxied install genuinely needs,
// each VERIFIED (yarn 4.9.1) env-settable + pure data (string/int), never a
// folder/plugin/constraints/env-file redirect or exec/inject vector.
//   *_NPM_*            scalar auth/registry (map npmScopes/npmRegistries are NOT
//                      flat-env-settable, so per-scope auth lives in the rc, not env).
//   *_HTTP(S)_PROXY    proxy URLs — Yarn IGNORES unprefixed HTTP_PROXY/HTTPS_PROXY,
//                      so these are the only way to proxy a host yarn install.
//   *_HTTP_TIMEOUT/RETRY, *_NETWORK_CONCURRENCY  ints (got timeout/retry/concurrency).
//   *_HTTPS_{CA,CERT,KEY}_FILE_PATH  PEM file paths read as TLS MATERIAL ONLY — yarn
//     4.9.1 does `readFile -> got https.{certificateAuthority,certificate,key}`, NEVER
//     parsed-as-config or required-as-module (VERIFIED: a `pwn.sh` at the path during a
//     real `yarn add` was read as cert data, NOT executed).  Kept by NAME, matching the
//     existing npm `cafile`/`certfile`/`keyfile` scalars (which are likewise kept by name
//     with no containment) — internal-CA / mTLS registries need them.  Residual (same as
//     npm's): an inherited path INTO the checkout is honored uncontained; acceptable
//     because the material is data-only AND host installs are lockfile-frozen
//     (npm ci / --frozen-lockfile / --immutable), so a PR-controlled CA cannot substitute
//     package bytes (integrity hash aborts on mismatch; code-swap would also need a
//     network MITM, which a CA alone does not grant).
// DELIBERATELY EXCLUDED (kept dangerous):
//   - YARN_NETWORK_SETTINGS — a per-host MAP carrying its own file-path + enableNetwork
//     sub-keys (the config-parsed class).
//   - YARN_UNSAFE_HTTP_WHITELIST / YARN_ENABLE_STRICT_SSL — pure data, but they WEAKEN
//     the TLS/cleartext defaults the clean-VM audit ran with.
//   - every *Folder / constraintsPath / injectEnvironmentFiles / enableScripts.
const YARN_ENV_ALLOW = new Set([
  'YARN_NPM_AUTH_TOKEN',
  'YARN_NPM_AUTH_IDENT',
  'YARN_NPM_REGISTRY_SERVER',
  'YARN_NPM_ALWAYS_AUTH',
  'YARN_HTTP_PROXY', // -> httpProxy (URL)
  'YARN_HTTPS_PROXY', // -> httpsProxy (URL)
  'YARN_HTTP_TIMEOUT', // -> httpTimeout (int)
  'YARN_HTTP_RETRY', // -> httpRetry (int)
  'YARN_NETWORK_CONCURRENCY', // -> networkConcurrency (int)
  'YARN_HTTPS_CA_FILE_PATH', // -> httpsCaFilePath (PEM CA, read as TLS material)
  'YARN_HTTPS_CERT_FILE_PATH', // -> httpsCertFilePath (PEM client cert)
  'YARN_HTTPS_KEY_FILE_PATH', // -> httpsKeyFilePath (PEM client key)
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
  // YARN_* is an ALLOWLIST too: yarn maps `YARN_<UPPER_SNAKE>` -> config and ENV BEATS
  // the rc over an open-ended surface that includes EXEC selectors (YARN_YARN_PATH
  // re-execs a JS path — VERIFIED yarn 4.9.1; YARN_PLUGINS, YARN_RC_FILENAME,
  // YARN_INJECT_ENVIRONMENT_FILES, the *Folder redirects, …), so a key is dangerous
  // UNLESS in YARN_ENV_ALLOW.  Applied here in the SHARED gate (UNCONDITIONALLY, not
  // gated on pm) so EVERY backend AGENT spawn gets it, not just the host yarn install —
  // closing the bare/mac-bare audit-vs-host asymmetry where the audit honored a
  // PR-controlled YARN_YARN_PATH before the trust gate.  Safe for npm/pnpm: they
  // ignore YARN_* entirely (VERIFIED), so dropping non-allowlisted YARN_* never breaks
  // them.  Case-insensitive (yarn lower-cases the env key before its `yarn_` match).
  if (lower.startsWith('yarn_')) {
    return !YARN_ENV_ALLOW.has(name.toUpperCase());
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
  const lexRoots = checkoutRootsLexical();
  const kept: string[] = [];
  for (const dir of pathVar.split(delimiter)) {
    // Drop empty ('' = cwd) and ANY non-absolute entry: it is resolved against
    // the child's cwd (=repoDir) at exec, which our check can't model, and a
    // `../x` can resolve into the checkout there.  Then drop checkout-under dirs by
    // BOTH the realpath (symlink-IN) and the lexical spelling (symlink-OUT: an entry
    // like `$GITHUB_WORKSPACE/tools -> /usr/bin` is PR-controlled and repointable in
    // trusted host part-2, so the system realpath must not let it survive).
    if (!isAbsolute(dir)) continue;
    if (isUnderCheckout(dir, roots)) continue;
    if (isLexicallyUnderCheckout(dir, lexRoots)) continue;
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

/**
 * Drop-in install cache/store-redirect PARITY (value-blind-lock close — sibling
 * of the pnpm config→env mirror in buildChildEnv).
 *
 * buildChildEnv (src/guest/agent.ts cacheRedirectEnv) injects a manager-specific
 * cache/store redirect into EVERY Phase-B lifecycle child to keep the package
 * manager's cache off the VM's /root tmpfs (ENOSPC on ~1000-package monorepos),
 * e.g. `npm_config_cache=<work_dir>/.npm-cache`.  The host install does not need
 * that redirect (real runner disk) — but if it simply OMITS the var, the trusted
 * host lifecycle child sees a DIFFERENT value (npm's default `~/.npm`) than the
 * audited guest child (`<work_dir>/.npm-cache`).  The lock is value-blind
 * (env-spy records env_read NAMEs only), so a dependency that branches on the
 * value — `process.env.npm_config_cache.endsWith('.npm-cache') ? benign : evil`
 * (or yarn: `process.env.YARN_CACHE_FOLDER ? benign : evil`) — runs benign() in
 * the audit and evil() on the trusted host while the committed lock still
 * matches.  Same class as the `npm_config_ignore_pnpmfile`/`script_shell` mirror.
 *
 * On the install:true FC/docker path the guest work_dir is pinned to the host
 * `repoDir` (M1 cwd alignment, config-override workDirOverride), so mirroring the
 * SAME repoDir-relative paths makes host child == guest child and closes the
 * oracle.  Applied to BOTH host phases so the part-1 fetch and part-2
 * rebuild/install share one cache dir (no double-download) — exactly like the
 * guest's Phase A fetch + Phase B run.  This REPLACES any PR-inherited
 * `npm_config_cache`/`YARN_*_FOLDER` (already stripped by stripDangerousEnv) with
 * a trusted, checkout-relative value, so the PR can never redirect the cache.
 *
 * pnpm's store_dir is already mirrored via the `--store-dir <repoDir>/.pnpm-store`
 * argument (pnpmStoreDirArg), which pnpm 10.x re-exports to the child as
 * `npm_config_store_dir` and 11.x strips on both sides — so pnpm needs nothing here.
 *
 * RESIDUAL (documented, accepted — same bucket as the M1 os.hostname/marker/cwd
 * residuals): on the bare / mac-bare backends the guest work_dir is a STAGED temp
 * path != repoDir, so these values still diverge there.  Firecracker is the
 * enforcement boundary; bare/mac-bare are best-effort/observe-only.
 */
function lifecycleCacheParityEnv(pm: Manager, repoDir: string): Record<string, string> {
  if (pm === 'npm') return { npm_config_cache: `${repoDir}/.npm-cache` };
  if (pm === 'yarn')
    return {
      YARN_GLOBAL_FOLDER: `${repoDir}/.yarn-global`,
      YARN_CACHE_FOLDER: `${repoDir}/.yarn-cache`,
    };
  return {}; // pnpm: store_dir handled by the --store-dir flag (pnpmStoreDirArg)
}

function hostInstallEnv(
  pm: Manager,
  repoDir: string,
  phase: 'fetch' | 'scripts',
  hostTmpdir?: string,
): NodeJS.ProcessEnv {
  // Drop dangerous selectors + sanitize PATH (shared with the bare backend), THEN
  // ALLOWLIST the surviving ambient env down to the guest lifecycle child's name-set
  // + the required auth/proxy pins, THEN layer the security pins on top so a filtered
  // name can never accidentally remove a pin.
  const env = stripDangerousEnv(process.env);
  // Close the value-blind env-read oracle: keep only names the FC/Docker guest
  // lifecycle child also has.  BOTH phases keep the base (PATH/HOME); only the FETCH
  // phase additionally keeps the registry/auth/TLS/proxy surface (part-1 runs no
  // lifecycle script, so no oracle, and it needs that surface to reach a private
  // registry), while the SCRIPT phase drops it so host part-2 == guest Phase B.
  // Everything else ambient (GITHUB_*/RUNNER_*/NODE_ENV/CI/LANG/TMPDIR/arbitrary
  // workflow `env:` + every SCRIPT_JAIL_* host knob) is dropped in both.  A denylist
  // could not — a workflow can set an arbitrary var.  See isHostInstallParityKeepName.
  for (const name of Object.keys(env)) {
    if (!isHostInstallParityKeepName(name, phase)) delete env[name];
  }
  // VALUE-BLIND-LOCK PARITY (round-15): `npm_config_git` defeats a repo `.npmrc
  // git=<pwn>` during git-DEPENDENCY CLONE, which happens ONLY in the FETCH phase
  // (part-1, `--ignore-scripts`).  `npm rebuild` (part-2) never clones, so the pin
  // is irrelevant there — and leaving it in part-2 was a value-blind oracle: the
  // host part-2 lifecycle child saw `npm_config_git=<abs>` while the guest Phase B
  // child (which never pins git) saw it ABSENT, so a dep could branch on the value
  // (env-spy is value-blind) and run the host-only branch after trust.  Scoping it
  // to the fetch phase makes host part-2 == guest Phase B (both ABSENT) → oracle
  // closed; the fetch-phase divergence is harmless (no lifecycle child reads it).
  if (phase === 'fetch') env['npm_config_git'] = trustedGitPath();
  // stripDangerousEnv already dropped EVERY inherited COREPACK_* (the `corepack_`
  // family prefix) and EVERY non-allowlisted YARN_* (the shared YARN_ENV_ALLOW gate),
  // so the parity drops are no longer re-done here — they apply to the backend AGENT
  // spawns too.  All that remains is to layer the POSITIVE pins the host install needs
  // on top of the now-clean env.
  // Corepack must not block on an interactive download prompt (match the audit:
  // docker.ts / init.sh / mac-bare set this) — and stripDangerousEnv just dropped any
  // inherited COREPACK_HOME, which could otherwise force a cache re-download.
  env['COREPACK_ENABLE_DOWNLOAD_PROMPT'] = '0';
  // round-17f (codex [critical]): corepack loads a PROJECT-controlled `.corepack.env`
  // from its cwd (= repoDir) at startup unless COREPACK_ENV_FILE=0.  Its loader merges
  // the file's COREPACK_* keys but spreads `...process.env` LAST, so process.env WINS
  // (verified corepack 0.35.0 corepack.cjs:13556).  stripDangerousEnv just dropped the
  // inherited COREPACK_HOME (corepack_ family) — leaving it UNSET — so without this a
  // repo `.corepack.env` setting `COREPACK_HOME=<checkout>/evil` REPOPULATES it inside
  // corepack and host part-1 (`hostInstallNoScripts`, a bare corepack shim at cwd=repoDir,
  // BEFORE the trust gate) execs a PR-planted `…/v1/<pm>/<ver>/<entry>` (VERIFIED: planted
  // pnpm.cjs ran).  The clean-VM (FC/Docker) guest keeps COREPACK_HOME SET so the file
  // never steers it → host-vs-audit divergence = RCE.  Pinning COREPACK_ENV_FILE=0 makes
  // the host ignore the file entirely (part-1 AND part-2), matching the guest.  It is
  // re-pinned AFTER stripDangerousEnv (which drops the corepack_ family) exactly like the
  // download-prompt flag above.
  env['COREPACK_ENV_FILE'] = '0';
  if (pm === 'npm') {
    // SECURITY (home-npmrc script-shell, #26): `$HOME/.npmrc` is npm's DEFAULT
    // userconfig; a `script-shell=<pwn>` there makes `npm rebuild --foreground-scripts`
    // (host part-2) run lifecycle scripts via that shell.  An ABSOLUTE, outside-checkout
    // runner `$HOME` passes detectCheckoutRelativeHome (which only refuses a HOME *under*
    // the checkout, never inspects the npmrc CONTENTS), yet the clean-VM audit uses a
    // DIFFERENT HOME (/root tmpfs) and never reads it — so the redirect is audit-BLIND
    // and a clean lock would authorize an unaudited host shell.  npm config precedence
    // makes the `npm_config_*` ENV BEAT userconfig (VERIFIED npm 11.13.0:
    // `npm_config_script_shell=/bin/sh` → `npm config get script-shell` = /bin/sh, marker
    // NOT written), exactly as the `npm_config_git` pin defeats a repo `.npmrc git=`.  The
    // clean-VM audit runs `npm rebuild` with the default /bin/sh, so this is PARITY-CORRECT.
    // Accepted collateral (mirrors the npm_config_git pin): it also overrides a benign
    // AUDITED `.npmrc script-shell=/bin/bash` — house-style, non-security; the fixed system
    // shell is strictly safer.  npm-scoped (pnpm uses the host part-2 --config.script-shell
    // flag; yarn berry has no script-shell config).
    env['npm_config_script_shell'] = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';
    // SECURITY (Codex review thread [53]): `$HOME/.npmrc` `ignore-scripts=true` is
    // npm's DEFAULT userconfig; with it set, host part-2 `npm rebuild
    // --foreground-scripts` SKIPS dependency lifecycle scripts (VERIFIED npm
    // 11.13.0: marker NOT written), while the clean-VM audit (HOME=/root, no such
    // npmrc) RAN them — so the host leaves audited-safe deps unbuilt, breaking the
    // "host reproduces the audited tree" invariant. An absolute outside-checkout
    // HOME passes detectCheckoutRelativeHome (which never inspects npmrc CONTENTS).
    // The `npm_config_*` ENV beats userconfig (VERIFIED: env false overrides
    // ignore-scripts=true), exactly like the script_shell pin above, so this is
    // parity-correct. npm re-exports `npm_config_ignore_scripts` to the lifecycle
    // child, so it is mirrored in the guest install-mode env (agent.ts) in lockstep
    // to keep the value-blind env_read identical on both sides. npm-scoped (pnpm's
    // rebuild governs its own scripts; yarn has no equivalent userconfig key).
    env['npm_config_ignore_scripts'] = 'false';
  }
  if (pm === 'yarn') {
    // Positive yarn pins (install-child specific).  The negative YARN_* sweep now
    // lives in stripDangerousEnv (the shared gate), so here we only SET the pins on
    // top of the already-swept env.  YARN_ENABLE_SCRIPTS is intentionally NOT re-set:
    // the sweep dropped any inherited value (not in the allowlist), so the rc governs
    // host part-2 IDENTICALLY to the audit — rc-true still builds, rc-false still skips.
    env['YARN_IGNORE_PATH'] = '1';
    env['YARN_RC_FILENAME'] = '.yarnrc.yml';
    env['YARN_PLUGINS'] = '';
    env['YARN_ENABLE_CONSTRAINTS_CHECKS'] = 'false';
  }
  // Drop-in install cache/store-redirect parity (value-blind-lock close): set the
  // SAME repoDir-relative cache the guest injects, REPLACING any PR-inherited
  // (already-stripped) value with a trusted one.  See lifecycleCacheParityEnv.
  Object.assign(env, lifecycleCacheParityEnv(pm, repoDir));
  // TMPDIR-presence parity with the AUDITING backend (value-blind env-read oracle).
  // The caller passes `hostTmpdir` ONLY when the audit ran on a backend whose guest
  // lifecycle child HAS TMPDIR (Firecracker exports /sjtmp); it passes undefined for
  // Docker (guest has none → the allowlist already dropped it).  The value is a TRUSTED
  // absolute outside-checkout temp from `trustedHostTmpdir()` (a fixed /tmp, NOT the
  // ambient-honoring os.tmpdir() — see that helper / codex round-4 [high]).  Setting the
  // NAME here makes a lifecycle script's `process.env.TMPDIR` read take the same
  // present/absent branch on host part-2 as it did in the audit.  The VALUE differs from
  // the VM's /sjtmp (a dedicated disk that does not exist on the host) — an accepted
  // residual visible only to a script branching on TMPDIR's value, same class as the
  // cwd/cache-path residuals.
  if (hostTmpdir !== undefined) env['TMPDIR'] = hostTmpdir;
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
  // TMPDIR-presence parity with the auditing backend (see hostInstallEnv): a real
  // host temp when Firecracker audited (guest has TMPDIR=/sjtmp), undefined for
  // Docker (guest has none → dropped).  Threaded from main.ts's auditBackend.
  hostTmpdir?: string,
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
  runOrThrow(base.cmd, finalArgs, repoDir, hostInstallEnv(pm, repoDir, 'fetch', hostTmpdir), spawn, 'no-scripts install', io, safeDisplayArgs, onOutput);
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

// ---------------------------------------------------------------------------
// SECURITY: host part-2 direct-launch (close the COREPACK_ROOT value-blind oracle)
// ---------------------------------------------------------------------------
//
// THREAT.  With `install: true` the action runs dependency lifecycle scripts on
// the trusted host (part-2, `hostRunScripts`).  The GUEST audit (commit 81a0747 /
// resolveLinuxManagerLaunch) resolves the PM's offline-cached JS entry and runs
// `node <entry>` DIRECTLY, BYPASSING the corepack shim — so the guest lifecycle
// child has NO `process.env.COREPACK_ROOT`.  If host part-2 spawned the PM by BARE
// name and that bare `pnpm`/`yarn` (or a `corepack enable npm` `npm`) is a corepack
// shim, corepack sets `COREPACK_ROOT` UNCONDITIONALLY in the lifecycle child before
// launching the managed bin.  env-spy is value-BLIND (it records env_read NAMES
// only), so a dep that does `if (process.env.COREPACK_ROOT) evil(); else benign();`
// is benign in the audit (clean lock) and evil on the host = post-trust RCE.
//
// FIX.  Make host part-2 ALSO direct-launch (`node <cached-entry>`), exactly like
// the guest, so `COREPACK_ROOT` is ABSENT on BOTH sides.  `COREPACK_HOME`/
// `COREPACK_ROOT` were already dropped from the child ENV by stripDangerousEnv (the
// `corepack_` family), but corepack RE-SETS `COREPACK_ROOT` inside its OWN process
// AFTER hostInstallEnv is built — so env-stripping alone cannot close it; not going
// through corepack (direct-launch) is the only lever.
//
// This is HOST-ONLY: it changes nothing the guest/lock sees (the audited argv stays
// `finalArgs`; we only change the *launcher* from `<pm>` to `node <entry>`), so it
// has ZERO lockfile/golden impact and dist/guest-agent.cjs is byte-unchanged.
//
// The per-version entry-read mechanics below DUPLICATE the guest's
// resolveLinuxManagerLaunch (src/guest/phase-install.ts) deliberately — the host
// resolver is self-contained (it reads the ACTION's corepack cache, not the guest's
// COREPACK_HOME) and the duplication keeps the two paths decoupled.

/** A direct-launch decision: spawn `node entry ...finalArgs` instead of bare PM. */
export interface HostManagerLaunch {
  node: string;
  entry: string;
}

/**
 * Mirror corepack's `getCorepackHomeFolder`: the executable cache root corepack
 * reads/writes managed PM tarballs under.  `COREPACK_HOME` wins; otherwise corepack
 * branches by PLATFORM — `<LOCALAPPDATA | <home>/AppData/Local>/node/corepack` on
 * win32, `<XDG_CACHE_HOME | <home>/.cache>/node/corepack` elsewhere.  The selectors
 * do NOT cross platforms: LOCALAPPDATA is consulted ONLY on win32, XDG_CACHE_HOME
 * ONLY on non-win32 (verified against corepack 0.35.0 `folderUtils.ts`).
 *
 * Fix-1 NOTE: `procEnv` here is the SAME env the lifecycle child runs under
 * (`hostInstallEnv(...,'scripts')`), which `stripDangerousEnv` has already cleared
 * of `COREPACK_HOME` / `XDG_CACHE_HOME` (the corepack_/xdg_ families) AND of the
 * win32 cache selector `LOCALAPPDATA`.  So with the child env this resolves to the
 * DEFAULT `<home>/.cache/node/corepack` — exactly where part-1
 * (`hostInstallNoScripts`, also run under `hostInstallEnv`, also stripped) warmed
 * the cache.  Reading the RAW `process.env` here would honour an inherited
 * `COREPACK_HOME`/`XDG_CACHE_HOME` that part-1's corepack never used, voiding the
 * cache backstop AND failing a legit corepack consumer closed.
 *
 * round-17e (codex [high]): the earlier `XDG_CACHE_HOME ?? LOCALAPPDATA ?? fallback`
 * MIXED the two platform selectors, so a non-win32 host (the action only runs on
 * Linux/macOS runners — darwin-x64 is out of scope, win32 is never a host) honoured
 * an inherited `LOCALAPPDATA`.  That re-opened the COREPACK_HOME executable-cache
 * selector class for a DIFFERENT name: a PR/runner-set `LOCALAPPDATA` pointing at a
 * checkout-controlled cache made host part-2 direct-launch a planted
 * `…/v1/<pm>/<ver>/<entry>`, AND diverged from where part-1's corepack (which uses
 * the non-win32 path) actually warmed the cache.  Branching by platform mirrors
 * corepack and ignores LOCALAPPDATA on the real (non-win32) host; the
 * `stripDangerousEnv` LOCALAPPDATA drop is the defense-in-depth second layer.
 */
function corepackCacheRoot(procEnv: NodeJS.ProcessEnv): string {
  const home = procEnv['COREPACK_HOME'];
  if (home !== undefined && home.length > 0) return home;
  // Mirror corepack's getCorepackHomeFolder per-platform: win32 uses LOCALAPPDATA
  // (fallback `<home>/AppData/Local`), every other platform uses XDG_CACHE_HOME
  // (fallback `<home>/.cache`).  The selectors NEVER cross platforms — consulting
  // LOCALAPPDATA on a non-win32 host (the only host kind) was the round-17e hole.
  const base =
    process.platform === 'win32'
      ? (procEnv['LOCALAPPDATA'] ?? join(homedir(), 'AppData', 'Local'))
      : (procEnv['XDG_CACHE_HOME'] ?? join(homedir(), '.cache'));
  return join(base, 'node', 'corepack');
}

/**
 * Read the relative entry path for a corepack-managed pnpm from the per-version
 * `.corepack` JSON (`bin.pnpm`, e.g. `./bin/pnpm.cjs` on 10.x / `./pnpm.mjs` on
 * 11.x), falling back to the cached `package.json` `bin.pnpm`.  ALWAYS read (never
 * hard-code .cjs vs .mjs — it varies per tarball).  Returns null on every miss so
 * the caller fails closed.  DUPLICATES guest readManagerBinRel (intentional).
 */
function readHostPnpmBinRel(verDir: string): string | null {
  for (const file of ['.corepack', 'package.json']) {
    try {
      const meta = JSON.parse(readFileSync(join(verDir, file), 'utf8')) as {
        bin?: Record<string, string> | string[];
      };
      const bin = meta.bin;
      if (bin !== undefined && !Array.isArray(bin)) {
        const rel = bin['pnpm'];
        if (typeof rel === 'string' && rel.length > 0) return rel;
      }
    } catch {
      // unreadable / malformed — try the next source
    }
  }
  return null;
}

/**
 * True when the resolved on-disk binary at `binPath` is a corepack SHIM.  The
 * EMPIRICALLY-VERIFIED signature is the literal `corepack.cjs` require target:
 * EVERY corepack shim (npm/pnpm/yarn) across corepack 0.24.1 / 0.30.0 / 0.31.0 /
 * 0.35.0 is `require('./lib/corepack.cjs').runMain([...])` — the `corepack.cjs`
 * substring is reliably present.  A standalone `pnpm` (`pnpm/bin/pnpm.cjs`) and
 * node-bundled `npm` contain ZERO `corepack.cjs` / `corepack` / `runMain` mentions
 * (verified: `npm pack pnpm@10` bin has 0 hits for all three) and set no
 * COREPACK_ROOT.  We match `corepack.cjs` ONLY — the bare `corepack` substring and
 * the broad `runMain` were over-broad (a standalone PM whose bytes happen to
 * contain either would be misclassified → fail-closed refusal of a legit
 * consumer).  This shim check is DEFENSE-IN-DEPTH: in the normal install:true flow
 * `cacheHasAnyVersion` is the PRIMARY corepack signal (part-1 warms the cache for
 * the same PM), so tightening here is low-risk for false-negatives.  Any read
 * error → treat as a shim (fail-safe: caller then resolves the cached entry / fails
 * closed).
 */
function isCorepackShim(binPath: string | undefined): boolean {
  if (binPath === undefined || binPath.length === 0) return false;
  try {
    const real = realpathSync(binPath);
    const content = readFileSync(real, 'utf8');
    return content.includes('corepack.cjs');
  } catch {
    // an unreadable resolved bin is suspicious → fail-safe to "managed"
    return true;
  }
}

/**
 * Resolve the first executable named `pm` on `pathVar`, following the lexical PATH
 * order.  Returns the absolute candidate (NOT realpath'd — `isCorepackShim`
 * realpaths it).  `undefined` when none found.
 */
function resolveBareOnPath(pm: string, pathVar: string | undefined): string | undefined {
  if (pathVar === undefined || pathVar === '') return undefined;
  const names = process.platform === 'win32' ? [`${pm}.cmd`, `${pm}.exe`, pm] : [pm];
  for (const dir of pathVar.split(delimiter)) {
    if (dir === '') continue;
    for (const name of names) {
      const candidate = join(dir, name);
      if (!isAbsolute(candidate)) continue;
      // MODEL execvp #1 — only a regular FILE is exec'd.  A directory (or symlink to
      // one) named `pnpm` passes both existence and access(X_OK) as a *searchable*
      // dir, but execvp does NOT exec it: it fails (EACCES/EISDIR) and keeps scanning
      // PATH.  We must skip it too — else a `<dir>/pnpm` before the real binary is
      // returned, `isCorepackShim` readFileSync's it → EISDIR → fail-safe "managed",
      // and a confirmed-standalone install is wrongly hijacked/refused while spawn
      // actually runs the LATER standalone (codex round-17d).  statSync follows
      // symlinks, so a symlink-to-file is kept and a symlink-to-dir is skipped; a
      // missing/broken candidate throws → skip.
      let st;
      try {
        st = statSync(candidate);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      // MODEL execvp #2 — the OS skips a non-EXECUTABLE PATH hit and keeps scanning,
      // so we must too: a readable but non-executable `pnpm` (mode 0644) earlier on
      // PATH would otherwise be classified "confirmed standalone" while spawn actually
      // execs a LATER executable corepack shim, re-opening the COREPACK_ROOT oracle
      // (codex round-17c).  access(X_OK) is exactly the check execvp uses; on win32
      // (Linux-gated host) it degrades to existence, which the `.cmd/.exe` name list
      // already covers.
      try {
        accessSync(candidate, fsConstants.X_OK);
      } catch {
        continue;
      }
      return candidate;
    }
  }
  return undefined;
}

/** True when `<cacheRoot>/v1/<pm>/` has at least one version subdir. */
function cacheHasAnyVersion(cacheRoot: string, pm: Manager): boolean {
  try {
    return readdirSync(join(cacheRoot, 'v1', pm), { withFileTypes: true }).some((d) =>
      d.isDirectory(),
    );
  } catch {
    return false;
  }
}

/** Read the `packageManager` pin from `<repoDir>/package.json`, stripping the
 *  `+<hash>` integrity suffix.  Returns `{ name, version }` or undefined. */
function readPackageManagerPin(repoDir: string): { name: string; version: string } | undefined {
  try {
    const pkg = JSON.parse(readFileSync(join(repoDir, 'package.json'), 'utf8')) as {
      packageManager?: unknown;
    };
    const pm = pkg.packageManager;
    if (typeof pm !== 'string' || pm.length === 0) return undefined;
    const at = pm.lastIndexOf('@');
    if (at <= 0) return undefined;
    const name = pm.slice(0, at);
    let version = pm.slice(at + 1);
    const plus = version.indexOf('+');
    if (plus !== -1) version = version.slice(0, plus);
    if (version.length === 0) return undefined;
    return { name, version };
  } catch {
    return undefined;
  }
}

/**
 * Resolve how host part-2 should LAUNCH the package manager, mirroring the guest's
 * direct-launch so `COREPACK_ROOT` is ABSENT on both sides (close the value-blind
 * oracle — see the section header above).
 *
 *   * Returns `{ node, entry }` → spawn `node entry ...finalArgs` (bypass corepack).
 *   * Returns `undefined`       → bare-launch is SAFE (standalone PM sets no
 *                                 COREPACK_ROOT); preserve standalone consumers.
 *
 * Decision tree:
 *   npm  — ALWAYS resolve node-bundled `npm-cli.js` from the toolchain root of
 *          `execPath` (matches the guest, and ignores a `corepack enable npm` shim by
 *          using node-bundled npm directly).  Exists → direct-launch.  ABSENT →
 *          THROW (fail closed), mirroring the guest (resolveLinuxManagerLaunch also
 *          throws): a bare `npm` on a `corepack enable npm` runner is a corepack shim
 *          that sets COREPACK_ROOT (re-opening the oracle), and a node lacking
 *          bundled npm cannot run `npm rebuild` anyway, so the guest audit would fail
 *          identically → parity-correct to refuse here too.
 *   pnpm/yarn — inspect the bare PM the child would exec (first match on the SAME
 *          sanitized PATH).  A corepack shim (or unreadable/suspicious bin) → MANAGED;
 *          a readable NON-shim binary → CONFIRMED standalone → `undefined` (bare-launch;
 *          e.g. pnpm/action-setup) even if a STALE corepack cache exists (it sets no
 *          COREPACK_ROOT, so there is nothing to override); NO bin on PATH → fall back
 *          to "cache holds a version" as the only managed signal.  Any read error →
 *          managed, fail-safe.  MANAGED → resolve the cached entry from the action's
 *          corepack cache, preferring the repo `packageManager` pin; ANY miss (pinned
 *          dir absent, ambiguous version, unreadable entry) → THROW.  A silent
 *          bare-launch of a corepack-managed-but-unresolvable PM would re-open the
 *          oracle, so fail closed loudly.
 */
export function resolveHostManagerLaunch(
  pm: Manager,
  repoDir: string,
  procEnv: NodeJS.ProcessEnv = process.env,
  execPath: string = process.execPath,
): HostManagerLaunch | undefined {
  if (pm === 'npm') {
    // npm is node-bundled (NOT corepack-managed): resolve from the toolchain root
    // the action runs under — `execPath` is `.../node/<ver>/bin/node`, so the
    // toolchain root is `dirname(dirname(execPath))`.  This deliberately ignores any
    // `corepack enable npm` shim (which WOULD set COREPACK_ROOT) by launching
    // node-bundled npm directly, matching the guest.
    const toolchainRoot = dirname(dirname(execPath));
    const entry = join(toolchainRoot, 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
    // FAIL CLOSED when node-bundled npm-cli.js is absent (mirrors the guest's
    // resolveLinuxManagerLaunch, which throws): a bare `npm` on a `corepack enable
    // npm` runner is a corepack shim that sets COREPACK_ROOT, re-opening the
    // value-blind oracle.  A node lacking bundled npm cannot run `npm rebuild`
    // anyway, and the guest audit already throws on the same layout, so refusing
    // here is parity-correct (never silently bare-launch npm).
    if (!existsSync(entry)) {
      throw new Error(
        `script-jail: host lifecycle install refuses to bare-launch npm ` +
          `(value-blind COREPACK_ROOT oracle): node-bundled npm-cli.js not found at ${entry}. ` +
          `A bare \`npm\` may be a \`corepack enable npm\` shim that sets COREPACK_ROOT; the ` +
          `clean-VM audit also fails on a node without bundled npm, so this fails closed to match.`,
      );
    }
    return { node: execPath, entry };
  }

  // pnpm / yarn.  Decide whether going through the bare name would route the
  // lifecycle child through corepack (which sets COREPACK_ROOT).  The bare PM the
  // child would actually exec is the FIRST match on the SAME sanitized PATH the
  // child runs under (procEnv is the child env) — so inspect EXACTLY that binary:
  //   * a corepack shim (corepack.cjs) → MANAGED (resolve the cached entry below).
  //   * an unreadable / suspicious bin → isCorepackShim fail-safes to true → MANAGED.
  //   * a readable, NON-shim binary → CONFIRMED standalone PM: it sets no
  //     COREPACK_ROOT, so bare-launch is safe REGARDLESS of any pre-existing corepack
  //     cache.  A stale `~/.cache/node/corepack` entry from an unrelated prior job
  //     must NOT hijack (no-pin) or fail-closed-break (pinned) a proven standalone
  //     install — there is no COREPACK_ROOT risk to justify overriding it (codex
  //     round-17 [medium]).
  //   * NO bare PM on PATH → the child's bare-launch would ENOENT (as part-1's,
  //     which also runs under this PATH, already would have); the corepack cache is
  //     then the only "managed" signal we have, so fall back to it.
  // Any detection read-error → managed (fail-safe; never bare-launch on uncertainty).
  let corepackManaged: boolean;
  try {
    const bareBin = resolveBareOnPath(pm, procEnv['PATH']);
    corepackManaged =
      bareBin !== undefined
        ? isCorepackShim(bareBin)
        : cacheHasAnyVersion(corepackCacheRoot(procEnv), pm);
  } catch {
    corepackManaged = true;
  }
  if (!corepackManaged) {
    // Standalone PM (e.g. pnpm installed via pnpm/action-setup): bare-launch is
    // safe — it sets no COREPACK_ROOT, so the guest (no COREPACK_ROOT) and the host
    // already match.  Preserve standalone consumers.
    return undefined;
  }

  // Corepack-managed → resolve the cached entry.  FAIL CLOSED on every miss: a
  // bare-launch here would re-open the oracle.
  const cacheRoot = corepackCacheRoot(procEnv);
  const pmDir = join(cacheRoot, 'v1', pm);
  const pin = readPackageManagerPin(repoDir);
  const failClosed = (detail: string): never => {
    throw new Error(
      `script-jail: host lifecycle install refuses to bare-launch the corepack-managed ${pm} ` +
        `(value-blind COREPACK_ROOT oracle): ${detail}. ` +
        `Expected the corepack-cached ${pm}${pin && pin.name === pm ? ` ${pin.version}` : ''} ` +
        `under ${pmDir}. Run the action's part-1 install (which warms the corepack cache) first, ` +
        `or pin "packageManager" in package.json so the version can be resolved.`,
    );
  };

  let verDir: string;
  if (pin !== undefined && pin.name === pm) {
    // A pin exists: prefer its version dir.  If the pin's dir is ABSENT, fail
    // closed (do NOT bare-launch / do NOT guess another version).
    const pinnedDir = join(pmDir, pin.version);
    if (!existsSync(pinnedDir)) {
      failClosed(`the pinned version dir ${pinnedDir} is absent`);
    }
    verDir = pinnedDir;
  } else {
    // No usable pin: accept the cache ONLY when it holds exactly one version dir
    // (Phase A / part-1 provisions exactly one).  Zero or >1 → ambiguous → throw.
    let versionDirs: string[];
    try {
      versionDirs = readdirSync(pmDir, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name);
    } catch (err) {
      return failClosed(`cannot read the corepack cache dir ${pmDir}: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (versionDirs.length !== 1) {
      // Fix-5 decision: NO lastKnownGood.json disambiguation.  Empirically (corepack
      // 0.35.0) the no-pin flow does NOT write `<cacheRoot>/lastKnownGood.json` —
      // it is only written by `corepack use`/`corepack install --activate` or an
      // in-major upgrade when a prior entry already exists, and it records a GLOBAL
      // default, not the version part-1 resolved for THIS repo.  Relying on it would
      // be a version-fragile false-negative oracle, so we KEEP exactly-one-dir and
      // fail closed (SAFE — never bare-launches).  On a dirty multi-version (reused/
      // self-hosted) runner with no `packageManager` pin this fails closed; the fix
      // is to pin "packageManager" so the version is unambiguous (see divergence.md).
      return failClosed(
        `expected exactly one ${pm} version dir, found ${versionDirs.length}` +
          `${versionDirs.length > 0 ? ` (${versionDirs.join(', ')})` : ''}; ` +
          `with no "packageManager" pin the version is ambiguous on a multi-version corepack cache — ` +
          `pin "packageManager" in package.json to disambiguate`,
      );
    }
    verDir = join(pmDir, versionDirs[0] as string);
  }

  if (pm === 'yarn') {
    // yarn berry's cache is a single bundled `yarn.js` at the version-dir root (its
    // `.corepack` `bin` is an ARRAY of names, giving no path).
    const entry = join(verDir, 'yarn.js');
    if (!existsSync(entry)) failClosed(`yarn.js not found at ${entry}`);
    return { node: execPath, entry };
  }

  // pnpm: the entry path (10.x `./bin/pnpm.cjs`, 11.x `./pnpm.mjs`) comes from the
  // per-version `.corepack` metadata (package.json `bin` as fallback) — never
  // hard-coded.
  const rel = readHostPnpmBinRel(verDir);
  if (rel === null) {
    failClosed(`could not read the pnpm entry path from ${join(verDir, '.corepack')} or package.json bin`);
  }
  const entry = resolve(verDir, rel as string);
  if (!existsSync(entry)) failClosed(`pnpm entry not found at ${entry}`);
  return { node: execPath, entry };
}

/** Injectable resolver seam (tests pass a fake), mirroring the HostStreamSpawn seam. */
export type HostManagerLaunchResolver = (
  pm: Manager,
  repoDir: string,
  procEnv: NodeJS.ProcessEnv,
) => HostManagerLaunch | undefined;

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
  args: ReadonlyArray<string>,
  io: HostInstallIo,
  protectedEnvNames: readonly string[] = [],
  spawn: HostStreamSpawn = streamSpawn,
  resolveLaunch: HostManagerLaunchResolver = resolveHostManagerLaunch,
  // TMPDIR-presence parity with the auditing backend (see hostInstallEnv): a real
  // host temp when Firecracker audited, undefined for Docker.  From main.ts.
  hostTmpdir?: string,
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
  // SECURITY (home-npmrc script-shell, #26 pnpm sibling): pnpm reads `script-shell`
  // from `~/.npmrc` (npm-compatible config source) on pnpm <= 10 (VERIFIED pnpm 10.34.3:
  // a runner `$HOME/.npmrc script-shell=<pwn>` runs the attacker shell on a pnpm install
  // that fires a lifecycle script).  The clean-VM audit uses a different HOME (/root), so
  // the redirect is audit-BLIND — the same class as the npm `npm_config_script_shell` pin.
  // pnpm does NOT honor its own `pnpm_config_*` env form for this key, but the CLI
  // `--config.script-shell` flag DOES win over the rc on every tested version (VERIFIED
  // 10.34.3 + 11.1.2: defeats the `~/.npmrc` redirect, build still runs; bare
  // `--script-shell` is REJECTED "Unknown option").  HOST-ONLY + host-command-local (same
  // posture as `--config.ignore-pnpmfile`): the guest Phase B is unaffected, and the audit
  // already runs with the default /bin/sh + /root HOME, so this is parity-correct.  (The
  // repo-pinned pnpm 11.1.2 ignores the rc key entirely and `pnpm rebuild` never honored it
  // even on pnpm 10 — this is defense-in-depth for a consumer pinning pnpm <= 10.)
  // NOTE (#43 home/project-npmrc node-options): the npm-side neutralizer
  // `--no-node-options` is NOT here — it lives in the SHARED `INSTALL_CMD.npm`
  // (src/shared/pm-commands.ts) so the host part-2 and the guest Phase B carry it
  // byte-identically.  A host-ONLY flag would change `npm_config_node_options`
  // for lifecycle scripts on the host but not the audit, re-opening a value-blind
  // oracle (env-spy records the env NAME only) — see the INSTALL_CMD comment.
  // Only the genuinely host-vs-audit-ASYMMETRIC pnpm pins stay command-local here
  // (the guest MUST keep the pnpmfile/script-shell so it AUDITS them).
  const hostHardening =
    pm === 'pnpm' ? ['--config.ignore-pnpmfile=true', '--config.script-shell=/bin/sh'] : [];
  // #19 FIDELITY (npm-only): re-pass the developer dep-selection args to part-2
  // so a lifecycle script run by `npm rebuild` sees the SAME NODE_ENV/omit env it
  // would under the single-phase `npm ci --omit=dev` this two-phase model
  // replaces (part-1 already splices them at hostInstallNoScripts).  `npm rebuild`
  // accepts the allowlisted flags (--omit/--include/--prod/-D/-P/--registry);
  // `pnpm rebuild --pending`/`yarn install` REJECT --omit/--prod and carry
  // dep-group state in the resolved tree, so they get nothing.  Same
  // `sanitizeInstallArgs` as part-1 → identical `kept`, in LOCKSTEP with the guest
  // Phase B (src/guest/phase-install.ts runInstallPhase) so the host argv equals
  // the audited argv.  Empty `kept` (the no-args default) splices nothing.
  const { kept } = sanitizeInstallArgs(args);
  const userArgs = pm === 'npm' ? kept : [];
  // Same store-dir pin as part 1 / the guest install phase: pnpm must relink
  // against the repo-local store, not the runner default (parity).  Order mirrors
  // part-1 / the guest: <base> <user args> <store-dir> <host hardening>.
  const finalArgs = [...cmd.args, ...userArgs, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  // SECURITY: never echo raw user tokens (a kept `--registry` is credential-free
  // per sanitizeInstallArgs, but stay consistent with part-1's safe display and
  // fail safe).  Banner + error messages use the user-token-free args + a
  // count-only suffix.
  const safeFinalArgs = [...cmd.args, ...pnpmStoreDirArg(pm, repoDir), ...hostHardening];
  const userArgSuffix =
    userArgs.length > 0
      ? ` (+${userArgs.length} user install arg${userArgs.length === 1 ? '' : 's'}, not shown)`
      : '';
  // Fix-1: compute the child env ONCE and feed it to BOTH the launch resolver AND
  // the spawn, so detection inspects EXACTLY the env (PATH + corepack cache root)
  // the lifecycle child runs under.  Two divergences this closes:
  //   * RAW-vs-SANITIZED PATH — `hostInstallEnv` sanitizes PATH (drops every
  //     checkout-controlled dir).  If the resolver read the RAW `process.env.PATH`,
  //     a checkout-shadow standalone PM could flip a real system corepack shim to
  //     "standalone" → bare-launch → the child then execs the (sanitized-PATH) shim
  //     and COREPACK_ROOT re-opens.  Passing the child env makes
  //     `resolveBareOnPath`/`isCorepackShim` inspect the same binary the child runs.
  //   * RAW-vs-STRIPPED corepack cache root — `stripDangerousEnv` drops
  //     COREPACK_HOME/XDG_CACHE_HOME, so part-1 (also run under `hostInstallEnv`)
  //     warmed the DEFAULT `~/.cache/node/corepack`.  Reading raw `process.env` here
  //     would point `corepackCacheRoot` at an inherited dir part-1 never used,
  //     voiding the cache backstop AND failing a legit corepack consumer closed.
  const childEnv = hostInstallEnv(pm, repoDir, 'scripts', hostTmpdir);
  // SECURITY (COREPACK_ROOT value-blind oracle): resolve HOW to launch the PM.
  // `undefined` → bare-launch is safe (standalone PM sets no COREPACK_ROOT); a
  // `{node,entry}` → direct-launch `node <entry> ...finalArgs`, BYPASSING corepack
  // so the lifecycle child has no COREPACK_ROOT — matching the guest Phase B
  // (resolveLinuxManagerLaunch).  Only the LAUNCHER changes; the audited argv
  // (`finalArgs`) is in LOCKSTEP with the guest (zero lockfile impact).  A
  // corepack-managed-but-unresolvable PM THROWS here (fail closed) rather than
  // silently bare-launching and re-opening the oracle.
  const launch = resolveLaunch(pm, repoDir, childEnv);
  const spawnCmd = launch ? launch.node : cmd.cmd;
  const spawnArgs = launch ? [launch.entry, ...finalArgs] : finalArgs;
  io.stdout.write(
    `[script-jail] host lifecycle scripts (audit matched): ${cmd.cmd} ${safeFinalArgs.join(' ')}${userArgSuffix}\n`,
  );
  // Keep the banner/error messages on the LOGICAL pm (cmd.cmd + safe args), never
  // the node/entry absolute path (noise + leaks an internal path).  Just note the
  // direct-launch so the log explains why corepack is absent.
  if (launch !== undefined) {
    io.stdout.write('[script-jail] (launched directly via node to bypass corepack)\n');
  }
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
  // #19: the npm user args we now splice into part-2 can be echoed back by npm
  // (e.g. `npm warn ... registry="…"`).  Mask their literal values too — same
  // derivation + label as the part-1 capture path (default minLen >= 4, so a
  // short benign value like `dev` from `--omit=dev` is not blanked; the whole
  // token is).  [] for pnpm/yarn and for no-args installs → identity.
  const userArgValues = deriveSensitiveValues(userArgs);
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
    safe = maskExactValues(safe, userArgValues, 'REDACTED:USER-ARG');
    safe = redactCredentialShapes(safe);
    (stream === 'stdout' ? io.stdout : io.stderr).write(`${safe}\n`);
  };
  const r = await spawn(spawnCmd, spawnArgs, repoDir, childEnv, onLine);
  // safeFinalArgs omits the user tokens (count-only suffix), so it is safe to
  // show in errors even though finalArgs now carries the npm user args (#19).
  const safeErrArgs = `${safeFinalArgs.join(' ')}${userArgSuffix}`;
  if (r.error !== undefined) {
    throw new Error(`script-jail: host lifecycle-script run could not spawn "${cmd.cmd}": ${r.error.message}`);
  }
  if (r.signal != null) {
    throw new Error(`script-jail: host lifecycle-script run (\`${cmd.cmd} ${safeErrArgs}\`) was killed by ${r.signal}`);
  }
  if (r.status !== 0) {
    throw new Error(
      `script-jail: host lifecycle-script run (\`${cmd.cmd} ${safeErrArgs}\`) exited with code ${r.status ?? 'null'}`,
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

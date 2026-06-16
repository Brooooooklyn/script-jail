// script-jail — src/shared/pm-commands.ts
//
// SINGLE SOURCE OF TRUTH for the per-package-manager install command shapes.
//
// The same two commands are needed in four places that must NEVER drift:
//   * the guest Phase A fetch        (src/guest/phase-fetch.ts)
//   * the guest Phase B install      (src/guest/phase-install.ts)
//   * the macOS guest Phase B        (src/guest/phase-install-macos.ts)
//   * the host drop-in install       (src/action/host-install.ts)
//
// FETCH_CMD = "install WITHOUT lifecycle scripts" (Phase A / host part-1):
//   downloads + links the lockfile-pinned tree with every lifecycle script
//   suppressed, so the scripts can be audited separately.
//
// INSTALL_CMD = "run the deferred lifecycle scripts" (Phase B / host part-2):
//   runs against the already-resolved tree FETCH_CMD produced.
//
// Keeping host part-1/part-2 byte-identical to the guest phases is what makes
// the host's node_modules "the thing the sandbox audited": both resolve the
// SAME lockfile-pinned graph with scripts off, then run the SAME deferred
// builds. The rationale for each individual flag lives in the guest phase
// files (phase-fetch.ts / phase-install.ts headers) — do not duplicate it here.

export type Manager = 'npm' | 'pnpm' | 'yarn';

export interface PmCommand {
  cmd: string;
  args: string[];
}

/** Phase A / host part-1: install with lifecycle scripts DISABLED. */
export const FETCH_CMD: Record<Manager, PmCommand> = {
  npm: { cmd: 'npm', args: ['ci', '--ignore-scripts'] },
  pnpm: {
    cmd: 'pnpm',
    args: ['install', '--frozen-lockfile', '--ignore-scripts', '--config.side-effects-cache=false'],
  },
  yarn: { cmd: 'yarn', args: ['install', '--immutable', '--mode=skip-build'] },
};

/** Phase B / host part-2: run the lifecycle scripts FETCH_CMD deferred. */
export const INSTALL_CMD: Record<Manager, PmCommand> = {
  npm: { cmd: 'npm', args: ['rebuild', '--foreground-scripts'] },
  pnpm: { cmd: 'pnpm', args: ['rebuild', '--pending', '--config.side-effects-cache=false'] },
  // No `--offline`: that is a Yarn Classic flag; Berry rejects it (Usage Error,
  // exit 1, zero events). Offline is enforced by the Phase-B network-namespace
  // sever; the cache Phase A populated makes this a zero-network relink+build.
  yarn: { cmd: 'yarn', args: ['install', '--immutable'] },
};

/**
 * pnpm only: force the content-addressed store onto the repo-local tree.
 *
 * The guest pins `--store-dir=<cwd>/.pnpm-store` so the store shares the repo
 * overlay disk (where node_modules lives, so hardlinks work) instead of the
 * small rootfs ext4 that the default `~/.local/share/pnpm/store` would overrun.
 * The HOST drop-in install must append the SAME flag (rooted at the host repo
 * dir) or the host and the audited sandbox resolve/link against DIFFERENT
 * stores — diverging the dependency layout the PR documents as identical.
 * `--store-dir` is a global pnpm flag and wins over .npmrc / env in pnpm's
 * config precedence chain.
 *
 * Returns the flag for pnpm, `[]` for npm / yarn (self-guarding so call sites
 * can append it unconditionally).  This single source is what keeps the guest
 * phases (phase-fetch / phase-install) and the host install (host-install.ts)
 * byte-identical.
 *
 * @param pm   the detected package manager.
 * @param cwd  the install root: sandbox `input.cwd`, host `repoDir`.
 */
export function pnpmStoreDirArg(pm: Manager, cwd: string): string[] {
  return pm === 'pnpm' ? [`--store-dir=${cwd}/.pnpm-store`] : [];
}

/** A bare boolean-style flag (no `=value`) that may consume the next token. */
function isBareFlag(token: string): boolean {
  return !token.includes('=');
}

/**
 * Reduce a CLI token to the canonical option key it would resolve to, or null
 * if it is not an option flag at all.  Mirrors how npm/nopt (and pnpm) accept
 * the same option under many surface spellings:
 *   * 1+ leading dashes (`--ignore-scripts`, `-ignore-scripts`, `---…`)
 *   * a joined value (`…=false`) — only the option name matters
 *   * a leading `no-` negation and a pnpm `config.` alias prefix
 *   * kebab / snake / camel / concatenated separators
 * The result is lowercased and separator-stripped, e.g. `--config.Ignore_Scripts`
 * → `ignorescripts`.
 *
 * Hand-written character walk (no regex): a flag's structure is small and
 * fixed, and the steps read more clearly as explicit slicing than as a pattern.
 */
function canonicalFlagKey(token: string): string | null {
  if (token.length === 0 || token[0] !== '-') return null; // positional / value

  // 1. Skip the leading run of dashes.
  let i = 0;
  while (i < token.length && token[i] === '-') i += 1;
  let body = token.slice(i);

  // 2. Keep only the option name — drop a joined `=value`.
  const eq = body.indexOf('=');
  if (eq !== -1) body = body.slice(0, eq);

  // 3. Lowercase, then peel a `no-` negation and a pnpm `config.` alias prefix.
  //    The `config.` peel MUST happen before separator collapsing (step 4) so
  //    the literal "config." word is removed — otherwise it would fold into the
  //    key (`configignorescripts`) and no longer prefix-match `ignorescripts`.
  body = body.toLowerCase();
  if (body.startsWith('no-')) body = body.slice('no-'.length);
  if (body.startsWith('config.')) body = body.slice('config.'.length);

  // 4. Collapse separators so kebab / snake / camel / concat all normalize.
  //    `.` is a separator too: pnpm accepts the DOTTED alias
  //    `--config.ignore.scripts=false`, which resolves to `ignore-scripts` and
  //    re-enables lifecycle scripts (empirically confirmed against pnpm 11.1.2).
  //    Stripping `.` after the `config.` peel collapses `ignore.scripts`
  //    → `ignorescripts` so the prefix match catches it.
  let key = '';
  for (const ch of body) {
    if (ch !== '-' && ch !== '_' && ch !== '.') key += ch;
  }
  return key;
}

/**
 * Rehydrate a separator-stripped canonical key (e.g. "ignorescripts",
 * "lockfiledir", "modulesdir") to its conventional kebab spelling for the
 * drop-group WARNING.  Input is always a grammar-derived canonical key — never
 * raw user text — so the output is safe to log.  Covers the well-known steering
 * keys explicitly; an unrecognized key (e.g. a one-off unknown flag) is returned
 * verbatim — it is still a separator-stripped, lowercased option NAME, with no
 * `=value` and no leading dashes, so it carries no credential payload.
 */
function rehydrateKebab(key: string): string {
  switch (key) {
    case 'ignorescripts':
      return 'ignore-scripts';
    case 'frozenlockfile':
      return 'frozen-lockfile';
    case 'fixlockfile':
      return 'fix-lockfile';
    case 'lockfiledir':
      return 'lockfile-dir';
    case 'lockfileonly':
      return 'lockfile-only';
    case 'lockfile':
      return 'lockfile';
    case 'modulesdir':
      return 'modules-dir';
    case 'virtualstoredir':
      return 'virtual-store-dir';
    case 'storedir':
      return 'store-dir';
    case 'workspaceroot':
      return 'workspace-root';
    default:
      return key; // dir, prefix, global, registry, filter, recursive, mode, immutable, c, g, r, w, … or any unknown flag
  }
}

/**
 * FAIL-CLOSED ALLOWLIST of canonical flag keys that are proven-safe
 * dependency-SELECTION options: they filter WHICH packages of the
 * lockfile-pinned tree get installed, and CANNOT redirect which lockfile is
 * read, where the install root / module output lives, whether lifecycle scripts
 * run, or the resolution source (registry).  Everything not on this set —
 * including all positionals and all unknown flags — is dropped (see
 * `sanitizeInstallArgs`).
 *
 * Why an allowlist and not a denylist: a denylist was proven STRUCTURALLY
 * UNSAFE here.  Three distinct pin-bypass families slipped past successive
 * denylist rounds (latest: pnpm `--dir alt --modules-dir ../node_modules`,
 * which materializes an ALTERNATE locked tree into the root node_modules at
 * exit 0 while the committed root lock — the SHA the audit gates on — stays
 * stale).  The safe surface (dependency-type filters) is small and stable; the
 * unsafe surface (every steering flag, every abbreviation, every PM's aliases)
 * is open-ended.  So we enumerate the safe set and refuse the rest.
 *
 * The map value is whether the flag TAKES A VALUE.  A value-taking flag in
 * SPLIT form (`--omit dev`) consumes the following token as its value (kept
 * together); a boolean flag never consumes the next token.  Joined `--omit=dev`
 * is a single token regardless.
 *
 * The set is intentionally minimal and empirically grounded (npm 11.x, pnpm
 * 10.34.x / 11.1.x, yarn Berry 4.x):
 *   * omit / include  — npm & pnpm dependency-group filters (value-taking).
 *   * prod / production / dev / optional — boolean dependency-group filters
 *     (`--no-optional` canonicalizes to `optional`, still dep-selection).
 *   * d / p  — the short flags `-D` / `-P`.  In pnpm these ARE `--dev` / `--prod`
 *     (dependency-type selection, boolean); in npm they are `--save-dev` /
 *     `--save-prod` (harmless save flags, inert under `npm ci`).  Crucially, in
 *     NO package manager does `-d`/`-D`/`-p`/`-P` resolve to a location/dir/
 *     prefix/global/source flag — the steering short flags are `-C` (`--dir`/
 *     `--prefix`, key `c`), `-g` (`--global`), `-r`, `-w`, `-F`/`-f`, none of
 *     which fold to `d` or `p` (verified empirically).  canonicalFlagKey
 *     lowercases, so `-d`/`-p` (npm `--loglevel info` / `--parseable`) also map
 *     here; both are harmless.  The documented action `args` example uses `-D`,
 *     so keeping these keeps that example valid.
 *
 * NOTE on negations: `--no-<allowlisted>` folds to the base key (e.g.
 * `--no-optional` → `optional`) and is itself dependency-selection, so it is
 * allowed.  No DANGEROUS flag's `--no-` form folds to an allowlisted key —
 * steering keys (`dir`, `prefix`, `modulesdir`, `global`, `registry`, `filter`,
 * `recursive`, `lockfile*`, `frozenlockfile`, `fixlockfile`, `immutable`,
 * `mode`, `ignorescripts`, …) are not in this set and never collapse into it.
 */
const ALLOWED_FLAG_KEYS: ReadonlyMap<string, { takesValue: boolean }> = new Map([
  ['omit', { takesValue: true }],
  ['include', { takesValue: true }],
  ['prod', { takesValue: false }],
  ['production', { takesValue: false }],
  ['dev', { takesValue: false }],
  ['optional', { takesValue: false }],
  ['p', { takesValue: false }], // -P (pnpm --prod / npm --save-prod / npm -p --parseable)
  ['d', { takesValue: false }], // -D (pnpm --dev  / npm --save-dev  / npm -d --loglevel)
]);

/**
 * FAIL-CLOSED ALLOWLIST for the SEPARATE `extra_install_args` channel — the
 * (currently dormant) npm cross-arch hints `--cpu` / `--os` / `--libc`.  These
 * select WHICH platform variant of the lockfile-pinned optionalDependencies gets
 * materialized (same safety class as `--omit=optional`): they cannot redirect
 * the lockfile, install root / module output, scripts, or the resolution source.
 *
 * Why a separate set: arch hints are not dependency-GROUP filters, so they are
 * not on `ALLOWED_FLAG_KEYS`.  But `extra_install_args` is read from the same
 * repo-deliverable `pm-flags.json` as `user_install_args`, so it MUST be
 * fail-closed at the guest boundary too — otherwise a steering flag (`--dir`,
 * `--lockfile-dir`, …) smuggled through this channel would bypass the
 * `user_install_args` sanitization.  Allowing exactly the arch hints keeps the
 * channel functional if `buildArchFlagOverlay` is ever revived while refusing
 * everything else.
 */
const ALLOWED_ARCH_KEYS: ReadonlyMap<string, { takesValue: boolean }> = new Map([
  ['cpu', { takesValue: true }],
  ['os', { takesValue: true }],
  ['libc', { takesValue: true }],
]);

/**
 * FAIL-CLOSED ALLOWLIST filter for developer-supplied install args.
 *
 * KEEP only tokens whose canonical flag key (see `canonicalFlagKey`) is on
 * `ALLOWED_FLAG_KEYS` — the proven-safe dependency-SELECTION flags that filter
 * the lockfile-pinned tree without redirecting which lock is read, where the
 * install root / module output lives, whether lifecycle scripts run, or the
 * resolution source.  DROP (and report) EVERYTHING ELSE: every unknown flag and
 * every positional.
 *
 * Why fail-closed: the materialized tree MUST be exactly the one pinned by the
 * committed root manager lock the audit gates on.  A denylist was proven
 * structurally unsafe — steering flags, abbreviations, and per-PM aliases form
 * an open-ended surface, and three pin-bypass families slipped past it over
 * successive rounds (latest: pnpm `--dir alt --modules-dir ../node_modules`,
 * which installs an alternate locked tree into the root node_modules at exit 0
 * while the root lock stays stale).  So everything that is not on the small,
 * stable safe set is refused — including `--dir`/`-C`/`--prefix`/`--modules-dir`/
 * `--virtual-store-dir`/`--store-dir` (root/output redirect), `--lockfile-dir`/
 * `--lockfile-only`/`--(no-)lockfile`/`--(no-)frozen-lockfile`/`--fix-lockfile`/
 * `--no-immutable` (lockfile location/enforcement), `--ignore-scripts` and its
 * `--no-` negation (script re-enable), `--global`/`-g`/`--workspace-root`/`-w`/
 * `--recursive`/`-r`/`--filter` (scope steering), `--registry`/`--config.registry`
 * (source swap), and any bare package name / path positional.
 *
 * Value tokens: an allowlisted VALUE-taking flag in SPLIT form (`--omit dev`)
 * keeps its following value token too (not dropped, not left dangling as a
 * positional).  Joined `--omit=dev` is a single token.  Boolean allowlisted
 * flags never consume a following token.
 *
 * Returns the kept args (to append after the fixed flags) and the dropped args
 * (so the caller can warn).  Pure; no shell parsing — the input is already an
 * argv array (the single split happens once at the input boundary).  MUST be
 * applied identically to the host install AND the sandbox fetch (it is called
 * from both `hostInstallNoScripts` and `runAudit`) so the two stay in parity.
 * The no-args path returns `{ kept: [], dropped: [], droppedKeys: [] }`
 * byte-identically (preserving all parity goldens).
 */
export interface SanitizeResult {
  kept: string[];
  dropped: string[];
  /** SAFE reasons for each DROP GROUP — one entry per LOGICAL drop (a flag plus
   *  any consumed value token count as a single entry).  Each entry is a
   *  constant derived from the flag GRAMMAR, never raw user text: a dropped
   *  flag reports its canonical option name (e.g. "--dir", "--ignore-scripts"),
   *  and a dropped positional reports the literal "<positional>".  Safe to log
   *  without leaking credentials. */
  droppedKeys: string[];
}

/**
 * Core fail-closed filter: KEEP only tokens whose canonical key is in `allow`
 * (carrying its value token for split value-flags), DROP + report everything
 * else.  `sanitizeInstallArgs` / `sanitizeArchInstallArgs` are the two public
 * entry points, differing only in which allowlist they enforce.
 */
function filterAgainstAllowlist(
  args: ReadonlyArray<string>,
  allow: ReadonlyMap<string, { takesValue: boolean }>,
): SanitizeResult {
  const kept: string[] = [];
  const dropped: string[] = [];
  const droppedKeys: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const key = canonicalFlagKey(a);
    if (key !== null && key.length > 0) {
      const allowed = allow.get(key);
      if (allowed !== undefined) {
        // KEEP the flag.  A value-taking allowlisted flag in SPLIT form
        // (`--omit dev`) must keep its following non-flag value token too, so it
        // does not dangle as a positional and get dropped on the next iteration.
        kept.push(a);
        if (
          allowed.takesValue &&
          isBareFlag(a) &&
          i + 1 < args.length &&
          !args[i + 1]!.startsWith('-')
        ) {
          kept.push(args[++i]!);
        }
        continue;
      }
      // A flag NOT on the allowlist — drop it.  Report its canonical option name
      // (rehydrated to the conventional kebab spelling), never the raw token.
      dropped.push(a);
      droppedKeys.push(`--${rehydrateKebab(key)}`);
      // Bare form (no `=value`): the package manager would consume the NEXT
      // token as this flag's value.  Drop it too so it cannot survive as a
      // dangling positional (which we would drop anyway, but consuming it keeps
      // the drop grouped under one reason and matches PM argv semantics).
      if (isBareFlag(a) && i + 1 < args.length && !args[i + 1]!.startsWith('-')) {
        dropped.push(args[++i]!);
      }
      continue;
    }
    // A positional (package name, path, or a value not consumed by an
    // allowlisted flag) — fail-closed: DROP it and report a grammar-derived
    // constant, never the raw value.
    dropped.push(a);
    droppedKeys.push('<positional>');
  }
  return { kept, dropped, droppedKeys };
}

/** Fail-closed allowlist of the developer `args` channel (dependency-selection
 *  flags only — see `ALLOWED_FLAG_KEYS`).  Applied identically to the host
 *  install and the sandbox fetch so the two stay in parity; the no-args path
 *  returns `{ kept: [], dropped: [], droppedKeys: [] }` byte-identically. */
export function sanitizeInstallArgs(args: ReadonlyArray<string>): SanitizeResult {
  return filterAgainstAllowlist(args, ALLOWED_FLAG_KEYS);
}

/** Fail-closed allowlist of the `extra_install_args` channel (npm cross-arch
 *  hints only — see `ALLOWED_ARCH_KEYS`).  Re-applied at the guest boundary so a
 *  steering flag cannot ride in through this channel even if the repo-delivered
 *  `pm-flags.json` is not overwritten by the host overlay. */
export function sanitizeArchInstallArgs(args: ReadonlyArray<string>): SanitizeResult {
  return filterAgainstAllowlist(args, ALLOWED_ARCH_KEYS);
}

/**
 * Split a single install-args string (the action `args` input / the CLI
 * `--args` value) into an argv array.
 *
 * Whitespace-separated, with single/double-quote grouping so values that
 * contain spaces survive (e.g. `--filter "my pkg"` → ['--filter','my pkg']).
 * This is NOT a full shell tokenizer — no escapes, no variable expansion — and
 * the result is handed to the package manager as discrete argv items, never
 * through a shell, so there is no command-injection surface.  Empty / blank
 * input yields `[]`.
 */
export function splitInstallArgs(raw: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  let started = false; // distinguishes a real (possibly empty quoted) token from inter-token gaps
  for (const ch of raw) {
    if (quote !== null) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      if (started) {
        out.push(cur);
        cur = '';
        started = false;
      }
      continue;
    }
    cur += ch;
    started = true;
  }
  if (started) out.push(cur);
  return out;
}

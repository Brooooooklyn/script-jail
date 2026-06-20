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
  // SECURITY (#43, home/project-npmrc node-options): npm re-derives `node-options`
  // from the EFFECTIVE npm config (userconfig $HOME/.npmrc AND the project
  // repoDir/.npmrc, the latter PR-controlled + staged into the sandbox) and exports
  // it to lifecycle scripts as both the child `NODE_OPTIONS` and the
  // `npm_config_node_options` env value.  `--no-node-options` neutralizes BOTH on
  // EVERY Phase-B site at once (this is the shared, lockstep source): the trusted
  // host never honors an audit-blind home-npmrc `--require <path>` (the host has no
  // shim to overwrite NODE_OPTIONS), and host+guest export an IDENTICAL empty
  // `npm_config_node_options` so a script branching on that env value cannot diverge
  // (env-spy records the NAME only — a host-only flag would be a value-blind oracle).
  // It MUST live here, not in a host-only hardening list, precisely to keep the host
  // and guest argv byte-identical.  Guest instrumentation is unaffected: the JS
  // preloads ride the LD_PRELOAD shim's exec-time NODE_OPTIONS rewrite, not npm's
  // node-options passthrough.  Verified npm 11.13.0: an empty NODE_OPTIONS /
  // npm_config_node_options ENV pin does NOT override the npmrc file, but
  // `--no-node-options` does, and it preserves the npmrc's registry/auth.
  npm: { cmd: 'npm', args: ['rebuild', '--foreground-scripts', '--no-node-options'] },
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
 * True when a `--registry` value embeds credentials in the URL userinfo
 * (`scheme://user:pass@host`, or a bare `scheme://token@host`).
 *
 * SECURITY (adversarial-review F1): a KEPT install arg is staged VERBATIM into
 * the repo-visible `etc/script-jail/pm-flags.json` sidecar (so the guest can
 * load it in Phase A).  That file sits inside the audit work_dir — the cwd of
 * the UNTRUSTED lifecycle scripts in Phase B — so any secret it carries is
 * readable by the very code being audited (and could surface via raw stderr
 * forwarding).  Registry AUTH therefore must live in `.npmrc` / env (honored by
 * the sandbox), NEVER inline in a CLI arg.  An inline-credential `--registry`
 * value is dropped (the bare `--registry=https://host/` form stays allowed).
 *
 * Detection inspects the AUTHORITY component for userinfo (`user[:pass]@`).
 * A structured `URL` parse handles schemeful URLs precisely (it decodes
 * percent-encoded userinfo into username/password).  A shape check then covers
 * the forms `new URL` misses or mis-parses (adversarial-review F3/F5):
 *   * scheme-relative `//user:pass@host`   — `new URL` throws (no scheme)
 *   * bare `user:pass@host` / `TOKEN@host` — `new URL` reads `user:` as an
 *                                            opaque scheme, so username is empty
 * The shape check strips an optional `scheme:` and a leading `//`, then takes
 * everything up to the first `/`, `?`, or `#`; an `@` there is userinfo.  An `@`
 * AFTER the first delimiter (a path segment like `https://host/org@scope/` or
 * `host/a//b@c`) is NOT userinfo and is correctly left alone.  Linear-time: the
 * scheme prefix is RFC-bounded (`{0,31}`) and `split` is linear, so no
 * backtracking.
 */
function registryUrlHasCredentials(value: string): boolean {
  try {
    const u = new URL(value);
    if (u.username.length > 0 || u.password.length > 0) return true;
  } catch {
    // not a parseable absolute URL — fall through to the authority shape check
  }
  let s = value.trim();
  const scheme = /^[a-z][a-z0-9+.-]{0,31}:/i.exec(s);
  if (scheme !== null) s = s.slice(scheme[0].length);
  if (s.startsWith('//')) s = s.slice(2);
  const authority = s.split(/[/?#]/, 1)[0] ?? '';
  return authority.includes('@');
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
 * Map a dropped flag's canonical key to the FIXED display token used in the
 * drop-group WARNING.  EVERY return value is a hard-coded constant — the
 * well-known steering keys get their conventional kebab name, and anything else
 * (an unknown / one-off flag) gets the sentinel `<flag>`.
 *
 * SECURITY: this MUST NOT echo a derived key.  `canonicalFlagKey` strips only
 * leading dashes, `=value`, `no-`/`config.`, and `-_.` separators — it does NOT
 * strip newlines, `%`, `::`, or other characters, and a flag NAME with no `=`
 * (e.g. `--<credential>`) survives intact as the key.  Logging that verbatim
 * into `hostInstallNoScripts`'s GitHub-Actions warning would allow workflow-
 * command injection (`\n::warning::…`) or a credential leak.  The switch only
 * matches CLEAN known keys (an injected key like `dir\n::warning` never equals
 * `case 'dir'`), so every dropped flag resolves to a constant.  No user text
 * reaches the log, so no GH-command escaping is needed downstream.
 */
function dropReason(key: string): string {
  switch (key) {
    case 'ignorescripts':
      return '--ignore-scripts';
    case 'frozenlockfile':
      return '--frozen-lockfile';
    case 'fixlockfile':
      return '--fix-lockfile';
    case 'lockfiledir':
      return '--lockfile-dir';
    case 'lockfileonly':
      return '--lockfile-only';
    case 'lockfile':
      return '--lockfile';
    case 'modulesdir':
      return '--modules-dir';
    case 'virtualstoredir':
      return '--virtual-store-dir';
    case 'storedir':
      return '--store-dir';
    case 'workspaceroot':
      return '--workspace-root';
    case 'dir':
      return '--dir';
    case 'prefix':
      return '--prefix';
    case 'global':
      return '--global';
    case 'filter':
      return '--filter';
    case 'recursive':
      return '--recursive';
    case 'mode':
      return '--mode';
    case 'immutable':
      return '--immutable';
    case 'registry':
      // Reached only via the value-level reject (inline-credential URL); the key
      // itself is allowlisted.  Fixed constant — explains WHY without echoing the
      // (secret-bearing) value.
      return '--registry (inline credentials — set registry auth in .npmrc/env)';
    default:
      return '<flag>'; // unknown / un-named flag — never echo the raw key (see note)
  }
}

/**
 * FAIL-CLOSED ALLOWLIST of canonical flag keys that are proven-safe: they CANNOT
 * redirect which lockfile is read, where the install root / module output lives,
 * or whether lifecycle scripts run.  Most are dependency-SELECTION filters (they
 * pick WHICH of the lockfile-pinned packages install); the one source knob is
 * `registry` (see its note).  Everything not on this set — including all
 * positionals and all unknown flags — is dropped (see `sanitizeInstallArgs`).
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
 *   * registry — the resolution SOURCE (value-taking).  NOT a steering knob.
 *     Under the fixed `--frozen-lockfile` / `npm ci` it does NOT relax the
 *     root-lock validation (a stale lock still errors `ERR_PNPM_OUTDATED_LOCKFILE`
 *     even with `--registry` — verified on real pnpm).  For WELL-FORMED locks
 *     (the normal case: every registry dep carries `resolved` + `integrity`) npm
 *     follows the lock's `resolved` URL and validates the integrity hash, so
 *     `--registry` cannot steer the installed bytes; pnpm's frozen-lockfile
 *     validation is likewise unaffected.  CAVEAT: a MALFORMED lock whose registry
 *     entry lacks `integrity` lets npm re-resolve bytes from the in-effect
 *     registry — but that is a PRE-EXISTING npm property independent of this flag
 *     (it occurs with the default registry and with a PR-controlled `.npmrc` too),
 *     and `--registry` here is a maintainer-fixed input (it rides the Action
 *     `args`, read from the base repo on `pull_request`, not PR-controllable), so
 *     allowlisting it adds no attacker capability.  Allowlisted by owner decision
 *     for private-registry consumers.  Registry AUTH belongs in `.npmrc` / env
 *     (honored by the sandbox), NOT in CLI args: a `rejectValue` predicate DROPS
 *     any `--registry` value embedding inline URL credentials (see
 *     `registryUrlHasCredentials` — the secret would otherwise be staged into the
 *     Phase-B-readable `pm-flags.json` sidecar).
 *
 * NOTE on negations: `--no-<allowlisted>` folds to the base key (e.g.
 * `--no-optional` → `optional`) and is itself dependency-selection, so it is
 * allowed.  No DANGEROUS flag's `--no-` form folds to an allowlisted key —
 * steering keys (`dir`, `prefix`, `modulesdir`, `global`, `filter`, `recursive`,
 * `lockfile*`, `frozenlockfile`, `fixlockfile`, `immutable`, `mode`,
 * `ignorescripts`, …) are not in this set and never collapse into it.
 */
/** An allowlist entry: whether the flag takes a value, and an optional
 *  value-level policy that DROPS the flag when the value itself is unsafe
 *  (e.g. a `--registry` URL embedding inline credentials). */
interface AllowEntry {
  takesValue: boolean;
  rejectValue?: (value: string) => boolean;
}

const ALLOWED_FLAG_KEYS: ReadonlyMap<string, AllowEntry> = new Map([
  ['omit', { takesValue: true }],
  ['include', { takesValue: true }],
  ['prod', { takesValue: false }],
  ['production', { takesValue: false }],
  ['dev', { takesValue: false }],
  ['optional', { takesValue: false }],
  ['p', { takesValue: false }], // -P (pnpm --prod / npm --save-prod / npm -p --parseable)
  ['d', { takesValue: false }], // -D (pnpm --dev  / npm --save-dev  / npm -d --loglevel)
  // private-registry SOURCE; root-lock gate unaffected (see note).  AUTH must go
  // in .npmrc/env — an inline-credential URL value is rejected (F1).
  ['registry', { takesValue: true, rejectValue: registryUrlHasCredentials }],
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
const ALLOWED_ARCH_KEYS: ReadonlyMap<string, AllowEntry> = new Map([
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
 * `--recursive`/`-r`/`--filter` (scope steering), and any bare package name /
 * path positional.  (`--registry` is the one allowed SOURCE flag — see
 * `ALLOWED_FLAG_KEYS`; it does not relax the root-lock gate, and an inline-
 * credential URL value is rejected so no secret reaches the staged sidecar.)
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
   *  any consumed value token count as a single entry).  Each entry is a FIXED
   *  CONSTANT, never raw/derived user text: a known steering flag reports a
   *  hard-coded name (e.g. "--dir", "--ignore-scripts"), an unknown flag reports
   *  "<flag>", and a positional reports "<positional>" (see `dropReason`).  Safe
   *  to log verbatim — no credential payload, no GH-command-injection surface. */
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
  allow: ReadonlyMap<string, AllowEntry>,
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
        // Resolve this flag's VALUE in either joined (`--registry=URL`) or split
        // (`--registry URL`) form so a value-level policy can inspect it.  A
        // value-taking flag in SPLIT form consumes the following non-flag token.
        const eq = a.indexOf('=');
        const splitValue =
          allowed.takesValue &&
          isBareFlag(a) &&
          i + 1 < args.length &&
          !args[i + 1]!.startsWith('-')
            ? args[i + 1]!
            : undefined;
        const value = eq >= 0 ? a.slice(eq + 1) : splitValue;
        // VALUE-LEVEL rejection: the flag is on the allowlist but THIS value is
        // unsafe (e.g. a `--registry` URL embedding inline credentials).  Drop it
        // and report only the fixed key — NEVER the value, which may be a secret.
        if (allowed.rejectValue !== undefined && value !== undefined && allowed.rejectValue(value)) {
          dropped.push(a);
          droppedKeys.push(dropReason(key));
          if (splitValue !== undefined) dropped.push(args[++i]!);
          continue;
        }
        // KEEP the flag.  A value-taking allowlisted flag in SPLIT form
        // (`--omit dev`) must keep its following non-flag value token too, so it
        // does not dangle as a positional and get dropped on the next iteration.
        kept.push(a);
        if (splitValue !== undefined) {
          kept.push(args[++i]!);
        }
        continue;
      }
      // A flag NOT on the allowlist — drop it.  Report a FIXED display token
      // (`dropReason`): a hard-coded name for known steering flags, `<flag>` for
      // anything else.  NEVER the raw/derived key — see `dropReason`'s note.
      dropped.push(a);
      droppedKeys.push(dropReason(key));
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

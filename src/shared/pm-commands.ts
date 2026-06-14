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
 * True when `token` could set a script/build-enabling option.
 *
 * `ignore-scripts` is matched by PREFIX, not equality, because npm/nopt
 * resolves any UNAMBIGUOUS abbreviation of a config option to the full option:
 * `--ignore=false`, `--ignore-s=false`, even `--ig=false` all set
 * `ignore-scripts` and re-enable lifecycle scripts (empirically confirmed
 * against real npm 11.x).  A fixed-spelling denylist cannot cover abbreviation,
 * so we drop ANY non-empty prefix of `ignorescripts`.  Over-matching (e.g.
 * dropping a bare `-i`) is the safe direction — the only real option that is a
 * prefix of `ignorescripts` is `ignore-scripts` itself; `--include`, `--omit`,
 * `-D`, `--prod`, `--no-optional`, … are not prefixes and survive.
 *
 * yarn `--mode` is matched EXACTLY: yarn Berry's parser (clipanion) does not
 * abbreviate, so an exact key is enough and we avoid over-dropping a legitimate
 * short flag like `-m`/`-mo`.
 */
function isForbiddenFlag(token: string): boolean {
  const key = canonicalFlagKey(token);
  if (key === null || key.length === 0) return false;
  // npm/nopt prefix abbreviation — but require ≥2 chars.  The single letter `i`
  // is AMBIGUOUS across npm options (include-*, init-*, install-*, if-present,
  // ignore-scripts), so npm does NOT resolve `--i` to ignore-scripts — it
  // expands to `--include-workspace-root` (verified on npm 11.13).  Dropping a
  // bare `i` would silently omit root workspace deps from the install graph.
  // `ig` is the SHORTEST unambiguous ignore-scripts prefix, so start there.
  if (key.length >= 2 && 'ignorescripts'.startsWith(key)) return true;
  if (key === 'mode') return true; // yarn build mode (exact)
  return false;
}

/**
 * Filter developer-supplied install args so they can never re-enable lifecycle
 * scripts in the no-scripts (Phase A / host part-1) install.
 *
 * Dropped (see `isForbiddenFlag` / `canonicalFlagKey`):
 *   * any token that resolves to `ignore-scripts` — every spelling, dash count,
 *     `no-`/`config.` prefix, AND every npm-accepted ABBREVIATION (`--ignore`,
 *     `--ig`, …).  JOINED (`…=false`) and SPLIT (`--ignore-scripts false`, where
 *     the following non-flag value token is dropped too) both covered.
 *   * any yarn `--mode` (joined `--mode=X` or split `--mode X`) — we force
 *     `--mode=skip-build`; a user mode could turn builds back on.
 *
 * Returns the kept args (to append after the fixed flags) and the dropped args
 * (so the caller can warn).  Pure; no shell parsing — the input is already an
 * argv array (the single split happens once at the input boundary).  MUST be
 * applied identically to the host install AND the sandbox fetch (it is called
 * from both `hostInstallNoScripts` and `runAudit`) so the two stay in parity.
 */
export function sanitizeInstallArgs(args: ReadonlyArray<string>): {
  kept: string[];
  dropped: string[];
} {
  const kept: string[] = [];
  const dropped: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (isForbiddenFlag(a)) {
      dropped.push(a);
      // Bare form (no `=value`): the package manager would consume the NEXT
      // token as the value (`--ignore-scripts false`, `--mode update-lockfile`).
      // Drop that value token too so a re-enabling value — or a dangling
      // positional — can never reach the argv.
      if (isBareFlag(a) && i + 1 < args.length && !args[i + 1]!.startsWith('-')) {
        dropped.push(args[++i]!);
      }
      continue;
    }
    kept.push(a);
  }
  return { kept, dropped };
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

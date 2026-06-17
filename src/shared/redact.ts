// script-jail — src/shared/redact.ts
//
// Single source of truth for credential-shape redaction, shared by BOTH the
// guest agent (Phase A failure dump / Phase B stdout tail) and the host
// drop-in install (part-1 package-manager output captured off the runner).
//
// This module imports NOTHING guest- or host-specific: it is pure string ops
// so it can be safely bundled into both `dist/main.cjs` and
// `dist/guest-agent.cjs` (mirrors the `buildRootPkgKeys` single-source
// precedent — one helper, used by guest + host, to eliminate divergence).
//
// LINEAR-TIME INVARIANT: every regex here runs on attacker-influenced,
// multi-MB package-manager output (Phase-A yarn buffers, host part-1 capture).
// Each pattern MUST be linear-time — no unbounded overlapping/greedy
// quantifiers that can backtrack O(N²). Bound any prefix that precedes a
// required literal (see the scheme cap below) rather than leaving it `*`.

/**
 * Redact credential SHAPES regardless of any protected-name list.
 *
 * Catches credentials that may NOT be in any caller-supplied list — URL
 * userinfo, npm rc auth lines, `Bearer` headers, and well-known token literal
 * shapes (npm / GitHub / AWS).
 *
 * LINE-LOCAL CONTRACT (Codex round-9 [high] #1): every shape below matches
 * WITHIN A SINGLE LINE — none may span a newline.  The Phase-B stdout
 * collector redacts per complete line (see attachStdoutTailCollector); a shape
 * whose marker and token straddle a '\n' would be masked by a whole-buffer
 * pass but MISSED per-line, and once the marker is front-dropped the surviving
 * token would leak.  Aligning the regexes to be line-local makes per-line
 * redaction COMPLETE for shapes: the inter-token whitespace classes use
 * `[^\S\n]` (whitespace except newline), and every token/value class already
 * excludes whitespace.  Real credentials are single-line, so this loses no
 * genuine coverage — a `Bearer` with its token on the NEXT line is, by this
 * contract, not a credential (its token, if itself a known shape or a layer-1
 * value, is still caught on its own line).
 */
export function redactCredentialShapes(text: string): string {
  return text
    // scheme://user:pass@host → keep scheme + host, drop userinfo.  The schemeful
    // form may appear mid-string (e.g. `proxy=https://user:pass@host`), so it
    // stays broad.  Scheme length is RFC-bounded ({0,31}) so the prefix can't
    // backtrack: an unbounded `*` here is O(N) per start position → O(N²) ReDoS
    // on long contiguous [a-z0-9+.-] runs (integrity hashes, long resolved URLs).
    // No real URI scheme exceeds 32 chars, so this is output-preserving.
    .replace(/([a-z][a-z0-9+.-]{0,31}:\/\/)[^/\s:@]+:[^/\s@]+@/gi, '$1<REDACTED:URL-CREDENTIALS>@')
    // scheme-RELATIVE //user:pass@host → same masking (parity with pm-commands'
    // credential rejector, adversarial-review F3), but ANCHORED to start-of-
    // string or a safe delimiter (whitespace / = / quote / paren / backtick) so a
    // `//` INSIDE a path (e.g. `https://host/p//a:b@c`, where `new URL` reports an
    // empty username) is NOT mistaken for userinfo and benign diagnostics are not
    // corrupted (adversarial-review F7).  Linear-time (bounded userinfo classes).
    .replace(/(^|[\s='"(`])\/\/[^/\s:@]+:[^/\s@]+@/g, '$1//<REDACTED:URL-CREDENTIALS>@')
    // npm rc auth lines: _authToken= / _auth= / _password=  (rc or env form)
    .replace(/((?:_authToken|_auth|_password)[^\S\n]*=[^\S\n]*)\S+/gi, '$1<REDACTED>')
    // Bearer <token>
    .replace(/(Bearer[^\S\n]+)[A-Za-z0-9._~+/-]{8,}=*/g, '$1<REDACTED>')
    // npm automation/granular token literals (npm_… 36+ char)
    .replace(/\bnpm_[A-Za-z0-9]{36,}\b/g, '<REDACTED:NPM-TOKEN>')
    // GitHub token literals (ghp_/gho_/ghs_/ghu_/ghr_ + 36+ char)
    .replace(/\bgh[posur]_[A-Za-z0-9]{36,}\b/g, '<REDACTED:GH-TOKEN>')
    // AWS access key id (AKIA/ASIA + 16 upper-alnum)
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '<REDACTED:AWS-KEY>');
}

/**
 * Mask exact literal `values` wherever they appear in `text`.
 *
 * Generalizes layer-1 of the guest's `redactSensitive`: the caller supplies raw
 * values + one label (vs. the guest's per-env-name `<REDACTED:name>` labels).
 *
 *   * `minLen` guard (default 4): values shorter than `minLen` are skipped so a
 *     short non-secret (e.g. `dev` from `--omit=dev`) does not blank out
 *     unrelated words (e.g. `devDependencies`) in the surrounding output.
 *     SECURITY CONSEQUENCE: a value shorter than `minLen` is NOT masked at all
 *     — accepted because genuine credentials are never < 4 chars, so the guard
 *     trades no real-secret coverage for the false-positive protection.
 *   * dedupe: identical values are masked once.
 *   * longest-first: sorted by length descending so a value that is a substring
 *     of another is not partially pre-masked.
 */
export function maskExactValues(
  text: string,
  values: readonly string[],
  label = 'REDACTED',
  minLen = 4,
): string {
  const unique = Array.from(new Set(values))
    .filter((v) => v.length >= minLen)
    .sort((a, b) => b.length - a.length);
  let out = text;
  const replacement = `<${label}>`;
  for (const value of unique) {
    out = out.split(value).join(replacement);
  }
  return out;
}

/** High-entropy floor for fragment masking — a shared substring shorter than
 * this is too short to distinguish a real (high-entropy) secret from benign
 * text.  A line span every one of whose `minFragment`-char windows is a
 * substring of a declared secret is treated as a leaked fragment and masked. */
const DEFAULT_MIN_FRAGMENT = 8;
/** FAIL-CLOSED memory backstop on the gram set (≈1M eight-char grams ≈ ~80 MB).
 * Sized far above a full OS-bounded environment's worth of distinct grams: a
 * single env var is capped at ~128 KiB and the whole environment at a couple
 * MiB, so a realistic 64-name `protected.env` yields orders of magnitude fewer
 * grams than this and gets FULL fragment coverage.  If a pathological declared
 * set ever exceeds the ceiling we do NOT silently stop adding later values'
 * grams — that would leak a LATER value's fragment purely by list order
 * (adversarial-review F6 round-3 #6) — we FAIL CLOSED and mask the whole text. */
const FRAGMENT_MAX_GRAMS = 1 << 20;

/**
 * Mask any span of `text` that is "secret-like" — i.e. every `minFragment`-char
 * window in the span is a substring of some declared secret value.
 *
 * `maskExactValues` only matches the WHOLE declared value, so a secret that
 * leaks as a FRAGMENT slips through — e.g. a concurrent writer's newline
 * truncates a secret mid-write on a SHARED stdout/stderr pipe, leaving only a
 * prefix on the line; a same-writer split leaves a prefix on one line and a
 * suffix on the next; or a middle slice survives (adversarial-review F6
 * round-3).  This catches all of those uniformly: build the set of every
 * `minFragment`-length substring (gram) of every declared value, then mask each
 * maximal run of positions whose gram is in that set.  A leaked prefix, suffix,
 * or middle fragment of length >= `minFragment` is fully covered by secret
 * grams, so the whole run is masked — there are NO per-value, longest-match,
 * occurrence-cap, or scan-window edges to leak past (the earlier extraction
 * approach regressed on every one of those).
 *
 * `minFragment` (default 8) is a high-entropy floor: a real token's 8-char
 * window coinciding with unrelated log text is vanishingly unlikely, so benign
 * output is not mass-masked; a CHAIN of coincidences (needed to extend a span)
 * is rarer still.  Over-masking (a benign span that happens to match) is
 * safe-side and the user explicitly declared the value secret.
 *
 * SCOPE: this is DEFENSE-IN-DEPTH; the PRIMARY protection is the env_read audit
 * gate (a script cannot obtain a value to leak — whole or fragmented — without a
 * recorded read that fails the PR pre-trust).  Bounded: O(sum |V|) to build the
 * gram set + O(|text| · minFragment) to scan, with no dependence on the number
 * or placement of occurrences.  The gram set carries a FAIL-CLOSED ceiling
 * (`FRAGMENT_MAX_GRAMS`): a declared set so large it exceeds the ceiling masks
 * the whole text rather than silently dropping a later value's coverage.
 */
export function maskValueFragments(
  text: string,
  values: readonly string[],
  label = 'REDACTED',
  minFragment = DEFAULT_MIN_FRAGMENT,
): string {
  if (text.length < minFragment) return text;
  const replacement = `<${label}>`;
  // Build the gram set from EVERY declared value (cross-value in one pass — no
  // per-value race).  Values at or below the floor are whole-masked elsewhere.
  const grams = new Set<string>();
  let capped = false;
  for (const v of values) {
    if (v.length <= minFragment) continue;
    for (let i = 0; i + minFragment <= v.length; i += 1) {
      grams.add(v.slice(i, i + minFragment));
      if (grams.size >= FRAGMENT_MAX_GRAMS) { capped = true; break; }
    }
    if (capped) break;
  }
  // The declared set hit the memory ceiling before every value's grams were
  // recorded → coverage can no longer be guaranteed for the LATER values, so
  // fail closed (mask everything) rather than leak a later value's fragment by
  // list order (adversarial-review F6 round-3 #6).
  if (capped) return replacement;
  if (grams.size === 0) return text;
  const n = text.length;
  let out = '';
  let i = 0;
  while (i + minFragment <= n) {
    if (grams.has(text.slice(i, i + minFragment))) {
      // Start of a secret-like span at position i (covers text[i .. i+minFragment)).
      // Extend while each next overlapping window is also a gram.
      let j = i;
      while (j + 1 + minFragment <= n && grams.has(text.slice(j + 1, j + 1 + minFragment))) j += 1;
      out += replacement;
      i = j + minFragment; // skip the whole covered span [i .. j+minFragment)
    } else {
      out += text[i];
      i += 1;
    }
  }
  out += text.slice(i); // trailing run shorter than minFragment cannot be a gram
  return out;
}

/**
 * Derive the exact literal values that must be masked out of captured
 * package-manager output that took developer-supplied install `args`.  For each
 * KEPT (already sanitized) token `t`:
 *   * push `t` itself (the whole token — airtight literal match), and
 *   * if `t` contains `=`, push the value substring after the first `=` — this
 *     catches a PM that REFORMATS `--registry=SECRET` into `registry="SECRET"`;
 *     the value `SECRET` still appears verbatim inside the reformatted echo.
 * `maskExactValues` applies the `minLen >= 4` filter, so a short non-secret
 * value like `dev` (from `--omit=dev`) is NOT masked — only the whole
 * `--omit=dev` token is — which avoids mangling unrelated words (e.g.
 * "devDependencies") in the PM output.  Nothing else is pushed.
 *
 * Single-sourced here (was a local helper in src/action/host-install.ts) so the
 * host part-1 capture path AND the guest Phase-A failure dump derive the
 * IDENTICAL value set — the same single-source precedent as the redactors
 * above.
 */
export function deriveSensitiveValues(args: readonly string[]): string[] {
  const values: string[] = [];
  for (const t of args) {
    values.push(t);
    const eq = t.indexOf('=');
    if (eq >= 0) values.push(t.slice(eq + 1));
  }
  return values;
}

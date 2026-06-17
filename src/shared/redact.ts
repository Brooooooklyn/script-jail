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

/** High-entropy floor for fragment masking — a prefix/suffix shorter than this
 * is too short to distinguish a real (high-entropy) secret from benign text. */
const DEFAULT_MIN_FRAGMENT = 8;
/** Per-affix scan-window cap (NOT an eligibility filter — a longer secret is
 * still protected at its first/last `FRAGMENT_SCAN_WINDOW` chars). */
const FRAGMENT_SCAN_WINDOW = 512;
/** Backstop on occurrences scanned per affix (a pathological line that repeats a
 * value's minimal prefix thousands of times can't force unbounded work). */
const FRAGMENT_MAX_OCCURRENCES = 4096;

/**
 * Longest prefix of `w` (>= `minFragment`, <= `w.length`) present anywhere in
 * `text`.  Returns 0 if none.  Finds the GLOBAL longest by extending every
 * occurrence of `w`'s minimal prefix, so a longer fragment at a later position
 * is not missed; early-breaks once a full-window match is found.
 */
function longestPrefixPresent(text: string, w: string, minFragment: number): number {
  if (w.length < minFragment) return 0;
  const minP = w.slice(0, minFragment);
  let best = 0;
  let from = 0;
  let seen = 0;
  for (;;) {
    const idx = text.indexOf(minP, from);
    if (idx === -1) break;
    let k = minFragment;
    const max = Math.min(w.length, text.length - idx);
    while (k < max && text.charCodeAt(idx + k) === w.charCodeAt(k)) k += 1;
    if (k > best) best = k;
    if (best >= w.length || (seen += 1) >= FRAGMENT_MAX_OCCURRENCES) break;
    from = idx + 1;
  }
  return best;
}

/** Longest suffix of `w` present anywhere in `text` (mirror of the prefix scan,
 * extending each occurrence of `w`'s minimal SUFFIX backward). */
function longestSuffixPresent(text: string, w: string, minFragment: number): number {
  if (w.length < minFragment) return 0;
  const minS = w.slice(w.length - minFragment);
  let best = 0;
  let from = 0;
  let seen = 0;
  for (;;) {
    const idx = text.indexOf(minS, from); // minS occupies text[idx .. idx+minFragment)
    if (idx === -1) break;
    let k = minFragment;
    // Extend backward: for suffix length k+1 the new leftmost char is
    // w[w.length-k-1], aligning with text[idx-(k-minFragment)-1].
    for (;;) {
      if (k >= w.length) break;
      const ti = idx - (k - minFragment) - 1;
      const wi = w.length - k - 1;
      if (ti < 0 || wi < 0 || text.charCodeAt(ti) !== w.charCodeAt(wi)) break;
      k += 1;
    }
    if (k > best) best = k;
    if (best >= w.length || (seen += 1) >= FRAGMENT_MAX_OCCURRENCES) break;
    from = idx + 1;
  }
  return best;
}

/**
 * Mask a PREFIX or SUFFIX of each declared secret value that appears in `text`.
 *
 * `maskExactValues` only matches the WHOLE declared value, so a secret that
 * leaks as a fragment slips through — e.g. when a concurrent writer's newline
 * truncates a secret mid-write on a SHARED stdout/stderr pipe, the line carries
 * only `V[0..k]` (a prefix), or a same-writer `V[0..k]\nV[k..]` split leaves a
 * prefix on one line and a suffix on the next (adversarial-review F6 round-3).
 * For each declared value `V`, this masks the LONGEST prefix and LONGEST suffix
 * of `V` present in `text`, each at least `minFragment` chars.  `minFragment` is
 * a high-entropy floor (default 8) so benign words are not mass-masked: a real
 * token's 8+ char prefix coinciding with unrelated log text is vanishingly
 * unlikely.
 *
 * Two correctness properties (adversarial-review F6 round-3, both regressed):
 *   * NON-DESTRUCTIVE discovery: every value's longest prefix/suffix is found
 *     against the ORIGINAL `text`, collected, then ALL fragments are masked once
 *     in LENGTH-DESCENDING order.  Mutating per value would let a longer value's
 *     short shared prefix consume the match gate, leaving a shorter value's
 *     longer leaked fragment's tail exposed.
 *   * SCAN WINDOW, not eligibility: a value longer than `FRAGMENT_SCAN_WINDOW` is
 *     NOT excluded — its first/last `FRAGMENT_SCAN_WINDOW` chars are scanned, so a
 *     prefix/suffix leak of a long secret (private key, service-account JSON,
 *     long opaque token) is still masked.
 *
 * SCOPE: this does NOT cover an arbitrary MIDDLE split (a deliberately
 * fragmented secret with neither end on a line) — the irreducible per-line
 * line-local residual, bounded by the PRIMARY env_read audit gate (a script
 * cannot obtain the value to fragment without a recorded read that fails the PR
 * pre-trust).  Fragment masking strengthens the defense-in-depth layer against
 * the realistic prefix/suffix truncation; it is not a trust boundary.
 *
 * Bounded: each affix scan is O(|text|) indexOf-amortized + bounded extension,
 * capped at `FRAGMENT_MAX_OCCURRENCES`, so a pathological line cannot force
 * unbounded work even with the full set of declared values.
 */
export function maskValueFragments(
  text: string,
  values: readonly string[],
  label = 'REDACTED',
  minFragment = DEFAULT_MIN_FRAGMENT,
): string {
  const replacement = `<${label}>`;
  // 1. DISCOVER (non-destructive): collect every present prefix/suffix fragment
  //    against the original text, so cross-value shared prefixes don't race.
  const fragments: string[] = [];
  for (const v of new Set(values)) {
    if (v.length <= minFragment) continue; // whole value is exact-masked elsewhere
    const preWin = v.length > FRAGMENT_SCAN_WINDOW ? v.slice(0, FRAGMENT_SCAN_WINDOW) : v;
    const pLen = longestPrefixPresent(text, preWin, minFragment);
    if (pLen >= minFragment) fragments.push(preWin.slice(0, pLen));
    const sufWin = v.length > FRAGMENT_SCAN_WINDOW ? v.slice(v.length - FRAGMENT_SCAN_WINDOW) : v;
    const sLen = longestSuffixPresent(text, sufWin, minFragment);
    if (sLen >= minFragment) fragments.push(sufWin.slice(sufWin.length - sLen));
  }
  if (fragments.length === 0) return text;
  // 2. APPLY longest-first so a longer fragment is masked before a shorter one
  //    (possibly a shared prefix) can consume part of it.
  let out = text;
  for (const frag of Array.from(new Set(fragments)).sort((a, b) => b.length - a.length)) {
    out = out.split(frag).join(replacement);
  }
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

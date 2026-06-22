// Path → canonical token. Longest-prefix match against the runtime paths
// observed inside the Firecracker VM. The resulting tokens make the lockfile
// stable across runs and across runners.
//
// Tokens (in priority order — longest-prefix wins):
//   $PKG          /work/node_modules/<pkg>           (per-event, see currentPkgDir)
//   $NODE_MODULES /work/node_modules
//   $REPO         /work
//   $CACHE        per-manager cache root (e.g. /root/.local/share/pnpm/store)
//   $HOME         /root
//   $TMPDIR       /tmp
//
// Hash collapsing: only applied under $TMPDIR and $CACHE prefixes. Package
// names under $NODE_MODULES and $PKG are stable identifiers — collapsing
// them destroys lockfile signal and causes spurious deduplication.
// System noise (kernel/libc/ICU/proc reads) is filtered separately in
// normalize.ts; this module is concerned only with rewriting paths it's given.

export interface TokenizeRoots {
  repo: string; // absolute path of the repo bind-mount inside the VM, e.g. "/work"
  nodeModules: string; // typically `${repo}/node_modules`
  home: string; // e.g. "/root"
  tmp: string; // e.g. "/tmp" — follows os.tmpdir(), i.e. the scratch tmp when init.sh redirects TMPDIR
  /**
   * Optional SECOND prefix that also renders as `$TMPDIR`.  When the guest's
   * init.sh points TMPDIR at the scratch disk (`/scratch/tmp`), `tmp` above
   * follows it via os.tmpdir() — but tools that ignore TMPDIR still write to
   * the literal `/tmp` tmpfs.  Without this alias those writes would surface
   * as raw `/tmp/...` paths (with uncollapsed hash names), breaking both
   * determinism and cross-backend parity.  Leave unset when `tmp` IS `/tmp`.
   */
  tmpLegacy?: string;
  cache: string; // per-manager, e.g. "/root/.local/share/pnpm/store"
}

/**
 * Strip trailing slashes from a path prefix, preserving a lone root `/`.
 * The root prefixes in {@link TokenizeRoots} are derived from `config.work_dir`
 * (which can arrive with a trailing slash from SCRIPT_JAIL_REPO_DIR /
 * GITHUB_WORKSPACE / a config override). Every prefix comparison here and in
 * normalize.ts / protected-paths.ts uses segment-boundary semantics
 * (`path[root.length] === '/'`) that BREAK when the root itself ends in '/',
 * which would silently drop genuine repo/node_modules events. Canonicalize the
 * roots ONCE at construction (see agent.ts) with this shared helper so the
 * package-manager matcher AND normalize agree. No-op for clean roots.
 */
export function stripTrailingSlashes(p: string): string {
  let end = p.length;
  while (end > 1 && p[end - 1] === '/') end--;
  return end === p.length ? p : p.slice(0, end);
}

/**
 * Canonicalize EVERY root prefix by stripping trailing slashes, so the
 * segment-boundary prefix checks in tokenize / normalize.isUnderRoot /
 * ProtectedPathsMatcher never mis-fire on a trailing-slash root. The SAME helper
 * is used by both ProtectedPathsMatcher (emit-time protected-path policy) and
 * normalize (lock rendering) so they agree on what is "under" each root.
 *
 * ALL prefixes — not just repo/nodeModules — must be canonicalized: the matcher
 * tokenizes a probed path against EVERY root, so a trailing slash on `home`
 * makes `tokenize('/home/u/.ssh/id_rsa')` fail the boundary check (the byte after
 * the prefix is '.', not '/'), leaving the path UN-tokenized so a protected
 * pattern like `$HOME/.ssh/**` no longer matches — and the ENOENT probe of a real
 * secret is then dropped as unprotected noise (a false negative, NOT cosmetic).
 * The same risk applies to `$TMPDIR`/`$CACHE` protected patterns, so tmp,
 * tmpLegacy and cache are stripped too. (Internal double slashes — e.g.
 * `home//Library` — are a CONSTRUCTION bug fixed at the source by canonicalizing
 * the base BEFORE deriving children; this helper only fixes trailing slashes.)
 */
export function canonicalizeTokenizeRoots(roots: TokenizeRoots): TokenizeRoots {
  return {
    ...roots,
    repo: stripTrailingSlashes(roots.repo),
    nodeModules: stripTrailingSlashes(roots.nodeModules),
    home: stripTrailingSlashes(roots.home),
    tmp: stripTrailingSlashes(roots.tmp),
    ...(roots.tmpLegacy !== undefined ? { tmpLegacy: stripTrailingSlashes(roots.tmpLegacy) } : {}),
    cache: stripTrailingSlashes(roots.cache),
  };
}

const HASH_PATTERN = /[A-Za-z0-9_-]{16,}/g;
const TEMP_SUFFIX = /\.tmp(\.[A-Za-z0-9]+)?$/;
// Yarn Berry (@yarnpkg/fslib `getTempName`) launches binary lifecycle scripts via a
// transient shim it writes to a temp dir named `xfs-<hash>`, where the hash is
// `Math.ceil(Math.random()*0x100000000).toString(16).padStart(8,'0')` — 8 lowercase hex
// digits, occasionally 9 (when the value reaches 2^32). That `xfs-<8-9hex>` segment is only
// 12-13 chars, below HASH_PATTERN's 16 floor, so it would otherwise pass through verbatim and
// make the path per-run-random (e.g. `$TMPDIR/xfs-021cebd2/husky`). Collapse the segment
// to `<hash>` (matching how a long `xfs-<32hex>` segment already collapses via HASH_PATTERN).
//
// ANCHORED to the FIRST segment directly under `$TMPDIR` on purpose (codex
// adversarial-review #3 — over-mask). `getTempName` creates the launcher dir
// directly under the fslib temp root (= the guest TMPDIR), so the real shape is
// always `$TMPDIR/xfs-<hash>/…` at depth 1 — exactly what the napi-rs flake showed.
// A GLOBAL/unanchored rule would also collapse a NESTED stable segment
// (`$TMPDIR/stable/xfs-deadbeef/…`) or a `$CACHE/…/xfs-<hex>/…` content-store path
// — attacker-influenceable stable names whose collapse would dedupe distinct audit
// entries and DESTROY signal. Restricting to the leading `$TMPDIR/xfs-<hex>` keeps
// the determinism fix while preserving every other path verbatim. NOT applied under
// `$CACHE` (Yarn never writes these launchers there). No `g` flag: a single
// start-anchored match.
const YARN_FSLIB_TEMP = /^(\$TMPDIR\/)xfs-[0-9a-f]{8,9}(?=\/|$)/;

export function tokenize(rawPath: string, roots: TokenizeRoots, currentPkgDir?: string): string {
  if (!rawPath.startsWith('/')) {
    // Already relative — leave alone (rare; strace usually resolves AT_FDCWD).
    return rawPath;
  }
  // longest-prefix wins. Order matters: $PKG (most specific) before $NODE_MODULES before $REPO.
  const prefixes: Array<[string, string] | null> = [
    currentPkgDir ? [currentPkgDir, '$PKG'] : null,
    [roots.nodeModules, '$NODE_MODULES'],
    [roots.repo, '$REPO'],
    [roots.cache, '$CACHE'],
    [roots.home, '$HOME'],
    [roots.tmp, '$TMPDIR'],
    roots.tmpLegacy !== undefined ? [roots.tmpLegacy, '$TMPDIR'] : null,
  ];
  // Sort by prefix length descending so $PKG beats $NODE_MODULES beats $REPO.
  const sorted = prefixes
    .filter((p): p is [string, string] => p !== null)
    .sort((a, b) => b[0].length - a[0].length);
  for (const [prefix, token] of sorted) {
    if (pathHasPrefix(rawPath, prefix)) {
      const tail = rawPath.slice(prefix.length) || '/';
      const tokenized = `${token}${tail === '/' ? '' : tail}`;
      // Only collapse unstable content-hash filenames under $TMPDIR and $CACHE.
      // $NODE_MODULES and $PKG paths contain package names that are stable
      // identifiers — collapsing them destroys lockfile signal.
      if (token === '$TMPDIR' || token === '$CACHE') {
        return collapseUnstable(tokenized);
      }
      return tokenized;
    }
  }
  // Unmatched absolute path (e.g. /usr/bin/node) — no collapse.
  return rawPath;
}

function pathHasPrefix(path: string, prefix: string): boolean {
  if (!path.startsWith(prefix)) return false;
  // /work matches /work and /work/x but not /worker.
  return path.length === prefix.length || path[prefix.length] === '/';
}

function collapseUnstable(path: string): string {
  let out = path;
  if (TEMP_SUFFIX.test(out)) out = out.replace(TEMP_SUFFIX, '.tmp<hash>');
  out = out.replace(YARN_FSLIB_TEMP, '$1<hash>');
  out = out.replace(HASH_PATTERN, (match) => {
    // Don't collapse short alphanumerics that happen to be ≥16 chars but look like words.
    if (/^[A-Z][A-Za-z]{15,}$/.test(match)) return match;
    return '<hash>';
  });
  return out;
}

// True when `tokenizedPath` lies inside the current package's own subtree
// (i.e. starts with `$PKG`). Used by normalize.ts to drop intra-package reads.
export function isInsidePkg(tokenizedPath: string): boolean {
  return tokenizedPath === '$PKG' || tokenizedPath.startsWith('$PKG/');
}

// True when `tokenizedPath` lies inside another package's subtree:
// inside $NODE_MODULES but not the current $PKG.
export function isCrossPackage(tokenizedPath: string): boolean {
  return (
    !isInsidePkg(tokenizedPath) &&
    (tokenizedPath === '$NODE_MODULES' || tokenizedPath.startsWith('$NODE_MODULES/'))
  );
}

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
// Unstable filename patterns collapse to <hash>.
// System noise (kernel/libc/ICU/proc reads) is filtered separately in
// normalize.ts; this module is concerned only with rewriting paths it's given.

export interface TokenizeRoots {
  repo: string; // absolute path of the repo bind-mount inside the VM, e.g. "/work"
  nodeModules: string; // typically `${repo}/node_modules`
  home: string; // e.g. "/root"
  tmp: string; // e.g. "/tmp"
  cache: string; // per-manager, e.g. "/root/.local/share/pnpm/store"
}

const HASH_PATTERN = /[A-Za-z0-9_-]{16,}/g;
const TEMP_SUFFIX = /\.tmp(\.[A-Za-z0-9]+)?$/;

export function tokenize(rawPath: string, roots: TokenizeRoots, currentPkgDir?: string): string {
  if (!rawPath.startsWith('/')) {
    // Already relative — leave alone (rare; strace usually resolves AT_FDCWD).
    return collapseUnstable(rawPath);
  }
  // longest-prefix wins. Order matters: $PKG (most specific) before $NODE_MODULES before $REPO.
  const prefixes: Array<[string, string] | null> = [
    currentPkgDir ? [currentPkgDir, '$PKG'] : null,
    [roots.nodeModules, '$NODE_MODULES'],
    [roots.repo, '$REPO'],
    [roots.cache, '$CACHE'],
    [roots.home, '$HOME'],
    [roots.tmp, '$TMPDIR'],
  ];
  // Sort by prefix length descending so $PKG beats $NODE_MODULES beats $REPO.
  const sorted = prefixes
    .filter((p): p is [string, string] => p !== null)
    .sort((a, b) => b[0].length - a[0].length);
  for (const [prefix, token] of sorted) {
    if (pathHasPrefix(rawPath, prefix)) {
      const tail = rawPath.slice(prefix.length) || '/';
      return collapseUnstable(`${token}${tail === '/' ? '' : tail}`);
    }
  }
  return collapseUnstable(rawPath);
}

function pathHasPrefix(path: string, prefix: string): boolean {
  if (!path.startsWith(prefix)) return false;
  // /work matches /work and /work/x but not /worker.
  return path.length === prefix.length || path[prefix.length] === '/';
}

function collapseUnstable(path: string): string {
  let out = path;
  if (TEMP_SUFFIX.test(out)) out = out.replace(TEMP_SUFFIX, '.tmp<hash>');
  out = out.replace(HASH_PATTERN, (match) => {
    // Don't collapse the token itself (e.g. $PKG, $REPO) — those start with $.
    if (match.startsWith('$')) return match;
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

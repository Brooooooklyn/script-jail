import {
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export interface StagedRepo {
  path: string;
  cleanup(): void;
}

export function stageRepoDirectory(input: {
  repoDir: string;
  parentDir: string;
  extraRepoOverlayFiles: ReadonlyArray<{ relPath: string; content: string }>;
}): StagedRepo {
  const stageRoot = mkdtempSync(join(input.parentDir, 'repo-stage-'));
  const repoStage = join(stageRoot, 'work');
  // SECURITY (Codex re-review, staged-symlink escape): `verbatimSymlinks` keeps a
  // committed RELATIVE symlink relative in the staged copy. WITHOUT it, cpSync
  // (dereference:false) rewrites a relative symlink to its REALPATH absolute target
  // in the ORIGINAL checkout, so the audit resolves it to a path that does not exist
  // in the sandbox (ENOENT → read dropped) while host part-2 resolves the original
  // relative link and EXECUTES the file host part-1 created — un-audited code under a
  // trusted lock. Verbatim makes the link resolve identically (relative, within the
  // tree) on both sides. No byte-stability impact: no committed symlink exists in any
  // fixture, so this is a no-op for current inputs.
  cpSync(input.repoDir, repoStage, { recursive: true, dereference: false, verbatimSymlinks: true });
  materializeExtraFiles(repoStage, input.extraRepoOverlayFiles);
  return {
    path: repoStage,
    cleanup: () => {
      rmSync(stageRoot, { recursive: true, force: true });
    },
  };
}

export function materializeExtraFiles(
  rootDir: string,
  files: ReadonlyArray<{ relPath: string; content: string }>,
): void {
  const root = resolve(rootDir);
  for (const entry of files) {
    const dest = resolve(root, entry.relPath);
    if (dest !== root && !dest.startsWith(root + '/')) {
      throw new Error(
        `[backend] extraRepoOverlayFiles entry '${entry.relPath}' escapes the staged repo`,
      );
    }
    writeOverlayFile(root, entry.relPath, entry.content);
  }
}

function writeOverlayFile(root: string, relPath: string, content: string): void {
  const parts = relPath.split('/').filter((part) => part.length > 0);
  if (parts.length === 0 || parts.some((part) => part === '..')) {
    throw new Error(
      `[backend] extraRepoOverlayFiles entry '${relPath}' is not a safe relative path`,
    );
  }

  let dir = root;
  for (const part of parts.slice(0, -1)) {
    dir = join(dir, part);
    ensureRealDirectory(dir);
  }

  const dest = join(dir, parts[parts.length - 1]!);
  // SECURITY (Codex re-review, gitlink leaf gap): the LEAF must not already exist in
  // the checkout.  ensureRealDirectory above inspects only the PARENT segments
  // (…/etc, …/etc/script-jail); it never looks at the final component.  A committed
  // gitlink/submodule (git index mode 160000) at e.g. `etc/script-jail/pm-flags.json`
  // checks out as a real (empty) DIRECTORY — and the reserved-path gate's recursive
  // readdir historically skipped directory entries, so it slipped through.  The old
  // `rmSync(dest, {recursive}); writeFileSync` would delete that directory and write
  // our sidecar in the STAGED copy ONLY: the host's real checkout keeps the gitlink
  // dir, so a lifecycle script doing `statSync('etc/script-jail/pm-flags.json')
  // .isDirectory()` (or readdir/existsSync of a child) diverges — the audit sees a
  // file, the host a directory — a host-vs-sandbox split the value-blind lock cannot
  // capture.  Fail closed: lstat first (NO-follow) and throw on ANY pre-existing
  // entry (gitlink dir, plain committed dir, symlink, OR file).  script-jail OWNS
  // this path and creates it fresh, so on a clean checkout the leaf never pre-exists.
  let leaf: ReturnType<typeof lstatSync> | undefined;
  try {
    leaf = lstatSync(dest);
  } catch {
    leaf = undefined; // absent — the normal case.
  }
  if (leaf !== undefined) {
    const kind = leaf.isSymbolicLink()
      ? 'symlink'
      : leaf.isDirectory()
        ? 'directory (a committed gitlink/submodule or plain directory)'
        : 'file';
    throw new Error(
      `[backend] cannot stage script-jail overlay: the checkout already has a ${kind} at ` +
        `'${dest}' — script-jail OWNS this path and writes its own sidecar here. It refuses ` +
        `to replace committed checkout content (under install:true that would also diverge ` +
        `the audit from the host re-run). Remove it from the checkout.`,
    );
  }
  writeFileSync(dest, content, { encoding: 'utf8', flag: 'wx' });
}

function ensureRealDirectory(path: string): void {
  let stat;
  try {
    // lstat (no-follow on the FINAL component): inspect THIS ancestor segment
    // itself.  writeOverlayFile calls this per-segment (…/etc, then …/etc/script-jail),
    // so a symlinked `etc` is seen as a symlink here even though a joined-path lstat
    // would have followed it.
    stat = lstatSync(path);
  } catch {
    mkdirSync(path, { recursive: true }); // absent → create a real dir
    return;
  }
  if (stat.isDirectory() && !stat.isSymbolicLink()) return; // already a real dir
  // SECURITY (Codex re-review, overlay-ancestor-symlink escape): the segment EXISTS
  // but is NOT a real directory — a committed SYMLINK (incl. dangling / symlink-to-dir)
  // or a regular FILE.  The old code rm+mkdir-REPLACED it, which mutates the staged copy
  // ONLY: the host's real checkout keeps the committed symlink/file, so host part-2
  // resolves a path (e.g. `etc/x` through a committed `etc -> payload`) to PR content
  // the audit — seeing a fresh real dir — never resolved (ENOENT, dropped), executing it
  // under a trusted lock.  Fail closed: throwing aborts the audit (untrusted ⇒ no host
  // install).  This is the single chokepoint covering every overlay path × ancestor
  // segment × backend.
  throw new Error(
    `[backend] cannot stage script-jail overlay: the checkout has a non-directory at ` +
      `'${path}' (a committed symlink or file) where script-jail needs a real directory. ` +
      `install:true refuses to replace it — that would make the audit diverge from the ` +
      `host checkout. Remove it from the checkout, or audit without 'install'.`,
  );
}

export function rewriteConfigWorkDir(input: {
  configPath: string;
  outDir: string;
  workDir: string;
}): string {
  const raw = readFileSync(input.configPath, 'utf8');
  const parsed = parseYaml(raw) as unknown;
  const config: Record<string, unknown> =
    parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? { ...(parsed as Record<string, unknown>) }
      : {};
  config['work_dir'] = input.workDir;

  const outPath = join(input.outDir, 'config.backend.yml');
  writeFileSync(outPath, stringifyYaml(config), 'utf8');
  return outPath;
}

// ---------------------------------------------------------------------------
// Control-sidecar delivery (out-of-repo)
// ---------------------------------------------------------------------------
//
// SECURITY (Codex re-review, audit-only sidecar oracle): script-jail's OWN control
// files (pm-flags.json / pnpm-arch.json — `config.yml` is delivered separately) must
// NOT live at any lifecycle-visible filesystem path.  Under install:true the host
// re-runs lifecycle scripts at the REAL checkout, which has no `etc/script-jail/` — so a
// sidecar staged at `<work>/etc/script-jail/pm-flags.json` (in-repo) OR bind-mounted at
// `/etc/script-jail/pm-flags.json` (absolute) is a host-vs-audit presence/content oracle
// the value-blind lock can't capture (a lifecycle script branching on
// `fs.existsSync('/etc/script-jail/pm-flags.json')` takes the benign path in the audit,
// the payload path on the host).  These are pure DELIVERY vehicles — the guest only
// needs the bytes — so we deliver the bytes as env CONTENT instead of a file: the guest
// reads `SCRIPT_JAIL_{PM_FLAGS,PNPM_ARCH}_CONTENT` from the AGENT's process env, which
// `buildChildEnv` strips from every lifecycle child.  No file is ever placed where a
// lifecycle script can stat it.  `config.yml` is the one control file that must stay a
// file (the agent reads it; on Docker it is a read-only bind it cannot unlink) — a
// documented irreducible residual, same class as LD_PRELOAD.

const RESERVED_SIDECAR_DIR = 'etc/script-jail';

/** Map a control-sidecar basename → the env var the guest reads its CONTENT from. */
const CONTROL_SIDECAR_ENV_BY_NAME: Readonly<Record<string, string>> = {
  'pm-flags.json': 'SCRIPT_JAIL_PM_FLAGS_CONTENT',
  'pnpm-arch.json': 'SCRIPT_JAIL_PNPM_ARCH_CONTENT',
};

export interface OverlayFile {
  relPath: string;
  content: string;
}

/**
 * Split overlay files into the script-jail control sidecars (anything under
 * `etc/script-jail/`) and the genuine repo-relative overlays (e.g. `.yarnrc.yml`,
 * which is real package-manager config the host install also reads at the repo root
 * and therefore MUST stay in the staged tree).  Stage-at-repo-root backends stage
 * only `repoOverlay` and deliver `controlSidecars` out-of-repo (as env content).
 */
export function partitionControlSidecars(files: ReadonlyArray<OverlayFile>): {
  repoOverlay: OverlayFile[];
  controlSidecars: OverlayFile[];
} {
  const repoOverlay: OverlayFile[] = [];
  const controlSidecars: OverlayFile[] = [];
  for (const f of files) {
    if (f.relPath === RESERVED_SIDECAR_DIR || f.relPath.startsWith(`${RESERVED_SIDECAR_DIR}/`)) {
      controlSidecars.push(f);
    } else {
      repoOverlay.push(f);
    }
  }
  return { repoOverlay, controlSidecars };
}

/**
 * Build the guest env vars that carry each control sidecar's CONTENT directly.
 * Returns a `{ SCRIPT_JAIL_PM_FLAGS_CONTENT: <json>, … }` dict the backend merges into
 * the agent's process env (docker `-e`, bare/mac-bare process env).  No file is written
 * anywhere — the bytes ride only the agent's env, never a lifecycle-visible path.  A
 * sidecar with an unrecognized basename is ignored (the guest has no reader for it).
 */
export function controlSidecarEnv(
  controlSidecars: ReadonlyArray<OverlayFile>,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const entry of controlSidecars) {
    const name = entry.relPath.split('/').filter((p) => p.length > 0).pop();
    const envName = name !== undefined ? CONTROL_SIDECAR_ENV_BY_NAME[name] : undefined;
    if (envName !== undefined) env[envName] = entry.content;
  }
  return env;
}

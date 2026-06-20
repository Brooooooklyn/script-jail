import {
  cpSync,
  existsSync,
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
  rmSync(dest, { recursive: true, force: true });
  writeFileSync(dest, content, { encoding: 'utf8', flag: 'wx' });
}

function ensureRealDirectory(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
    return;
  }
  const stat = lstatSync(path);
  if (stat.isDirectory() && !stat.isSymbolicLink()) return;
  rmSync(path, { recursive: true, force: true });
  mkdirSync(path, { recursive: true });
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

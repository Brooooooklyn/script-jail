// script-jail — test/action/install-preflight.test.ts
//
// Unit tests for the `install: true` pre-trust config-exec detector.  Each
// vector was empirically reproduced against pnpm 10.34/11.1 and yarn Berry 4.16
// (see the module header); these tests pin the static detection that refuses
// install before any of that code can run on the runner.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  detectPreTrustConfigExec,
  detectInstallWorkDirDivergence,
  detectCheckoutRelativeHome,
} from '../../src/action/install-preflight.js';

let dir: string;
beforeEach(() => {
  // realpathSync resolves the macOS /var -> /private/var symlink so the path
  // equality checks in the ancestor-scan boundary logic match what callers see.
  dir = realpathSync(mkdtempSync(join(tmpdir(), 'sj-preflight-')));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const write = (rel: string, content: string): void => {
  const full = join(dir, rel);
  mkdirSync(join(full, '..'), { recursive: true });
  writeFileSync(full, content);
};

/** Write `content` to an absolute path, creating parent dirs. */
const writeAt = (full: string, content: string): void => {
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
};

describe('detectPreTrustConfigExec — npm', () => {
  it('returns null even with a .pnpmfile.cjs / .yarnrc.yml present (npm ignores both)', () => {
    write('.pnpmfile.cjs', 'module.exports = {}');
    write('.yarnrc.yml', 'yarnPath: ./x.cjs\n');
    // npm has no pnpmfile/yarnrc surface; its only pre-trust config exec (the git
    // binary) is handled by the npm_config_git pin, not here.
    expect(detectPreTrustConfigExec(dir, 'npm')).toBeNull();
  });
});

describe('detectPreTrustConfigExec — pnpm', () => {
  it('blocks a default .pnpmfile.cjs', () => {
    write('.pnpmfile.cjs', 'console.log("hi")');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/\.pnpmfile\.cjs/);
  });

  it('does NOT block a dot-less pnpmfile.cjs (not a pnpm default)', () => {
    write('pnpmfile.cjs', 'console.log("hi")');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a default .pnpmfile.mjs (pnpm 11 prefers it over .cjs)', () => {
    write('.pnpmfile.mjs', 'export const hooks = {}');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/\.pnpmfile\.mjs/);
  });

  it('does NOT block a dot-less pnpmfile.mjs (not a pnpm default)', () => {
    write('pnpmfile.mjs', 'export const hooks = {}');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a .npmrc pnpmfile= relocation', () => {
    write('.npmrc', 'pnpmfile=./evil.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpmfile/);
  });

  it('blocks a .npmrc global-pnpmfile= relocation (case/space tolerant)', () => {
    write('.npmrc', '  Global-Pnpmfile = ./evil.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/global-pnpmfile/i);
  });

  it('ignores a commented-out pnpmfile= line', () => {
    write('.npmrc', '; pnpmfile=./evil.cjs\n# global-pnpmfile=./x\nregistry=https://r/\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a pnpm-workspace.yaml pnpmfile: key', () => {
    write('pnpm-workspace.yaml', 'pnpmfile: ./evil.cjs\npackages:\n  - "pkgs/*"\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpm-workspace\.yaml/);
  });

  it('blocks a pnpm-workspace.yaml configDependencies: key', () => {
    write('pnpm-workspace.yaml', 'configDependencies:\n  my-cfg: 1.0.0+sha512-x\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/pnpm-workspace\.yaml/);
  });

  it('fails closed on an unparseable pnpm-workspace.yaml', () => {
    write('pnpm-workspace.yaml', 'pnpmfile: : : [unbalanced\n  - {');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/unparseable/);
  });

  it('blocks a package.json pnpm.configDependencies (pnpm 10 fetch/extract vector)', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { configDependencies: { 'my-cfg': '1.0.0+sha512-deadbeef' } } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.json/);
  });

  it('blocks a package.json pnpm.pnpmfile (defense in depth)', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { pnpmfile: './evil.cjs' } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.json/);
  });

  it('fails closed on an unparseable package.json', () => {
    write('package.json', '{ not: valid json ');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/unparseable root .package\.json/);
  });

  it('does NOT block a package.json with a benign pnpm block', () => {
    write('package.json', JSON.stringify({ name: 'x', pnpm: { onlyBuiltDependencies: ['esbuild'] } }));
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('blocks a package.yaml root manifest with no package.json (pnpm 10 reads its pnpm config)', () => {
    write('package.yaml', 'name: x\npnpm:\n  configDependencies:\n    cfg: "1.0.0+sha512-deadbeef"\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.yaml/);
  });

  it('blocks a package.json5 root manifest with no package.json', () => {
    write('package.json5', '{ name: "x", /* json5 */ }');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toMatch(/package\.json5/);
  });

  it('does NOT block package.yaml when a package.json also exists (package.json shadows it)', () => {
    write('package.json', '{"name":"x"}');
    write('package.yaml', 'pnpm:\n  configDependencies:\n    cfg: "1.0.0+sha512-x"\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });

  it('returns null for a clean pnpm repo (lock + plain workspace, no hooks)', () => {
    write('package.json', '{"name":"x"}');
    write('pnpm-workspace.yaml', 'packages:\n  - "pkgs/*"\n');
    write('.npmrc', 'registry=https://registry.npmjs.org/\n');
    expect(detectPreTrustConfigExec(dir, 'pnpm')).toBeNull();
  });
});

describe('detectPreTrustConfigExec — yarn (Berry)', () => {
  it('blocks .yarnrc.yml yarnPath', () => {
    write('.yarnrc.yml', 'yarnPath: ./.evil-yarn.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/yarnPath/);
  });

  it('blocks .yarnrc.yml plugins (object form)', () => {
    write('.yarnrc.yml', 'plugins:\n  - path: ./p.cjs\n    spec: "@x/y"\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/plugins/);
  });

  it('blocks .yarnrc.yml plugins (string form)', () => {
    write('.yarnrc.yml', 'plugins:\n  - ./p.cjs\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/plugins/);
  });

  it('does NOT block an empty plugins array', () => {
    write('.yarnrc.yml', 'plugins: []\nnodeLinker: node-modules\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('blocks enableConstraintsChecks:true WHEN a yarn.config.cjs is present', () => {
    write('.yarnrc.yml', 'enableConstraintsChecks: true\n');
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/enableConstraintsChecks/);
  });

  it.each(['1', "'1'", 'true', '"true"'])('blocks enableConstraintsChecks:%s (every yarn-enabling representation) with a yarn.config.cjs', (val) => {
    write('.yarnrc.yml', `enableConstraintsChecks: ${val}\n`);
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/enableConstraintsChecks/);
  });

  it.each(['false', '0', '"false"'])('does NOT block enableConstraintsChecks:%s (definitely false)', (val) => {
    write('.yarnrc.yml', `enableConstraintsChecks: ${val}\n`);
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('does NOT block enableConstraintsChecks:true without a yarn.config file (hook no-ops)', () => {
    write('.yarnrc.yml', 'enableConstraintsChecks: true\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('does NOT block enableConstraintsChecks:true with only a yarn.config.js (yarn loads .cjs only)', () => {
    // yarn Berry's loadUserConfig() hardcodes the literal `yarn.config.cjs`
    // (verified 4.5.0–4.16.0); a `yarn.config.js` is never executed, so an inert
    // one must not over-fire the gate.
    write('.yarnrc.yml', 'enableConstraintsChecks: true\n');
    write('yarn.config.js', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('does NOT block a yarn.config.cjs when the flag is off (default false)', () => {
    write('.yarnrc.yml', 'nodeLinker: node-modules\n');
    write('yarn.config.cjs', 'module.exports = {}');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('fails closed on a present-but-unparseable .yarnrc.yml', () => {
    write('.yarnrc.yml', 'yarnPath: : : [unbalanced\n  - {');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toMatch(/unparseable/);
  });

  it('returns null when there is no .yarnrc.yml (classic .yarnrc is not a Berry vector)', () => {
    write('.yarnrc', 'yarn-path "./x.js"\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });

  it('returns null for a clean Berry repo (benign .yarnrc.yml)', () => {
    write('.yarnrc.yml', 'nodeLinker: node-modules\nenableTelemetry: false\n');
    expect(detectPreTrustConfigExec(dir, 'yarn')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Ancestor-rc scan (yarn Berry): when repoDir is a SUBDIRECTORY of the
// workspace checkout, Yarn Berry walks UP parent dirs and loads `plugins:` /
// `yarnPath` from an ANCESTOR `.yarnrc.yml` at startup — executing repo code on
// the runner pre-trust.  The preflight scans every dir from repoDir up to and
// INCLUDING workspaceRoot, but NEVER above it (parent dirs / ~ are runner-owned).
// ---------------------------------------------------------------------------
describe('detectPreTrustConfigExec — yarn ancestor .yarnrc.yml scan', () => {
  it('blocks a plugins: entry in an ANCESTOR .yarnrc.yml within the workspace', () => {
    // repoDir = <ws>/pkg ; the offending rc lives at <ws>/.yarnrc.yml.
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    const reason = detectPreTrustConfigExec(pkg, 'yarn', ws);
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/plugins/);
  });

  it('blocks a yarnPath in an ANCESTOR .yarnrc.yml and names the ancestor dir', () => {
    const ws = dir;
    const pkg = join(ws, 'apps', 'web');
    writeAt(join(ws, '.yarnrc.yml'), 'yarnPath: ./.evil-yarn.cjs\n');
    writeAt(join(pkg, 'package.json'), '{"name":"web"}');
    const reason = detectPreTrustConfigExec(pkg, 'yarn', ws);
    expect(reason).toMatch(/yarnPath/);
    // The error should mention the ancestor dir (not repoDir) so the message is clear.
    expect(reason).toContain(ws);
  });

  it('does NOT scan a .yarnrc.yml ABOVE the workspace root (out of PR scope)', () => {
    // Layout: <root>/ws is the workspace; the offending rc is at <root>/.yarnrc.yml
    // (above ws).  repoDir === ws.  Must never walk above workspaceRoot.
    const root = dir;
    const ws = join(root, 'ws');
    writeAt(join(root, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(ws, 'package.json'), '{"name":"ws"}');
    expect(detectPreTrustConfigExec(ws, 'yarn', ws)).toBeNull();
  });

  it('repoDir === workspaceRoot: ancestor-only rc absent → no false reject', () => {
    const ws = dir;
    writeAt(join(ws, '.yarnrc.yml'), 'nodeLinker: node-modules\n');
    writeAt(join(ws, 'package.json'), '{"name":"ws"}');
    expect(detectPreTrustConfigExec(ws, 'yarn', ws)).toBeNull();
  });

  it('repoDir === workspaceRoot: an at-repoDir plugins rc still blocks (existing behavior preserved)', () => {
    const ws = dir;
    writeAt(join(ws, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    expect(detectPreTrustConfigExec(ws, 'yarn', ws)).toMatch(/plugins/);
  });

  it('repoDir OUTSIDE workspaceRoot (e2e-style): scans only repoDir, ignores rc above it', () => {
    // repoDir is a consumer dir staged outside the checkout (RUNNER_TEMP).  An
    // ancestor rc ABOVE the consumer dir is runner-owned and must NOT be inspected.
    const consumerParent = join(dir, 'tmpx');
    const consumer = join(consumerParent, 'consumer');
    const checkout = join(dir, 'checkout');
    writeAt(join(consumerParent, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(consumer, 'package.json'), '{"name":"consumer"}');
    writeAt(join(checkout, 'package.json'), '{"name":"checkout"}');
    // consumer is NOT inside checkout → scan only consumer (which is clean).
    expect(detectPreTrustConfigExec(consumer, 'yarn', checkout)).toBeNull();
  });

  it('repoDir OUTSIDE workspaceRoot: an rc AT repoDir still blocks', () => {
    const consumer = join(dir, 'tmpx', 'consumer');
    const checkout = join(dir, 'checkout');
    writeAt(join(consumer, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    expect(detectPreTrustConfigExec(consumer, 'yarn', checkout)).toMatch(/plugins/);
  });

  it('workspaceRoot omitted/undefined: scans only repoDir (back-compat)', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    // No workspaceRoot → behave exactly as before (scan only repoDir, which is clean).
    expect(detectPreTrustConfigExec(pkg, 'yarn')).toBeNull();
  });

  it('ancestor enableConstraintsChecks + a yarn.config.cjs at the ancestor project root blocks', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'enableConstraintsChecks: true\n');
    writeAt(join(ws, 'yarn.config.cjs'), 'module.exports = {}');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'yarn', ws)).toMatch(/enableConstraintsChecks/);
  });

  it('blocks ancestor enableConstraintsChecks + a yarn.config.cjs at the INSTALL-CWD subdir (codex idx-11 bypass)', () => {
    // The real Yarn behavior (VERIFIED 4.5.0): the `enableConstraintsChecks` FLAG
    // cascades down from the ancestor rc, but yarn loads `yarn.config.cjs` from the
    // INSTALL-CWD project root (the audited subdir), NOT the rc's dir.  The old gate
    // checked only the rc's dir (ws), so this layout — flag at ws, config at the
    // audited pkg — slipped through and let attacker code run IN-AUDIT.  Must block.
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'enableConstraintsChecks: true\n');
    writeAt(join(pkg, 'yarn.config.cjs'), 'module.exports = {}'); // at the install cwd, NOT ws
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'yarn', ws)).toMatch(/enableConstraintsChecks/);
  });

  it('does NOT block ancestor enableConstraintsChecks with NO yarn.config.cjs anywhere (hook no-ops)', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'enableConstraintsChecks: true\n');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'yarn', ws)).toBeNull();
  });

  it('blocks ancestor enableConstraintsChecks + yarn.config.cjs at an INTERMEDIATE project root (codex chain-check)', () => {
    // repoDir = <ws>/project/packages/app (a workspace member, no own lock); yarn's
    // actual project root is <ws>/project with <ws>/project/yarn.config.cjs; the
    // enabling rc is the outer <ws>/.yarnrc.yml.  VERIFIED yarn 4.5.0: running from
    // packages/app loads <ws>/project/yarn.config.cjs — NEITHER repoDir NOR the rc's
    // dir — so the gate must scan the whole repoDir->workspaceRoot chain.
    const ws = dir;
    const app = join(ws, 'project', 'packages', 'app');
    writeAt(join(ws, '.yarnrc.yml'), 'enableConstraintsChecks: true\n');
    writeAt(join(ws, 'project', 'yarn.config.cjs'), 'module.exports = {}'); // intermediate root
    writeAt(join(app, 'package.json'), '{"name":"app"}');
    expect(detectPreTrustConfigExec(app, 'yarn', ws)).toMatch(/enableConstraintsChecks/);
  });

  it('fails closed on an unparseable ANCESTOR .yarnrc.yml', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.yarnrc.yml'), 'yarnPath: : : [unbalanced\n  - {');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'yarn', ws)).toMatch(/unparseable/);
  });

  // Containment regression: a child directory whose NAME starts with ".." (e.g.
  // "..pkg") yields a `relative(ws, repo)` of "..pkg/app".  A naive
  // `startsWith('..')` containment check wrongly classifies that valid child as
  // OUTSIDE the workspace and skips the PR-controlled ancestors — leaving the
  // pre-trust startup-exec hole reachable.  It MUST be walked up to the workspace.
  it('blocks an ancestor rc when repoDir is a child named "..pkg" (dot-dot-prefix containment)', () => {
    const ws = dir;
    const pkg = join(ws, '..pkg', 'app');
    writeAt(join(ws, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(pkg, 'package.json'), '{"name":"app"}');
    expect(detectPreTrustConfigExec(pkg, 'yarn', ws)).toMatch(/plugins/);
  });

  // Symlink: a symlinked repoDir must be resolved to its real path so the walk
  // follows the ancestor chain Yarn actually reads on disk.
  it('resolves a symlinked repoDir before walking, still reaching the workspace ancestor rc', () => {
    const ws = dir;
    const app = join(ws, 'real', 'app');
    writeAt(join(ws, '.yarnrc.yml'), 'plugins:\n  - ./p.cjs\n');
    writeAt(join(app, 'package.json'), '{"name":"app"}');
    const link = join(ws, 'link');
    symlinkSync(join(ws, 'real'), link); // <ws>/link -> <ws>/real
    // repoDir given THROUGH the symlink; realpath => <ws>/real/app (under ws).
    expect(detectPreTrustConfigExec(join(link, 'app'), 'yarn', ws)).toMatch(/plugins/);
  });
});

// ---------------------------------------------------------------------------
// pnpm ancestor scan: configDependencies in an ANCESTOR pnpm-workspace.yaml /
// package.json is fetched + extracted pre-trust (NOT suppressed by the host
// `--ignore-pnpmfile` backstop, which only covers pnpmfile code-exec).  The
// pnpmfile vectors themselves are fully backstopped and need no ancestor scan.
// ---------------------------------------------------------------------------
describe('detectPreTrustConfigExec — pnpm ancestor configDependencies scan', () => {
  it('blocks configDependencies in an ANCESTOR pnpm-workspace.yaml within the workspace', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, 'pnpm-workspace.yaml'), 'configDependencies:\n  cfg: "1.0.0+sha512-deadbeef"\n');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'pnpm', ws)).toMatch(/configDependencies|pnpm-workspace\.yaml/);
  });

  it('blocks pnpm.configDependencies in an ANCESTOR package.json within the workspace', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, 'package.json'), JSON.stringify({ name: 'x', pnpm: { configDependencies: { cfg: '1.0.0+sha512-deadbeef' } } }));
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'pnpm', ws)).toMatch(/configDependencies|package\.json/);
  });

  it('does NOT block an ancestor .pnpmfile.cjs (host --ignore-pnpmfile backstops it)', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, '.pnpmfile.cjs'), 'console.log("hi")');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'pnpm', ws)).toBeNull();
  });

  it('does NOT scan configDependencies ABOVE the workspace root', () => {
    const root = dir;
    const ws = join(root, 'ws');
    writeAt(join(root, 'pnpm-workspace.yaml'), 'configDependencies:\n  cfg: "1.0.0+sha512-deadbeef"\n');
    writeAt(join(ws, 'package.json'), '{"name":"ws"}');
    expect(detectPreTrustConfigExec(ws, 'pnpm', ws)).toBeNull();
  });

  it('pnpm with workspaceRoot omitted scans only repoDir (back-compat)', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(ws, 'pnpm-workspace.yaml'), 'configDependencies:\n  cfg: "1.0.0+sha512-deadbeef"\n');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectPreTrustConfigExec(pkg, 'pnpm')).toBeNull();
  });

  // Same dot-dot-prefix containment regression as the yarn side: an ancestor
  // configDependencies must still be found when repoDir is a child named "..pkg".
  it('blocks ancestor configDependencies when repoDir is a child named "..pkg"', () => {
    const ws = dir;
    const pkg = join(ws, '..pkg', 'app');
    writeAt(join(ws, 'pnpm-workspace.yaml'), 'configDependencies:\n  cfg: "1.0.0+sha512-deadbeef"\n');
    writeAt(join(pkg, 'package.json'), '{"name":"app"}');
    expect(detectPreTrustConfigExec(pkg, 'pnpm', ws)).toMatch(/configDependencies/);
  });
});

// ---------------------------------------------------------------------------
// FIX 15: install + a diverging config `work_dir` → fail closed.
// ---------------------------------------------------------------------------
//
// `work_dir` (consumer config field, NO clamp) reaches the FC/docker guest
// verbatim, so the guest audits at `cwd=work_dir` (e.g. /work/packages/app)
// while host install/rebuild ALWAYS run at the repoDir ROOT (/work).  A benign
// subproject can then audit clean while host part-2 runs UN-AUDITED repo-root
// lifecycle scripts.  detectInstallWorkDirDivergence fails closed pre-trust on
// any work_dir that is not the staged repo root (`/work`).
describe('detectInstallWorkDirDivergence', () => {
  const configAt = (content: string): string => {
    const p = join(dir, '.script-jail.yml');
    writeFileSync(p, content);
    return p;
  };

  it('rejects a work_dir pointing at a subproject', () => {
    const reason = detectInstallWorkDirDivergence(configAt('work_dir: /work/packages/app\n'));
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/work_dir/);
    expect(reason).toContain('/work/packages/app');
    expect(reason).toMatch(/unaudited repo-root scripts/);
  });

  it('rejects any non-/work work_dir (even outside the staged tree)', () => {
    expect(detectInstallWorkDirDivergence(configAt('work_dir: /elsewhere\n'))).not.toBeNull();
  });

  it('allows an explicit work_dir of /work (the staged repo root)', () => {
    expect(detectInstallWorkDirDivergence(configAt('work_dir: /work\n'))).toBeNull();
  });

  it('allows an unset work_dir (defaults to /work)', () => {
    expect(detectInstallWorkDirDivergence(configAt('node_version: 20\n'))).toBeNull();
  });

  it('allows an absent config file (default work_dir /work)', () => {
    expect(detectInstallWorkDirDivergence(join(dir, 'does-not-exist.yml'))).toBeNull();
  });

  it('allows a malformed config (handled elsewhere)', () => {
    // A scalar / non-mapping yaml declares no work_dir mapping → not our concern.
    expect(detectInstallWorkDirDivergence(configAt('- just\n- a\n- list\n'))).toBeNull();
  });

  it('allows a non-string work_dir (e.g. numeric) — not a path divergence', () => {
    expect(detectInstallWorkDirDivergence(configAt('work_dir: 42\n'))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Checkout-relative $HOME (codex idx-20): package managers load config from
// $HOME at startup ($HOME/.yarnrc.yml plugins / $HOME/.npmrc script-shell), so a
// $HOME that resolves UNDER the checkout lets a PR-committed home config run code
// on the runner pre-trust — unseen by the sandbox (different HOME).  The
// repoDir->workspaceRoot ancestor scan does NOT cover a sibling/non-ancestor
// $HOME, so install must refuse when HOME is checkout-relative.
// ---------------------------------------------------------------------------
describe('detectCheckoutRelativeHome — refuse install on a checkout-relative $HOME', () => {
  it('refuses when HOME is a sibling subdir of repoDir inside the workspace ($WS/.home)', () => {
    const ws = dir;
    const pkg = join(ws, 'pkg');
    const home = join(ws, '.home'); // sibling of pkg, under the checkout — NOT on the repoDir->ws chain
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    writeAt(join(home, '.yarnrc.yml'), 'plugins:\n  - ./evil.cjs\n');
    const reason = detectCheckoutRelativeHome(home, pkg, ws);
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/HOME/);
  });

  it('refuses when HOME IS the workspace root (PR controls $WS/.yarnrc.yml)', () => {
    const ws = dir;
    writeAt(join(ws, 'package.json'), '{"name":"ws"}');
    expect(detectCheckoutRelativeHome(ws, ws, ws)).not.toBeNull();
  });

  it('refuses when HOME is under repoDir even with no workspaceRoot (local)', () => {
    const repo = dir;
    const home = join(repo, '.home');
    writeAt(join(home, '.npmrc'), 'script-shell=./pwn.sh\n');
    expect(detectCheckoutRelativeHome(home, repo)).not.toBeNull();
  });

  it('allows a HOME OUTSIDE the checkout (the normal runner home)', () => {
    const ws = join(dir, 'ws');
    const home = join(dir, 'runner-home'); // sibling of ws, NOT under it
    writeAt(join(ws, 'package.json'), '{"name":"ws"}');
    expect(detectCheckoutRelativeHome(home, ws, ws)).toBeNull();
  });

  it('allows HOME as an ANCESTOR of repoDir (repoDir = $HOME/project — the common case)', () => {
    const home = dir;
    const repo = join(home, 'project'); // repo is INSIDE home, home is NOT inside the checkout
    writeAt(join(repo, 'package.json'), '{"name":"p"}');
    expect(detectCheckoutRelativeHome(home, repo)).toBeNull();
  });

  it('allows an UNSET (undefined) HOME — PM falls back to the OS home (absolute, outside checkout)', () => {
    // VERIFIED npm 11.13.0: with HOME unset, `npm config get userconfig` is the real
    // user's `~/.npmrc` (absolute, outside the checkout) — not PR-controlled.
    expect(detectCheckoutRelativeHome(undefined, dir, dir)).toBeNull();
  });

  it('refuses an EMPTY-string HOME (npm reads a literal repoDir/~/.npmrc — round-7)', () => {
    // VERIFIED npm 11.13.0: `HOME=` leaves `~` UN-expanded, so npm (cwd=repoDir) reads a
    // LITERAL `repoDir/~/.npmrc` — a PR-committable `~` dir — and execs its script-shell on
    // rebuild.  '' is non-absolute, so it must be refused (NOT treated as "nothing to resolve").
    const reason = detectCheckoutRelativeHome('', dir, dir);
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/absolute/i);
  });

  it('refuses a RELATIVE HOME (subdir repo + `../.home` bypass — round-6)', () => {
    // The PM expands `~/.npmrc` against ITS cwd (=repoDir). For repoDir=$WS/pkg, a
    // relative HOME `../.home` lands at $WS/.home/.npmrc (PR-controlled, INSIDE the
    // checkout) — VERIFIED npm 11.13.0 reads it and execs its script-shell. But this
    // preflight runs in the action process whose cwd need not equal repoDir, so a
    // value-based containment test on a relative HOME could resolve elsewhere and pass.
    // Fail closed on ANY non-absolute HOME regardless of the action process cwd.
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    const reason = detectCheckoutRelativeHome('../.home', pkg, ws);
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/HOME/);
    expect(reason).toMatch(/absolute/i);
  });

  it('refuses ALL non-absolute HOME forms — even one that resolves outside from the action cwd', () => {
    // Fail-closed: a non-absolute HOME has no legit install use; we do not try to prove
    // a particular cwd makes it safe. `.home`, `../../x`, `~`-leading, and '' are all refused.
    const ws = dir;
    const pkg = join(ws, 'pkg');
    writeAt(join(pkg, 'package.json'), '{"name":"p"}');
    expect(detectCheckoutRelativeHome('.home', pkg, ws)).not.toBeNull();
    expect(detectCheckoutRelativeHome('../../elsewhere', pkg, ws)).not.toBeNull();
    expect(detectCheckoutRelativeHome('~/x', pkg, ws)).not.toBeNull(); // literal tilde is not absolute
    expect(detectCheckoutRelativeHome('', pkg, ws)).not.toBeNull(); // empty string is not absolute
  });
});

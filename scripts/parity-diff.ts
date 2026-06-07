// script-jail — scripts/parity-diff.ts
//
// Compare two .script-jail.lock.yml files for byte-equality after the same
// canonicalization that `src/action/diff.ts` applies for the action's
// check-mode diff, plus parity-only filtering for known host/VMM noise.
// Volatile fields the renderer intentionally lets drift across runs
// (`generated_at`, `manager_lockfile_sha256`) are normalised to a fixed
// placeholder before comparison.
//
// Invoked from `.github/workflows/parity-test.yml` as:
//
//   pnpm exec oxnode scripts/parity-diff.ts \
//     --left  artifacts/linux/linux-lockfile.yml      --left-label  linux-firecracker \
//     --right artifacts/macos-arm64/macos-lockfile.yml --right-label macos-arm64-vz \
//     --report parity-report.md
//
// Exit codes:
//   0 — lockfiles are byte-equal after canonicalization (parity holds).
//   1 — lockfiles diverge.
//   2 — usage error or input file missing.
//
// Output:
//   stdout — the unified diff (empty when parity holds).
//   --report <path> — Markdown report (verdict + counts + embedded diff).
//                     Suitable for $GITHUB_STEP_SUMMARY.
//
// What this DOES catch:
//   - PM-flag overlay bug (linux-only package selected on macOS).
//   - Lock renderer ordering bug (different event order between platforms).
//   - Audit-policy desync (spurious event on one side).
//
// What this DOES filter:
//   - Ambient CI/VMM env names that are not dependency-controlled.
//   - Apple Virtualization.framework NAT resolver noise.
//   - One exact esbuild native self-verify spawn that depends on backend
//     filesystem optimisation details; both sides still record `node install.js`.
//
// What this does NOT filter:
//   Arbitrary spawn/exec divergence still surfaces as a diff hunk.  Keep
//   spawn filters exact and evidence-backed; the maintainer should read the
//   report and decide before adding new rules.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

interface ParityOptions {
  left: string;
  right: string;
  leftLabel: string;
  rightLabel: string;
  reportPath: string | null;
}

type ParityListField = 'external_reads' | 'env_read' | 'network_attempts' | 'spawn_attempts';

const PARITY_ONLY_EXTERNAL_READS = new Set([
  // Puppeteer probes its default browser cache root. Whether that directory
  // exists is host/backend state; writes to it still surface via escaped_writes.
  '$HOME/.cache/puppeteer',
]);

const PARITY_ONLY_ENV_READS = new Set([
  // CI/git transport environment present on the GitHub runner but not on the
  // committed local macOS fixture.
  'GIT_ASKPASS',
  'GIT_SSH_COMMAND',
  'HOSTNAME',
  // Resolver configuration inherited from the host/VMM.
  'LOCALDOMAIN',
  'NOPROXY',
  'RES_OPTIONS',
  // Agent/backend control and terminal env that lifecycle children should not
  // rely on; older generated baselines may still contain them.
  'LINES',
  'POSIXLY_CORRECT',
  'SCRIPT_JAIL_CONFIG_PATH',
  'SCRIPT_JAIL_CONNECTION',
  'SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH',
  'SCRIPT_JAIL_NATIVE_PRELOAD_PATH',
  'SCRIPT_JAIL_PHASE_B_UNSHARE_NET',
  'SCRIPT_JAIL_PLATFORM_PRELOAD_PATH',
  'TERM',
  // Test-knob probes from dependency helper libraries. Presence depends on
  // the ambient process env, not on the dependency install behavior.
  'COLS',
  'TESTING_TAR_FAKE_PLATFORM',
  '__FAKE_FS_O_FILENAME__',
  '__FAKE_PLATFORM__',
]);

// Resolver-address noise.  Entries are stored in their POST-canonicalization
// form: `canonicalize` strips the `<BLOCKED> ` prefix from connect entries on
// BOTH sides (see canonicalizeConnect) before `filterParityOnlyNoise` runs, so
// these are matched without the prefix.  A blocked Linux/VZ DNS attempt and an
// (online) macOS-bare DNS attempt therefore both reduce to `connect <addr>:53`
// and filter identically.
const PARITY_ONLY_NETWORK_ATTEMPTS = new Set([
  // Apple Virtualization.framework NAT resolver observed in local arm64 VZ
  // lockfiles. Linux action backends see public resolvers instead.
  'connect 192.168.64.1:53',
  // Azure-hosted runner DNS endpoint observed from the Docker backend on
  // ubuntu-24.04-arm. It is host resolver plumbing, not dependency behavior.
  'connect 168.63.129.16:53',
  // macOS-bare backend: the system stub resolver (mDNSResponder) listens on
  // the loopback DNS port, so a name lookup the install triggers connects to
  // 127.0.0.1:53.  That is host resolver plumbing on macOS, the same class of
  // noise as the VZ NAT and Azure entries above — not dependency behavior.
  'connect 127.0.0.1:53',
]);

const PARITY_ONLY_SPAWN_ATTEMPTS = new Set([
  // esbuild's postinstall verifies the selected native binary. Depending on
  // backend filesystem semantics, its JS shim may be hardlinked/replaced before
  // validation, so one side can record this direct native spawn in addition to
  // the common `node install.js` lifecycle entry.
  '$PKG/bin/esbuild --version',
  // simple-git-hooks probes the local checkout hook path when the audited
  // workspace has a usable .git directory. Container backends can run from a
  // copied workspace without that git metadata, so this is host shape noise.
  'sh -c git config --local core.hooksPath',
]);

const NPM_DEBUG_LOG_BASENAME =
  /\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}_\d{3}Z-debug-(\d+)\.log$/;

class ParityArgError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParityArgError';
  }
}

// Mirror `src/action/diff.ts` canonicalization: replace the two volatile
// field values with a fixed placeholder.  We do NOT YAML-parse-and-reserialize
// — that would normalise away legitimate whitespace and key-order
// differences which ARE meaningful divergences.  Line-level substitution
// keeps the diff faithful.
function canonicalize(content: string): string {
  const volatileCanonicalized = content
    .split('\n')
    .map((line) => {
      if (/^generated_at:\s/.test(line)) return 'generated_at: <canonical>';
      if (/^manager_lockfile_sha256:\s/.test(line)) {
        return 'manager_lockfile_sha256: <canonical>';
      }
      return canonicalizeConnect(canonicalizeNpmDebugLog(line));
    })
    .join('\n');
  return filterParityOnlyNoise(volatileCanonicalized);
}

// Strip the `<BLOCKED> ` prefix from connect entries on BOTH sides before
// comparison (same precedent as the volatile generated_at/SHA fields).  The
// Linux/Firecracker backends run Phase B offline, so every observed connect()
// is recorded as `<BLOCKED> connect <host>:<port>`.  The macOS-bare backend is
// observe-only and stays ONLINE, so its connect() succeeds and normalize emits
// the same line with NO prefix.  Both lockfiles stay faithful to what their
// backend actually saw (we do NOT weaken the Linux blocked-vs-succeeded signal
// inside normalize); we only reconcile the attempt at diff time so one
// committed lock satisfies both backends.  The match is narrow: only
// `<BLOCKED> connect ` list items are touched — dlopen entries (also
// `<BLOCKED> <path>`) never start with `connect `, so they are untouched.
function canonicalizeConnect(line: string): string {
  const match = /^(\s*-\s+)<BLOCKED> (connect .*)$/.exec(line);
  if (!match) return line;
  return `${match[1]}${match[2]}`;
}

function filterParityOnlyNoise(content: string): string {
  const out: string[] = [];
  let activeList: { field: ParityListField; indent: number } | null = null;

  for (const line of content.split('\n')) {
    const fieldMatch = /^(\s*)(external_reads|env_read|network_attempts|spawn_attempts):(?:\s.*)?$/.exec(line);
    if (fieldMatch) {
      activeList = {
        field: fieldMatch[2] as ParityListField,
        indent: fieldMatch[1]!.length,
      };
      out.push(line);
      continue;
    }

    if (activeList !== null) {
      const indent = leadingSpaces(line);
      if (line.trim() !== '' && indent <= activeList.indent) {
        activeList = null;
      }
    }

    if (activeList !== null) {
      const itemMatch = /^(\s*)-\s+(.*)$/.exec(line);
      if (itemMatch && itemMatch[1]!.length > activeList.indent) {
        const item = itemMatch[2]!;
        if (isParityOnlyListItem(activeList.field, item)) continue;
      }
    }

    out.push(line);
  }

  return collapseEmptyFilteredLists(out.join('\n'));
}

function collapseEmptyFilteredLists(content: string): string {
  const lines = content.split('\n');
  const out: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const match = /^(\s*)(external_reads|env_read|network_attempts|spawn_attempts):\s*$/.exec(line);
    if (!match) {
      out.push(line);
      continue;
    }

    const indent = match[1]!.length;
    let next = i + 1;
    while (next < lines.length && lines[next]!.trim() === '') {
      next++;
    }

    if (next >= lines.length || leadingSpaces(lines[next]!) <= indent) {
      out.push(`${match[1]}${match[2]}: []`);
      continue;
    }

    out.push(line);
  }

  return out.join('\n');
}

function canonicalizeNpmDebugLog(line: string): string {
  const match = NPM_DEBUG_LOG_BASENAME.exec(line);
  if (!match) return line;

  const prefix = line.slice(0, match.index);
  if (
    !prefix.endsWith('/.npm/_logs/') &&
    !prefix.endsWith('$HOME/.npm/_logs/') &&
    !prefix.endsWith('$CACHE/_logs/')
  ) {
    return line;
  }

  return `${prefix}<timestamp>-debug-${match[1]}.log`;
}

function leadingSpaces(line: string): number {
  const match = /^ */.exec(line);
  return match ? match[0].length : 0;
}

function isParityOnlyListItem(field: ParityListField, item: string): boolean {
  if (field === 'external_reads') return PARITY_ONLY_EXTERNAL_READS.has(item);
  if (field === 'env_read') return PARITY_ONLY_ENV_READS.has(item);
  if (field === 'network_attempts') return PARITY_ONLY_NETWORK_ATTEMPTS.has(item);
  return PARITY_ONLY_SPAWN_ATTEMPTS.has(item);
}

function parseArguments(argv: ReadonlyArray<string>): ParityOptions {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      left: { type: 'string' },
      right: { type: 'string' },
      'left-label': { type: 'string', default: 'left' },
      'right-label': { type: 'string', default: 'right' },
      report: { type: 'string' },
    },
    strict: true,
    allowPositionals: false,
  });

  if (typeof values.left !== 'string' || values.left.length === 0) {
    throw new ParityArgError('--left <path> is required');
  }
  if (typeof values.right !== 'string' || values.right.length === 0) {
    throw new ParityArgError('--right <path> is required');
  }

  return {
    left: values.left,
    right: values.right,
    leftLabel: values['left-label'] ?? 'left',
    rightLabel: values['right-label'] ?? 'right',
    reportPath: typeof values.report === 'string' ? values.report : null,
  };
}

// Use the system `diff -u` rather than implementing LCS in TypeScript: the
// output format is stable across coreutils versions and every CI runner has
// it, the comparison is already line-canonicalised before we get here, and
// any future enhancement (filters, statistics) can read the unified-diff
// stream rather than its own algorithm.
function unifiedDiff(opts: {
  leftPath: string;
  rightPath: string;
  leftLabel: string;
  rightLabel: string;
}): string {
  try {
    execFileSync('diff', [
      '-u',
      '--label', opts.leftLabel,
      '--label', opts.rightLabel,
      opts.leftPath,
      opts.rightPath,
    ], { stdio: 'pipe' });
    return '';
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer; stderr?: Buffer };
    // diff exit 1 = differences found (expected); exit 2 = trouble.
    if (e.status === 1 && e.stdout) return e.stdout.toString('utf8');
    const stderr = e.stderr ? e.stderr.toString('utf8') : '';
    throw new Error(`diff failed (exit=${String(e.status ?? '?')}): ${stderr}`);
  }
}

function summariseDiff(diff: string): { insertions: number; deletions: number; hunks: number } {
  let insertions = 0;
  let deletions = 0;
  let hunks = 0;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) insertions++;
    else if (line.startsWith('-') && !line.startsWith('---')) deletions++;
    else if (line.startsWith('@@')) hunks++;
  }
  return { insertions, deletions, hunks };
}

function renderMarkdownReport(args: {
  opts: ParityOptions;
  match: boolean;
  diff: string;
}): string {
  const { opts, match, diff } = args;
  if (match) {
    return [
      '# Parity report',
      '',
      `**Verdict:** parity holds — lockfiles are byte-equal after canonicalization.`,
      '',
      '| side | path | label |',
      '|---|---|---|',
      `| left | \`${opts.left}\` | ${opts.leftLabel} |`,
      `| right | \`${opts.right}\` | ${opts.rightLabel} |`,
      '',
      'Volatile fields (`generated_at`, `manager_lockfile_sha256`) and known parity-only host/VMM noise were canonicalised before comparison.',
      '',
    ].join('\n');
  }

  const { insertions, deletions, hunks } = summariseDiff(diff);
  return [
    '# Parity report',
    '',
    `**Verdict:** diverged — lockfiles are NOT byte-equal after canonicalization.`,
    '',
    '| side | path | label |',
    '|---|---|---|',
    `| left | \`${opts.left}\` | ${opts.leftLabel} |`,
    `| right | \`${opts.right}\` | ${opts.rightLabel} |`,
    '',
    `**Summary:** ${hunks} hunk(s), ${insertions} insertion(s), ${deletions} deletion(s).`,
    '',
    'See `docs/parity-testing.md` for how to interpret arm64-on-Apple-Silicon divergence vs. real audit drift. Known parity-only host/VMM noise is filtered before this diff.',
    '',
    '<details>',
    '<summary>Unified diff</summary>',
    '',
    '```diff',
    diff.trimEnd(),
    '```',
    '',
    '</details>',
    '',
  ].join('\n');
}

function main(argv: ReadonlyArray<string>): number {
  let opts: ParityOptions;
  try {
    opts = parseArguments(argv);
  } catch (err) {
    if (err instanceof ParityArgError) {
      process.stderr.write(`parity-diff: ${err.message}\n`);
      process.stderr.write('usage: parity-diff.ts --left <path> --right <path>\n');
      process.stderr.write('                      [--left-label <name>] [--right-label <name>] [--report <path>]\n');
      return 2;
    }
    throw err;
  }

  let leftRaw: string;
  let rightRaw: string;
  try {
    leftRaw = readFileSync(opts.left, 'utf8');
  } catch {
    process.stderr.write(`parity-diff: cannot read --left at ${opts.left}\n`);
    return 2;
  }
  try {
    rightRaw = readFileSync(opts.right, 'utf8');
  } catch {
    process.stderr.write(`parity-diff: cannot read --right at ${opts.right}\n`);
    return 2;
  }

  const leftCanon = canonicalize(leftRaw);
  const rightCanon = canonicalize(rightRaw);
  const match = leftCanon === rightCanon;

  let diff = '';
  if (!match) {
    const stage = mkdtempSync(join(tmpdir(), 'parity-diff-'));
    const leftPath = join(stage, 'left.yml');
    const rightPath = join(stage, 'right.yml');
    writeFileSync(leftPath, leftCanon);
    writeFileSync(rightPath, rightCanon);
    diff = unifiedDiff({
      leftPath,
      rightPath,
      leftLabel: opts.leftLabel,
      rightLabel: opts.rightLabel,
    });
    process.stdout.write(diff);
  }

  if (opts.reportPath !== null) {
    writeFileSync(opts.reportPath, renderMarkdownReport({ opts, match, diff }));
  }

  return match ? 0 : 1;
}

process.exit(main(process.argv.slice(2)));

// script-jail — src/action/diff.ts
//
// Renders a unified diff between the committed and generated install-lock
// YAML files, plus a set of GitHub Actions error annotations the runner UI
// can display inline against the lockfile.
//
// Annotation format:
//   ::error file=<lockPath>,line=<N>::<message>
//
// We emit one annotation per hunk of the structured patch (each hunk targets
// the new-file start line).  When the committed file is missing entirely
// we emit a single "would be created" annotation at line 1.
//
// Volatile-field canonicalization:
//   `generated_at` and `manager_lockfile_sha256` change on every run for
//   reasons orthogonal to the audit's semantic content (timestamp from
//   Date.now() and the consumer's manager lockfile bytes respectively).
//   Without canonicalization, `mode=check` would surface a drift hunk on
//   every honest re-run.  We collapse both fields to a fixed sentinel for
//   the equality check; if everything ELSE matches, the result is
//   match: true and the unified output is empty.  When there's real
//   drift, the unified output still shows the ORIGINAL field values so
//   reviewers see actual timestamps rather than the sentinel.

import { createTwoFilesPatch, structuredPatch } from 'diff';
import { parse as parseYaml } from 'yaml';

import { Lock } from '../lock/schema.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DiffResult {
  /** Empty string when committed === generated (byte-equal). */
  unified: string;
  /** One GitHub Actions ::error annotation per hunk.  Empty when no diff. */
  annotations: string[];
  /** True when the inputs are byte-equal. */
  match: boolean;
}

export interface RenderDiffArgs {
  /** Display-friendly path used in the annotation `file=` field. */
  lockPath: string;
  /** Contents of the committed file ('' when missing). */
  committed: string;
  /** Contents produced by the VM run. */
  generated: string;
}

// ---------------------------------------------------------------------------
// renderDiff
// ---------------------------------------------------------------------------

const CONTEXT = 3;

export function renderDiff(args: RenderDiffArgs): DiffResult {
  const { lockPath, committed, generated } = args;

  // Fast path: byte-equal.
  if (committed === generated) {
    return { unified: '', annotations: [], match: true };
  }

  // Equality path: canonicalize volatile fields before comparing.  If the
  // only delta is `generated_at` and/or `manager_lockfile_sha256`, treat
  // as a match.  We DON'T return the canonicalized text in the unified
  // output — reviewers want to see real values when there IS real drift.
  const canonicalCommitted = canonicalizeVolatileFields(committed);
  const canonicalGenerated = canonicalizeVolatileFields(generated);
  if (canonicalCommitted === canonicalGenerated) {
    return { unified: '', annotations: [], match: true };
  }

  const oldLabel = `a/${lockPath}`;
  const newLabel = `b/${lockPath}`;

  const unified = createTwoFilesPatch(
    oldLabel,
    newLabel,
    committed,
    generated,
    undefined,
    undefined,
    { context: CONTEXT },
  );

  // Missing-committed special case.
  if (committed === '') {
    // Count the lines in the generated file (treat trailing newline as not
    // adding an empty final line).
    const lineCount = countLines(generated);
    const ann = `::error file=${lockPath},line=1::lockfile missing — would be created (${lineCount} lines)`;
    return { unified, annotations: [ann], match: false };
  }

  // Walk the structured patch to emit one annotation per hunk.
  const patch = structuredPatch(
    oldLabel,
    newLabel,
    committed,
    generated,
    undefined,
    undefined,
    { context: CONTEXT },
  );

  const annotations: string[] = [];
  for (const hunk of patch.hunks) {
    let added = 0;
    let removed = 0;
    for (const line of hunk.lines) {
      // diff prefixes each line with one of: '+', '-', ' ', '\\'.
      const first = line.charAt(0);
      if (first === '+') added++;
      else if (first === '-') removed++;
    }
    const startLine = Math.max(1, hunk.newStart);
    annotations.push(
      `::error file=${lockPath},line=${startLine}::lockfile drifted ` +
      `(${added} lines added, ${removed} lines removed in this hunk)`,
    );
  }

  return { unified, annotations, match: false };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Replace the values of `generated_at` and `manager_lockfile_sha256` with a
 * fixed sentinel so honest re-runs (where only those two fields change)
 * compare equal.  Operates on string lines, not parsed YAML, to preserve
 * exact formatting in the original file — the canonical text is only used
 * for the equality check.
 *
 * Matches lines at the top-level of the YAML document (no leading
 * whitespace).  The render() in src/lock/render.ts always emits both fields
 * at column 0, so a strict anchor is correct here.
 */
function canonicalizeVolatileFields(yaml: string): string {
  return yaml.replace(
    /^(generated_at|manager_lockfile_sha256):.*$/gm,
    '$1: <canonicalized>',
  );
}

// ---------------------------------------------------------------------------
// audit_bypass detection
// ---------------------------------------------------------------------------

/**
 * One `<EXEC_FAIL_OPEN> <prog>` entry surfaced in the generated lockfile.
 * Carries the package id and lifecycle stage so the action can emit a
 * targeted annotation pointing the auditor at the bypass.
 */
export interface AuditBypassEntry {
  packageId: string;
  stage: string;
  entry: string;
}

/**
 * Scan a generated lockfile (YAML text) for any non-empty `audit_bypass`
 * arrays under `packages.<pkg>.lifecycle.<stage>`.  Returns one
 * AuditBypassEntry per offending string.
 *
 * SECURITY (defense in depth): the byte-equality diff path treats a
 * committed lockfile that ALREADY contains `<EXEC_FAIL_OPEN> …` lines as
 * "no drift" — which is exactly the silenced state a malicious PR would
 * commit to baseline a permanent audit bypass.  This scan is the standalone
 * gate that fires even when the diff matches, so an attacker cannot launder
 * a permanent bypass through a single approved PR.
 *
 * The check parses the YAML defensively: malformed input returns an empty
 * array (caller's diff path will surface the malformedness separately).
 * It does NOT enforce the full Lock schema (so future schema additions do
 * not break this gate); it walks the parsed tree by shape.
 */
export function findAuditBypass(generated: string): AuditBypassEntry[] {
  let doc: unknown;
  try {
    doc = parseYaml(generated);
  } catch {
    return [];
  }
  if (doc === null || typeof doc !== 'object') return [];

  // Prefer the strict schema parse when it succeeds — that gives us
  // canonical key shapes — but fall back to a hand-walk on validation
  // failure so a partially-corrupt lockfile still triggers the gate.
  const parsed = Lock.safeParse(doc);
  const packagesRaw = parsed.success
    ? parsed.data.packages
    : (doc as { packages?: unknown }).packages;
  if (
    packagesRaw === undefined ||
    packagesRaw === null ||
    typeof packagesRaw !== 'object'
  ) {
    return [];
  }

  const out: AuditBypassEntry[] = [];
  for (const [packageId, pkgRaw] of Object.entries(
    packagesRaw as Record<string, unknown>,
  )) {
    if (pkgRaw === null || typeof pkgRaw !== 'object') continue;
    const lifecycleRaw = (pkgRaw as { lifecycle?: unknown }).lifecycle;
    if (
      lifecycleRaw === null ||
      lifecycleRaw === undefined ||
      typeof lifecycleRaw !== 'object'
    ) {
      continue;
    }
    for (const [stage, blockRaw] of Object.entries(
      lifecycleRaw as Record<string, unknown>,
    )) {
      if (blockRaw === null || typeof blockRaw !== 'object') continue;
      const ab = (blockRaw as { audit_bypass?: unknown }).audit_bypass;
      if (!Array.isArray(ab)) continue;
      for (const entry of ab) {
        if (typeof entry === 'string' && entry.length > 0) {
          out.push({ packageId, stage, entry });
        }
      }
    }
  }
  return out;
}

/**
 * Format a list of audit_bypass entries as a single human-readable error
 * line, suitable for stderr / Action log surfacing.  Truncates long lists
 * to keep the message bounded.
 */
export function formatAuditBypassError(entries: AuditBypassEntry[]): string {
  const MAX = 10;
  const head = entries.slice(0, MAX).map((e) => {
    return `${e.packageId} (${e.stage}): ${e.entry}`;
  });
  const more =
    entries.length > MAX ? ` (+${entries.length - MAX} more)` : '';
  return (
    'Audit envelope was bypassed — see audit_bypass entries: [' +
    head.join('; ') +
    ']' +
    more
  );
}

// ---------------------------------------------------------------------------

/**
 * Count the number of lines in `s`.  An empty string is 0 lines.  A trailing
 * newline does NOT contribute an extra empty line (so "a\nb\n" is 2 lines).
 */
function countLines(s: string): number {
  if (s === '') return 0;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) === 10 /* \n */) n++;
  }
  // If the string does not end with a newline, the last partial line counts.
  if (s.length > 0 && s.charCodeAt(s.length - 1) !== 10) n++;
  return n;
}

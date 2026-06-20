// script-jail — src/release/backfill.ts
//
// Pure-ish core for the release-backfill tool (`scripts/release-backfill.ts`).
//
// What lives here:
//   - `computeManifestExpected` — recompute the 12 file SHAs from a staged
//     download tree (rootfs ext4s via the canonical/time-masked hash, the rest
//     via plain streaming sha256).
//   - `parseDockerDigestsFromLog` — extract the 4 floating-tag GHCR rootfs refs
//     from a buildx push log.
//   - `renderArtifactManifestTs` — typed full-literal codegen for
//     `src/action/artifact-manifest.ts`, byte-stable against the committed
//     manifest (template-with-region: static header + inline comments verbatim,
//     only the tag / 12 hex values / 4 GHCR refs substituted).
//   - `bumpVersion` — set `package.json` `version` to the bare version,
//     preserving 2-space indent + trailing newline.
//   - `buildManifest` — assemble the parts into an `ArtifactManifest`.
//
// No `gh`/exec/network lives here so unit tests need no network — the orchestrating
// CLI (`scripts/release-backfill.ts`) owns the `gh` I/O.

import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { join } from 'node:path';

import type {
  ArtifactArch,
  ArtifactManifest,
  ManifestPlatform,
} from '../action/pre-fetch-artifacts.js';
import type { RunnerImage } from '../action/runner-image.js';
import { canonicalRootfsHash } from '../rootfs/repro-hash.js';
import { sha256File } from '../shared/http-download.js';

// ---------------------------------------------------------------------------
// Input validation (defense-in-depth)
// ---------------------------------------------------------------------------
//
// The artifact manifest is security-critical: it pins the exact rootfs/shim/
// GHCR artifacts the action downloads and trusts at runtime, and these values
// are interpolated into GENERATED TypeScript (renderArtifactManifestTs) +
// GHCR refs.  An unescaped `version`/`repo` could break out of a single-quoted
// TS string literal and inject arbitrary code into the committed manifest.  So
// `version` and `repo` are STRICTLY shaped before they ever reach codegen.  The
// CLI runs locally on maintainer-typed args today, but Phase 2 (CI auto-backfill)
// will feed these from workflow_dispatch inputs — fail closed now.

/** Strict bare semver (no leading `v`): MAJOR.MINOR.PATCH (+ optional pre/build). */
const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * One `owner` or `name` path segment: alnum / `.` / `_` / `-`, and MUST contain
 * at least one alphanumeric (so a pure-dot segment like `.` or `..` — which would
 * normalize to a different path in a download URL — is rejected, not accepted).
 */
const REPO_SEGMENT_RE = /^(?=[A-Za-z0-9._-]*[A-Za-z0-9])[A-Za-z0-9._-]+$/;

/**
 * Full digest-pinned GHCR rootfs ref shape (lowercased owner with ≥1 alnum,
 * 64-hex digest).  The owner alnum requirement mirrors {@link assertRepo}.
 */
const GHCR_REF_RE =
  /^ghcr\.io\/(?=[a-z0-9._-]*[a-z0-9])[a-z0-9._-]+\/script-jail-rootfs:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$/;

/** Throw unless `version` is a bare semver with NO leading `v`. */
export function assertBareVersion(version: string): void {
  if (!SEMVER_RE.test(version)) {
    throw new Error(
      `release-backfill: version must be a bare semver (e.g. 0.2.6), got '${version}'.`,
    );
  }
}

/** Throw unless `repo` is a safe `owner/name` (exactly two alnum-bearing segments). */
export function assertRepo(repo: string): void {
  const parts = repo.split('/');
  if (
    parts.length !== 2 ||
    !REPO_SEGMENT_RE.test(parts[0]!) ||
    !REPO_SEGMENT_RE.test(parts[1]!)
  ) {
    throw new Error(
      `release-backfill: repo must be 'owner/name' — each segment alnum / . / _ / - ` +
        `with at least one alphanumeric and no '.'/'..' traversal; got '${repo}'.`,
    );
  }
}

/** Throw unless `tag` is `v` + a bare semver (the manifest tag form). */
export function assertTag(tag: string): void {
  if (!tag.startsWith('v') || !SEMVER_RE.test(tag.slice(1))) {
    throw new Error(
      `release-backfill: manifest tag must be 'v' + bare semver (e.g. v0.2.6), got '${tag}'.`,
    );
  }
}

/** A GitHub Actions run id: a non-empty run of decimal digits. */
const RUN_ID_RE = /^[1-9][0-9]*$/;

/**
 * Throw unless `run` is a bare numeric GitHub run id.  It flows into both the
 * `gh run …` args AND (for the online path) the per-run staging directory name,
 * so reject anything with path separators / `.`/`..` / leading zero — a stray
 * `--run ../../etc` must never land as a directory component.
 */
export function assertRunId(run: string): void {
  if (!RUN_ID_RE.test(run)) {
    throw new Error(
      `release-backfill: --run must be a numeric GitHub run id (e.g. 27868987817), got '${run}'.`,
    );
  }
}

/** lstat `p` without following symlinks; null if it does not exist. */
function lstatOrNull(p: string): Stats | null {
  try {
    return lstatSync(p);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Create a FRESH, repo-local per-run staging directory `<stagingRoot>/<childName>`
 * and return its path.  Fail-closed against symlink-escape on the *destructive*
 * wipe:
 *
 *   - `stagingRoot` (e.g. `<repo>/.release-backfill`) must be a REAL directory we
 *     own.  If it is a SYMLINK, `rmSync(<stagingRoot>/<child>, {recursive})` would
 *     be resolved by the kernel to `<symlink-target>/<child>` and delete a tree
 *     OUTSIDE the repo.  We `lstat` (never follow) and refuse a symlink / non-dir.
 *   - the per-run child itself must not be a pre-existing symlink either (a
 *     `recursive` wipe of a symlinked dir could reach its target).
 *
 * `childName` must be a single safe path component (no separators / `..`); the
 * caller builds it from an asserted tag + asserted-numeric run id, but we
 * re-check defensively since this function deletes.
 */
export function prepareCleanStagingDir(stagingRoot: string, childName: string): string {
  if (childName.length === 0 || /[\\/]/.test(childName) || childName === '.' || childName === '..') {
    throw new Error(
      `release-backfill: refusing unsafe staging child name '${childName}' (must be a single path component).`,
    );
  }

  // Guard the staging ROOT: real directory only, never a symlink.
  const rootStat = lstatOrNull(stagingRoot);
  if (rootStat !== null) {
    if (rootStat.isSymbolicLink()) {
      throw new Error(
        `release-backfill: staging root '${stagingRoot}' is a symlink; refusing (a wipe ` +
          `would delete its target tree OUTSIDE the repo). Remove the symlink and retry.`,
      );
    }
    if (!rootStat.isDirectory()) {
      throw new Error(
        `release-backfill: staging root '${stagingRoot}' exists and is not a directory; refusing.`,
      );
    }
  } else {
    mkdirSync(stagingRoot, { recursive: true });
  }

  const dir = join(stagingRoot, childName);
  // Guard the per-run child: never wipe through a pre-existing symlink.
  const childStat = lstatOrNull(dir);
  if (childStat !== null && childStat.isSymbolicLink()) {
    throw new Error(
      `release-backfill: staging dir '${dir}' is a symlink; refusing to wipe it.`,
    );
  }

  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Escape a string for literal use inside a RegExp. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The pre-fetched / offline inputs `--dir` (staged artifact tree) and `--log`
 * (buildx push log) MUST be used TOGETHER or not at all.  Mixing one local input
 * with one fetched-from-run input combines a run-bound source with an unbound
 * one — e.g. `--run RUN_A` (artifacts downloaded + digests fetched/bound to A)
 * with `--log <RUN_B log>` would pin RUN_A file hashes alongside RUN_B GHCR
 * digests and still pass the local validators.  Both-together = explicit offline
 * mode where the operator vouches for provenance; neither = everything fetched
 * and bound to `--run`.  Returns true iff in full-offline mode.
 */
export function assertOfflineInputsConsistent(opts: {
  dir?: string | undefined;
  log?: string | undefined;
}): boolean {
  const hasDir = opts.dir !== undefined;
  const hasLog = opts.log !== undefined;
  if (hasDir !== hasLog) {
    throw new Error(
      `release-backfill: --dir and --log must be used TOGETHER (full offline mode — ` +
        `the operator vouches that both came from the same run) or NEITHER (fetch + ` +
        `bind everything to --run). Got --dir=${hasDir}, --log=${hasLog}.`,
    );
  }
  return hasDir;
}

/**
 * Pick the producer `build` job id from a run's job list, BINDING any caller
 * `override` to THIS run.  When `override` is given it MUST be a job of the run
 * the artifacts came from — otherwise a `--build-job` pointing at a DIFFERENT
 * producer run could feed a log whose GHCR digests don't belong to the artifacts
 * being hashed.  With no override, the job named `build` is used.
 */
export function selectBuildJobId(
  jobs: ReadonlyArray<{ databaseId: number; name: string }>,
  override?: string,
): string {
  if (override !== undefined) {
    const match = jobs.find((j) => String(j.databaseId) === override);
    if (match === undefined) {
      throw new Error(
        `release-backfill: --build-job ${override} is not a job of the requested run. ` +
          `Jobs: [${jobs.map((j) => `${j.name}:${j.databaseId}`).join(', ')}]`,
      );
    }
    return override;
  }
  const build = jobs.find((j) => j.name === 'build');
  if (build === undefined) {
    throw new Error(
      `release-backfill: no job named 'build' in the requested run. ` +
        `Jobs: [${jobs.map((j) => j.name).join(', ')}]`,
    );
  }
  return String(build.databaseId);
}

// ---------------------------------------------------------------------------
// Staged-tree layout
// ---------------------------------------------------------------------------
//
// This is the download layout the CLI produces and the validators expect:
//   <stagedDir>/images/{rootfs-*.ext4, libscriptjail*.so, vmlinux-vz-*}
//   <stagedDir>/{script-jail-vm-arm64-darwin, libscriptjail-arm64.dylib,
//                coreutils-arm64, bash-arm64}   (mac-bin files at the root)
//
// `ext4` keys route through `canonicalRootfsHash`; everything else uses plain
// sha256.  `under: 'images' | 'root'` records where in the staged tree the file
// lands; `platform` records which `expected` section it belongs to.

interface ArtifactSpec {
  readonly key: string;
  readonly platform: ManifestPlatform;
  readonly under: 'images' | 'root';
  readonly canonical: boolean;
}

/**
 * The 12 file artifacts pinned in `PINNED_MANIFEST.expected`, in manifest order.
 * 3 linux + 9 darwin.  The 4 `rootfs-*.ext4` entries (`canonical: true`) hash via
 * the time-masked canonical rootfs hash; the other 8 via plain sha256.
 */
export const MANIFEST_FILE_ARTIFACTS: ReadonlyArray<ArtifactSpec> = [
  // linux
  { key: 'rootfs-ubuntu-22.04.ext4', platform: 'linux', under: 'images', canonical: true },
  { key: 'rootfs-ubuntu-24.04.ext4', platform: 'linux', under: 'images', canonical: true },
  { key: 'libscriptjail.so', platform: 'linux', under: 'images', canonical: false },
  // darwin
  { key: 'rootfs-ubuntu-22.04-arm64.ext4', platform: 'darwin', under: 'images', canonical: true },
  { key: 'rootfs-ubuntu-24.04-arm64.ext4', platform: 'darwin', under: 'images', canonical: true },
  { key: 'libscriptjail-arm64.so', platform: 'darwin', under: 'images', canonical: false },
  { key: 'libscriptjail-arm64.dylib', platform: 'darwin', under: 'root', canonical: false },
  { key: 'coreutils-arm64', platform: 'darwin', under: 'root', canonical: false },
  { key: 'bash-arm64', platform: 'darwin', under: 'root', canonical: false },
  { key: 'vmlinux-vz-x86_64', platform: 'darwin', under: 'images', canonical: false },
  { key: 'vmlinux-vz-arm64', platform: 'darwin', under: 'images', canonical: false },
  { key: 'script-jail-vm-arm64-darwin', platform: 'darwin', under: 'root', canonical: false },
];

const HEX64_RE = /^[0-9a-f]{64}$/;

/** Absolute path of an artifact within a staged tree. */
function artifactPath(stagedDir: string, spec: ArtifactSpec): string {
  return spec.under === 'images'
    ? join(stagedDir, 'images', spec.key)
    : join(stagedDir, spec.key);
}

/** Plain streaming sha256 of a file on disk (no canonical masking). */
function plainSha256(filePath: string): Promise<string> {
  // Reuse the project's streaming sha256 helper so a behaviour change there
  // propagates here (and the canonical path stays the only difference).
  return sha256File(filePath);
}

// ---------------------------------------------------------------------------
// computeManifestExpected
// ---------------------------------------------------------------------------

/**
 * Recompute the 12 file SHAs from a staged download tree (layout above).
 *
 * The 4 `rootfs-*.ext4` keys use the time-masked canonical rootfs hash
 * (`canonicalRootfsHash`, in-process — NOT a shell to dist/repro-hash-cli.cjs);
 * the other 8 use plain streaming sha256.  Every digest is asserted to be
 * lowercase 64-hex.  Throws a clear error on any missing artifact.
 */
export async function computeManifestExpected(
  stagedDir: string,
): Promise<ArtifactManifest['expected']> {
  const linux: Record<string, string> = {};
  const darwin: Record<string, string> = {};

  for (const spec of MANIFEST_FILE_ARTIFACTS) {
    const path = artifactPath(stagedDir, spec);
    if (!existsSync(path)) {
      throw new Error(
        `release-backfill: missing artifact '${spec.key}' (expected at ${path}). ` +
          `Check the producer run uploaded it and the staged tree layout is correct.`,
      );
    }
    const digest = spec.canonical
      ? await canonicalRootfsHash(path)
      : await plainSha256(path);
    if (!HEX64_RE.test(digest)) {
      throw new Error(
        `release-backfill: computed digest for '${spec.key}' is not 64-char ` +
          `lowercase hex: '${digest}'`,
      );
    }
    if (spec.platform === 'linux') linux[spec.key] = digest;
    else darwin[spec.key] = digest;
  }

  return { linux, darwin };
}

// ---------------------------------------------------------------------------
// parseDockerDigestsFromLog
// ---------------------------------------------------------------------------

/** The 4 floating GHCR tags we keep, mapped to their (arch, runnerImage) slot. */
const FLOATING_TAG_SLOTS: ReadonlyArray<{
  readonly tag: string;
  readonly arch: ArtifactArch;
  readonly runnerImage: RunnerImage;
}> = [
  { tag: 'ubuntu-22.04', arch: 'x64', runnerImage: 'ubuntu-22.04' },
  { tag: 'ubuntu-24.04', arch: 'x64', runnerImage: 'ubuntu-24.04' },
  { tag: 'ubuntu-22.04-arm64', arch: 'arm64', runnerImage: 'ubuntu-22.04' },
  { tag: 'ubuntu-24.04-arm64', arch: 'arm64', runnerImage: 'ubuntu-24.04' },
];

/**
 * Extract the 4 FLOATING-tag GHCR rootfs refs from a buildx push log.
 *
 * Matches `ghcr.io/<owner>/script-jail-rootfs:<tag>@sha256:<64-hex>` occurrences
 * ANCHORED to the requested `repo` owner (a stray ref for another owner can't be
 * picked up + rewritten under us).  buildx pushes BOTH the floating tag
 * (`:ubuntu-22.04`) AND a version-suffixed dup (`:ubuntu-22.04-v<version>`); the
 * log also carries `exporting manifest/config/attestation` decoy `sha256:` lines
 * (different shape, never matched).
 *
 * For each of the 4 floating tags { ubuntu-22.04, ubuntu-24.04,
 * ubuntu-22.04-arm64, ubuntu-24.04-arm64 } we require BOTH the floating ref and
 * its `${floating}-${tag}` version-suffixed dup to be present and to carry the
 * SAME digest — binding the pinned digest to THIS producer run's version.  All
 * occurrences of a tag must agree; the 4 floating digests must be 64-char
 * lowercase hex (over-long tokens are rejected, not truncated) and distinct.
 */
export function parseDockerDigestsFromLog(
  buildLogText: string,
  { repo, tag }: { repo: string; tag: string },
): NonNullable<ArtifactManifest['dockerImages']> {
  assertRepo(repo);
  assertTag(tag);

  const owner = repo.split('/')[0]!; // assertRepo guarantees a non-empty owner.
  const ownerLc = owner.toLowerCase();

  // Owner-ANCHORED match: only refs under the REQUESTED owner count, so a stray
  // `ghcr.io/<other-owner>/script-jail-rootfs:...` line in the log can't be
  // picked up and silently rewritten under us.  The trailing `(?![0-9A-Za-z._-])`
  // boundary REJECTS a malformed digest token instead of truncating it to the
  // first 64 chars: NO digest/tag token character (hex, uppercase, digit, or the
  // `.`/`_`/`-` that can appear in an OCI tag) may follow the 64 hex — only a
  // real separator (whitespace / quote / EOL).  So `...586c_bad`, `...586c.bad`,
  // `...586cg`, or a 65th hex char all fail the match rather than pinning the
  // 64-char prefix of a corrupt token.
  const re = new RegExp(
    `ghcr\\.io/${escapeRegExp(ownerLc)}/script-jail-rootfs:([A-Za-z0-9._-]+)@sha256:([0-9a-f]{64})(?![0-9A-Za-z._-])`,
    'g',
  );

  // Collect EVERY owner-anchored match — both the floating tag AND the
  // version-suffixed dup the producer pushes — asserting per-tag agreement.
  const byTag = new Map<string, string>();
  let match: RegExpExecArray | null;
  while ((match = re.exec(buildLogText)) !== null) {
    const matchedTag = match[1]!;
    const digest = match[2]!;
    const seen = byTag.get(matchedTag);
    if (seen !== undefined && seen !== digest) {
      throw new Error(
        `release-backfill: conflicting digests for tag '${matchedTag}' in build ` +
          `log: '${seen}' vs '${digest}'.`,
      );
    }
    byTag.set(matchedTag, digest);
  }

  const x64: Partial<Record<RunnerImage, string>> = {};
  const arm64: Partial<Record<RunnerImage, string>> = {};
  const chosen: string[] = [];
  for (const slot of FLOATING_TAG_SLOTS) {
    const floating = byTag.get(slot.tag);
    // PROVENANCE BINDING: tie the pinned digest to THIS producer run's version
    // by requiring the `${floating}-${tag}` dup the producer also pushes, AND
    // that it carries the SAME digest.  Without this the parser would accept a
    // floating-tag digest from any run (incl. a stale pre-existing image).
    const suffixed = byTag.get(`${slot.tag}-${tag}`);
    if (floating === undefined) {
      throw new Error(
        `release-backfill: no GHCR push for floating tag '${slot.tag}' under owner ` +
          `'${ownerLc}' in the build log.`,
      );
    }
    if (suffixed === undefined) {
      throw new Error(
        `release-backfill: missing version-suffixed GHCR push '${slot.tag}-${tag}' ` +
          `— cannot bind the '${slot.tag}' digest to ${tag}.`,
      );
    }
    if (floating !== suffixed) {
      throw new Error(
        `release-backfill: '${slot.tag}' digest '${floating}' does not match its ` +
          `version-suffixed dup '${slot.tag}-${tag}' digest '${suffixed}'.`,
      );
    }
    const ref = `ghcr.io/${ownerLc}/script-jail-rootfs:${slot.tag}@sha256:${floating}`;
    chosen.push(floating);
    if (slot.arch === 'x64') x64[slot.runnerImage] = ref;
    else arm64[slot.runnerImage] = ref;
  }

  // All 4 floating digests must be distinct (a repeated digest is a bug).
  if (new Set(chosen).size !== chosen.length) {
    throw new Error(
      `release-backfill: non-distinct GHCR digests across the 4 floating tags: ` +
        `[${chosen.join(', ')}]`,
    );
  }

  return { x64, arm64 };
}

// ---------------------------------------------------------------------------
// renderArtifactManifestTs — typed full-literal codegen (byte-stable)
// ---------------------------------------------------------------------------
//
// Template-with-region: the static header doc comment, the `import type`, the
// JSDoc above the export, and the load-bearing inline comments inside the literal
// are reproduced VERBATIM; only `tag`, the 12 hex values, and the 4 GHCR refs are
// substituted.  The per-section column padding is reproduced so the output
// byte-matches the committed manifest, and the value-line shape `'<key>': '<value>',`
// is exactly what `check-publish-artifacts.sh`'s grep parser requires.

/** The static file header (file doc comment + import + JSDoc), verbatim. */
const MANIFEST_HEADER = `// script-jail — src/action/artifact-manifest.ts
//
// Pinned manifest of release artifacts the action AND the macOS CLI consume
// at runtime.  See \`./pre-fetch-artifacts.ts\` for release-asset downloads,
// \`./backend/docker.ts\` for digest-pinned GHCR image pulls, and
// \`.github/workflows/release.yml\` for the tag-triggered workflow that
// downloads and publishes both forms. \`expected\` is split by platform so the
// action (Linux-only) and the macOS CLI can pin distinct asset sets from one
// source of truth.
//
// Build-once / download-forever release flow:
//
//   1. Run \`.github/workflows/release-build.yml\` (workflow_dispatch, required
//      \`tag\` input).  The producer builds every image asset ONCE — rootfs
//      ext4s (per runner image + arm64 variants), Docker rootfs images,
//      libscriptjail.so / libscriptjail-arm64.so, the VZ vmlinux kernels, the
//      script-jail-vm-arm64-darwin Mach-O binary, and the macOS-native
//      libscriptjail-arm64.dylib shim — pushes the 4 GHCR rootfs images, and
//      prints a paste-block of the 10 file SHAs + 4 GHCR digests in the job
//      output.
//   2. Paste the 10 file SHAs and 4 GHCR digests from the producer run's
//      paste-block into the maps below.
//   3. Bump \`tag\` to match the new release.
//   4. Rebuild \`dist/\` (\`pnpm build:bundle\`), commit, and push the tag.
//   5. \`release.yml\` fires on the tag, DOWNLOADS the producer's artifacts,
//      and verifies them against this manifest — it never rebuilds the images.
//
// Supply-chain note:
//
//   At Action/CLI runtime, \`./pre-fetch-artifacts.ts\` re-checks every
//   downloaded asset against the SHAs pinned here.  That supply-chain
//   verification is independent of the release flow above and is always on.
//
// Bootstrap caveat:
//
//   The values below are PLACEHOLDERS until the first producer-backed release
//   is cut.  Until then, any action run will (correctly) fail the hash check.
//   After pasting in the real SHAs/digests from a \`release-build.yml\` run and
//   tagging, the manifest is self-consistent.
//
// Why no \`script-jail-vm-x86_64-darwin\`:
//   The Intel macOS runner is deprecated by GitHub; building an Intel
//   Mach-O cross-compile from Apple Silicon is feasible but out of v1
//   scope.  v1 ships the arm64 binary only and a developer on an Intel
//   Mac must build from source via \`cargo build -p script-jail-host-mac\`.

import type { ArtifactManifest } from './pre-fetch-artifacts.js';

/**
 * Pinned manifest.  Paste the 9 file SHAs + 4 GHCR digests from the
 * \`release-build.yml\` producer run's paste-block, bump \`tag\`, rebuild
 * \`dist/\`, and commit before pushing the release tag.  See the file header
 * for the full build-once / download-forever update workflow.
 */
`;

/** The upstream repo this tool releases; carries the rename comment in the literal. */
const UPSTREAM_REPO = 'Brooooooklyn/script-jail';

/** Repo line for the upstream default (with its trailing inline comment). */
const MANIFEST_REPO_LINE =
  `  repo: '${UPSTREAM_REPO}', // renamed from scriptjail (old name redirects)`;

/**
 * The `repo:` line for the literal.  The upstream default reproduces the exact
 * committed line (with the rename comment) so the byte-oracle holds; a validated
 * non-default repo gets a plain line (so `--repo` is honored, not silently
 * dropped).  `repo` MUST be assertRepo-validated before this is called.
 */
function repoLine(repo: string): string {
  return repo === UPSTREAM_REPO ? MANIFEST_REPO_LINE : `  repo: '${repo}',`;
}

/**
 * A literal value line `'<key>': '<value>',` for one section, with `value`
 * padded so the opening value-quote lands at `valueCol` (0-based index within
 * the line).  Indentation is 6 spaces (`expected.<platform>.<key>`).
 */
function valueLine(key: string, value: string, valueCol: number): string {
  const prefix = `      '${key}': `;
  // prefix already ends with one space after the colon; pad to reach valueCol.
  const pad = ' '.repeat(Math.max(0, valueCol - prefix.length));
  return `${prefix}${pad}'${value}',`;
}

/** Compute the value-quote column for a section: indent(6) + maxQuotedKey + 2. */
function sectionValueCol(keys: ReadonlyArray<string>): number {
  let maxQuotedKey = 0;
  for (const key of keys) {
    const quoted = key.length + 2; // surrounding single quotes
    if (quoted > maxQuotedKey) maxQuotedKey = quoted;
  }
  return 6 + maxQuotedKey + 2; // 6 indent + key + `: `
}

/**
 * Typed full-literal codegen of `src/action/artifact-manifest.ts`.  Byte-stable:
 * reproduces the static header, JSDoc, repo constant, the load-bearing inline
 * comments, and the per-section column padding exactly.
 */
export function renderArtifactManifestTs(manifest: ArtifactManifest): string {
  const { tag, expected, dockerImages } = manifest;
  if (dockerImages === undefined) {
    throw new Error('release-backfill: manifest.dockerImages is required for codegen.');
  }

  // Every value interpolated into the generated TS literal must be strictly
  // shaped FIRST — `tag`/`repo` could otherwise break out of a single-quoted
  // string and inject code into the committed manifest.
  assertTag(tag);
  assertRepo(manifest.repo);

  const linux = expected.linux;
  const darwin = expected.darwin;

  const linuxCol = sectionValueCol(Object.keys(linux));
  const darwinCol = sectionValueCol(Object.keys(darwin));

  const get = (section: Record<string, string>, key: string): string => {
    const v = section[key];
    if (v === undefined) {
      throw new Error(`release-backfill: manifest is missing expected key '${key}'.`);
    }
    if (!/^[0-9a-f]{64}$/.test(v)) {
      throw new Error(
        `release-backfill: expected key '${key}' is not a 64-char lowercase sha256: '${v}'.`,
      );
    }
    return v;
  };

  const dockerRef = (arch: ArtifactArch, image: RunnerImage): string => {
    const ref = dockerImages[arch]?.[image];
    if (ref === undefined) {
      throw new Error(
        `release-backfill: manifest is missing dockerImages.${arch}['${image}'].`,
      );
    }
    if (!GHCR_REF_RE.test(ref)) {
      throw new Error(
        `release-backfill: dockerImages.${arch}['${image}'] is not a valid ` +
          `digest-pinned GHCR ref: '${ref}'.`,
      );
    }
    return ref;
  };

  const lines: string[] = [];
  lines.push(MANIFEST_HEADER.replace(/\n$/, '')); // header already ends with one newline
  lines.push(`export const PINNED_MANIFEST: ArtifactManifest = {`);
  lines.push(repoLine(manifest.repo));
  lines.push(`  tag: '${tag}',`);
  lines.push(`  expected: {`);
  lines.push(`    linux: {`);
  lines.push(valueLine('rootfs-ubuntu-22.04.ext4', get(linux, 'rootfs-ubuntu-22.04.ext4'), linuxCol));
  lines.push(valueLine('rootfs-ubuntu-24.04.ext4', get(linux, 'rootfs-ubuntu-24.04.ext4'), linuxCol));
  lines.push(valueLine('libscriptjail.so', get(linux, 'libscriptjail.so'), linuxCol));
  lines.push(`    },`);
  lines.push(`    darwin: {`);
  lines.push(valueLine('rootfs-ubuntu-22.04-arm64.ext4', get(darwin, 'rootfs-ubuntu-22.04-arm64.ext4'), darwinCol));
  lines.push(valueLine('rootfs-ubuntu-24.04-arm64.ext4', get(darwin, 'rootfs-ubuntu-24.04-arm64.ext4'), darwinCol));
  lines.push(valueLine('libscriptjail-arm64.so', get(darwin, 'libscriptjail-arm64.so'), darwinCol));
  lines.push(`      // macOS-native Mach-O shim for the bare backend (DYLD_INSERT_LIBRARIES),`);
  lines.push(`      // ad-hoc signed in build-mac-bin; pinned by a plain sha256 of the signed`);
  lines.push(`      // dylib (backfilled from the v0.2.2 producer run 27406262406).`);
  lines.push(valueLine('libscriptjail-arm64.dylib', get(darwin, 'libscriptjail-arm64.dylib'), darwinCol));
  lines.push(`      // Bare-backend SIP-substitution binaries (the shim redirects /bin/sh +`);
  lines.push(`      // coreutils to these plain-arm64 binaries, so no arm64e dylib is needed).`);
  lines.push(`      // coreutils-arm64 is the official uutils 0.4.0 prebuilt — a fixed upstream`);
  lines.push(`      // artifact with a stable BINARY sha (producer recomputed it to the same`);
  lines.push(`      // value).  bash-arm64 is built-from-source by the producer; byte-identical`);
  lines.push(`      // across the v0.2.0/v0.2.1/v0.2.2 producer runs.`);
  lines.push(valueLine('coreutils-arm64', get(darwin, 'coreutils-arm64'), darwinCol));
  lines.push(valueLine('bash-arm64', get(darwin, 'bash-arm64'), darwinCol));
  lines.push(valueLine('vmlinux-vz-x86_64', get(darwin, 'vmlinux-vz-x86_64'), darwinCol));
  lines.push(valueLine('vmlinux-vz-arm64', get(darwin, 'vmlinux-vz-arm64'), darwinCol));
  lines.push(`      // No \`script-jail-vm-x86_64-darwin\` — see the file header for the`);
  lines.push(`      // Intel-macOS-runner deprecation note.`);
  lines.push(valueLine('script-jail-vm-arm64-darwin', get(darwin, 'script-jail-vm-arm64-darwin'), darwinCol));
  lines.push(`    },`);
  lines.push(`  },`);
  lines.push(`  dockerImages: {`);
  lines.push(`    x64: {`);
  lines.push(`      'ubuntu-22.04': '${dockerRef('x64', 'ubuntu-22.04')}',`);
  lines.push(`      'ubuntu-24.04': '${dockerRef('x64', 'ubuntu-24.04')}',`);
  lines.push(`    },`);
  lines.push(`    arm64: {`);
  lines.push(`      'ubuntu-22.04': '${dockerRef('arm64', 'ubuntu-22.04')}',`);
  lines.push(`      'ubuntu-24.04': '${dockerRef('arm64', 'ubuntu-24.04')}',`);
  lines.push(`    },`);
  lines.push(`  },`);
  lines.push(`};`);

  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// bumpVersion
// ---------------------------------------------------------------------------

/**
 * Set `package.json` `version` to the BARE version (no leading `v`), preserving
 * the file's 2-space indentation and trailing newline.  Throws if the version
 * arg carries a `v` prefix (the CLI passes the bare form; this guards a typo).
 */
export function bumpVersion(pkgJsonPath: string, version: string): void {
  // Strict bare semver (also rejects a leading 'v' and any injection metachar).
  assertBareVersion(version);
  const raw = readFileSync(pkgJsonPath, 'utf8');
  const hadTrailingNewline = raw.endsWith('\n');
  const pkg = JSON.parse(raw) as Record<string, unknown>;
  pkg.version = version;
  // 2-space indent (matches the committed package.json); add back the trailing
  // newline JSON.stringify drops.
  const out = JSON.stringify(pkg, null, 2) + (hadTrailingNewline ? '\n' : '');
  writeFileSync(pkgJsonPath, out);
}

// ---------------------------------------------------------------------------
// buildManifest
// ---------------------------------------------------------------------------

/**
 * Assemble an `ArtifactManifest` from a staged tree + buildx push log.  The
 * `tag` is derived as `v${version}` from the bare version.
 */
export async function buildManifest({
  stagedDir,
  buildLogText,
  repo,
  version,
}: {
  stagedDir: string;
  buildLogText: string;
  repo: string;
  version: string;
}): Promise<ArtifactManifest> {
  assertBareVersion(version);
  assertRepo(repo);
  const tag = `v${version}`;
  const expected = await computeManifestExpected(stagedDir);
  const dockerImages = parseDockerDigestsFromLog(buildLogText, { repo, tag });
  return { repo, tag, expected, dockerImages };
}

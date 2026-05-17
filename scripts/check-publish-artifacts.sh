#!/usr/bin/env bash
# script-jail — scripts/check-publish-artifacts.sh
#
# Publish-job gate.  Verifies the build-job artifacts about to be uploaded to
# a GitHub release match the SHA-256 digests recorded in the tagged source's
# `src/action/artifact-manifest.ts` and (for `dist/main.js`) the bytes of the
# tagged `dist/main.js` itself.
#
# Why this exists:
#   The release workflow splits into two jobs.  The `build` job runs npm/pnpm
#   lifecycle scripts and Docker — i.e. third-party code — under a read-only
#   token, then hands artifacts to the `publish` job via actions/upload-artifact.
#   The `publish` job carries `contents: write`.  If a compromised dependency
#   tampered with an artifact in the build job, the publish job would
#   blindly upload the tampered bytes to the release.
#
#   This script runs in the publish job AFTER a fresh checkout of the tagged
#   source and BEFORE the upload step.  It re-derives the expected SHAs from
#   the in-repo manifest (and the in-repo dist/main.js), recomputes the SHAs
#   of the downloaded artifacts, and refuses to proceed on mismatch.
#
# Bootstrap path:
#   On the very first tag of a fresh fork, `PINNED_MANIFEST.expected` is
#   entirely placeholders — there are no real SHAs to verify against yet.  In
#   that documented case we emit a warning and proceed so the maintainer can
#   copy the published SHAs into the manifest and cut the next tag.  Mixed
#   manifests (some real, some placeholder) are treated as bugs and rejected.
#
# Flags:
#   --manifest <path>      Path to src/action/artifact-manifest.ts (required).
#   --dir <path>           Directory containing the downloaded artifacts
#                          (expects images/ and dist/ subdirs).
#   --dist-source <path>   Optional path to the tagged dist/main.js to compare
#                          the artifact's dist/main.js against.  When omitted,
#                          dist/main.js verification is skipped (useful for
#                          tests that only exercise the manifest path).

set -euo pipefail

MANIFEST=""
DIR=""
DIST_SOURCE=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:-}"
      shift 2
      ;;
    --dir)
      DIR="${2:-}"
      shift 2
      ;;
    --dist-source)
      DIST_SOURCE="${2:-}"
      shift 2
      ;;
    *)
      echo "check-publish-artifacts: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$MANIFEST" ] || [ -z "$DIR" ]; then
  echo "check-publish-artifacts: --manifest and --dir are required" >&2
  exit 2
fi

if [ ! -f "$MANIFEST" ]; then
  echo "check-publish-artifacts: manifest file not found: $MANIFEST" >&2
  exit 1
fi

# --- Parse manifest -----------------------------------------------------------
#
# We do NOT run `pnpm install` in the publish job (that would re-introduce
# the third-party-code threat we're defending against), so we cannot import
# the TypeScript module.  Instead we grep the three known keys directly.
#
# Each entry in PINNED_MANIFEST.expected matches the form (whitespace-tolerant):
#     '<name>': '<value>',
# where <value> is either a 64-char lowercase hex SHA or a
# PLACEHOLDER_SHA256_<NAME> bootstrap string.
#
# The parser is intentionally strict to defeat a few specific poisoning
# vectors a malicious or sloppy change to the source file could introduce:
#
#   1. Scope: we extract the `expected: { ... }` block from PINNED_MANIFEST
#      and ONLY search inside that block.  A stray example line in a comment
#      or another exported map elsewhere in the file cannot satisfy the
#      regex.
#   2. Metacharacter safety: artifact names contain `.` which is a regex
#      wildcard.  We escape the key before interpolating it into the regex
#      so `rootfs-ubuntu-22x04xext4` does not silently substitute for
#      `rootfs-ubuntu-22.04.ext4`.
#   3. Single-match: we require exactly ONE line per key.  A duplicate
#      definition (whether deliberate or the result of a bad merge) fails
#      the parser instead of silently picking one.
#
# The extraction prints the value to stdout; success/failure is signalled by
# exit code, and ALL diagnostics go to stderr so they're never confused with
# the value itself.

# Extract the `expected: { ... }` block of PINNED_MANIFEST into a temp file
# so subsequent greps cannot match against unrelated parts of the source.
#
# Strategy: awk state machine — once we see `export const PINNED_MANIFEST`
# we wait for the literal `expected: {` opener, then echo every line until
# the matching `}` at the same indentation.  This is intentionally
# brittle-by-design: any reformatting of the manifest source must keep the
# `expected: {` / `},` pattern this script depends on.
EXPECTED_BLOCK="$(awk '
  BEGIN { in_manifest = 0; in_expected = 0 }
  /export[[:space:]]+const[[:space:]]+PINNED_MANIFEST/ { in_manifest = 1; next }
  in_manifest && /^[[:space:]]*expected:[[:space:]]*\{/ { in_expected = 1; next }
  in_expected && /^[[:space:]]*\},?[[:space:]]*$/ { in_expected = 0; in_manifest = 0; exit }
  in_expected { print }
' "$MANIFEST")"

if [ -z "$EXPECTED_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate PINNED_MANIFEST.expected { ... } block in $MANIFEST" >&2
  exit 1
fi

# Escape regex metacharacters in a string so it can be interpolated into a
# POSIX/ERE pattern as a literal.  We escape the BRE/ERE special set; the
# manifest keys we care about contain `.` and `-`, neither of which appears
# in our key set as an intentional regex feature.
escape_regex() {
  printf '%s' "$1" | sed -E 's/[][\\.^$*+?(){}|/-]/\\&/g'
}

# Extract the value for a manifest key from the captured expected block.
# Requires EXACTLY one match (zero or multiple is an error).  Echoes the
# value on success; on failure echoes a diagnostic to stderr and returns 1.
extract_expected() {
  local name="$1"
  local escaped
  escaped="$(escape_regex "$name")"
  local matches
  matches="$(printf '%s\n' "$EXPECTED_BLOCK" | grep -cE "^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'[^']*'[[:space:]]*,?[[:space:]]*\$" || true)"
  if [ "$matches" -eq 0 ]; then
    echo "check-publish-artifacts: manifest key not found: '${name}'" >&2
    return 1
  fi
  if [ "$matches" -gt 1 ]; then
    echo "check-publish-artifacts: manifest key '${name}' appears $matches times — must appear exactly once." >&2
    return 1
  fi
  printf '%s\n' "$EXPECTED_BLOCK" \
    | grep -E "^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'[^']*'[[:space:]]*,?[[:space:]]*\$" \
    | sed -E "s/^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'([^']*)'.*/\1/"
}

# `set -e` would normally swallow extract_expected's non-zero exit inside
# command substitution.  We catch failures explicitly so the error message
# the helper printed to stderr surfaces with a non-zero exit.
if ! EXPECTED_ROOTFS_22="$(extract_expected 'rootfs-ubuntu-22.04.ext4')"; then
  exit 1
fi
if ! EXPECTED_ROOTFS_24="$(extract_expected 'rootfs-ubuntu-24.04.ext4')"; then
  exit 1
fi
if ! EXPECTED_LIBSO="$(extract_expected 'libscriptjail.so')"; then
  exit 1
fi

# --- Classify placeholders ----------------------------------------------------

PLACEHOLDER_PREFIX="PLACEHOLDER_SHA256_"

is_placeholder() {
  case "$1" in
    "${PLACEHOLDER_PREFIX}"*) return 0 ;;
    *) return 1 ;;
  esac
}

PLACEHOLDER_COUNT=0
REAL_COUNT=0
for v in "$EXPECTED_ROOTFS_22" "$EXPECTED_ROOTFS_24" "$EXPECTED_LIBSO"; do
  if is_placeholder "$v"; then
    PLACEHOLDER_COUNT=$((PLACEHOLDER_COUNT + 1))
  else
    REAL_COUNT=$((REAL_COUNT + 1))
  fi
done

ALL_PLACEHOLDERS=0
if [ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -eq 0 ]; then
  ALL_PLACEHOLDERS=1
fi

# --- Locate artifacts ---------------------------------------------------------

ART_ROOTFS_22="$DIR/images/rootfs-ubuntu-22.04.ext4"
ART_ROOTFS_24="$DIR/images/rootfs-ubuntu-24.04.ext4"
ART_LIBSO="$DIR/images/libscriptjail.so"
ART_DIST="$DIR/dist/main.js"

# Artifacts must exist in BOTH modes — a missing file means the build job's
# upload-artifact step is broken, not a bootstrap nuance.
missing=()
for f in "$ART_ROOTFS_22" "$ART_ROOTFS_24" "$ART_LIBSO" "$ART_DIST"; do
  if [ ! -f "$f" ]; then
    missing+=("$f")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "check-publish-artifacts: required artifact(s) missing from $DIR:" >&2
  for f in "${missing[@]}"; do
    echo "  $f" >&2
  done
  exit 1
fi

# --- Compute artifact SHAs ----------------------------------------------------

sha_of() {
  sha256sum "$1" | cut -d' ' -f1
}

COMPUTED_ROOTFS_22="$(sha_of "$ART_ROOTFS_22")"
COMPUTED_ROOTFS_24="$(sha_of "$ART_ROOTFS_24")"
COMPUTED_LIBSO="$(sha_of "$ART_LIBSO")"
COMPUTED_DIST="$(sha_of "$ART_DIST")"

# --- Mixed-manifest is a packaging bug (checked BEFORE bootstrap) -------------

if [ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]; then
  echo "check-publish-artifacts: manifest has $PLACEHOLDER_COUNT placeholder entr(ies) mixed with $REAL_COUNT real SHA(s)." >&2
  echo "  This is a packaging bug — either every entry is a real SHA (normal release)," >&2
  echo "  or every entry is a placeholder (documented bootstrap loop)." >&2
  echo "  Fix src/action/artifact-manifest.ts before tagging." >&2
  exit 1
fi

# --- Verify dist/main.js (runs in BOTH normal and bootstrap modes) -----------
#
# dist/main.js is not in PINNED_MANIFEST.expected — instead it's committed to
# the tag (Task #20).  The fresh-checkout copy is an independent source of
# truth that doesn't depend on the manifest, so the comparison is meaningful
# even when the manifest itself is in bootstrap placeholders.  Skipping this
# check in bootstrap mode would leave the JavaScript action bundle outside
# the new gate exactly when consumers most need it intact.

errors=()
check() {
  local name="$1"
  local expected="$2"
  local computed="$3"
  if [ "$expected" != "$computed" ]; then
    errors+=("$name: expected=$expected computed=$computed")
  fi
}

if [ -n "$DIST_SOURCE" ]; then
  if [ ! -f "$DIST_SOURCE" ]; then
    echo "check-publish-artifacts: --dist-source given but file not found: $DIST_SOURCE" >&2
    exit 1
  fi
  EXPECTED_DIST="$(sha_of "$DIST_SOURCE")"
  check "dist/main.js" "$EXPECTED_DIST" "$COMPUTED_DIST"
fi

# --- Bootstrap path -----------------------------------------------------------
#
# All-placeholder manifest: the rootfs/libso SHAs have no trustworthy
# reference yet (this IS the run that produces them), so we skip those
# three comparisons and print the computed values for the maintainer to
# paste into the manifest.  The dist/main.js comparison above still ran.

if [ "$ALL_PLACEHOLDERS" -eq 1 ]; then
  echo "::warning::check-publish-artifacts: PINNED_MANIFEST.expected is entirely placeholders; skipping SHA comparison (bootstrap path). Copy the SHAs below into src/action/artifact-manifest.ts and cut the next tag."
  echo "check-publish-artifacts: bootstrap mode — manifest entries are placeholders." >&2
  echo "  rootfs-ubuntu-22.04.ext4: $COMPUTED_ROOTFS_22" >&2
  echo "  rootfs-ubuntu-24.04.ext4: $COMPUTED_ROOTFS_24" >&2
  echo "  libscriptjail.so:             $COMPUTED_LIBSO" >&2
  echo "  dist/main.js:             $COMPUTED_DIST" >&2
  if [ "${#errors[@]}" -gt 0 ]; then
    echo "check-publish-artifacts: dist/main.js mismatch in bootstrap mode — refusing to publish." >&2
    for e in "${errors[@]}"; do
      echo "  $e" >&2
    done
    exit 1
  fi
  exit 0
fi

# --- Compare manifest-pinned artifacts ----------------------------------------

check "rootfs-ubuntu-22.04.ext4" "$EXPECTED_ROOTFS_22" "$COMPUTED_ROOTFS_22"
check "rootfs-ubuntu-24.04.ext4" "$EXPECTED_ROOTFS_24" "$COMPUTED_ROOTFS_24"
check "libscriptjail.so"             "$EXPECTED_LIBSO"     "$COMPUTED_LIBSO"

if [ "${#errors[@]}" -gt 0 ]; then
  echo "check-publish-artifacts: SHA mismatch — refusing to publish." >&2
  for e in "${errors[@]}"; do
    echo "  $e" >&2
  done
  exit 1
fi

echo "check-publish-artifacts: OK — all artifact SHAs match the tagged manifest."

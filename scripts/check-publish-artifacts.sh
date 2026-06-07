#!/usr/bin/env bash
# script-jail — scripts/check-publish-artifacts.sh
#
# Publish-job gate.  Verifies the build-job artifacts about to be uploaded to
# a GitHub release match the SHA-256 digests recorded in the tagged source's
# `src/action/artifact-manifest.ts` and (for `dist/main.cjs`) the bytes of the
# tagged `dist/main.cjs` itself.
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
#   the in-repo manifest (and the in-repo dist/main.cjs), recomputes the SHAs
#   of the downloaded artifacts, and refuses to proceed on mismatch.
#
# Bootstrap path:
#   On the very first tag of a fresh fork, every entry in
#   `PINNED_MANIFEST.expected.{linux,darwin}` AND every digest-pinned ref in
#   `PINNED_MANIFEST.dockerImages.{x64,arm64}` is a placeholder — there are no
#   real SHAs to verify against yet.  In that documented case we emit a
#   warning and proceed so the maintainer can copy the published SHAs into
#   the manifest and cut the next tag.  Mixed manifests (some real, some
#   placeholder) are treated as bugs and rejected.  The all-or-nothing
#   classification spans BOTH the 10 file SHAs and the 4 Docker image refs:
#   pasting real file SHAs while leaving the Docker refs as placeholders (or
#   vice versa) trips the mixed-manifest reject.
#
# Manifest shape:
#   `PINNED_MANIFEST.expected` is platform-keyed:
#     expected: {
#       linux:  { 'rootfs-…': '<sha>', 'libscriptjail.so': '<sha>', … },
#       darwin: { 'vmlinux-vz-x86_64': '<sha>', 'libscriptjail-arm64.so': …, … },
#     }
#   The parser walks each `<platform>: { ... }` sub-block and extracts the
#   keys it cares about.  The `<platform>` prefix in offender messages
#   disambiguates the two sections (`linux/libscriptjail.so` vs.
#   `darwin/libscriptjail-arm64.so`).
#
#   `PINNED_MANIFEST.dockerImages` is arch-keyed, each arch holding two
#   Ubuntu-major image refs:
#     dockerImages: {
#       x64:   { 'ubuntu-22.04': '<ref>', 'ubuntu-24.04': '<ref>' },
#       arm64: { 'ubuntu-22.04': '<ref>', 'ubuntu-24.04': '<ref>' },
#     }
#   Each `<ref>` is a digest-pinned GHCR pull spec of the form
#   `ghcr.io/<owner>/script-jail-rootfs:<tag>@sha256:<digest-or-placeholder>`.
#   We extract all 4 refs and fold them into the placeholder/real
#   classification.  Note a Docker ref NEVER starts with the
#   `PLACEHOLDER_SHA256_` prefix (it starts with `ghcr.io/`), so a ref is
#   classified as a placeholder when it CONTAINS the `PLACEHOLDER_SHA256_`
#   substring (the placeholder digest token), else real.  Docker refs are NOT
#   SHA-verified against downloaded files here (there is no local file to
#   hash); they participate only in the all-or-nothing placeholder/real
#   classification so a partially-backfilled manifest is caught before tagging.
#
# Flags:
#   --manifest <path>          Path to src/action/artifact-manifest.ts (required).
#   --dir <path>               Directory containing the downloaded artifacts
#                              (expects images/ and dist/ subdirs).
#   --dist-source <path>       Optional path to the tagged dist/main.cjs to compare
#                              the artifact's dist/main.cjs against.  When omitted,
#                              dist/main.cjs is neither REQUIRED in the artifact
#                              dir nor verified — under the build-once/download-
#                              forever contract the producer ships no dist/* in
#                              the artifact set (the dist that ships comes from the
#                              tagged checkout), so release.yml omits this flag and
#                              the downloaded dir has no dist/ subtree.  Also used
#                              by tests that only exercise the manifest path.
#   --dist-cli-source <path>   Optional path to the tagged dist/cli.cjs to compare
#                              the artifact's dist/cli.cjs against.  Same threat
#                              class as --dist-source: the publish job downloads
#                              dist/cli.cjs from the build job and uploads it to
#                              the release; a tampered cli.cjs would ship to npm
#                              consumers.  When omitted, dist/cli.cjs verification
#                              is silently skipped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MANIFEST=""
DIR=""
DIST_SOURCE=""
DIST_CLI_SOURCE=""
# Standalone canonical-rootfs-hash bundle (dist/repro-hash-cli.cjs).  The rootfs
# ext4 entries in the manifest are pinned by their CANONICAL hash (volatile
# superblock time fields masked — see src/rootfs/repro-hash.ts), NOT a plain
# sha256sum, so we recompute them the same way the build job's "Compute SHAs"
# step did and the consumer's preFetchArtifacts does.  We run the COMMITTED
# bundle with `node` (no pnpm install in the publish job — that would
# reintroduce the third-party-code threat this gate defends against).  Default
# is the bundle in the tagged checkout; --repro-hash-cli overrides it (tests).
REPRO_HASH_CLI=""

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
    --dist-cli-source)
      DIST_CLI_SOURCE="${2:-}"
      shift 2
      ;;
    --repro-hash-cli)
      REPRO_HASH_CLI="${2:-}"
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

# Resolve the canonical-rootfs-hash bundle (default: tagged checkout's dist/).
if [ -z "$REPRO_HASH_CLI" ]; then
  REPRO_HASH_CLI="$SCRIPT_DIR/../dist/repro-hash-cli.cjs"
fi
if [ ! -f "$REPRO_HASH_CLI" ]; then
  echo "check-publish-artifacts: repro-hash CLI not found: $REPRO_HASH_CLI" >&2
  echo "  (run 'pnpm build:repro-hash' and commit dist/repro-hash-cli.cjs)" >&2
  exit 1
fi

if [ ! -f "$MANIFEST" ]; then
  echo "check-publish-artifacts: manifest file not found: $MANIFEST" >&2
  exit 1
fi

# --- Parse manifest -----------------------------------------------------------
#
# We do NOT run `pnpm install` in the publish job (that would re-introduce
# the third-party-code threat we're defending against), so we cannot import
# the TypeScript module.  Instead we grep the known keys directly per
# platform section.
#
# Each entry in the nested expected block matches (whitespace-tolerant):
#     '<name>': '<value>',
# where <value> is either a 64-char lowercase hex SHA or a
# PLACEHOLDER_SHA256_<NAME> bootstrap string.
#
# Two-pass extraction:
#   1. Pull out the `expected: { ... }` block of PINNED_MANIFEST.
#   2. Within that block, split into one sub-block per platform key
#      (`linux: { ... }`, `darwin: { ... }`) and scope each value lookup to
#      that sub-block.
#
# The parser is intentionally strict to defeat a few specific poisoning
# vectors a malicious or sloppy change to the source file could introduce:
#
#   1. Scope: we extract `expected: { ... }` from PINNED_MANIFEST and then
#      EACH `<platform>: { ... }` sub-block before searching for asset
#      values.  A stray example line in a comment or another exported map
#      elsewhere in the file cannot satisfy the regex.
#   2. Metacharacter safety: artifact names contain `.` which is a regex
#      wildcard.  We escape the key before interpolating it into the regex
#      so `rootfs-ubuntu-22x04xext4` does not silently substitute for
#      `rootfs-ubuntu-22.04.ext4`.
#   3. Single-match: we require exactly ONE line per key per platform.  A
#      duplicate definition (whether deliberate or the result of a bad
#      merge) fails the parser instead of silently picking one.
#
# The extraction prints the value to stdout; success/failure is signalled by
# exit code, and ALL diagnostics go to stderr so they're never confused with
# the value itself.

# Extract the `expected: { ... }` block of PINNED_MANIFEST into a variable.
# Strategy: awk state machine that counts `{` / `}` characters so the
# extraction survives nested sub-blocks (`linux: { ... }` and
# `darwin: { ... }` inside expected). We start the
# depth counter at 1 immediately after seeing `expected: {`, then echo
# every line until depth returns to 0.
#
# The depth counter is intentionally character-based (gsub returns the
# count) rather than line-based: a stray `}` in a string value would be
# rare in this file (asset names contain only `[A-Za-z0-9._-]`), but
# counting characters is robust to "two braces on one line" and matches
# how a JS parser would walk the file.
EXPECTED_BLOCK="$(awk '
  BEGIN { in_manifest = 0; in_expected = 0; depth = 0 }
  /export[[:space:]]+const[[:space:]]+PINNED_MANIFEST/ { in_manifest = 1; next }
  in_manifest && /^[[:space:]]*expected:[[:space:]]*\{/ { in_expected = 1; depth = 1; next }
  in_expected {
    opens  = gsub(/\{/, "{", $0)
    closes = gsub(/\}/, "}", $0)
    depth += opens - closes
    if (depth <= 0) { in_expected = 0; in_manifest = 0; exit }
    print
  }
' "$MANIFEST")"

if [ -z "$EXPECTED_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate PINNED_MANIFEST.expected { ... } block in $MANIFEST" >&2
  exit 1
fi

# Carve a platform sub-block out of EXPECTED_BLOCK.  We rely on the same
# `<key>: { ... }` opener/closer pattern as the outer extraction.  Platform
# keys MUST appear at the start of their line (`linux:` or `darwin:`).
extract_platform_block() {
  local platform="$1"
  printf '%s\n' "$EXPECTED_BLOCK" | awk -v plat="$platform" '
    BEGIN { in_section = 0 }
    !in_section && $0 ~ ("^[[:space:]]*" plat ":[[:space:]]*\\{") { in_section = 1; next }
    in_section && /^[[:space:]]*\},?[[:space:]]*$/ { in_section = 0; exit }
    in_section { print }
  '
}

LINUX_BLOCK="$(extract_platform_block 'linux')"
DARWIN_BLOCK="$(extract_platform_block 'darwin')"

if [ -z "$LINUX_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate linux: { ... } sub-block inside PINNED_MANIFEST.expected" >&2
  exit 1
fi
if [ -z "$DARWIN_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate darwin: { ... } sub-block inside PINNED_MANIFEST.expected" >&2
  exit 1
fi

# Extract the `dockerImages: { ... }` block of PINNED_MANIFEST into a variable.
# `dockerImages` lives at the same nesting level as `expected` (a direct
# property of PINNED_MANIFEST), NOT inside it — so we re-run the same
# brace-counting awk state machine over the whole manifest rather than carving
# it out of EXPECTED_BLOCK.  The depth counter starts at 1 immediately after
# seeing `dockerImages: {` and echoes every line until depth returns to 0,
# surviving the nested `x64: { ... }` / `arm64: { ... }` arch sub-blocks.
DOCKER_BLOCK="$(awk '
  BEGIN { in_manifest = 0; in_docker = 0; depth = 0 }
  /export[[:space:]]+const[[:space:]]+PINNED_MANIFEST/ { in_manifest = 1; next }
  in_manifest && /^[[:space:]]*dockerImages:[[:space:]]*\{/ { in_docker = 1; depth = 1; next }
  in_docker {
    opens  = gsub(/\{/, "{", $0)
    closes = gsub(/\}/, "}", $0)
    depth += opens - closes
    if (depth <= 0) { in_docker = 0; in_manifest = 0; exit }
    print
  }
' "$MANIFEST")"

if [ -z "$DOCKER_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate PINNED_MANIFEST.dockerImages { ... } block in $MANIFEST" >&2
  exit 1
fi

# Carve an arch sub-block out of DOCKER_BLOCK.  Mirrors extract_platform_block:
# the same `<key>: { ... }` opener/closer pattern.  Arch keys (`x64`, `arm64`)
# MUST appear at the start of their line.
extract_arch_block() {
  local arch="$1"
  printf '%s\n' "$DOCKER_BLOCK" | awk -v a="$arch" '
    BEGIN { in_section = 0 }
    !in_section && $0 ~ ("^[[:space:]]*" a ":[[:space:]]*\\{") { in_section = 1; next }
    in_section && /^[[:space:]]*\},?[[:space:]]*$/ { in_section = 0; exit }
    in_section { print }
  '
}

DOCKER_X64_BLOCK="$(extract_arch_block 'x64')"
DOCKER_ARM64_BLOCK="$(extract_arch_block 'arm64')"

if [ -z "$DOCKER_X64_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate x64: { ... } sub-block inside PINNED_MANIFEST.dockerImages" >&2
  exit 1
fi
if [ -z "$DOCKER_ARM64_BLOCK" ]; then
  echo "check-publish-artifacts: could not locate arm64: { ... } sub-block inside PINNED_MANIFEST.dockerImages" >&2
  exit 1
fi

# Escape regex metacharacters in a string so it can be interpolated into a
# POSIX/ERE pattern as a literal.  We escape the BRE/ERE special set; the
# manifest keys we care about contain `.` and `-`, neither of which appears
# in our key set as an intentional regex feature.
escape_regex() {
  printf '%s' "$1" | sed -E 's/[][\\.^$*+?(){}|/-]/\\&/g'
}

# Extract the value for a manifest key from a given block.  Requires EXACTLY
# one match (zero or multiple is an error).  Echoes the value on success; on
# failure echoes a diagnostic to stderr and returns 1.  The `platform`
# argument is used purely for diagnostic prefixes (`linux/...`, `darwin/...`).
extract_from_block() {
  local platform="$1"
  local block="$2"
  local name="$3"
  local escaped
  escaped="$(escape_regex "$name")"
  local matches
  matches="$(printf '%s\n' "$block" | grep -cE "^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'[^']*'[[:space:]]*,?[[:space:]]*\$" || true)"
  if [ "$matches" -eq 0 ]; then
    echo "check-publish-artifacts: manifest key not found: '${platform}/${name}'" >&2
    return 1
  fi
  if [ "$matches" -gt 1 ]; then
    echo "check-publish-artifacts: manifest key '${platform}/${name}' appears $matches times — must appear exactly once." >&2
    return 1
  fi
  printf '%s\n' "$block" \
    | grep -E "^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'[^']*'[[:space:]]*,?[[:space:]]*\$" \
    | sed -E "s/^[[:space:]]*'${escaped}'[[:space:]]*:[[:space:]]*'([^']*)'.*/\1/"
}

# `set -e` would normally swallow extract_from_block's non-zero exit inside
# command substitution.  We catch failures explicitly so the error message
# the helper printed to stderr surfaces with a non-zero exit.

# --- Linux platform keys ------------------------------------------------------
if ! EXPECTED_LINUX_ROOTFS_22="$(extract_from_block 'linux' "$LINUX_BLOCK" 'rootfs-ubuntu-22.04.ext4')"; then
  exit 1
fi
if ! EXPECTED_LINUX_ROOTFS_24="$(extract_from_block 'linux' "$LINUX_BLOCK" 'rootfs-ubuntu-24.04.ext4')"; then
  exit 1
fi
if ! EXPECTED_LINUX_LIBSO="$(extract_from_block 'linux' "$LINUX_BLOCK" 'libscriptjail.so')"; then
  exit 1
fi

# --- Darwin platform keys -----------------------------------------------------
if ! EXPECTED_DARWIN_ROOTFS_22_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'rootfs-ubuntu-22.04-arm64.ext4')"; then
  exit 1
fi
if ! EXPECTED_DARWIN_ROOTFS_24_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'rootfs-ubuntu-24.04-arm64.ext4')"; then
  exit 1
fi
if ! EXPECTED_DARWIN_LIBSO_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'libscriptjail-arm64.so')"; then
  exit 1
fi
# The macOS-native Mach-O shim (bare backend). Pinned by a PLAIN sha256 — like
# the .so shims / kernels / Mach-O VZ helper, NOT the canonical rootfs hash.
if ! EXPECTED_DARWIN_DYLIB_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'libscriptjail-arm64.dylib')"; then
  exit 1
fi
# Bare-backend SIP-substitution binaries (plain arm64). Pinned by PLAIN sha256
# like the dylib. coreutils-arm64 is the fixed uutils prebuilt's BINARY sha;
# bash-arm64 is producer-built (placeholder until backfilled).
if ! EXPECTED_DARWIN_COREUTILS_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'coreutils-arm64')"; then
  exit 1
fi
if ! EXPECTED_DARWIN_BASH_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'bash-arm64')"; then
  exit 1
fi
if ! EXPECTED_VMLINUX_VZ_X86_64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'vmlinux-vz-x86_64')"; then
  exit 1
fi
if ! EXPECTED_VMLINUX_VZ_ARM64="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'vmlinux-vz-arm64')"; then
  exit 1
fi
if ! EXPECTED_SJ_VM_ARM64_DARWIN="$(extract_from_block 'darwin' "$DARWIN_BLOCK" 'script-jail-vm-arm64-darwin')"; then
  exit 1
fi
# Intentionally NO key for `script-jail-vm-x86_64-darwin` — Intel macOS
# runners are deprecated and v1 does not ship that binary.  Adding the key
# here would force a stub artifact in the build job.

# --- Docker image refs --------------------------------------------------------
# The 4 digest-pinned GHCR refs live in PINNED_MANIFEST.dockerImages, keyed by
# arch then Ubuntu major.  Each value is a single-quoted string so the same
# extract_from_block helper applies; the arch is the diagnostic prefix.
if ! DOCKER_X64_22="$(extract_from_block 'x64' "$DOCKER_X64_BLOCK" 'ubuntu-22.04')"; then
  exit 1
fi
if ! DOCKER_X64_24="$(extract_from_block 'x64' "$DOCKER_X64_BLOCK" 'ubuntu-24.04')"; then
  exit 1
fi
if ! DOCKER_ARM64_22="$(extract_from_block 'arm64' "$DOCKER_ARM64_BLOCK" 'ubuntu-22.04')"; then
  exit 1
fi
if ! DOCKER_ARM64_24="$(extract_from_block 'arm64' "$DOCKER_ARM64_BLOCK" 'ubuntu-24.04')"; then
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

# Docker refs never START with the placeholder prefix — they start with
# `ghcr.io/` and carry the placeholder token in the `@sha256:` digest position
# (`...@sha256:PLACEHOLDER_SHA256_DOCKER_ROOTFS_<...>`).  So a ref is a
# placeholder when it CONTAINS the prefix substring anywhere, else real.
is_docker_placeholder() {
  case "$1" in
    *"${PLACEHOLDER_PREFIX}"*) return 0 ;;
    *) return 1 ;;
  esac
}

PLACEHOLDER_COUNT=0
REAL_COUNT=0
# The 12 file SHAs use the prefix-anchored placeholder test.
for v in \
  "$EXPECTED_LINUX_ROOTFS_22" "$EXPECTED_LINUX_ROOTFS_24" "$EXPECTED_LINUX_LIBSO" \
  "$EXPECTED_DARWIN_ROOTFS_22_ARM64" "$EXPECTED_DARWIN_ROOTFS_24_ARM64" \
  "$EXPECTED_DARWIN_LIBSO_ARM64" "$EXPECTED_DARWIN_DYLIB_ARM64" \
  "$EXPECTED_DARWIN_COREUTILS_ARM64" "$EXPECTED_DARWIN_BASH_ARM64" \
  "$EXPECTED_VMLINUX_VZ_X86_64" "$EXPECTED_VMLINUX_VZ_ARM64" \
  "$EXPECTED_SJ_VM_ARM64_DARWIN"
do
  if is_placeholder "$v"; then
    PLACEHOLDER_COUNT=$((PLACEHOLDER_COUNT + 1))
  else
    REAL_COUNT=$((REAL_COUNT + 1))
  fi
done

# The 4 Docker image refs participate in the SAME all-or-nothing
# classification, but use the substring placeholder test (a ref carries the
# placeholder token inside its `@sha256:` digest, not at the start).  Folding
# them in here means a real-files + placeholder-docker (or vice versa) manifest
# trips the mixed-manifest reject below.
for ref in \
  "$DOCKER_X64_22" "$DOCKER_X64_24" \
  "$DOCKER_ARM64_22" "$DOCKER_ARM64_24"
do
  if is_docker_placeholder "$ref"; then
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

# Linux platform artifacts (always required — the build job produces these).
ART_LINUX_ROOTFS_22="$DIR/images/rootfs-ubuntu-22.04.ext4"
ART_LINUX_ROOTFS_24="$DIR/images/rootfs-ubuntu-24.04.ext4"
ART_LINUX_LIBSO="$DIR/images/libscriptjail.so"
ART_DIST="$DIR/dist/main.cjs"
ART_DIST_CLI="$DIR/dist/cli.cjs"

# Darwin platform artifacts (built in the same release pipeline, uploaded as
# separate workflow artifacts, and aggregated here).
ART_DARWIN_ROOTFS_22_ARM64="$DIR/images/rootfs-ubuntu-22.04-arm64.ext4"
ART_DARWIN_ROOTFS_24_ARM64="$DIR/images/rootfs-ubuntu-24.04-arm64.ext4"
ART_DARWIN_LIBSO_ARM64="$DIR/images/libscriptjail-arm64.so"
ART_VMLINUX_VZ_X86_64="$DIR/images/vmlinux-vz-x86_64"
ART_VMLINUX_VZ_ARM64="$DIR/images/vmlinux-vz-arm64"
ART_SJ_VM_ARM64_DARWIN="$DIR/script-jail-vm-arm64-darwin"
# The macOS-native Mach-O shim is built on the macOS leg and downloaded to the
# artifacts ROOT (next to script-jail-vm-arm64-darwin), NOT under images/.
ART_DARWIN_DYLIB_ARM64="$DIR/libscriptjail-arm64.dylib"
# Bare-backend SIP-substitution binaries, also at the artifacts ROOT.
ART_DARWIN_COREUTILS_ARM64="$DIR/coreutils-arm64"
ART_DARWIN_BASH_ARM64="$DIR/bash-arm64"

# Artifacts must exist in BOTH modes — a missing file means the build job's
# upload-artifact step is broken, not a bootstrap nuance.  Tests that only
# exercise the linux/dist path do not produce the darwin artifacts; the
# release workflow's full run does.  Whether to require the darwin set is
# controlled by SCRIPT_JAIL_CHECK_DARWIN_ARTIFACTS=1 — defaulted ON, but tests
# can override.
CHECK_DARWIN_ARTIFACTS="${SCRIPT_JAIL_CHECK_DARWIN_ARTIFACTS:-1}"

required_files=("$ART_LINUX_ROOTFS_22" "$ART_LINUX_ROOTFS_24" "$ART_LINUX_LIBSO")
# dist/main.cjs and dist/cli.cjs are only required when the caller supplies a
# source to compare against.  The "source" path is the tagged fresh-checkout
# copy; without it, we have nothing to compare against AND nothing to require —
# under the build-once/download-forever contract the producer no longer ships
# dist/* in the artifact set (the dist that ships comes from the tagged
# checkout), so release.yml omits both flags and the downloaded artifact dir
# carries NO dist/ subtree.  Requiring it unconditionally would fail every
# real release.  Back-compat: tests that exercise the dist path pass the
# matching --dist-source / --dist-cli-source.
if [ -n "$DIST_SOURCE" ]; then
  required_files+=("$ART_DIST")
fi
if [ -n "$DIST_CLI_SOURCE" ]; then
  required_files+=("$ART_DIST_CLI")
fi
if [ "$CHECK_DARWIN_ARTIFACTS" = "1" ]; then
  required_files+=(
    "$ART_DARWIN_ROOTFS_22_ARM64"
    "$ART_DARWIN_ROOTFS_24_ARM64"
    "$ART_DARWIN_LIBSO_ARM64"
    "$ART_DARWIN_DYLIB_ARM64"
    "$ART_DARWIN_COREUTILS_ARM64"
    "$ART_DARWIN_BASH_ARM64"
    "$ART_VMLINUX_VZ_X86_64"
    "$ART_VMLINUX_VZ_ARM64"
    "$ART_SJ_VM_ARM64_DARWIN"
  )
fi

missing=()
for f in "${required_files[@]}"; do
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

# Plain sha256 for the .so shims, VZ kernels, Mach-O binary, and dist bundles.
sha_of() {
  sha256sum "$1" | cut -d' ' -f1
}

# Canonical (time-masked) hash for the rootfs ext4 images — the digest kind the
# manifest pins for them.  `node` exits non-zero (and prints to stderr) on any
# error, and command substitution under `set -e` propagates that, so a broken
# hasher fails the gate rather than yielding an empty digest that string-matches
# an empty manifest value.
canonical_rootfs_hash() {
  node "$REPRO_HASH_CLI" "$1"
}

COMPUTED_LINUX_ROOTFS_22="$(canonical_rootfs_hash "$ART_LINUX_ROOTFS_22")"
COMPUTED_LINUX_ROOTFS_24="$(canonical_rootfs_hash "$ART_LINUX_ROOTFS_24")"
COMPUTED_LINUX_LIBSO="$(sha_of "$ART_LINUX_LIBSO")"
# Hash the dist bundles ONLY when their source is supplied — see the
# required_files note above: without --dist-source the artifact dir carries no
# dist/main.cjs to hash (it would `sha_of` a non-existent file and fail).
if [ -n "$DIST_SOURCE" ]; then
  COMPUTED_DIST="$(sha_of "$ART_DIST")"
fi
if [ -n "$DIST_CLI_SOURCE" ]; then
  COMPUTED_DIST_CLI="$(sha_of "$ART_DIST_CLI")"
fi

if [ "$CHECK_DARWIN_ARTIFACTS" = "1" ]; then
  COMPUTED_DARWIN_ROOTFS_22_ARM64="$(canonical_rootfs_hash "$ART_DARWIN_ROOTFS_22_ARM64")"
  COMPUTED_DARWIN_ROOTFS_24_ARM64="$(canonical_rootfs_hash "$ART_DARWIN_ROOTFS_24_ARM64")"
  COMPUTED_DARWIN_LIBSO_ARM64="$(sha_of "$ART_DARWIN_LIBSO_ARM64")"
  # Plain sha256 — the dylib is not a rootfs ext4, so it has no time-masked
  # canonical form to mask.
  COMPUTED_DARWIN_DYLIB_ARM64="$(sha_of "$ART_DARWIN_DYLIB_ARM64")"
  # Plain sha256 for the substitution binaries too.
  COMPUTED_DARWIN_COREUTILS_ARM64="$(sha_of "$ART_DARWIN_COREUTILS_ARM64")"
  COMPUTED_DARWIN_BASH_ARM64="$(sha_of "$ART_DARWIN_BASH_ARM64")"
  COMPUTED_VMLINUX_VZ_X86_64="$(sha_of "$ART_VMLINUX_VZ_X86_64")"
  COMPUTED_VMLINUX_VZ_ARM64="$(sha_of "$ART_VMLINUX_VZ_ARM64")"
  COMPUTED_SJ_VM_ARM64_DARWIN="$(sha_of "$ART_SJ_VM_ARM64_DARWIN")"
fi

# --- Mixed-manifest is a packaging bug (checked BEFORE bootstrap) -------------

if [ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]; then
  echo "check-publish-artifacts: manifest has $PLACEHOLDER_COUNT placeholder entr(ies) mixed with $REAL_COUNT real SHA(s)." >&2
  echo "  This is a packaging bug — either every entry is a real SHA (normal release)," >&2
  echo "  or every entry is a placeholder (documented bootstrap loop)." >&2
  echo "  Fix src/action/artifact-manifest.ts before tagging." >&2
  exit 1
fi

# --- Verify dist/main.cjs (runs in BOTH normal and bootstrap modes) -----------
#
# dist/main.cjs is not in PINNED_MANIFEST.expected — instead it's committed to
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
  check "dist/main.cjs" "$EXPECTED_DIST" "$COMPUTED_DIST"
fi

# dist/cli.cjs is in the same threat class as dist/main.cjs: the publish job
# downloads the artifact from the build job and uploads it directly to the
# release.  The fresh-checkout copy of dist/cli.cjs is the independent source
# of truth.  Like the main.cjs check above, this comparison runs in BOTH
# normal and bootstrap modes — skipping it in bootstrap would leave the npm
# CLI bundle outside the gate exactly when consumers most need it intact.
if [ -n "$DIST_CLI_SOURCE" ]; then
  if [ ! -f "$DIST_CLI_SOURCE" ]; then
    echo "check-publish-artifacts: --dist-cli-source given but file not found: $DIST_CLI_SOURCE" >&2
    exit 1
  fi
  EXPECTED_DIST_CLI="$(sha_of "$DIST_CLI_SOURCE")"
  check "dist/cli.cjs" "$EXPECTED_DIST_CLI" "$COMPUTED_DIST_CLI"
fi

# --- Bootstrap path -----------------------------------------------------------
#
# All-placeholder manifest: the rootfs/libso/kernel SHAs have no trustworthy
# reference yet (this IS the run that produces them), so we skip those
# comparisons and print the computed values for the maintainer to paste into
# the manifest.  The dist/main.cjs and dist/cli.cjs comparisons above still ran.

if [ "$ALL_PLACEHOLDERS" -eq 1 ]; then
  echo "::warning::check-publish-artifacts: PINNED_MANIFEST.expected is entirely placeholders; skipping SHA comparison (bootstrap path). Copy the SHAs below into src/action/artifact-manifest.ts and cut the next tag."
  echo "check-publish-artifacts: bootstrap mode — manifest entries are placeholders." >&2
  echo "  linux/rootfs-ubuntu-22.04.ext4:        $COMPUTED_LINUX_ROOTFS_22" >&2
  echo "  linux/rootfs-ubuntu-24.04.ext4:        $COMPUTED_LINUX_ROOTFS_24" >&2
  echo "  linux/libscriptjail.so:                $COMPUTED_LINUX_LIBSO" >&2
  if [ "$CHECK_DARWIN_ARTIFACTS" = "1" ]; then
    echo "  darwin/rootfs-ubuntu-22.04-arm64.ext4: $COMPUTED_DARWIN_ROOTFS_22_ARM64" >&2
    echo "  darwin/rootfs-ubuntu-24.04-arm64.ext4: $COMPUTED_DARWIN_ROOTFS_24_ARM64" >&2
    echo "  darwin/libscriptjail-arm64.so:         $COMPUTED_DARWIN_LIBSO_ARM64" >&2
    echo "  darwin/libscriptjail-arm64.dylib:      $COMPUTED_DARWIN_DYLIB_ARM64" >&2
    echo "  darwin/coreutils-arm64:                $COMPUTED_DARWIN_COREUTILS_ARM64" >&2
    echo "  darwin/bash-arm64:                     $COMPUTED_DARWIN_BASH_ARM64" >&2
    echo "  darwin/vmlinux-vz-x86_64:              $COMPUTED_VMLINUX_VZ_X86_64" >&2
    echo "  darwin/vmlinux-vz-arm64:               $COMPUTED_VMLINUX_VZ_ARM64" >&2
    echo "  darwin/script-jail-vm-arm64-darwin:    $COMPUTED_SJ_VM_ARM64_DARWIN" >&2
  fi
  if [ -n "$DIST_SOURCE" ]; then
    echo "  dist/main.cjs:                         $COMPUTED_DIST" >&2
  fi
  if [ -n "$DIST_CLI_SOURCE" ]; then
    echo "  dist/cli.cjs:                          $COMPUTED_DIST_CLI" >&2
  fi
  if [ "${#errors[@]}" -gt 0 ]; then
    # `errors[]` accumulates dist/main.cjs and (when --dist-cli-source is
    # supplied) dist/cli.cjs mismatches; per-error lines below name the
    # exact offending bundle.  The summary line keeps the historical
    # "dist/main.cjs mismatch" prefix for log-grep compatibility.
    echo "check-publish-artifacts: dist/main.cjs mismatch in bootstrap mode — refusing to publish." >&2
    for e in "${errors[@]}"; do
      echo "  $e" >&2
    done
    exit 1
  fi
  exit 0
fi

# --- Compare manifest-pinned artifacts ----------------------------------------

check "linux/rootfs-ubuntu-22.04.ext4" "$EXPECTED_LINUX_ROOTFS_22" "$COMPUTED_LINUX_ROOTFS_22"
check "linux/rootfs-ubuntu-24.04.ext4" "$EXPECTED_LINUX_ROOTFS_24" "$COMPUTED_LINUX_ROOTFS_24"
check "linux/libscriptjail.so"         "$EXPECTED_LINUX_LIBSO"     "$COMPUTED_LINUX_LIBSO"
if [ "$CHECK_DARWIN_ARTIFACTS" = "1" ]; then
  check "darwin/rootfs-ubuntu-22.04-arm64.ext4" "$EXPECTED_DARWIN_ROOTFS_22_ARM64" "$COMPUTED_DARWIN_ROOTFS_22_ARM64"
  check "darwin/rootfs-ubuntu-24.04-arm64.ext4" "$EXPECTED_DARWIN_ROOTFS_24_ARM64" "$COMPUTED_DARWIN_ROOTFS_24_ARM64"
  check "darwin/libscriptjail-arm64.so"         "$EXPECTED_DARWIN_LIBSO_ARM64"     "$COMPUTED_DARWIN_LIBSO_ARM64"
  check "darwin/libscriptjail-arm64.dylib"      "$EXPECTED_DARWIN_DYLIB_ARM64"     "$COMPUTED_DARWIN_DYLIB_ARM64"
  check "darwin/coreutils-arm64"                "$EXPECTED_DARWIN_COREUTILS_ARM64" "$COMPUTED_DARWIN_COREUTILS_ARM64"
  check "darwin/bash-arm64"                     "$EXPECTED_DARWIN_BASH_ARM64"      "$COMPUTED_DARWIN_BASH_ARM64"
  check "darwin/vmlinux-vz-x86_64"              "$EXPECTED_VMLINUX_VZ_X86_64"      "$COMPUTED_VMLINUX_VZ_X86_64"
  check "darwin/vmlinux-vz-arm64"               "$EXPECTED_VMLINUX_VZ_ARM64"       "$COMPUTED_VMLINUX_VZ_ARM64"
  check "darwin/script-jail-vm-arm64-darwin"    "$EXPECTED_SJ_VM_ARM64_DARWIN"     "$COMPUTED_SJ_VM_ARM64_DARWIN"
fi

if [ "${#errors[@]}" -gt 0 ]; then
  echo "check-publish-artifacts: SHA mismatch — refusing to publish." >&2
  for e in "${errors[@]}"; do
    echo "  $e" >&2
  done
  exit 1
fi

echo "check-publish-artifacts: OK — all artifact SHAs match the tagged manifest."

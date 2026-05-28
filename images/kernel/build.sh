#!/usr/bin/env bash
# script-jail — images/kernel/build.sh
#
# Build the Virtualization.framework-compatible Linux kernel for the macOS
# audit VM.  Invoked from `.github/workflows/release.yml` on the
# ubuntu-24.04 runner; not intended to run on Darwin dev hosts (see the
# host-gate below).
#
# The kernel is pinned to one upstream version per script-jail tag and built
# from a hand-curated `.config` (one per arch — `x86_64-vz.config` /
# `arm64-vz.config`).  The configs are deliberately minimal: only the
# drivers VZ exposes (virtio-pci, virtio-blk, virtio-net, virtio-vsock,
# 8250 serial console) plus the rootfs filesystems (ext4, tmpfs).  See
# `docs/architecture.md`'s "Cross-host parity (macOS VZ)" section for the
# rationale.
#
# Outputs:
#   images/vmlinux-vz-x86_64   (bzImage payload extracted via objcopy)
#   images/vmlinux-vz-arm64    (arch/arm64/boot/Image directly)
#
# Each output is paired with a `<name>.sha256` file recorded from the
# BUILT artifact (not from any input).  The sidecar therefore acts as a
# tamper-detection check on the cached output — NOT as an input-change
# detector: editing the kbuild config (`images/kernel/<arch>-vz.config`)
# or bumping `DEFAULT_LINUX_VERSION` does NOT bust the cache.  Re-run
# with `--force` after local edits to either of those.  Release CI
# always passes `--force`, so production is unaffected.
#
# Required flags:
#   --arch=<x86_64|arm64>      target arch
#
# Optional flags:
#   --version=<linux-x.y.z>    upstream kernel version (default below)
#   --output=<path>            override the output path
#   --force                    rebuild even if the cached output is fresh
#                              (Local config edits → re-run with --force.)
#
# Cross-compilation:
#   When the host's `uname -m` doesn't match the target arch we set ARCH
#   and CROSS_COMPILE.  The release runner is amd64; arm64 builds therefore
#   require `gcc-aarch64-linux-gnu` (apt-get install pulls it in).
#
# Test seams:
#   SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST=<linux|darwin>
#     Overrides the host-OS detection for tests; never set in production.
#   SCRIPT_JAIL_KERNEL_BUILD_DRY_RUN=1
#     Echoes "DRY RUN: would build vmlinux-vz-<arch> from <version>" and
#     exits 0 instead of fetching/building.  Used by the argument-parsing
#     unit tests to verify --arch=… is accepted without standing up a
#     real toolchain.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Linux 6.6.x was the current LTS line when the VZ kernel path was added;
# 6.6.50 was the pinned tip at the moment of authoring. objc2-virtualization
# 0.3.x boots this kernel without complaint (the framework's only kernel
# requirement is "virtio-pci + a serial console"). Bumping this is a
# release-level concern: re-run the full build, refresh the manifest SHAs,
# cut a tag.
DEFAULT_LINUX_VERSION="6.6.50"

# Pinned upstream tarball SHA-256 digests.  When you bump
# DEFAULT_LINUX_VERSION you MUST also update the corresponding entry here
# (or the verification step below fails).  Add new entries; never edit
# existing entries — the historical pin must remain reproducible.
sha256_for_version() {
  case "$1" in
    6.6.50)
      # Source: https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc
      echo "c065e36daf28210060c91a37ef3e92ac5814784e634577e04e406297ead2e86e"
      ;;
    *)
      echo "UNPINNED"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ARCH=""
LINUX_VERSION="$DEFAULT_LINUX_VERSION"
OUTPUT=""
FORCE=0

usage() {
  cat >&2 <<EOF
Usage: images/kernel/build.sh --arch=<x86_64|arm64> [--version=<x.y.z>] [--output=<path>] [--force]

Required:
  --arch=<x86_64|arm64>        Target architecture.

Options:
  --version=<linux-x.y.z>      Upstream Linux kernel version (default: ${DEFAULT_LINUX_VERSION}).
  --output=<path>              Override output path (default: images/vmlinux-vz-<arch>).
  --force                      Rebuild even when the cached output's SHA matches.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch=*)
      ARCH="${1#--arch=}"
      shift
      ;;
    --arch)
      ARCH="${2:-}"
      shift 2
      ;;
    --version=*)
      LINUX_VERSION="${1#--version=}"
      shift
      ;;
    --version)
      LINUX_VERSION="${2:-}"
      shift 2
      ;;
    --output=*)
      OUTPUT="${1#--output=}"
      shift
      ;;
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "build.sh: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$ARCH" ]; then
  echo "build.sh: --arch is required (accepted values: x86_64, arm64)" >&2
  usage
  exit 2
fi

case "$ARCH" in
  x86_64|arm64) ;;
  *)
    echo "build.sh: --arch must be one of: x86_64, arm64 (got: $ARCH)" >&2
    usage
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# Host gate
# ---------------------------------------------------------------------------
#
# Building a Linux kernel on macOS requires a Linux container/VM; running
# this script directly on Darwin is a misuse.  Surface a clear "use the
# release CI" message and exit 2.

HOST_OS="${SCRIPT_JAIL_KERNEL_BUILD_TEST_HOST:-$(uname -s | tr '[:upper:]' '[:lower:]')}"

case "$HOST_OS" in
  darwin)
    cat >&2 <<EOF
build.sh: cannot build a Linux kernel on a Darwin host.
  Building the Linux kernel requires a Linux toolchain (flex, bison,
  libelf-dev, libssl-dev, and a cross-compiler for arm64).  Use the
  release CI workflow (.github/workflows/release.yml) which runs this
  script on the ubuntu-24.04 runner, or run inside a Linux container.
EOF
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IMAGES_DIR/.." && pwd)"

if [ -z "$OUTPUT" ]; then
  OUTPUT="$IMAGES_DIR/vmlinux-vz-$ARCH"
fi
OUTPUT_SHA="${OUTPUT}.sha256"

CONFIG_FILE="$SCRIPT_DIR/${ARCH}-vz.config"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "build.sh: kbuild config not found at $CONFIG_FILE" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Dry-run path (test seam)
# ---------------------------------------------------------------------------

if [ "${SCRIPT_JAIL_KERNEL_BUILD_DRY_RUN:-0}" = "1" ]; then
  echo "DRY RUN: would build vmlinux-vz-${ARCH} from linux-${LINUX_VERSION} (config: ${CONFIG_FILE})"
  echo "DRY RUN: output → ${OUTPUT}"
  exit 0
fi

# ---------------------------------------------------------------------------
# Cache check
# ---------------------------------------------------------------------------
#
# Tamper-detection only: if both the output and its sidecar .sha256 exist
# and the recorded SHA still matches the file on disk, skip the rebuild.
# The sidecar is hashed from the OUTPUT (see the final `sha256sum > .sha256`
# at the bottom of the script), so this check validates that the cached
# binary has not changed since we wrote it — it does NOT detect input
# changes.  Editing `images/kernel/<arch>-vz.config` or bumping
# `DEFAULT_LINUX_VERSION` will NOT bust this cache: a local dev iteration
# on those files must re-run with `--force` to actually rebuild.
# `release.yml` always passes `--force`, so production is unaffected.

if [ "$FORCE" -ne 1 ] && [ -f "$OUTPUT" ] && [ -f "$OUTPUT_SHA" ]; then
  expected="$(cut -d' ' -f1 < "$OUTPUT_SHA")"
  actual="$(sha256sum "$OUTPUT" | cut -d' ' -f1)"
  if [ "$expected" = "$actual" ]; then
    echo "build.sh: ${OUTPUT} is up to date (sha256 matches); skipping rebuild."
    exit 0
  fi
  echo "build.sh: ${OUTPUT}.sha256 disagrees with the file (expected=${expected}, actual=${actual}); rebuilding." >&2
fi

# ---------------------------------------------------------------------------
# Toolchain check
# ---------------------------------------------------------------------------

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "build.sh: missing required command: $1" >&2
    return 1
  fi
}

require_cmd curl
require_cmd tar
require_cmd sha256sum
require_cmd make
require_cmd gcc
require_cmd flex
require_cmd bison

case "$ARCH" in
  arm64)
    if [ "$(uname -m)" != "aarch64" ]; then
      require_cmd aarch64-linux-gnu-gcc
    fi
    ;;
  x86_64)
    if [ "$(uname -m)" != "x86_64" ]; then
      require_cmd x86_64-linux-gnu-gcc
    fi
    ;;
esac

# ---------------------------------------------------------------------------
# Fetch + verify upstream tarball
# ---------------------------------------------------------------------------

BUILD_DIR="$(mktemp -d -t script-jail-kernel-build-XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

LINUX_MAJOR="$(echo "$LINUX_VERSION" | cut -d. -f1)"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v${LINUX_MAJOR}.x/linux-${LINUX_VERSION}.tar.xz"
TARBALL_PATH="$BUILD_DIR/linux-${LINUX_VERSION}.tar.xz"

echo "build.sh: fetching ${TARBALL_URL}"
curl -fL -o "$TARBALL_PATH" "$TARBALL_URL"

EXPECTED_TARBALL_SHA="$(sha256_for_version "$LINUX_VERSION")"
if [ "$EXPECTED_TARBALL_SHA" = "UNPINNED" ]; then
  echo "build.sh: no pinned SHA-256 for linux-${LINUX_VERSION}; add it to sha256_for_version()." >&2
  exit 1
fi
echo "${EXPECTED_TARBALL_SHA}  ${TARBALL_PATH}" | sha256sum -c -

# ---------------------------------------------------------------------------
# Extract + configure
# ---------------------------------------------------------------------------

echo "build.sh: extracting ${TARBALL_PATH}"
tar -C "$BUILD_DIR" -xf "$TARBALL_PATH"
KERNEL_SRC="$BUILD_DIR/linux-${LINUX_VERSION}"

echo "build.sh: copying pinned config ${CONFIG_FILE} → ${KERNEL_SRC}/.config"
cp "$CONFIG_FILE" "$KERNEL_SRC/.config"

# ---------------------------------------------------------------------------
# Cross-compile setup
# ---------------------------------------------------------------------------
#
# MUST be assembled BEFORE the `olddefconfig` invocation below: when the
# host arch and target arch differ (release runner is amd64, arm64 builds
# cross-compile), `make olddefconfig` evaluates the freshly-copied .config
# against the host's arch/Kconfig unless `ARCH=` is in the environment.
# Without it, arm64-only symbols (`CONFIG_ARM64=y`, `CONFIG_ARM_GIC_V3=y`,
# `CONFIG_ARM64_4K_PAGES=y`) are silently dropped or rewritten — the kernel
# then builds successfully but won't boot under VZ.

declare -a MAKE_ENV=()
HOST_ARCH="$(uname -m)"
case "$ARCH" in
  arm64)
    if [ "$HOST_ARCH" != "aarch64" ]; then
      MAKE_ENV+=("ARCH=arm64" "CROSS_COMPILE=aarch64-linux-gnu-")
    else
      MAKE_ENV+=("ARCH=arm64")
    fi
    ;;
  x86_64)
    if [ "$HOST_ARCH" != "x86_64" ]; then
      MAKE_ENV+=("ARCH=x86_64" "CROSS_COMPILE=x86_64-linux-gnu-")
    else
      MAKE_ENV+=("ARCH=x86_64")
    fi
    ;;
esac

# Resolve any kbuild defaults the pinned config did not enumerate.  We do
# NOT run `make defconfig` first — that would overwrite our pinned config.
# `"${MAKE_ENV[@]}"` carries the cross-compile ARCH/CROSS_COMPILE pair so
# arm64-only symbols survive the olddefconfig pass on an amd64 host.
make -C "$KERNEL_SRC" "${MAKE_ENV[@]}" olddefconfig

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

JOBS="$( (nproc 2>/dev/null || echo 4) )"
echo "build.sh: building linux-${LINUX_VERSION} for ${ARCH} with -j${JOBS}"
make -C "$KERNEL_SRC" "${MAKE_ENV[@]}" -j"$JOBS" \
  $(if [ "$ARCH" = "x86_64" ]; then echo bzImage; else echo Image; fi)

# ---------------------------------------------------------------------------
# Stage output
# ---------------------------------------------------------------------------

mkdir -p "$IMAGES_DIR"

case "$ARCH" in
  x86_64)
    # objc2-virtualization expects an uncompressed kernel image (no
    # bzImage self-extracting wrapper).  `extract-vmlinux` is shipped in
    # the source tree.
    EXTRACT="$KERNEL_SRC/scripts/extract-vmlinux"
    BZIMAGE="$KERNEL_SRC/arch/x86_64/boot/bzImage"
    "$EXTRACT" "$BZIMAGE" > "$OUTPUT"
    ;;
  arm64)
    cp "$KERNEL_SRC/arch/arm64/boot/Image" "$OUTPUT"
    ;;
esac

sha256sum "$OUTPUT" | tee "$OUTPUT_SHA"
echo "build.sh: done — ${OUTPUT}"

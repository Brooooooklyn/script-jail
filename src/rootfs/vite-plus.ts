// script-jail — src/rootfs/vite-plus.ts
//
// Pinned toolchain provisioning constants for the rootfs.
//
// The rootfs no longer carries a "host-node" ext4 disk packed from the
// runner's own Node install (that disk shipped a host-arch binary, which is
// a Mach-O on a macOS host and cannot execute inside the Linux guest).
//
// Instead the rootfs bakes the standalone `vp` (vite-plus) binary at build
// time, and the guest's init.sh runs `vp env install <NODE_VERSION>` during
// Phase A (network on) to download a real Linux Node toolchain.  corepack
// (bundled with that Node) then provides pnpm / yarn.
//
// Both values are PINNED EXACTLY so the generated lockfile is reproducible:
//   - vp itself: an npm-published per-arch tarball, SHA-verified at build.
//   - Node: an exact x.y.z so a Linux-CI run and a macOS-VZ run weeks apart
//     resolve the identical npm/corepack versions.  `vp env install 24`
//     (major-only) would drift and break cross-host parity.

/** Architectures the rootfs is built for. */
export type VitePlusArch = 'x64' | 'arm64';

/** Pinned vite-plus CLI version (npm `@voidzero-dev/vite-plus-cli-linux-*`). */
export const VITE_PLUS_VERSION = '0.1.22';

/**
 * Exact Node.js version `vp env install` provisions inside the guest.
 * Pinned x.y.z — see the file header for why a bare major would break parity.
 */
export const NODE_VERSION = '24.15.0';

/**
 * SHA-256 of the per-arch vite-plus CLI npm tarball.  Verified in
 * Dockerfile.base after download.  Update together with VITE_PLUS_VERSION.
 */
export const VITE_PLUS_SHA256: Readonly<Record<VitePlusArch, string>> = {
  x64:   '97f356232f83a14c633c9632873cb1cb71d97f690482566ec813d6f3bad2be3e',
  arm64: '41186f8dc5f1483a0f8b3943673da884d38abfc8e6e46859ba4764afc9d5acee',
};

/**
 * npm registry tarball URL for the per-arch vite-plus CLI.  The package name
 * embeds the arch (`x64` / `arm64`); the tarball extracts to `package/vp`.
 */
export function vitePlusTarballUrl(arch: VitePlusArch): string {
  const pkg = `@voidzero-dev/vite-plus-cli-linux-${arch}-gnu`;
  return `https://registry.npmjs.org/${pkg}/-/vite-plus-cli-linux-${arch}-gnu-${VITE_PLUS_VERSION}.tgz`;
}

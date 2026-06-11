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

/**
 * Host OS the vite-plus CLI binary targets.  `linux` is the rootfs/guest path
 * (existing, byte-for-byte unchanged); `darwin` is the macOS-native bare
 * backend, which provisions Node directly on the Mac (no VM).
 */
export type VitePlusOs = 'linux' | 'darwin';

/** Pinned vite-plus CLI version (npm `@voidzero-dev/vite-plus-cli-*`). */
export const VITE_PLUS_VERSION = '0.1.22';

/**
 * Exact Node.js version `vp env install` provisions inside the guest.
 * Pinned x.y.z — see the file header for why a bare major would break parity.
 */
export const NODE_VERSION = '24.15.0';

/**
 * SHA-256 of the per-arch Linux vite-plus CLI npm tarball.  Verified in
 * Dockerfile.base after download.  Update together with VITE_PLUS_VERSION.
 */
export const VITE_PLUS_SHA256: Readonly<Record<VitePlusArch, string>> = {
  x64:   '97f356232f83a14c633c9632873cb1cb71d97f690482566ec813d6f3bad2be3e',
  arm64: '41186f8dc5f1483a0f8b3943673da884d38abfc8e6e46859ba4764afc9d5acee',
};

/**
 * SHA-256 of the per-arch macOS (darwin) vite-plus CLI npm tarball.  Verified
 * by `src/cli/provision-node-mac.ts` after download (the macOS-native bare
 * backend has no Dockerfile.base).  Update together with VITE_PLUS_VERSION.
 *
 * Unlike the Linux packages, the darwin package name carries NO `-gnu` suffix
 * (`@voidzero-dev/vite-plus-cli-darwin-<arch>`).
 */
export const VITE_PLUS_DARWIN_SHA256: Readonly<Record<VitePlusArch, string>> = {
  arm64: '95ab62b3287e3761247b1cb5f9a0a5bd90d1b6f86cc79c8e777f00dbd0157eff',
  x64:   '2399331bd59270ea5e01288ba2e6e50d91bbeff3f0e34cedea0e427c7da361ea',
};

/**
 * npm registry tarball URL for the per-(os, arch) vite-plus CLI.  The package
 * name embeds the OS + arch; the tarball extracts to `package/vp`.
 *
 * The `os` parameter DEFAULTS to `'linux'` so every existing rootfs/build
 * caller is byte-for-byte unchanged.  Linux packages carry a `-gnu` suffix
 * (`vite-plus-cli-linux-<arch>-gnu`); darwin packages do not
 * (`vite-plus-cli-darwin-<arch>`).
 */
export function vitePlusTarballUrl(arch: VitePlusArch, os: VitePlusOs = 'linux'): string {
  const slug = os === 'darwin' ? `darwin-${arch}` : `linux-${arch}-gnu`;
  const pkg = `@voidzero-dev/vite-plus-cli-${slug}`;
  return `https://registry.npmjs.org/${pkg}/-/vite-plus-cli-${slug}-${VITE_PLUS_VERSION}.tgz`;
}

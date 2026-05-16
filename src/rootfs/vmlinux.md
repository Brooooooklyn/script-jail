# vmlinux — kernel image pin

npm-jar boots a Firecracker microVM using a precompiled `vmlinux` kernel
image. The image is fetched at action runtime by `ensureBinaries`
(`src/action/firecracker/download.ts`) and verified against a pinned SHA-256
before use.

## Pinned source

URL:

    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223

SHA-256 (must match the constant `PINNED_VMLINUX_SHA256` in `src/main.ts`):

    22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65

This is the kernel image AWS publishes for Firecracker's own CI under
`spec.ccfc.min`. It is a Linux 5.10.223 build whose `.config` is the one
under `firecracker-ci/v1.10/x86_64/vmlinux-5.10.223.config` in the same
bucket; the kernel is GPL-2.0, the build is reproducible from that config.

### Why 5.10.223 (not "vmlinux-5.10.bin")

Earlier Firecracker docs referenced an unsuffixed `vmlinux-5.10.bin` in the
same bucket; that key returns `NoSuchKey` today. The `firecracker-ci/v1.10/`
prefix now publishes patch-level kernels (`vmlinux-5.10.223`, etc.). We pin
to a specific patch so the SHA stays meaningful; bump it deliberately.

Re-verify with:

    curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223" | sha256sum

## Building your own

For deployments that want a stricter or audited kernel config, build a
`vmlinux` from upstream Linux using Firecracker's recommended recipe.
Firecracker ships a starter config at `resources/microvm-kernel-x86_64-5.10.config`
in their repo; with the Linux source tree extracted alongside it, run:

    cp resources/microvm-kernel-x86_64-5.10.config .config
    make olddefconfig
    make vmlinux -j"$(nproc)"

then update `PINNED_VMLINUX_URL` (point at your own hosted artifact) and
`PINNED_VMLINUX_SHA256` (the `sha256sum` of your `vmlinux`) in `src/main.ts`,
and mirror the new digest in this file. See Firecracker's kernel policy at
[firecracker-microvm/firecracker v1.8.0 docs/kernel-policy.md](https://github.com/firecracker-microvm/firecracker/blob/v1.8.0/docs/kernel-policy.md)
for guidance on supported kernel versions and required features (vsock,
virtio, MMIO, KVM guest support). Tag-pinned so the link doesn't shift
meaning when Firecracker reorganizes their docs tree.

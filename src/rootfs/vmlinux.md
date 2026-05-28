# vmlinux - Firecracker kernel pins

When the Firecracker backend is selected, `script-jail` boots the guest with a
precompiled `vmlinux` kernel. `ensureBinaries()` in
`src/action/firecracker/download.ts` downloads the kernel at action runtime and
verifies it against the pinned SHA-256 in
`src/action/backend/firecracker.ts`.

Docker and bare backends do not use these kernels. The macOS
Virtualization.framework path uses the separate `images/vmlinux-vz-*`
artifacts.

## Pinned Sources

The current Firecracker backend pins Linux 5.10.223 images published from AWS
Firecracker CI under `spec.ccfc.min`.

### x64

URL:

    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223

SHA-256:

    22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65

Re-verify with:

    curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.223" | sha256sum

### arm64

URL:

    https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/aarch64/vmlinux-5.10.223

SHA-256:

    eb5d95ac8a67f7a86acf0cb35625633713ad5170b56de8617808d0e18bb832ec

Re-verify with:

    curl -sL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/aarch64/vmlinux-5.10.223" | sha256sum

## Why 5.10.223

Earlier Firecracker docs referenced an unsuffixed `vmlinux-5.10.bin` in the
same bucket; that key is not a stable pin. The `firecracker-ci/v1.10/` prefix
publishes patch-level kernels (`vmlinux-5.10.223`, etc.). Pinning the patch
version plus SHA keeps the runtime artifact reproducible.

## Building Your Own

For deployments that want a stricter or audited kernel config, build `vmlinux`
from upstream Linux using Firecracker's recommended recipe. Firecracker ships a
starter config at `resources/microvm-kernel-x86_64-5.10.config` in their repo;
with the Linux source tree extracted alongside it, run:

    cp resources/microvm-kernel-x86_64-5.10.config .config
    make olddefconfig
    make vmlinux -j"$(nproc)"

Then update the matching entry in `PINNED_KERNELS` in
`src/action/backend/firecracker.ts`, including the URL and SHA-256, and mirror
the new values in this file. See Firecracker's kernel policy at
[firecracker-microvm/firecracker v1.8.0 docs/kernel-policy.md](https://github.com/firecracker-microvm/firecracker/blob/v1.8.0/docs/kernel-policy.md)
for supported kernel guidance and required features such as vsock, virtio,
MMIO, and KVM guest support.

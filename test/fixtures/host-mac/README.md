This directory hosts macOS-host smoke fixtures. PR 3 ships only the config-validation
fixture; PR 5 adds real kernel + rootfs artifacts at the paths referenced in this file.

The current fixture (`smoke.json`) intentionally points at non-existent files. The
`script-jail-vm` binary must reject it with a "kernel_path" validation error and exit
64. The macOS CI workflow at `.github/workflows/test-macos.yml` asserts on that.

Files added in PR 5:
- `missing-kernel` -> real arm64 vmlinuz
- `missing-rootfs.img` -> ubuntu rootfs ext4 image
- `missing-repo.img` -> empty repo overlay

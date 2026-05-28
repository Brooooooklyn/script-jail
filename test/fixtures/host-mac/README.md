This directory hosts macOS-host smoke fixtures.

The current fixture (`smoke.json`) intentionally points at non-existent files. The
`script-jail-vm` binary must reject it with a "kernel_path" validation error and exit
64. The macOS CI workflow at `.github/workflows/test-macos.yml` asserts on that.

The missing paths are part of the test contract; do not replace them with real
artifacts. Real macOS VZ runs resolve release artifacts through the CLI and
manifest instead of this fixture directory.

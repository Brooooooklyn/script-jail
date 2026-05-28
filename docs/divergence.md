# Known divergence

The macOS Virtualization.framework runner produces audit lockfiles that aim
for byte-for-byte parity with the Linux Action backend. The parity workflow
now runs Linux CI on `ubuntu-24.04-arm`; on hosted runners `backend: auto`
falls through to Docker because KVM is unavailable. Both sides still use a
Linux/arm64 audit environment.

Known host/backend noise is either removed before rendering or filtered by
`scripts/parity-diff.ts`. A remaining diff is a CI failure. The TL;DR: if your
`.script-jail.lock.yml` differs between macOS and Linux CI, check the cases
below before treating it as a product bug.

## Why divergence is possible

Even with the same guest architecture, rootfs family, vsock agent, and
package-manager binary, a few signals leak through the VM boundary and break
determinism across hosts:

- **Ambient environment.** GitHub Actions sets CI variables and runner
  metadata that a local macOS generation does not have. The guest filters
  known Node/bootstrap reads, npm/yarn/pnpm client reads, and selected CI
  noise, but a new package-manager version can still introduce a new probe
  that needs a narrow filter or a regenerated baseline.

- **Backend/device surface.** Firecracker, Docker, bare Linux, and
  Virtualization.framework expose different device and procfs/sysfs shapes.
  Most package installs do not inspect these, but a native postinstall can.

- **Native binaries the lifecycle script execs directly.** Some scripts
  shell out to a host-provided binary (`python`, `cc`, `make`). Whether the
  VM rootfs ships that binary is a property of the rootfs build, not of the
  VMM. v1 deliberately ships a minimal rootfs (no `gcc`, no `python`); the
  lockfile records the `execve` attempt either way, so this is not a
  divergence the docs need to track.

The old Linux/x64-vs-macOS/arm64 direction deliberately injected
package-manager flags/config to force `linux-x64-glibc` resolution. That has
been removed. `src/cli/arch-flags.ts` is now a no-op compatibility seam, and
both CI and local parity runs should resolve Linux/arm64 optional packages.
If a diff shows `@swc/core-linux-x64-gnu` or `@esbuild/linux-x64` on only one
side, treat that as a bug in action/CLI input defaulting or stale lockfile
generation, not as expected divergence.

- **bun.** Unsupported — `detectPm` throws `BunUnsupportedError` before
  any audit runs. v1 will not add support; the JS-only env hooks bun
  ignores would leave too much unaudited.

## Cross-host parity testing

Two separate contracts back the "byte-equal lockfile" claim, and they are
exercised by two separate test suites. Conflating the two is a recurring
documentation mistake — the suites cover unrelated invariants.

### macOS-side smoke and parity checks

`test/e2e/mac-parity.test.ts` is the artifact-gated local test scaffold for
the macOS CLI/VZ path. It runs only on Darwin hosts and skips itself entirely
when the VZ kernel artifact (`images/vmlinux-vz-<arch>`) or the per-arch rootfs
is absent. The committed scaffold still contains placeholder fixture cases;
real per-fixture assertions become useful once the release artifacts are
available on the developer host or in a suitable self-hosted macOS environment.

On Linux CI, `parity-test.yml` now exercises the Action backend on
`ubuntu-24.04-arm` and diffs it against the committed local macOS/VZ lockfile.

### Release-artifact packaging check

`test/scripts/check-publish-artifacts.test.ts` is a different contract
entirely: it asserts the release workflow refuses to publish a tag whose
build-job artifacts have been tampered with or whose manifest is in a
malformed shape. It runs everywhere (the script under test is shell, not
TS, and the test drives it via `child_process`). It does **not** exercise
lockfile byte-equality; it gates the publish job that ships the
artifacts every lockfile audit depends on.

The remaining divergence is documented above; everything else should
produce byte-equal lockfiles. File an issue when it does not.

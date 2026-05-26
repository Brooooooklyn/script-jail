# Known divergence (v1)

The macOS Virtualization.framework runner produces audit lockfiles that aim
for byte-for-byte parity with the Firecracker / Linux-CI runner. In v1 a
handful of corner cases produce lockfile diffs that the maintainer must
recognise as "expected divergence" rather than chase as bugs. This page
catalogues every one and points at the planned v2 fix.

The TL;DR: if your `.script-jail.lock.yml` diff fails on macOS but passes on
Linux CI (or vice versa), check the cases below before opening an issue.

## Why divergence is possible

Even with the same kernel image, the same rootfs, the same vsock agent, and
the same package-manager binary, a few signals leak through the VM boundary
and break determinism across hosts:

- **Host architecture.** A package shipping a native binding for `linux-x64`
  and `linux-arm64` will resolve a different `.node` file under an Apple
  Silicon host than under a GitHub `ubuntu-24.04` runner. The lifecycle
  script runs the same way, but the recorded file reads and `execve` payloads
  reference different ELF interpreters and library paths.

- **Package-manager arch flags.** npm, pnpm, and yarn each consult
  `process.platform` and `process.arch` when picking optional dependencies
  to install. Without an arch overlay (PR 4 ships one), the host's
  `darwin-arm64` would suppress packages the Linux CI happily fetches.

- **Native binaries the lifecycle script execs directly.** Some scripts
  shell out to a host-provided binary (`python`, `cc`, `make`). Whether the
  VM rootfs ships that binary is a property of the rootfs build, not of the
  VMM. v1 deliberately ships a minimal rootfs (no `gcc`, no `python`); the
  lockfile records the `execve` attempt either way, so this is not a
  divergence the docs need to track.

The cases below are the residual divergence after PR 4's arch-flag overlay.

## Native execve / addon loads of x86_64 binaries on arm64 hosts

**Symptom.** A package that ships only a `linux-x64` prebuilt (no `linux-arm64`
variant) lands in `node_modules` on a Linux-amd64 runner with the prebuilt
in place. During install, the lifecycle script then `execve`s the x86_64
binary or asks Node to load the x86_64 native addon. On an Apple Silicon
(`darwin-arm64`) host the VM is also arm64, so the same lifecycle script either:

1. Re-fetches the arm64 prebuilt — different file-read / `<EXEC>` payload —
   or
2. Falls back to source build, executing `cc`/`make` instead — completely
   different event shape — or
3. Fails the install with a "no prebuilt for platform" error before the
   lifecycle script runs at all.

**Affected fixture/scenario.** Any package that ships per-arch prebuilts
under its `optionalDependencies` (the canonical pattern is
`@swc/core-linux-arm64-gnu` paired with `@swc/core-linux-x64-gnu`). The
e2e fixture `test/fixtures/native-prebuild-divergence/` exercises the
fall-through case (option 2 above) on arm64.

**v2 mitigation.** Per-arch lockfiles (`.script-jail.lock-x64.yml` vs.
`.script-jail.lock-arm64.yml`) generated in lock-step, with the check-mode
diff selecting the correct file by host arch. The maintainer commits both
files and CI verifies the matching half on its native arch.

## Yarn classic (yarn 1.x) best-effort warning

**Symptom.** yarn 1.x ignores `--cpu` / `--os` / `--libc` CLI flags entirely
and ignores `.yarnrc.yml` (which it does not recognise as a config file).
The arch-flag overlay PR 4 ships therefore has no effect on yarn classic.
A yarn-classic install on arm64 picks up `darwin-arm64` optional
dependencies that wouldn't appear on the Linux runner.

**Affected fixture/scenario.** Any repo using yarn 1.x. The CLI emits a
warning at startup (`script-jail: yarn-classic detected — arch-flag overlay
unsupported, lockfile may differ on macOS vs. Linux runners`); pnpm and
yarn-berry users see no such warning. PR 2's `parseArgs` records the
warning but cannot fix the root cause.

**v2 mitigation.** Drop yarn 1.x from the supported-PM matrix entirely
(yarn classic is in maintenance mode upstream). Until then, the best-effort
warning above is the only mitigation; the documented workaround is "switch
to yarn berry or pnpm if you want macOS/Linux parity".

## Package-manager flag overrides

These are the flag/config overlays PR 4's `buildArchFlagOverlay` injects.
They are not divergence in themselves — they are how we *avoid* divergence —
but listing them here lets a debugger trace a "why is this package not
installed" back to a host-arch mismatch.

- **npm and pnpm.** PR 4's overlay appends `--cpu=x64 --os=linux
  --libc=glibc` to the install command via
  `etc/script-jail/pm-flags.json` (deserialised by
  `src/guest/load-pm-flags.ts` and concatenated into the
  `phase-fetch`/`phase-install` argv). The package manager then resolves
  optional dependencies as if it were running on `linux-x64-glibc`,
  regardless of the actual host arch.

- **yarn 4+ (berry).** PR 4 generates a `.yarnrc.yml` overlay that sets
  `supportedArchitectures: { cpu: [x64], os: [linux], libc: [glibc] }` and
  drops it into the per-run repo overlay so yarn berry sees it as a
  workspace-local config. yarn berry merges this with the user's own
  `.yarnrc.yml` if any.

- **bun.** Unsupported — `detectPm` throws `BunUnsupportedError` before
  any audit runs. v1 will not add support; the JS-only env hooks bun
  ignores would leave too much unaudited.

## Cross-host parity testing

Two separate contracts back the "byte-equal lockfile" claim, and they are
exercised by two separate test suites. Conflating the two is a recurring
documentation mistake — the suites cover unrelated invariants.

### macOS-side parity check

`test/e2e/mac-parity.test.ts` (gated on `darwin` + Apple Silicon) is the
test that actually compares audit-result lockfiles produced by the macOS
CLI against the Linux-CI goldens for the same fixture. It runs only on
Darwin hosts and skips itself entirely when the VZ kernel artifact
(`images/vmlinux-vz-<arch>`) or the per-arch rootfs is absent.

PR 4 status: the suite is scaffolded with four `it.todo` slots, one per
fixture (`reads-secret-env`, `tries-dlopen`, `reads-home-ssh`,
`tries-network-egress`). The bodies are filled in once PR 5's kernel
artifact is published — at that point each `it.todo` becomes a real
parity assertion.

On Linux CI the audit-result lockfile-parity guarantee is purely
**declarative** — no test runs there. We rely on the Apple-Silicon-Darwin
job to surface a regression.

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

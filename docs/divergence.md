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

## macOS bare backend

`script-jail check --backend bare` on a Mac audits the install **directly on
the host** (no VM, no container). It mirrors the Linux `bare` backend but,
because macOS has no `strace` and no `/proc`, the Mach-O `__interpose` shim is
the **sole** event source. That single difference drives every reconciliation
rule below. The goal is unchanged: one committed `.script-jail.lock.yml` that
reconciles against the Linux Action backend after `scripts/parity-diff.ts`
canonicalization. These are the macOS-specific cases that filter must absorb.

- **SIP-binary substitution (why there is no arm64e dylib).** On Apple Silicon
  the system shells (`/bin/sh`, `/bin/bash`) and coreutils (`/bin/echo`, …) are
  **arm64e**, and dyld refuses to inject a plain-arm64 dylib into an arm64e
  process. Rather than ship a universal arm64+arm64e dylib (which needs a nightly
  `-Z build-std` toolchain), the shim **never runs the arm64e binary**: at exec
  time it rewrites any `/bin`/`/usr/bin` program whose basename is `sh`/`bash`
  to a bundled **from-source bash** (`bash-arm64`), and any uutils applet to a
  bundled **uutils/coreutils** multi-call binary (`coreutils-arm64`) — both plain
  arm64, both ad-hoc signed. `argv[0]` is preserved so bash self-selects sh/bash
  mode and uutils dispatches the right applet. The dylib then loads cleanly into
  the substitute, so script-jail ships a **thin `aarch64-apple-darwin` dylib**.
  Two consequences for divergence:
  - **Audit-blind residual, surfaced as `<AUDIT_BLIND>`.** Any `/bin`/`/usr/bin`
    binary that is *not* a shell or a uutils applet — `sed`, `awk`, `grep`,
    `find`, `xargs`, `which`, `cmp`, `/usr/bin/python3`, `/usr/bin/git`, `perl`,
    `ruby`, … — has no plain-arm64 substitute, so when `sip_redirect` leaves the
    path unchanged the real arm64e binary runs with `DYLD_INSERT_LIBRARIES`
    stripped by SIP: it and its descendants run **un-instrumented** (a malicious
    `find . -exec /bin/sh -c '<exfil>' \;` would otherwise hide the exfil
    entirely). The shim tags such execs `audit_blind`, and `normalize.ts` renders
    them with an **`<AUDIT_BLIND>` prefix in `spawn_attempts`/`spawn_blocked`** so
    the lock diff exposes the blind subtree. This is **informational, not an
    `audit_bypass` hard-fail** — benign `find`/`sed`/`grep` use stays green; a
    reviewer simply sees *which* exec escaped instrumentation and must inspect it.
    Note this is a deliberate **coverage trade of the no-arm64e substitution
    model**, not parity with fspy: the prior re-signing approach *did* instrument
    these tools (via a universal arm64+arm64e dylib), at the cost of a nightly
    `-Z build-std` toolchain. Firecracker remains the high-assurance backend when
    full subtree coverage matters.
  - **Blind-classification robustness (lexical canon + spawnp PATH search).** The
    `audit_blind` tag and `sip_redirect` both key off the program path, so a
    non-canonical path could dodge them: `/usr/lib/../bin/find` does not byte-match
    `/usr/bin/` yet still execs the real `find`. Before classifying *and* before
    redirect matching, the shim runs a **purely lexical** canonicalizer that
    collapses `.`, `..`, and `//` in **absolute** paths — so `/usr/lib/../bin/find`
    → `/usr/bin/find` is still marked `<AUDIT_BLIND>`, and `/usr/lib/../../bin/sh`
    → `/bin/sh` is still redirected to the bundled bash. `posix_spawnp` with a
    **bare name** (no slash) is run through the same in-process `PATH` search that
    `execvp` uses, so `posix_spawnp("find", …)` resolves to `/usr/bin/find` and is
    marked too. **Residual (lexical, not realpath):** the canonicalizer does **not**
    resolve symlinks and does **not** rewrite **relative** (cwd-anchored) paths, so a
    symlink that points at a SIP binary, or a `../../bin/find` resolved against the
    cwd, can still run blind **and unmarked**. These are narrow — Node's
    `child_process` always hands libuv an **absolute, resolved** path — but real;
    Firecracker remains the high-assurance backend.
  - **Fingerprinting + BSD-semantics caveat.** The substitutes are uutils (GNU
    semantics) and bash 5.3, not the macOS BSD system binaries, so behaviour
    diverges in two ways. (1) *Fingerprint:* a script can detect the sandbox from
    version banners (`date --version` succeeds under uutils, fails on real macOS)
    **and** from BSD-vs-GNU flag handling — `date -j`, `stat -f`, `cp -X` are
    rejected by uutils; `du`/`df` report different block-size units; `uname -p`
    prints `unknown` vs `arm`. A benign-when-watched payload *could* gate on these
    and evade. (2) *Correctness:* a lifecycle script relying on those BSD-specific
    flags behaves differently under the bare backend than on the host. Both are
    inherent to substitution-based observation (the Linux backend has the
    analogous "GNU coreutils + dash in the rootfs" property). For evasion- and
    fidelity-sensitive audits, use **Firecracker**.

- **Connect: attempt-only canonicalization.** Per the observe-only network
  posture, the macOS bare backend stays **online** — the shim hooks `connect()`,
  records the attempt, and lets it proceed. The Linux backends run Phase B
  **offline**, so the same `connect()` is recorded as `<BLOCKED> connect
  <host>:<port>`. Each committed lock stays faithful to what its backend
  actually saw (`src/lock/normalize.ts` does **not** rewrite the per-host
  connect result), so `scripts/parity-diff.ts` strips the `<BLOCKED> ` prefix
  from `connect` entries on **both** sides before comparison — the same
  diff-time precedent as `generated_at`. After stripping, a Linux blocked
  attempt and a macOS succeeded attempt to the **same** host:port reconcile,
  while a connect to a **different** host still surfaces as a diff hunk. This
  preserves the Linux audit's blocked-vs-succeeded signal in its own committed
  lock without weakening it.

  > **Security note.** Observe-only means the macOS backend **records** but does
  > not **prevent** egress: a malicious `connect()` actually succeeds, unlike
  > Linux's offline Phase B. This is an intentional posture difference for the
  > bare backend; Firecracker remains the high-assurance backend when egress
  > prevention matters.

- **Resolver-address filter.** A name lookup the install triggers connects to
  the host's DNS endpoint. The parity filter already drops the Apple
  Virtualization.framework NAT resolver (`192.168.64.1:53`) and the Azure
  runner endpoint (`168.63.129.16:53`); the macOS bare backend adds the system
  stub resolver on loopback (`127.0.0.1:53`, mDNSResponder). These are host
  resolver plumbing, not dependency behavior. Because the connect prefix is
  stripped first, the filter set stores these entries in their prefix-less
  `connect <addr>:53` form.

- **`/private` realpath canonicalization.** On macOS `/var`, `/tmp`, and `/etc`
  are symlinks into `/private`, so the absolute path the shim resolves (via
  `F_GETPATH`/`realpath`) comes back as `/private/var/...`, `/private/tmp/...`,
  `/private/etc/...`. `normalize.ts` strips the `/private` prefix (darwin-gated)
  **before** tokenization and noise filtering, so the canonical `/var`, `/tmp`,
  `/etc` forms match both the tokenize roots and the shared system-noise
  prefixes the Linux side uses. The rewrite is segment-bounded: `/private/var`
  rewrites, `/private/variant` does not.

- **macOS system-noise prefixes.** The shim, unlike strace, surfaces the dyld
  runtime and Apple framework reads a hardened-runtime Node and the bundled
  plain-arm64 shell/coreutils substitutes perform at startup. `normalize.ts` drops these as system noise
  **only when `os === 'darwin'`**: `/System/`, root-level `/Library/` (the
  per-user `/Users/<u>/Library` is **not** dropped — it can hold real package
  writes), the `dyld_shared_cache_*` image, the dyld state store under
  `/var/db/dyld/`, and the provisioned-node toolchain cache (matched by its
  fixed `script-jail-cache` directory segment — the macOS analog of the Linux
  `/opt/vp` noise prefix). The darwin gate is a **security boundary**: a
  malicious Linux lockfile must never be able to smuggle macOS-shaped paths
  (e.g. a `/System/...` write inside a package dir) past a Linux audit gate
  that would otherwise drop them. The shared `/usr/lib`, `/usr/share`, and
  `/dev` prefixes apply on both platforms.

- **Case-insensitive filesystem caveat.** The default macOS volume (APFS) is
  **case-insensitive but case-preserving**, whereas the Linux audit rootfs is
  case-sensitive. A lifecycle script that reads `README.md` then `readme.md`
  observes one inode on macOS and two distinct paths on Linux; tokenization
  preserves the as-spelled casing, so the two sides can render different
  `external_reads` entries. Real packages rarely depend on this, but a fixture
  that exercises mixed-case paths can diverge. If you hit it, normalize the
  fixture's casing rather than weakening the comparator — case-folding paths
  globally would mask genuine cross-package escapes that differ only by case.

- **Host-toolchain exec: ENOENT vs ok.** The Linux audit ships a deliberately
  minimal rootfs (no `gcc`, no `python`, no host `git`), so a script that
  shells out to a build toolchain records the `exec` attempt with an ENOENT
  result. A developer Mac (or a `macos-14` runner) usually has the Xcode
  Command Line Tools installed, so the **same** exec succeeds (`ok`). Both
  sides record the spawn attempt, but the result differs. Constrain the parity
  fixture to packages that do not shell to host toolchains; if a fixture must,
  the spawn result — not just the path — will surface as a diff. Do **not**
  blanket-canonicalize spawn results to attempt-only: that would erase the
  Linux signal that an exec was blocked.

- **Dropped `audit_bypass` detectors.** Three `audit_bypass` event kinds are
  **strace-derived** and have no macOS equivalent, because there is no kernel
  syscall channel to cross-check the libc-level shim against:
  `<SYSCALL_EXEC_BYPASS>` (a raw `syscall(SYS_execve, …)` that skipped every
  libc wrapper), `<EVENTS_FILE_FORGERY>` (a non-shim-loaded pid writing forged
  events into the trusted JSONL channel), and `<UNRESOLVED_PATH>` (a
  dirfd/cwd-relative open the strace canonicalizer could not resolve). These
  **never** appear in macOS-bare goldens. The filesystem-based events-file
  tamper detector still fails closed on macOS, and `<EXEC_FAIL_OPEN>` /
  `<AUDIT_FD_LOST>` are still emitted by the shim/preload layers. This is an
  inherent fidelity gap of a no-strace backend: **Firecracker remains the
  high-assurance backend**; the macOS bare backend trades some kernel-level
  cross-checks for a VM-free, CI-native macOS audit.

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

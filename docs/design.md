# Design

`script-jail` exists because package-manager lifecycle scripts are arbitrary
code that run at dependency-install time. A dependency can reach a developer or
CI machine only after a lockfile diff lands in a repository, so the lockfile
review is the best place to surface what that install code actually does.

This document explains the design rationale. For implementation mechanics, see
[architecture.md](./architecture.md).

## Problem

`preinstall`, `install`, `postinstall`, and `prepare` scripts run during normal
package-manager workflows. They can read credentials, inspect the host, spawn
tools, load native code, write into neighboring packages, and attempt network
egress before application code ever imports the package.

Traditional dependency review focuses on package names, versions, CVEs, and
source diffs. Those are useful, but they do not answer the operational question
reviewers often need during a lockfile change: what did the new install scripts
try to touch?

`script-jail` makes that behavior reviewable. It reruns the install in a
single-use audit backend and turns the observable lifecycle-script behavior
into a deterministic YAML lockfile.

## What Script-Jail Does

On a package-manager lockfile change, `script-jail` runs the install in two
phases inside a Linux audit environment. Phase A fetches dependencies with
network enabled. Phase B disables network, traces lifecycle scripts, attributes
events to `pkg@version` plus lifecycle stage, normalizes paths, and renders a
byte-stable `.script-jail.lock.yml`.

The Action's default `check` mode compares the generated lockfile to the
committed copy. If any non-canonical diff remains, the PR fails and the unified
diff becomes the review surface. The local macOS CLI produces the same Linux
guest lockfile through Apple's Virtualization.framework so developers can
regenerate or check the lock before pushing.

## Threat Model

Defended cases:

- Lifecycle scripts reading protected files such as `~/.ssh/**`, `~/.npmrc`,
  or repo-local `.env` files.
- Lifecycle scripts reading protected env vars such as `NPM_TOKEN`,
  `NODE_AUTH_TOKEN`, `GITHUB_TOKEN`, or cloud credentials.
- Writes that escape the owning package directory, including cross-package
  writes under `node_modules`.
- `execve` attempts, including missing binaries that reveal native toolchain
  assumptions.
- Raw-syscall exec bypasses that avoid the shim's libc wrappers.
- Attempts to tamper with the audit environment, such as removing
  `LD_PRELOAD`, `NODE_OPTIONS`, or sticky `SCRIPT_JAIL_*` vars.
- Network attempts during Phase B, when the install should be offline.
- Legacy `dlopen-block.cjs` quarantine events when that optional preload is
  enabled in tests or future quarantine modes.

Not defended cases:

- A package that behaves benignly during install and attacks only at
  application runtime.
- Full same-UID integrity of the audit JSONL channel. The current design has
  forgery detection, but the complete fix is UID separation. See the
  [same-UID audit-channel limitation](./architecture.md#same-uid-audit-channel-limitation).
- Compromise of `script-jail` release artifacts themselves. The artifact
  manifest pins SHAs and Docker digests, but the first release still needs
  real non-placeholder values.
- General-purpose process sandboxing outside the package-install workflow.

Assumptions:

- Firecracker VMs and Docker containers are single-use and discarded.
- Bare mode runs against a staged copy of the repository and deletes it after
  the run.
- Phase B is offline, so install-time exfiltration is bounded even when a
  script executes.
- Reviewers treat lockfile changes as security-relevant and inspect new audit
  signals before merging.

## Goals

- **Observe below JavaScript.** Native addons, libuv, libc, and child processes
  must be visible even when JavaScript hooks are bypassed.
- **Keep output deterministic.** The lockfile is valuable only if the diff is
  stable across identical inputs. Volatile fields are canonicalized in the diff
  path; everything else should be byte-stable.
- **Make review simple.** The output is YAML grouped by package and lifecycle
  stage, not a severity score.
- **Preserve real installs.** Native addons and `child_process.spawn` are
  allowed by default; the audit records behavior rather than breaking common
  install scripts.
- **Keep local and CI results aligned.** macOS developers should be able to
  generate a Linux guest lockfile that matches CI after known host/backend
  noise is filtered.
- **Run where CI actually runs.** Firecracker is preferred, but Docker and bare
  Linux keep the audit path usable when hosted runners do not expose KVM.

## Non-Goals

- Runtime protection after install.
- Replacing `npm audit`, SCA tools, vulnerability databases, or provenance
  systems.
- bun support in v1. bun does not honor the Node preload model that
  `script-jail` relies on for JS env-read auditing.
- A general-purpose container or VM sandbox API.
- Silent auto-approval of dependency behavior. The diff is the signal; humans
  still review it.

## Key Decisions

### Backend Isolation Over JS Hooks

Lifecycle scripts can cross the JavaScript boundary immediately. Native addons
load through the dynamic linker, child processes enter the kernel through
`execve`, and Node/libuv can read env vars through libc without touching a
`process.env` Proxy. A JS-only hook would miss these paths.

The audit therefore runs in a backend that can combine kernel tracing with
process-level preloads. Firecracker gives the strongest isolation boundary.
Docker and bare Linux trade isolation strength for availability while keeping
the same guest agent, `strace`, shim, normalization, and lockfile renderer.

### Separate Host Backends, Shared Guest Pipeline

Linux CI and macOS developer machines need different host-side launchers:

- Linux uses the Action entrypoint in `src/main.ts` and selects
  Firecracker, Docker, or bare mode from `src/action/backend/`.
- macOS uses the CLI in `src/cli/` and a Rust
  Virtualization.framework helper in `src/host-mac/`.

Both paths converge on the same guest agent, frame protocol, install phases,
event schema, normalization, and renderer. Host code owns startup, staging, and
transport; guest code owns the audit.

### Two-Phase Install

Phase A exists because package managers need network to fetch dependencies.
Tracing that phase would mostly capture registry, cache, and package-manager
client behavior, not lifecycle-script intent.

Phase B starts after fetch. The network is disabled, `strace` is attached, and
the lifecycle rebuild/install command runs. Only Phase B events enter the
lockfile.

### Drop-in Install Trust Model (`install: true`)

By default the host runner never receives a `node_modules` — the install runs on
a throwaway copy inside the backend and only the lockfile YAML crosses back. The
opt-in `install: true` mode turns the Action into a drop-in install replacement
by reusing the SAME two-phase split on the host:

1. **Host part 1** — the package manager installs with `--ignore-scripts`
   (`--mode=skip-build` for yarn). No third-party code runs; the real
   `node_modules` is populated safely.
2. **Sandbox audit** — unchanged. The lockfile is diffed against the committed
   `.script-jail.lock.yml` and the audit-bypass gate fires.
3. **Host part 2** — the deferred lifecycle scripts run on the host, but ONLY
   when the audit is *trusted*: `mode === 'check'` ∧ the lock matched ∧ no
   audit-bypass entry. On drift or bypass the scripts never run; the safe
   no-scripts tree is left in place and the job fails.

The command shapes for both host halves are the single source of truth in
`src/shared/pm-commands.ts`, shared with the guest phases so the host install is
byte-identical to what the sandbox audited. The trust signal is surfaced from
`runAudit` as `{ exitCode, trusted }`; `main.ts` gates part 2 on `trusted`.

**Accepted residual — host part 2 runs online.** Real lifecycle scripts
(`prebuild-install`, `node-pre-gyp`) fetch prebuilt binaries, so part 2 cannot
run inside an offline network namespace on a generic runner. Consequence: a
`connect` the sandbox recorded as `<BLOCKED>` (Phase B is offline) WILL succeed
when the same script runs on the host. Trust therefore derives from the committed
lock being **human-reviewed**, not from host isolation — a matching audit means
"behaviour is unchanged from the reviewed lock," not "safe to run with the
network on." This is strictly safer than an unaudited install step (which runs
the same scripts online with zero recording) but weaker than the audit-only mode,
where every script stays inside the sandbox. `install` requires a committed lock
and is rejected in `update` mode (which regenerates the lock and skips the
bypass scan, leaving no fail-closed gate). See also the [README drop-in install
section](../README.md#drop-in-install).

To keep that online egress from being silent, part 2 first scans the matched
lock (`collectNetworkAttempts`) and, if any `network_attempts` are recorded,
emits a `::warning::` with the count plus a per-package list before running the
scripts. The recorded destination is the resolved **IP:port** the offline audit
captured — `strace` parses the `connect()` sockaddr, never a DNS name — so the
warning notes the host may resolve a different address. It is a directional
heads-up that egress *will* happen, not an exact preview of where.

**Accepted residual — the root `prepare` is audited but not run on the host.**
The sandbox runs a dedicated second audited pass for the *root* project's
`prepare` script (`npm rebuild --foreground-scripts` and yarn-berry
`install --immutable` never run a root `prepare`), so its reads/writes/egress
*are* recorded in the lock. But host part 2 runs only `INSTALL_CMD[pm]`
(`npm rebuild` / `pnpm rebuild --pending` / `yarn install --immutable`) — it
does **not** run the root `prepare`. The asymmetry is deliberate: the host drop-in
install is for consuming a project's dependencies safely, not for building the
project itself. Two consequences follow:

- For a project whose root `prepare` generates build output (e.g. compiling
  `dist/`), `install: true` does **not** produce that output on the host — it is
  **not** a full `npm install` / `yarn install` for the root package. Run your
  build step separately after the Action.
- The egress warning above may list `network_attempts` that came from the
  root-`prepare` audit pass. Those connects will **not** fire during host part 2,
  because the root `prepare` does not run there. The warning still surfaces them
  for review (they describe behaviour the lock captured), but for the root
  `prepare` specifically the "will happen on the host" framing does not apply.

### Layered Observation

No single layer sees everything:

- `strace` sees filesystem, process, and network syscalls.
- The Rust `LD_PRELOAD` shim sees libc env reads, exec-family calls, and env
  mutation attempts before forwarding to libc.
- `env-spy.cjs` sees JavaScript `process.env.X` reads after Node has copied
  `environ[]` into its internal map.
- `platform-spoof.cjs` keeps platform-conditioned install branches pointed at
  the configured target.
- `dlopen-block.cjs` remains as a legacy optional quarantine preload, but the
  default runtime does not inject it.

These layers are intentionally overlapping only where cross-checks are useful,
such as raw-syscall exec-bypass detection.

### Audit, Do Not Break Normal Native Installs

Early designs considered disabling native addons or blocking `dlopen`. That
made common packages fail before their behavior could be reviewed. The current
default leaves native addons and `child_process.spawn` enabled inside the
backend and records what they do.

This is why `tries-dlopen` is expected to show a normal `node script.js` spawn
rather than a blocked native-addon load in the default fixture path.

### Byte-Stable YAML Instead of a Score

The lockfile is intentionally boring: sorted keys, sorted lists, fixed
indentation, and stable path tokens such as `$PKG`, `$NODE_MODULES`, `$HOME`,
`$REPO`, `$CACHE`, and `$TMPDIR`. A deterministic diff is easier to review than
a score whose meaning changes with heuristics.

`generated_at` and `manager_lockfile_sha256` are intentionally volatile and are
canonicalized by the diff path. Any other churn is treated as a bug or as a
host/backend noise pattern that needs a narrow filter.

### Same-Arch Parity

The old parity direction forced macOS arm64 runs to resolve a Linux x64 package
tree. That made optional dependency names line up with x64 CI, but lifecycle
scripts still ran in a real arm64 VM, which produced unavoidable native
behavior drift.

The current direction is same-arch parity. The parity workflow runs Linux CI on
`ubuntu-24.04-arm`, and the committed macOS/VZ fixture is a Linux arm64 guest
lockfile. Package-manager architecture overlays are now a compatibility seam,
not the normal path.

### Filter Runtime Noise Narrowly

The lockfile should describe dependency lifecycle behavior, not Node's own
startup or the package-manager client's ambient environment. The install phase
therefore records Node bootstrap env/file reads as a baseline and filters
unprotected repeats from package output. It also filters unprotected env reads
from npm, pnpm, and Yarn client pids.

Protected reads are never hidden by these filters: a protected file or env var
still surfaces as `<HIDDEN> ...`.

The parity diff has a second, narrower filter for host/backend noise that can
survive into otherwise equivalent lockfiles, such as VZ vs Azure DNS resolver
addresses and `$HOME/.cache/puppeteer` read probes. Writes to those paths still
surface.

## Roadmap

v1 scope:

- GitHub Action with `check` and `update` modes.
- Linux backend abstraction: Firecracker, Docker, and bare executor.
- macOS CLI path through Virtualization.framework.
- npm, pnpm, and Yarn support.
- Two-phase install with Phase B offline.
- `strace`, Rust shim, and Node preload audit layers.
- Deterministic `.script-jail.lock.yml`.
- Hard-gated Linux/macOS parity workflow for the pinned upstream fixture.

Deferred work:

- UID separation for the audit channel.
- `execle` coverage in the Rust shim.
- Broader syscall coverage for filesystem mutations such as mkdir, symlink,
  link, rmdir, and additional rename shapes.
- Better handling for async socket connect completion (`getsockopt(SO_ERROR)`).
- A configurable host-control timeout for the Phase A to Phase B `go` signal.
- Intel macOS coverage when there is a practical runner or release path.
- Real release artifact SHAs and Docker image digests after the first release
  artifact bootstrap.
- bun support only if there is a credible audit path for its lifecycle model.

## Known Limitations

For detailed mechanisms and security caveats, read
[architecture.md](./architecture.md#threat-model-and-known-gaps). For
cross-host lockfile limits and parity triage, read
[divergence.md](./divergence.md).

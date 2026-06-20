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
network on." Compared with an unaudited install step (which runs the same scripts
online with zero recording), `install: true` at least records and gates on the
behaviour the sandbox observed; but it is **weaker** than the audit-only mode and
is **not** a guarantee that the host run matches the audit. Host part 2 happens on
the *uninstrumented* runner, so an environment-sensitive script can detect the
sandbox and behave differently there (see *Accepted residual — environment-sensitive
scripts can detect the sandbox*, below). Trust is bounded by the **human-reviewed
lock**, not by host/sandbox parity. `install` requires a committed lock and is
rejected in `update` mode (which regenerates the lock and skips the bypass scan,
leaving no fail-closed gate). See also the [README drop-in install
section](../README.md#drop-in-install).

To keep that online egress from being silent, part 2 first scans the matched
lock (`collectNetworkAttempts`) and, if any `network_attempts` are recorded,
emits a `::warning::` with the count plus a per-package list before running the
scripts. The recorded destination is the resolved **IP:port** the offline audit
captured — `strace` parses the `connect()` sockaddr, never a DNS name — so the
warning notes the host may resolve a different address. It is a directional
heads-up that egress *will* happen, not an exact preview of where.

The warning is **scoped to what host part 2 actually runs** (`formatEgressWarning`
in `src/action/diff.ts`). Not every audited egress entry fires on the host: the
sandbox always audits the root `prepare` in a dedicated pass (below), but host
part 2 invokes `INSTALL_CMD[pm]`, whose coverage of the root `prepare` differs by
manager — npm (`rebuild --foreground-scripts`) and yarn (`install --immutable`)
do **not** run it, pnpm (`rebuild --pending`) **does**. So for npm/yarn, egress
entries whose `(stage === 'prepare', packageId ∈ rootPackageIds)` are partitioned
out of the host-bound "WILL now succeed" list and shown instead in a separate
"audited in the sandbox; NOT run on the host (root `prepare`)" block. For pnpm
those entries stay host-bound. Surfacing an audited-but-not-run connect as "WILL
now succeed" would over-claim; the partition keeps the warning honest about what
the runner will actually reach.

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
  root-`prepare` audit pass. For npm/yarn those connects will **not** fire during
  host part 2, because the root `prepare` does not run there, so they are shown in
  the warning's separate audited-only block (above); for pnpm they stay
  host-bound. The warning still surfaces them for review (they describe behaviour
  the lock captured) either way.

**Accepted residual — environment-sensitive scripts can detect the sandbox.**
Host part 2 re-runs the lifecycle scripts on the *uninstrumented* runner, in an
environment that cannot be made byte-identical to the audited one. A script that
*detects* it is being audited can stay benign in the sandbox and misbehave only on
the host — and the byte-stable lock still matches, because the audit never saw the
malicious branch. This is inherent to re-running on a host the auditor does not
control; the trust boundary is the human-reviewed lock, **not** host/sandbox parity.

script-jail closes the most ergonomic tells as **defense-in-depth (not a complete
fix)**:

- **cwd parity.** `process.cwd()` (the `getcwd` syscall) is not traced, so a
  cwd-branch is invisible to the lock. For `install: true` the audit `work_dir` is
  pinned to the real host repoDir (`installWorkDir` → the effective config's
  `work_dir`), so the audited cwd equals the host re-run's: Docker mounts the
  staged repo at `${repoDir}` (`-v staged:${repoDir}`); Firecracker `mount --move`s
  the repo disk from `/work` to `${repoDir}` in `init.sh` while still privileged
  (before the `setpriv` cap-drop), falling back to a `/work` audit if the move
  fails. The literal path never reaches the lock — it tokenizes to `$REPO`.
- **env hygiene.** The host re-run drops the env-var tells the sandbox does not
  carry (`HOSTNAME`, `PWD`, every `SCRIPT_JAIL_*` host knob), aligning the env-var
  view with what the audit saw.
- **no un-staged ancestor.** The sandbox stages only `repoDir`, but host part 2
  runs at `cwd=repoDir` on the runner where the checkout *ancestor* is real and
  PR-controlled. A root lifecycle script reading `../<committed>` (a value-blind
  read) or `require()`-ing `../../mal.js` (code the audit never ran) would diverge.
  So `install: true` **refuses a `repoDir` that is a strict subdirectory of
  `GITHUB_WORKSPACE`** (`detectSubdirInstallAncestorEscape`): the audit must run
  from the checkout root, where `repoDir`'s parent is runner-owned, not
  PR-controlled. A subproject (`SCRIPT_JAIL_REPO_DIR=<subdir>`) can still be audited
  in pure-audit mode (`install: false`); only the host re-run requires root-level
  `repoDir`.

What this CANNOT close (irreducible while host part 2 runs uninstrumented):

- **Syscalls** — `os.hostname()`/`uname()` (no backend hooks them) and other
  kernel-observable differences (the microVM/container `/proc`, mount table, …).
- **Node version string** — the audit pins the guest Node (`NODE_VERSION` in
  `src/rootfs/vite-plus.ts`); host part 2 runs under the Action's bundled Node
  (`action.yml using: node24`), whose *patch* level the consumer cannot pin. A
  script branching on the exact `process.version` / `process.versions.modules`
  string is therefore in the same uninstrumented-detection class as `os.hostname()`
  (no layer records it). `main.ts` gates on the Node **major** only: the major sets
  the native ABI (`NODE_MODULE_VERSION` is per-major), so the one lock-*affecting*
  divergence — a native addon compiled against a different ABI — is closed, while
  exact-patch parity would break `install: true` on essentially every real runner.
- **Marker files** — `/.dockerenv` (Docker), `/etc/script-jail/config.yml`.
- **The instrument itself** — the audited child MUST carry
  `LD_PRELOAD=libscriptjail.so` and `NODE_OPTIONS=--require …preloads`; a script
  keyed on their *absence* fires only on the host. Removing them disables the audit.
- **bare / mac-bare cwd** — the cwd parity above is Firecracker/Docker only. The
  `bare`/`mac-bare` backends audit at a staged temp path, so their `process.cwd()`
  still differs from the host re-run (documented in
  [docs/divergence.md](./divergence.md); Firecracker is the enforcement boundary).

Bottom line: `install: true` is a convenience that records and gates on observed
behaviour — **not** a sandbox guarantee against an adversary who tailors a payload
to the audit environment. Review the lock.

**Non-forgeable root identity (`root_anchored`).** The root project's events are
privileged: it is not under `node_modules`, so a root-attributed fs event has no
`$PKG` token and surfaces as `$REPO/...` in `external_reads`/`escaped_writes`.
But attribution derives the package label from the **forgeable** `npm_package_name`
the observed process exported, so a malicious dependency could spawn a child with
`npm_package_name=<root-project-name>` and launder its own repo writes under the
root's identity — and, if a forged write matched a genuine root write, dedupe them
away so the escape disappears entirely. Env is therefore insufficient to decide
root identity.

The fix is a non-forgeable verdict, `root_anchored`, that the producer stamps on
every root-attributed fs read/write (consumed in `src/lock/normalize.ts`, never
rendered):

- **Linux/Firecracker (the enforcement boundary)** computes it from a signal a
  lifecycle script cannot rewrite after the fact: the kernel-observed process tree
  (`clone`/`fork`/`vfork` edges) plus the cwd each process had at its **first
  `execve`**. The package manager sets a lifecycle script's cwd to the package dir
  *before* the script can run, and the value is snapshotted at exec time, so a
  later `chdir(workDir)` cannot launder it. `isRepoRootAnchored`
  (`src/guest/root-anchor.ts`) walks an event's pid up the parent chain to the
  package-manager root: the event is anchored **iff** every hop either never
  exec'd (inherits its parent's identity) or exec'd at the repo root, with no
  ancestor that exec'd in a dependency directory. It is a **pure, fail-closed**
  walk — an unresolvable cwd, a broken lineage, or a depth-bound overrun all
  return `false`.
- **The dedicated root-`prepare` pass is bulletproof by construction.** That pass
  runs `<manager> run prepare` and nothing else, so *every* event it produces
  genuinely belongs to the root's prepare regardless of any forged env. A
  force-attribution emitter (in `src/guest/agent.ts`) rewrites each event in the
  pass onto the canonical root key with `root_anchored = true` (for the full
  anchorable set: read/write AND spawn/connect/env_read, so a genuine root prepare
  non-fs event never mis-renders `<FORGED_ROOT>`) at the emitter boundary — the only point where "this came from the prepare pass" is still
  known. No untrusted actor can be in that pass, so it needs no process-tree walk.
- **macOS-bare defaults it `true`** (observe-only; see `docs/divergence.md`). It
  has no strace process-tree / exec-cwd machinery, so root identity there is
  env-trusted — a documented residual, with Firecracker as the enforcement
  boundary.

`normalize.ts` then surfaces the cases distinctly. The verdict + `<FORGED_ROOT>`
treatment is **no longer read/write-only** — it now covers the non-fs trio
(`spawn` / `connect` / `env_read`) as well, since all of those carry `pid` and
`isRepoRootAnchored` is purely pid-based:

| Event | `root_anchored` | Renders as |
| --- | --- | --- |
| genuine root (read/write) | `true` | `$REPO/...` (exactly as before) |
| forged root read/write (claims root, not anchored) | `!== true` | `<FORGED_ROOT> $REPO/...` (outermost prefix) |
| genuine root spawn/connect/env_read | `true` | unmarked (`node …` / `connect host:port` / `NAME`, as before) |
| forged root spawn/connect/env_read | `!== true` | `<FORGED_ROOT> ` outermost (before any `<BLOCKED>`/`<ENOENT>`/`<AUDIT_BLIND>` tag) |
| non-root with no package dir | n/a | throws (fail closed) |

A forged-root event is **never dropped and never throws** — dropping would be a
dependency-triggered hide, throwing would crash the whole audit. The
`<FORGED_ROOT> ` prefix makes it a distinct string that can never dedupe-collapse
with a genuine root entry, so a laundering attempt is fail-loud for the reviewer.
Extending it to non-fs kinds closes two harms a dependency that unsets
`npm_package_name` (while keeping a recognised `npm_lifecycle_event`) could
otherwise cause: (1) its `connect`/`spawn`/`env_read` would dedupe-collapse with —
or be indistinguishable from — a genuine root entry, and (2) the drop-in-install
egress warning (`src/action/diff.ts`) would misclassify a forged `<repo-root>`
`prepare` connect as "audited-only / will NOT run on the host" for npm/yarn, even
though under `install:true` the forging dependency's lifecycle DOES run online on
the host — understating a real egress risk. The diff partition now routes any
`<FORGED_ROOT> ` egress to host-bound. Genuine root output is byte-identical to
before the change.

**Nameless roots are audited, not refused.** A root `package.json` with no `name`
(e.g. an unnamed private monorepo root running `preinstall: npx only-allow pnpm` +
`postinstall: simple-git-hooks`) leaves `npm_package_name` empty, so its own
lifecycle events would attribute to null and be dropped at the null-attribution
gate — leaving the root unaudited and the lock deceptively clean. The agent used to
**fail closed** (refuse to emit a lockfile) whenever a nameless root ran a main-pass
lifecycle or `prepare` script. That over-fired: it refused to audit the very common
unnamed monorepo root even in pure-audit mode, where the only consequence is a
weaker audit, not RCE. Now `buildRootPkgKeys` gives a nameless-but-parseable root
the synthetic key `ROOT_SENTINEL = '<repo-root>'` (`src/guest/attribution.ts`), and
nameless handling lives in the **attribution layer**, not a dispatcher rescue:
`attributionFromEnvVars` takes a `rootSentinel` parameter and, when the observed env
has an empty `npm_package_name` but a recognised `npm_lifecycle_event`, attributes
the event to the sentinel. "Recognised" means a *canonical*
`LifecycleStage` (`preinstall` / `install` / `postinstall` / `prepare`), one of
pnpm's main-pass root rebuild-class hooks (`prepublish` / `prerebuild` / `rebuild`
/ `postrebuild`, which `pnpm rebuild --pending` runs on the root with a
non-canonical lifecycle name; folded into `install`), or one of npm's
prepare-wrapper hooks (`preprepare` / `postprepare`, which `npm run prepare` fires
around the dedicated root-prepare pass; folded into `prepare`). The non-canonical
hooks are folded so they are audited rather than silently dropped at the
null-attribution gate before the prepare pass's force-attribution emitter could
restamp them. This widening is **scoped to the nameless-root sentinel**: a named
package keeps the strict 4-stage gate, so it never changes named-package
attribution. This is consumed by both the `/proc` walk (the
`Attribution` ctor carries the sentinel) and the shim fast-path
(`shimExecAttribution` / `classifyShimNodeStartupMarker`, the only attribution
source on macOS, which has no `/proc` environ). Two consequences fall out for free:
(1) **all** event kinds for the nameless root's lifecycle surface — `spawn` /
`connect` / `env_read`, not just `read` / `write` (the old read/write-only rescue
dropped the rest); and **all** of them route through the same defer →
end-of-drain `root_anchored` stamp (the defer predicate covers
read/write/spawn/connect/env_read, never `exec`). A genuine root event renders
unmarked (`$REPO/...` for fs, `node …` / `connect host:port` / `NAME` for non-fs);
a forged/unanchored one gets the `<FORGED_ROOT> ` prefix (outermost, before any
`<BLOCKED>`/`<ENOENT>`/`<AUDIT_BLIND>`/`<HIDDEN>` tag). This closes the prior
unmarked-non-fs residual: a forged root `connect`/`spawn`/`env_read` can no longer
dedupe-collapse with a genuine root entry, and a forged `<repo-root>` `prepare`
connect is no longer mistaken for the genuine root's host-safe prepare by the
drop-in-install egress partition.
(2) The package-manager **driver** and its non-lifecycle workers carry *no*
canonical `npm_lifecycle_event`, so they still attribute to null → dropped — which
is what stops the driver's bulk store/cache/`$REPO` I/O from flooding `<repo-root>`
(the driver pid is also null-attributed and equals the root pid, so a read/write
rescue keyed only on null attribution would have swept it all in). Because anchoring
keeps the lock non-deceptive (escaping behaviour surfaces and the diff gate fails on
it), the refusal is unnecessary and was removed. The fail-closed gates for a
genuinely-unparseable alternate root manifest (`package.yaml` / `package.json5` with
no `package.json`) and for a zero-event `prepare` pass remain — both orthogonal to
the nameless class.

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

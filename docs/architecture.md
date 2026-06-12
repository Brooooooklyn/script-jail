# Architecture

## Host vs guest

The Action splits into a host controller and a Linux audit agent. Firecracker
connects them over vsock; Docker and bare mode use the same frame protocol over
stdio.

- **Host** (`src/main.ts`, `src/action/`) — runs on the GitHub Actions runner. Detects the package manager and runner image, selects a backend, prepares the effective config/repo overlay, drives the agent protocol, then diffs/renders the result.
- **Agent** (`src/guest/`) — runs inside the selected Linux backend. Reads `.script-jail.yml`, runs the install in two phases under `strace`, applies the protected-path policy, attributes events to packages and lifecycle stages, normalizes/renders the lockfile, and emits everything back to the host.

The kernel-level observation is load-bearing. A pure-JS sandbox can't catch libuv-backed env reads, `dlopen` for native addons, or `execve` of arbitrary binaries — those reach the kernel before any JS hook fires. Firecracker is the strongest isolation boundary, but Docker and bare mode still keep the syscall/preload audit path available when KVM is missing.

## Cross-host parity (macOS VZ)

The same audit runs in two places:

- **Linux CI** — the GitHub Action invocation. The host half lives in
  `src/main.ts` + `src/action/`. `backend: auto` tries
  Firecracker, then Docker, then bare Linux. Firecracker-specific code lives in
  `src/action/backend/firecracker.ts` and `src/action/firecracker/`; Docker and
  bare mode live in `src/action/backend/`.

- **macOS developer host** — the local CLI invocation
  (`pnpm exec script-jail …`). Boots Apple's Virtualization.framework via
  `objc2-virtualization`; the host half lives in `src/host-mac/` (Rust)
  driven by `src/cli/` (TypeScript). Requires macOS 14+.

Both halves share the same guest agent (`src/guest/`), frame protocol
(`src/shared/vsock-protocol.ts`), and lockfile renderer (`src/lock/`). The split
is intentionally thin: backend startup, filesystem staging, and transport
wiring differ; the audit pipeline does not.

The release pipeline (`release.yml`) ships per-platform artifacts under one
tag and publishes Docker rootfs images to GHCR. Firecracker/bare Linux consume
`rootfs-ubuntu-<major>.ext4` + `libscriptjail.so` + the pinned upstream
`vmlinux` from Firecracker CI; Docker consumes digest-pinned
`script-jail-rootfs` image refs; the macOS CLI consumes
`rootfs-ubuntu-<major>-arm64.ext4` + `libscriptjail-arm64.so` + the hand-built
`vmlinux-vz-{x86_64,arm64}` + the `script-jail-vm-arm64-darwin` Mach-O binary.
The manifest in `src/action/artifact-manifest.ts` keeps release-asset SHAs in
`expected: { linux: {...}, darwin: {...} }` and Docker image pins in
`dockerImages`.

A small set of host/backend noise is either filtered before the lockfile is
rendered or filtered by the parity diff. Any remaining byte difference is a
parity failure; see [docs/divergence.md](./divergence.md) for the catalogue.

## Two-phase install

1. **Phase A — fetch.** Network on, no strace. Lets the package manager resolve the registry and populate its cache. Output of this phase is not audited.
2. **Phase B — install.** Network off (Firecracker removes guest routing; Docker disconnects the container; bare mode runs the traced command under `unshare -n`), strace attached. Every syscall the lifecycle scripts make is captured. Native addons and `child_process` spawns are allowed to run inside the backend; failed or unavailable child binaries are recorded in the lockfile.

Phase B is the only phase whose events end up in the lockfile.

## Event pipeline

```
strace -ff output ──► strace-parser ─┐
                                     ├──► attributed raw events
shim/env-spy JSONL ─► shim parser ───┘          │
                                                │
                      protected-paths + bootstrap/client filters ◄── .script-jail.yml
                                                │
                                           normalize
                         (tokenize paths, drop intra-package noise, dedupe)
                                                │
                                             render
                                  (canonical YAML, byte-stable)
                                                │
                                      .script-jail.lock.yml
```

Key files:

- `src/guest/strace-parser.ts` — parses filesystem, process, fd-state, and network strace lines.
- `src/guest/protected-paths.ts` — replaces values for protected paths/env-vars with `<HIDDEN>`; drops `ENOENT` probes for unprotected paths so the audit reflects intent, not noise.
- `src/guest/attribution.ts` + `proc-reader.ts` — walk `/proc/<pid>/status` PPid chain looking for an ancestor whose `environ` carries `npm_package_name` + a canonical `npm_lifecycle_event`. Results are cached per starting pid; `invalidate(pid)` drops the cache so a recycled pid re-walks `/proc`.
- `src/lock/normalize.ts` — drops reads inside the owning package's own directory; marks cross-package writes; coalesces duplicates.
- `src/lock/tokenize.ts` — substitutes `$PKG`, `$NODE_MODULES`, `$HOME`, `$REPO`, `$CACHE`, `$TMPDIR` for absolute paths.
- `src/lock/render.ts` — emits canonical YAML.

### Attribution and snapshot lifecycle

`Attribution.attribute(pid)` returns a `{ pkg, lifecycle }` pair by walking the pid's `/proc/<pid>/status` PPid chain and reading each ancestor's `environ`. The walk terminates at pid 0/1 or when `readPpid` returns null. Results are cached per starting pid.

The phase-install dispatcher layers a per-pid **attribution snapshot** on top of the cache so fallback paths can attribute events even when `/proc` is no longer authoritative (child reaped, envp scrubbed by a raw `execve`, etc.). Each snapshot carries `{ pkg, lifecycle, recordedAtTs, stale }`:

- **`recordedAtTs`** is the monotonic dispatcher ts of the line that wrote the snapshot. `recordAttribution` only overwrites an entry when the incoming ts is `>=` the stored ts. This protects against strace `-ff` cross-file ordering: per-pid trace files are drained in filesystem order, not happens-before, so a new generation's `clone(...) = <recycledPid>` line can be processed before an older generation's delayed `+++ exited +++` line. The ts gate ensures the older event can't clobber the fresh snapshot.

- **`stale`** is set to `true` on the exit line when `/proc` also returns null for the pid (the recycled generation hasn't set up `/proc` yet, or there is no recycled generation). Snapshots are never evicted on exit — the never-evict policy is required because no available signal (dispatcher ts, `/proc` liveness, outstanding-clones counter) can distinguish "normal clone-then-exit" from "delayed old-exit observed after a recycled clone" from observation order alone. Instead, fallback paths treat stale snapshots as missing: forgery attribution and bypass synthesis skip them, the spawn fallback still emits the event but routes it to `<unattributed>`, and the clone-parent-lookup re-attributes via `/proc`. When a delayed clone eventually arrives, `recordAttribution` writes a fresh entry (`stale: false`) and the package label resumes.

- The dispatcher calls `Attribution.invalidate(pid)` twice on every exit line — once before the post-invalidate liveness probe (so the probe doesn't read a dead-generation cached pkg), and once after (so a later recycle triggers a fresh walk rather than reading a cached null).

This model evolved through several rounds of Codex adversarial review (commits `e5af2be` → `f6a8d34` on `feat/exec-shim-env-reinject`); the final design is documented in-line at the exit-line handler in `src/guest/phase-install.ts`.

## Preload stack

| Layer | File | Catches |
| --- | --- | --- |
| Rust `LD_PRELOAD` shim | `src/shim/src/lib.rs` → `libscriptjail.so` | libc `getenv` / `secure_getenv` / `__secure_getenv` (covers libuv, native addons, child binaries inheriting env); `execve` / `execv` / `execvp` / `execvpe` / `execveat` / `fexecve` / `posix_spawn` / `posix_spawnp` (re-injects audit env vars on every exec); `setenv` / `unsetenv` / `putenv` / `clearenv` (refuses tampering of protected names). |
| Node `--require` JS | `src/guest/env-spy.cjs` | JS `process.env.X` reads (Node copies env into a JS object early; `getenv` won't see these). |
| Node `--require` JS | `src/guest/platform-spoof.cjs` | spoofs `process.platform` / `process.arch` to flush out OS-conditioned attack branches. |

`src/guest/dlopen-block.cjs` remains in-tree as a legacy quarantine preload and
has its own tests, but it is not part of the default `buildChildEnv()` preload
set. Default installs do not pass `--no-addons`, so N-API/native dependency
postinstalls and `child_process.spawn` use the normal Node runtime path while
the backend, strace, and LD_PRELOAD shim observe their file/env/network/exec
activity.

Adding a new audit category means picking the right layer: kernel-only behavior → strace; libc-level → Rust shim; JS-API-only → preload.

### Rust shim crate

`src/shim/` is a `#![no_std]` cdylib (`crate-type = ["cdylib"]`) that produces `libscriptjail.so`. Layout:

- `Cargo.toml` — two direct dependencies: `libc = "0.2"` (no_std, syscalls) and `ctor = "1.0"` with `default-features = false, features = ["proc_macro"]` (the default `std` feature collides with the crate's `#[panic_handler]`). Release profile pins `opt-level = "z"`, `lto = true`, `panic = "abort"`, `strip = true`.
- `rust-toolchain.toml` — pins the compiler to a specific stable channel for reproducible builds across CI and local dev.
- `Cargo.lock` is committed so transitive dep drift can't change the bytes between two tagged builds (the artifact SHA is recorded in `src/action/artifact-manifest.ts`).
- `src/lib.rs` is the entire implementation: `#[panic_handler]` aborts; recursion is guarded by a `pthread_key_create`-backed thread-local set up at the very top of the `#[ctor::ctor]` constructor; real symbols are resolved via `libc::dlsym(libc::RTLD_NEXT, …)`; if the pthread key fails to create, init returns early without setting `INIT_DONE` so the wrappers stay on transparent passthrough; all buffers are fixed-size stack allocations, no allocator is linked.

Build path: `pnpm build` → `scripts/build.ts:buildShim` → `cargo build --release --manifest-path src/shim/Cargo.toml` → copy `target/release/libscriptjail.so` → `images/libscriptjail.so` → rootfs Dockerfile copies into `/lib/libscriptjail.so`. On macOS dev hosts `buildShim` short-circuits with a warning.

### Env-read detection in detail

Env-var reads need both the libc shim and the JS preload because they sit on opposite sides of a one-shot copy.

**libc layer — `src/shim/src/lib.rs`.** A `#![no_std]` Rust cdylib that wraps `getenv`, `secure_getenv`, and the deprecated `__secure_getenv` alias via `LD_PRELOAD`. Real symbols are resolved with `libc::dlsym(libc::RTLD_NEXT, …)` inside a `#[ctor::ctor]` constructor. A `pthread_key_create`-backed thread-local recursion guard suppresses re-entry when `dlsym` / `open` / `clock_gettime` internally call `getenv` — the key is created before any other syscall so the bypass path is available from the very first instruction of init. When the name is on the protected list the wrapper returns `NULL` to the caller; otherwise it forwards to the real implementation. A musl fallback substitutes `getenv` for absent `secure_getenv` (script-jail guests are never setuid, so the semantics match). If `pthread_key_create` itself fails (PTHREAD_KEYS_MAX exhausted, exceedingly rare), the constructor returns early with `INIT_DONE = false`, leaving every wrapper on a transparent passthrough path so the host process is never broken. Catches libuv, native addons, and any child process that inherits the preload. For Node processes launched with the script-jail preloads, unprotected runtime-startup probes are emitted as raw events and then filtered by the Node bootstrap baseline; protected names are still hidden and reported.

**JS layer — `src/guest/env-spy.cjs`.** Node parses `environ[]` once at startup into an in-memory map and serves every `process.env.X` read from there without re-entering libc, so the most common attacker pattern (`process.env.NPM_TOKEN`) is invisible to the libc shim. This preload (loaded via `NODE_OPTIONS=--require`) replaces `process.env` with a Proxy whose `get` trap emits the audit event and applies hiding. Its `has`, `ownKeys`, and `getOwnPropertyDescriptor` traps hide protected names from enumeration without producing extra read events. The Proxy is installed with `Object.defineProperty(process, 'env', { writable: false, configurable: false })` to prevent `delete process.env` from restoring the original. A `Symbol.for('script-jail.env-spy.installed')` sentinel makes the preload idempotent across nested invocations; `logFd` and the protected-name set are pre-resolved against the **original** `process.env` before the Proxy is installed so the audit path itself cannot recurse through it.

**Critical detail — the Proxy receiver.** In the `get` / `set` traps, forward via `Reflect.get(target, prop, target)` (and the equivalent for `set`), passing `target` — not the Proxy — as the receiver. `process.env` is a host-side `EnvironmentVariableNamespace` object whose accessors use `this` to find the underlying environment store. When the receiver is the Proxy, Node can't locate the store and reads silently return wrong values, which breaks `child_process.spawn` with no diagnostic. The equivalent member-access form (`target[prop]`) also works.

**Unified event shape.** Both layers emit JSONL to `SCRIPT_JAIL_LOG_FILE` (preferred) or `SCRIPT_JAIL_LOG_FD` (tests), one of these `kind`s:

- `env_read` — `{"kind":"env_read","name":...,"pid":...,"ts":...,"hidden":...}` emitted by libc `getenv` / JS `process.env.X` reads. Protected names are hidden from the caller and rendered with `<HIDDEN>`; unprotected runtime and package-manager noise is filtered before rendering when it matches the bootstrap/client rules below.
- `exec` — `{"kind":"exec","prog":...,"argv0":...,"pid":...,"ts":...,"envp_alloc_failed"?:...}` emitted by the shim's exec wrappers (`execve` / `execv*` / `execveat` / `fexecve` / `posix_spawn[p]`) before forwarding to the real symbol. The optional `envp_alloc_failed` flag fires when env re-injection couldn't allocate and the caller's `envp` was forwarded unmodified (the exec still proceeds; the audit trail records the degraded state).
- `env_tamper` — `{"kind":"env_tamper","op":"setenv|unsetenv|putenv|clearenv","name":...,"pid":...,"ts":...,"refused":true}` emitted by the in-process env-mutator wrappers when the target is one of the protected names. The call is refused (returns 0 to the caller) and the audit event records the attempt.
- `dlopen` — `{"kind":"dlopen","filename":...,"result":"blocked","pid":...,"ts":...}` emitted only by the optional legacy `dlopen-block.cjs` preload, not by the default runtime path.

Writes are kept ≤ `PIPE_BUF` so they are atomic. Downstream, normalize dedupes, attribution maps `pid` → owning package + lifecycle stage, and the renderer emits one block per (package, event-kind) pair.

**Protected-list policy.** Both layers read the same list, sourced from `.script-jail.yml` and serialized into `SCRIPT_JAIL_PROTECTED_ENV_NAMES` (comma-separated strict POSIX env-var names). Adding a new protected name only requires editing the config — both layers pick it up at process start.

### Bootstrap and package-manager noise filtering

The install phase traces Node, npm, pnpm, and Yarn internals, but the rendered
lockfile should focus on dependency lifecycle behavior. `phase-install.ts`
therefore maintains two narrow filters:

- **Node bootstrap baseline.** For confirmed Node pids, unprotected env reads
  and file reads observed during startup are recorded as a baseline. Later
  unprotected repeats of those names/paths are filtered from package output.
  This removes runtime noise such as OpenSSL probes without using a static
  denylist that would hide a real package-specific secret read.
- **Package-manager client pids.** Unprotected env reads from the root npm,
  pnpm, or Yarn client process are filtered. Child lifecycle processes are not
  blanket-filtered; their own non-baseline env reads remain visible.

Protected env and file reads are never filtered by these rules. Writes,
unresolved relative paths, spawn/connect/dlopen events, and synthetic
audit-bypass events are also not filtered.

The startup boundary is visible in both channels. `env-spy.cjs` sets
`SCRIPT_JAIL_NODE_STARTUP_DONE`; the Rust shim consumes that assignment and
emits a trusted `node_startup_done` JSONL marker. `env-spy.cjs` also opens
`/tmp/script-jail-node-startup-done`; the file is expected not to exist, and
the failed `openat` provides a same-pid strace marker for file-read ordering.

### Cross-exec preservation

The shim wraps all eight exec entry points (`execve`, `execv`, `execvp`,
`execvpe`, `execveat`, `fexecve`, `posix_spawn`, `posix_spawnp`) via the same
`dispatch_exec` / `dispatch_spawn` funnels in `src/shim/src/lib.rs`. Before
forwarding to the real symbol, every wrapper rewrites the caller-supplied
`envp`:

- `LD_PRELOAD` is overwritten with the canonical shim path captured at
  `shim_init` time.
- `NODE_OPTIONS` is overwritten with the canonical `--require=...` block for
  the active JS preloads.
- `LD_AUDIT` and `LD_LIBRARY_PATH` are stripped completely.
- Seven `SCRIPT_JAIL_*` sticky vars (`SCRIPT_JAIL_LOG_FILE`,
  `SCRIPT_JAIL_LOG_FD`, `SCRIPT_JAIL_PROTECTED_ENV_NAMES`,
  `SCRIPT_JAIL_SPOOF_PLATFORM`, `SCRIPT_JAIL_SPOOF_ARCH`,
  `SCRIPT_JAIL_PRELOAD_PATH`, `SCRIPT_JAIL_NODE_OPTIONS`) are overwritten with
  their init-time canonical values. If a canonical value is empty, any
  caller-supplied entry for that sticky var is removed.

The canonical values for `LD_PRELOAD` and `NODE_OPTIONS` reinjection come from two env vars read at `shim_init` time: `SCRIPT_JAIL_PRELOAD_PATH` (set to `/lib/libscriptjail.so` by `buildChildEnv` in `src/guest/agent.ts`) and `SCRIPT_JAIL_NODE_OPTIONS` (set to the space-separated `--require=…` block for the active `/usr/local/lib/script-jail/*.cjs` preloads). This means every child process — however the parent constructs its `envp` — inherits a canonical audit environment.

The `setenv` / `unsetenv` / `putenv` / `clearenv` wrappers close the in-process mutation window. Any call that targets one of the audit-chain protected names (`LD_PRELOAD`, `NODE_OPTIONS`, `LD_AUDIT`, `LD_LIBRARY_PATH`, or any `SCRIPT_JAIL_*` sticky var) is silently refused: the wrapper returns 0 so the caller sees no error (Node's `delete process.env.X` path does not raise), but the underlying env entry is not modified. Refused calls are recorded in the audit log.

**Known gap.** `execle` is the one exec variant the shim does not wrap: its `char *const envp[]` is passed as a C variadic argument, and intercepting variadics in stable `#![no_std]` Rust requires inline asm or a nightly toolchain bump; deferred to v2. In glibc, `execl` and `execlp` build their argument vector and then call `execve` with the process's own `__environ`, so the setenv/unsetenv guards in this version close the practical-attack window for those two. Direct `char **environ` array manipulation (bypassing all libc env functions) remains uncovered; this is rare in npm lifecycle scripts.

## Agent protocol

The guest agent emits newline-delimited JSON frames. Firecracker carries those
frames over vsock; Docker and bare mode carry them over stdio. Two event
categories share the channel:

- `raw` events emitted incrementally during Phase B (one per audited syscall after the protected-paths filter).
- A single terminal `lockfile` frame with the rendered YAML, attribution summary, and exit status.

Firecracker keeps the strongest separation: no shared filesystem, no container
runtime, no Docker-in-Docker. Docker and bare mode trade isolation strength for
runner availability while keeping the same agent protocol and lockfile
pipeline.

## Rootfs

Built per Ubuntu runner image (`ubuntu-22.04`, `ubuntu-24.04`) and arch by `src/rootfs/build.ts`. The image is minimal: no `gcc`, no `python`, no `$HOME` contents, no credentials. It bakes the standalone `vp` (vite-plus) binary; the guest's `init.sh` (Firecracker) or Docker backend bootstrap runs `vp env install <pinned version>` during Phase A to download a real Linux Node toolchain into `/opt/vp`, then `corepack enable` for `pnpm`/`yarn`. Firecracker (and the macOS VZ helper) mounts three virtio drives at boot:

1. The rootfs itself.
2. An ext4 overlay holding the consumer repo + package-manager caches at
   `/work` (the pnpm store, yarn global folder, and npm cache are all
   redirected here — the rootfs and the tmpfs mounts are far too small for a
   real dependency graph).
3. An empty ext4 scratch disk (label `scratch`) mounted at `/scratch` for
   audit artifacts: the per-pid `strace -ff` logs and the events JSONL. These
   previously lived on the 64 MB `/tmp` tmpfs, which large installs overflow.
   When the disk is absent (Docker / bare backends), the guest agent falls
   back to `/tmp` via `SCRIPT_JAIL_SCRATCH_DIR`.

There is no host-Node drive: the toolchain is provisioned at runtime, so a macOS host (whose own `node` is a Mach-O binary) can still produce a Linux-guest lockfile. The exact Node version is pinned in `src/rootfs/vite-plus.ts` for byte-stable cross-host parity.

The pinned kernel (Linux 5.10.223 from AWS Firecracker CI) lives outside the rootfs and is downloaded by the host when the Firecracker backend is selected.

## Diff and modes

- `mode=check` (default) — generated lockfile is diffed against the committed `.script-jail.lock.yml`. Any non-canonical delta fails the action with a unified diff annotation.
- `mode=update` — generated lockfile is written in place. Used to regenerate after a legitimate dependency change.

`generated_at` and `manager_lockfile_sha256` change every run by design; the diff path canonicalizes them so they don't cause false positives. See `src/action/diff.ts`.

## Threat model and known gaps

### Same-UID audit-channel limitation

The audit events file (`SCRIPT_JAIL_LOG_FILE`) is owned and writable by the
same UID as the audited process. A malicious lifecycle script with that UID can:

1. Open the events file directly (bypassing the shim emit path) and append
   forged JSONL records. The `<EVENTS_FILE_FORGERY>` audit_bypass detector
   catches the canonical attack via strace openat cross-check, but a process
   already trusted by the detector (one that has libscriptjail.so mapped)
   can still write to the file from inside its address space.

2. Discover existing audit fds via `/proc/self/fd/N` and write directly to
   them, which strace's openat trace cannot detect.

3. Use `openat(dirfd, basename, ...)` or path aliases
   (`/tmp/foo/../events-dir/./events-<tag>.jsonl`) to open the file via
   spellings the path-equality detector may miss. (The strace parser now
   canonicalizes these; see commit 7a4a281. The per-run-random basename
   `events-<32-hex>.jsonl` minted in `createEventsFile` also feeds the
   Layer-1 basename safety net in `phase-install.ts`.)

4. Spoof the shim-trust signal by `open("/lib/libscriptjail.so", O_RDONLY)`
   without actually loading it. The forgery detector grants shim-trust to
   any pid that reads the .so file because we have no cheap kernel-side
   signal that ld.so actually mapped the segment. The truly unforgeable
   signal would be the kernel-side mmap of the .so as executable
   (`PROT_EXEC`), but tracing every `mmap` syscall is prohibitively
   expensive for an interactive install. A shim-emitted runtime event
   after init would be same-UID forgeable (see gap 1). The only
   complete fix is UID separation (see below).

These gaps are accepted in v1 because:
- Firecracker microVMs and Docker containers are single-use and discarded after install; bare mode uses a staged copy of the repo and deletes it after the run.
- Network is off during install (Phase B), so exfiltration is bounded.
- Strace observes process spawns and syscalls regardless of forged events.
- The audit_bypass gate is defense-in-depth, not the primary security guarantee.

A future v2 may add UID separation: run the audited process as a different
UID than the agent, so the events file is read-only to the audited process
and write-only to the shim's process group. This requires:
- A separate init step to create a sandboxed UID with no write access to
  agent-owned paths.
- The events file owned by the agent UID, group-owned by the shim's UID,
  mode 0640.
- The shim runs with setegid into the shim's UID for events-file writes.

Until then, the audit_bypass gate is best-effort detection of canonical
attacks (envp scrubbing, raw syscall exec, file unlink/truncate/rename,
mtime/ctime tamper). It is not a cryptographic integrity check.

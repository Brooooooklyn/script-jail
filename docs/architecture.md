# Architecture

## Host vs guest

The Action splits into two halves connected over a vsock socket:

- **Host** (`src/main.ts`, `src/action/`) — runs on the GitHub Actions runner. Detects the package manager, downloads/caches Firecracker + kernel + rootfs, builds an ext4 overlay containing the repo, boots the VM, brokers the vsock session, then diffs/renders the result.
- **Guest** (`src/guest/`) — runs inside the microVM. Reads `.script-jail.yml`, runs the install in two phases under `strace`, applies the protected-path policy, attributes events to packages and lifecycle stages, normalizes/renders the lockfile, and emits everything back over vsock.

The kernel boundary is load-bearing. A pure-JS sandbox can't catch libuv-backed env reads, `dlopen` for native addons, or `execve` of arbitrary binaries — those reach the kernel before any JS hook fires. Hence the microVM.

## Cross-host parity (macOS VZ)

The same audit runs in two places:

- **Linux CI** — the GitHub Action invocation. Boots Firecracker; the host
  half lives in `src/main.ts` + `src/action/firecracker/`.

- **macOS developer host** — the local CLI invocation
  (`pnpm exec script-jail …`). Boots Apple's Virtualization.framework via
  `objc2-virtualization`; the host half lives in `src/host-mac/` (Rust)
  driven by `src/cli/` (TypeScript). Requires macOS 14+.

Both halves share the same guest agent (`src/guest/`), the same vsock
protocol (`src/shared/vsock-protocol.ts`), and the same lockfile renderer
(`src/lock/`). The split is intentionally thin — only the VMM startup,
disk attachment, and console wiring differ.

The release pipeline (`release.yml`) ships per-platform artifacts under
one tag: the Linux runner consumes `rootfs-ubuntu-<major>.ext4` +
`libscriptjail.so` + the pinned upstream `vmlinux` from Firecracker CI;
the macOS CLI consumes `rootfs-ubuntu-<major>-arm64.ext4` +
`libscriptjail-arm64.so` + the hand-built `vmlinux-vz-{x86_64,arm64}` +
the `script-jail-vm-arm64-darwin` Mach-O binary. The manifest in
`src/action/artifact-manifest.ts` is platform-keyed
(`expected: { linux: {...}, darwin: {...} }`) so each consumer pins only
the SHAs it cares about.

A handful of cases produce byte-different lockfiles across the two
runners — see [docs/divergence.md](./divergence.md) for the catalogue and
the v2 mitigation path.

## Two-phase install

1. **Phase A — fetch.** Network on, no strace. Lets the package manager resolve the registry and populate its cache. Output of this phase is not audited.
2. **Phase B — install.** Network off (default route nulled, no DNS), strace attached. Every syscall the lifecycle scripts make is captured. `dlopen` and `execve` of disallowed binaries are blocked by the preloads/policy.

Phase B is the only phase whose events end up in the lockfile.

## Event pipeline

```
strace -ff output ──► strace-parser ──► raw events (JSONL)
                                            │
                          protected-paths filter ◄─── .script-jail.yml
                                            │
                                       attribution
                            (pid → pkg@version + lifecycle stage)
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

- `src/guest/strace-parser.ts` — parses `openat`, `connect`, `execve` strace lines.
- `src/guest/protected-paths.ts` — replaces values for protected paths/env-vars with `<HIDDEN>`; drops `ENOENT` probes for unprotected paths so the audit reflects intent, not noise.
- `src/guest/attribution.ts` + `proc-reader.ts` — walk `/proc/<pid>/status` PPid chain looking for an ancestor whose `environ` carries `npm_package_name` + a canonical `npm_lifecycle_event`. Results are cached per starting pid; `invalidate(pid)` drops the cache so a recycled pid re-walks `/proc`.
- `src/lock/normalize.ts` — drops reads inside the owning package's own directory; marks cross-package writes; coalesces duplicates.
- `src/lock/tokenize.ts` — substitutes `$PKG`, `$NODE_MODULES`, `$HOME`, `$REPO`, `$CACHE`, `$TMP` for absolute paths.
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
| Node `--require` JS | `src/guest/dlopen-block.cjs` | `process.dlopen` calls — blocks native addons before they map. |
| Node `--require` JS | `src/guest/platform-spoof.cjs` | spoofs `process.platform` / `process.arch` to flush out OS-conditioned attack branches. |

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

**libc layer — `src/shim/src/lib.rs`.** A `#![no_std]` Rust cdylib that wraps `getenv`, `secure_getenv`, and the deprecated `__secure_getenv` alias via `LD_PRELOAD`. Real symbols are resolved with `libc::dlsym(libc::RTLD_NEXT, …)` inside a `#[ctor::ctor]` constructor. A `pthread_key_create`-backed thread-local recursion guard suppresses re-entry when `dlsym` / `open` / `clock_gettime` internally call `getenv` — the key is created before any other syscall so the bypass path is available from the very first instruction of init. When the name is on the protected list the wrapper returns `NULL` to the caller; otherwise it forwards to the real implementation. A musl fallback substitutes `getenv` for absent `secure_getenv` (script-jail guests are never setuid, so the semantics match). If `pthread_key_create` itself fails (PTHREAD_KEYS_MAX exhausted, exceedingly rare), the constructor returns early with `INIT_DONE = false`, leaving every wrapper on a transparent passthrough path so the host process is never broken. Catches libuv, native addons, and any child process that inherits the preload. For Node processes launched with the script-jail preloads, unprotected runtime-startup probes are suppressed until `env-spy.cjs` finishes installing the `process.env` Proxy; protected names are still hidden and reported.

**JS layer — `src/guest/env-spy.cjs`.** Node parses `environ[]` once at startup into an in-memory map and serves every `process.env.X` read from there without re-entering libc, so the most common attacker pattern (`process.env.NPM_TOKEN`) is invisible to the libc shim. This preload (loaded via `NODE_OPTIONS=--require`) replaces `process.env` with a Proxy whose `get` / `has` / `ownKeys` / `getOwnPropertyDescriptor` traps emit the audit event and apply hiding. The Proxy is installed with `Object.defineProperty(process, 'env', { writable: false, configurable: false })` to prevent `delete process.env` from restoring the original. A `Symbol.for('script-jail.env-spy.installed')` sentinel makes the preload idempotent across nested invocations; `logFd` and the protected-name set are pre-resolved against the **original** `process.env` before the Proxy is installed so the audit path itself cannot recurse through it.

**Critical detail — the Proxy receiver.** In the `get` / `set` traps, forward via `Reflect.get(target, prop, target)` (and the equivalent for `set`), passing `target` — not the Proxy — as the receiver. `process.env` is a host-side `EnvironmentVariableNamespace` object whose accessors use `this` to find the underlying environment store. When the receiver is the Proxy, Node can't locate the store and reads silently return wrong values, which breaks `child_process.spawn` with no diagnostic. The equivalent member-access form (`target[prop]`) also works.

**Unified event shape.** Both layers emit JSONL to `SCRIPT_JAIL_LOG_FILE` (preferred) or `SCRIPT_JAIL_LOG_FD` (tests), one of three `kind`s:

- `env_read` — `{"kind":"env_read","name":...,"pid":...,"ts":...,"hidden":...}` emitted by every libc `getenv` / JS `process.env.X` read of a name on the protected list.
- `exec` — `{"kind":"exec","prog":...,"argv0":...,"pid":...,"ts":...,"envp_alloc_failed"?:...}` emitted by the shim's exec wrappers (`execve` / `execv*` / `execveat` / `fexecve` / `posix_spawn[p]`) before forwarding to the real symbol. The optional `envp_alloc_failed` flag fires when env re-injection couldn't allocate and the caller's `envp` was forwarded unmodified (the exec still proceeds; the audit trail records the degraded state).
- `env_tamper` — `{"kind":"env_tamper","op":"setenv|unsetenv|putenv|clearenv","name":...,"pid":...,"ts":...,"refused":true}` emitted by the in-process env-mutator wrappers when the target is one of the protected names. The call is refused (returns 0 to the caller) and the audit event records the attempt.

Writes are kept ≤ `PIPE_BUF` so they are atomic. Downstream, normalize dedupes, attribution maps `pid` → owning package + lifecycle stage, and the renderer emits one block per (package, event-kind) pair.

**Protected-list policy.** Both layers read the same list, sourced from `.script-jail.yml` and serialized to `SCRIPT_JAIL_PROTECTED_ENV_FILE` (one name per line; `#` for comments). Adding a new protected name only requires editing the config — both layers pick it up at process start.

### Node bootstrap file-read filtering

The install phase still traces Node bootstrap file reads with strace, but
filters unprotected reads out of the rendered lockfile until script-jail's JS
preloads are installed. This removes runtime file-read noise such as
`/etc/ssl/openssl.cnf` from package lifecycle blocks; the Rust shim applies the
same bootstrap boundary to unprotected OpenSSL env probes such as
`OPENSSL_ia32cap` / `OPENSSL_armcap`.

The boundary is deliberately strace-visible rather than a shim JSONL-only event:
`env-spy.cjs` opens `/tmp/script-jail-node-startup-done` after installing the
`process.env` Proxy. The file is expected not to exist; the failed `openat`
appears in the same per-pid strace stream as bootstrap file reads, so
`phase-install.ts` can drop only same-pid reads before that marker. Protected
path reads, writes, unresolved relative paths, spawn/connect/dlopen events, and
synthetic audit-bypass events are not filtered.

### Cross-exec preservation

The shim wraps all eight exec entry points (`execve`, `execv`, `execvp`, `execvpe`, `execveat`, `fexecve`, `posix_spawn`, `posix_spawnp`) via the same `dispatch_exec` / `dispatch_spawn` funnels in `src/shim/src/lib.rs`. Before forwarding to the real symbol, every wrapper rewrites the caller-supplied `envp`:

- `LD_PRELOAD` — the shim's own path is colon-appended, ensuring the child process loads `libscriptjail.so` even if the parent tried to remove it.
- `NODE_OPTIONS` — the `--require=…` block is space-appended so the three JS preloads are loaded in every Node child.
- Seven `SCRIPT_JAIL_*` sticky vars (`SCRIPT_JAIL_LOG_FILE`, `SCRIPT_JAIL_LOG_FD`, `SCRIPT_JAIL_PROTECTED_ENV_FILE`, `SCRIPT_JAIL_SPOOF_PLATFORM`, `SCRIPT_JAIL_SPOOF_ARCH`, `SCRIPT_JAIL_PRELOAD_PATH`, `SCRIPT_JAIL_NODE_OPTIONS`) — each is added to the rewritten `envp` only when absent (`ensure_env` semantics), preserving any value the caller deliberately reassigned for a side channel.

The canonical values for `LD_PRELOAD` and `NODE_OPTIONS` reinjection come from two env vars read at `shim_init` time: `SCRIPT_JAIL_PRELOAD_PATH` (set to `/lib/libscriptjail.so` by `buildChildEnv` in `src/guest/agent.ts`) and `SCRIPT_JAIL_NODE_OPTIONS` (set to the space-separated `--require=…` block for the three `/usr/local/lib/script-jail/*.cjs` preloads). This means every child process — however the parent constructs its `envp` — inherits a canonical audit environment.

The `setenv` / `unsetenv` / `putenv` / `clearenv` wrappers close the in-process mutation window. Any call that targets one of the nine protected names (`LD_PRELOAD`, `NODE_OPTIONS`, or any `SCRIPT_JAIL_*` sticky var) is silently refused: the wrapper returns 0 so the caller sees no error (Node's `delete process.env.X` path does not raise), but the underlying env entry is not modified. Refused calls are recorded in the audit log.

**Known gap.** `execle` is the one exec variant the shim does not wrap: its `char *const envp[]` is passed as a C variadic argument, and intercepting variadics in stable `#![no_std]` Rust requires inline asm or a nightly toolchain bump; deferred to v2. In glibc, `execl` and `execlp` build their argument vector and then call `execve` with the process's own `__environ`, so the setenv/unsetenv guards in this version close the practical-attack window for those two. Direct `char **environ` array manipulation (bypassing all libc env functions) remains uncovered; this is rare in npm lifecycle scripts.

## vsock protocol

The guest agent opens a vsock CID/port pair; the host listens. Stream is newline-delimited JSON. Two event categories share the channel:

- `raw` events emitted incrementally during Phase B (one per audited syscall after the protected-paths filter).
- A single terminal `lockfile` frame with the rendered YAML, attribution summary, and exit status.

No shared filesystem, no container runtime, no Docker-in-Docker.

## Rootfs

Built per Ubuntu runner image (`ubuntu-22.04`, `ubuntu-24.04`) and arch by `src/rootfs/build.ts`. The image is minimal: no `gcc`, no `python`, no `$HOME` contents, no credentials. It bakes the standalone `vp` (vite-plus) binary; the guest's `init.sh` runs `vp env install <pinned version>` during Phase A to download a real Linux Node toolchain into `/opt/vp`, then `corepack enable` for `pnpm`/`yarn`. Two virtio drives mount at boot:

1. The rootfs itself.
2. An ext4 overlay holding the consumer repo + caches at `/work`.

There is no host-Node drive: the toolchain is provisioned at runtime, so a macOS host (whose own `node` is a Mach-O binary) can still produce a Linux-guest lockfile. The exact Node version is pinned in `src/rootfs/vite-plus.ts` for byte-stable cross-host parity.

The pinned kernel (Linux 5.10.223 from AWS Firecracker CI) lives outside the rootfs and is downloaded by the host via the artifact manifest.

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
- The microVM is single-use and discarded after install.
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

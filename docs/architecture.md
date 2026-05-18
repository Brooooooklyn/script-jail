# Architecture

## Host vs guest

The Action splits into two halves connected over a vsock socket:

- **Host** (`src/main.ts`, `src/action/`) — runs on the GitHub Actions runner. Detects the package manager, downloads/caches Firecracker + kernel + rootfs, builds an ext4 overlay containing the repo, boots the VM, brokers the vsock session, then diffs/renders the result.
- **Guest** (`src/guest/`) — runs inside the microVM. Reads `.script-jail.yml`, runs the install in two phases under `strace`, applies the protected-path policy, attributes events to packages and lifecycle stages, normalizes/renders the lockfile, and emits everything back over vsock.

The kernel boundary is load-bearing. A pure-JS sandbox can't catch libuv-backed env reads, `dlopen` for native addons, or `execve` of arbitrary binaries — those reach the kernel before any JS hook fires. Hence the microVM.

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
- `src/guest/attribution.ts` + `proc-reader.ts` — map a pid to the owning package using `/proc/<pid>/cwd` and the discovered `node_modules` tree.
- `src/lock/normalize.ts` — drops reads inside the owning package's own directory; marks cross-package writes; coalesces duplicates.
- `src/lock/tokenize.ts` — substitutes `$PKG`, `$NODE_MODULES`, `$HOME`, `$REPO`, `$CACHE`, `$TMP` for absolute paths.
- `src/lock/render.ts` — emits canonical YAML.

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

Build path: `pnpm build` → `scripts/build.ts:buildShim` → `cargo build --release --manifest-path src/shim/Cargo.toml` → copy `src/shim/target/release/libscriptjail.so` → `images/libscriptjail.so` → rootfs Dockerfile copies into `/lib/libscriptjail.so`. On macOS dev hosts `buildShim` short-circuits with a warning.

### Env-read detection in detail

Env-var reads need both the libc shim and the JS preload because they sit on opposite sides of a one-shot copy.

**libc layer — `src/shim/src/lib.rs`.** A `#![no_std]` Rust cdylib that wraps `getenv`, `secure_getenv`, and the deprecated `__secure_getenv` alias via `LD_PRELOAD`. Real symbols are resolved with `libc::dlsym(libc::RTLD_NEXT, …)` inside a `#[ctor::ctor]` constructor. A `pthread_key_create`-backed thread-local recursion guard suppresses re-entry when `dlsym` / `open` / `clock_gettime` internally call `getenv` — the key is created before any other syscall so the bypass path is available from the very first instruction of init. When the name is on the protected list the wrapper returns `NULL` to the caller; otherwise it forwards to the real implementation. A musl fallback substitutes `getenv` for absent `secure_getenv` (script-jail guests are never setuid, so the semantics match). If `pthread_key_create` itself fails (PTHREAD_KEYS_MAX exhausted, exceedingly rare), the constructor returns early with `INIT_DONE = false`, leaving every wrapper on a transparent passthrough path so the host process is never broken. Catches Node startup, libuv, native addons, and any child process that inherits the preload.

**JS layer — `src/guest/env-spy.cjs`.** Node parses `environ[]` once at startup into an in-memory map and serves every `process.env.X` read from there without re-entering libc, so the most common attacker pattern (`process.env.NPM_TOKEN`) is invisible to the libc shim. This preload (loaded via `NODE_OPTIONS=--require`) replaces `process.env` with a Proxy whose `get` / `has` / `ownKeys` / `getOwnPropertyDescriptor` traps emit the audit event and apply hiding. The Proxy is installed with `Object.defineProperty(process, 'env', { writable: false, configurable: false })` to prevent `delete process.env` from restoring the original. A `Symbol.for('script-jail.env-spy.installed')` sentinel makes the preload idempotent across nested invocations; `logFd` and the protected-name set are pre-resolved against the **original** `process.env` before the Proxy is installed so the audit path itself cannot recurse through it.

**Critical detail — the Proxy receiver.** In the `get` / `set` traps, forward via `Reflect.get(target, prop, target)` (and the equivalent for `set`), passing `target` — not the Proxy — as the receiver. `process.env` is a host-side `EnvironmentVariableNamespace` object whose accessors use `this` to find the underlying environment store. When the receiver is the Proxy, Node can't locate the store and reads silently return wrong values, which breaks `child_process.spawn` with no diagnostic. The equivalent member-access form (`target[prop]`) also works.

**Unified event shape.** Both layers emit the same JSONL line — `{"kind":"env_read","name":...,"pid":...,"ts":...,"hidden":...}` — to `SCRIPT_JAIL_LOG_FILE` (preferred) or `SCRIPT_JAIL_LOG_FD` (tests). Writes are kept ≤ `PIPE_BUF` so they are atomic. Downstream, normalize dedupes, attribution maps `pid` → owning package + lifecycle stage, and the renderer emits one `env_read:` block per package.

**Protected-list policy.** Both layers read the same list, sourced from `.script-jail.yml` and serialized to `SCRIPT_JAIL_PROTECTED_ENV_FILE` (one name per line; `#` for comments). Adding a new protected name only requires editing the config — both layers pick it up at process start.

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

Built per Ubuntu runner image (`ubuntu-22.04`, `ubuntu-24.04`) by `src/rootfs/build.ts`. The image is minimal: no `gcc`, no `python`, no `$HOME` contents, no credentials. Three virtio drives mount at boot:

1. The rootfs itself (read-only).
2. An ext4 overlay holding the consumer repo + caches at `/work`.
3. The host's Node install at `/opt/host-node` — so the same Node binary the runner uses also runs inside the VM, without baking a Node version into the rootfs.

The pinned kernel (Linux 5.10.223 from AWS Firecracker CI) lives outside the rootfs and is downloaded by the host via the artifact manifest.

## Diff and modes

- `mode=check` (default) — generated lockfile is diffed against the committed `.script-jail.lock.yml`. Any non-canonical delta fails the action with a unified diff annotation.
- `mode=update` — generated lockfile is written in place. Used to regenerate after a legitimate dependency change.

`generated_at` and `manager_lockfile_sha256` change every run by design; the diff path canonicalizes them so they don't cause false positives. See `src/action/diff.ts`.

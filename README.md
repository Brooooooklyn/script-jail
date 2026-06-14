# script-jail

Backend-isolated audit of npm, pnpm, and Yarn lifecycle scripts. `script-jail`
turns dependency install behavior into a deterministic `.script-jail.lock.yml`
so suspicious file, env, process, native-addon, and network behavior is visible
in code review.

## What It Does

When `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` changes, the GitHub
Action re-runs the install through a Linux audit backend. `backend: auto` tries
Firecracker first, then Docker, then a bare Linux executor. Each backend runs
the same guest agent with `strace` plus the `LD_PRELOAD` shim and Node preloads.

The generated `.script-jail.lock.yml` records lifecycle-script reads and writes
outside the owning package directory, env-var reads, protected-secret accesses,
`execve`, audit-bypass attempts, legacy `dlopen` quarantine events, and blocked
network attempts. In `check` mode, any non-canonical lockfile diff fails the PR
with a unified diff.

## Status

Released. `script-jail` and its three platform packages are published to npm,
and each GitHub release carries the full artifact set. The Action and CLI
verify every downloaded rootfs, kernel, shim, and Docker image against the
hash manifest committed in `src/action/artifact-manifest.ts` before use.
Backends: Firecracker, Docker, and bare Linux in CI; a Virtualization.framework
VM (`vz`) and a native no-VM `bare` backend on macOS.

## GitHub Action

Use `check` mode on pull requests. Commit `.script-jail.lock.yml` when an
intentional dependency change alters the audit.

```yaml
name: script-jail

on:
  pull_request:
    paths:
      - package-lock.json
      - pnpm-lock.yaml
      - yarn.lock
      - .script-jail.yml
      - .script-jail.lock.yml

jobs:
  audit-install:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      - uses: Brooooooklyn/scriptjail@<pinned-tag>
        with:
          mode: check
          config: .script-jail.yml
          lock: .script-jail.lock.yml
          backend: auto
          spoof-platform: linux
          # Defaults to the runner CPU architecture when omitted.
          # spoof-arch: arm64
          cache-firecracker: "true"
```

`backend: auto` prefers Firecracker when Linux, `/dev/kvm`, and `tap0` are
available. On GitHub-hosted `ubuntu-24.04-arm`, KVM is unavailable, so the
parity workflow normally falls through to Docker.

## Drop-in Install

By default the Action only **audits** — it never installs dependencies on your
runner. Set `install: true` to make it a **drop-in replacement for your install
step**. It splits the install into two halves:

1. **On the runner, with lifecycle scripts disabled** — `npm ci`/`pnpm install
   --frozen-lockfile`/`yarn install --immutable` with `--ignore-scripts`
   (`--mode=skip-build` for yarn). This is always safe: no third-party code runs.
   It populates your real `node_modules`.
2. **In the sandbox** — the same install runs under the audit envelope and the
   generated lockfile is diffed against the committed `.script-jail.lock.yml`.
3. **On the runner, only if the audit matches** — the deferred lifecycle scripts
   run on the host, completing a usable `node_modules`. On any drift or
   audit-bypass the scripts are **never** run and the job fails.

```yaml
      - uses: Brooooooklyn/script-jail@<pinned-tag>
        with:
          mode: check          # required for install (see below)
          install: true
          # Extra package-manager install flags, applied to BOTH the host
          # install and the sandbox audit (so the lock can't drift):
          args: "--omit=dev"
```

Then your build steps can use `node_modules` directly — no second `install` step.

**Requirements & semantics**

- `install: true` requires `mode: check` **and** a committed `.script-jail.lock.yml`.
  Generate the lock once with `mode: update` (install off), commit it, then turn
  `install` on. `install` is rejected in `update` mode (update regenerates the
  lock and skips the bypass scan, so there is no fail-closed gate).
- On audit **drift or bypass**, the safe no-scripts `node_modules` is left in
  place but the lifecycle scripts are skipped and the job exits non-zero.
- `args` is split into discrete argv items (quote values that contain spaces)
  and passed to the package manager directly — never through a shell. Flags that
  would re-enable scripts in step 1 (`--no-ignore-scripts`, yarn `--mode`, …) are
  dropped with a warning.
- The Action **audits** your root project's `prepare` script in the sandbox but
  does **not run it on the runner** in step 3 (it runs only `rebuild`/`install
  --immutable`, which never invoke a root `prepare`). So `install: true` is a
  drop-in replacement for installing your **dependencies**, not a full build of
  your **own** package: if your root `prepare` generates build output (compiling
  `dist/`, etc.), run your build step separately afterwards. Any
  `network_attempts` the warning lists that originate from the root `prepare`
  pass will **not** fire on the runner.

> **Security note.** Step 3 runs the lifecycle scripts **on the runner with the
> network on** (real postinstalls fetch prebuilt binaries, so this is
> unavoidable). The sandbox audited them offline, so a `connect` recorded as
> `<BLOCKED>` in the lock **will succeed** on the runner. Trust comes from the
> committed lock being reviewed, not from host isolation: a matching audit means
> "behaviour is unchanged from the reviewed lock," not "safe to run online."
> Review the recorded reads/writes/spawns/connects before committing a lock. This
> is still strictly safer than an unaudited `install` step. Audit-only mode
> (`install` unset) keeps scripts entirely inside the sandbox.
>
> Before step 3 runs, if the matched lock recorded any `network_attempts`, the
> action emits a `::warning::` naming the count and the destinations those
> scripts will now reach online. The destinations are the **IP:port** the
> offline audit observed (`connect()` carries a resolved address, not a DNS
> name), so a fresh online resolve may hit a different address — treat the list
> as a heads-up, not an exact preview.

## Configuration

`.script-jail.yml` defines which files and env vars should be hidden from
lifecycle scripts and marked as protected in the lockfile:

```yaml
protected:
  files:
    - ~/.ssh/**
    - ~/.npmrc
    - $REPO/.env
    - $REPO/.env.*
  env:
    - NPM_TOKEN
    - NODE_AUTH_TOKEN
    - GITHUB_TOKEN

spoof:
  platform: linux
  arch: arm64
```

The Action inputs `spoof-platform` and `spoof-arch` override the config for
that run without modifying the file on disk.

## Lockfile Example

The generated `.script-jail.lock.yml` is grouped by package identity and
lifecycle stage. Empty lists are intentional: they keep the schema stable and
make newly observed behavior obvious in diffs. Two extra lists, `audit_bypass`
and `env_tamper`, appear only when populated — a clean run renders neither.

```yaml
schema_version: 1
manager: pnpm
manager_lockfile_sha256: "..."
node_version: 24.15.0
generated_at: 2026-05-28T08:00:00.000Z
packages:
  suspicious-install@1.2.3:
    lifecycle:
      postinstall:
        external_reads:
          - <HIDDEN> $HOME/.npmrc
          - $REPO/package.json
        escaped_writes:
          - <CROSS_PACKAGE> $NODE_MODULES/victim-package/package.json
          - $TMPDIR/<hash>/build.log
        env_read:
          - <HIDDEN> NPM_TOKEN
          - PATH
        spawn_attempts:
          - node postinstall.js
        spawn_blocked:
          - <ENOENT> gcc -c native.c
        dlopen_attempts: []
        network_attempts:
          - <BLOCKED> connect 198.51.100.7:443
```

## macOS CLI

On macOS 14 or newer, the CLI audits installs through one of two backends:

- `vz` (default on Apple Silicon) — boots the same Linux guest agent in a
  lightweight VM through Apple's Virtualization.framework.
- `bare` — runs natively with a Mach-O `DYLD_INSERT_LIBRARIES` shim and bundled
  bash/coreutils substitutes, no VM. Network activity is recorded but not
  blocked on this backend; SIP-protected tools that cannot be instrumented are
  marked `<AUDIT_BLIND>`.

```bash
pnpm exec script-jail init                  # create .script-jail.lock.yml
pnpm exec script-jail update                # overwrite .script-jail.lock.yml
pnpm exec script-jail check                 # diff against the committed lockfile
pnpm exec script-jail check --backend bare  # native audit, no VM
```

When no subcommand is provided, the CLI defaults to `init` if the lockfile does
not exist and `check` if it does. The runtime artifacts (VZ helper, VZ kernel,
rootfs, and the `.so`/`.dylib` shims) ship inside `@script-jail/darwin-arm64`;
a repo checkout resolves them from `images/` instead.

## Installation and packaging

The main `script-jail` npm package is JS-only: it ships `dist/cli.cjs`, the
guest agent (`dist/guest-agent.cjs`), the Node preloads, and this README — no
runtime artifacts. The platform-specific runtime payloads live in three
optional dependency packages, one per supported host:

- `@script-jail/darwin-arm64` — VZ helper (`script-jail-vm`), VZ kernel
  (`vmlinux-vz-arm64`), `libscriptjail-arm64.so`, a compressed Ubuntu 24.04
  arm64 rootfs, and the bare-backend binaries (`libscriptjail-arm64.dylib`,
  `bash-arm64`, `coreutils-arm64`).
- `@script-jail/linux-x64` — `libscriptjail.so` and a compressed Ubuntu 24.04
  x64 rootfs.
- `@script-jail/linux-arm64` — `libscriptjail-arm64.so` and a compressed Ubuntu
  24.04 arm64 rootfs.

Each optional package declares matching `os`/`cpu`, so `npx script-jail` (or any
install) automatically pulls only the `@script-jail/<os>-<arch>` that matches
the current host and skips the rest. Intel macOS (`darwin-x64`) is not
supported. In a repo checkout the CLI instead resolves these artifacts from
`images/` as a development fallback. On first run, the CLI expands the
compressed rootfs into a sparse cache under `~/Library/Caches/script-jail` on
macOS, or under `SCRIPT_JAIL_CACHE_DIR` (falling back to the system temp dir) on
Linux.

## How It Works

Install auditing is split into two phases. Phase A runs the package-manager
fetch with network enabled and no audit output. Phase B disables network and
runs lifecycle scripts under `strace`, the Rust `LD_PRELOAD` shim, and Node
preloads. The guest normalizes attributed events into a byte-stable YAML
lockfile. See [docs/design.md](./docs/design.md) for rationale and
[docs/architecture.md](./docs/architecture.md) for the control flow.

## Why Backend Isolation

A pure-JS install sandbox cannot close the important gaps: native addons and
`child_process` reach the kernel, libc/libuv env reads bypass a `process.env`
Proxy, and bun does not honor the Node preload model. Firecracker is the
strongest Linux isolation boundary; Docker and bare mode keep the same
syscall/preload audit available on runners without KVM.

## Docs

- [Design](./docs/design.md) - rationale, threat model, and tradeoffs.
- [Architecture](./docs/architecture.md) - host/guest split and audit pipeline.
- [Development](./docs/development.md) - build, release, and CI conventions.
- [Releasing](./docs/releasing.md) - first-release runbook and version-bump sequence.
- [Testing](./docs/testing.md) - Vitest projects, fixtures, and e2e workflows.
- [Divergence](./docs/divergence.md) - cross-host parity limits.
- [Parity testing](./docs/parity-testing.md) - Linux/macOS parity workflow.
- [N-API preload research](./docs/research/napi-preload-shared-state.md) -
  shared-state probe for a future trusted startup signal.

## License

MIT

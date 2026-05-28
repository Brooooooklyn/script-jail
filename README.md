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

Feature-complete pre-release. The Action, guest agent, backend abstraction,
Docker fallback, bare Linux executor, macOS Virtualization.framework CLI path,
lockfile renderer, and parity CI are implemented. The first public release
still needs real artifact-manifest SHAs and GHCR image digests in
`src/action/artifact-manifest.ts`; this repo's own CI uses
`SCRIPT_JAIL_E2E_SELF_TEST=1` while those release artifacts are bootstrapped.

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
make newly observed behavior obvious in diffs.

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

On macOS 14 or newer, the CLI runs the same Linux guest agent through Apple's
Virtualization.framework:

```bash
pnpm exec script-jail init     # create .script-jail.lock.yml
pnpm exec script-jail update   # overwrite .script-jail.lock.yml
pnpm exec script-jail check    # diff against the committed lockfile
```

When no subcommand is provided, the CLI defaults to `init` if the lockfile does
not exist and `check` if it does. The macOS path requires the VZ helper binary,
VZ kernel, per-arch rootfs, and `libscriptjail` release artifacts; in this repo
checkout those are produced by the release/build workflows and resolved from
`images/`.

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
- [Testing](./docs/testing.md) - Vitest projects, fixtures, and e2e workflows.
- [Divergence](./docs/divergence.md) - cross-host parity limits.
- [Parity testing](./docs/parity-testing.md) - Linux/macOS parity workflow.
- [N-API preload research](./docs/research/napi-preload-shared-state.md) -
  shared-state probe for a future trusted startup signal.

## License

MIT

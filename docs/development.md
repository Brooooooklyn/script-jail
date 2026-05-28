# Development

## Build pipeline

`pnpm build` runs `scripts/build.ts` (via `oxnode`) which:

1. Bundles `src/main.ts` to `dist/main.cjs` with esbuild (cjs target, node20).
2. Builds the Rust shim (`cargo build --release --manifest-path src/shim/Cargo.toml`) and copies `target/release/libscriptjail.so` → `images/libscriptjail.so` (skipped on macOS dev hosts; CI provides the Rust toolchain via `dtolnay/rust-toolchain@stable` pinned to match `rust-toolchain.toml`).
3. Optionally cross-compiles `images/libscriptjail-arm64.so` when `--shim-arm64` is passed.
4. Builds the per-runner-image rootfs when rootfs building is not skipped. The rootfs builder bundles `src/guest/agent.ts` to `dist/guest-agent.cjs` and copies `src/guest/*.cjs` preloads to `dist/preloads/` before building the Docker image and ext4.

For day-to-day host-side edits, `pnpm build:bundle` is enough (rebuilds only `dist/main.cjs`). CLI edits require `pnpm build:cli`; guest/preload edits require `pnpm build:guest-agent` or a rootfs build.

## The `dist/` invariant

`dist/` is committed. `test.yml` re-bundles in CI and fails if the result differs from what's checked in. After any `src/` change that affects shipped behaviour:

- Host changes → `pnpm build:bundle` (rebuilds `dist/main.cjs`).
- Guest or preload changes → `pnpm build` (rebuilds `dist/guest-agent.cjs` and `dist/preloads/`).
- CLI changes → `pnpm build:cli` (rebuilds `dist/cli.cjs`).
- Rootfs changes → `pnpm build --runner-image=ubuntu-XX.YY` per supported image; rootfs SHAs need updating in the artifact manifest (see release flow).
- Shim changes (`src/shim/src/lib.rs` or `src/shim/Cargo.toml`) → rebuild via `cargo build --release` (or `pnpm build`, which wraps it); the resulting `libscriptjail.so` is released alongside the rootfs.

Always include the rebuilt `dist/` files in the same commit as the source change.

## Common gotchas

- **Use `pnpm`, not `npm`/`yarn`.** The repo pins `packageManager` and `pnpm-lock.yaml`.
- **Use `oxnode` for `.ts` scripts, not `tsx`.** This is set globally; honour it inside `scripts/` and ad-hoc tooling.
- **`generated_at` and `manager_lockfile_sha256` are intentionally volatile.** Don't try to make them stable — `src/action/diff.ts` canonicalises them when comparing. Other fields must be byte-stable across runs on identical input.
- **Don't touch `dist/` by hand.** Always regenerate via the build commands. Hand-edited bundles will be overwritten on the next build and may fail the CI diff check.
- **Goldens are generated.** `test/fixtures/<scenario>/expected-events.json` comes from `scripts/build-e2e-golden.ts`. Hand-editing them is a process smell.
- **Phase B is offline.** Anything you add to Phase B must not require network access. The default route is removed before strace attaches.
- **Protected-path policy lives in three places.** The Rust shim filters libc `getenv` / `secure_getenv`; the JS preload filters JS `process.env` reads; `protected-paths.ts` filters strace-observed file reads. All three must agree on the policy from `.script-jail.yml`. Additionally, the exec and env-mutator wrappers in the shim consume two extra sticky vars — `SCRIPT_JAIL_PRELOAD_PATH` and `SCRIPT_JAIL_NODE_OPTIONS` — that are set by `buildChildEnv` in `src/guest/agent.ts`. These must stay in sync with the active preload locations on the rootfs (`/lib/libscriptjail.so`, `/usr/local/lib/script-jail/platform-spoof.cjs`, and `/usr/local/lib/script-jail/env-spy.cjs`). `dlopen-block.cjs` is a legacy optional quarantine preload and is not injected by default.
- **In `env-spy.cjs`, pass `target` (not the Proxy) as the receiver to `Reflect.get` / `Reflect.set`.** `process.env` is a host-side `EnvironmentVariableNamespace` whose accessors use `this` to find the underlying env store; using the Proxy as the receiver makes reads silently return wrong values and breaks `child_process.spawn` with no diagnostic. See [docs/architecture.md](./architecture.md#env-read-detection-in-detail) for the full reasoning.

## Release flow

Tagged releases (`release.yml`) bundle:

- `dist/main.cjs`, `dist/guest-agent.cjs`, `dist/cli.cjs`, and `dist/preloads/*.cjs`.
- `libscriptjail.so` and `libscriptjail-arm64.so` (Rust shim binaries; built with the toolchain pinned in `rust-toolchain.toml`).
- The per-runner-image Linux rootfs ext4 images for x64 and arm64.
- Firecracker/VZ kernel artifacts, including the VZ-specific kernel names consumed by the macOS helper.
- The Darwin arm64 `script-jail-vm` helper used by the macOS CLI backend.
- Digest-pinned Docker rootfs images in GHCR for each supported runner image and architecture.
- A manifest pinning Firecracker binaries, kernels, rootfs SHAs, Docker image refs, shim SHAs, and macOS helper artifacts.

When bumping any pinned artifact:

1. Rebuild the affected artifacts and let `release.yml` publish them.
2. Copy the release summary's URLs, SHAs, and Docker image refs into `src/action/artifact-manifest.ts`.
3. Run `scripts/validate-manifest.ts` to confirm hashes/image refs match.
4. Bump the version tag only after the manifest validates against the published assets.

The repo's own CI sets `SCRIPT_JAIL_E2E_SELF_TEST=1` to skip manifest validation (so the action under test isn't gated on the very artifacts it's building).

## CI overview

- `test.yml` — typecheck + unit/guest/integration/fake-e2e Vitest projects on matrix of Ubuntu 22.04/24.04 × Node 22/24/26; verifies `dist/main.cjs`, `dist/guest-agent.cjs`, and `dist/cli.cjs` are current.
- `e2e.yml` — boots real Firecracker VMs on Ubuntu 22.04/24.04; creates `tap0`, requires `/dev/kvm`, asserts attack markers, then verifies `mode=check` fails on tampered lockfiles.
- `parity-test.yml` — on parity-relevant PRs, runs the Action backend on `ubuntu-24.04-arm` (`backend: auto`, normally Docker on hosted arm runners) and hard-fails if the generated lockfile differs from the committed macOS/VZ arm64 baseline after parity-only filtering.
- `test-macos.yml` — builds/tests the macOS host helper and validates the config-error smoke fixture.
- `release.yml` — produces tagged artifacts per the manifest.

Failing CI almost always means one of: out-of-date `dist/`, a golden that needs regenerating, a missed canonicalization in the renderer, or a real audit-policy change that legitimately shifts a fixture's expected events.

# Development

## Build pipeline

`pnpm build` runs `scripts/build.ts` (via `oxnode`) which:

1. Bundles `src/main.ts` to `dist/main.cjs` with esbuild (cjs target, node20).
2. Bundles the guest agent (`src/guest/agent.ts` + entry) to `dist/guest-agent.cjs`.
3. Copies/compiles the preloads to `dist/preloads/*.cjs`.
4. Builds the Rust shim (`cargo build --release --manifest-path src/shim/Cargo.toml`) and copies `target/release/libscriptjail.so` → `images/libscriptjail.so` (skipped on macOS dev hosts; CI provides the Rust toolchain via `dtolnay/rust-toolchain@stable` pinned to match `rust-toolchain.toml`).
5. Optionally builds the per-runner-image rootfs when `--runner-image=ubuntu-22.04|ubuntu-24.04` is passed.

For day-to-day host-side edits, `pnpm build:bundle` is enough (rebuilds only `dist/main.cjs`).

## The `dist/` invariant

`dist/` is committed. `test.yml` re-bundles in CI and fails if the result differs from what's checked in. After any `src/` change that affects shipped behaviour:

- Host changes → `pnpm build:bundle` (rebuilds `dist/main.cjs`).
- Guest or preload changes → `pnpm build` (rebuilds `dist/guest-agent.cjs` and `dist/preloads/`).
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

- `dist/` JS artifacts.
- `libscriptjail.so` (Rust shim binary; built with the toolchain pinned in `rust-toolchain.toml`).
- The per-runner-image rootfs (ext4).
- A manifest pinning Firecracker, kernel, and rootfs SHAs.

When bumping any pinned artifact:

1. Update the URL/SHA in `src/action/artifact-manifest.ts`.
2. Run `scripts/validate-manifest.ts` to confirm hashes match.
3. Rebuild affected artifacts and let `release.yml` publish them.
4. Bump the version tag.

The repo's own CI sets `SCRIPT_JAIL_E2E_SELF_TEST=1` to skip manifest validation (so the action under test isn't gated on the very artifacts it's building).

## CI overview

- `test.yml` — typecheck + unit/guest/integration on matrix of Ubuntu 22.04/24.04 × Node 22/24; verifies `dist/main.cjs` is current.
- `e2e.yml` — boots real Firecracker VMs against the fixtures; asserts attack markers and check/update mode correctness.
- `release.yml` — produces tagged artifacts per the manifest.

Failing CI almost always means one of: out-of-date `dist/`, a golden that needs regenerating, a missed canonicalization in the renderer, or a real audit-policy change that legitimately shifts a fixture's expected events.

# script-jail

Firecracker-sandboxed audit of npm/pnpm/yarn lifecycle scripts, packaged as a GitHub Action. Lockfile changes trigger an install inside a minimal microVM; every read/write/env-read/dlopen/execve/connect that escapes a package's own directory is recorded into a deterministic, byte-stable `.script-jail.lock.yml`. The Action diffs the generated lock against the committed copy and fails the PR on mismatch.

For the user-facing description and motivation, see [README.md](./README.md).

## Stack

- TypeScript on Node 20+, ESM source compiled to CJS via esbuild.
- pnpm (pinned via `packageManager` field) — always use `pnpm`, never `npm` or `yarn`.
- Vitest with four projects (unit / guest / integration / e2e).
- Build runner: `oxnode` (do not use `tsx` or `ts-node`).
- Rust `LD_PRELOAD` shim (`#![no_std]` cdylib in `src/shim/`, pinned via `src/shim/rust-toolchain.toml`); built with `cargo build --release` and copied to `images/libscriptjail.so`.

## Repo layout

| Path | Role |
| --- | --- |
| `src/main.ts`, `src/action/` | Host-side: action entry, Firecracker lifecycle, lockfile diff, caching. |
| `src/guest/` | Guest-side agent that runs inside the VM (orchestrator, strace parser, preloads, emit, attribution). |
| `src/shim/` | Rust `LD_PRELOAD` shim (`#![no_std]` cdylib) that intercepts libc `getenv` / `secure_getenv` / `__secure_getenv`. |
| `src/lock/` | Event schema (zod), normalize, render, tokenize. |
| `src/rootfs/` | ext4 rootfs builder, per Ubuntu major (22.04 / 24.04). |
| `scripts/` | `build.ts`, `build-e2e-golden.ts`, manifest/artifact validators. |
| `test/` | unit/, guest/, integration/, e2e/, plus `fixtures/` (one dir per attack pattern). |
| `dist/` | Committed bundles: `main.cjs`, `guest-agent.cjs`, `preloads/*.cjs`. CI verifies they are up-to-date — **rebuild after any `src/` change before committing.** |
| `action.yml`, `.script-jail.yml` | Action surface and default consumer config. |

## Workflow commands

```bash
pnpm build            # full build (bundles + rootfs when --runner-image given)
pnpm build:bundle    # esbuild dist/main.cjs only (fastest)
pnpm typecheck       # tsc --noEmit
pnpm test            # unit + guest + integration (no VM)
pnpm test:guest      # guest-side modules only
pnpm test:integration
pnpm test:e2e        # boots a real Firecracker VM — needs /dev/kvm
pnpm cli             # oxnode src/cli/index.ts
```

`pnpm test` is the default loop. `pnpm test:e2e` requires Linux + `/dev/kvm` + tap networking and is intended for the `e2e.yml` workflow, not local dev.

## Important conventions

- **`dist/` is committed.** `test.yml` re-bundles and diffs; an out-of-date bundle fails CI. After meaningful `src/` edits run `pnpm build:bundle` (and `pnpm build` if guest/preloads changed).
- **Lockfile output is byte-stable.** `src/lock/render.ts` sorts keys by codepoint order and uses fixed indentation. Don't add fields or formatting that aren't reproducible across runs. `generated_at` and `manager_lockfile_sha256` are the only intentionally-volatile fields and are canonicalized in the diff path (see `src/action/diff.ts`).
- **Two-phase install.** Phase A fetches with network on and no strace; Phase B installs with network off and strace on. Treat them as separate concerns in `src/guest/`.
- **Three preloads compose, do not overlap.** `env-spy.cjs` audits JS `process.env` reads via a Proxy; `dlopen-block.cjs` blocks `process.dlopen` before native addons load; `platform-spoof.cjs` spoofs `process.platform` / `process.arch`. The Rust shim (`src/shim/src/lib.rs`) catches libc `getenv` calls that bypass Node. Adding new audit categories means picking the right layer.
- **Fixtures encode attack patterns.** Each `test/fixtures/<scenario>/` has a `package.json`, a lifecycle script, and `expected-events.json`. Regenerate goldens with `scripts/build-e2e-golden.ts`; do not hand-edit goldens.
- **Artifact manifest is pinned.** `src/action/artifact-manifest.ts` pins Firecracker, kernel, and rootfs SHAs. Bumping any artifact means updating the manifest and regenerating release artifacts via `release.yml`.

## Further reading

- [docs/architecture.md](./docs/architecture.md) — host/guest split, event pipeline, vsock protocol, two-phase install.
- [docs/testing.md](./docs/testing.md) — vitest projects, fixtures, e2e setup, goldens.
- [docs/development.md](./docs/development.md) — build pipeline, `dist/` invariant, common gotchas, release flow.

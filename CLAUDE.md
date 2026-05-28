# script-jail

Backend-isolated audit of npm/pnpm/yarn lifecycle scripts, packaged as a GitHub Action plus a macOS CLI. Lockfile changes trigger an install inside the selected Linux audit backend (Firecracker, Docker, or bare Linux; macOS uses Virtualization.framework locally). Reads/writes/env reads/spawns/connects/audit-bypass signals that escape normal package boundaries are recorded into a deterministic, byte-stable `.script-jail.lock.yml`. The Action diffs the generated lock against the committed copy and fails the PR on mismatch.

For the user-facing description and motivation, see [README.md](./README.md).

## Stack

- TypeScript on Node 20+, ESM source compiled to CJS via esbuild.
- pnpm (pinned via `packageManager` field) — always use `pnpm`, never `npm` or `yarn`.
- Vitest with four projects (unit / guest / integration / e2e).
- Build runner: `oxnode` (do not use `tsx` or `ts-node`).
- Rust `LD_PRELOAD` shim (`#![no_std]` cdylib in `src/shim/`, pinned via the root `rust-toolchain.toml`); built with `cargo build --release` and copied to `images/libscriptjail.so`.

## Repo layout

| Path | Role |
| --- | --- |
| `src/main.ts`, `src/action/` | Host-side: action entry, backend selection, Firecracker/Docker/bare launchers, lockfile diff, caching. |
| `src/guest/` | Guest-side agent that runs inside the selected backend (orchestrator, strace parser, preloads, emit, attribution). |
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
pnpm test            # all Vitest projects, including fake e2e (no real VM)
pnpm test:guest      # guest-side modules only
pnpm test:integration
pnpm test:e2e        # fake VM/vsock e2e harness; real Firecracker e2e is the workflow
pnpm cli             # oxnode src/cli/index.ts
```

`pnpm test` is the default loop. `pnpm test:e2e` uses the fake VM/vsock harness; privileged real Firecracker coverage is handled by `.github/workflows/e2e.yml`.

## Important conventions

- **`dist/` is committed.** `test.yml` re-bundles and diffs; an out-of-date bundle fails CI. After meaningful `src/` edits run `pnpm build:bundle` (and `pnpm build` if guest/preloads changed).
- **Lockfile output is byte-stable.** `src/lock/render.ts` sorts keys by codepoint order and uses fixed indentation. Don't add fields or formatting that aren't reproducible across runs. `generated_at` and `manager_lockfile_sha256` are the only intentionally-volatile fields and are canonicalized in the diff path (see `src/action/diff.ts`).
- **Two-phase install.** Phase A fetches with network on and no strace; Phase B installs with network off and strace on. Treat them as separate concerns in `src/guest/`.
- **Default preloads compose, do not quarantine native addons.** `env-spy.cjs` audits JS `process.env` reads via a Proxy; `platform-spoof.cjs` spoofs `process.platform` / `process.arch`; the Rust shim (`src/shim/src/lib.rs`) catches libc env reads, exec-family calls, and env tamper. `dlopen-block.cjs` is legacy optional quarantine coverage, not injected by default.
- **Fixtures encode attack patterns.** Each `test/fixtures/<scenario>/` has a `package.json`, a lifecycle script, and `expected-events.json`. Regenerate goldens with `scripts/build-e2e-golden.ts`; do not hand-edit goldens.
- **Artifact manifest is pinned.** `src/action/artifact-manifest.ts` pins release rootfs ext4s, shim binaries, VZ helper artifacts, and Docker image refs. Bumping any artifact means updating the manifest and regenerating release artifacts via `release.yml`.

## Further reading

- [docs/architecture.md](./docs/architecture.md) — host/guest split, event pipeline, vsock protocol, two-phase install.
- [docs/design.md](./docs/design.md) — rationale, threat model, and tradeoffs.
- [docs/testing.md](./docs/testing.md) — vitest projects, fixtures, e2e setup, goldens.
- [docs/development.md](./docs/development.md) — build pipeline, `dist/` invariant, common gotchas, release flow.

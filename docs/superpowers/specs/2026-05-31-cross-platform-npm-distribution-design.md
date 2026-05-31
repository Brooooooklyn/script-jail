# Design: cross-platform npm distribution for `script-jail` v0.1.0

- **Date:** 2026-05-31
- **Status:** Approved design, pending spec review → implementation plan
- **Scope:** Publish `script-jail` as a cross-platform npm CLI (macOS-arm64 + Linux-x64 + Linux-arm64) and execute the project's first npm + GitHub release.

## 1. Summary

Today `script-jail` ships two ways: a GitHub Action (Linux: Firecracker/Docker/bare) and a macOS-only npm CLI (Apple Virtualization.framework). The npm package (`package.json` v0.1.0) bundles **macOS-arm64-only** artifacts, and the CLI hard-rejects every non-macOS host (`src/cli/detect-host.ts:111`).

This project makes `npx script-jail` work on **Linux too**, by:
1. Lifting the CLI's macOS-only gate and wiring the Linux path to the **existing** Action backends (`firecracker → docker → bare`) through the shared core `src/shared/run-audit.ts`.
2. Distributing per-host runtime artifacts via **per-platform optional-dependency packages** (the esbuild/swc model).
3. Publishing a coordinated **big-bang v0.1.0** covering both platforms.
4. Making the rootfs build **byte-reproducible** so the Action's manifest two-tag bootstrap is sound.

The audit engine is **not** changing — this is distribution + host-detection + wiring + release plumbing.

## 2. Goals / non-goals

**Goals**
- `npm i -g script-jail` (or `npx`) runs the auditor on macOS-arm64, Linux-x64, Linux-arm64.
- Linux CLI uses full backend parity (`firecracker → docker → bare`).
- One coordinated v0.1.0 publish (main package + 3 platform packages) to npm `latest`.
- The first GitHub release + the Action's two-tag manifest bootstrap are executable and correct.

**Non-goals (explicit, deferred)**
- Intel macOS CLI (`@script-jail/darwin-x64`) — no VZ helper is built for Intel today; the CLI errors clearly on Intel mac.
- Shipping the 22.04 rootfs in npm packages — the CLI defaults to 24.04; 22.04 stays Action-only.
- Bundling the Firecracker binary/kernel for fully-offline Firecracker (it keeps using the pinned upstream download).
- Any change to the audit/observation pipeline, lock schema, or guest agent behavior.

## 3. Locked decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Linux delivery | **Cross-platform npm CLI** | `npx script-jail` works on Linux, not just the Action. |
| D2 | Linux backend(s) | **Full parity: firecracker → docker → bare** | Reuse the Action's `runSelectedBackend`; no new audit logic. |
| D3 | Artifact distribution | **Per-platform optional-dependency packages** | npm installs only the matching `@script-jail/<os>-<arch>`; offline after install. |
| D4 | Sequencing | **Big-bang at v0.1.0** | Both platforms shipped together on first publish. |
| D5 | Manifest bootstrap | **R1: make rootfs reproducible** | Keep the two-tag bootstrap; fix the latent reproducibility gap it assumes. |
| D6 | Linux Docker on v0.1.0 | **Pull-by-tag fallback w/ warning when manifest digest is placeholder** | GHCR images are pushed at v0.1.0; lets Linux-Docker work day one without waiting for backfill. (Recommendation — see §10 open item O1.) |

## 4. Architecture

### 4.1 Package topology

A tiny main package whose `optionalDependencies` pull exactly one platform package, selected by npm via `os`/`cpu`:

| Package | `os` / `cpu` | Ships |
|---|---|---|
| **`script-jail`** (main) | — | `dist/cli.cjs`, `dist/guest-agent.cjs`, `dist/preloads/*.cjs`, `README.md`; `optionalDependencies` pinned to `=0.1.0` |
| **`@script-jail/darwin-arm64`** | darwin / arm64 | `rootfs-ubuntu-24.04-arm64.ext4.gz`, `vmlinux-vz-arm64`, `libscriptjail-arm64.so`, `script-jail-vm` (VZ helper, mode `0755`) |
| **`@script-jail/linux-x64`** | linux / x64 | `rootfs-ubuntu-24.04.ext4.gz`, `libscriptjail.so` |
| **`@script-jail/linux-arm64`** | linux / arm64 | `rootfs-ubuntu-24.04-arm64.ext4.gz`, `libscriptjail-arm64.so` |

Notes:
- Guest-agent + preload JS is platform-independent → lives once in the main package (used by Linux `bare` mode, which runs the agent as host Node).
- The **Firecracker binary + kernel** are *not* bundled. They keep using the existing pinned upstream download (`src/action/firecracker/download.ts`): the binary from `github.com/firecracker-microvm/firecracker` (v1.8.0, SHA-pinned) and the kernel `vmlinux-5.10.223` from the Firecracker CI S3 bucket (SHA-pinned). So Firecracker mode needs network on first use; bundling is a deferred follow-up.
- The **Docker** backend pulls the GHCR rootfs image; nothing is bundled for it.

### 4.2 CLI runtime (`src/cli/`)

- **`detect-host.ts` → `detect-platform.ts`:** generalize the detector to return `{ os: 'darwin' | 'linux', arch: 'x64' | 'arm64', macosMajor? }`. Keep the macOS-14 (Darwin 23) floor; accept Linux x64/arm64. Compute the platform-package name `@script-jail/${os}-${arch}`. Intel mac (darwin/x64) stays rejected with a clear message (no VZ helper).
- **`index.ts`:** branch on `os`.
  - *darwin* → today's VZ `launch` closure (unchanged): `spawnVm` + `runAudit({ launch, baseRootfsPath })`.
  - *linux* → construct the **same backend map `src/main.ts:180-199` builds** (`createFirecrackerBackend` / `createDockerBackend` / `createBareBackend`) and call `runAudit({ execute: runSelectedBackend({ requested: 'auto', backends, ... }) })`. The backend `ctx` needs `imagesDir` (a CLI cache dir), `runnerImage` (default `ubuntu-24.04`), `arch`, `manifest: PINNED_MANIFEST`, `http: NodeHttpClient`, `selfTest: false`.
- **Artifact resolution (`src/shared/artifacts.ts`):** add a resolver that locates the installed platform package via `createRequire(import.meta.url).resolve('@script-jail/<os>-<arch>/package.json')`, with a fallback to the dev-checkout `images/` dir (current behavior). `resolveArtifacts` keeps returning absolute paths; `rootfs-cache.ts` continues to sparse-expand the `.ext4.gz` on first run for every platform.
- **CLI-injected `preFetchArtifacts` for Linux FC/bare:** instead of downloading the rootfs/shim from the GitHub release (the Action behavior), the CLI injects a `preFetchArtifacts` that **uses the local platform-package files** (the factories already accept `preFetchArtifacts` as a seam — `src/main.ts:182,196`). Firecracker binary + kernel still come from `ensureBinaries` (upstream, pinned-SHA, cached in the CLI cache dir).
- **Docker on the CLI:** `resolveDockerImage` (`src/action/backend/docker.ts:189-203`) is digest-only today and throws `BackendUnavailable` on a placeholder. Per **D6**, add a CLI-only pull-by-tag fallback (`ghcr.io/<owner>/script-jail-rootfs:ubuntu-24.04`) with a "not digest-pinned" warning when the manifest digest is still a placeholder. (Open item O1.)
- **Friendly errors:** if the optional dep is missing (`--no-optional`, unsupported platform) → a clear message naming the expected `@script-jail/<os>-<arch>` package.
- **No `validateManifest` in the CLI path:** unlike `src/main.ts:121`, the CLI must **not** call `validateManifest(PINNED_MANIFEST)`. This is deliberate and load-bearing: it's why the CLI works on v0.1.0 while the Action does not (§6). The manifest is consulted only by the Docker backend for image digests (D6/O1); the FC/bare rootfs comes from the platform package via the injected `preFetchArtifacts`, never the manifest.

### 4.3 Per-platform packages + release pipeline

- **`scripts/assemble-npm-packages.mjs` (new):** for each of the 4 packages, create a staging dir, write its `package.json` (name, `version` = tag, `os`/`cpu`, `files`), and gzip/copy the right artifacts in. Driven from the release `publish` job.
- **`scripts/assert-npm-packlist.mjs` (generalize):** today it validates only the single mac-bundled set. Make it validate **each** package's packed file list, size ceiling, and the `0755` bit on the VZ helper.
- **`package.json` (main):** rewrite `files` to `[dist/cli.cjs, dist/guest-agent.cjs, dist/preloads/*.cjs, README.md]`; add `optionalDependencies` (`@script-jail/darwin-arm64`, `@script-jail/linux-x64`, `@script-jail/linux-arm64` = `0.1.0`). Remove the mac artifacts from the main `files` (they move to `@script-jail/darwin-arm64`).
- **`release.yml` publish order:** publish **platform packages first, then the main package** (so `optionalDependencies` resolve at install time). Each `npm publish --provenance --access public`. The version==tag gate (`release.yml:558-561`) stays and applies to every package.

### 4.4 R1 — reproducible rootfs (`src/rootfs/`)

The two-tag manifest bootstrap (§7) requires that a rebuild of the rootfs produces the **same** SHA-256 it pinned. Today `makeExt4Native` (`src/rootfs/build.ts:723-730`) runs `mkfs.ext4` with no fixed UUID/hash-seed/timestamps → every build differs. R1 makes it deterministic:
- `mkfs.ext4 -U <fixed-uuid> -E hash_seed=<fixed-uuid>` (stable filesystem UUID + directory hash seed).
- Export `SOURCE_DATE_EPOCH` (honored by e2fsprogs ≥ 1.45 for superblock/inode timestamps); apply the same to `makeExt4ViaDocker` (`build.ts:745-760`).
- Deterministic file mtimes in the `docker export` tree (e.g. normalize mtimes before `mkfs -d`), and confirm the Docker base is digest-pinned so the exported filesystem contents are stable.
- **CI guard:** add a "build twice, compare SHA-256" check (a workflow step or test) so a future regression that reintroduces nondeterminism fails loudly rather than silently breaking the next release's manifest gate.

R1 is **Action-only** (the npm CLI is manifest-independent) and is not on the npm critical path, but it must land **before the v0.1.1 manifest backfill**.

## 5. Control flow — CLI on Linux (new path)

```
detect-platform() → { os: 'linux', arch }
  └─ resolve @script-jail/linux-<arch> install dir → rootfs.ext4.gz + libscriptjail.so
  └─ ensureRootfs() sparse-gunzips rootfs.ext4.gz → cache dir (rootfs-cache.ts)
  └─ build backend map { firecracker, docker, bare } (same as src/main.ts)
  └─ runAudit({ execute: runSelectedBackend({ requested:'auto', backends, ctx }) })
        firecracker: gate on /dev/kvm + tap0; rootfs from package; fc binary+kernel from ensureBinaries (upstream)
        docker:      pull GHCR image (digest from manifest, else tag fallback + warning [D6])
        bare:        unshare -n + strace; shim+agent from package/main
  └─ mode=update → write .script-jail.lock.yml ; mode=check → diff + audit-bypass gate
```

macOS path is unchanged (VZ `launch` closure).

## 6. What works vs degraded on v0.1.0

- ✅ **npm CLI, macOS-arm64** — VZ path; artifacts bundled in `@script-jail/darwin-arm64`; manifest-independent.
- ✅ **npm CLI, Linux `bare`** — shim + guest-agent from packages; manifest-independent.
- ✅ **npm CLI, Linux `firecracker`** — rootfs/shim from package; fc binary+kernel from upstream; works where `/dev/kvm` + a root-created `tap0` exist (KVM CI boxes), else `auto` falls through.
- ⚠️ **npm CLI, Linux `docker`** — needs a GHCR digest; placeholder on v0.1.0. With D6 pull-by-tag fallback → works day one (warned); without it → works at v0.1.1.
- ❌ **GitHub Action (external consumers)** — non-functional on v0.1.0: the placeholder manifest hard-fails `validateManifest` (`src/main.ts:121`) at startup for *all* Linux backends. Recovers at v0.1.1 after backfill (§7). This is expected/documented (`release.yml:15-20`).

## 7. First-release ordering (runbook)

### Phase 0 — pre-tag (one-time)
1. npm: own the unscoped name `script-jail`; create the `@script-jail` org/scope; set `NPM_TOKEN` (or OIDC trusted-publisher) with publish rights to **both**.
2. Land workstreams #1–#3 (Linux CLI, packaging/release, R1). Confirm `PINNED_MANIFEST.repo` = `Brooooooklyn/scriptjail`, `tag = 'v0.1.0'`, SHAs left as `PLACEHOLDER_SHA256_*`.
3. Rebuild & commit all bundles (`pnpm build:bundle && build:guest-agent && build:cli`); `package.json` version == `0.1.0` (and every platform package's version == `0.1.0`).
4. Green on the exact commit being tagged: **`test.yml`** (incl. `dist/*.cjs` freshness — release.yml does *not* re-check drift), **`e2e.yml`** (real Firecracker), **`test-macos.yml`** (Rust VZ helper). `parity-test.yml` if parity surface changed.

### Phase 1 — tag `v0.1.0`
5. Push `v0.1.0`. `release.yml`: `build-mac-bin` → `build` (validate-manifest bootstrap-aware warns; typecheck/test; bundle main+cli; shim x64+arm64; 4 rootfs; 2 VZ kernels; Compute SHAs) → `publish`.
6. Publish-job side-effect order (all after the verify gates): **GHCR push (4 images) → stage+packlist → GitHub release upload → npm publish**. npm publish order = **platform packages first, then `script-jail`**.
7. `npm publish` is the **only non-re-runnable step** (it's last — good). GHCR push and gh-release upload are safely re-runnable for the same tag. If npm publish fails partway, a re-run is the correct recovery; if a *later* problem is found after npm succeeded, recover by bumping the version (you cannot republish `@0.1.0`).
8. Outcome: npm CLI live for both platforms (§6); Action not yet consumer-functional.

### Phase 2 — backfill → tag `v0.1.1`
9. From the v0.1.0 job summaries, paste the 9 file SHAs (`expected.linux` + `expected.darwin`) and the 4 Docker digests (`dockerImages.{x64,arm64}`) into `src/action/artifact-manifest.ts`; set `tag: 'v0.1.1'`. (`check-publish-artifacts.sh` rejects a *mixed* placeholder+real manifest — backfill all-or-nothing.)
10. Bump versions to `0.1.1`; `pnpm build:bundle` (re-embed the manifest into `dist/main.cjs`); commit; green CI; push `v0.1.1`.
11. Because R1 makes the rootfs reproducible, the v0.1.1 build reproduces v0.1.0's SHAs and `check-publish-artifacts.sh`'s strict path passes. After v0.1.1, the Action's Firecracker/bare (release-downloaded rootfs) + Docker (digest-pinned GHCR) all resolve for consumers.

## 8. Testing strategy

- **Unit:** `detect-platform` (linux/darwin × x64/arm64 matrices, macOS-14 floor, Intel-mac rejection); artifact resolution (installed-dep path + dev fallback + missing-dep error); Linux backend-map construction (inject fakes like the existing e2e harness does for the Action).
- **Packaging:** dry-run `assemble-npm-packages.mjs` + generalized `assert-npm-packlist.mjs` over all 4 packages in CI before publish (exact file list, size cap, `0755` bit).
- **Reproducibility (R1):** CI "build rootfs twice, assert identical SHA-256".
- **E2E:** reuse the fake-VM harness; add a CLI-on-Linux smoke asserting the backend map is built and `runAudit` is invoked with `execute` (no real VM). Real Firecracker stays in `e2e.yml`.
- **Invariant:** `dist/*.cjs` rebuilt & committed (the `test.yml` drift gate) after any `src/` change.

## 9. Risks

- **R1 completeness:** full ext4 reproducibility is finicky (UUID, hash seed, timestamps, export ordering). The "build-twice" CI guard is the backstop; if it can't be made green, fall back to the R2 self-pinning-manifest redesign (rejected for now).
- **npm publish ordering / atomicity:** publishing N packages is not transactional. If a platform package publishes but the main package fails, installs could resolve a partial set. Mitigation: publish platform packages first; the main package last; on failure, re-run only the unpublished packages (already-published versions can't be re-pushed → bump if a published one is wrong).
- **Firecracker on a dev laptop:** needs `/dev/kvm` + a root-created `tap0`; the CLI can't self-configure networking. Documented as a host prerequisite; `auto` gracefully falls through to docker/bare.
- **Scope creep:** four workstreams in one spec/plan. Implementation should still land them in the dependency order #1 → #2 → (#3 parallel) → #4.

## 10. Open items

- **O1 (D6):** confirm the Linux-Docker **pull-by-tag fallback** for v0.1.0 (recommended) vs. requiring the digest (Docker works only at v0.1.1). Affects one branch in `docker.ts` + a warning.
- **O2:** confirm npm name `script-jail` and scope `@script-jail` are owned/available before tagging (external, can't verify from the repo).

## 11. File-level change list (appendix)

**Workstream #1 — Linux CLI**
- `src/cli/detect-host.ts` → `src/cli/detect-platform.ts`: generalize to `{os,arch,macosMajor?}`; add Linux; keep mac floor; package-name helper.
- `src/cli/index.ts`: linux branch builds backend map + `runAudit({execute})`; keep darwin VZ path.
- `src/shared/artifacts.ts`: resolve from installed `@script-jail/<os>-<arch>` (createRequire) with dev `images/` fallback; add Linux artifact names.
- `src/action/backend/docker.ts`: CLI pull-by-tag fallback for placeholder digest (O1/D6).
- New CLI-injected `preFetchArtifacts` (local-artifacts) wired into the linux backend ctx.
- Tests: `test/cli/detect-platform.test.ts`, artifact-resolution tests, linux backend-map smoke.

**Workstream #2 — Packaging + release**
- `package.json`: `files` rewrite + `optionalDependencies` + (main has no `os`/`cpu`).
- `scripts/assemble-npm-packages.mjs` (new).
- `scripts/assert-npm-packlist.mjs`: per-package generalization.
- `.github/workflows/release.yml`: assemble + publish 3 platform packages before the main package.

**Workstream #3 — R1 reproducible rootfs**
- `src/rootfs/build.ts`: deterministic `mkfs.ext4` (`-U`, `hash_seed`, `SOURCE_DATE_EPOCH`) in `makeExt4Native` + `makeExt4ViaDocker`; deterministic export mtimes.
- `src/rootfs/Dockerfile.base`: ensure digest-pinned base / deterministic contents as needed.
- CI: "build rootfs twice, compare SHA" guard.

**Workstream #4 — First-release runbook**
- `docs/development.md` (or a new `docs/releasing.md`): the Phase 0→1→2 runbook from §7.

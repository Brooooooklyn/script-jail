<!-- Implementation plan generated 2026-05-31 from the cross-platform npm distribution spec.
     Source spec: docs/superpowers/specs/2026-05-31-cross-platform-npm-distribution-design.md -->

# Cross-Platform npm Distribution — Sequenced Implementation Plan

Synthesized from four workstream plans (Linux CLI, Packaging/Release, Reproducible rootfs, First-release runbook), with all HIGH/MEDIUM adversarial-review fixes folded in. Spec: `docs/superpowers/specs/2026-05-31-cross-platform-npm-distribution-design.md`.

---

## Branching & dist invariant (read first)

1. Branch off a clean `main`: `git switch -c feat/cross-platform-npm-dist`. Do not commit on `main`.
2. **`dist/` is committed and gated.** `test.yml` re-bundles and diffs; an out-of-date `dist/cli.cjs` (or `dist/main.cjs`) fails CI. After any `src/` edit, rebuild the affected bundle before committing:
   - `pnpm build:cli` after `src/cli/**` or `src/shared/**` or `src/action/backend/docker.ts` edits → regenerates `dist/cli.cjs`.
   - `pnpm build:bundle` after edits that flow into `dist/main.cjs` (e.g. `docker.ts`, `artifact-manifest.ts`).
   - `src/rootfs/**` edits do not change any committed bundle (build-time only).
3. **Lockfile output is byte-stable** — do not add non-reproducible fields. Not touched by this work but keep `pnpm test` green.
4. Run `pnpm typecheck && pnpm test` before every commit. Commit `dist/*.cjs` in the **same** commit as the `src/` change that produced it.
5. Note: the working tree already has `M dist/cli.cjs`, `M src/cli/index.ts`, `M src/shared/artifacts.ts`, `M .github/workflows/release.yml`, `M docs/development.md`, `M README.md`, `M package.json`, plus untracked `scripts/assert-npm-packlist.mjs`, `src/cli/rootfs-cache.ts`, `test/cli/rootfs-cache.test.ts`. **Verified correction (WS2 reviewer):** `package.json` does **not** yet have `optionalDependencies` and its `files` still lists the mac artifacts (`package.json:9-12`). Treat the installed-platform-package path as not-yet-real; all WS1 unit tests for it use an injected fake `require`, and the only working resolution path until WS2 publishes is the dev `images/` fallback.

### Ownership of shared files (conflict resolution)

| File | Owner | Other touchers | Strategy |
| --- | --- | --- | --- |
| `.github/workflows/release.yml` | **WS2** owns the `publish` job (assemble + per-package packlist + platform-first publish). **WS3** owns one new step in the `build` job (rootfs determinism guard). | WS4 only *describes* it. | Different jobs → logically independent. Land WS3's `build`-job step and WS2's `publish`-job rewrite as separate commits; if textually adjacent, WS2 rebases on WS3. WS4's runbook references the **target** step names WS2 produces. |
| `package.json` | **WS2** owns `files` + `optionalDependencies` (PKG-4, authoritative source). | WS1 reads `platformPackageName()`; WS2 derives the staged main manifest from it. | PKG-4 lands before WS1's index.ts wiring uses the names; regenerate `pnpm-lock.yaml` in the same commit as PKG-4. |
| `src/shared/artifacts.ts` | **WS1** owns the resolver + `imagesDir` override + optional `repoRoot`. | WS2's `scripts/npm-packages.mjs` filenames must equal what the resolver looks up. | Single filename contract enforced by a binding test (Phase 4, Task 4.1). |
| `src/action/backend/docker.ts` | **WS1** owns `resolveDockerImageRef` + `allowTagFallback`. | Shared with the Action (`src/main.ts:194`). | `allowTagFallback` defaults **false** → Action byte-unchanged. |
| `docs/development.md`, `README.md` | **WS2** owns the packaging-topology prose rewrite (PKG-6). **WS4** owns the runbook link + non-contradiction edits (W4-T3). | — | WS2 rewrites obsolete single-package prose first; WS4 adds links last. |

---

## Phase 1 — Linux CLI runtime (WS1)

Goal: `npx script-jail` runs on Linux x64/arm64 by reusing the Action's firecracker→docker→bare backends through `runAudit({execute})`, never calling `validateManifest`. macOS VZ path stays byte-for-byte unchanged.

### Task 1.1 — Generalize host detection into `detect-platform.ts`

- **Files:** `src/cli/detect-platform.ts` (new), `src/cli/detect-host.ts`, `test/cli/detect-platform.test.ts` (new), `test/cli/detect-host.test.ts`.
- **Change:** Create `detectPlatform(input?): DetectedPlatform` where `DetectedPlatform = { os: 'darwin'|'linux'; arch: 'x64'|'arm64'; macosMajor?: number }`, keeping injection seams (`platform`/`release`/`arch`). Logic:
  - `darwin`: keep the exact Sonoma-floor logic (`darwinMajor = parseInt(release.split('.')[0]); macosMajor = darwinMajor - 9`; throw `UnsupportedMacOSError` if `<14` or `NaN`) **and** reject `darwin/x64` with a new typed error (message names `darwin-x64` / VZ / not supported). Return `{os:'darwin', arch:'arm64', macosMajor}`.
  - `linux`: accept `x64`/`arm64` (else `UnsupportedArchError`); return `{os:'linux', arch}`.
  - other: throw a generalized `NotSupportedPlatformError` whose message still names the GitHub Action.
  - Re-export `NotMacOSError`, `UnsupportedMacOSError`, `UnsupportedArchError`, `MIN_MACOS_MAJOR=14`; add `platformPackageName(p) => '@script-jail/${os}-${arch}'`.
- **HIGH fix (WS1 reviewer #1) — resolve the darwin/x64 contradiction:** The current `detect-host.ts` **accepts** `darwin/x64` and `test/cli/detect-host.test.ts:21-24` asserts `{macosMajor:14, hostArch:'x64'}`. You cannot both introduce the Intel-mac rejection and keep that test green via a delegating shim. **Decision: migrate fully in this task.** Make `detect-host.ts` a thin compat shim whose `detectHost` does NOT delegate the arch gate (it keeps returning `{macosMajor, hostArch}` for darwin including x64, used only by untouched callers until Task 1.4), OR — preferred — delete the darwin/x64 acceptance: in the **same task**, edit `test/cli/detect-host.test.ts:21-24` to drop/redirect that assertion and have the shim's `detectHost` throw on `darwin/x64`. Pick the delete-and-redirect path so there is exactly one darwin/x64 behavior. Keep `detect-host.ts` exporting the legacy error classes + a `detectHost` adapter that returns `{macosMajor, hostArch:arch}` for the macOS-arm64 case so the existing `index.test.ts` injection (`detectHost: () => ({macosMajor:14, hostArch:'arm64'})`, `test/cli/index.test.ts:67`) keeps compiling until Task 1.4 migrates index.ts.
- **Tests first (`test/cli/detect-platform.test.ts`):**
  - `detectPlatform({platform:'darwin',release:'23.6.0',arch:'arm64'})` → `{os:'darwin',arch:'arm64',macosMajor:14}`
  - `{release:'24.1.0'}` → `macosMajor:15`; `{release:'22.0.0'}` throws `UnsupportedMacOSError`
  - `{platform:'darwin',release:'23.0.0',arch:'x64'}` throws Intel-mac rejection (message mentions `darwin-x64`/VZ/not supported)
  - `{platform:'linux',arch:'x64'}` → `{os:'linux',arch:'x64'}` (no `macosMajor`); `arch:'arm64'` likewise; `arch:'ia32'` throws `UnsupportedArchError`
  - `{platform:'win32',...}` throws and message references the GitHub Action
  - `platformPackageName` for `linux-x64`, `linux-arm64`, `darwin-arm64`
  - Update `test/cli/detect-host.test.ts:21-24` so the darwin/x64 case now reflects the shim's chosen behavior (removed or throws), not the old acceptance.
- **Verify:** `pnpm test -- test/cli/detect-platform.test.ts test/cli/detect-host.test.ts && pnpm typecheck`

### Task 1.2 — Platform-package artifact resolver + `imagesDir` override in `src/shared/artifacts.ts`

- **Files:** `src/shared/artifacts.ts`, `test/shared/artifacts.test.ts`.
- **Change:**
  - Add `resolvePlatformPackageDir(input: { packageName; require?: NodeRequire; devImagesDir?: string }): { imagesDir; source: 'package'|'dev' }`. Try `req.resolve(`${packageName}/package.json`)` (`req = input.require ?? (typeof require !== 'undefined' ? require : createRequire(import.meta.url))`, inside the function in try/catch — mirror the `__filename` dance already in `index.ts`). On success `imagesDir = dirname(resolvedPkgJson)` (spec §4.1: platform packages ship artifacts at package **root**). On resolve failure fall back to `devImagesDir` with `source:'dev'`; if neither exists throw a typed `PlatformPackageMissingError` naming `@script-jail/<os>-<arch>` and the unsupported-platform hint.
  - **MEDIUM fix (WS1 reviewer #5):** broaden the fallback catch to treat **any** resolve failure (`MODULE_NOT_FOUND` *and* `ERR_PACKAGE_PATH_NOT_EXPORTED`, and generally any throw) as "package not usable → try `devImagesDir`", not only `err.code === 'MODULE_NOT_FOUND'`.
  - **MEDIUM fix (WS1 reviewer #2):** make `ArtifactInput.repoRoot` **optional** (it is required today at `src/shared/artifacts.ts:47` and destructured unconditionally at `:86`). Add optional `imagesDir?: string`; branch `const imagesDir = input.imagesDir ?? join(input.repoRoot!, 'images')` with a runtime guard that exactly one of `{repoRoot, imagesDir}` is provided. Keep `resolveArtifacts` otherwise pure; `manifestKey()` untouched.
  - **MEDIUM fix (WS2 reviewer):** keep the package-branch test injection-only — no `@script-jail/*` is installed yet, so the dev fallback is the only real path this phase.
- **Tests first (`test/shared/artifacts.test.ts`):**
  - injected `require.resolve → '/fake/node_modules/@script-jail/linux-x64/package.json'` → `{imagesDir:'/fake/node_modules/@script-jail/linux-x64', source:'package'}`
  - injected require throwing `MODULE_NOT_FOUND` → falls back to existing `devImagesDir`, `source:'dev'`
  - injected require throwing `ERR_PACKAGE_PATH_NOT_EXPORTED` → also falls back (regression guard for fix #5)
  - missing package + missing `devImagesDir` → throws `PlatformPackageMissingError` (message names `@script-jail/linux-arm64`)
  - `resolveArtifacts({imagesDir:'/pkg', hostArch:'x64', ubuntuMajor:'24.04'})` → `rootfsPath '/pkg/rootfs-ubuntu-24.04.ext4'`, `compressedRootfsPath '/pkg/rootfs-ubuntu-24.04.ext4.gz'`, `libscriptjailSoPath '/pkg/libscriptjail.so'`
  - arm64 variant → `-arm64` rootfs + `libscriptjail-arm64.so`
  - existing `resolveArtifacts({repoRoot})` cases stay green (repoRoot still accepted)
- **Verify:** `pnpm test -- test/shared/artifacts.test.ts && pnpm typecheck`

### Task 1.3 — CLI-local `preFetchArtifacts` to materialize the platform-package rootfs+shim into `imagesDir`

- **Files:** `src/cli/local-artifacts.ts` (new), `test/cli/local-artifacts.test.ts` (new).
- **Change:** Export `createLocalPreFetchArtifacts({ packageImagesDir; hostArch; ubuntuMajor:'24.04'; ensureRootfs? }): typeof preFetchArtifacts` (same signature as `src/action/pre-fetch-artifacts.ts:preFetchArtifacts`, drops into `FirecrackerBackendDeps.preFetchArtifacts` / `BareBackendDeps.preFetchArtifacts`). Inside the closure, given `{imagesDir, runnerImage, arch}`:
  1. compute wanted rootfs name via the FC backend's own rule: `rootfs-${runnerImage}[-arm64].ext4` (with `runnerImage='ubuntu-24.04'`).
  2. `ensureRootfs()` (from `src/cli/rootfs-cache.ts`, already on disk) sparse-gunzips `packageImagesDir/rootfs-ubuntu-24.04[-arm64].ext4.gz` into the cache; then **link** (fallback **copy** on `EXDEV`) the materialized raw ext4 from the cache return path to `join(imagesDir, wantedRootfs)`.
  3. copy `libscriptjail[-arm64].so` to `join(imagesDir, ...)`.
  4. `mkdirSync(imagesDir, {recursive:true})` first.
  - This **replaces** the GitHub-release download; the closure must never touch the manifest or `http.download`.
- **LOW fix (WS1 reviewer #6) — idempotency:** before `linkSync`, **skip** when the dest already exists with the expected byte length (`linkSync` to an existing path throws `EEXIST`). Size-gate the `.so` copy the same way.
- **Tests first (`test/cli/local-artifacts.test.ts`):**
  - arm64: given `{imagesDir, runnerImage:'ubuntu-24.04', arch:'arm64', manifest, http}` → `imagesDir/rootfs-ubuntu-24.04-arm64.ext4` materialized (file exists + byte length == gunzipped sample) and `imagesDir/libscriptjail-arm64.so` copied
  - x64 → `rootfs-ubuntu-24.04.ext4` + `libscriptjail.so` (no arch suffix on `.so`)
  - idempotent: second call does **not** throw, does **not** re-run `ensureRootfs` (injected spy), and does not re-copy (dest-exists-with-right-size short-circuits before `linkSync`)
  - the injected `http.download` spy is **never** called
- **Verify:** `pnpm test -- test/cli/local-artifacts.test.ts && pnpm typecheck`

### Task 1.4 — Wire the Linux branch in `src/cli/index.ts` (backend map + `runAudit({execute})`, no `validateManifest`)

- **Files:** `src/cli/index.ts`, `test/cli/index.test.ts`.
- **Change:** Migrate from `detectHost` to `detectPlatform`; replace `host: DetectedHost` with `platform: DetectedPlatform`. Branch on `platform.os`:
  - **darwin:** keep the exact existing path. Resolve images via `resolvePlatformPackageDir({ packageName: platformPackageName(platform), devImagesDir: join(repoRoot,'images') }).imagesDir`, pass that as `imagesDir` to `resolveArtifacts` (so npm-installed darwin works and dev checkout falls back). Keep `resolveScriptJailRoot` for the version lookup and `devImagesDir` root (WS1 reviewer missing-edit). Keep `ensureRootfs` + VZ `launch` closure + `runAudit({launch, baseRootfsPath})`. `hostArch = platform.arch`.
  - **linux (new):** `packageImagesDir = resolvePlatformPackageDir({...}).imagesDir`; build a CLI cache `imagesDir` under `SCRIPT_JAIL_CACHE_DIR` (fallback `os.tmpdir()/script-jail-images`) — **not** `RUNNER_TEMP` (action-only) — and `mkdirSync`. `const http = new NodeHttpClient()`; `const localPreFetch = createLocalPreFetchArtifacts({packageImagesDir, hostArch:platform.arch, ubuntuMajor:'24.04'})`. Build the **same** backend map shape as `src/main.ts:180`:
    ```
    const backends: BackendMap = {
      firecracker: createFirecrackerBackend({ preFetchArtifacts: localPreFetch, cacheFirecracker:false, warn }),
      docker:      createDockerBackend({ stderr, allowTagFallback:true }),
      bare:        createBareBackend({ preFetchArtifacts: localPreFetch, stderr }),
    };
    ```
    Then call `doRunAudit({ ..., hostArch:platform.arch, execute:(auditInput) => runSelectedBackend({ requested:'auto', backends, warn, ctx:{ ...auditInput, imagesDir, runnerImage:'ubuntu-24.04', arch:platform.arch, manifest:PINNED_MANIFEST, http, selfTest:false } }) })`.
  - **CRITICAL:** never import or call `validateManifest` in `index.ts`. `PINNED_MANIFEST` flows into `ctx` **only** for the Docker backend's digest lookup. `selfTest:false` is mandatory (else Docker requires a pre-pulled local image).
- **MEDIUM/LOW fixes — injection seams (WS1 reviewer #7 + missing-edits):** add to `CliDeps`: a `buildBackends`/`runSelectedBackend` seam (so linux smoke tests never `.run()` real backends or probe `/dev/kvm`/docker) **and** a `resolvePlatformPackageDir` seam (so the `PlatformPackageMissingError` friendly-error test has an injection point). Keep `detectHost` as an accepted alias adapter so the existing I2 regression tests inject the legacy `{macosMajor, hostArch}` shape unchanged.
- **Tests first (`test/cli/index.test.ts`):**
  - LINUX smoke: inject `detectPlatform:()=>({os:'linux',arch:'x64'})` + fake `runAudit` capturing input → assert `input.execute` is a function, `input.launch` undefined, `input.hostArch==='x64'`, `input.baseRootfsPath` undefined
  - LINUX ctx: real `runAudit` override calls `input.execute(...)`; inject `runSelectedBackend` seam capturing `ctx` → assert `ctx.runnerImage==='ubuntu-24.04'`, `ctx.arch==='x64'`, `ctx.manifest===PINNED_MANIFEST`, `ctx.selfTest===false`, `ctx.imagesDir` set, `ctx.http` defined
  - LINUX no-validateManifest: with the real `PINNED_MANIFEST` (placeholder SHAs), `run()` reaches `runAudit`/`execute` and does **not** exit 1 with a packaging-bug message before backend selection
  - LINUX friendly-error: inject `resolvePlatformPackageDir` seam throwing `PlatformPackageMissingError` → `run()` exits 1, stderr names `@script-jail/linux-x64`
  - DARWIN: all existing cases stay green (host gating, spoof-arch default, init/check defaulting, `buildArchFlagOverlay` hostArch I2 regression); arm64 still uses `launch` + `baseRootfsPath`, not `execute`
- **Verify:** `pnpm test -- test/cli/index.test.ts && pnpm typecheck`

### Task 1.5 — Docker pull-by-tag fallback (D6) for placeholder manifest digest

- **Files:** `src/action/backend/docker.ts`, `test/action/backend/docker.test.ts`.
- **Change (MEDIUM fix WS1 reviewer #3 — wire the live path, not dead code):**
  - **Export** a pure helper `resolveDockerImageRef(ctx, { allowTagFallback }): { ref: string; warning?: string }` (today `resolveDockerImage` is **private** at `docker.ts:189`). It keeps the existing behavior: self-test refs, and **throw** `BackendUnavailableError` when the manifest entry is `undefined`/empty (a real config error). New: when `!ctx.selfTest`, the resolved ref's digest matches `/sha256:PLACEHOLDER/` (or the ref contains the literal `PLACEHOLDER` token), **and** `allowTagFallback` is true → derive the tag-only ref by `split('@')[0]` of the placeholder ref (preserve owner casing from the manifest, do **not** hardcode it) and return `{ ref: tagRef, warning: '...non-digest-pinned image...pin a digest at v0.1.1' }`.
  - Add `allowTagFallback?: boolean` (default **false**) to `DockerBackendDeps`. **Rewire `createDockerBackend.run()` line 34**: replace `const imageRef = resolveDockerImage(ctx)` with `const { ref: imageRef, warning } = resolveDockerImageRef(ctx, { allowTagFallback })` and write `warning` to `deps.stderr` when present.
  - **Action byte-unchanged:** `src/main.ts:194` keeps `createDockerBackend({ stderr })` (fallback false) → placeholder ref returned verbatim as today.
- **Tests first (`test/action/backend/docker.test.ts`):**
  - placeholder digest + `allowTagFallback:true` (x64/ubuntu-24.04) → `{ref:'ghcr.io/<owner>/script-jail-rootfs:ubuntu-24.04', warning: /non-digest|not.*pinned/}`
  - arm64 placeholder + fallback → `:ubuntu-24.04-arm64`
  - placeholder + `allowTagFallback:false` (Action default) → returns placeholder ref unchanged (no warning)
  - real digest ref + fallback:true → returns digest ref verbatim, no warning
  - missing/empty manifest entry → throws `BackendUnavailableError` regardless of flag
  - **live-path test:** `run()` with `allowTagFallback:true` emits the warning to `stderr` and pulls the tag ref
  - existing `cleanupStagedDockerRepo` cases stay green
- **Verify:** `pnpm test -- test/action/backend/docker.test.ts && pnpm typecheck`

### Task 1.6 — Rebuild `dist/cli.cjs` + full matrix (drift gate)

- **Files:** `dist/cli.cjs`.
- **Change:** `pnpm build:cli`. Confirm no `dist/main.cjs` change is needed from Phase 1 unless `docker.ts` flows into it — if so, run `pnpm build:bundle` too and commit both. Do **not** hand-edit bundles.
- **Verify:** `pnpm typecheck && pnpm test`; `git diff --stat` shows only the expected `dist/*.cjs` regenerated. No leftover references to removed `detect-host` symbols.

---

## Phase 2 — Packaging & multi-package release (WS2)

Goal: split into a tiny main `script-jail` (JS only) + three optional-dep platform packages `@script-jail/{darwin-arm64,linux-x64,linux-arm64}`, and rewire `release.yml` to assemble/gate/publish all four. **Confirmed task order (WS2 reviewer): PKG-4 → PKG-1 → PKG-2 → PKG-3 → PKG-5 → PKG-6.** Depends on Phase 1 package-name contract (`platformPackageName`).

### Task 2.1 (PKG-4) — Rewrite main `package.json` + regenerate lockfile

- **Files:** `package.json`, `pnpm-lock.yaml`, `test/scripts/main-package-manifest.test.ts` (new).
- **Change:** Set `files` to exactly `["dist/cli.cjs","dist/guest-agent.cjs","dist/preloads/*.cjs","README.md"]` (remove the four mac entries `package.json:9-12`). Add `optionalDependencies: {'@script-jail/darwin-arm64':'0.1.0','@script-jail/linux-x64':'0.1.0','@script-jail/linux-arm64':'0.1.0'}`. Keep `bin:{script-jail:'dist/cli.cjs'}`, `version:'0.1.0'`, all scripts/deps. **No `os`/`cpu` on main** (must install everywhere so npm picks the matching optional dep).
- **ORDERING HAZARD fix (WS2 reviewer):** adding `optionalDependencies` changes `pnpm-lock.yaml`. Regenerate and commit the lockfile **in this same commit**, then verify `pnpm install --frozen-lockfile` passes locally with the three optional deps unresolvable (npm/pnpm skip unresolved optional deps). This must precede PKG-5 wiring (the release `build` job runs `pnpm install --frozen-lockfile`, `release.yml:145`).
- **Tests first:** read `./package.json` and assert: no `os`/`cpu`; `files` equals the 4-entry array; `optionalDependencies` has exactly the 3 scoped names all `=== version`; `bin['script-jail']==='dist/cli.cjs'`; `files` references no `images/` or `bin/` path.
- **Verify:** `pnpm test -- test/scripts/main-package-manifest.test.ts && pnpm install --frozen-lockfile`

### Task 2.2 (PKG-1) — Canonical package-manifest spec module

- **Files:** `scripts/npm-packages.mjs` (new), `test/scripts/npm-packages.test.ts` (new).
- **Change:** Export `npmPackages(version)` returning the 4-package source of truth `{ name, dir, packageJson, artifacts, maxPackBytes }`:
  - **main** `script-jail`: `files` mirroring PKG-4 exactly, `bin`, no `os`/`cpu`, `optionalDependencies` all `=version`; `artifacts=[]`.
  - **`@script-jail/darwin-arm64`**: `os:['darwin']`, `cpu:['arm64']`, `files=['rootfs-ubuntu-24.04-arm64.ext4.gz','vmlinux-vz-arm64','libscriptjail-arm64.so','script-jail-vm']`; artifact map: `images/rootfs-ubuntu-24.04-arm64.ext4`→gzip→`.gz`; `images/vmlinux-vz-arm64`→copy; `images/libscriptjail-arm64.so`→copy; `script-jail-vm-arm64-darwin` (artifacts root) → dest `script-jail-vm` mode **0o755**.
  - **`@script-jail/linux-x64`**: `os:['linux']`, `cpu:['x64']`, `files=['rootfs-ubuntu-24.04.ext4.gz','libscriptjail.so']`; `images/rootfs-ubuntu-24.04.ext4`→gzip; `images/libscriptjail.so`→copy.
  - **`@script-jail/linux-arm64`**: `os:['linux']`, `cpu:['arm64']`, `files=['rootfs-ubuntu-24.04-arm64.ext4.gz','libscriptjail-arm64.so']`.
  - Shared fields: `version`, `description`, `license:'MIT'`, `type:'module'`, `publishConfig:{access:'public'}`, `engines:{node:'>=20.0.0'}`.
- **LOW fix (WS2 reviewer #4) — per-package pack cap:** put an explicit `maxPackBytes` per package in this module (e.g. **200 MiB** for platform packages with the gz rootfs, small cap for main), so the CI-only "gz exceeds 70 MiB" failure mode is removed. `SCRIPT_JAIL_NPM_MAX_PACK_BYTES` remains an override.
- **ORDERING HAZARD fix (WS2 reviewer):** PKG-1's main `files` array must **exactly equal** PKG-4's. PKG-4 is authoritative; PKG-1 mirrors it. Header comment: filenames here are a load-bearing contract with `src/shared/artifacts.ts` (Phase 1).
- **Tests first:** `npmPackages('0.1.0')` → exactly 4 names; main has no `os`/`cpu` and `optionalDependencies` all `'0.1.0'`; each platform package's exact `os`/`cpu`/`files`; darwin VZ helper mode `0o755` dest `script-jail-vm`; all rootfs artifacts `gzip:true` ending `.ext4.gz`; passing `'0.1.1'` propagates to every `version` and optional-dep value; each platform package's `maxPackBytes` is generous.
- **Verify:** `pnpm test -- test/scripts/npm-packages.test.ts`

### Task 2.3 (PKG-2) — Generalize `scripts/assert-npm-packlist.mjs`

- **Files:** `scripts/assert-npm-packlist.mjs`, `test/scripts/assert-npm-packlist.test.ts` (new).
- **Change:** Take the package staging dir as `argv[2]` (default `.`); read `<dir>/package.json` `name`; look up the spec via `npmPackages(pkg.version)`. Expected packed files = spec `files` expanded (resolve `dist/preloads/*.cjs` by globbing the staged dir) + `package.json`. Run `spawnSync('npm',['pack','--dry-run','--json'],{cwd:dir})`. Compare sorted `pack.files.map(e=>e.path)` to expected. For the VZ helper (darwin-arm64 only) assert `files.find(e=>e.path==='script-jail-vm').mode === 0o755`. Size cap from `pkg`'s `maxPackBytes` (per-package), `SCRIPT_JAIL_NPM_MAX_PACK_BYTES` override. Add `--all <stagingRoot>` loop mode. Keep `fail()`/`formatBytes()`.
- **LOW fix (WS2 reviewer #3) — do not over-assert exec bit on main:** `npm pack --dry-run --json` reports `dist/cli.cjs` at mode `0o644` even though it is the `bin` target (npm sets exec at install time). Scope the 0o755 assertion strictly to `script-jail-vm`. Add a test comment so a contributor does not add a wrong 0o755 check on main.
- **Tests first (spawnSync-driven, dummy files only):**
  - valid darwin-arm64 dir (chmod `script-jail-vm` 0755) → exit 0
  - `script-jail-vm` chmod 0644 → exit 1 mentioning executable/0755
  - drop `libscriptjail-arm64.so` → exit 1 "file list mismatch"
  - main `script-jail` dir with `dist/cli.cjs`+`dist/guest-agent.cjs`+3 preloads+README → exit 0; preload glob expanded to all three; assert `dist/cli.cjs` reported at 0o644
  - size over tiny `SCRIPT_JAIL_NPM_MAX_PACK_BYTES=10` → exit 1 "exceeds limit"
- **Verify:** `pnpm test -- test/scripts/assert-npm-packlist.test.ts` (requires `npm` on PATH, consistent with existing `check-publish-artifacts.test.ts`)

### Task 2.4 (PKG-3) — `scripts/assemble-npm-packages.mjs`

- **Files:** `scripts/assemble-npm-packages.mjs` (new), `test/scripts/assemble-npm-packages.test.ts` (new), `.gitignore`.
- **Change:** `node scripts/assemble-npm-packages.mjs --artifacts <dir> --out <stagingRoot> --version <v>`. For each `npmPackages(version)`: create `<stagingRoot>/<sanitizedName>/` (e.g. `script-jail`, `script-jail-darwin-arm64`); write `package.json` (2-space indent + trailing newline). For **main**, derive from repo-root `./package.json` overwriting `files`/`optionalDependencies` and dropping `devDependencies`/`scripts`/`packageManager` for a clean published manifest (keep name/version/description/type/license/bin/engines/publishConfig). Copy main JS from `<artifacts>/dist/...` + repo README. For platform packages: `gzip:true` → stream `<artifacts>/images/<src>` through `zlib.createGzip` into `<dir>/<dest>`; else `copyFileSync`; then `chmodSync` (0o755 for `script-jail-vm`, else 0o644). Validate every source path up front; `fail()` naming any missing artifact. Add `npm-staging/` to `.gitignore` (WS2 reviewer optional missing-edit).
- **MEDIUM fix (WS2 reviewer #1) — reproducible-gzip wording:** Node `zlib.gzipSync` is **run-to-run deterministic** (no mtime/FNAME) — that is all that's required. Do **not** claim byte-identity with GNU `gzip -n` (the OS-identifier header byte and deflate stream differ; that goal is unachievable and unnecessary). Verified nothing pins the `.ext4.gz` SHA: `artifact-manifest.ts` has no `.gz` entry, the packlist gate checks only file-list/size/mode, and `src/cli/rootfs-cache.ts` validates the gz against a **self-computed** digest, never a pinned one. Use a fixed zlib level; document that gz bytes intentionally differ from legacy `gzip -n`.
- **Tests first (spawnSync-driven, fake artifacts dir):** 4 staging dirs created; each `package.json` correct name/version/os/cpu/files/optionalDependencies; darwin-arm64 `script-jail-vm` mode `& 0o755`; `.ext4.gz` files have gzip magic `0x1f8b` and gunzip back to the dummy bytes; main dir has cli+guest-agent+3 preloads+README and **no** `images/`; **determinism:** two runs into two roots → byte-identical gz; **failure:** omit `images/libscriptjail.so` → non-zero naming the missing file; **end-to-end:** run `assert-npm-packlist` on each assembled dir → all exit 0.
- **Verify:** `pnpm test -- test/scripts/assemble-npm-packages.test.ts`

### Task 2.5 (PKG-5) — Rewire `release.yml` `publish` job

- **Files:** `.github/workflows/release.yml`, `test/scripts/release-workflow.test.ts` (new).
- **Change:** In the `publish` job, replace "Stage npm macOS package assets" (`release.yml:553-571`) and the final "Publish npm package" (`release.yml:593-596`) with:
  1. **Stage npm packages:** keep the version==tag gate (`release.yml:556-561`), generalized to all packages, then `node scripts/assemble-npm-packages.mjs --artifacts artifacts --out npm-staging --version "$version"`. Inputs already downloaded into `./artifacts` (`release.yml:404-412`, `:419-423`); confirm `vmlinux-vz-arm64` is in the build-job upload list (`release.yml:368` — it is) and the x64/arm64 ext4 + `.so`.
  2. **Validate npm packlists:** `node scripts/assert-npm-packlist.mjs --all npm-staging`.
  3. **Publish platform-first then main:** `for pkg in script-jail-darwin-arm64 script-jail-linux-x64 script-jail-linux-arm64; do (cd npm-staging/$pkg && npm publish --provenance --access public); done` THEN `(cd npm-staging/script-jail && npm publish --provenance --access public)`. Keep `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`; `id-token:write` is present (`release.yml:389`). Leave GHCR push + gh-release upload steps unchanged.
- **ORDERING (load-bearing, WS2 reviewer):** platform packages MUST publish before main so `optionalDependencies` resolve at install. npm publish is non-transactional/non-re-runnable for a published version — partial-failure recovery is re-running unpublished packages or bumping the version.
- **LOW fix (WS2 reviewer #6):** note in the step comments that a future 4th preload requires updating **three** places: build-job upload glob (`release.yml:372`, already glob — OK), assemble copy (glob — OK), and the hard-coded `cmp -s` list in "Verify Docker runtime JS artifacts" (`release.yml:446-449`, **not** a glob).
- **Bind names:** staging-dir sanitized names are the single source via `npm-packages.mjs`; the release loop iterates exactly those.
- **Tests first (`test/scripts/release-workflow.test.ts`, parse with the `yaml` dep):** publish job contains a step invoking `assemble-npm-packages.mjs` (`--artifacts`,`--out`); a step invoking `assert-npm-packlist.mjs`; the publish step publishes the 3 platform packages **before** `script-jail` (assert via `indexOf`); every `npm publish` includes `--provenance` and `--access public`; the version==tag gate string is still present; `NODE_AUTH_TOKEN` still references `secrets.NPM_TOKEN`.
- **Verify:** `pnpm test -- test/scripts/release-workflow.test.ts`; optionally `actionlint .github/workflows/release.yml`.

### Task 2.6 (PKG-6) — Rewrite packaging prose in README + development.md

- **Files:** `README.md`, `docs/development.md`.
- **Change (MEDIUM fix WS2 reviewer #2 — rewrite, do not append):** The working tree already contains obsolete single-package prose that is now **false**:
  - `README.md` (~lines 149-151): "The npm package currently ships the Apple Silicon runtime artifacts…script-jail-vm, the VZ kernel, libscriptjail-arm64.so, and a compressed Ubuntu 24.04 arm64 rootfs" → rewrite to: main ships only `dist/cli.cjs` + `guest-agent.cjs` + preloads + README; runtime artifacts live in the per-platform optional packages (`darwin-arm64`, `linux-x64`, `linux-arm64`; Intel mac unsupported); `npx script-jail` auto-pulls the matching `@script-jail/<os>-<arch>`.
  - `docs/development.md` (release-bundle bullet "An npm package containing dist/cli.cjs plus the macOS arm64 runtime artifacts…" and the packlist paragraph "if npm would omit a required macOS asset"): generalize to the 4-package topology, that guest-agent+preloads live once in main (used by Linux bare mode), that `assemble-npm-packages.mjs` stages from CI artifacts and `assert-npm-packlist.mjs` gates **each** package, and the platform-first publish order. Drop "macOS asset" wording.
- **Coordinate with WS4:** link the runbook rather than duplicate Phase 0→2 steps (WS4 owns the runbook; this owns topology).
- **Tests first:** none new here; README inclusion in the main tarball is already covered by Task 2.3's main-package packlist test.
- **Verify:** `pnpm test` (no regressions); manual read for accuracy.

---

## Phase 3 — Reproducible rootfs (WS3, parallelizable with Phases 1–2)

Goal: make the rootfs ext4 byte-reproducible so the v0.1.1 manifest backfill reproduces v0.1.0's SHAs. **Action-only; not on the npm critical path, but MUST land before the v0.1.1 backfill (Phase 5).** Confined to `src/rootfs/` + one `release.yml` `build`-job step. Confirmed order: R1-1 → R1-2 → R1-3 → R1-4 → R1-5.

### Task 3.1 (R1-1) — Deterministic-fs constants + pure `buildMkfsExt4Args`

- **Files:** `src/rootfs/build.ts`, `test/rootfs/build-config.test.ts` (new).
- **Change:** Add exported `ROOTFS_FIXED_UUID = '5343524a-2d6a-6169-6c2d-726f6f746673'` and `ROOTFS_SOURCE_DATE_EPOCH = 1700000000`. Extract `buildMkfsExt4Args(exportDir, outImage, sizeMB): string[]` → `['-d', exportDir, '-L', 'rootfs', '-O', '^has_journal', '-m', '0', '-U', UUID, '-E', `hash_seed=${UUID}`, outImage, `${sizeMB}M`]` (existing `-L`/`-O`/`-m` preserved; `-U`/`-E` before positionals). Rewrite `makeExt4Native` to call it.
- **Tests first:** argv includes adjacent `-U <UUID>` and `-E hash_seed=<UUID>`; preserves `-d`/`-L rootfs`/`-O ^has_journal`/`-m 0`; ends `<outImage>` then `<sizeMB>M`; UUID matches 8-4-4-4-12 regex, epoch is a stable positive int; repeated calls deeply-equal (purity).
- **Verify:** `pnpm test -- test/rootfs/build-config.test.ts && pnpm typecheck`

### Task 3.2 (R1-2) — Export `SOURCE_DATE_EPOCH` + normalize export-tree mtimes

- **Files:** `src/rootfs/build.ts`, `test/rootfs/build-config.test.ts`.
- **Change:** (a) `runMkfs(args)` spawns `mkfs.ext4` via `spawnSync` (argv form, mirror `overlay.ts:246-262` explicit nonzero-status throw) with `env:{...process.env, SOURCE_DATE_EPOCH:String(ROOTFS_SOURCE_DATE_EPOCH)}` (e2fsprogs ≥1.45 honors it; ubuntu-24.04 ships 1.47). Export a pure `mkfsEnv()` returning the env overlay for unit assertion. (b) In `exportAndConvert` (build.ts:762-801), after `docker export | tar -x -C tmpDir` and the empty-dir guard, normalize all file/dir/symlink mtimes to the epoch via exported `buildNormalizeMtimesArgv(dir, epoch)` → `find <dir> -exec touch --no-dereference --date=@<epoch> {} +`. Touch failures are **fatal** (do not silently skip).
- **Tests first:** `buildNormalizeMtimesArgv('/tmp/x',1700000000)` contains `--no-dereference`, `--date=@1700000000`, targets the dir; symlinks not followed; `mkfsEnv().SOURCE_DATE_EPOCH === '1700000000'`.
- **Verify:** `pnpm test -- test/rootfs/build-config.test.ts && pnpm typecheck`

### Task 3.3 (R1-3) — Digest-pin Docker bases + deterministic Alpine helper

- **Files:** `src/rootfs/build.ts`, `src/rootfs/Dockerfile.base`, `test/rootfs/build-config.test.ts`.
- **Change:**
  - **Dockerfile.base:** add `ARG UBUNTU_REF=<digest-pinned-default>` and change line 13 `FROM ubuntu:${UBUNTU_MAJOR}` → `FROM ${UBUNTU_REF}`. **RETAIN `ARG UBUNTU_MAJOR`** — it is still consumed downstream by the apt-mirror `RUN`/sed logic (WS3 reviewer missing-edit).
  - **build.ts:** add a pinned `UBUNTU_BASE_DIGEST: Record<RunnerImage, Record<BuildArch, string>>` (per-arch image digests, not manifest-list, for byte-stability under buildx `--platform`). Thread `--build-arg UBUNTU_REF=ubuntu@sha256:<digest>` into the **shared `buildArgs` string (build.ts:676-681)** so **both** the plain `docker build` x64 path (697-704) **and** the `docker buildx build` arm64 path (688-696) inherit it (WS3 reviewer missing-edit). Add `ALPINE_HELPER_REF = 'alpine@sha256:<digest>'`; replace `alpine:latest` in `makeExt4ViaDocker` (745-760). Extract `buildMkfsExt4ViaDockerScript(imageName, sizeMB)` reusing the same UUID/epoch + the same mtime-normalize + `SOURCE_DATE_EPOCH=<epoch> mkfs.ext4 ... -U <uuid> -E hash_seed=<uuid>`. Document the digest-refresh command (`docker buildx imagetools inspect ubuntu:24.04`) and that the authoritative release SHA comes from the native Linux path (Alpine path is best-effort).
- **Tests first:** `buildMkfsExt4ViaDockerScript('rootfs.ext4',1024)` contains the same `-U`/`-E hash_seed` flags and sets `SOURCE_DATE_EPOCH=<epoch>` before `mkfs.ext4`, and normalizes mtimes (`--no-dereference --date=@<epoch>`) before mkfs; `ALPINE_HELPER_REF` and each `UBUNTU_BASE_DIGEST` entry match `^[a-z0-9./:-]+@sha256:[0-9a-f]{64}$`; dockerBuild build-args include the pinned `UBUNTU_REF` (assert via exported `buildDockerBuildArgs`/the digest map for the right `(runnerImage,arch)`).
- **Verify:** `pnpm test -- test/rootfs/build-config.test.ts && pnpm typecheck`

### Task 3.4 (R1-4) — Linux+docker-gated reproducibility integration test

- **Files:** `test/integration/rootfs-reproducibility.test.ts` (new), `src/rootfs/build.ts` (export the conversion seam).
- **Change (WS3 reviewer missing-edit):** **Export** the ext4-conversion seam from `build.ts` (`exportAndConvert`/`makeExt4Native` or a new `convertContainerToExt4`, currently private at :762) so the test can build the docker image **once**, then run conversion **twice** over the same exported tree and compare SHAs — isolating mkfs+normalize determinism without paying the docker-build cost twice. Gate with `describe.skipIf(platform !== 'linux' || !dockerAvailable)` (mirror `overlay.test.ts:157`); detect docker via `spawnSync('docker',['version'])`. Runs in the `integration` vitest project (120s timeout).
- **Tests first (the test IS the artifact):** two conversions of the same exported tree produce byte-identical ext4 (sha256 equal); skip cleanly (not fail) when docker unavailable or non-Linux. If it flakes, capture residual-nondeterminism as an open question (pre-sort `-d` tree / `mke2fs.conf`) — do **not** mask with retries.
- **Verify:** on a Linux+docker host, `pnpm test:integration -- rootfs-reproducibility`; on mac/non-docker CI it must no-op.

### Task 3.5 (R1-5) — CI determinism guard in the `build` job

- **Files:** `.github/workflows/release.yml`.
- **Change (ORDERING — load-bearing):** Insert a step **immediately after** "Build rootfs (ubuntu-24.04, x64)" (`release.yml:258-259`) and **before** the arm64 rootfs builds (`:265/:268`) and "Restore x64 shim artifact" (`:275`) — because the arm64 steps stage `libscriptjail-arm64.so` over `images/libscriptjail.so`, so a later rebuild would compare a shim-contaminated image and false-pass/fail. Copy `images/rootfs-ubuntu-24.04.ext4` to `/tmp/first.ext4`, rebuild in place (x64, skip bundle/shim), `sha256sum` both, `[ "$sha1" = "$sha2" ] || { echo '::error::rootfs ext4 is not byte-reproducible'; exit 1; }`. The in-place rebuild becomes the uploaded artifact (identical by construction). Comment references R1 + the v0.1.1 backfill rationale.
- **Conflict note:** this is in the `build` job; WS2's Task 2.5 edits the `publish` job. Land as separate commits; if textually adjacent, WS2 rebases on this.
- **Tests first:** none (workflow YAML); validate with `actionlint` and a `node -e` YAML parse. R1-4 is the behavioral guarantee; R1-5 is its production deployment.
- **Verify:** `actionlint .github/workflows/release.yml`.

---

## Phase 4 — Cross-workstream integration guards

### Task 4.1 — Filename-contract binding test (WS1↔WS2)

- **Files:** `test/scripts/filename-contract.test.ts` (new).
- **Change (LOW fix WS2 reviewer #5 — mechanically enforce the prose-only contract):** import `npmPackages('0.1.0')` from `scripts/npm-packages.mjs` **and** `resolveArtifacts`/`resolvePlatformPackageDir` from `src/shared/artifacts.ts`, and assert each platform package's `files` basenames equal what the resolver looks up per `(os,arch)`: `rootfs-ubuntu-24.04.ext4.gz` / `rootfs-ubuntu-24.04-arm64.ext4.gz` (and that `compressedRootfsPath` derives as `${rootfsPath}.gz`), `libscriptjail.so` / `libscriptjail-arm64.so`, `vmlinux-vz-arm64`. This is the single highest-value cross-workstream guard; without it a filename drift fails only at runtime install on a real Linux/macOS box.
- **Verify:** `pnpm test -- test/scripts/filename-contract.test.ts`

### Task 4.2 — Full matrix + dist rebuild after all src/script changes

- **Files:** `dist/cli.cjs` (and `dist/main.cjs` if `docker.ts` flows into it).
- **Change:** `pnpm build:cli` (+ `pnpm build:bundle` if needed). Confirm `git diff --stat` shows only expected `dist/*.cjs`.
- **Verify:** `pnpm typecheck && pnpm test` (all four projects). On a Linux+docker host also run `pnpm test:integration`.

---

## Phase 5 — First-release runbook (WS4, last)

Goal: author `docs/releasing.md` capturing Phase 0→1→2 and the works/degraded matrix. Doc-only. Confirmed order W4-T1 → W4-T2 → W4-T3. **Must reflect the post-WS2 target step names** and the verified line numbers below.

### Task 5.1 (W4-T1) — Doc-claim cross-check test FIRST (TDD for a doc)

- **Files:** `test/docs/releasing-claims.test.ts` (new), asserts against `docs/releasing.md` (created in 5.2).
- **Note (WS4 reviewer missing-edit, resolved):** vitest `unit` project `include: ['test/**/*.test.ts']` with exclude only `integration|guest|e2e` (verified `vitest.config.ts:8-10`) → `test/docs/**` **is** picked up. No relocation. State this in the test header.
- **Change:** assertions, each paired with a comment naming the doc claim it guards:
  1. `docs/releasing.md` exists and is non-empty (fails until 5.2).
  2. doc mentions repo slug `Brooooooklyn/scriptjail` and tags `v0.1.0`/`v0.1.1`.
  3. import `PINNED_MANIFEST` and compute counts: `Object.keys(expected.linux).length + Object.keys(expected.darwin).length === 9`, `Object.keys(dockerImages.x64).length + Object.keys(dockerImages.arm64).length === 4`; assert the doc's stated number **equals the computed number** (single-sourced, not hardcoded twice).
  4. **MEDIUM fix (WS4 reviewer #3) — step-name coupling:** assert only on step names WS2 is contracted to **preserve** in the final `publish` job (coordinate exact names with Phase 2 Task 2.5 — e.g. "Stage npm packages", the publish step). Do **not** assert the current "Stage npm macOS package assets" / "Publish npm package" names, which WS2 renames. Gate these assertions on the post-WS2 names so they do not break mid-sequence.
  5. `src/cli/index.ts` does **not** contain `validateManifest(` (CLI-skips-manifest invariant) and `src/main.ts` **does** contain `doValidateManifest(PINNED_MANIFEST)`.
- **Tests first:** the five assertions above; the file must FAIL initially (no `docs/releasing.md`).
- **Verify:** `pnpm test -- test/docs/releasing-claims.test.ts` (expect red until 5.2).

### Task 5.2 (W4-T2) — Write `docs/releasing.md`

- **Files:** `docs/releasing.md` (new).
- **HIGH/MEDIUM fixes — use verified line numbers (WS4 reviewer #1, #2; confirmed by me this session):**
  - `doValidateManifest(PINNED_MANIFEST)` is at **`src/main.ts:121`** (the plan's "119" and "spec off by 2" are wrong; the spec's :121 is correct). Use the stable string `doValidateManifest(PINNED_MANIFEST)` in prose; reserve the raw line for the appendix.
  - `const backends: BackendMap` is at **`src/main.ts:180`** (the plan's ":185" is wrong; the spec's 180-199 is correct).
  - `SCRIPT_JAIL_E2E_SELF_TEST` self-test bypass at `src/main.ts:108`.
  - mixed-manifest reject gate at **`scripts/check-publish-artifacts.sh:376-391`** (comment :376, condition `[ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]` at :378).
- **Change — sections:**
  - **Phase 0 (pre-tag, manual):** own npm name `script-jail` + `@script-jail` scope + token for **both** (O2); confirm WS1–WS3 landed and `PINNED_MANIFEST.repo==='Brooooooklyn/scriptjail'`, `tag==='v0.1.0'`, all `PLACEHOLDER_SHA256_*`; rebuild+commit bundles; `version===0.1.0` on main + all platform packages; green on the exact tagged commit (test.yml drift gate, e2e.yml, test-macos.yml, parity-test.yml).
  - **Phase 1 (tag v0.1.0):** build-mac-bin → build (validate-manifest warn-only-placeholders passes) → publish. Document the publish-job side-effect order: check-publish verify → Verify Docker JS → GHCR push (4 images) → Stage npm packages (incl. version==tag gate) + per-package `assert-npm-packlist` → gh release upload → **`npm publish` LAST**. Document **multi-package order = 3 platform packages first, main last** (target state delivered by WS2 Phase 2; flag that the pre-WS2 committed file published one package). npm publish is the **only non-re-runnable** step and is correctly last; GHCR/gh-release are re-runnable; post-publish problems require a version bump.
  - **Phase 2 (backfill → v0.1.1):** paste 9 file SHAs + 4 Docker digests from the v0.1.0 job summaries into `src/action/artifact-manifest.ts`; set `tag:'v0.1.1'`; **all-or-nothing** (mixed manifest rejected at `check-publish-artifacts.sh:378`); bump all versions to 0.1.1; `pnpm build:bundle` to re-embed the manifest into `dist/main.cjs`; green CI; push `v0.1.1`. WS3 reproducibility makes v0.1.1 reproduce v0.1.0's SHAs so the strict check passes.
  - **Works/degraded matrix (spec §6):** macOS-arm64 CLI = WORKS (manifest-independent; `src/cli/index.ts` never calls `validateManifest`). Linux bare CLI = WORKS. Linux firecracker CLI = WORKS where `/dev/kvm`+tap exist, else `auto` falls through. **Linux docker CLI = DEGRADED:** **LOW fix (WS4 reviewer #4)** — on v0.1.0 the placeholder docker ref is non-empty (`...@sha256:PLACEHOLDER_...`), so `resolveDockerImage` (`src/action/backend/docker.ts:189-203`) **RETURNS** it and the failure surfaces at the actual `docker pull` (it does **not** throw `BackendUnavailableError`); the D6 pull-by-tag fallback (Phase 1 Task 1.5, `allowTagFallback:true`) makes it usable day-one with a warning — contingent on O1. **GitHub Action = BROKEN on v0.1.0:** attribute to `src/main.ts:110-122` (`doValidateManifest` fail-fast) + README Status; cite the `release.yml` header (14-20) only for the SHA-mismatch bootstrap, a related-but-distinct mechanism (LOW fix WS4 reviewer #5). Recovers at v0.1.1.
  - **Cross-check appendix:** map each claim to its source, regenerated against HEAD (grep the real lines of `doValidateManifest(PINNED_MANIFEST)` → 121 and `const backends: BackendMap` → 180 before finalizing). **LOW fix (WS4 reviewer #6):** phrase the dist note as "release.yml does not gate on committed-dist freshness (no git-diff drift check); it verifies build-job-produced `dist/main.cjs`/`dist/cli.cjs` content via `check-publish-artifacts.sh` (`release.yml:440-441`); the freshness gate is test.yml."
- **Tests first:** none new; Task 5.1's test turns green.
- **Verify:** `pnpm test -- test/docs/releasing-claims.test.ts` (now green).

### Task 5.3 (W4-T3) — Link the runbook from development.md + README

- **Files:** `docs/development.md`, `README.md`, `test/docs/releasing-claims.test.ts`.
- **Change:** In `docs/development.md` "Release flow", add a pointer to `docs/releasing.md` for the Phase 0→2 sequence + matrix (packaging-topology detail already rewritten by Phase 2 Task 2.6 — do not contradict). In `README.md` "Docs" list, add `- [Releasing](./docs/releasing.md) - first-release runbook and version-bump sequence.` Surgical link insertion only.
- **Tests first:** extend `test/docs/releasing-claims.test.ts`: README contains `](./docs/releasing.md)`; `development.md` contains `docs/releasing.md`.
- **Verify:** `pnpm test -- test/docs/releasing-claims.test.ts`

---

## Definition of done

- [ ] All four vitest projects green: `pnpm test` (unit/guest/e2e on any host); `pnpm test:integration` on a Linux+docker host (incl. `rootfs-reproducibility`).
- [ ] `pnpm typecheck` clean; no leftover references to removed `detect-host` symbols.
- [ ] `dist/cli.cjs` (and `dist/main.cjs` if touched) rebuilt and committed in the same commit as their `src/` change; `test.yml` drift gate would pass (`git diff` shows no further bundle delta after `pnpm build:cli`/`build:bundle`).
- [ ] `pnpm install --frozen-lockfile` passes with the three unpublished `optionalDependencies` skipped; `pnpm-lock.yaml` committed alongside `package.json`.
- [ ] Main `package.json`: no `os`/`cpu`, `files` = 4 JS-only entries, `optionalDependencies` pinned to the version; `bin` intact.
- [ ] `scripts/npm-packages.mjs` is the single source for names, `files`, artifact map, and per-package pack caps; `assemble` + `packlist` + `release.yml` loop all derive from it.
- [ ] Filename-contract test (Task 4.1) green — `npm-packages.mjs` basenames == `resolveArtifacts`/`resolvePlatformPackageDir` lookups.
- [ ] `release.yml` `publish` job: assemble → per-package packlist → publish 3 platform packages **then** main, each `--provenance --access public`; version==tag gate preserved; `release-workflow.test.ts` green. `build` job has the x64 rootfs determinism guard placed before arm64/shim-restore steps.
- [ ] `resolveDockerImageRef` exported, wired into `run()`, `allowTagFallback` defaults false (Action byte-unchanged), CLI passes `true`; live-path warning test green.
- [ ] CLI never calls `validateManifest` (asserted); Action still hard-fails on placeholder manifest at `src/main.ts:121`.
- [ ] Rootfs builds byte-reproducibly (R1-4 seam test); Docker bases + Alpine helper digest-pinned; `UBUNTU_MAJOR` retained in `Dockerfile.base`.
- [ ] `docs/releasing.md` written with **verified** line refs (`src/main.ts:121`, `:180`, `:108`; `check-publish-artifacts.sh:376-391`); `releasing-claims.test.ts` green; README + development.md link it; obsolete single-package prose rewritten.
- [ ] R1 (Phase 3) merged **before** the v0.1.1 backfill (Phase 5 Phase-2 section), so v0.1.1 reproduces v0.1.0's SHAs.

## External prerequisites (cannot be verified from the repo — gate before tagging)

- **O1 — Docker pull-by-tag default:** confirm `allowTagFallback:true` for the CLI Linux-Docker backend is approved for v0.1.0 (Docker works day-one, warned) vs requiring a real digest (works only at v0.1.1). This flips one sentence of the works/degraded matrix; the runbook is written so only that sentence changes once O1 is decided.
- **O2 — npm name / scope / token:** the unscoped name `script-jail` **and** the `@script-jail` org/scope must be owned, and `NPM_TOKEN` (or an OIDC trusted-publisher) must have publish rights to **both**, before pushing the `v0.1.0` tag. Hard Phase 0 gate.

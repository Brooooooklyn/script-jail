# Releasing

Release runbook for script-jail under the **build-once / download-forever**
single-tag flow: a manually-dispatched producer (`release-build.yml`) builds
every VM-image asset exactly once, the operator backfills the producer's SHAs +
digests into the committed manifest, and pushing the single release tag
`vX.Y.Z` runs `release.yml`, which **downloads and verifies** those exact
artifacts (it never rebuilds them) and publishes. This document covers that
sequence plus the works/degraded matrix that explains what is usable before vs.
after the first producer-backed release.

The release repo is **`Brooooooklyn/scriptjail`**.

> **Why a separate producer?** The pinned artifact manifest in
> `src/action/artifact-manifest.ts` records the SHA-256 of every release asset
> and the digest of every GHCR image, and the Action/CLI verify downloaded
> assets against it at runtime. Several of those assets — the VZ kernels, the
> Mach-O VZ helper, the GHCR Docker images — are NOT byte-reproducible, so they
> cannot be rebuilt at tag time and compared. Instead `release-build.yml` builds
> every asset **once** and stores them as tag-suffixed Actions artifacts; the
> later `release.yml` run on the tag downloads those exact bytes and verifies
> them against the committed manifest. Build once, download forever.
>
> **Reproducibility is no longer a release gate.** Because the release publishes
> the exact bytes the producer built (and verifies them against the committed
> SHAs), byte-reproducibility of the binaries is not required and is not gated
> in either workflow. The rootfs ext4s are still pinned by their **canonical
> (time-masked) hash** (`src/rootfs/repro-hash.ts`) — that is simply *how* those
> assets are verified, and it lets an auditor optionally rebuild a rootfs and
> confirm it matches — but a divergent rebuild does not block a release.

For day-to-day build/dist conventions and the packaging topology (four npm
packages, single source of truth in `scripts/npm-packages.mjs`), see
[development.md](./development.md). This runbook covers only the release
sequence and what each phase delivers.

---

## Phase 0 — pre-release manual gates

These steps are done by hand before the tag is pushed. Confirm each explicitly.

1. **npm namespace ownership + trusted publishers (OIDC).** Own the unscoped
   main package name `script-jail` AND the `@script-jail` scope on the registry,
   and have a **trusted publisher** configured for **all four** published
   packages (`script-jail` + `@script-jail/darwin-arm64`,
   `@script-jail/linux-x64`, `@script-jail/linux-arm64`), each pointing at this
   repo's `release.yml`. Set once per package with
   `npm trust github <pkg> --file release.yml --repo Brooooooklyn/scriptjail --allow-publish`
   (needs npm >= 11.16.0 and an interactive 2FA login — `npm login --auth-type=web`;
   a bypass-2FA automation token is rejected by `npm trust`). The publish job then
   authenticates by OIDC (`id-token: write`), so **no npm auth-token secret is
   required** and provenance is attached automatically. A config missing on even
   one of the four packages fails partway through the publish loop.

   > **Bootstrap exception (historical).** Trusted publishing requires the
   > package to already exist on the registry, so the *very first* publish of a
   > brand-new name cannot use OIDC. `0.1.0` was that one-time **manual / local**
   > bootstrap publish (no `v0.1.0` tag was pushed for it). Every release from
   > the first producer-backed one onward uses OIDC via `release.yml`.

2. **Versions are aligned at `X.Y.Z`.** The main `package.json` `version` must be
   `X.Y.Z` on `main`. The three platform packages do not carry a committed
   version — they are stamped from the tag at publish time by
   `scripts/assemble-npm-packages.mjs` (and the main version is gated against the
   tag by the version==tag check in the publish job). You bump the main version
   during the backfill commit (Phase 2), so on a fresh branch it may still read
   the previous release's value here.

3. **Green CI on the exact release commit.** `test.yml` (incl. the dist
   freshness gate), `e2e.yml`, `test-macos.yml`, and `parity-test.yml` must be
   green on the commit you are about to release — the producer and the tag should
   point at an already-green commit, not trigger the first run.

---

## Phase 1 — run the producer (`release-build.yml`)

Dispatch the producer manually: **Actions → release-build → Run workflow**, with
`tag = vX.Y.Z`, on the **target release commit** (select that commit's branch as
the workflow ref). Under `workflow_dispatch` the tag must be supplied
explicitly — `github.ref_name` is the dispatched *branch*, not a `v*.*.*` tag.

The producer builds every image asset exactly once:

1. **`build-mac-bin`** (macOS Apple-Silicon runner) — cross-build the Darwin
   arm64 `script-jail-vm` Mach-O helper and upload it as the tag-suffixed
   artifact `mac-bin-vX.Y.Z`. (It cannot be built on a Linux runner.)
2. **`build`** (Linux runner) — install / bundle, build both x64 + arm64 rootfs
   ext4s for each Ubuntu major, build the x64 + cross-compiled arm64 Rust shims,
   build both VZ vmlinux kernels, **push the 4 GHCR rootfs Docker images**, and
   upload the 8 binary image assets as the tag-suffixed artifact
   `release-assets-vX.Y.Z`. It then prints two paste-blocks to the job summary:
   the **10 file SHAs** ("Artifact SHAs" — from the *Compute SHAs* step) and the
   **4 Docker digests** ("Docker image refs" — from the *Publish Docker rootfs
   images* step).

> The producer **never** publishes to npm, creates a GitHub release, or verifies
> the manifest — those stay in `release.yml`. The artifacts ship ONLY the binary
> image assets, deliberately **not** `dist/*`: the producer runs on the
> *pre-backfill* commit, whose `dist/main.cjs` still embeds the placeholder
> manifest, so shipping it would publish a broken Action. The npm package's
> `dist/*` is staged from the **tagged** checkout in `release.yml` instead.
>
> Because the binaries do **not** depend on the manifest or the version, it is
> correct that the producer runs *before* the manifest backfill (Phase 2).
>
> **90-day artifact retention.** Both producer artifacts
> (`release-assets-vX.Y.Z`, `mac-bin-vX.Y.Z`) are uploaded with
> `retention-days: 90` (set in `release-build.yml`). The tag MUST be pushed
> (Phase 3) within that window — once the artifacts expire, `release.yml`'s
> download step has nothing to fetch and the only recovery is to **re-dispatch
> the producer** (a fresh build, whose non-reproducible kernel/Mach-O bytes
> change, so you must re-backfill the manifest from the new run's SHAs). After a
> successful publish the **durable** copies are the **GitHub release assets** and
> the **npm tarballs** — NOT the Actions artifacts; a release rerun after the
> artifacts expire cannot re-download them.

---

## Phase 2 — backfill the manifest and commit

Paste the producer's values into `src/action/artifact-manifest.ts` and commit.

> **Backfill from the LATEST successful producer run for the tag.** `release.yml`
> locates the producer artifacts by scanning successful `release-build.yml` runs
> **newest-first** and taking the first that carries `release-assets-vX.Y.Z`. If
> you re-dispatched the producer (e.g. after a transient failure), backfill the
> SHAs from that **newest** run's paste-blocks — the kernel/Mach-O bytes are not
> reproducible, so SHAs from an older run would not match the binaries the
> release actually downloads, and the verify step would fail.

1. **Paste the 10 file SHAs + 4 Docker digests.** Copy the **10 file SHAs**
   (3 `expected.linux` + 7 `expected.darwin`) from the *Compute SHAs* paste-block
   and the **4 Docker digests** (2 `dockerImages.x64` + 2 `dockerImages.arm64`)
   from the *Docker image refs* paste-block of the LATEST producer run, replacing
   every `PLACEHOLDER_SHA256_*` token.
2. **Set `tag` to `'vX.Y.Z'`** in the same file.
3. **All-or-nothing across all 14 pinned entries.** A manifest with SOME real
   values and SOME placeholders is a packaging bug and is rejected by
   `check-publish-artifacts.sh` (the mixed-manifest gate:
   `[ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]` → `exit 1`). The
   classification folds **all 14 pinned entries — the 10 file SHAs AND the 4
   Docker digests** — into one `PLACEHOLDER_COUNT` / `REAL_COUNT` tally, so
   pasting the real file SHAs while leaving the Docker refs as placeholders (or
   vice versa) trips the reject. Replace every placeholder, or none. (File SHAs
   are matched by the `PLACEHOLDER_SHA256_` prefix; a Docker ref instead carries
   that token inside its `@sha256:` digest position, so refs are matched by the
   placeholder substring — but both feed the same tally.)
4. **Bump the version to `X.Y.Z`** in the main `package.json` (the platform
   packages are stamped from the tag by `scripts/assemble-npm-packages.mjs`), to
   satisfy the version==tag gate in the publish job.
5. **Rebuild `dist/` and commit.** Run `pnpm build:bundle` (re-embeds the updated
   manifest into `dist/main.cjs` — the Action consumes the manifest from the
   bundled bytes, not from `src/`), plus `pnpm build:cli`,
   `pnpm build:guest-agent`, and `pnpm build:repro-hash` if those sources
   changed, then commit the regenerated bundles. The `verify` job re-bundles and
   diffs, so a stale committed `dist/` fails the release.

---

## Phase 3 — push the tag `vX.Y.Z`

Pushing the `vX.Y.Z` tag runs `release.yml`, whose two jobs run in order. It
**never rebuilds** the rootfs ext4s, shims, VZ kernels, Mach-O helper, or GHCR
images — it downloads the producer's artifacts and verifies them.

### `verify` job

Runs with NO write credentials and `persist-credentials: false`. It builds
nothing that ships. It enforces, in order:

1. **Manifest-no-placeholders gate** ("Gate manifest contains no placeholders
   (must be fully backfilled)"). Any remaining `PLACEHOLDER_SHA256_*` token
   fails LOUD — an un-backfilled manifest would brick every Action consumer and
   ship a placeholder `dist/main.cjs` to npm. Unlike the old two-tag bootstrap,
   there is no documented placeholder-at-tag-time case. It also runs
   `validate-manifest.ts` (no `--warn-only-placeholders`) to enforce shape
   (lowercase 64-hex, etc.).
2. **Typecheck + test** (`pnpm typecheck`, `pnpm test`).
3. **Committed-dist freshness gate** — re-bundles `dist/main.cjs`, `dist/cli.cjs`,
   `dist/guest-agent.cjs`, `dist/repro-hash-cli.cjs` and `git diff --exit-code`s
   them, the same drift gate `test.yml` enforces. A stale committed `dist/` at
   the tag fails here, because the npm package + the GitHub-release `dist` assets
   ship the COMMITTED bundles (the release never re-bundles for shipping).

`publish` depends on `verify`, so a failed gate blocks the irreversible publish.

### `publish` job

The only job with write scopes (`contents: write` + `id-token: write`) plus
`actions: read` / `packages: read` to fetch the cross-run producer artifacts and
inspect the GHCR digests. Its irreversible side effects run in a deliberate
order so the single non-re-runnable step is last:

1. **Download producer build artifacts (by tag-suffixed name)** — walks
   successful `release-build.yml` runs newest-first, finds the first carrying
   `release-assets-vX.Y.Z`, and downloads the 8 binary image assets into
   `artifacts/images/` plus the Mach-O helper into `artifacts/`. Matched by the
   tag-suffixed artifact NAME, because the producer ran on a different commit
   than the tag (commit-SHA match is impossible). (Re-runnable.)
2. **Verify downloaded artifacts against tagged manifest** —
   `check-publish-artifacts.sh` recomputes each downloaded asset's digest (the
   canonical time-masked hash for the rootfs ext4s, via the committed
   `dist/repro-hash-cli.cjs`; a plain `sha256sum` for everything else) and
   compares them to the manifest SHAs. This is the **integrity backstop** that
   detects a tampered or wrong artifact. It runs BEFORE any upload/publish, so a
   mismatch refuses to publish. (No `--dist-source`/`--dist-cli-source` is passed
   — the producer no longer ships `dist/*`; the `dist/*` that ships comes from
   this tagged checkout and is already covered by the `verify` freshness gate.)
   (Re-runnable.)
3. **Verify pinned Docker digests resolve in GHCR (backfill gate)** — runs
   `docker buildx imagetools inspect` on every real `dockerImages` ref, asserting
   each digest the producer pushed actually **exists** in GHCR (not equality —
   the Docker rootfs images are not byte-reproducible). Catches a hand-copy typo
   or a stale/GC'd digest before any publish. (Re-runnable.)
4. **Stage npm packages** — `assemble-npm-packages.mjs` builds the four staging
   dirs: `dist/*` from THIS tagged checkout (real manifest), binaries from the
   downloaded `./artifacts`. Also enforces the **version==tag gate**
   (`package.json` version must equal the tag without the leading `v`).
   (Re-runnable.)
5. **Validate npm packlists** — `assert-npm-packlist.mjs --all` asserts each
   staged package's packed `files`, the VZ helper exec bit, and the per-package
   size ceiling. (Re-runnable.)
6. **Upload release assets** — `gh release` upload of the rootfs/kernel/shim/
   helper assets (from the downloaded artifacts) plus `dist/main.cjs` /
   `dist/cli.cjs` (from this tagged checkout). (Re-runnable: re-uploading
   overwrites.)
7. **Publish npm packages (platform-first, main last)** — the publish of an
   *unpublished* version is the only non-re-runnable side effect. The step is
   **idempotent**: it probes each package with a read-only
   `npm view "$name@$version"` and SKIPS any version already on the registry,
   publishing only the absent ones. So a re-run of a partially-failed release
   republishes only the still-unpublished packages. Because it is last, every
   re-runnable side effect has already succeeded by the time publish fires.

### multi-package publish order

The publish step ("Publish npm packages (platform-first, main last)") publishes
**the 3 platform packages first, then the main `script-jail` package last**:

```
@script-jail/darwin-arm64  @script-jail/linux-x64  @script-jail/linux-arm64   # platform packages first
script-jail                                                                    # main package last
```

This order is load-bearing: the main package's `optionalDependencies` reference
the three platform packages by exact version, so they must already be on the
registry for a consumer's `npm install script-jail` to resolve the matching
`os`/`cpu` one. If a later package in the loop fails after an earlier one
published, recovery is to re-run the job — the idempotent skip republishes only
the still-unpublished packages (or bump the version and re-tag for a genuinely
new release). There is no in-place fix for an already-published version.

---

## Optional — GitHub immutable releases

As complementary defense-in-depth, consider enabling **immutable releases** in
the repo settings (Settings → General → Releases). GitHub then enforces that a
published release's assets cannot be changed after the fact; the manifest's
pinned SHAs verify *what* those assets are, and immutability guarantees they
*stay* that way. This is optional — the manifest SHA check is the primary
integrity control — but it closes the window where a release asset could be
silently swapped after publish.

> **Caveat — incompatible with the current rerun-recovery path.** Immutable
> releases are **not** compatible with the overwrite-based rerun recovery
> described in Phase 3. The publish job's "Upload release assets" step (step 6)
> runs BEFORE the idempotent npm-publish loop (step 7) and re-uploads the assets
> by overwriting. With an immutable release, that re-upload to an
> already-published release is blocked, so a rerun (e.g. to republish a package
> that failed after the release was created) would fail at the asset step and
> never reach the npm recovery — stranding the still-unpublished packages.
> Enable immutable releases only if you instead recover by **bumping the version
> and re-tagging** (a brand-new release, no overwrite) rather than re-running the
> same tag.

---

## Works / degraded matrix

What is usable before vs. after the **first producer-backed release**, and why.
Before that release the committed manifest is all placeholders; after it the
manifest is fully backfilled and verified.

| Target | Placeholder manifest (pre-first-release) | Backfilled manifest | Why |
| --- | --- | --- | --- |
| macOS-arm64 CLI | **WORKS** | WORKS | Manifest-independent — the CLI never calls `validateManifest`, so placeholder SHAs do not gate it. |
| Linux bare CLI | **WORKS** | WORKS | Bare backend fetches the shim directly; no manifest gate in the CLI path. |
| Linux firecracker CLI | **WORKS*** | WORKS* | Works where `/dev/kvm` + a tap device exist; otherwise `backend: auto` falls through to another backend. |
| Linux docker CLI | **DEGRADED** | WORKS | See below — usable with a warning via the tag-fallback path. |
| GitHub Action | **BROKEN** | WORKS | The Action fail-fasts on a placeholder manifest; recovers once real SHAs are pinned. |

> Note: a placeholder manifest cannot reach a *published* release at all — the
> `verify` job's manifest gate fails the tag push before publish. The
> placeholder column describes the state of an un-released fresh fork / branch
> (the committed default before the first backfill), which is what a developer
> building locally from source sees.

### macOS-arm64 CLI = WORKS even with a placeholder manifest

The CLI never validates the pinned manifest: `src/cli/index.ts` does NOT call
`validateManifest(`. The macOS path resolves its artifacts from the installed
`@script-jail/darwin-arm64` package, not from the manifest's SHAs, so it is
fully usable even while the manifest is all placeholders.

### Linux docker CLI = DEGRADED with a placeholder manifest (usable with a warning)

With a placeholder manifest the Docker ref is a **non-empty placeholder**
(`...@sha256:PLACEHOLDER_...`). `resolveDockerImageRef` only throws
`BackendUnavailableError` when there is NO entry for the `(arch, runnerImage)`
pair; a non-empty placeholder is not "missing", so the function **returns** it
rather than throwing. The CLI passes `allowTagFallback: true`, which downgrades
the placeholder digest ref to its tag-only form (`split('@')[0]`) and emits a
warning, making the docker backend usable — pulling by tag instead of by pinned
digest.

### GitHub Action = BROKEN with a placeholder manifest

The Action hard-fails before doing any work: `doValidateManifest(PINNED_MANIFEST)`
runs as the first real statement of `main()` (skipped only under the
`SCRIPT_JAIL_E2E_SELF_TEST` self-test bypass this repo's own CI sets), and a
placeholder manifest fails that gate. The Action works once the real SHAs are
pinned (which, as noted above, is a precondition for the tag to publish at all).

---

## Appendix — claim → source cross-check

Stable strings are used in the prose above; the raw line numbers below are a
snapshot and may drift — re-grep before relying on them.

| Claim | Source | Line (snapshot) |
| --- | --- | --- |
| producer is workflow_dispatch with a required `tag` | `.github/workflows/release-build.yml` — `workflow_dispatch:` / `inputs: tag` | 34 / 36 |
| producer builds + uploads binary assets (no dist) | `.github/workflows/release-build.yml` — `name: Upload build artifacts` (only `images/*`) | 364 |
| producer pushes the 4 GHCR images | `.github/workflows/release-build.yml` — `name: Publish Docker rootfs images` | 409 |
| producer prints the SHA + digest paste-blocks | `.github/workflows/release-build.yml` — `## Artifact SHAs` / `## Docker image refs` | 308 / 514 |
| release downloads (never rebuilds) producer artifacts | `.github/workflows/release.yml` — `name: Download producer build artifacts (by tag-suffixed name)` | 206 |
| backfill from the LATEST producer run (newest-first lookup) | `.github/workflows/release.yml` — `gh run list --workflow release-build.yml --status success` (newest-first) | 217 |
| Action fail-fast manifest gate | `src/main.ts` — `doValidateManifest(PINNED_MANIFEST)` | 121 |
| self-test bypass skips the gate | `src/main.ts` — `SCRIPT_JAIL_E2E_SELF_TEST` | 108 |
| CLI skips the manifest | `src/cli/index.ts` — no `validateManifest(` call | n/a |
| tag-time manifest-no-placeholders gate | `.github/workflows/release.yml` — `Gate manifest contains no placeholders (must be fully backfilled)` | 109 |
| committed-dist freshness gate (verify job) | `.github/workflows/release.yml` — `Verify committed dist bundles are up to date` | 145 |
| mixed-manifest reject condition | `scripts/check-publish-artifacts.sh` — `[ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]` | 547 |
| mixed-manifest reject (comment header) | `scripts/check-publish-artifacts.sh` — `This is a packaging bug` | 549 |
| all-or-nothing spans 9 files + 4 docker | `scripts/check-publish-artifacts.sh` — `The 4 Docker image refs participate in the SAME all-or-nothing` | 419 |
| docker tag-fallback / placeholder handling | `src/action/backend/docker.ts` — `resolveDockerImageRef` | n/a |
| pinned manifest (repo/tag/counts) | `src/action/artifact-manifest.ts` — `PINNED_MANIFEST` | 54 |
| rootfs pinned by canonical (time-masked) hash | `src/rootfs/repro-hash.ts` — `canonicalRootfsHash`; recomputed in `scripts/check-publish-artifacts.sh` — `canonical_rootfs_hash`; consumed in `src/action/pre-fetch-artifacts.ts` | n/a |
| integrity backstop (SHA verify of downloads) | `.github/workflows/release.yml` — `Verify downloaded artifacts against tagged manifest` → `check-publish-artifacts.sh` | 293 |
| GHCR digest-resolves gate | `.github/workflows/release.yml` — `Verify pinned Docker digests resolve in GHCR (backfill gate)` | 327 |
| OIDC trusted publish (npm upgrade, no token) | `.github/workflows/release.yml` — `Upgrade npm for OIDC trusted publishing` (`npm install -g npm@11.16.0`) + publish job `id-token: write` | 283 / 176 |
| publish step names + multi-package order | `.github/workflows/release.yml` — "Stage npm packages" / "Validate npm packlists" / "Publish npm packages (platform-first, main last)" | 376 / 395 / 435 |

**dist note.** The release ships the COMMITTED `dist/` bundles (the publish job
never re-bundles for shipping). The freshness gate — that the committed `dist/`
matches a fresh rebuild of `src/` — runs in `release.yml`'s `verify` job
("Verify committed dist bundles are up to date") and in `test.yml`. The npm
package's `dist/*` is staged from the tagged checkout by
`scripts/assemble-npm-packages.mjs`; the producer's artifacts deliberately
exclude `dist/*`.

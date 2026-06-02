# Releasing

First-release runbook for script-jail: the Phase 0 → 1 → 2 bootstrap loop that
takes a fresh fork from placeholder manifest to a fully runnable Action, plus
the works/degraded matrix that explains exactly what is usable at each tag.

The release repo is **`Brooooooklyn/scriptjail`**. The bootstrap loop spans two
tags: **`v0.1.0`** publishes the npm packages and release assets while the
pinned manifest still carries placeholders, and **`v0.1.1`** backfills the real
SHAs/digests so the GitHub Action validates and runs.

> Why two tags? The pinned artifact manifest in
> `src/action/artifact-manifest.ts` references the SHA-256 of every release
> asset and the digest of every GHCR image — but those values only exist once a
> release has actually built and uploaded them. The first tag produces the
> artifacts; the second tag pins them. This mirrors the bootstrap caveat
> documented in `src/action/artifact-manifest.ts` and `release.yml`.

For day-to-day build/dist conventions and the packaging topology (four npm
packages, single source of truth in `scripts/npm-packages.mjs`), see
[development.md](./development.md). This runbook covers only the release
sequence and what each tag delivers.

---

## Phase 0 — pre-tag manual gates

These steps are done by hand, once, before the first tag is pushed. None of
them are enforced by CI on a fresh fork, so confirm each explicitly.

1. **npm namespace ownership + trusted publishers (manual prerequisite O2).** Own
   the unscoped main package name `script-jail` AND the `@script-jail` scope on
   the registry, and have a **trusted publisher** configured for **all four**
   published packages (`script-jail` + `@script-jail/darwin-arm64`,
   `@script-jail/linux-x64`, `@script-jail/linux-arm64`), each pointing at this
   repo's `release.yml`. Set once per package with
   `npm trust github <pkg> --file release.yml --repo Brooooooklyn/scriptjail --allow-publish`
   (needs npm >= 11.16.0 and an interactive 2FA login — `npm login --auth-type=web`;
   a bypass-2FA automation token is rejected by `npm trust`). The publish job then
   authenticates by OIDC (`id-token: write`), so **no npm auth-token secret is
   required** and provenance is attached automatically. A config missing on even
   one of the four packages fails partway through the publish loop.

   > **Bootstrap exception.** Trusted publishing requires the package to already
   > exist on the registry, so the *very first* publish of a brand-new name
   > cannot use OIDC. v0.1.0 was that one-time bootstrap (published with a
   > token / locally); v0.1.0 → v0.1.1 and every release after it use OIDC.

2. **Manifest is in the documented bootstrap state.** In
   `src/action/artifact-manifest.ts` confirm:
   - `repo` is `'Brooooooklyn/scriptjail'`,
   - `tag` is `'v0.1.0'`,
   - **every** SHA value is still a `PLACEHOLDER_SHA256_*` token (no real SHAs
     mixed in — a mixed manifest is rejected, see Phase 2).

3. **Rebuild and commit the bundles.** Any `src/` change since the last build
   means `dist/` is stale. Run the build, then commit the regenerated bundles
   (`dist/main.cjs`, `dist/cli.cjs`, `dist/guest-agent.cjs`,
   `dist/preloads/*.cjs`) so the tagged commit carries the bytes the release job
   verifies. The freshness gate that catches a stale `dist/` is `test.yml` (see
   the dist note in the appendix).

4. **Versions are aligned at `0.1.0`.** The main `package.json` `version` must
   be `0.1.0` on `main`, and the three platform packages assemble to the same
   version (they are stamped from the tag by `scripts/assemble-npm-packages.mjs`
   and gated by the version==tag check in the publish job).

5. **Green CI on the exact tagged commit.** `test.yml` (incl. the dist
   freshness gate), `e2e.yml`, `test-macos.yml`, and `parity-test.yml` must be
   green on the commit you are about to tag — the tag should point at an
   already-green commit, not trigger the first run.

---

## Phase 1 — tag `v0.1.0`

Pushing the `v0.1.0` tag runs `release.yml`, whose jobs run in order:

1. **`build-mac-bin`** — cross-build the Darwin arm64 `script-jail-vm` Mach-O
   helper on the macOS runner (it cannot be built on the Linux publish runner)
   and upload it as a workflow artifact.
2. **`build`** — install / typecheck / test / build the bundles, build the
   rootfs ext4 images, the Rust shim `.so`s, and the VZ kernels. The
   "Validate pinned artifact manifest (bootstrap-aware)" step runs
   `validate-manifest.ts --warn-only-placeholders`: with an all-placeholder
   manifest it **warns** (and writes the "this release will NOT run as an
   action" notice to the step summary) but exits 0, so the build proceeds.
3. **`publish`** — the only job with write-scoped credentials.

### publish-job side-effect order

The `publish` job performs its irreversible side effects in a deliberate order
so that the single non-re-runnable step is last:

1. **Verify downloaded artifacts against tagged manifest** —
   `check-publish-artifacts.sh` recomputes the SHAs of the downloaded assets and
   compares them to the manifest, and verifies the build-job-produced
   `dist/main.cjs` / `dist/cli.cjs` content. Runs BEFORE any upload, so a
   mismatch refuses to publish. (Re-runnable.)
2. **Verify Docker runtime JS artifacts** — `cmp -s` the guest agent and
   preload bundles against the checked-out tree. (Re-runnable.)
3. **GHCR push** — push the four digest-pinned Docker rootfs images. (Idempotent
   / re-runnable: re-pushing an identical layer set is a no-op.)
4. **Stage npm packages** — `assemble-npm-packages.mjs` builds the four staging
   dirs from the artifacts. This step also enforces the **version==tag gate**
   (`package.json` version must equal the tag without the leading `v`). (Re-runnable.)
5. **Validate npm packlists** — `assert-npm-packlist.mjs --all` asserts each
   staged package's packed `files`, the VZ helper exec bit, and the per-package
   size ceiling. (Re-runnable.)
6. **Upload release assets** — `gh release` upload of the rootfs/kernel/shim/
   helper/dist assets. (Re-runnable: re-uploading overwrites.)
7. **`npm publish` LAST** — the **only non-re-runnable step**. A version that
   has already been published cannot be re-published. Because it is last, every
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
published, recovery is to re-run only the still-unpublished packages or bump the
version and re-tag — there is no in-place fix for an already-published version.

---

## Phase 2 — backfill → `v0.1.1`

After `v0.1.0` has published, the job summaries hold the real SHAs and image
digests. Backfill them and cut the second tag.

1. **Paste the real values into `src/action/artifact-manifest.ts`.** Copy the
   **9 file SHAs** (3 `expected.linux` + 6 `expected.darwin`) and the
   **4 Docker digests** (2 `dockerImages.x64` + 2 `dockerImages.arm64`) from the
   `v0.1.0` job summaries, replacing every `PLACEHOLDER_SHA256_*` token.
2. **Set `tag` to `'v0.1.1'`** in the same file.
3. **All-or-nothing across all 13 entries.** A manifest with SOME real values
   and SOME placeholders is a packaging bug and is rejected by
   `check-publish-artifacts.sh` (the mixed-manifest gate:
   `[ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]` → `exit 1`). The
   classification spans **all 13 pinned entries — the 9 file SHAs AND the 4
   Docker digests** — folded into one `PLACEHOLDER_COUNT` / `REAL_COUNT` tally.
   Pasting the real file SHAs while leaving the Docker refs as placeholders (or
   vice versa) trips the reject. Replace every placeholder, or none. (File SHAs
   are matched by the `PLACEHOLDER_SHA256_` prefix; a Docker ref instead carries
   that token inside its `@sha256:` digest position, so refs are matched by the
   placeholder substring — but both feed the same tally.)
4. **Bump all versions to `0.1.1`** — the main `package.json` and the platform
   package versions, to satisfy the version==tag gate at the next tag.
5. **`pnpm build:bundle`** to re-embed the updated manifest into
   `dist/main.cjs` (the Action consumes the manifest from the bundled bytes, not
   from `src/`), and commit the regenerated bundle.
6. **Verify the pinned Docker digests actually resolve in GHCR.** The release
   workflow hard-gates this automatically — the *Verify pinned Docker digests
   resolve in GHCR (backfill gate)* step in `release.yml` runs `docker buildx
   imagetools inspect` on every real `dockerImages` ref **before any `npm
   publish`** and fails the release on a missing or mistyped digest. (The Docker
   rootfs images are NOT byte-reproducible, so the gate asserts the pinned digest
   **exists** in GHCR, not that a re-push would reproduce it.) Bootstrap
   placeholders are skipped. Sanity-check locally before tagging, e.g.
   `docker buildx imagetools inspect ghcr.io/brooooooklyn/script-jail-rootfs:ubuntu-24.04@sha256:<digest>`
   for each of the 4 refs — a hand-copy typo from the job summary is the failure
   this catches.
7. **Green CI, then push `v0.1.1`.**

### Why the `v0.1.1` build reproduces `v0.1.0`'s SHAs (R1 — true cross-run reproducibility)

The `v0.1.1` backfill only works if a rootfs ext4 built weeks later, on a
different runner, hashes to the EXACT bytes `v0.1.0` released. That is not free —
it is engineered, and the early R1 attempt missed three drift sources that this
build now pins:

1. **Pinned per-arch Ubuntu base digest.** The Dockerfile's `FROM` resolves
   `ubuntu@sha256:…` (not a floating `ubuntu:<major>` tag) from the per-arch
   `UBUNTU_BASE_DIGEST` map in `src/rootfs/build.ts`. It is threaded into BOTH
   paths: the local rootfs build (`buildDockerBuildArgs` → `--build-arg
   UBUNTU_REF=…`) and the GHCR publish (the `build_one` helper in `release.yml`
   reads the same map and passes `--build-arg UBUNTU_REF=…`), so the ext4s and
   the published Docker images share one base.

2. **Frozen apt snapshot.** The Dockerfile repoints apt at
   `snapshot.ubuntu.com/.../${UBUNTU_SNAPSHOT}` (default
   `UBUNTU_SNAPSHOT=20260501T000000Z`), which serves the archive state as-of
   that UTC instant, so `apt-get install` resolves the SAME package versions on
   every run instead of whatever the live mirrors currently carry. Because the
   snapshot's `Release` files carry an old `Valid-Until`, apt is told
   `Acquire::Check-Valid-Until "false"` so it does not reject them as expired.

3. **Pinned mkfs layout.** `mkfs.ext4` no longer inherits the runner host's
   `/etc/mke2fs.conf` or e2fsprogs compiled-in defaults: the checked-in
   `src/rootfs/mke2fs.conf` is pointed at via `MKE2FS_CONFIG` (`mkfsEnv()`),
   and `buildMkfsExt4Args` pins the size-dependent geometry the conf cannot
   express — `-b 4096 -I 256`, a fixed `-U`/`-E hash_seed` (the
   `ROOTFS_FIXED_UUID`), and `-O ^has_journal,^metadata_csum_seed` (no journal,
   and the metadata-checksum seed derives from the pinned UUID rather than an
   independent random seed). `SOURCE_DATE_EPOCH` plus the `debugfs` mtime-
   normalize post-pass clamp every timestamp to a fixed instant.

**The authoritative cross-run gate is `check-publish-artifacts.sh`.** At
`v0.1.1` the manifest is fully real (no longer all-placeholder), so the script
takes its strict path: it recomputes the SHAs of the freshly-built artifacts and
compares them against the pinned `v0.1.0` values you just pasted in. If
reproduction fails — any of the three pins above regressed — the SHAs diverge,
the comparison fails LOUD, and the publish is blocked rather than shipping a
manifest whose pinned SHAs do not match the bytes consumers will download.

The same-run "Assert x64 rootfs ext4s are byte-reproducible (ubuntu-24.04,
ubuntu-22.04)" step in `release.yml` (now covering BOTH x64 majors) is an early
smoke test, not the authoritative gate: it rebuilds each x64 rootfs in place and
asserts the two ext4s are byte-identical WITHIN one run, catching a reproduc-
ibility regression before the slower publish job. arm64 reproducibility is left
to the authoritative cross-run comparison above (rebuilding arm64 in-run would
need slow qemu).

**Refresh knobs (both change the released SHAs, so a refresh forces a new
backfill):**

- **`UBUNTU_SNAPSHOT`** — the apt snapshot date, the `ARG UBUNTU_SNAPSHOT`
  default in `src/rootfs/Dockerfile.base`. Bump it to a newer in-the-past UTC
  instant to pick up newer package versions.
- **`UBUNTU_BASE_DIGEST`** — the per-arch base-image digests in
  `src/rootfs/build.ts`. Re-resolve with `docker buildx imagetools inspect
  ubuntu:<major> --raw` (per-`linux/<arch>` manifest digest, not the index
  digest) and update both arches.

All of this is validated in CI on a real Linux runner — the snapshot resolution,
the mkfs layout, and the byte-identity guards cannot be exercised on macOS
(which has no native `mkfs.ext4` / `debugfs`).

---

## Works / degraded matrix

What is usable at each tag, and why.

| Target | v0.1.0 | v0.1.1 | Why |
| --- | --- | --- | --- |
| macOS-arm64 CLI | **WORKS** | WORKS | Manifest-independent — the CLI never calls `validateManifest`, so placeholder SHAs do not gate it. |
| Linux bare CLI | **WORKS** | WORKS | Bare backend fetches the shim directly; no manifest gate in the CLI path. |
| Linux firecracker CLI | **WORKS*** | WORKS* | Works where `/dev/kvm` + a tap device exist; otherwise `backend: auto` falls through to another backend. |
| Linux docker CLI | **DEGRADED** | WORKS | See below — usable day-one with a warning via the tag-fallback path. |
| GitHub Action | **BROKEN** | WORKS | The Action fail-fasts on a placeholder manifest; recovers once real SHAs are pinned. |

### macOS-arm64 CLI = WORKS day-one

The CLI never validates the pinned manifest: `src/cli/index.ts` does NOT call
`validateManifest(`. The macOS path resolves its artifacts from the installed
`@script-jail/darwin-arm64` package, not from the manifest's SHAs, so it is
fully usable at `v0.1.0` even while the manifest is all placeholders.

### Linux docker CLI = DEGRADED on v0.1.0 (usable with a warning)

On `v0.1.0` the manifest's Docker ref is a **non-empty placeholder**
(`...@sha256:PLACEHOLDER_...`). `resolveDockerImageRef` only throws
`BackendUnavailableError` when there is NO entry for the `(arch, runnerImage)`
pair; a non-empty placeholder is not "missing", so the function **returns** it
rather than throwing. With the Action's default behavior the failure would
surface later, at the actual `docker pull` of an unresolvable digest. The CLI
passes `allowTagFallback: true`, which downgrades the placeholder digest ref to
its tag-only form (`split('@')[0]`) and emits a warning, making the docker
backend usable on day-one — pulling by tag instead of by pinned digest.

### GitHub Action = BROKEN on v0.1.0

The Action hard-fails before doing any work: `doValidateManifest(PINNED_MANIFEST)`
runs as the first real statement of `main()` (skipped only under the
`SCRIPT_JAIL_E2E_SELF_TEST` self-test bypass this repo's own CI sets), and a
placeholder manifest fails that gate. The README Status section documents this
state. The Action recovers at `v0.1.1` once the real SHAs are pinned.

---

## Appendix — claim → source cross-check

Stable strings are used in the prose above; the raw line numbers below are a
snapshot and may drift — re-grep before relying on them.

| Claim | Source | Line (snapshot) |
| --- | --- | --- |
| Action fail-fast manifest gate | `src/main.ts` — `doValidateManifest(PINNED_MANIFEST)` | 121 |
| self-test bypass skips the gate | `src/main.ts` — `SCRIPT_JAIL_E2E_SELF_TEST` | 108 |
| backend map (CLI/Action backend wiring) | `src/main.ts` — `const backends: BackendMap = {` | 180 |
| CLI skips the manifest | `src/cli/index.ts` — no `validateManifest(` call | n/a |
| mixed-manifest reject condition | `scripts/check-publish-artifacts.sh` — `[ "$PLACEHOLDER_COUNT" -gt 0 ] && [ "$REAL_COUNT" -gt 0 ]` | 494 |
| mixed-manifest reject (comment header) | `scripts/check-publish-artifacts.sh` — `This is a packaging bug` | 496 |
| all-or-nothing spans 9 files + 4 docker | `scripts/check-publish-artifacts.sh` — `The 4 Docker image refs participate in the SAME all-or-nothing` | 389 |
| docker tag-fallback / placeholder handling | `src/action/backend/docker.ts` — `resolveDockerImageRef` | 218 |
| pinned manifest (repo/tag/counts) | `src/action/artifact-manifest.ts` — `PINNED_MANIFEST` | 44 |
| Ubuntu base digest pinned (UBUNTU_REF) | `src/rootfs/build.ts` — `UBUNTU_BASE_DIGEST` / `buildDockerBuildArgs` | 152 / 184 |
| frozen apt snapshot | `src/rootfs/Dockerfile.base` — `ARG UBUNTU_SNAPSHOT` / `Acquire::Check-Valid-Until "false"` | 24 / 92 |
| pinned mkfs layout | `src/rootfs/build.ts` — `buildMkfsExt4Args` / `mkfsEnv` (`MKE2FS_CONFIG`) + `src/rootfs/mke2fs.conf` | 850 / 895 |
| GHCR publish pins same UBUNTU_REF | `.github/workflows/release.yml` — `Pin the GHCR build's base image` / `--build-arg "UBUNTU_REF=…"` | 544 / 580 |
| same-run reproducibility smoke test | `.github/workflows/release.yml` — `Assert x64 rootfs ext4s are byte-reproducible` | 281 |
| authoritative cross-run gate (strict SHA compare) | `.github/workflows/release.yml` — `Verify downloaded artifacts against tagged manifest` → `check-publish-artifacts.sh` | 480 |
| OIDC trusted publish (npm upgrade, no token) | `.github/workflows/release.yml` — `Upgrade npm for OIDC trusted publishing` (`npm install -g npm@11.16.0`) + publish job `id-token: write` | 473 / 427 |
| publish step names + multi-package order | `.github/workflows/release.yml` — "Stage npm packages" / "Validate npm packlists" / "Publish npm packages (platform-first, main last)" | 697 / 723 / 759 |

**dist note.** `release.yml` does NOT gate on committed-`dist/` freshness — it
has no git-diff drift check. It verifies the build-job-produced `dist/main.cjs` /
`dist/cli.cjs` *content* via `check-publish-artifacts.sh` (the `--dist-source` /
`--dist-cli-source` arguments). The freshness gate — that the committed `dist/`
matches a fresh rebuild of `src/` — is `test.yml`.

# Parity testing

The parity workflow (`.github/workflows/parity-test.yml`) verifies that the
`.script-jail.lock.yml` produced by:

- **Linux** running the action under real Firecracker on `ubuntu-24.04-arm`
  (arm64 guest), and
- **macOS** running the CLI under real Virtualization.framework (arm64 guest)

are byte-equal — modulo the canonicalised volatile fields (`generated_at`,
`manager_lockfile_sha256`) — for a pinned upstream fixture.

The fixture lives in [`test/parity/fixture.yml`](../test/parity/fixture.yml)
and pins [`vuejs/core`](https://github.com/vuejs/core) at a specific tag +
commit SHA.

## Why this exists

`script-jail`'s entire value proposition is "the lockfile generated locally
on macOS is identical to what CI would produce on Linux." That promise is
load-bearing for the developer loop:

```
$ pnpm exec script-jail update     # macOS dev
$ git add .script-jail.lock.yml
$ git commit && git push
$ # CI runs the action in `check` mode against the committed lockfile.
```

If the macOS and Linux pipelines drift, the developer ships a lockfile that
CI rejects on the next PR — defeating the local-dev path. The parity test
is the regression gate that catches that drift before a release goes out.

## Why `vuejs/core`

The fixture choice deliberately stresses the pieces most likely to diverge:

- **pnpm monorepo** with 28+ workspace packages — exercises the real fetch
  graph and the per-workspace install ordering, not a trivial one-package
  smoke.
- **Heavy native postinstall** — `esbuild` self-verify, `rollup` per-arch
  optional deps, the Vite toolchain. These are the exact code paths that
  previously diverged under Linux/x64 CI vs local arm64; the workflow now
  runs Linux CI on arm64 so native package selection should match the local
  VZ guest.
- **Stable upstream**. Vue's release cadence is slow enough that a pinned
  tag stays meaningful across script-jail releases; the parity baseline
  doesn't churn weekly.

## Pipeline architecture

```
                ┌──────────────────────────┐
                │  resolve-fixture         │
                │  (reads test/parity/...) │
                └────┬─────────────────────┘
                     │   repo + sha + tag + pm
        ┌────────────┼──────────────────────┐
        ▼            ▼                      ▼
  linux-firecracker        committed macos-arm64-vz lockfile
  (real action +           (generated locally on bare-metal
   arm64 Firecracker        Apple Silicon; nested VZ cannot
   on ubuntu-24.04-arm)     run on GitHub-hosted macOS)
        │                          │
        └────────────┬─────────────┘
                 ▼
              diff
   (parity-diff.ts → parity-report.md)
   (advisory report when streams differ)
```

Each platform job runs the same code path a real consumer would:

- **Linux** runs on `ubuntu-24.04-arm`, sets up Firecracker the same way
  `e2e.yml` does (chmod `/dev/kvm`, create `tap0`, enable NAT), builds the
  arm64 rootfs, and invokes the action by setting `INPUT_*` env vars and
  running `node dist/main.cjs`.
- **macOS** is committed rather than generated in CI. A maintainer runs the
  CLI's `update` subcommand locally on bare-metal Apple Silicon and commits
  `test/parity/macos-arm64-lockfile.yml`.

Both produce a `.script-jail.lock.yml`. The `diff` job downloads the fresh
Linux lockfile, canonicalises the volatile fields on both sides, and compares.

## Interpreting the parity report

`scripts/parity-diff.ts` emits a markdown report. Before comparing, it
canonicalizes the volatile header fields and filters known parity-only
host/VMM noise such as ambient CI env probes and the local VZ DNS resolver.
It does not hide native executable divergence. Three cases:

### ✅ Parity holds

The lockfiles are byte-equal after canonicalisation. Ship it.

### ❌ Diverged — explainable

`docs/divergence.md` enumerates remaining parity-only differences. After the
move to arm64 CI, native package-selection mismatches should no longer be the
default explanation; first suspect ambient environment reads, VMM-specific
device/procfs differences, or a stale committed macOS lockfile.

### ❌ Diverged — unexpected

Anything else is a bug. Common shapes:

- **An `env_read` event appears on one side and not the other** → audit
  policy desync between the action's pre-fetch path and the CLI's
  artifact-resolution path. Check `src/cli/index.ts`'s call into
  `buildEffectiveConfig` against the action's call site.
- **Event ordering differs** → renderer non-determinism. The lock renderer
  in `src/lock/render.ts` sorts by codepoint order; check that both jobs
  produce the same input stream to `renderLock`.
- **A package shows up on one side but not the other** → package-manager
  resolution desync. The Linux and macOS sides should both resolve arm64
  Linux optional packages now; check whether an input override, stale
  committed lockfile, or package-manager environment read changed the target.

## Triggering the workflow

```bash
# Manual:
gh workflow run parity-test.yml

# Watch the most recent run:
gh run watch
```

The workflow also runs automatically on PRs that touch the parity-relevant
surface (CLI, shared utilities, guest agent, host-mac crate, lock schema,
artifact builds, kernel build, and the parity infrastructure itself).
Other PRs skip it — the workflow is heavy (~25 min wall clock) and the
ordinary `test.yml` matrix is enough for unrelated changes.

## Bumping the fixture pin

Vue releases on a regular cadence; the pin should be refreshed periodically
to ensure the parity test exercises current upstream behaviour:

```bash
# Pick the new tag — usually the latest stable (not a beta):
gh api repos/vuejs/core/releases/latest | jq -r '.tag_name'

# Resolve to a commit SHA so a force-pushed tag can't retroactively change
# what the test audits:
gh api repos/vuejs/core/git/refs/tags/<tag> | jq -r '.object.sha'

# Edit test/parity/fixture.yml, update `tag` and `sha`.
# Trigger the workflow.  If divergence appears that wasn't there before,
# investigate before merging the bump — the new tag may have introduced a
# postinstall script that exercises a code path we handle non-uniformly.
```

## Known limitations

- **Intel Mac coverage** is deferred — GitHub-hosted Intel macOS runners
  are deprecated. Once a self-hosted Intel runner is available, a third
  job (`macos-x64-vz`) would extend the matrix without re-architecting
  this workflow. Intel parity would catch a different bug class
  (Rosetta-equivalent native exec) that the arm64 path filters out via
  package-selection.
- **The workflow depends on KVM on the arm runner** — `ubuntu-24.04-arm`
  gives the right CPU architecture, but Firecracker still requires `/dev/kvm`.
  The workflow probes it explicitly and fails with a clear error if the runner
  image changes.
- **No caching** — every run builds rootfs, kernel, and shim from scratch
  (~15 min upfront). Once the fixture pin and the build inputs stabilise,
  `actions/cache@v4` keys derived from `git rev-parse HEAD:images/` and
  the kernel build script's SHA would shave ~10 min per run.

# Parity testing

The parity workflow (`.github/workflows/parity-test.yml`) verifies that the
`.script-jail.lock.yml` produced by:

- **Linux** running the action under real Firecracker (x86_64 guest), and
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
  optional deps, the Vite toolchain. These are the exact code paths where
  cross-arch divergence is expected on Apple Silicon (the postinstall tries
  to `execve` an x86_64 binary downloaded by the `--cpu=x64` PM overlay, and
  ENOEXEC on the arm64 guest).
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
  linux-firecracker  macos-arm64-vz   build-mac-arm64-artifacts
  (real action +     (real CLI +       (arm64 rootfs, .so,
   Firecracker)       VZ on macos-      vmlinux-vz-arm64)
                      latest, depends
                      on the artifact
                      job)
        │            │
        └────────┬───┘
                 ▼
              diff
   (parity-diff.ts → parity-report.md)
   (fails workflow when streams differ)
```

Each platform job runs the same code path a real consumer would:

- **Linux** sets up Firecracker the same way `e2e.yml` does (chmod
  `/dev/kvm`, create `tap0`, enable NAT) and invokes the action by setting
  `INPUT_*` env vars and running `node dist/main.cjs`.
- **macOS** builds the CLI (`pnpm build:cli`) and the host-mac Rust binary
  (`cargo build --release -p script-jail-host-mac`), downloads the arm64
  rootfs / shim / VZ kernel from `build-mac-arm64-artifacts`, then runs
  the CLI's `update` subcommand against the Vue checkout.

Both produce a `.script-jail.lock.yml`. The `diff` job downloads both,
canonicalises the two volatile fields, and compares.

## Interpreting the parity report

`scripts/parity-diff.ts` emits a markdown report. Before comparing, it
canonicalizes the volatile header fields and filters known parity-only
host/VMM noise such as ambient CI env probes and the local VZ DNS resolver.
It does not hide native executable divergence. Three cases:

### ✅ Parity holds

The lockfiles are byte-equal after canonicalisation. Ship it.

### ❌ Diverged — explainable (v1 known-divergence)

`docs/divergence.md` enumerates the cases where v1 deliberately produces a
different lockfile on Apple Silicon than on Linux CI:

- A package whose postinstall `execve`s a downloaded x86_64 binary will
  emit a `spawn` event with `result: enoent`/`eacces` on the arm64 guest
  and `result: ok` on the Linux x86_64 guest.
- A package that loads or execs an x86_64 native artifact may produce
  different file-read or spawn shapes on an arm64 guest. Native addon loading
  is not blocked by default; the parity question is whether the resulting
  platform-specific file/exec surface is expected for that package.

These cases are real divergence; they are flagged in the parity report and
the maintainer reads the diff to confirm every divergent event is in this
expected category. **Today this judgment is manual.** Future work in
`scripts/parity-diff.ts` will add a `--allow-arm64-enoexec` filter that
strips events matching the documented pattern from the arm64 side before
comparison, turning the maintainer's judgment into a workflow gate.

### ❌ Diverged — unexpected

Anything else is a bug. Common shapes:

- **An `env_read` event appears on one side and not the other** → audit
  policy desync between the action's pre-fetch path and the CLI's
  artifact-resolution path. Check `src/cli/index.ts`'s call into
  `buildEffectiveConfig` against the action's call site.
- **Event ordering differs** → renderer non-determinism. The lock renderer
  in `src/lock/render.ts` sorts by codepoint order; check that both jobs
  produce the same input stream to `renderLock`.
- **A package shows up on one side but not the other** → PM-flag overlay
  bug. The arm64 side should select identical packages to the x86_64 side
  thanks to `--cpu=x64 --os=linux --libc=glibc`. If a package is missing
  from the arm64 lockfile, `src/cli/arch-flags.ts` or
  `src/guest/load-pm-flags.ts` is dropping the flag somewhere.

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
- **The cross-arch divergence filter is not yet automated** — see the
  "Diverged — explainable" subsection above. The first few real parity-
  test runs are expected to produce divergent diffs; reading them is how
  we learn the filter rules to encode in v2 of `parity-diff.ts`.
- **No caching** — every run builds rootfs, kernel, and shim from scratch
  (~15 min upfront). Once the fixture pin and the build inputs stabilise,
  `actions/cache@v4` keys derived from `git rev-parse HEAD:images/` and
  the kernel build script's SHA would shave ~10 min per run.

# Parity testing

The parity workflow (`.github/workflows/parity-test.yml`) verifies that the
`.script-jail.lock.yml` produced by:

- **Linux** running the action backend on `ubuntu-24.04-arm`
  (`backend: auto`, normally Docker on hosted runners) — generated fresh on
  every run, and
- **macOS/VZ** running the CLI under real Virtualization.framework (arm64
  guest) — a **committed** baseline (`test/parity/macos-arm64-lockfile.yml`),
  since nested VZ cannot boot in CI, and
- **macOS-bare** running the CLI's `update --backend bare` natively on a hosted
  `macos-14` runner (no VM) — generated fresh on every run

are byte-equal — modulo the canonicalised volatile fields (`generated_at`,
`manager_lockfile_sha256`) — for a pinned upstream fixture. The fresh Linux
lockfile is diffed against **both** macOS sides: against the committed VZ
baseline (the `diff` job) and against the fresh macOS-bare lockfile (the
`diff-macos-bare` job).

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
              ┌───────────┴────────────┐
              ▼                        ▼
        linux-backend             macos-bare
        (real action +            (CLI update --backend
         auto backend on           bare, NATIVE on a
         ubuntu-24.04-arm)         hosted macos-14, no VM)
              │   │                    │
              │   └──────────┬─────────┘
              │              ▼
              │         diff-macos-bare
              │   (linux vs fresh macos-bare,
              │    both generated this run)
              ▼
            diff
   (linux vs committed macos-arm64-vz
    lockfile — generated locally on
    bare-metal Apple Silicon; nested
    VZ cannot run on GitHub-hosted macOS)
   (both: parity-diff.ts → report.md;
    fail when streams differ)
```

Each platform job runs the same code path a real consumer would:

- **Linux** runs on `ubuntu-24.04-arm`, builds the action bundle plus arm64
  rootfs/Docker image, and invokes the action by setting `INPUT_*` env vars
  and running `node dist/main.cjs`. Hosted arm64 runners do not expose KVM, so
  `backend: auto` normally selects Docker after the Firecracker availability
  check fails.
- **macOS/VZ** is committed rather than generated in CI. A maintainer runs the
  CLI's `update` subcommand locally on bare-metal Apple Silicon and commits
  `test/parity/macos-arm64-lockfile.yml`.
- **macOS-bare** is **CI-native**: the `macos-bare` job runs on a hosted
  `macos-14` runner and invokes the CLI's `update --backend bare` directly. The
  bare backend needs no VM — it runs the install on the host under the Mach-O
  shim via `DYLD_INSERT_LIBRARIES` — so it boots fine on a hosted runner, unlike
  the VZ path, which cannot run in CI because GitHub-hosted macOS runners are
  themselves virtualized and Apple's Virtualization.framework does not nest.
  This is the first macOS parity gate generated fresh in CI on both sides.

All three produce a `.script-jail.lock.yml`. The `diff` job downloads the fresh
Linux lockfile and diffs it against the committed VZ baseline; the
`diff-macos-bare` job diffs the same fresh Linux lockfile against the fresh
macOS-bare lockfile. Both jobs run `scripts/parity-diff.ts`, which canonicalises
the volatile fields on both sides and reconciles the documented platform
plumbing differences enumerated in [`docs/divergence.md`](./divergence.md)
(injection/provisioning env, libSystem/CoreFoundation runtime probes, the SIP
`<AUDIT_BLIND>` git framing, and the intrinsically platform-divergent package
set). Either job fails the workflow if any diff remains after the parity-only
filters.

## Interpreting the parity report

`scripts/parity-diff.ts` emits a markdown report. The comparison is
**structural**: each lock is parsed, validated against a fully `.strict()` parity
schema (`ParityLock`, built on `src/lock/schema.ts`), danger-walked, then the
divergent packages are dropped and the parity-only noise filtered **on the parsed
structure**, and the result is re-rendered through the canonical byte-stable
serializer (`src/lock/render.ts`) before the two renders are diffed. It fails
closed if either lock is malformed, carries an unknown field or top-level
section, uses a YAML alias/anchor/merge key, or does not parse — the parser and
the strip/filter operate on the same structure, so they cannot disagree. The
volatile header fields (`generated_at`, `manager_lockfile_sha256`) are normalised
before rendering; known parity-only host/VMM noise (ambient CI env probes, the
local VZ DNS resolver) is filtered out. Those env/read/resolver waivers are
global (ambient harness noise, read in every package); the benign-spawn waivers
are scoped to the exact package they belong to, so an unrelated package cannot
launder them. It does not hide native executable divergence. Four outcomes:

### ✅ Parity holds

The lockfiles are byte-equal after canonicalisation. Ship it.

### ❌ Diverged — explainable

`docs/divergence.md` enumerates remaining parity-only differences. After the
move to arm64 CI, native package-selection mismatches should no longer be the
default explanation; first suspect ambient environment reads, VMM-specific
device/procfs differences, or a stale committed macOS lockfile.

Explainable divergence is still a CI failure. Add or update the narrow filter
in `scripts/parity-diff.ts`, or regenerate the committed macOS baseline when the
lockfile change is intentional.

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

### 🚨 Danger — a blocking signal the gate refuses to launder

The report carries a **danger table** (and the job log prints a `!! DANGER`
block) for any signal that must never pass as parity even when the comparable
text is byte-equal. There are four shapes:

- **Escape hidden in an excluded package.** A suspicious signal inside one of the
  intrinsically platform-divergent packages otherwise excluded from the byte
  comparison (`@swc/core`, `puppeteer`, `unrs-resolver` — see
  [`docs/divergence.md`](./divergence.md)). The exclusion is screened per side by
  `collectDivergentDangers`: a non-events-file escaped write, a `<HIDDEN>` **or
  credential-named** env read (matched by credential SHAPE, not a name list —
  case-insensitive substrings `TOKEN`/`SECRET`/`PASSWORD`/`CREDENTIAL`/
  `AUTHORIZATION`/`PRIVATEKEY`/`BEARER`/… plus whole-token `AUTH`/`KEY`/`PAT`, so
  `github_token`, `npm_config__authToken`, `NPM_AUTH`, `DOCKER_AUTH_CONFIG`,
  `SERVICE_ACCOUNT_KEY`, `GITHUB_PAT` hit while the benign `npm_config_always_auth`,
  `…UNAUTHORIZED`, `*_PATH`, `MONKEY` do not), a `<HIDDEN>`/sensitive file read
  (case-insensitive, segment/suffix-aware — the default protected set
  `.ssh`/`.aws`/`.npmrc`/`.gnupg`/… plus cloud-CLI / package-manager stores
  `.config/gcloud`/`.azure`/`.kube`/`.git-credentials`/`.pypirc`/`.cargo/credentials`/
  composer `auth.json`/NuGet config and key-file suffixes `.pem`/`.p12`/`.pfx`/`.key`),
  a non-resolver or *succeeded* connect, any
  `dlopen`/`audit_bypass`/`env_tamper`, or a spawn outside that package's benign
  allowlist.
- **One-sided divergent package or stage.** A divergent package present on only
  one side, *or* present on both but with a one-sided / mismatched lifecycle stage
  (`field: divergent_presence`). The block is excluded from the byte comparison,
  so a one-sided absence — or a `lifecycle: {}` / wrong-stage block — would
  otherwise pass silently; it is a resolution/producer desync and fails the gate,
  naming the side (and stage) it is missing from.
- **Malformed / unknown shape.** A lock that fails the strict parity schema
  (`field: schema`) — a non-array field, an unknown lifecycle field, an unknown
  sibling next to `lifecycle`, or an unknown **top-level section**.
- **Structural feature.** A lock that uses a YAML alias, anchor, merge key, a
  non-string mapping key, `__proto__`, or a mapping key containing a control
  character such as TAB (`field: structure`), or one that does not parse
  (`field: yaml`). The canonical renderer never emits any of these, so a
  conformant lock has none; the control-char rejection in particular keeps a key
  from forging a package→stage presence composite.

This is **never** routine noise — treat it as a real audit signal. Inspect the
named package and side first; do not "fix" it by widening the benign allowlist
unless you have confirmed the new spawn/read is genuinely part of that package's
pinned-version install.

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
- **The workflow no longer depends on KVM on the arm runner** —
  `ubuntu-24.04-arm` gives the right CPU architecture, and the backend selector
  falls through to Docker when `/dev/kvm` is absent.
- **No rootfs/shim/Docker image cache** — every arm parity run builds the
  arm64 action bundle, shim, rootfs, and Docker image from source. Hosted arm
  runners normally use the Docker backend rather than booting Firecracker, so
  the job no longer depends on a freshly built Firecracker kernel, but the
  guest artifacts still dominate runtime. `setup-node` caches pnpm packages;
  artifact-level caching is still deferred.

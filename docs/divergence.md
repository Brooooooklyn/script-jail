# Known divergence

The macOS Virtualization.framework runner produces audit lockfiles that aim
for byte-for-byte parity with the Linux Action backend. The parity workflow
now runs Linux CI on `ubuntu-24.04-arm`; on hosted runners `backend: auto`
falls through to Docker because KVM is unavailable. Both sides still use a
Linux/arm64 audit environment.

Known host/backend noise is either removed before rendering or filtered by
`scripts/parity-diff.ts`. A remaining diff is a CI failure. The TL;DR: if your
`.script-jail.lock.yml` differs between macOS and Linux CI, check the cases
below before treating it as a product bug.

## Why divergence is possible

Even with the same guest architecture, rootfs family, vsock agent, and
package-manager binary, a few signals leak through the VM boundary and break
determinism across hosts:

- **Ambient environment.** GitHub Actions sets CI variables and runner
  metadata that a local macOS generation does not have. The guest filters
  known Node/bootstrap reads, npm/yarn/pnpm client reads, and selected CI
  noise, but a new package-manager version can still introduce a new probe
  that needs a narrow filter or a regenerated baseline.

- **Backend/device surface.** Firecracker, Docker, bare Linux, and
  Virtualization.framework expose different device and procfs/sysfs shapes.
  Most package installs do not inspect these, but a native postinstall can.

- **`install: true` audit cwd (cwd-detection parity).** Under `install: true`
  the host re-runs lifecycle scripts at the real repoDir, so the audit aligns its
  cwd to match: **Firecracker/Docker** pin the guest `work_dir` to `${repoDir}`
  (Docker `-v staged:${repoDir}`; Firecracker `mount --move`s the repo disk there
  in `init.sh`, falling back to a `/work` audit if the move fails). The
  **`bare`/`mac-bare`** backends audit at a staged temp path and do **not** align,
  so under `install: true` their `process.cwd()` differs from the host re-run — a
  cwd-detection residual. Firecracker is the enforcement boundary; a payload that
  branches on `process.cwd()` would be caught there, recorded as a host-vs-sandbox
  cwd parity only on FC/Docker. Either way this is defense-in-depth, not a complete
  sandbox guarantee — see the `install: true` trust model in
  [docs/design.md](./design.md#drop-in-install-trust-model-install-true).

- **`install: true` yarn-Berry `yarnPath` (repo-toolchain trust; audit and host both run the registry yarn).**
  The pre-trust gate (`src/action/install-preflight.ts`) **allows `install: true` for a
  repoDir-own committed `yarnPath`** (one resolving INSIDE repoDir, i.e. the repo's own
  `.yarn/releases/yarn-*.cjs`). This is an **owner trust decision**: the repo's own committed
  yarn toolchain is trusted (the repo is CI's trust root, not dependency code), the same class
  as a committed lifecycle script. Still **refused**: an *ancestor* `yarnPath` (never staged
  into the sandbox → would run unaudited), an *escaping*/out-of-repo `yarnPath`, and
  `.yarnrc.yml` `plugins:` / `enableConstraintsChecks`+`yarn.config.cjs` (these execute repo
  code at yarn startup and remain refused; relaxable per-consumer if ever needed).

  **Audit == host because both ignore `yarnPath`.** Under `install: true` the guest sets
  `YARN_IGNORE_PATH=1` in its yarn launch env for **both** phases (`buildChildEnv` install-mode
  pins), exactly like `hostInstallEnv` does on both host phases. A direct `node yarn.js` re-execs
  `yarnPath` UNLESS `YARN_IGNORE_PATH=1` (verified, yarn 4.17.0), so without this the guest would
  audit the repo-VENDORED yarn while the host ran the REGISTRY yarn — an audit-vs-host divergence
  that could hide dependency lifecycle behavior. With it, **both** the audit (guest Phase A fetch
  + Phase B install) and the host install (part-1 + part-2) run the corepack/registry yarn pinned
  by `packageManager`, ignoring the vendored `yarnPath` entirely. The repo-vendored binary is
  therefore never executed by script-jail on this path, so the gate allowing a repoDir-own
  `yarnPath` is sound (it is inert — both sides ignore it) and no dependency action can hide in a
  vendored-vs-registry gap. (`YARN_IGNORE_PATH=1` is install-mode-ONLY: pure `mode: check`, which
  has no host install to diverge from, audits the repo's yarn as-is and is unchanged.) The gate
  ALSO requires an exact `packageManager: "yarn@<version>"` pin for a contained `yarnPath`, so the
  guest audit and a corepack-shim host both corepack-resolve the SAME version (without it the guest
  would corepack-default to yarn 1.22.x for a Berry repo — a nonsense audit; verified). A
  non-corepack **standalone** host yarn of a different version is NOT closed by the pin and falls
  under the *install: true host package-manager VERSION* residual immediately below (runner-image
  controlled, NOT PR-controllable, Firecracker-enforced). Residual (accepted, benign):
  script-jail audits+installs with the registry yarn of the pinned version, not the repo's exact
  vendored file; for the normal case (an unmodified `yarn set version` binary) these are the same
  official release, and a repo that *patched* its vendored yarn would have the patch ignored
  **consistently on both sides**. **Firecracker is the enforcement boundary.**

- **`install: true` host package-manager VERSION (defense-in-depth residual).**
  The host lifecycle pass (`src/action/host-install.ts`) runs the
  **runner's** installed `npm`/`pnpm`/`yarn` version — not necessarily the
  corepack-pinned version the guest audit uses inside the sandbox. A lifecycle
  script that branches on the PM version (`npm --version`,
  `process.env.npm_config_user_agent`, a `packageManager`-gated code path)
  therefore sees the runner's version on the host re-run and the corepack-pinned
  one in the audit, so its behaviour can diverge. This is **low severity and not
  PR-controllable**: the runner PM version is owner/runner-image controlled, not
  something a fork PR can set, and it is bounded by the same trust model as the
  rest of the host pass — the host only runs lifecycle scripts whose sandbox
  audit was already clean. **Firecracker is the enforcement boundary**, and this
  is an accepted residual rather than a parity bug.

  The host **bypasses corepack** by direct-launching `node <cached-entry>`
  exactly like the guest (commit 81a0747 / `resolveLinuxManagerLaunch`): when the
  bare `pnpm`/`yarn` on the runner is a corepack shim (or corepack has cached a
  version), `hostRunScripts` resolves the offline-cached PM entry from the
  action's corepack cache and spawns `node <entry> …` instead. This keeps
  `COREPACK_ROOT`/`COREPACK_HOME` **absent on both sides** — corepack sets
  `COREPACK_ROOT` *unconditionally* in the lifecycle child before launching a
  managed bin, and env-stripping alone cannot close it (corepack re-sets it inside
  its own process), so the only lever is to not go through corepack. That closes
  the **value-blind oracle** where a dep does `if (process.env.COREPACK_ROOT)
  evil(); else benign();` — benign in the audit (clean lock) but evil on the host.

  The launch resolver inspects the **same sanitized `PATH` and the same default
  corepack cache** the part-1 fetch warmed: `hostRunScripts` builds the child env
  once (`hostInstallEnv(…,'scripts')`) and feeds it to *both* the resolver and the
  spawn, so the corepack-shim probe reads exactly the binary the child execs and
  the cache-root probe reads the stripped default `~/.cache/node/corepack` (part-1
  ran corepack under the same stripped env), not an inherited
  `COREPACK_HOME`/`XDG_CACHE_HOME`. The shim probe matches the verified
  `corepack.cjs` require-target signature only (the bare `corepack`/`runMain`
  substrings were over-broad and could mis-flag a standalone PM).

  Residual: a **standalone (non-corepack) consumer** (e.g. `pnpm/action-setup`)
  bare-launches its own PM, which is safe — it sets no `COREPACK_ROOT`, so the
  guest (no `COREPACK_ROOT`) and host already match. The resolver inspects the bare
  PM the child would exec (first match on the sanitized `PATH`): a **readable,
  non-shim** binary is a *confirmed* standalone PM and bare-launches **even if the
  runner's corepack cache holds a (stale) version of that PM** — a leftover
  `~/.cache/node/corepack` entry from an unrelated prior job must not hijack or
  fail-closed-break a proven standalone install (there is no `COREPACK_ROOT` risk to
  justify overriding it). **npm** routes through the node-bundled `npm-cli.js`
  directly; if that is absent (a node without bundled npm, or one where bare `npm`
  is a `corepack enable npm` shim) the host **fails closed** (throws) — the guest's
  `resolveLinuxManagerLaunch` throws on the same layout, so this is parity-correct,
  not a new divergence. A corepack-managed PM (the bare PM **is** a corepack shim,
  or none is on `PATH`) whose cached entry cannot be resolved **fails closed**
  (throws) rather than bare-launching and re-opening the oracle. This includes the
  **multi-version-no-pin** case: when the bare PM is a corepack shim on a reused/
  self-hosted runner whose corepack cache holds >1 version **and** the repo has no
  `packageManager` pin, the resolver cannot disambiguate which version part-1
  resolved (corepack does **not** write a per-`COREPACK_HOME` `lastKnownGood.json`
  on the project-pin-driven flow — verified corepack 0.35.0), so it fails closed;
  pin `"packageManager"` in `package.json` to resolve it. A corepack-managed
  **yarn@1.x** pin fails closed on **both** host and guest (the resolver expects a
  berry `yarn.js`), again no new host/guest divergence. (The host child env is
  otherwise hardened: `hostInstallEnv` strips inherited loader/config vars —
  `NODE_OPTIONS`, `LD_PRELOAD`/`LD_AUDIT`/`DYLD_*`, `GIT_SSH_COMMAND` and the
  other git transport overrides, `NPM_CONFIG_SCRIPT_SHELL`/`_USERCONFIG`/
  `_GLOBALCONFIG`/`_IGNORE_SCRIPTS` — and sanitizes `PATH` of every
  checkout-controlled dir, so a PR cannot inject pre-trust code or redirect
  tool/config resolution that the audit never saw.)

- **Native binaries the lifecycle script execs directly.** Some scripts
  shell out to a host-provided binary (`python`, `cc`, `make`). Whether the
  VM rootfs ships that binary is a property of the rootfs build, not of the
  VMM. v1 deliberately ships a minimal rootfs (no `gcc`, no `python`); the
  lockfile records the `execve` attempt either way, so this is not a
  divergence the docs need to track.

The old Linux/x64-vs-macOS/arm64 direction deliberately injected
package-manager flags/config to force `linux-x64-glibc` resolution. That has
been removed. `src/cli/arch-flags.ts` is now a no-op compatibility seam, and
both CI and local parity runs should resolve Linux/arm64 optional packages.
If a diff shows `@swc/core-linux-x64-gnu` or `@esbuild/linux-x64` on only one
side, treat that as a bug in action/CLI input defaulting or stale lockfile
generation, not as expected divergence.

- **bun.** Unsupported — `detectPm` throws `BunUnsupportedError` before
  any audit runs. v1 will not add support; the JS-only env hooks bun
  ignores would leave too much unaudited.

## macOS bare backend

`script-jail check --backend bare` on a Mac audits the install **directly on
the host** (no VM, no container). It mirrors the Linux `bare` backend but,
because macOS has no `strace` and no `/proc`, the Mach-O `__interpose` shim is
the **sole** event source. That single difference drives every reconciliation
rule below. The goal is unchanged: one committed `.script-jail.lock.yml` that
reconciles against the Linux Action backend after `scripts/parity-diff.ts`
canonicalization. These are the macOS-specific cases that filter must absorb.

- **SIP-binary substitution (why there is no arm64e dylib).** On Apple Silicon
  the system shells (`/bin/sh`, `/bin/bash`) and coreutils (`/bin/echo`, …) are
  **arm64e**, and dyld refuses to inject a plain-arm64 dylib into an arm64e
  process. Rather than ship a universal arm64+arm64e dylib (which needs a nightly
  `-Z build-std` toolchain), the shim **never runs the arm64e binary**: at exec
  time it rewrites any `/bin`/`/usr/bin` program whose basename is `sh`/`bash`
  to a bundled **from-source bash** (`bash-arm64`), and any uutils applet to a
  bundled **uutils/coreutils** multi-call binary (`coreutils-arm64`) — both plain
  arm64, both ad-hoc signed. `argv[0]` is preserved so bash self-selects sh/bash
  mode and uutils dispatches the right applet. The dylib then loads cleanly into
  the substitute, so script-jail ships a **thin `aarch64-apple-darwin` dylib**.
  Two consequences for divergence:
  - **Audit-blind residual, surfaced as `<AUDIT_BLIND>`.** Any `/bin`/`/usr/bin`
    binary that is *not* a shell or a uutils applet — `sed`, `awk`, `grep`,
    `find`, `xargs`, `which`, `cmp`, `/usr/bin/python3`, `/usr/bin/git`, `perl`,
    `ruby`, … — has no plain-arm64 substitute, so when `sip_redirect` leaves the
    path unchanged the real arm64e binary runs with `DYLD_INSERT_LIBRARIES`
    stripped by SIP: it and its descendants run **un-instrumented** (a malicious
    `find . -exec /bin/sh -c '<exfil>' \;` would otherwise hide the exfil
    entirely). The shim tags such execs `audit_blind`, and `normalize.ts` renders
    them with an **`<AUDIT_BLIND>` prefix in `spawn_attempts`/`spawn_blocked`** so
    the lock diff exposes the blind subtree. This is **informational, not an
    `audit_bypass` hard-fail** — benign `find`/`sed`/`grep` use stays green; a
    reviewer simply sees *which* exec escaped instrumentation and must inspect it.
    Note this is a deliberate **coverage trade of the no-arm64e substitution
    model**, not parity with fspy: the prior re-signing approach *did* instrument
    these tools (via a universal arm64+arm64e dylib), at the cost of a nightly
    `-Z build-std` toolchain. Firecracker remains the high-assurance backend when
    full subtree coverage matters.
  - **External (non-SIP) system tools are also audit-blind.** SIP only strips
    `DYLD_INSERT_LIBRARIES` for `/bin` and `/usr/bin`; a tool resolved to a
    **non-SIP** location — Homebrew (`/opt/homebrew`, `/usr/local`), `/nix`,
    `/Library`, a user's `~/.foo/bin`, etc. — would otherwise **load the dylib**
    and emit *its own* `getenv`/file/connect traffic (e.g. Homebrew `git`'s 20+
    `GIT_*` reads + `$HOME/.gitconfig`) under the spawning package's attribution.
    That is pure macOS-only noise the Linux microVM never produces (Linux records
    only the spawn line for such a tool), so it diverges the lock. The shim
    classifies any exec target resolved **outside every keep-audited root** (the
    provisioned-toolchain root = parent of the shell-shim dir, this process's own
    exec dir, the shell-shim dir, the **live** install cwd, the **immutable** cwd
    snapshotted at ctor before any lifecycle `chdir`, and the **install/repo root**
    `SCRIPT_JAIL_WORK_DIR` = the agent's `config.work_dir`) as an **external system
    tool**: it strips `DYLD_INSERT_LIBRARIES` / `DYLD_FORCE_FLAT_NAMESPACE` /
    `NODE_OPTIONS` / the sticky `SCRIPT_JAIL_*` vars from the child env (so the
    shim never loads into it **or its subtree**) and tags the exec `audit_blind`,
    surfaced as `<AUDIT_BLIND>` exactly like the SIP case above. This **widens the
    blind set** to match the SIP model rather than instrumenting non-SIP tools
    half-way (which produced wrong, package-attributed reads). **Same trade as the
    SIP residual:** a malicious package can run code via an external interpreter
    (`/opt/homebrew/bin/python3 ./postinstall.py`, `perl ./x.pl`, a `git` alias/
    hook) un-instrumented — but the blind subtree is **surfaced** (`<AUDIT_BLIND>`)
    for a reviewer, and **Firecracker is the enforcement boundary**. **Keep-audited
    by design:** the provisioned node + its node-spawned-node children + every
    `node_modules/.bin`/`.pnpm-store`/package-owned binary under the **install
    root** stay instrumented (they are package code Linux audits), so this only
    blinds genuine *system* tools. The install-root anchor (`SCRIPT_JAIL_WORK_DIR`,
    sticky + re-injected) is what keeps a top-level `node_modules/.bin` helper
    audited even when a lifecycle script `chdir`s into a package dir first — such a
    helper is a *sibling* of the per-package cwd, so the live/immutable-cwd anchors
    alone would miss it.
  - **Blind-classification robustness (lexical canon + spawnp PATH search).** The
    `audit_blind` tag and `sip_redirect` both key off the program path, so a
    non-canonical path could dodge them: `/usr/lib/../bin/find` does not byte-match
    `/usr/bin/` yet still execs the real `find`. Before classifying *and* before
    redirect matching, the shim runs a **purely lexical** canonicalizer that
    collapses `.`, `..`, and `//` in **absolute** paths — so `/usr/lib/../bin/find`
    → `/usr/bin/find` is still marked `<AUDIT_BLIND>`, and `/usr/lib/../../bin/sh`
    → `/bin/sh` is still redirected to the bundled bash. `posix_spawnp` with a
    **bare name** (no slash) is run through the same in-process `PATH` search that
    `execvp` uses, so `posix_spawnp("find", …)` resolves to `/usr/bin/find` and is
    marked too. The `sip_redirect` **substitution** match (which swaps `/bin/sh` →
    bundled bash, a coreutil → uutils) is still purely lexical, so a symlink to a
    SIP shell/coreutil is **not** substituted — but it is still caught as an
    external tool (see next).
  - **External-tool classification resolves symlinks (realpath).**
    `is_external_system_tool` — which decides whether to strip DYLD + sticky vars
    and mark `<AUDIT_BLIND>` for a spawn outside every keep-audited root — runs the
    program path through the **real `realpath`** before classifying (adversarial
    review). That both **absolutizes** a relative path (against this process's live
    cwd — exact for an `execve`, which does not change cwd; see the `posix_spawn`
    caveat below) and **resolves symlinks**, so an
    *in-tree* symlink such as `node_modules/.bin/git` → `/opt/homebrew/bin/git` (or
    a relative `./node_modules/.bin/git`) classifies on its TRUE target → EXTERNAL
    → `<AUDIT_BLIND>`, instead of being lexically kept and run shimmed (which would
    leak the tool's reads) or run dyld-stripped-but-unmarked. This does **not**
    false-strip legit package code: pnpm's store is pinned in-tree
    (`--store-dir=${cwd}/.pnpm-store`, under work-dir keep-root #6) so store
    symlinks resolve back under the install root, and the provisioned toolchain
    path has no non-`/private` symlink component (its realpath differs from the
    lexical anchor only by the `/private` bridge the keep-root checks already
    reconcile). **Residuals (accepted, Firecracker is the enforcement boundary):**
    (1) *TOCTOU* — the classifier realpaths the path but the kernel later `exec`s
    the original pathname, so a **concurrent** process racing a symlink swap in the
    tiny classify→exec window can desync the decision; the outcome is fail-closed
    (an external tool kept → macOS-only noise → byte-divergence fails the gate) or
    audit-blind-recorded (an in-tree payload run stripped is still surfaced as
    `<AUDIT_BLIND>`). Closing it fully needs `fexecve` on an O_NOFOLLOW fd, which
    would break the bundled coreutils' argv[0]-based multi-call dispatch. (2)
    *Hardlinks* — `realpath` resolves symlinks, not hardlinks; a same-volume
    hardlink to a system tool's inode placed in-tree would read as in-tree (system
    bins are typically SIP/read-only, so this is narrow). (3) A `realpath` **failure**
    on an **absolute** input falls back to the lexical path — err-toward-keep; that
    exec would generally `ENOENT` too. A failure on a **relative** input does NOT
    strip; `posix_spawn`'s child-cwd ambiguity is handled by chdir tracking instead
    (next bullet).
  - **`posix_spawn` relative-program targets are audit-blind under a tracked chdir**
    (adversarial-review HIGH, 2026-06). `execve` resolves a relative program path
    against the calling process's cwd — exactly the cwd `is_external_system_tool`'s
    `realpath` used — so it is provable. `posix_spawn`/`posix_spawnp` can carry a
    `posix_spawn_file_actions_addchdir_np` / `_addfchdir_np` action that moves the
    **child's** cwd before it resolves a relative path, so the parent-cwd classify
    is for the wrong directory — `./tool` could resolve under the chdir target to a
    SIP binary (or symlink to one) that runs un-audited with **no** marker. There is
    **no public API** to read a `posix_spawn_file_actions_t` back, so the shim
    **interposes the functions that add a chdir action** — the 10.15
    `addchdir_np` / `_addfchdir_np` (in Rust) **and** the macOS-26 non-`_np`
    replacements `addchdir` / `_addfchdir` — plus `init`/`destroy`, and records
    which file-actions carry a child-cwd change (a fixed spinlocked set,
    `CHDIR_FA_SLOTS`; insert on add, clear on init/destroy, overflow fails closed).
    The set is keyed by the file-actions **handle address** (the
    `posix_spawn_file_actions_t *` the caller passes), **not** the heap object: a
    later `addopen`/`addclose` **reallocs** the object (verified — its pointer
    moves), so an object value captured at `addchdir` time would not match
    `*file_actions` at spawn time, whereas the handle address is stable.
    `dispatch_spawn_macos` then marks a spawn **`<AUDIT_BLIND>`**
    while **keeping DYLD** (`external` stays false) iff its program path is
    **relative** AND its file-actions handle is **tracked as carrying a chdir** — an
    honest "could not see what the child execs," yet an auditable plain-arm64 child
    still loads the shim and emits its own events. This fires **only** on a real
    child-cwd change: the stdio-only file-actions libuv attaches to *every* spawn are
    not chdir actions, so ordinary relative spawns are unaffected. Absolute program
    paths are cwd-independent (a chdir cannot move them) and are never affected. This
    closes the **decoy** variant — a benign `./tool` planted in the parent cwd so
    `realpath` succeeds there while the chdir target holds a different binary — which
    a parent-cwd realpath check alone would miss (verified end-to-end: the decoy,
    a `_np` chdir followed by enough `addclose` to realloc the object, and a non-`_np`
    chdir all render `<AUDIT_BLIND>`; a no-chdir relative spawn and an absolute-under-
    keep-root spawn do not). The non-`_np` symbols are `__API_AVAILABLE(macos(26.0))`,
    so their interpose lives in C (stable Rust has no weak extern). Making it both
    **build** and **load** on the pre-26 `macos-14` parity runner — whose SDK omits
    these symbols from `libSystem.tbd` entirely (only the `_np` forms exist; verified
    in `MacOSX15.4.sdk`) — takes **two** mechanisms working together:
    1. **Compile:** on a sub-26 SDK the C file declares the two functions manually with
       `__attribute__((weak_import))` (guarded off on the macOS-26 SDK, which already
       declares them availability-weak at the sub-26 deployment target). Without this
       a bare reference is an implicit-declaration error.
    2. **Link:** the kept `__interpose` tuples still emit relocations to those symbols,
       so the final cdylib link would fail with *Undefined symbols …
       `_posix_spawn_file_actions_add{,f}chdir`* before the runtime weak-NULL behavior
       is ever reached. `src/shim/build.rs` adds `-Wl,-U,_posix_spawn_file_actions_addchdir`
       and `…_addfchdir` (cdylib-scoped, exactly those two symbols) to allow them
       undefined at link. Paired with the `weak_import` reference, each becomes a
       **weak, dynamically-looked-up** undefined: dyld binds it to the real function on
       macOS 26+ and to **NULL** on older macOS, where a `{ replacement, NULL }`
       interpose tuple is an inert no-op so the dylib still loads (verified on both
       SDKs: 15.4 → link OK, symbols `weak external … dynamically looked up`; 26.5 →
       symbols `weak external … from libSystem`, dylib loads under injection). The
       `-U` flags are a harmless no-op on the 26 SDK, where the symbols are present.
    **Reachability:** the parity fixture (`vuejs/core`) has
    **zero** relative-program spawns — its only `./` line is `node ./postinstall.js`,
    where the program is `node` (PATH-resolved to the absolute provisioned node) and
    `./postinstall.js` is an argument — so this is **gate-neutral**. A bare-name
    `posix_spawnp` that DOES carry a tracked chdir (libuv adds one for its `cwd`
    option, so ordinary lifecycle `sh`/`node` spawns have one) is still resolved
    through the **absolute** `PATH` dirs (`resolve_path_search_chdir_safe`), which a
    chdir cannot move, so it stays PROVABLE (resolved → `sip_redirect` / correct
    marking) and is NOT falsely `<AUDIT_BLIND>`; only a name the kernel could reach
    via a cwd-dependent `PATH` segment (empty / relative / `.`) — the actual attack
    surface — is left bare and marked. **Residual
    (accepted):** the set is keyed by handle address, so a caller that copies the
    `posix_spawn_file_actions_t` **value** into a second variable and spawns with
    `&copy` presents a different handle and is not tracked — but the type is opaque,
    copying it is unsupported (a `destroy` of one would double-free the shared
    object) and no real toolchain does this; and macOS-bare is observe-only, so
    Firecracker remains the enforcement boundary. This is the same class as the
    raw-syscall interpose bypass below: a determined native attacker can already
    evade an `LD_PRELOAD`/`__interpose` auditor, so closing it is out of scope for
    this observation layer. The two alternatives are deliberately rejected: keying
    on the object **value** instead of the handle would reintroduce the realloc
    miss this design fixes (appending later actions moves the heap object), and
    pessimistically blinding *every* relative-program `posix_spawn` with a non-null
    `file_actions` would over-blind the benign stdio-only spawns libuv attaches to
    nearly every child and risk diverging from Linux.
  - **Fingerprinting + BSD-semantics caveat.** The substitutes are uutils (GNU
    semantics) and bash 5.3, not the macOS BSD system binaries, so behaviour
    diverges in two ways. (1) *Fingerprint:* a script can detect the sandbox from
    version banners (`date --version` succeeds under uutils, fails on real macOS)
    **and** from BSD-vs-GNU flag handling — `date -j`, `stat -f`, `cp -X` are
    rejected by uutils; `du`/`df` report different block-size units; `uname -p`
    prints `unknown` vs `arm`. A benign-when-watched payload *could* gate on these
    and evade. (2) *Correctness:* a lifecycle script relying on those BSD-specific
    flags behaves differently under the bare backend than on the host. Both are
    inherent to substitution-based observation (the Linux backend has the
    analogous "GNU coreutils + dash in the rootfs" property). For evasion- and
    fidelity-sensitive audits, use **Firecracker**.

- **Connect: blocked on Linux, online on macOS-bare, reconciled by prefix strip.**
  Linux runs Phase B **offline** via `unshare -n`, so every observed connect is
  recorded `<BLOCKED> connect <host>:<port>`. The macOS bare backend is
  **observe-only and stays ONLINE** (user decision 3): the Rust shim interposes
  `connect`/`connectx` (`src/shim/src/net.rs`), gated on `SCRIPT_JAIL_MACOS_AUDIT_OPS`
  which `src/guest/agent.ts` sets for Phase B only, but it does **not** enforce
  offline — it FORWARDS the real call and records the attempt with its TRUE result
  (a succeeded connect → `connect <host>:<port>` with no prefix; a failed one →
  `<BLOCKED> connect …`). A non-blocking connect — which is how libuv, and thus
  **all** Node networking, issues connects — returns `EINPROGRESS` (or `EALREADY`/
  `EISCONN`) while the SYN is already on the wire: that counts as **egress-occurred
  → "ok"**, not blocked (round-12 finding F3). Both classifiers agree
  (`src/guest/strace-parser.ts` for Linux, `src/shim/src/net.rs` for macOS-bare);
  resolving the *final* result of an in-flight connect would need an `SO_ERROR`
  follow-up, tracked as v2. `connectx` (the Darwin connect-equivalent) is observed
  the same way, since a connect-only interpose would miss it. `AF_UNIX`/other
  local-IPC families are not inet and are dropped. Each committed lock stays
  faithful to what its backend saw (`src/lock/normalize.ts` does **not** rewrite
  the per-host result), and `scripts/parity-diff.ts` reconciles the offline/online
  split by **stripping the `<BLOCKED> ` prefix from connect entries on both sides**
  (narrowly — only `<BLOCKED> connect ` entries, never dlopen), so a Linux blocked
  connect and a macOS online connect to the SAME host reduce to
  `connect <host>:<port>` and match. A connect to a **different** host, or one
  present on only one side, still surfaces as a diff hunk; inside a danger-checked
  divergent package, any non-resolver connect surfaces regardless of result.
  Host-resolver noise is reconciled by an **exact-match** allowlist of the three
  observed resolver endpoints (see below), compared in their post-strip
  `connect <addr>:53` form.

  > **The strip is attempt-parity, not enforcement-parity (round-12 finding F1,
  > kept by decision).** Collapsing a Linux-`<BLOCKED>` connect and a macOS-`ok`
  > connect to the same `host:port` is deliberate: the parity gate exists to prove
  > the two backends observed the **same dependency behaviour** (a byte-stable,
  > cross-backend-reproducible lock), **not** to assert macOS prevented egress. The
  > alternative — failing or flagging every Linux-blocked-vs-macOS-ok connect —
  > would diverge on *every* benign network-using package (puppeteer fetching
  > Chrome, @swc fetching wasm, any registry/DNS touch), making the gate useless.
  > The honest enforcement claim lives in the security note below: macOS-bare does
  > **not** enforce; **Firecracker** does. The raw macOS lock still shows the true
  > `ok`/`<BLOCKED>` per host (normalize never rewrites it) — only the diff
  > reconciles the offline/online split.

  > **Security note — macOS-bare does NOT enforce offline.** Unlike Linux's
  > `unshare -n` (a kernel network namespace), the macOS bare backend has no
  > kernel-level network-off: it is **observe-only**, and even the observation
  > only covers processes the Mach-O shim is loaded into. Three gaps follow — all
  > closed by Firecracker, none by macOS-bare:
  >   1. **Audit-blind children egress for real.** SIP-protected system binaries
  >      that are not substituted (`curl`, `git`, `python3`, `perl`, `ruby`, …)
  >      strip `DYLD_INSERT_LIBRARIES` on exec, so the shim never loads — a
  >      lifecycle script that runs `curl https://evil` reaches the live host
  >      network and the connect is never recorded (only the `<AUDIT_BLIND>`
  >      spawn is).
  >   2. **Raw syscalls bypass the interpose.** Native code that issues
  >      `syscall(SYS_connect)` / `SYS_connectx` / `SYS_sendto` / `SYS_sendmsg(_x)`
  >      directly never touches the `__interpose` table, so it egresses with no
  >      `NetworkEvent`.
  >   3. **Connectionless datagrams are neither blocked nor recorded** —
  >      `sendto`/`sendmsg` are not interposed in the observe-only model (see the
  >      residual list below).
  > Phase A fetch is online by design (lifecycle scripts do not run in Phase A —
  > npm/pnpm fetch with `--ignore-scripts`). **For any audit where egress
  > prevention or completeness matters, use Firecracker** — it is the
  > high-assurance backend; macOS-bare is a local convenience whose network
  > recording is best-effort over instrumented processes only.

- **Resolver-address filter.** A name lookup the install triggers connects to
  the host's DNS endpoint. On macOS-bare these succeed (online); on Linux they
  are blocked (offline). After the `<BLOCKED> ` strip both reduce to
  `connect <addr>:53`, and the parity filter drops the three observed resolver
  endpoints: the Apple Virtualization.framework NAT resolver (`192.168.64.1:53`),
  the Azure runner endpoint (`168.63.129.16:53`), and the macOS system stub
  resolver on loopback (`127.0.0.1:53`, mDNSResponder). These are host resolver
  plumbing, not dependency behavior. A connect to any other endpoint — or to one
  of these on a port other than 53 — still surfaces.

- **Intrinsically platform-divergent packages (danger-checked exclusion).** Three
  packages install via a genuinely different code path on the bare backend's
  "Darwin-pretending-to-be-Linux" environment (it spoofs `platform=linux`), so
  `scripts/parity-diff.ts` excludes the **per-package lock block** for each from
  **both** lockfiles before the byte comparison. They are matched by **name
  prefix** (`@swc/core@`, `puppeteer@`, `unrs-resolver@`) so a fixture version
  bump cannot silently un-exclude them. **The comparison is structural, not
  line-based:** each lock is parsed, strict-validated, danger-walked, then the
  divergent packages are dropped and the parity-only noise filtered **on the
  parsed structure**, and the result is re-rendered through the canonical
  byte-stable serializer (`src/lock/render.ts`) before the two renders are
  diffed. Because the parser and the strip/filter operate on the same structure,
  they can never disagree the way a line scanner and the parser could — the class
  of evasions a text stripper allowed (YAML aliases splicing one package's
  content into another, non-canonical key spellings desyncing the scanner,
  unknown top-level sections escaping the byte compare) is eliminated
  structurally. To keep that guarantee, the gate rejects the YAML features that
  reintroduce ambiguity: **aliases, anchors, merge keys, non-string keys,
  `__proto__`, and keys carrying a control character (e.g. TAB) all fail CLOSED**
  as a whole-lock danger (the canonical renderer never emits any of them, so a
  conformant lock has none — the control-char rejection in particular stops a key
  from forging a `package\tstage` presence composite). Both locks are validated against a **fully
  `.strict()`** parity schema (`ParityLock` in `scripts/parity-diff.ts`, built on
  `src/lock/schema.ts`) at **every** level — top section, package entry, and
  lifecycle block — so a malformed shape (an `external_reads` that is an object),
  an unknown extra field (`secret_reads: [$HOME/.ssh/id_rsa]`), and an unknown
  top-level **section** (e.g. a `metadata:` sibling) all fail CLOSED as a danger
  rather than being silently dropped from both re-renders. Top-level strictness is
  load-bearing here: the re-render only serializes known fields, so a permissive
  schema would drop an unknown section from both sides and launder a one-sided
  escape to a clean exit 0. The exclusion is **not** blind: before a block is
  dropped, `collectDivergentDangers` screens the parsed block on **each** side for
  any signal a one-sided escape could hide behind. The exfil-vector screens are
  **default-deny over what the producer records** — *every* non-events-file
  `escaped_writes`, *every* recorded `network_attempts` that is not a known DNS
  resolver, *every* `dlopen_attempts`/`audit_bypass`/`env_tamper`, and *every* spawn
  outside the per-package benign allowlist fails the gate. This is the strongest
  control, but it is bounded by audit coverage, so it is **not** an unconditional
  "a secret can never leave": see the **connectionless-egress residual** below. The
  credential **read** screen is therefore a co-equal control, not a fallback — it
  flags the suspicious READ itself: a `<HIDDEN>` **or credential-named** `env_read`
  and a
  `<HIDDEN>`/sensitive `external_reads`. Because a divergent package legitimately
  reads a large, platform-varying set of benign config/proxy/locale vars (the
  committed baseline alone has 88) and the screen runs per side **including the
  fresh Linux side**, the read screens cannot be default-deny without false-failing
  on a benign read — so they match credential **shape** categorically rather than by
  name list (adversarial review rounds 5/6/7): credential env substrings
  (`TOKEN`/`SECRET`/`PASSWORD`/`CREDENTIAL`/`AUTHORIZATION`/`PRIVATEKEY`/`BEARER`/…,
  case-insensitive) plus whole-**token** markers `AUTH`/`KEY`/`PAT` (split on
  separators and camelCase, so `NPM_AUTH`/`SERVICE_ACCOUNT_KEY`/`GITHUB_PAT` hit but
  `…UNAUTHORIZED`/`MONKEY`/`*_PATH` and the benign `npm_config_always_auth` flag do
  not). The file screen matches the repo default protected set (`.ssh`/`.aws`/
  `.npmrc`/`.netrc`/`.gnupg`) **plus** cloud-CLI / package-manager credential stores
  the default set omits (`.config/gcloud`, `.azure`, `.kube`, `.docker/config`,
  `.git-credentials`, `.pypirc`, `.cargo/credentials`, composer `auth.json`, NuGet
  config) and key-file suffixes (`.pem`/`.p12`/`.pfx`/`.key`) and `.env`/`.env.*`,
  segment/suffix-aware so a credential dir does not over-match a benign sibling
  (`.cargo/credentials`, not the `.cargo` registry cache; `/.env`, not
  `/.environment`). **Known residuals** (neither is unique to a stripped package —
  both are audit-coverage limits of the engine, documented so the gate's guarantee
  is not overstated):
  - **Innocuously-named env secret.** A secret in an env var with no credential
    token/keyword (e.g. `DEPLOY_HOOK` holding a token) is not flagged by the read
    screen. To *leave*, it still needs a recorded exfil vector (network/spawn/
    cross-package or external write), which the default-deny screens catch.
  - **Connectionless datagram egress (macOS-bare): neither prevented nor recorded.**
    A connectionless `sendto`/`sendmsg` to an IP literal skips `connect()`/
    `getaddrinfo()`. On **Linux** Phase B runs under `unshare -n`, so the datagram
    cannot leave (prevented, loopback only). On **macOS-bare** the backend is
    observe-only and stays online, and `sendto`/`sendmsg` are **not** interposed,
    so such a datagram DOES leave the host and produces no `network_attempts`
    entry (the lock schema's `NetworkEvent` is `connect`-only). This is the same
    class of gap as the audit-blind / raw-syscall egress called out in the connect
    security note above — macOS-bare does not enforce offline. Recording datagram
    egress on macOS would also require adding `sendto`/`sendmsg` to the Linux
    strace set + the `NetworkEvent` schema (a one-sided macOS event would break
    byte parity). Use **Firecracker** when datagram egress must be prevented.
  - **Package writes to the audit events file are dropped (trusted-pid residual).**
    Shim-instrumented lifecycle processes append their `env_read` audit lines to
    `SCRIPT_JAIL_LOG_FILE` BY PATH (fd 3 does not survive the npm/pnpm/yarn
    `stdio:'inherit'` spawn) and re-open it by path on EBADF as an anti-tamper
    measure. The producer (Linux: `phase-install.ts`; macOS: the shim's
    `path_is_audit_log`) drops writes to that exact path so the audit channel does
    not self-observe. The events path is **readable** by package code (not a
    read-protected env name), so a malicious shim-loaded pid that opens the same
    path also has its write dropped. This is not separately defensible —
    env-spy's own legitimate by-path reopen is indistinguishable from a malicious
    open at the `open()` layer, and flagging would break the reopen and flake the
    parity gate — so it is accepted as the **same trusted-pid residual** already
    documented in `phase-install.ts` (an attacker inside an already-shim-loaded
    pid can write forged JSONL regardless; the forgery detector only backstops
    NON-shim-loaded writers). Firecracker's strace-sourced event stream is not
    user-space-writable and does not share this channel.
  - **Clean-exit void of an active-phase ctime-only events-file tamper (accepted
    irreducible residual; Codex round-4 [high], 2026-06-12).** The tailer's
    "events file ctime advanced without new bytes" gate (`runStraceTailer` in
    `src/guest/agent.ts`) is the backstop for a same-UID script doing a metadata-
    only mutation — truncate-back, `utimes`-restore, or a same-size in-place
    substitution — that leaves `size === eventsPos` so the size/maxSeenSize gates
    do not see it. On a **large** repo `strace -ff` lingers >150ms past the last
    events byte, and the kernel's **lazy ctime finalize** of the last legit write
    produces the EXACT `{ctime advanced, size === eventsPos}` shape — so the gate
    cannot fire immediately without a guaranteed false positive (it rejected legit
    installs of ~1000-package monorepos, the v0.2.2 blocker). The gate therefore
    records the suspicion **provisionally** and resolves it against the strace
    **exit disposition**: a CLEAN whole-tree exit (no survivor can remain) VOIDs
    it as the benign finalize; an ABNORMAL exit or absent disposition (macOS /
    unit) PROMOTES it to a fatal tamper. The residual: a real ctime-only tamper
    that the attacker performs and then lets the install exit 0 is **also** voided.
    This is irreducible — `{ctime↑, size flat}` is indistinguishable from the
    finalize by any stat/poll/inotify signal (an inotify-fire immediate gate was
    tried and FALSE-POSITIVED on the real CI kernels, confirmed by CI and an
    independent review). The **primary** defense is unaffected: the inotify-driven
    drain reads the attacker's appended bytes (recording the forged line) unless
    they win a sub-millisecond cross-process race against the concurrently-running
    tailer; the void only narrows the ctime backstop to {race won} AND {clean
    exit} AND {no later observed activity} — the **same class** as PR #10's
    accepted post-exit-freeze residual (a root attacker racing the tailer is
    outside the enforceable boundary).
  - **Defer-and-re-resolve: two irreducible single-pass cross-file ordering limits,
    handled in the SAFE direction (accepted residuals).** `strace -ff` writes one
    trace file per pid and the guest drains them in `readdir` (inode) order with no
    causal key, so a clone child's relative `openat(AT_FDCWD, …)` can be processed
    BEFORE its parent's `clone() = <child>` line. The deterministic fix
    (`src/guest/phase-install.ts`, "defer-and-re-resolve") parks such an unresolved
    relative open and re-resolves it at end-of-drain against the clone-inherited
    initial cwd. Two cross-file orderings cannot be disambiguated in a single pass;
    both resolve to a **fail-loud, never-hide-real-behavior** outcome:
    - **(#1) CLONE_FS cwd-group provenance → fail closed to `<UNRESOLVED_PATH>`.**
      A deferred read ANY of whose process-lineage ancestors was EVER a member of a
      `CLONE_FS` cwd group is failed closed rather than resolved, because a
      sibling/grandparent `chdir` of the shared group cwd can be causally-prior to the
      read yet drain AFTER the clone snapshot, leaving the inherited cwd STALE
      (resolving would risk a protected-path FALSE NEGATIVE). The gate is a
      **replay-time** bounded walk UP the `childParent` lineage
      (`lineageEverCwdShared(seedParentPid)`) against the sticky `everCwdShared` set —
      both structures are complete after the full drain, so the verdict is
      drain-independent. The walk covers ANY `CLONE_FS` ancestor in the lineage, not
      just the immediate parent: a plain-fork intermediate that is NOT itself in
      `everCwdShared` can COPY a stale shared-group cwd down to the child from a
      `CLONE_FS`-shared ancestor whose `chdir` drained late (codex round-3 #1) — a
      pure `everCwdShared.has(seedParentPid)` check (the immediate parent only) missed
      that transitive case and silently resolved against the stale cwd. The earlier
      stamp-time membership sample is likewise blind when even the immediate parent's
      own `CLONE_FS` membership edge drains after it plain-forks the child
      (codex round-2 #1). The walk also **fails closed on lineage ambiguity** (codex
      round-3 pid-reuse follow-up): the final `childParent` map is read at replay, so a
      recycled intermediate pid (re-cloned by a different, non-`CLONE_FS` parent before
      replay, overwriting its parent edge) could otherwise route the walk down the
      recycled chain and silently MISS the original `CLONE_FS` ancestor. An overwritten
      edge is recorded in `childParentReused`; the walk returns "shared" (fail closed)
      when it hits a reused edge, a cycle, or the iteration cap — `false` is trusted
      only for an unambiguous walk to the lineage root. (No single-edge-per-pid map is
      generation-CORRECT under reuse — first-write and last-write each lose a different
      generation — so the walk is generation-SAFE, not correct: it never yields a silent
      false negative, at the cost of the reuse over-fire.) Accepted conservative
      over-fires, both SAFE (the probe surfaces as a fail-loud `<UNRESOLVED_PATH>`
      audit_bypass, never a missed protected path) and confined to pathological trees:
      (a) a parent that shared then `unshare(CLONE_FS)`-detached still carries the
      sticky bit, so a plain child it forks afterward also fails closed; (b) a PURE
      plain-fork chain with NO `CLONE_FS` ancestor but whose deferred read's lineage
      intermediate (seedParent-walk) pid is RECYCLED mid-drain also fails closed (the
      recycled edge makes the original lineage unverifiable); and (c) a deferred read
      whose OWN pid is recycled across generations with DIFFERENT-parent clones
      (`childParentReused.has(P)`) AND where some parent generation has a `CLONE_FS`
      lineage (`childAllParents`) fails closed — the wrong-generation stamp might have
      laundered a real shared ancestor out of the walk. The own-pid-reuse gate is
      PRECISE: a pure plain-fork recycled pid (no `CLONE_FS` parent generation) still
      resolves under its stamped generation, preserving the accepted reaped-pid residual
      (MEMORY: `reaped-child-env-read-pid-reuse-residual`). A lineage with NO `CLONE_FS`
      ancestor AND no pid reuse (the real napi/plain-fork flake this fix targets)
      completes a clean walk to the root and still resolves — **including** the case
      where a chain intermediate `chdir`s AFTER it clones the next hop: the intermediate's
      chdir `lineTs` versus its clone-of-next-hop `lineTs` are both in that pid's OWN
      per-pid file, a proven within-file happens-before, so the walk recognizes the child
      inherited the intermediate's PRE-`chdir` cwd and keeps resolving (rather than failing
      closed on the mere presence of a later chdir). This removes a real drain-order
      divergence: ROOT-DOWN drain resolved the inherited cwd while LEAF-UP previously
      fell to `<UNRESOLVED_PATH>` — the two now agree. Only a genuinely unprovable order
      (an unobserved seeding clone, or a `CLONE_FS`/pid-reuse lineage) still fails closed. Two **accepted
      pre-existing SILENT false-negative residuals** (out of scope — verified to predate
      this fix on HEAD; the lineage walk does not change either): **(i) inline COPY
      staleness** — the INLINE (non-deferred) path takes a private COPY of the shared
      group-root cwd at clone-drain, so when the shared `chdir` drains last the model
      resolves against the stale copy; the true protected path (e.g. shared
      `$HOME/.ssh/...`) is not surfaced and the stale non-protected resolution is dropped
      with no `<UNRESOLVED_PATH>`. **(ii) same-parent pid-reuse generation ambiguity** —
      when the SAME numeric parent re-forks the SAME child pid and the parent's own cwd
      changed between generations, the deferred read can be first-stamp-wins bound to the
      wrong generation's cwd (verified identical on HEAD `c198ee3` — the original
      `everCwdShared.has(seedParentPid)` gate keys on the same wrong-gen
      seedParent/initialCwd). This is the same irreducible generation-ambiguity class as
      the reaped-pid residual: the wrong-gen stamp is byte-identical to a legitimate
      same-generation stamp and there is no `CLONE_FS` signal to trip the precise gate,
      so failing closed would break the legitimate same-pid fast-exit resolve and
      over-fire the reaped-pid class. Both residuals are pinned by regressions so a
      future generation-qualified rewrite (the only sound closure) is a deliberate,
      visible change; neither is claimed harmless.
    - **(#3) Inherited Node-bootstrap window → emit (over-record), never suppress.**
      A deferred read in an inherited Node-bootstrap window is EMITTED (over-recorded
      as package behavior) rather than suppressed when cross-file ordering is
      ambiguous. The replay filters a deferred read as bootstrap noise ONLY on
      POSITIVE, drain-independent evidence — the resolved path is already in the
      `nodeBootstrapFileReads` baseline, the child inherited file-pending at its
      seeding clone (gated by the child's OWN startup-done marker), or the child has
      its OWN bootstrap window (own marker ts vs read ts, same per-pid file → causal).
      The prior cross-file `read.ts < parentEndedTs` parent-window inference was
      DROPPED: it could SUPPRESS a genuine package read of a non-Node helper forked
      after the parent's bootstrap window closed but whose racing read drained before
      the parent's marker (codex round-2 #3) — and suppressing a real package read is
      the dangerous direction for a security audit. The residual (a Node-internal
      read of a non-Node child over-recorded as package behavior) never hides real
      behavior and does not occur in normal npm/pnpm/yarn plain-fork lifecycle trees.
    - **(#4) Deferred null-ATTRIBUTION re-resolution → drain-order-independent,
      recycled-pid-SAFE.** Yarn Berry runs a binary lifecycle (e.g. napi-rs's `husky`
      `prepare`) via a TRANSIENT launcher it writes to `$TMPDIR/xfs-<hash>/<bin>`
      (`@yarnpkg/fslib` `getTempName`). That launcher pid is often reaped before its
      strace lines drain, so the LIVE `/proc` walk returns null and — pre-fix — its
      spawn + absolute reads/writes were DROPPED, flaking between captured and absent
      across runs (the shim-before-strace drain order is a soft contract). The fix
      parks such null-attribution SPAWNS and ABSOLUTE reads/writes and, at end-of-drain,
      re-resolves them via `resolveDeferredAttribution` against the COMPLETE
      `attributionGenByPid` map (the set of DISTINCT `(pkg,lifecycle)` generations
      recorded for the pid across the whole drain — drain-order-independent by
      construction). A single-generation pid attributes confidently (the determinism
      win); a pid number RECYCLED across generations resolves to `<unattributed>` so the
      event SURFACES fail-loud (it tokenizes against `$NODE_MODULES`/`$REPO` with no
      `$PKG` prefix) rather than relabeling a gen-A escaped write under the recycled
      gen-B package and being DROPPED as an intra-package `$PKG` write (codex round-2
      [high]). A pid never seeded → dropped (the null-gate floor). The recycle is
      detected by THREE drain-order-independent signals, so the surface holds even when
      the earlier generation is UNSHIMMED and never seeds the gen map (codex Bugbot
      [medium], 2026-06-21): (a) the gen map itself flips `ambiguous` when ≥2 distinct
      generations each seed; (b) `pidRecycled` — strace observed a successful execve for
      the pid AFTER its own `+++ exited +++` line (a definitive new program image on a
      reused pid number, ordered within the pid's own `-ff` file); (c) `childParentReused`
      — the pid's clone parent edge was repointed by a DIFFERENT parent. Any of the three
      → `<unattributed>`. This gate covers every event resolved THROUGH
      `resolveDeferredAttribution`: the absolute null-attribution replay AND the
      relative-open `inheritedAttrib`-null fallback. **Accepted pre-existing residual
      (codex round-4 [critical], verified PRE-EXISTING not introduced by this fix):** a
      relative open that DOES carry a clone-propagated `inheritedAttrib` reads that stamp
      DIRECTLY (it predates this fix verbatim), bypassing `resolveDeferredAttribution`.
      `stampDeferredRelOpens` is keyed by pid alone + first-stamp-wins, so for a recycled
      pid the stamp is whichever generation's clone drained first. In the narrow corner
      where (i) BOTH generations are pure plain-fork (no `CLONE_FS` anywhere, so
      `childPidReuseHidCloneFs` does not veto), (ii) the wrong generation's clone drains
      first, (iii) neither generation `chdir`'d (so the cwd resolves), AND (iv) the
      resolved path lands inside the stamped wrong package's own dir, the relative write
      relabels under that package and `normalize` drops it as `$PKG` — a hidden write.
      Any `CLONE_FS` in either lineage routes it to `<UNRESOLVED_PATH>` (surfaces). This
      is the SAME pure-plain-fork recycled-pid residual class the env_read path documents
      (`reaped-child-env-read-pid-reuse-residual`) and is drain-order-dependent like the
      inline path below; the sound closure (route recycled-pid relative opens through
      `resolveDeferredAttribution`) is deliberately deferred because it changes the
      accepted F6 "bind to the stamping generation" behavior (recycled-pid relative reads
      would become deterministic `<unattributed>` instead of the first-stamp generation —
      a precision-vs-determinism tradeoff). **Accepted pre-existing residual (codex round-3
      [critical]; owner decision — document + ship):** the INLINE (non-deferred,
      live-`/proc`-`result`) fs path is NOT covered by this map. If a gen-A write line
      drains while the dispatcher LAGS and the kernel has already RECYCLED the pid to
      gen-B with a populated `/proc` (so `attribute(pid)` returns gen-B), that write
      emits under gen-B and, if it lands in gen-B's own dir, is dropped as an
      intra-package write — a HIDDEN escaped write. This is the WRITE manifestation of
      the same PID_MAX-wrap-bounded `/proc`-liveness reorder race the exit-line handler
      already documents as accepted (`src/guest/phase-install.ts`, the
      `attributionSnapshotByPid` exit-line model), and predates this fix (committed in
      PR #22, not introduced here). The only sound closure is to defer the inline fs
      path to end-of-drain resolution (so attribution reads the complete
      `attributionGenByPid`) or a generation-qualified `/proc` walk; both are out of
      scope for the determinism fix and tracked as a deliberate, visible follow-up. It
      is NOT covered by the env_read-only `reaped-child-env-read-pid-reuse-residual`.
  Any finding **fails the gate** even when the
  comparable text is byte-equal, so the exclusion can never launder a real
  escape. The exclusion is also **symmetric down to the lifecycle stage**: a
  divergent package present on only **one** side — *or* present on both but with a
  one-sided / mismatched lifecycle stage (e.g. an empty `lifecycle: {}` vs a real
  `postinstall`) — is a resolution/producer desync, not a free pass; the
  cross-side presence check (package **and** stage) fails the gate and names the
  missing side, so a one-sided absence can no longer be silently accepted. Each block is still
  recorded in each backend's uploaded lockfile for manual inspection, and the
  platform-**invariant** packages (`esbuild`, `simple-git-hooks`) stay under full
  byte comparison, so real audit drift is still caught. Root cause per package:
  - **@swc/core** — the linux-arm64 native binding cannot load on Darwin, so its
    `postinstall.js` spawns `npm install @swc/wasm` (a whole nested npm
    invocation), absent on Linux where the native binding loads.
  - **puppeteer** — `install.mjs`'s `await import('puppeteer/internal/node/install.js')`
    throws on the bare backend and it `process.exit(0)`s early, so it never
    reaches the ~50 config/proxy env reads + the DNS connect that the Linux
    install performs.
  - **unrs-resolver** — `@napi-rs/postinstall` detects the platform without
    shelling out to `uname`/`sed`/`dirname` on Darwin, so the Linux run records
    the helper spawns are absent.

  > **Residual — resolver waiver inside the divergent-package danger check**
  > (adversarial review round-11, finding F2). The 3-IP host-resolver allowlist
  > (`127.0.0.1:53` / `192.168.64.1:53` / `168.63.129.16:53`) is honored by
  > `collectDivergentDangers`, not only by the byte-comparison filter. This is
  > **load-bearing**: @swc/core's nested `npm install @swc/wasm` performs a live
  > registry DNS lookup on the **online** macOS-bare backend (it is
  > `<BLOCKED>`/absent on offline Linux), and attribution folds that child's
  > `connect 127.0.0.1:53` into @swc/core's danger-checked block — so without the
  > waiver the freshly generated macOS-bare CI leg would false-fail every run. The
  > laundering surface is bounded to those 3 exact infra IPs on port 53 — loopback
  > (local mDNSResponder, no remote reach), the VZ NAT gateway (absent on the bare
  > backend), and the Azure magic IP — so it cannot exfil to an
  > attacker-controlled remote host; any **other** `host:port` still fails the
  > danger check. It is strictly narrower than, and the same class as, the
  > accepted connectionless-`sendto` egress residual above.
  >
  > **Round-12 re-challenge (kept by decision).** A later review re-flagged this
  > as a DNS-tunnel laundering channel: `NetworkEvent` records only `host:port`,
  > not the DNS *qname*, so a lifecycle could in principle encode bytes into
  > lookup names sent through the waived `:53` resolver and out to an authoritative
  > nameserver — invisible in the lock. Two facts bound it and it is **kept as
  > designed**: (1) removing the waiver from `collectDivergentDangers` does **not**
  > close the channel — qnames are uncaptured on *both* backends, so the only
  > effect is to false-fail @swc/core every run; (2) DNS-over-resolver exfil is
  > inherent to *any* online backend, which is exactly why this is observe-only and
  > **Firecracker (offline Phase B) is the enforcement boundary**. Closing it for
  > real needs producer-side qname capture (v2) or offline enforcement, not a
  > diff-time waiver change.

  > **Observe-only download WRITE waiver + traversal guard.** A network-download
  > divergent package (puppeteer) actually writes the downloaded files on the
  > online macOS-bare backend while offline Linux blocks the fetch and writes
  > nothing. Under `--source-of-truth left`, `reconcileObserveOnly` waives a macOS
  > `escaped_writes` ONLY when (a) the package matches `PARITY_DIVERGENT_PACKAGES`
  > and (b) the value sits at/under one of THAT package's **hardcoded** download
  > roots (`PARITY_DIVERGENT_DOWNLOAD_ROOTS`, e.g. `puppeteer@` → `$HOME/.cache/
  > puppeteer`) — never under a path the (influenceable) trusted side merely read.
  > The value is **lexically normalized** (`.`/`..`/`//` collapsed over the
  > `$TOKEN` tail) before the prefix test, so a traversal escape that *starts* with
  > the root but lands outside it (`$HOME/.cache/puppeteer/../../.ssh/
  > authorized_keys` → `$HOME/.ssh/authorized_keys`) is **not** waived — the shim
  > records `open()`'s path argument verbatim and neither the shim's fs path-builder
  > nor the tokenizer collapses `..` (adversarial review). A bounded residual
  > remains by design: a write *genuinely* under the package's own cache root is
  > waived un-flagged — that is the package's own download dir, not a system
  > persistence location, and Firecracker (offline Phase B) is the enforcement
  > boundary.

  > **Observe-only download CONNECT — explicit egress allowlist, TOLERATED-and-
  > surfaced.** The same network-download package also makes a real `connect` to the
  > CDN on macOS-bare, which offline Linux never records: its Phase B (`unshare -n`)
  > lookup dies at DNS before any connect survives, so EVERY Linux package block is
  > `network_attempts: []` (verified across the whole parity fixture). A non-resolver
  > connect is **demoted from blocking to tolerated** by `reconcileObserveOnly` ONLY
  > when its `(package-prefix, phase)` is on the **explicit, repo-committed egress
  > allowlist** `PARITY_OBSERVE_ONLY_EGRESS_ALLOW` (`egressAcknowledged`) — today the
  > single entry `puppeteer@` → `['postinstall']`. This gate is **independent of any
  > package write**: a divergent package not on the list (`@swc/core`, `unrs-resolver`),
  > or `puppeteer@` in any other phase (e.g. `preinstall`), gets NO demotion — its
  > connect stays a BLOCKING danger (the `3b`/`3c` tests pin both bounds). Host is not
  > matched (the CDN rotates IPs run-to-run, `142.251.218.187` → `.219`, and the lock
  > stores raw IPs) and there is no trusted-side connect to anchor on.
  >
  > **Why an explicit allowlist, not a write-derived gate (adversarial review round
  > 3).** An earlier revision derived the connect waiver from a same-phase
  > `escaped_write` under the package's own cache root — "download evidence". That is
  > **package-controlled and forgeable**: a compromised `puppeteer@` could mint it by
  > writing a throwaway `$HOME/.cache/puppeteer/.sentinel` and then `connect` anywhere.
  > Because CI fails only on a non-zero exit, demoting that connect to a non-failing
  > `TOLERATED` line did not close the hole — the egress still shipped. The fix is to
  > gate the connect on a **curated CI decision no package can influence**: the
  > acknowledgement now lives in source (`PARITY_OBSERVE_ONLY_EGRESS_ALLOW`), reviewed
  > like any other code, and nothing a package does at install time can add itself.
  > Every acknowledged connect is still **surfaced** as a non-failing `TOLERATED
  > observe-only egress` entry (stdout block + report table, `formatTolerated`), never
  > silently dropped (`3d` pins that a connect is tolerated with NO write at all —
  > proof the gate is allowlist-derived, not write-derived). The gate exits 0 for the
  > known CDN download (otherwise it false-fails every run — puppeteer always
  > downloads). **Accepted residual (owner decision):** a compromised `puppeteer@` in
  > its acknowledged `postinstall` phase could `connect` to an **arbitrary** host and
  > have it tolerated — the exception is destination-agnostic by necessity (no sound
  > host pin on an observe-only backend whose offline counterpart records nothing). It
  > is bounded by: the allowlist is a FIXED repo-committed list, the connect stays
  > VISIBLE in both the lock and the parity report, and **Firecracker (offline Phase B)
  > — never macOS-bare — is the egress enforcement boundary**.
  >
  > **Inherited residual — forgeable package LABEL (adversarial review round 11,
  > ACCEPTED owner decision).** The allowlist keys on the package label `f.pkg`, and
  > that label is **not** a CI-controlled fact: the guest derives it from the observed
  > process's own `npm_package_name`/`npm_package_version` env via a `/proc/<pid>/environ`
  > walk (`src/guest/attribution.ts:188-205`). A malicious lifecycle script of *some
  > other* package can spawn a child with forged `npm_package_name=puppeteer`, so that
  > child's exfil `connect` is recorded under `puppeteer@…` **upstream**, and the differ
  > — seeing only the lock — tolerates it. This is the **known, documented v1
  > attribution limitation** (`attribution.ts:188-195` `TODO(v2)`; `docs/design.md` "Not
  > defended … the complete fix is UID separation"; pinned by
  > `test/guest/attribution.test.ts`), surfacing through a new path — **not** a new
  > hole. It is **not closeable in the differ**: the *entire* divergent block (its
  > writes, its connects, its key) is attributed by the same forgeable env, so there is
  > no un-forgeable signal in the lock to distinguish a real puppeteer download from a
  > forgery, and tolerating puppeteer's *legitimate* download connect (required for a
  > green gate) inherently tolerates a forged one. The earlier write-derived gate was
  > forgeable the *same* way (`.sentinel` mint, round 3); moving to a label key did not
  > add forgeability, it exposed the shared root cause. It is **bounded** by the same
  > two facts as above: (1) the label is **orthogonal to enforcement** — Firecracker/
  > Linux Phase B is offline, so egress is BLOCKED regardless of which package the
  > connect is labelled under; this name-keyed allowlist only applies on macOS-bare,
  > which is explicitly *not* the egress boundary; and (2) the connect stays **SURFACED**
  > (mislabelled, never hidden) in both the lock and the parity report (`3e` pins both
  > bounds). The complete fix is **v2 attribution hardening** (trusted lifecycle roots /
  > UID separation), out of scope for the parity differ.

- **Parity-only noise filters: env/read GLOBAL, spawn PACKAGE-SCOPED.** The
  reconciliation waivers in `scripts/parity-diff.ts` are split by how the signal
  arises (adversarial review finding #3). The env reads (`LD_PRELOAD` ⇄
  `DYLD_INSERT_LIBRARIES`, `SCRIPT_JAIL_*`, `COREPACK_HOME`, `VP_HOME`, the
  libSystem/CF/dyld probes, locale internals) and the host-resolver connects are
  **global**: each is read AMBIENTLY by the harness's own injection/loader
  machinery inside EVERY audited process, so it appears in every package's list,
  deduped to a set, and is one-sided BY CONSTRUCTION (each OS reads its own
  injection var — verified against real linux + macOS-bare locks). Scoping those
  to a package would mean listing them under all packages for zero gain, and a
  deliberate package read is invisible anyway (it folds into the ever-present
  ambient entry; removing the waiver would just fail parity on every run). The
  only sound separation of "harness read it" vs "package read it" is producer-side
  bootstrap tagging — future work, out of scope for the diff layer. By contrast
  the **spawn** waivers (esbuild's `$PKG/bin/esbuild --version`; simple-git-hooks'
  `git config` probe in both its `sh -c …` and `<AUDIT_BLIND> …` forms) are
  **package-scoped**: each is reconciled ONLY inside the package it was observed
  in, so an unrelated package cannot launder it as host noise. Every waiver is an
  EXACT match (no prefixes), so a novel env name or spawn fails closed as a diff.

- **Agent events-file write.** The audit agent writes its own event stream to a
  JSONL file at `$TMPDIR/<hash>/<hash>.jsonl`. That is the agent's **own**
  instrumentation write, not dependency behavior, so `src/guest/phase-install.ts`
  drops the write to the agent's own events-file path from `escaped_writes`
  (matched against the canonical + resolved events-file path) and it never
  appears in the lock. This runs in the guest, so it applies on **both**
  platforms — Linux Firecracker/Docker and the VZ Linux guest alike. A committed
  baseline generated **before** this fix still lists `$TMPDIR/<hash>/<hash>.jsonl`
  in `escaped_writes` and must be regenerated.

- **`/private` realpath canonicalization.** On macOS `/var`, `/tmp`, and `/etc`
  are symlinks into `/private`, so the absolute path the shim resolves (via
  `F_GETPATH`/`realpath`) comes back as `/private/var/...`, `/private/tmp/...`,
  `/private/etc/...`. `normalize.ts` strips the `/private` prefix (darwin-gated)
  **before** tokenization and noise filtering, so the canonical `/var`, `/tmp`,
  `/etc` forms match both the tokenize roots and the shared system-noise
  prefixes the Linux side uses. The rewrite is segment-bounded: `/private/var`
  rewrites, `/private/variant` does not.

- **macOS system-noise prefixes.** The shim, unlike strace, surfaces the dyld
  runtime and Apple framework reads a hardened-runtime Node and the bundled
  plain-arm64 shell/coreutils substitutes perform at startup. `normalize.ts` drops these as system noise
  **only when `os === 'darwin'`**: `/System/`, root-level `/Library/` (the
  per-user `/Users/<u>/Library` is **not** dropped — it can hold real package
  writes), the `dyld_shared_cache_*` image, the dyld state store under
  `/var/db/dyld/`, and the provisioned-node toolchain cache (matched by its
  fixed `script-jail-cache` directory segment — the macOS analog of the Linux
  `/opt/vp` noise prefix). The darwin gate is a **security boundary**: a
  malicious Linux lockfile must never be able to smuggle macOS-shaped paths
  (e.g. a `/System/...` write inside a package dir) past a Linux audit gate
  that would otherwise drop them. The shared `/usr/lib`, `/usr/share`, and
  `/dev` prefixes apply on both platforms.

- **Case-insensitive filesystem caveat.** The default macOS volume (APFS) is
  **case-insensitive but case-preserving**, whereas the Linux audit rootfs is
  case-sensitive. A lifecycle script that reads `README.md` then `readme.md`
  observes one inode on macOS and two distinct paths on Linux; tokenization
  preserves the as-spelled casing, so the two sides can render different
  `external_reads` entries. Real packages rarely depend on this, but a fixture
  that exercises mixed-case paths can diverge. If you hit it, normalize the
  fixture's casing rather than weakening the comparator — case-folding paths
  globally would mask genuine cross-package escapes that differ only by case.

- **Host-toolchain exec: ENOENT vs ok.** The Linux audit ships a deliberately
  minimal rootfs (no `gcc`, no `python`, no host `git`), so a script that
  shells out to a build toolchain records the `exec` attempt with an ENOENT
  result. A developer Mac (or a `macos-14` runner) usually has the Xcode
  Command Line Tools installed, so the **same** exec succeeds (`ok`). Both
  sides record the spawn attempt, but the result differs. Constrain the parity
  fixture to packages that do not shell to host toolchains; if a fixture must,
  the spawn result — not just the path — will surface as a diff. Do **not**
  blanket-canonicalize spawn results to attempt-only: that would erase the
  Linux signal that an exec was blocked.

- **Root identity is env-trusted on macOS-bare (`root_anchored` defaulted
  `true`).** The root project's fs events surface as `$REPO/...`, and a dependency
  forging `npm_package_name=<root>` to launder its repo writes under the root is
  caught on Linux/Firecracker by the non-forgeable `root_anchored` verdict, which
  is computed from the kernel process tree + per-pid exec-cwd
  (`isRepoRootAnchored`; see `docs/design.md` "Non-forgeable root identity").
  macOS-bare is **observe-only** and has no `strace` process-tree / exec-cwd
  machinery, so it cannot compute that verdict and **defaults
  `root_anchored: true`** on every root-attributed fs event
  (`src/guest/phase-install-macos.ts`). Consequence for divergence: a **forged**
  attack payload could render differently across backends — Linux marks the
  laundered write `<FORGED_ROOT> $REPO/...`, macOS-bare treats it as a genuine
  `$REPO/...` — so the two locks diverge on that line for a *malicious* fixture.
  **Benign/parity fixtures are unaffected:** a genuine root event anchors `true`
  on both backends and renders identically. The dedicated root-`prepare` pass also
  force-attributes `root_anchored: true` on both backends (it runs only the root's
  prepare, by construction). As with the other macOS-bare residuals,
  **Firecracker is the enforcement boundary**; the env-trusted default is a known
  no-strace fidelity gap, not a parity bug.

  This residual extends to **nameless roots** (a parseable root `package.json`
  with no `name`, e.g. an unnamed private monorepo root running
  `preinstall: npx only-allow pnpm` + `postinstall: simple-git-hooks`). Such a
  root's own lifecycle is recognised in the **attribution layer** — an empty
  `npm_package_name` plus a canonical `npm_lifecycle_event` attributes to the
  synthetic `<repo-root>` sentinel (`ROOT_SENTINEL`; see `docs/design.md`
  "Non-forgeable root identity"). On macOS-bare this flows through the shim
  fast-path (`shimExecAttribution` / `classifyShimNodeStartupMarker`), which is
  the only attribution source there (no `/proc` environ). Its lifecycle events
  are now **surfaced** — not dropped, and no longer fail-closed — for **all** event
  kinds (`spawn` / `connect` / `env_read` as well as `read` / `write`); and **all**
  of those kinds now route through the same `root_anchored` stamp as a named root
  (the prior unmarked-non-fs residual is closed). Linux/Firecracker computes the
  real verdict from the process tree; macOS-bare, having no process tree,
  **defaults `root_anchored: true`** on every root-attributed read/write/spawn/
  connect/env_read. So a **forged/unanchored** nameless event of any kind can
  render differently across backends — Linux marks it `<FORGED_ROOT> …` (e.g.
  `<FORGED_ROOT> $REPO/...` or `<FORGED_ROOT> connect host:port`), macOS-bare
  renders it unmarked (genuine) — exactly as for a named forged root. Benign
  nameless-root fixtures anchor `true` on Linux and render identically on both
  sides (the macOS-bare non-fs default `true` is precisely what preserves that
  parity — without it a benign root's non-fs events would mis-render
  `<FORGED_ROOT>` on macOS only); Firecracker remains the enforcement boundary.

- **Dropped `audit_bypass` detectors.** Three `audit_bypass` event kinds are
  **strace-derived** and have no macOS equivalent, because there is no kernel
  syscall channel to cross-check the libc-level shim against:
  `<SYSCALL_EXEC_BYPASS>` (a raw `syscall(SYS_execve, …)` that skipped every
  libc wrapper), `<EVENTS_FILE_FORGERY>` (a non-shim-loaded pid writing forged
  events into the trusted JSONL channel), and `<UNRESOLVED_PATH>` (a
  dirfd/cwd-relative open the strace canonicalizer could not resolve). These
  **never** appear in macOS-bare goldens. The filesystem-based events-file
  tamper detector still fails closed on macOS, and `<EXEC_FAIL_OPEN>` /
  `<AUDIT_FD_LOST>` are still emitted by the shim/preload layers. This is an
  inherent fidelity gap of a no-strace backend: **Firecracker remains the
  high-assurance backend**; the macOS bare backend trades some kernel-level
  cross-checks for a VM-free, CI-native macOS audit.

- **The `node_startup_done` marker is forgeable content on macOS-bare.** The
  marker rides the same same-UID-appendable JSONL channel as every other event,
  and macOS-bare drops the `<EVENTS_FILE_FORGERY>` detector (above), so a
  same-UID lifecycle process can append a syntactically valid marker for any pid.
  The dispatcher therefore treats marker *contents* (ts, npm fields, any
  provenance tag) as untrusted and uses a marker only in directions that cannot
  manufacture a false negative from a forged line:
  - **Env-read window is record-safe (this branch).** A marker only *ends* a
    pid's bootstrap env window — it never opens a `raw.ts < endedTs` suppression
    ceiling (a forged high `ts` would otherwise drop every later env read). There
    is deliberately no trusted marker-provenance field; the worst a forged marker
    can do is clear pending early → record *more* (the safe direction).
  - **Two residual marker-trust paths remain, both pre-existing and accepted.**
    (1) A marker still *confirms+drops* a non-node candidate pid's buffered
    read/env_read events as Node bootstrap baseline — this is the load-bearing
    suppression of the shebang pm-client's own bootstrap noise (benignly the
    client execs `node` in the same pid and env-spy emits the marker), so making
    it record-safe would flood every benign macOS lock; a *forged* same-pid
    marker is the adversarial flip-side. (2) A marker's npm fields seed/supersede
    per-pid attribution (`classifyShimNodeStartupMarker`) — macOS-bare's *only*
    attribution source, since `MacOSProcReader` has no `/proc` environ — so a
    forged marker can relabel a later env read (the same forgeable-attribution
    residual as a forged exec env; supersession itself exists for recycled-pid
    correctness). Benign installs are unaffected (the marker env-spy emits carries
    the *same* npm fields the exec snapshot already recorded → no relabel; a
    genuine non-node candidate emits no marker → its buffer flushes). As with the
    other macOS-bare residuals, **Firecracker is the enforcement boundary**: the
    strace backend's process tree + `<EVENTS_FILE_FORGERY>` detector close both
    paths there. These are accepted no-strace fidelity gaps, not parity bugs.

## Cross-host parity testing

Two separate contracts back the "byte-equal lockfile" claim, and they are
exercised by two separate test suites. Conflating the two is a recurring
documentation mistake — the suites cover unrelated invariants.

### macOS-side smoke and parity checks

`test/e2e/mac-parity.test.ts` is the artifact-gated local test scaffold for
the macOS CLI/VZ path. It runs only on Darwin hosts and skips itself entirely
when the VZ kernel artifact (`images/vmlinux-vz-<arch>`) or the per-arch rootfs
is absent. The committed scaffold still contains placeholder fixture cases;
real per-fixture assertions become useful once the release artifacts are
available on the developer host or in a suitable self-hosted macOS environment.

On Linux CI, `parity-test.yml` now exercises the Action backend on
`ubuntu-24.04-arm` and diffs it against the committed local macOS/VZ lockfile.

### Release-artifact packaging check

`test/scripts/check-publish-artifacts.test.ts` is a different contract
entirely: it asserts the release workflow refuses to publish a tag whose
build-job artifacts have been tampered with or whose manifest is in a
malformed shape. It runs everywhere (the script under test is shell, not
TS, and the test drives it via `child_process`). It does **not** exercise
lockfile byte-equality; it gates the publish job that ships the
artifacts every lockfile audit depends on.

The remaining divergence is documented above; everything else should
produce byte-equal lockfiles. File an issue when it does not.

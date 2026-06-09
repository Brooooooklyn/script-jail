// script-jail — scripts/parity-diff.ts
//
// Compare two .script-jail.lock.yml files for equivalence after the same
// canonicalization that `src/action/diff.ts` applies for the action's
// check-mode diff, plus parity-only filtering for known host/VMM noise.
//
// Pipeline (per side):  parse → reject aliases/anchors/merge-keys → strict
// schema-validate → danger-walk the divergent packages → strip divergent
// packages + filter parity-only noise on the PARSED structure → re-render
// canonically via `src/lock/render.ts` → byte-diff the two renders.
//
// Operating on the parsed structure (not raw lines) means the parser and the
// strip/filter can never disagree (the failure class Codex round-3 found in the
// old line-based stripper): YAML aliases, anchors, non-canonical key spellings,
// reordered keys, and unknown top-level sections can no longer hide drift behind
// a stripped region — they are either rejected up front (alias/anchor/merge) or
// normalised away by the canonical renderer (key spelling/order/whitespace) and
// the strict schema (unknown fields/sections).  render.ts emits byte-identical
// output for identical structure on both backends, so re-rendering is sound:
// only a genuine content difference survives to the diff.  The volatile header
// fields (`generated_at`, `manager_lockfile_sha256`) are normalised to a fixed
// placeholder before rendering.
//
// Invoked from `.github/workflows/parity-test.yml` as:
//
//   pnpm exec oxnode scripts/parity-diff.ts \
//     --left  artifacts/linux/linux-lockfile.yml      --left-label  linux-firecracker \
//     --right artifacts/macos-arm64/macos-lockfile.yml --right-label macos-arm64-vz \
//     --report parity-report.md
//
// Exit codes:
//   0 — renders are byte-equal and no danger fired (parity holds).
//   1 — renders diverge, a divergent package is one-sided, or a danger fired.
//   2 — usage error or input file missing.
//
// Output:
//   stdout — the unified diff (empty when parity holds) + any danger block.
//   --report <path> — Markdown report (verdict + counts + embedded diff).
//                     Suitable for $GITHUB_STEP_SUMMARY.
//
// Both locks are validated against a strict parity schema (ParityLock) before
// any comparison; a non-conforming lock (malformed shape, unknown field, unknown
// top-level section), a lock using YAML aliases/anchors/merge keys, or a lock
// that does not parse fails CLOSED as a whole-lock danger.
//
// What this DOES catch:
//   - PM-flag overlay bug (linux-only package selected on macOS).
//   - Audit-policy desync (spurious event on one side).
//   - A divergent package present on ONE side only (a resolution desync, not a
//     free pass — see the symmetric-presence check in main()).
//   - An escape hidden inside an excluded divergent package (the danger walk).
//
// What this DOES filter (on the parsed structure):
//   - Ambient CI/VMM env names that are not dependency-controlled (GLOBAL — each
//     is read ambiently by the harness in EVERY package; see PARITY_ONLY_ENV_READS).
//   - Apple Virtualization.framework / host NAT resolver noise (GLOBAL).
//   - The repo-root dir-stat ($REPO) the macOS shim cannot hook + the puppeteer
//     cache-root probe (GLOBAL).
//   - esbuild's native self-verify spawn and simple-git-hooks' git-config probe
//     — PACKAGE-SCOPED (PARITY_ONLY_SCOPED_SPAWNS), reconciled ONLY inside the
//     package they belong to so an unrelated package cannot launder them.
//   - INTRINSICALLY platform-divergent packages (PARITY_DIVERGENT_PACKAGES:
//     @swc/core, puppeteer, unrs-resolver) install via a genuinely different code
//     path on Darwin-pretending-Linux (root-caused in docs/divergence.md). Their
//     blocks are excluded from the byte comparison ONLY AFTER a per-block DANGER
//     check (collectDivergentDangers) clears them on both sides — a one-sided
//     escaped write, `<HIDDEN>` read, real connect, dlopen, audit_bypass,
//     env_tamper, or unapproved spawn FAILS the gate — and ONLY when the package
//     is present on BOTH sides.  The exclusion walks `parsed.packages`, so a
//     divergent-named key elsewhere (a future sibling section) is rejected by the
//     strict schema, never stripped unchecked.  The platform-INVARIANT packages
//     (esbuild, simple-git-hooks) stay under full byte comparison.
//
// What this does NOT filter:
//   Arbitrary spawn/exec divergence still surfaces as a diff hunk.  The
//   `<BLOCKED> ` connect prefix IS stripped on both sides (observe-only model):
//   Linux runs Phase B offline so it records `<BLOCKED> connect …`, while
//   macOS-bare stays online and records a succeeded `connect …`; stripping
//   reconciles the two so one committed lock satisfies both backends.  The strip
//   is narrow (only `<BLOCKED> connect ` entries; dlopen is untouched) and a
//   one-sided connect to a non-resolver host still surfaces.  Secret-like
//   env/file reads (NPM_TOKEN, AWS_*, $HOME/.ssh, …) are never in any filter set —
//   and inside an excluded divergent package the danger check re-asserts they are
//   absent — so a one-sided exfiltration always fails.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { isScalar, parseDocument, visit } from 'yaml';
import { z } from 'zod';

import { render } from '../src/lock/render.js';
import type { PackageBlock } from '../src/lock/schema.js';

// Parity-local lifecycle block.  This deliberately does NOT reuse `LifecycleBlock`
// from src/lock/schema.ts: that schema `.default([])`s every list, so a lock
// MISSING one of the seven always-rendered fields would be accepted, defaulted to
// `[]`, and re-rendered into the same bytes as a lock that carries it — masking a
// producer/renderer shape omission (adversarial review round-4).  render.ts
// ALWAYS emits those seven, so the parity gate REQUIRES them (a missing one fails
// CLOSED).  The two optional fields (`audit_bypass`, `env_tamper`) are emitted by
// render.ts only when non-empty, so they may be absent and default to `[]`.
// `.strict()` rejects any unrecognized field (e.g. `secret_reads:`).
const ParityLifecycleBlock = z
  .object({
    external_reads: z.array(z.string()),
    escaped_writes: z.array(z.string()),
    env_read: z.array(z.string()),
    spawn_attempts: z.array(z.string()),
    spawn_blocked: z.array(z.string()),
    dlopen_attempts: z.array(z.string()),
    network_attempts: z.array(z.string()),
    audit_bypass: z.array(z.string()).default([]),
    env_tamper: z.array(z.string()).default([]),
  })
  .strict();

// A parity-gate-specific lock schema.  The canonical Lock (src/lock/schema.ts)
// is intentionally PERMISSIVE so it can round-trip older/newer schema versions
// (its objects STRIP unknown keys rather than reject them).  The parity gate is
// stricter ON PURPOSE and FULLY `.strict()` at every level — top level, package
// entry, and lifecycle block: both compared locks are produced by the SAME
// current release, so ANY unknown field is suspect.  This matters because the
// re-render step (render.ts) only serializes the fields it knows: a permissive
// schema would silently DROP an unknown top-level SECTION, a stray sibling next
// to `lifecycle`, or an unrecognized lifecycle field (e.g.
// `secret_reads: [$HOME/.ssh/id_rsa]`) from BOTH renders, laundering a one-sided
// escape to a clean exit 0.  Strict validation fails CLOSED instead — a
// non-conforming lock is a whole-lock danger (and the top level being strict is
// what closes the "unknown top-level section" gap that a line-based diff used to
// catch only by accident).  Package keys and lifecycle-stage keys stay arbitrary
// strings (as in the canonical schema): an unknown stage is still danger-walked
// and its block is still strict-validated, and render.ts canonicalizes stage
// ordering.  Non-string keys are rejected earlier, structurally (see
// structuralReject), before this schema runs.
const ParityLock = z
  .object({
    schema_version: z.literal(1),
    manager: z.enum(['npm', 'pnpm', 'yarn']),
    manager_lockfile_sha256: z.string(),
    node_version: z.string(),
    generated_at: z.string(),
    packages: z.record(
      z.string(),
      z.object({ lifecycle: z.record(z.string(), ParityLifecycleBlock) }).strict(),
    ),
  })
  .strict();

type ParityPackages = z.infer<typeof ParityLock>['packages'];
type LifecycleBlockData = z.infer<typeof ParityLifecycleBlock>;

interface ParityOptions {
  left: string;
  right: string;
  leftLabel: string;
  rightLabel: string;
  reportPath: string | null;
}

const PARITY_ONLY_EXTERNAL_READS = new Set([
  // Puppeteer probes its default browser cache root. Whether that directory
  // exists is host/backend state; writes to it still surface via escaped_writes.
  '$HOME/.cache/puppeteer',
  // The bare repo ROOT directory itself.  Linux strace records the install's
  // opendir/stat of `$REPO`; the macOS Mach-O shim hooks file open/read but not
  // bare-directory stat (getattrlist/opendir), so the repo-root dir-stat is a
  // documented macOS fidelity gap (Firecracker stays the high-assurance
  // backend).  This is the repo's OWN working root, not an escape, and the
  // meaningful file reads beneath it (`$REPO/package.json`, …) ARE captured on
  // both backends, so only the bare-dir entry is reconciled here.
  '$REPO',
  // NOTE: `$HOME/.gitconfig` and `/usr/bin/ldd` are intentionally NOT filtered
  // here.  `$HOME/.gitconfig` is a global git-config read that can expose
  // credential helpers / tokenized URL rewrites / include paths — filtering it
  // package-agnostically would erase a real one-sided escape signal (adversarial
  // review finding #4), and it does not appear in the clean fixture anyway.
  // `/usr/bin/ldd` only ever shows up inside the intrinsically-divergent
  // packages (@swc/core, unrs-resolver), which are handled by the whole-block
  // danger-checked exclusion below (processDivergentPackages) — so it never
  // needs a global waiver, and a `/usr/bin/ldd` read by a platform-INVARIANT
  // package would correctly surface as a diff.
]);

// Env-read waivers are GLOBAL (package-agnostic), and deliberately so — unlike
// the spawn waivers above which are package-scoped (adversarial review finding
// #3).  Empirically (real linux + macOS-bare locks), every entry here is read
// AMBIENTLY by the audit harness's own injection/provisioning/loader machinery
// INSIDE each audited node process — so each name appears in EVERY package's
// `env_read`, deduped into a set, and is one-sided BY CONSTRUCTION (Linux reads
// `LD_PRELOAD`, macOS reads `DYLD_INSERT_LIBRARIES`/`SCRIPT_JAIL_MACOS_AUDIT_OPS`;
// neither has the other's name).  Two consequences: (1) scoping these to a
// package would mean listing them under ALL packages (no security gain, high
// churn); (2) a package DELIBERATELY reading one is invisible anyway — the name
// is already present from the ambient read and the list is a set, so the
// deliberate read folds into the existing entry with nothing extra to hide.
// Removing any entry would therefore fail parity on EVERY run, not surface a new
// signal.  The only sound way to separate "harness read it" from "package read
// it" is producer-side bootstrap tagging (drop the harness's own reads at the
// node_startup_done boundary) — tracked as future work, out of scope for the
// diff layer.  Each name is still an EXACT match (no prefix) so a NOVEL env name
// fails closed as a diff.
const PARITY_ONLY_ENV_READS = new Set([
  // CI/git transport environment present on the GitHub runner but not on the
  // committed local macOS fixture.
  'GIT_ASKPASS',
  'GIT_SSH_COMMAND',
  'HOSTNAME',
  // Resolver configuration inherited from the host/VMM.
  'LOCALDOMAIN',
  'NOPROXY',
  'RES_OPTIONS',
  // Agent/backend control and terminal env that lifecycle children should not
  // rely on; older generated baselines may still contain them.
  'LINES',
  'POSIXLY_CORRECT',
  'SCRIPT_JAIL_CONFIG_PATH',
  'SCRIPT_JAIL_CONNECTION',
  'SCRIPT_JAIL_ENV_SPY_PRELOAD_PATH',
  'SCRIPT_JAIL_NATIVE_PRELOAD_PATH',
  'SCRIPT_JAIL_PHASE_B_UNSHARE_NET',
  'SCRIPT_JAIL_PLATFORM_PRELOAD_PATH',
  'TERM',
  // Test-knob probes from dependency helper libraries. Presence depends on
  // the ambient process env, not on the dependency install behavior.
  'COLS',
  'TESTING_TAR_FAKE_PLATFORM',
  '__FAKE_FS_O_FILENAME__',
  '__FAKE_PLATFORM__',
  // ── macOS-bare ⇄ Linux harness/platform env (added with the bare backend) ──
  // The audit harness's OWN injection + provisioning + shell vars.  These are
  // inherently platform-asymmetric (Linux injects LD_PRELOAD; macOS-bare injects
  // DYLD_* — see the DYLD_ prefix below) and are NOT dependency behavior.  A
  // package READING them to detect the audit is still recorded in each backend's
  // own lockfile (this only reconciles the cross-backend diff, where the var
  // names cannot match by construction).
  'LD_PRELOAD',
  'VP_HOME',
  'COREPACK_HOME',
  'SCRIPT_JAIL_MACOS_AUDIT_OPS',
  'SCRIPT_JAIL_SHELL_SHIM_DIR',
  '_',
  'SHLVL',
  'TMPDIR',
  // git/locale i18n internals probed by the SIP `git` (or the bundled bash hop)
  // during `git config`.  Host plumbing, not dependency behavior; the GIT_*
  // family is covered by the prefix list below.
  'LANGUAGE',
  'LC_CTYPE',
  'LC_TIME',
  'GETTEXT_LOG_UNTRANSLATED',
  'XDG_CONFIG_HOME',
  // macOS libSystem / CoreFoundation / dyld runtime probes.  These are read by
  // fresh libSystem image inits inside macOS-spawned children (or by the dyld
  // loader itself), never by the npm package's own logic, and have no Linux
  // analog — so a macOS-bare child carries them while the Linux side does not.
  //
  // These are listed as EXACT names rather than matched by prefix (`OS_*`,
  // `DYLD_*`, …).  Adversarial review finding #3: a broad `GIT_`/`DYLD_` prefix
  // would also erase a one-sided read of a credential / sandbox-detection probe
  // like `GIT_TOKEN`, `GIT_CONFIG_GLOBAL`, or a novel `DYLD_*` — exactly the
  // audit signal the gate must keep.  Enumerating the observed set is more
  // maintenance on a fixture bump (a new libSystem probe needs adding here), but
  // it fails CLOSED: an unknown env name surfaces as a diff instead of being
  // silently absorbed.
  'ACTIVITY_LOG_STDERR',
  'CFFIXED_USER_HOME',
  'CFLOG_FORCE_STDERR',
  'CFStringDisableIsolates',
  'LIBDISPATCH_CONTINUATION_ALLOCATOR',
  'LIBDISPATCH_TIMERS_FORCE_MAX_LEEWAY',
  'LIBTRACE_DRIVERKIT',
  'OSLogRateLimit',
  'OS_ACTIVITY_DT_MODE',
  'OS_ACTIVITY_MODE',
  'OS_ACTIVITY_PROPAGATE_MODE',
  'OS_ACTIVITY_STREAM',
  'OS_ACTIVITY_TOOLS_OVERSIZE',
  'OS_ACTIVITY_TOOLS_PRIVACY',
  'OS_LOG_FAULT_REPORTS',
  'RES_DEBUG',
  'SYSINFO_CONF_ENABLE',
  'XBS_DISABLE_LIBINFO',
  '__CFPREFERENCES_AVOID_DAEMON',
  '__CFPreferencesTestDaemon',
  // The macOS-bare injection vars the dyld loader reads to perform the shim
  // insert — the exact macOS analog of `LD_PRELOAD` (already filtered above).
  // Like `LD_PRELOAD`, a package READING these to detect the audit is recorded
  // in each backend's own lockfile; only the cross-backend NAME mismatch is
  // reconciled.  Exact names (no `DYLD_` prefix) so a novel `DYLD_*` surfaces.
  'DYLD_FORCE_FLAT_NAMESPACE',
  'DYLD_INSERT_LIBRARIES',
  // Benign config/terminal probes read by the package manager on ONE backend
  // only because of marker-timing fidelity (the macOS node_startup_done boundary
  // fires before npm's config layer loads, so these surface post-marker on
  // macOS but are pre-marker bootstrap noise on Linux).  Not secrets.
  'FORCE_COLOR',
  'npm_config_sign_git_commit',
  'npm_config_sign_git_tag',
]);

// Resolver-address noise.  Entries are stored in their POST-strip form (no
// `<BLOCKED> ` prefix): both the danger screen and filterBlock run each connect
// entry through stripBlockedConnect FIRST.  Linux runs Phase B offline so it
// records `<BLOCKED> connect <addr>:53`; macOS-bare stays ONLINE (observe-only
// shim) so its succeeded resolver lookup records `connect <addr>:53` with no
// prefix.  Both strip to `connect <addr>:53` and match here.  Each backend sees
// its own host resolver IP (VZ NAT / Azure runner / macOS loopback mDNSResponder),
// so all three appear on one side only and are reconciled as host plumbing — not
// dependency egress.  A connect to a NON-resolver host (e.g. 8.8.8.8:443) is
// absent from this set, so after stripping it still surfaces as a diff / danger.
const PARITY_ONLY_NETWORK_ATTEMPTS = new Set([
  // Apple Virtualization.framework NAT resolver observed in local arm64 VZ
  // lockfiles. Linux action backends see public resolvers instead.
  'connect 192.168.64.1:53',
  // Azure-hosted runner DNS endpoint observed from the Docker backend on
  // ubuntu-24.04-arm. It is host resolver plumbing, not dependency behavior.
  'connect 168.63.129.16:53',
  // macOS-bare backend: the system stub resolver (mDNSResponder) listens on
  // the loopback DNS port, so a name lookup the install triggers a connect to
  // 127.0.0.1:53.  Host resolver plumbing on macOS, same class as VZ NAT/Azure.
  'connect 127.0.0.1:53',
]);

// Spawn waivers are PACKAGE-SCOPED, not global (adversarial review finding #3):
// each benign spawn is reconciled ONLY inside the package it was observed in, so
// an unrelated package cannot launder e.g. esbuild's native self-verify or
// simple-git-hooks' git-config probe as host noise.  `pkg` is matched as a NAME
// PREFIX against the enclosing package key (the same prefix form as
// PARITY_DIVERGENT_PACKAGES).  filterBlock receives the enclosing package key so
// it can apply these in context (isScopedSpawnNoise).
const PARITY_ONLY_SCOPED_SPAWNS: ReadonlyArray<{ pkg: string; spawn: string }> = [
  // esbuild's postinstall verifies the selected native binary. Depending on
  // backend filesystem semantics, its JS shim may be hardlinked/replaced before
  // validation, so one side can record this direct native spawn in addition to
  // the common `node install.js` lifecycle entry.
  { pkg: 'esbuild@', spawn: '$PKG/bin/esbuild --version' },
  // simple-git-hooks probes the local checkout hook path when the audited
  // workspace has a usable .git directory. Container backends can run from a
  // copied workspace without that git metadata, so this is host shape noise.
  { pkg: 'simple-git-hooks@', spawn: 'sh -c git config --local core.hooksPath' },
  // The macOS-bare representation of the SAME `git config` action: the bundled
  // bash hop reaches the SIP `git`, whose DYLD insert is stripped, so its
  // internals are audit-blind and normalize tags the spawn `<AUDIT_BLIND>`.
  // Linux records the strace-visible `sh -c git config …` form above; both name
  // the identical action, so the platform-specific framing is reconciled here.
  { pkg: 'simple-git-hooks@', spawn: '<AUDIT_BLIND> git config --local core.hooksPath' },
];

// Packages whose lifecycle install is INTRINSICALLY platform-divergent under the
// linux-spoof-on-real-macOS bare backend, root-caused and documented in
// docs/divergence.md.  Matched by NAME prefix so a fixture version bump does not
// silently un-exclude them.  Root cause per package:
//   @swc/core      — the linux-arm64 native binding cannot load on Darwin, so
//                    postinstall.js spawns `npm install @swc/wasm` (a whole nested
//                    npm invocation, absent on Linux where the native binding loads).
//   puppeteer      — install.mjs's `await import('puppeteer/internal/node/install.js')`
//                    throws on the bare backend and it `process.exit(0)`s early,
//                    so it never reaches the ~50 config/proxy reads + DNS connect
//                    that the Linux install performs.
//   unrs-resolver  — @napi-rs/postinstall detects the platform without shelling
//                    out to uname/sed/dirname on Darwin, so the helper spawns the
//                    Linux run records are absent.
//
// These blocks are NOT byte-compared (their benign content genuinely differs by
// platform), BUT they are NOT blindly dropped either.  Adversarial review
// finding #1: a blind whole-block strip would let a one-sided `<HIDDEN> NPM_TOKEN`
// read, escaped write, real connect, dlopen, audit_bypass, or env_tamper hide
// inside one of these packages and pass with exit 0.  Instead,
// `processDivergentPackages` runs a DANGER check on each block (see
// collectDivergentDangers): the block is excluded from the byte comparison ONLY
// when it is provably benign; any dangerous signal on EITHER side fails the gate
// and is reported.  The platform-INVARIANT packages (esbuild, simple-git-hooks)
// stay under full strict byte comparison.
const PARITY_DIVERGENT_PACKAGES: ReadonlyArray<string> = [
  '@swc/core@',
  'puppeteer@',
  'unrs-resolver@',
];

// NOTE on the agent's own events-file write: it is dropped at the PRODUCER
// (src/guest/phase-install.ts "Fix C" on Linux; the shim's `path_is_audit_log`
// on macOS-bare), so a current lock never carries it and the committed baseline
// has been regenerated without it.  parity-diff therefore does NOT waive it — a
// `$TMPDIR/<hash>/<hash>.jsonl` escaped write is fully default-deny like any
// other (a tokenized `<hash>` path is FORGEABLE, so waiving it would let a
// package launder a one-sided TMPDIR escape — adversarial review round-9).

// CREDENTIAL/SECRET screen for a stripped divergent package's reads.  This is a
// DEFENSE-IN-DEPTH layer: the primary exfil controls in `collectDivergentDangers`
// are already DEFAULT-DENY (every non-events `escaped_writes`, every non-resolver
// `network_attempts`, every non-allowlisted `spawn_*` fails the gate), so a secret
// cannot LEAVE a divergent package un-flagged regardless of this screen.  These
// patterns additionally flag the credential READ itself as an early signal.
//
// Env/file READS cannot be default-deny: a divergent package legitimately reads a
// large, platform-varying set of benign config/proxy/locale vars and system paths
// (the committed baseline alone has 88 such env names), and the screen runs PER
// SIDE — including the freshly-generated Linux side, whose benign read set is not
// enumerable here — so an allowlist would false-FAIL parity CI on a benign read.
// Instead the screen matches credential SHAPE categorically (rounds 5/6/7): not a
// name-by-name list but the token/affix families that name a secret.  KNOWN
// RESIDUAL: a secret stored in an innocuously-NAMED var (no token/keyword) is not
// flagged here — it is covered by the default-deny exfil controls above.

// Unambiguous credential substrings (matched on the UPPER-CASED env name): each is
// long enough to never appear inside a benign config var (verified against the
// baseline's 88 divergent-package env reads).  `AUTHORIZATION` does NOT match the
// benign `…UNAUTHORIZED` (that ends `AUTHORIZED`, not `AUTHORIZATION`).
const SENSITIVE_ENV_SUBSTRINGS: ReadonlyArray<string> = [
  'TOKEN',
  'SECRET',
  'PASSWORD',
  'PASSWD',
  'PASSPHRASE',
  'CREDENTIAL',
  'AUTHORIZATION',
  'PRIVATEKEY',
  'APIKEY',
  'ACCESSKEY',
  'BEARER',
  'SSH_AUTH_SOCK',
  // Docker registry auth blob (base64 creds, content of ~/.docker/config.json).
  'DOCKER_AUTH',
  // DB password vars that abbreviate to `_PWD` (`MYSQL_PWD`, `MARIADB_PWD`, …).
  // The leading underscore is load-bearing: it matches `*_PWD` without tripping
  // the benign bare `PWD`/`OLDPWD` (current-dir) vars a divergent package reads.
  '_PWD',
];

// Short credential markers that ARE ambiguous as raw substrings, so they are
// matched only as a WHOLE TOKEN (the name split on separators AND camelCase humps,
// upper-cased).  `AUTH` catches `NPM_AUTH`/`DOCKER_AUTH_CONFIG`/`npm_config__auth`
// but not `…UNAUTHORIZED` (token `UNAUTHORIZED`).  `KEY` catches
// `SERVICE_ACCOUNT_KEY`/`API_KEY`/`PRIVATE_KEY` but not `MONKEY` (token `MONKEY`).
// `PAT` catches `GITHUB_PAT` but not `*_PATH` (token `PATH`).
const SENSITIVE_ENV_TOKENS: ReadonlySet<string> = new Set(['AUTH', 'KEY', 'PAT']);

// Benign names that LOOK credential-shaped under the rules above but are not.  npm's
// deprecated `always-auth` config FLAG surfaces as `npm_config_always_auth` (token
// `AUTH`); it is a boolean, not a secret.  Checked FIRST, so it can never be
// laundered into a real credential (an exact full-name match, not a substring).
const BENIGN_ENV_NAME_EXCEPTIONS: ReadonlySet<string> = new Set(['NPM_CONFIG_ALWAYS_AUTH']);

// Credential FILE markers.  Substrings are SEGMENT-aware (anchored with a leading
// `/` or a specific filename) so a credential DIR does not over-match a benign
// sibling (`/.cargo/credentials`, NOT `/.cargo`, so the cargo registry cache a
// native package reads is not flagged).  Covers the repo default protected set
// (`.ssh`/`.aws`/`.npmrc`/`.netrc`/`.gnupg` — see `.script-jail.yml`) PLUS the
// common cloud-CLI / package-manager credential stores the default set omits
// (gcloud, azure, kube, docker, git-credentials, pypirc, cargo, composer, nuget —
// adversarial review rounds 6/7).  Matched case-insensitively.
const SENSITIVE_FILE_SUBSTRINGS: ReadonlyArray<string> = [
  '/.ssh',
  '/.aws',
  '/.gnupg',
  '/.azure',
  '/.kube',
  '/.config/gcloud',
  '/.config/gh',
  '/.docker/config',
  '/.npmrc',
  '/.netrc',
  '.gitconfig',
  '/.git-credentials',
  '/.pypirc',
  '/.cargo/credentials',
  '/.composer/auth.json',
  'composer/auth.json',
  'auth.json',
  'nuget.config',
  'id_rsa',
  'id_ed25519',
  '/etc/shadow',
];

// Private-key / certificate file SUFFIXES, matched on the path END (not a raw
// substring) so a benign path that merely contains `.pem`/`.key` mid-segment is
// not flagged (adversarial review round-7: prefer suffix/segment over substring).
const SENSITIVE_FILE_SUFFIXES: ReadonlyArray<string> = ['.pem', '.p12', '.pfx', '.key'];

// Dotenv secret files.  The repo's own default protected set covers `$REPO/.env`
// and `$REPO/.env.*` (see `.script-jail.yml`), but a SUCCEEDED protected read
// surfaces as a RAW path (not `<HIDDEN>`), so a divergent package reading
// `$REPO/.env.local` would otherwise pass (adversarial review round-8).  Anchored
// to a final `/.env` path SEGMENT (optionally `.<suffix>`) so it matches
// `.env`/`.env.local`/`.env.production` but NOT `/.environment` or a mid-path
// `dotenv/` directory.
const SENSITIVE_DOTENV_RE = /\/\.env(\.[^/]*)?$/;

// Per-divergent-package allowlist of the EXACT benign spawns observed for the
// pinned fixture (both backends), used by the danger check: any spawn_attempt /
// spawn_blocked entry in a divergent package that is NOT here is "unapproved" →
// danger (adversarial review finding #1, "unapproved spawns").  Version-pinned
// entries are coupled to test/parity/fixture.yml — when the fixture pin bumps,
// regenerate these alongside the committed baseline (see docs/parity-testing.md).
const PARITY_DIVERGENT_BENIGN_SPAWNS: ReadonlyArray<{ prefix: string; spawns: ReadonlySet<string> }> = [
  {
    prefix: '@swc/core@',
    spawns: new Set([
      'node postinstall.js',
      // macOS wasm fallback: the linux-arm64 binding can't load, so postinstall
      // shells out to a nested npm install of @swc/wasm.
      'npm install --no-save --loglevel=error --prefer-offline --no-audit --progress=false @swc/wasm@1.15.33',
    ]),
  },
  {
    prefix: 'puppeteer@',
    spawns: new Set(['node install.mjs']),
  },
  {
    prefix: 'unrs-resolver@',
    spawns: new Set([
      'dirname $PKG/node_modules/.bin/napi-postinstall',
      'napi-postinstall unrs-resolver 1.11.1 check',
      'node $PKG/node_modules/.bin/../../../napi-postinstall/lib/cli.js unrs-resolver 1.11.1 check',
      // The recorded argv has two literal backslashes (`s,\\,/,g`); this TS
      // literal `\\\\` is that exact two-backslash string.
      'sed -e s,\\\\,/,g',
      'uname',
      '<ENOENT> node $PKG/node_modules/.bin/../../../napi-postinstall/lib/cli.js unrs-resolver 1.11.1 check',
    ]),
  },
];

// A dangerous signal found inside an excluded (divergent) package block.  When
// any are collected (from either side), the gate FAILS even if the comparable
// text is byte-equal — the divergent-package exclusion must never launder a
// real one-sided escape into a clean parity result.
interface DangerFinding {
  side: string;
  pkg: string;
  phase: string;
  field: string;
  value: string;
}

const NPM_DEBUG_LOG_BASENAME =
  /\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}_\d{3}Z-debug-(\d+)\.log$/;

class ParityArgError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParityArgError';
  }
}

interface CanonResult {
  text: string;
  dangers: DangerFinding[];
  divergentKeys: Set<string>;
}

// A whole-lock fatal danger (parse / structure / schema).  When present on
// either side the gate fails and the byte diff is suppressed — the structure is
// untrustworthy, so the danger message is the signal, not a full-file delete.
function wholeLockDanger(side: string, field: string, value: string): DangerFinding {
  return { side, pkg: '<whole-lock>', phase: '-', field, value };
}

// Canonicalize one lock for comparison.  Parse → reject aliases/anchors/merge →
// strict-validate → danger-walk → strip divergent packages + filter parity-only
// noise on the PARSED structure → re-render canonically via render.ts.  Returns
// the canonical text, any dangers, and the set of divergent-package keys present
// on this side (for the caller's symmetric-presence check).  We re-render rather
// than substitute on raw lines so the parser and the strip/filter operate on the
// SAME structure — render.ts is byte-stable, so identical content on both
// backends yields identical bytes, and only a real difference survives the diff.
function canonicalize(content: string, side: string): CanonResult {
  const noKeys = new Set<string>();

  let doc: ReturnType<typeof parseDocument>;
  try {
    doc = parseDocument(content, { merge: false });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { text: '', dangers: [wholeLockDanger(side, 'yaml', `lockfile did not parse as YAML: ${detail}`)], divergentKeys: noKeys };
  }
  if (doc.errors.length > 0) {
    const detail = doc.errors.slice(0, 3).map((e) => e.message).join('; ');
    return { text: '', dangers: [wholeLockDanger(side, 'yaml', `lockfile did not parse as YAML: ${detail}`)], divergentKeys: noKeys };
  }

  // Reject the YAML features that let raw text and parsed structure disagree
  // (an alias expands to content a text strip never saw; a non-canonical key
  // spelling can desync a line scanner).  render.ts never emits any of these, so
  // a conformant lock has none — a tampered one fails CLOSED here.
  const structural = structuralReject(doc);
  if (structural !== null) {
    return { text: '', dangers: [wholeLockDanger(side, 'structure', structural)], divergentKeys: noKeys };
  }

  // Strict schema validation.  Guarantees every watched field is a string[] and
  // that no unknown field / section hides anywhere (including the top level), so
  // both the danger walk and the canonical re-render are sound.
  const parsed = ParityLock.safeParse(doc.toJS());
  if (!parsed.success) {
    const detail = parsed.error.issues
      .slice(0, 5)
      .map((i) => `${i.path.join('.') || '<root>'}: ${i.message}`)
      .join('; ');
    return {
      text: '',
      dangers: [wholeLockDanger(side, 'schema', `lockfile does not conform to the lock schema: ${detail}`)],
      divergentKeys: noKeys,
    };
  }

  const dangers = collectDivergentDangers(parsed.data.packages, side);

  // Build the render input: drop divergent packages (recording their presence
  // keys for the caller's symmetric-presence check) and filter parity-only noise
  // from the rest.  render.ts always emits a list that filters down to empty as
  // `[]`, so no separate "collapse empty list" pass is needed.
  const divergentKeys = new Set<string>();
  const packages = new Map<string, PackageBlock>();
  for (const [key, pkgVal] of Object.entries(parsed.data.packages)) {
    if (PARITY_DIVERGENT_PACKAGES.some((p) => key.startsWith(p))) {
      // Record the excluded package AND each of its lifecycle stages.  The block
      // is dropped from the byte comparison, so the symmetric-presence check is
      // the only thing guarding it: tracking the package alone would miss a
      // one-sided `lifecycle: {}` or a stage that runs on one platform but not the
      // other (adversarial review round-5).  `\t` cannot appear in a package key
      // or lifecycle stage name, so it is an unambiguous composite separator.
      divergentKeys.add(key);
      for (const stage of Object.keys(pkgVal.lifecycle)) {
        divergentKeys.add(`${key}\t${stage}`);
      }
      continue;
    }
    const lifecycle: PackageBlock['lifecycle'] = {};
    for (const [stage, block] of Object.entries(pkgVal.lifecycle)) {
      (lifecycle as Record<string, LifecycleBlockData>)[stage] = filterBlock(block, key);
    }
    packages.set(key, { lifecycle });
  }

  const text = render({
    manager: parsed.data.manager,
    manager_lockfile_sha256: '<canonical>',
    node_version: parsed.data.node_version,
    generated_at: '<canonical>',
    packages,
  });

  return { text, dangers, divergentKeys };
}

// Reject YAML aliases, anchors, and merge keys.  Returns a reason string when
// the lock uses any of them, else null.  These are the features that let a
// line-based reader and the structural parser disagree; the canonical renderer
// never emits them, so a conformant lock has none.  In practice the anchor branch
// trips first for any alias-using lock (a valid alias requires a preceding
// anchor, since forward aliases are a YAML parse error), but the Alias branch is
// kept so a hypothetical dangling-alias node is still named, not just rejected.
function structuralReject(doc: ReturnType<typeof parseDocument>): string | null {
  let reason: string | null = null;
  visit(doc, {
    Alias() {
      reason = 'lockfile uses a YAML alias (*ref); aliases are not allowed (they can mask cross-package drift)';
      return visit.BREAK;
    },
    Node(_key, node) {
      const anchor = (node as { anchor?: string }).anchor;
      if (anchor) {
        reason = `lockfile uses a YAML anchor (&${anchor}); anchors are not allowed`;
        return visit.BREAK;
      }
    },
    Pair(_key, pair) {
      const k = pair.key;
      // Every key in a lock render.ts produces is a plain STRING scalar.  Reject
      // anything else: a non-scalar (complex/collection) key, or a non-string
      // scalar key.  The non-string check is load-bearing — `doc.toJS()` projects
      // a key onto a JS string property, so a numeric `1:` and a quoted `"1":`,
      // or an explicit `!!merge <<` (whose key value is a Symbol, not the string
      // '<<'), collapse/merge into another key and silently erase the loser's
      // content BEFORE the danger walk or render ever sees it (adversarial review
      // round-4).  Rejecting non-string keys closes both the explicit-merge and
      // key-collision classes; the implicit `<<` (a literal string key under
      // merge:false) is caught by the explicit value check below.
      if (!isScalar(k)) {
        reason = 'lockfile uses a non-scalar (complex/collection) mapping key; only plain string keys are allowed';
        return visit.BREAK;
      }
      if (typeof k.value !== 'string') {
        reason = `lockfile uses a non-string mapping key (${String(k.value)}); only plain string keys are allowed (a non-string key can merge or collapse into another during JS projection)`;
        return visit.BREAK;
      }
      if (k.value === '<<') {
        reason = 'lockfile uses a YAML merge key (<<); merge keys are not allowed';
        return visit.BREAK;
      }
      // `__proto__` is a STRING key, but render.ts keys a plain object by name
      // (`packages[k] = …`), so `__proto__` hits the JS prototype setter instead
      // of creating an own key — the package/stage silently VANISHES from the
      // re-render on both sides, laundering a one-sided escape to exit 0
      // (adversarial review round-4 follow-up).  render.ts cannot faithfully
      // round-trip it and no valid npm name is `__proto__` (names cannot start
      // with `_`), so reject it.  `constructor`/`prototype` are NOT rejected: they
      // round-trip as ordinary own keys (verified) and are legitimate package
      // names, so they stay under full byte comparison.
      if (k.value === '__proto__') {
        reason = 'lockfile uses the reserved key "__proto__"; it cannot be faithfully rendered (it hits the JS prototype setter) and is not allowed';
        return visit.BREAK;
      }
      // Reject any control character (C0 + DEL, incl. TAB/newline) in a key.
      // render.ts only ever emits package specs (`name@version`) and fixed
      // lifecycle-stage names as keys — none contain control chars.  The
      // symmetric-presence check joins `${pkg}\t${stage}` into a single Set token
      // (see canonicalize), so a TAB *inside* a key could forge a composite that
      // collides with a real `pkg\tstage` pair.  The multi-composite design
      // already fails closed on such a collision (every genuine divergence emits
      // both a bare and a per-stage token, and the trusted side's keys are not
      // attacker-controlled), but enforcing the no-control-char invariant here
      // makes that guarantee structural rather than emergent.
      if (/[\u0000-\u001f\u007f]/.test(k.value)) {
        reason = 'lockfile uses a mapping key containing a control character (e.g. TAB/newline); such keys are never emitted by the canonical renderer and are not allowed (they could forge a package→stage composite)';
        return visit.BREAK;
      }
    },
  });
  return reason;
}

// Inspect each {@link PARITY_DIVERGENT_PACKAGES} block in the already-validated,
// already-parsed lock for any dangerous signal that the whole-block exclusion
// would otherwise launder into a clean parity result.  A finding fails the gate;
// a fully benign block is excluded from the byte comparison (its key never enters
// the render map).  Runs per side so a one-sided escape is attributed to the
// backend that produced it.  `packages` is the strict-validated map, so every
// list is a string[] (zod applied `.default([])`) and no field is unrecognised —
// the walk below needs no defensive coercion.
function collectDivergentDangers(packages: ParityPackages, side: string): DangerFinding[] {
  const findings: DangerFinding[] = [];
  for (const [pkg, pkgVal] of Object.entries(packages)) {
    if (!PARITY_DIVERGENT_PACKAGES.some((p) => pkg.startsWith(p))) continue;
    const benignSpawns = benignSpawnsFor(pkg);
    for (const [phase, fields] of Object.entries(pkgVal.lifecycle)) {
      const add = (field: string, value: string): void => {
        findings.push({ side, pkg, phase, field, value });
      };
      // A file escape — fully default-deny.  The agent's own events-file write is
      // dropped at the producer, so any escaped write here is a real escape (a
      // `$TMPDIR/<hash>/<hash>.jsonl` is forgeable post-tokenization and is NOT
      // waived — adversarial review round-9).
      for (const w of fields.escaped_writes) add('escaped_writes', w);
      // Native code loads / raw-syscall bypass / env tampering: never benign here.
      for (const d of fields.dlopen_attempts) add('dlopen_attempts', d);
      for (const a of fields.audit_bypass) add('audit_bypass', a);
      for (const t of fields.env_tamper) add('env_tamper', t);
      // Secret env access — a protected read is marked `<HIDDEN>`, but a
      // credential-bearing var the producer's protected set does not cover
      // surfaces as a RAW name, so also flag sensitive env NAMES (round-5).
      for (const e of fields.env_read) {
        if (e.startsWith('<HIDDEN>') || isSensitiveEnvRead(e)) add('env_read', e);
      }
      // Secret/credential file reads: `<HIDDEN>` OR a sensitive host path.
      for (const r of fields.external_reads) {
        if (r.startsWith('<HIDDEN>') || isSensitiveExternalRead(r)) add('external_reads', r);
      }
      // Real egress — any connect that is not a known-benign host resolver.
      // Strip the offline `<BLOCKED> ` prefix before the allowlist test so a
      // Linux blocked resolver and a macOS online resolver both reconcile;
      // report the ORIGINAL value so the danger names exactly what was recorded.
      for (const n of fields.network_attempts) {
        if (!PARITY_ONLY_NETWORK_ATTEMPTS.has(stripBlockedConnect(n))) add('network_attempts', n);
      }
      // Unapproved spawns (both the attempted and blocked lists).
      for (const s of fields.spawn_attempts) {
        if (!benignSpawns.has(s)) add('spawn_attempts', s);
      }
      for (const s of fields.spawn_blocked) {
        if (!benignSpawns.has(s)) add('spawn_blocked', s);
      }
    }
  }
  return findings;
}

function benignSpawnsFor(pkg: string): ReadonlySet<string> {
  const entry = PARITY_DIVERGENT_BENIGN_SPAWNS.find((e) => pkg.startsWith(e.prefix));
  return entry ? entry.spawns : new Set<string>();
}

function isSensitiveExternalRead(path: string): boolean {
  const lower = path.toLowerCase();
  if (SENSITIVE_FILE_SUBSTRINGS.some((p) => lower.includes(p))) return true;
  if (SENSITIVE_FILE_SUFFIXES.some((s) => lower.endsWith(s))) return true;
  return SENSITIVE_DOTENV_RE.test(lower);
}

// Split an env name into upper-cased tokens on separators (`_`, `-`, `.`, `/`,
// `:`, …) AND camelCase humps, so `npm_config__authToken` →
// [NPM, CONFIG, AUTH, TOKEN] and the whole-token markers (AUTH/KEY/PAT) match
// without the substring false-trips on `…UNAUTHORIZED` / `MONKEY` / `…_PATH`.
function envNameTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toUpperCase());
}

function isSensitiveEnvRead(name: string): boolean {
  const upper = name.toUpperCase();
  if (BENIGN_ENV_NAME_EXCEPTIONS.has(upper)) return false;
  if (SENSITIVE_ENV_SUBSTRINGS.some((p) => upper.includes(p))) return true;
  return envNameTokens(name).some((t) => SENSITIVE_ENV_TOKENS.has(t));
}

// Apply the parity-only noise filters to one lifecycle block, returning a new
// block.  env/read/network waivers are GLOBAL (ambient host/loader noise — see
// the PARITY_ONLY_ENV_READS header for why scoping them is unsound); the spawn
// waivers are PACKAGE-SCOPED so an unrelated package cannot launder esbuild's or
// simple-git-hooks' benign spawn as host noise.  Every item is first run through
// canonicalizeNpmDebugLog so the volatile npm debug-log basename matches across
// runs.  Fields with no waiver (escaped_writes, spawn_blocked, dlopen_attempts,
// audit_bypass, env_tamper) pass through unchanged.
function filterBlock(block: LifecycleBlockData, pkg: string): LifecycleBlockData {
  const canon = (items: ReadonlyArray<string>): string[] => items.map(canonicalizeNpmDebugLog);
  return {
    external_reads: canon(block.external_reads).filter((i) => !PARITY_ONLY_EXTERNAL_READS.has(i)),
    escaped_writes: canon(block.escaped_writes),
    env_read: canon(block.env_read).filter((i) => !PARITY_ONLY_ENV_READS.has(i)),
    spawn_attempts: canon(block.spawn_attempts).filter((i) => !isScopedSpawnNoise(i, pkg)),
    spawn_blocked: canon(block.spawn_blocked),
    dlopen_attempts: canon(block.dlopen_attempts),
    // Observe-only: strip the offline `<BLOCKED> ` prefix from connect entries
    // (NOT dlopen) on BOTH sides, then drop known host-resolver noise.  The
    // SURVIVING value is the stripped form, so a Linux blocked connect and a
    // macOS online connect re-render to the identical `connect <host>:<port>`.
    network_attempts: canon(block.network_attempts)
      .map(stripBlockedConnect)
      .filter((i) => !PARITY_ONLY_NETWORK_ATTEMPTS.has(i)),
    audit_bypass: canon(block.audit_bypass),
    env_tamper: canon(block.env_tamper),
  };
}

// A package-scoped benign spawn is reconciled ONLY inside the package it was
// observed in (the waiver's `pkg` is matched as a NAME PREFIX against the
// enclosing package key), so a different package reading the same spawn one-sided
// still surfaces.
function isScopedSpawnNoise(item: string, pkg: string): boolean {
  return PARITY_ONLY_SCOPED_SPAWNS.some((w) => w.spawn === item && pkg.startsWith(w.pkg));
}

// Symmetric-presence check: a divergent package (and each of its lifecycle
// stages) is excluded from the byte comparison, so if any appears on ONE side
// only the comparison would silently accept it (both sides end up without the
// block).  A one-sided divergent package — OR a one-sided / mismatched stage
// inside a two-sided package — is a resolution/producer desync; fail the gate and
// name the side it is missing from.  `divergentKeys` holds both the bare package
// key and `${pkg}\t${stage}` composites (see canonicalize).
function presenceDangers(left: CanonResult, right: CanonResult, opts: ParityOptions): DangerFinding[] {
  const out: DangerFinding[] = [];
  const oneSided = (present: CanonResult, absent: CanonResult, presentLabel: string, absentLabel: string): void => {
    for (const k of present.divergentKeys) {
      if (absent.divergentKeys.has(k)) continue;
      const tab = k.indexOf('\t');
      const pkg = tab === -1 ? k : k.slice(0, tab);
      const stage = tab === -1 ? '-' : k.slice(tab + 1);
      const what = tab === -1 ? 'divergent package' : `divergent package stage \`${stage}\``;
      out.push({
        side: presentLabel,
        pkg,
        phase: stage,
        field: 'divergent_presence',
        value: `present on ${presentLabel} but absent on ${absentLabel} — a one-sided ${what} cannot be excluded from comparison`,
      });
    }
  };
  oneSided(left, right, opts.leftLabel, opts.rightLabel);
  oneSided(right, left, opts.rightLabel, opts.leftLabel);
  return out;
}

// Observe-only network reconciliation.  Linux runs Phase B offline (`unshare
// -n`) so every connect records `<BLOCKED> connect <host>:<port>`; macOS-bare
// stays ONLINE (the shim forwards connect/connectx and records the TRUE result)
// so its succeeded connect records `connect <host>:<port>` with NO prefix.  Strip
// the `<BLOCKED> ` prefix from connect entries on BOTH sides so both reduce to
// `connect <host>:<port>` and reconcile.  NARROW by design: only an entry whose
// remainder begins `connect ` is touched — dlopen entries are ALSO
// `<BLOCKED> <path>` (normalize.ts) but never begin `connect `, so they pass
// through untouched (the same scoping HEAD's canonicalizeConnect regex used).
function stripBlockedConnect(item: string): string {
  return item.startsWith('<BLOCKED> connect ') ? item.slice('<BLOCKED> '.length) : item;
}

function canonicalizeNpmDebugLog(line: string): string {
  const match = NPM_DEBUG_LOG_BASENAME.exec(line);
  if (!match) return line;

  const prefix = line.slice(0, match.index);
  if (
    !prefix.endsWith('/.npm/_logs/') &&
    !prefix.endsWith('$HOME/.npm/_logs/') &&
    !prefix.endsWith('$CACHE/_logs/')
  ) {
    return line;
  }

  return `${prefix}<timestamp>-debug-${match[1]}.log`;
}

function parseArguments(argv: ReadonlyArray<string>): ParityOptions {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      left: { type: 'string' },
      right: { type: 'string' },
      'left-label': { type: 'string', default: 'left' },
      'right-label': { type: 'string', default: 'right' },
      report: { type: 'string' },
    },
    strict: true,
    allowPositionals: false,
  });

  if (typeof values.left !== 'string' || values.left.length === 0) {
    throw new ParityArgError('--left <path> is required');
  }
  if (typeof values.right !== 'string' || values.right.length === 0) {
    throw new ParityArgError('--right <path> is required');
  }

  return {
    left: values.left,
    right: values.right,
    leftLabel: values['left-label'] ?? 'left',
    rightLabel: values['right-label'] ?? 'right',
    reportPath: typeof values.report === 'string' ? values.report : null,
  };
}

// Use the system `diff -u` rather than implementing LCS in TypeScript: the
// output format is stable across coreutils versions and every CI runner has
// it, the comparison is already line-canonicalised before we get here, and
// any future enhancement (filters, statistics) can read the unified-diff
// stream rather than its own algorithm.
function unifiedDiff(opts: {
  leftPath: string;
  rightPath: string;
  leftLabel: string;
  rightLabel: string;
}): string {
  try {
    execFileSync('diff', [
      '-u',
      '--label', opts.leftLabel,
      '--label', opts.rightLabel,
      opts.leftPath,
      opts.rightPath,
    ], { stdio: 'pipe' });
    return '';
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer; stderr?: Buffer };
    // diff exit 1 = differences found (expected); exit 2 = trouble.
    if (e.status === 1 && e.stdout) return e.stdout.toString('utf8');
    const stderr = e.stderr ? e.stderr.toString('utf8') : '';
    throw new Error(`diff failed (exit=${String(e.status ?? '?')}): ${stderr}`);
  }
}

function summariseDiff(diff: string): { insertions: number; deletions: number; hunks: number } {
  let insertions = 0;
  let deletions = 0;
  let hunks = 0;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) insertions++;
    else if (line.startsWith('-') && !line.startsWith('---')) deletions++;
    else if (line.startsWith('@@')) hunks++;
  }
  return { insertions, deletions, hunks };
}

function renderMarkdownReport(args: {
  opts: ParityOptions;
  ok: boolean;
  diff: string;
  dangers: DangerFinding[];
}): string {
  const { opts, ok, diff, dangers } = args;
  const table = [
    '| side | path | label |',
    '|---|---|---|',
    `| left | \`${opts.left}\` | ${opts.leftLabel} |`,
    `| right | \`${opts.right}\` | ${opts.rightLabel} |`,
    '',
  ];

  if (ok) {
    return [
      '# Parity report',
      '',
      `**Verdict:** parity holds — the canonical re-renders are byte-equal, every divergent package is present on both sides, and no dangerous signal was found in any excluded divergent package.`,
      '',
      ...table,
      'Volatile fields (`generated_at`, `manager_lockfile_sha256`) and known parity-only host/VMM noise were canonicalised before comparison.',
      '',
    ].join('\n');
  }

  const parts: string[] = [
    '# Parity report',
    '',
    `**Verdict:** diverged — NOT safe to treat as parity.`,
    '',
    ...table,
  ];

  if (dangers.length > 0) {
    parts.push(
      `**Blocking signal(s) (${dangers.length}):** a malformed/structural lock, a one-sided divergent package, or an escape hidden inside an excluded divergent package — none may launder into a clean parity result.`,
      '',
      '| side | package | phase | field | value |',
      '|---|---|---|---|---|',
      ...dangers.map(
        (d) =>
          `| ${d.side} | \`${d.pkg}\` | ${d.phase} | ${d.field} | \`${d.value.replace(/\|/g, '\\|')}\` |`,
      ),
      '',
    );
  }

  if (diff.trim() !== '') {
    const { insertions, deletions, hunks } = summariseDiff(diff);
    parts.push(
      `**Diff summary:** ${hunks} hunk(s), ${insertions} insertion(s), ${deletions} deletion(s).`,
      '',
      'See `docs/parity-testing.md` for how to interpret arm64-on-Apple-Silicon divergence vs. real audit drift. Known parity-only host/VMM noise is filtered before this diff.',
      '',
      '<details>',
      '<summary>Unified diff</summary>',
      '',
      '```diff',
      diff.trimEnd(),
      '```',
      '',
      '</details>',
      '',
    );
  }

  return parts.join('\n');
}

function main(argv: ReadonlyArray<string>): number {
  let opts: ParityOptions;
  try {
    opts = parseArguments(argv);
  } catch (err) {
    if (err instanceof ParityArgError) {
      process.stderr.write(`parity-diff: ${err.message}\n`);
      process.stderr.write('usage: parity-diff.ts --left <path> --right <path>\n');
      process.stderr.write('                      [--left-label <name>] [--right-label <name>] [--report <path>]\n');
      return 2;
    }
    throw err;
  }

  let leftRaw: string;
  let rightRaw: string;
  try {
    leftRaw = readFileSync(opts.left, 'utf8');
  } catch {
    process.stderr.write(`parity-diff: cannot read --left at ${opts.left}\n`);
    return 2;
  }
  try {
    rightRaw = readFileSync(opts.right, 'utf8');
  } catch {
    process.stderr.write(`parity-diff: cannot read --right at ${opts.right}\n`);
    return 2;
  }

  const left = canonicalize(leftRaw, opts.leftLabel);
  const right = canonicalize(rightRaw, opts.rightLabel);

  const blockDangers = [...left.dangers, ...right.dangers];
  // A whole-lock fatal danger (parse / structure / schema) means one render is
  // empty and untrustworthy — skip the symmetric-presence check (its divergent
  // key set is empty) and suppress the byte diff (it would be a noisy full-file
  // delete); the danger message is the signal.
  const hasFatal = blockDangers.some((d) => d.pkg === '<whole-lock>');
  const presence = hasFatal ? [] : presenceDangers(left, right, opts);
  const dangers = [...blockDangers, ...presence];

  const textMatch = left.text === right.text;
  // Parity holds ONLY when the comparable text is byte-equal AND no dangerous
  // signal fired: an escape inside an excluded divergent package, a one-sided
  // divergent package, or a malformed/structural lock all fail the gate even
  // when the comparable text matches.
  const ok = textMatch && dangers.length === 0;

  let diff = '';
  if (!textMatch && !hasFatal) {
    const stage = mkdtempSync(join(tmpdir(), 'parity-diff-'));
    const leftPath = join(stage, 'left.yml');
    const rightPath = join(stage, 'right.yml');
    writeFileSync(leftPath, left.text);
    writeFileSync(rightPath, right.text);
    diff = unifiedDiff({
      leftPath,
      rightPath,
      leftLabel: opts.leftLabel,
      rightLabel: opts.rightLabel,
    });
    process.stdout.write(diff);
  }

  if (dangers.length > 0) {
    process.stdout.write(formatDangers(dangers));
  }

  if (opts.reportPath !== null) {
    writeFileSync(opts.reportPath, renderMarkdownReport({ opts, ok, diff, dangers }));
  }

  return ok ? 0 : 1;
}

// Human-readable danger block for stdout / CI logs.
function formatDangers(dangers: DangerFinding[]): string {
  const lines = [
    '',
    '!! DANGER: blocking signal(s) — a malformed/structural lock, a one-sided',
    '!! divergent package, or an escape hidden inside an excluded (platform-',
    '!! divergent) package that is screened but not byte-compared.',
    '!! Parity FAILS — inspect before trusting this lock:',
    '',
  ];
  for (const d of dangers) {
    lines.push(`  [${d.side}] ${d.pkg} ${d.phase}.${d.field}: ${d.value}`);
  }
  lines.push('');
  return lines.join('\n');
}

process.exit(main(process.argv.slice(2)));

// script-jail — env-shim (Rust no_std cdylib)
//
// LD_PRELOAD shim: wraps getenv / secure_getenv / __secure_getenv to audit
// env-var reads and hide protected names. The contract (exported symbols,
// JSONL event shape, env-var protocol) is exercised by the test suite at
// test/guest/env-shim.test.ts — that's the regression gate.
//
// Design notes that are specific to the Rust port:
//   - `#![no_std]`: this library is loaded into every process spawned by the
//     audited lifecycle scripts, including very early in their startup.
//     Avoid std startup, allocator, and panic-unwinding machinery.
//   - `panic = "abort"` + `#[panic_handler]` calling `libc::abort()`.
//   - Recursion guard via `pthread_key_create` (matches C's __thread int).
//     The key is created at the very top of the constructor, before any
//     dlsym call, because dlsym / open may themselves call getenv.
//   - All buffers are fixed-size stack allocations; no allocator is linked.

#![no_std]
// Rust 2024 promoted `unsafe_op_in_unsafe_fn` from allow to warn.  This crate
// is a libc-shim cdylib whose `unsafe extern "C" fn` exports contain dozens of
// FFI/raw-pointer operations; wrapping each one in an additional `unsafe { }`
// block adds noise without changing the trust boundary, since the crate has
// no `extern "Rust"` callers and every export is, by design, the trusted
// landing point for an LD_PRELOAD interception.  Suppress at crate root so
// the existing 2021 semantics carry over verbatim.
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_uint, c_void};
#[cfg(target_os = "linux")]
use core::mem::transmute;
use core::ptr;
#[cfg(target_os = "linux")]
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

// macOS-only modules: the Mach-O `__interpose` machinery plus the file-op and
// connect hooks that Linux gets from strace.  Each is `#[cfg(target_os =
// "macos")]` end-to-end so the Linux ELF build is byte-for-byte unchanged.
#[cfg(target_os = "macos")]
mod fileops;
#[cfg(target_os = "macos")]
mod interpose;
#[cfg(target_os = "macos")]
mod net;

// ── panic handler ──────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { libc::abort() }
}

// ── tunables ───────────────────────────────────────────────────────────────

// LOAD-BEARING: `MAX_PROTECTED` and `NAME_MAX_LEN` must stay in lockstep with
// `MAX_PROTECTED_ENV_NAMES` and `PROTECTED_NAME_MAX_LEN` in
// `src/shim/canon-buf-len.ts`.  Those TS constants gate `buildChildEnv` so the
// agent refuses to compose a `SCRIPT_JAIL_PROTECTED_ENV_NAMES` value that the
// shim would silently truncate inside `load_protect_list_from_bytes` (either
// by exceeding the entry-count cap or by exceeding the per-entry byte cap).
// Without the matching agent-side guard, the dropped names leak through
// env-spy / shim getenv unannotated.  Any change to either constant here MUST
// be mirrored in canon-buf-len.ts (and vice-versa).  See also CANON_BUF_LEN
// (Finding 2 in the same audit-trust series) and the comment next to
// `CANON_PROTECTED_ENV_NAMES_MAX_LEN`.
const MAX_PROTECTED: usize = 64;
const NAME_MAX_LEN: usize = 256;
const JSONL_BUF: usize = 4096;
const TRUNC_MARKER: &[u8] = b"<truncated>";
// macOS-only: caps for the `"argv"` array serialized into the exec JSONL record
// (see `append_argv_field`).  Fixed so the output is DETERMINISTIC regardless of
// how long / how many argv entries a lifecycle script supplies — a process that
// times its exec differently must produce byte-identical JSONL.  Truncation past
// these caps is deterministic (drop trailing elements / clamp per-element).
#[cfg(target_os = "macos")]
const MAX_ARGV_ELEMS: usize = 64;
#[cfg(target_os = "macos")]
const MAX_ARGV_ELEM_LEN: usize = 512;
// LOAD-BEARING: must stay in lockstep with `CANON_PROTECTED_ENV_NAMES_MAX_LEN`
// in `src/shim/canon-buf-len.ts`.  That constant equals `CANON_BUF_LEN - 1`
// (max payload bytes excluding the NUL terminator) and gates the agent's
// `buildChildEnv` against composing a `SCRIPT_JAIL_PROTECTED_ENV_NAMES` value
// that would silently truncate inside `capture_canon` below — which would
// drop the suffix from the protect list and leak those env-var names through
// env-spy / shim getenv unannotated.  Any change to CANON_BUF_LEN here MUST
// be mirrored in `src/shim/canon-buf-len.ts` (and vice versa).
const CANON_BUF_LEN: usize = 1024;
/// Room for: LD_PRELOAD + NODE_OPTIONS + 9 × SCRIPT_JAIL_* injected entries
/// (must be >= 2 + STICKY_VARS.len()).  Margin keeps small future additions
/// safe.
const MAX_ENVP_GROWTH: usize = 14;
/// Sanity cap on input envp length — rejects hostile or corrupted envps.
const MAX_ENVP_SANITY: usize = 8192;

// ── platform linker-var names ───────────────────────────────────────────────
//
// The env var that names the preloaded shim (re-injected on every exec from
// CANON_PRELOAD_PATH), plus the dynamic-linker search-path vars that must be
// STRIPPED so an attacker cannot load a malicious DSO before our wrappers
// shadow the audited symbols.  These differ between the two loaders:
//   LINUX  (ld.so):   LD_PRELOAD; strip LD_AUDIT + LD_LIBRARY_PATH.
//   MACOS  (dyld):    DYLD_INSERT_LIBRARIES; strip DYLD_LIBRARY_PATH +
//                     DYLD_FRAMEWORK_PATH.
// Both names are also listed in AUDIT_PROTECTED_NAMES so the in-process
// setenv/unsetenv/putenv guards refuse to restore them between the exec-time
// strip and the next exec.
#[cfg(target_os = "linux")]
const PRELOAD_VAR: &[u8] = b"LD_PRELOAD";
#[cfg(target_os = "macos")]
const PRELOAD_VAR: &[u8] = b"DYLD_INSERT_LIBRARIES";

/// Dynamic-linker search-path vars stripped from every child envp.
#[cfg(target_os = "linux")]
const LINKER_STRIP_VARS: &[&[u8]] = &[b"LD_AUDIT", b"LD_LIBRARY_PATH"];
#[cfg(target_os = "macos")]
const LINKER_STRIP_VARS: &[&[u8]] = &[b"DYLD_LIBRARY_PATH", b"DYLD_FRAMEWORK_PATH"];

// ── protect-list (fixed-size, written once at constructor time) ────────────

struct ProtectedList {
    names: core::cell::UnsafeCell<[[u8; NAME_MAX_LEN]; MAX_PROTECTED]>,
    count: AtomicUsize,
}
// SAFETY: writes to `names` happen exclusively in the ctor before INIT_DONE is
// set; readers only access it after observing INIT_DONE via Acquire.
unsafe impl Sync for ProtectedList {}

static PROTECTED: ProtectedList = ProtectedList {
    names: core::cell::UnsafeCell::new([[0u8; NAME_MAX_LEN]; MAX_PROTECTED]),
    count: AtomicUsize::new(0),
};

// ── canonical sticky env-var buffers (written once at constructor time) ─────

struct CanonBuf {
    bytes: core::cell::UnsafeCell<[u8; CANON_BUF_LEN]>,
    len: AtomicUsize,
}
// SAFETY: writes to `bytes` happen exclusively in the ctor before INIT_DONE is
// set; readers only access it after observing INIT_DONE via Acquire.
unsafe impl Sync for CanonBuf {}

static CANON_NODE_OPTIONS: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_PRELOAD_PATH: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// Sticky SCRIPT_JAIL_* vars are also snapshotted at shim_init from the trusted
// parent environ.  Reading them via libc::getenv at exec-time is UNSAFE: a
// native attacker can mutate `environ[i]` directly (bypassing setenv/putenv
// guards) to redirect the child's audit chain (log file, protect-list path,
// platform/arch spoof).  Capturing once during the ctor — before any user
// code runs — gives us a tamper-proof source of truth for rewrite_envp.

static CANON_LOG_FILE: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_LOG_FD: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// Finding 4 (audit-trust): the protected-env list lives directly inside an
// env var (`SCRIPT_JAIL_PROTECTED_ENV_NAMES=NAME1,NAME2,…`) snapshotted into
// this CanonBuf at shim_init.  The previous design (load from a `/tmp` file
// pointed at by SCRIPT_JAIL_PROTECTED_ENV_FILE) was vulnerable to a same-UID
// lifecycle script overwriting / truncating the file before spawning a
// child; that child's shim would then load the attacker's weakened list at
// its own shim_init and stop hiding NPM_TOKEN / GH_TOKEN / etc.
//
// Inline-in-env removes the file entirely.  STICKY_VARS re-injects the
// canonical value on every exec (overwrite_env), so a descendant cannot
// strip or shorten the list either.  AUDIT_PROTECTED_NAMES additionally
// refuses setenv/unsetenv/putenv on the var name itself.
static CANON_PROTECTED_ENV_NAMES: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_SPOOF_PLATFORM: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_SPOOF_ARCH: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// MACOS only: directory holding the materialized, ad-hoc-re-signed copies of
// `/bin/sh`, `/bin/bash`, and the coreutils a lifecycle script may exec.  SIP
// strips `DYLD_INSERT_LIBRARIES` for system binaries under `/bin` and
// `/usr/bin`, so the shim would never load into them; `sip_redirect`
// (dispatch_exec / dispatch_spawn) rewrites the program path into this
// directory's re-signed copy, which DOES honor DYLD.  Snapshotted at ctor like
// every other sticky var (tamper-proof) and re-injected on every exec.  Shares
// the CanonBuf cap (see canon-buf-len.ts).
#[cfg(target_os = "macos")]
static CANON_SHELL_SHIM_DIR: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// MACOS only: the DIRECTORY holding THIS process's own executable, snapshotted
// at shim_init via _NSGetExecutablePath (then lexically canonicalized and
// trimmed to its parent dir).  Under the bare backend the shim is loaded into
// the PROVISIONED, re-signed node, whose layout is
//   <cacheDir>/script-jail-node-mac/node-<ver>-<arch>-vp<v>/vp-home/js_runtime/.../bin/node
// and the corepack/pnpm/npm/npx/yarn shims sit in that SAME bin/ dir.  So a
// node-spawned-node (pnpm worker, npm child) and every package-manager shim
// resolve to a path UNDER this directory — it is a "keep-audited" root.
//
// WHY a captured self-exec dir and NOT a SCRIPT_JAIL_CACHE_DIR getenv: the bare
// backend's lifecycle child env is sanitized (sanitizeLifecycleBaseEnv,
// src/guest/agent.ts) which STRIPS every SCRIPT_JAIL_* var not on a small
// allow-list — SCRIPT_JAIL_CACHE_DIR is NOT on it, so the var is absent inside
// the very install children where the classifier runs.  _NSGetExecutablePath is
// always available and points at the audited node regardless of env scrubbing,
// which makes it the robust signal.  Cap-shared with the other CanonBufs
// (CANON_BUF_LEN == 1024 == PATH_MAX, so a real toolchain path always fits).
// FAIL-SAFE: if capture fails and this dir stays empty, is_external_system_tool
// disables the strip entirely (treats everything as keep-audited) rather than
// risk blinding the audited node — see the empty-anchor guard there.
#[cfg(target_os = "macos")]
static CANON_SELF_EXEC_DIR: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// MACOS only: the process's working directory snapshotted ONCE at shim_init via
// getcwd (then lexically canonicalized).  For the ROOT audited process this is
// the INSTALL ROOT — captured BEFORE any lifecycle script can `chdir` — covering
// node_modules/.bin, the in-repo .pnpm-store, and package-owned native helpers
// that live under the install dir.
//
// WHY an IMMUTABLE init-cwd in ADDITION to the live getcwd() read in
// is_external_system_tool (adversarial-review finding, high, 2026-06): the live
// getcwd() check classifies against the CURRENT cwd, so attacker-controlled
// lifecycle code can `chdir('/tmp')` and THEN exec an ABSOLUTE package-owned
// helper from the original install dir.  That target is outside the provision
// roots AND outside the new cwd, so the live check would FALSE-STRIP a
// package-owned helper that Linux still audits — blinding it (and its subtree)
// and producing a byte-divergence against the Linux source-of-truth.  Capturing
// the cwd once at ctor (before user code runs) and adding it as a keep root
// closes that chdir window: a helper under the install root stays audited
// regardless of any runtime chdir.  This is a UNION with — not a replacement for
// — the live getcwd() check (the union only EXPANDS the keep set, so it can never
// newly false-STRIP something the current code keeps).
//
// Same CanonBuf / ctor-only-writer / Ordering::Release pattern as
// CANON_SELF_EXEC_DIR.  FAIL-SAFE: if capture fails the buf stays empty and the
// keep-root check ignores it (empty root never matches) — it simply does not
// contribute, falling back to the other anchors.
#[cfg(target_os = "macos")]
static CANON_INIT_CWD: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// MACOS only: the install/repo root (the agent's `config.work_dir`), passed in
// via the SCRIPT_JAIL_WORK_DIR env var and snapshotted at shim_init like every
// other sticky var.  This is the WHOLE install tree — it covers BOTH
// `node_modules/<pkg>` (a lifecycle child's ctor cwd) AND its SIBLING
// `node_modules/.bin/<helper>` (top-level shims).  is_external_system_tool uses
// it as keep-root #6 to close a false-strip class the init-cwd anchor misses:
// after a lifecycle script `chdir`s into `node_modules/<pkg>`, a top-level
// `node_modules/.bin/<helper>` lies OUTSIDE the per-package init-cwd anchor (it
// is a SIBLING of the package dir, not under it) — so the helper would be
// FALSE-STRIPPED of DYLD and run un-shimmed, blinding it (and its subtree) and
// producing a spurious parity GATE FAILURE vs the Linux source-of-truth, which
// still audits it.  Anchoring on the install root keeps the entire tree audited
// regardless of any per-package chdir.
//
// WHY a sticky env var (and not the live getcwd / init-cwd snapshot): the agent
// KNOWS the install root authoritatively (config.work_dir) and passes it down,
// so it is process-independent — the SAME value in the orchestrator node, the
// substituted bash, and every node-spawned helper, no matter which process is
// classifying.  Captured (and re-injected) like every other sticky var so a
// descendant cannot strip it; unsetting it is additionally audited as
// env_tamper (AUDIT_PROTECTED_NAMES), so tampering is self-defeating.  This does
// NOT over-broaden: a real system tool (/usr/bin/git, /opt/homebrew/bin/git)
// lives OUTSIDE work_dir → still classified external → the git-leak audit-blind
// fix stays intact.  Shares the CanonBuf cap (see canon-buf-len.ts).
// FAIL-SAFE: if the var is absent the buf stays empty and the keep-root check
// in is_external_system_tool ignores it (empty root never matches) — it simply
// does not contribute, falling back to the other anchors (NOT "keep all").
#[cfg(target_os = "macos")]
static CANON_WORK_DIR: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

// MACOS only: native file/connect auditing is enabled for Phase B, but kept
// off during Phase A fetch.  Linux Phase A has the env preload but no strace
// syscall stream; this flag gives macOS the same phase boundary while still
// preserving env_read coverage in both phases.
#[cfg(target_os = "macos")]
static CANON_MACOS_AUDIT_OPS: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

#[cfg(target_os = "macos")]
static MACOS_AUDIT_OPS: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
pub(crate) fn macos_audit_ops_enabled() -> bool {
    MACOS_AUDIT_OPS.load(Ordering::Acquire)
}

// npm lifecycle attribution, snapshotted at shim_init from THIS process's own
// (inherited) environ.  Stamped into every `exec` record (emit_exec_for_pid) so
// the guest agent can attribute a spawn to its owning package WITHOUT walking
// /proc — the in-process read is authoritative (never reaped) and deterministic
// across backends, which is what closes the macOS-VZ-vs-Docker attribution race
// for short-lived `.bin` shell-shim helpers (dirname/sed/uname).  Captured at
// ctor (not exec-time): npm sets these per-script and they are constant for the
// process, and a ctor snapshot resists a script mutating npm_package_name
// mid-run to frame a sibling package.  These are NOT sticky/re-injected (unlike
// the SCRIPT_JAIL_* / LD_PRELOAD vars) — they propagate naturally via fork/exec
// env inheritance and the agent only needs to READ them.
static CANON_NPM_PACKAGE_NAME: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_NPM_PACKAGE_VERSION: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

static CANON_NPM_LIFECYCLE_EVENT: CanonBuf = CanonBuf {
    bytes: core::cell::UnsafeCell::new([0u8; CANON_BUF_LEN]),
    len: AtomicUsize::new(0),
};

/// Returns the live byte slice of a CanonBuf (without the NUL terminator).
/// Safe to call after INIT_DONE is observed via Acquire — by then the ctor has
/// finished writing and `len` is stable.
unsafe fn canon_bytes(buf: &CanonBuf) -> &[u8] {
    let len = buf.len.load(Ordering::Acquire);
    let bytes = &*buf.bytes.get();
    &bytes[..len]
}

/// True when the NUL-terminated `cpath` equals the audit events-file path
/// (SCRIPT_JAIL_LOG_FILE, captured into CANON_LOG_FILE at ctor).
///
/// The macOS fileops hooks must NEVER record operations on the shim's OWN
/// events file: env-spy opens SCRIPT_JAIL_LOG_FILE BY PATH as its env_read sink
/// (and re-opens it by path on EBADF — anti-tamper Finding 4), and without this
/// skip that open would surface as a spurious `write` event attributed to the
/// running lifecycle script (self-observation of the audit channel).  On Linux
/// the file-op stream comes from strace and this suppression lives in the
/// producer (phase-install.ts); here it is applied at source — hence
/// `#[cfg(target_os = "macos")]`.  Returns false when no log path was captured
/// (e.g. the fd-only test configuration).
///
/// KNOWN RESIDUAL (adversarial review round-10, finding F3): the events path is
/// READABLE by package code, so a malicious shim-loaded pid that opens this exact
/// path is also suppressed here — the SAME accepted trusted-pid residual as the
/// Linux producer drop.  env-spy's legitimate by-path reopen is indistinguishable
/// from a malicious open at the open() layer, so flagging package opens of the
/// log path would break the reopen and flake the parity gate.  See the matching
/// note in src/guest/phase-install.ts and docs/divergence.md.
#[cfg(target_os = "macos")]
pub(crate) unsafe fn path_is_audit_log(cpath: *const c_char) -> bool {
    let log = canon_bytes(&CANON_LOG_FILE);
    if log.is_empty() {
        return false;
    }
    let mut i = 0usize;
    loop {
        let b = *cpath.add(i) as u8;
        if b == 0 {
            return i == log.len();
        }
        if i >= log.len() || log[i] != b {
            return false;
        }
        i += 1;
    }
}

// ── log fd ─────────────────────────────────────────────────────────────────

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

// ── real symbol pointers (resolved via dlsym at ctor time) ─────────────────
//
// LINUX: the preloaded shadow symbols are reached by name, so we must dlsym
// `RTLD_NEXT` for the genuine libc implementation and call THROUGH the saved
// pointer.  MACOS: dyld `__interpose` rewrites the audited binary's bindings,
// and (proven by the spike) a DIRECT `libc::<fn>` reference from inside our
// replacement reaches the real symbol WITHOUT re-entering the interpose table.
// So on macOS the `real_*_raw` helpers below call `libc::` directly and there
// are no `REAL_*` AtomicPtr slots / dlsym block at all.

#[cfg(target_os = "linux")]
type GetenvFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

#[cfg(target_os = "linux")]
static REAL_CLEARENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_EXECV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_EXECVEAT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_EXECVP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_EXECVPE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_FEXECVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_GETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_POSIX_SPAWN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_POSIX_SPAWNP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_PUTENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_SECURE_GETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_SETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_os = "linux")]
static REAL_UNSETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[cfg(target_os = "linux")]
unsafe fn real_getenv_raw(name: *const c_char) -> *mut c_char {
    let p = REAL_GETENV.load(Ordering::Acquire);
    if p.is_null() {
        return ptr::null_mut();
    }
    let f: GetenvFn = transmute(p);
    f(name)
}

#[cfg(target_os = "linux")]
unsafe fn real_secure_getenv_raw(name: *const c_char) -> *mut c_char {
    let p = REAL_SECURE_GETENV.load(Ordering::Acquire);
    if !p.is_null() {
        let f: GetenvFn = transmute(p);
        return f(name);
    }
    // musl fallback: secure_getenv absent, but script-jail guests are never
    // setuid, so secure_getenv == getenv semantically.
    real_getenv_raw(name)
}

// MACOS: direct same-image libc reference (no interpose recursion — R8).
#[cfg(target_os = "macos")]
unsafe fn real_getenv_raw(name: *const c_char) -> *mut c_char {
    libc::getenv(name)
}

// MACOS has no secure_getenv / __secure_getenv (and the guests are never
// setuid), so secure_getenv == getenv.  The interpose table only ever rebinds
// `getenv`; this exists so shared code that calls `real_secure_getenv_raw`
// compiles, but no `secure_getenv` interpose entry is emitted on macOS.
#[cfg(target_os = "macos")]
unsafe fn real_secure_getenv_raw(name: *const c_char) -> *mut c_char {
    libc::getenv(name)
}

// MACOS: REAL realpath — resolve `path` (collapsing symlinks + `.`/`..`) into the
// caller-provided `resolved` buffer (MUST be >= PATH_MAX bytes).  Like the other
// `real_*_raw` helpers this is a DIRECT same-image `libc::realpath` reference: we
// never interpose `realpath` (it is not in our interpose table — the only
// `b"realpath"` byte string elsewhere is a SIP_COREUTILS *applet name*), and even
// if a downstream load DID interpose it, a direct `libc::<fn>` call from inside
// our own image reaches the genuine symbol WITHOUT re-entering the interpose
// table (see the real-symbol note above — R8).  No malloc: we pass a non-NULL
// buffer (passing NULL would make libc malloc the result, which is forbidden in
// our no_std hot path).  Returns NULL (errno set) on ENOENT / ELOOP / etc., which
// the sole caller treats as "unresolvable → fall back to the lexical path".
#[cfg(target_os = "macos")]
unsafe fn real_realpath_raw(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    libc::realpath(path, resolved)
}

// ── init state + pthread-key-backed recursion guard ────────────────────────

static INIT_DONE: AtomicBool = AtomicBool::new(false);
static KEY_READY: AtomicBool = AtomicBool::new(false);
// pthread_key_t is c_uint on Linux. Store as usize for atomic access.
static IN_SHIM_KEY: AtomicUsize = AtomicUsize::new(0);

fn in_shim() -> bool {
    if !KEY_READY.load(Ordering::Acquire) {
        return false;
    }
    let key = IN_SHIM_KEY.load(Ordering::Acquire) as libc::pthread_key_t;
    unsafe { !libc::pthread_getspecific(key).is_null() }
}

fn set_in_shim(v: bool) {
    if !KEY_READY.load(Ordering::Acquire) {
        return;
    }
    let key = IN_SHIM_KEY.load(Ordering::Acquire) as libc::pthread_key_t;
    let val: *mut c_void = if v { 1 as *mut c_void } else { ptr::null_mut() };
    unsafe {
        let _ = libc::pthread_setspecific(key, val);
    }
}

const NODE_STARTUP_DONE_ENV: &[u8] = b"SCRIPT_JAIL_NODE_STARTUP_DONE";

unsafe fn putenv_name_eq_bytes(string: *mut c_char, name_bytes: &[u8]) -> bool {
    if string.is_null() {
        return false;
    }
    let len = name_bytes.len();
    for i in 0..len {
        if (*string.add(i) as u8) != name_bytes[i] {
            return false;
        }
    }
    let next = *string.add(len) as u8;
    next == b'=' || next == 0
}

// ── errno (cfg-gated for cross-platform `cargo check`) ─────────────────────

#[cfg(target_os = "linux")]
unsafe fn errno() -> c_int {
    *libc::__errno_location()
}
#[cfg(target_os = "macos")]
unsafe fn errno() -> c_int {
    *libc::__error()
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
unsafe fn errno() -> c_int {
    0
}

/// Set errno to `e` (no-op on platforms without a known location).  Caller
/// must hold the recursion guard if there is any risk of the underlying
/// thread-local accessor calling back into a shim wrapper.
#[cfg(target_os = "linux")]
unsafe fn set_errno(e: c_int) {
    *libc::__errno_location() = e;
}
#[cfg(target_os = "macos")]
unsafe fn set_errno(e: c_int) {
    *libc::__error() = e;
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
unsafe fn set_errno(_e: c_int) {}

// ── string helpers ─────────────────────────────────────────────────────────

unsafe fn cstr_eq(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    let mut i = 0usize;
    while i < NAME_MAX_LEN {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
    }
    false
}

unsafe fn cstr_is_empty(s: *const c_char) -> bool {
    s.is_null() || *s == 0
}

// Parse a decimal C-string into a non-negative c_int up to 65535.
// Returns -1 on any non-digit, overflow, or empty input.
unsafe fn parse_fd(s: *const c_char) -> c_int {
    if s.is_null() {
        return -1;
    }
    let mut result: i32 = 0;
    let mut i = 0usize;
    let mut saw_digit = false;
    loop {
        let c = *s.add(i) as u8;
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return -1;
        }
        result = match result.checked_mul(10) {
            Some(v) => v,
            None => return -1,
        };
        result = match result.checked_add((c - b'0') as i32) {
            Some(v) => v,
            None => return -1,
        };
        if result > 65535 {
            return -1;
        }
        saw_digit = true;
        i += 1;
        if i > 10 {
            return -1;
        }
    }
    if !saw_digit { -1 } else { result }
}

unsafe fn is_protected(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    let count = PROTECTED.count.load(Ordering::Acquire).min(MAX_PROTECTED);
    let table = &*PROTECTED.names.get();
    for i in 0..count {
        let entry = table[i].as_ptr() as *const c_char;
        if cstr_eq(entry, name) {
            return true;
        }
    }
    false
}

// ── protect-list loader ────────────────────────────────────────────────────

// Finding 4 (audit-trust): the protected-env list is parsed from
// `SCRIPT_JAIL_PROTECTED_ENV_NAMES` — a comma-separated, init-time-captured
// env var — not from a /tmp file path that any same-UID lifecycle script
// could overwrite.  See the CANON_PROTECTED_ENV_NAMES static for the
// security rationale.
//
// Behaviour: the input is a byte slice (the contents of a CanonBuf, sans
// trailing NUL).  Entries are separated by ',' or '\n' (the latter only as
// belt-and-braces for any future config-file fallback — production agents
// emit comma-separated).  Empty entries and leading-'#' entries are
// skipped.  Entries longer than NAME_MAX_LEN-1 bytes are dropped entirely
// (matching the original file-based behaviour for "overlong" lines).
//
// Each commit writes into `PROTECTED.names` and bumps `count`; the caller
// MUST observe `INIT_DONE == false` for the duration so no concurrent
// reader trips on the partial write.  `shim_init` enforces this — it's the
// only caller and runs entirely before INIT_DONE flips.
unsafe fn load_protect_list_from_bytes(bytes: &[u8]) {
    let mut entry = [0u8; NAME_MAX_LEN];
    let mut entry_len: usize = 0;
    let mut overlong = false;
    let mut count: usize = 0;

    fn commit(entry: &[u8], len: usize, count: &mut usize) {
        // Strip trailing CR (in case of CRLF-fed input).
        let mut len = len;
        while len > 0 && entry[len - 1] == b'\r' {
            len -= 1;
        }
        // Strip leading and trailing ASCII whitespace.  Comma-separated
        // configs are often written `NAME1, NAME2, NAME3` for readability;
        // accept that.
        let mut start = 0usize;
        while start < len && (entry[start] == b' ' || entry[start] == b'\t') {
            start += 1;
        }
        while len > start && (entry[len - 1] == b' ' || entry[len - 1] == b'\t') {
            len -= 1;
        }
        let slice_len = len - start;
        if slice_len == 0 || entry[start] == b'#' {
            return;
        }
        if *count < MAX_PROTECTED {
            // SAFETY: ctor-only writer; no concurrent readers (INIT_DONE is
            // false until after this routine returns).
            unsafe {
                let table = &mut *PROTECTED.names.get();
                let dst = &mut table[*count];
                let take = slice_len.min(NAME_MAX_LEN - 1);
                dst[..take].copy_from_slice(&entry[start..start + take]);
                dst[take] = 0;
            }
            *count += 1;
        }
    }

    for &byte in bytes {
        // Treat both ',' and '\n' as entry separators.  '\n' is unlikely to
        // appear in the env-var-encoded channel but cheap to support.
        if byte == b',' || byte == b'\n' {
            if overlong {
                overlong = false;
                entry_len = 0;
                continue;
            }
            commit(&entry, entry_len, &mut count);
            entry_len = 0;
        } else {
            if overlong {
                continue;
            }
            if entry_len >= NAME_MAX_LEN {
                overlong = true;
                entry_len = 0;
                continue;
            }
            entry[entry_len] = byte;
            entry_len += 1;
        }
    }
    // Trailing entry without separator at EOF.
    if !overlong && entry_len > 0 {
        commit(&entry, entry_len, &mut count);
    }

    PROTECTED.count.store(count, Ordering::Release);
}

// ── EnvBuf + env helpers ───────────────────────────────────────────────────
//
// Heap-backed mutable environment array for exec wrappers.  All allocation
// goes through libc::malloc / libc::free; no Rust allocator is linked.
//
// Layout invariants:
//   ptrs[0..count]   – the live entries (pointers into either the original
//                       envp_in array or into strings we malloc'd).
//   ptrs[count]      – always NULL (terminator).
//   owned[0..owned_count] – all malloc'd entry strings we are responsible for
//                       freeing.  These are a subset of ptrs[].
//   cap              – total slots allocated for ptrs (>= count + 1).
//   owned_cap        – total slots allocated for owned (>= owned_count).
//
// EnvBuf is stack-local, used exclusively by a single exec wrapper call on
// one thread.  No Send/Sync impls needed.
//
// Recursion-guard scope:
//   These helpers wrap each individual libc::malloc / libc::free in
//   set_in_shim(true/false) so glibc malloc's internal getenv calls
//   (MALLOC_* knobs) hit the early-return path.  set_in_shim is a flat
//   overwrite — there is NO save/restore of the prior state.  Therefore
//   exec wrappers must NOT rely on the guard being held across calls to
//   envbuf_from / overwrite_env / ensure_env: after they return, in_shim()
//   is false.  Any real_getenv_raw call the wrapper needs (e.g. PATH for
//   execvp) MUST happen before envbuf_from is invoked, OR be wrapped in
//   its own set_in_shim(true/false) pair.

struct EnvBuf {
    ptrs: *mut *const c_char, // libc::malloc'd; NULL-terminated.
    cap: usize,               // capacity in slots (entries + 1 for terminator).
    count: usize,             // currently-occupied entries (not counting NULL).
    owned: *mut *mut c_char,  // libc::malloc'd: per-entry strdup'd C strings we created.
    owned_cap: usize,
    owned_count: usize,
}

/// Build an EnvBuf from an incoming `envp_in` pointer array (may be NULL).
///
/// Returns None if:
///   - the input envp has more than MAX_ENVP_SANITY entries (hostile envp), or
///   - any malloc call fails.
/// On None the caller should forward envp_in unchanged.
unsafe fn envbuf_from(envp_in: *const *const c_char) -> Option<EnvBuf> {
    // Count input entries.  NULL envp means zero entries.
    let count_in: usize = if envp_in.is_null() {
        0
    } else {
        let mut n = 0usize;
        loop {
            if n > MAX_ENVP_SANITY {
                return None;
            }
            if (*envp_in.add(n)).is_null() {
                break;
            }
            n += 1;
        }
        n
    };

    // ptrs capacity: count_in + growth headroom + 1 NULL terminator.
    let ptrs_cap = count_in + MAX_ENVP_GROWTH + 1;
    let ptrs_bytes = ptrs_cap
        .checked_mul(core::mem::size_of::<*const c_char>())
        .unwrap_or(0);

    // owned capacity: growth headroom + 1 (never more than MAX_ENVP_GROWTH entries owned).
    let owned_cap = MAX_ENVP_GROWTH + 1;
    let owned_bytes = owned_cap
        .checked_mul(core::mem::size_of::<*mut c_char>())
        .unwrap_or(0);

    if ptrs_bytes == 0 || owned_bytes == 0 {
        return None;
    }

    set_in_shim(true);
    let ptrs_raw = libc::malloc(ptrs_bytes) as *mut *const c_char;
    set_in_shim(false);
    if ptrs_raw.is_null() {
        return None;
    }

    set_in_shim(true);
    let owned_raw = libc::malloc(owned_bytes) as *mut *mut c_char;
    set_in_shim(false);
    if owned_raw.is_null() {
        set_in_shim(true);
        libc::free(ptrs_raw as *mut c_void);
        set_in_shim(false);
        return None;
    }

    // Shallow-copy input entries into ptrs.
    if count_in > 0 {
        core::ptr::copy_nonoverlapping(envp_in as *const *const c_char, ptrs_raw, count_in);
    }
    // NUL-terminate.
    *ptrs_raw.add(count_in) = ptr::null();

    Some(EnvBuf {
        ptrs: ptrs_raw,
        cap: ptrs_cap,
        count: count_in,
        owned: owned_raw,
        owned_cap,
        owned_count: 0,
    })
}

/// Free all malloc'd memory in buf and zero out its fields.  Idempotent.
unsafe fn free_envbuf(buf: &mut EnvBuf) {
    // Free all entry strings we own.
    for i in 0..buf.owned_count {
        let p = *buf.owned.add(i);
        if !p.is_null() {
            set_in_shim(true);
            libc::free(p as *mut c_void);
            set_in_shim(false);
        }
    }
    buf.owned_count = 0;

    if !buf.owned.is_null() {
        set_in_shim(true);
        libc::free(buf.owned as *mut c_void);
        set_in_shim(false);
        buf.owned = ptr::null_mut();
    }
    buf.owned_cap = 0;

    if !buf.ptrs.is_null() {
        set_in_shim(true);
        libc::free(buf.ptrs as *mut c_void);
        set_in_shim(false);
        buf.ptrs = ptr::null_mut();
    }
    buf.cap = 0;
    buf.count = 0;
}

/// Find the slot index of an entry whose `NAME=` prefix matches `name`.
/// `name` is the bare name without `=` (e.g. `b"LD_PRELOAD"`).
/// Returns the index into buf.ptrs[], or None.
unsafe fn envbuf_find(buf: &EnvBuf, name: &[u8]) -> Option<usize> {
    let nlen = name.len();
    for i in 0..buf.count {
        let entry = *buf.ptrs.add(i);
        if entry.is_null() {
            continue;
        }
        // Check that entry[0..nlen] == name and entry[nlen] == b'='.
        let mut ok = true;
        for j in 0..nlen {
            if *entry.add(j) as u8 != name[j] {
                ok = false;
                break;
            }
        }
        if ok && *entry.add(nlen) as u8 == b'=' {
            return Some(i);
        }
    }
    None
}

/// Free a single malloc'd entry — used on push/set failure paths so the
/// caller does not leak the just-allocated string.
unsafe fn free_entry(entry: *mut c_char) {
    if entry.is_null() {
        return;
    }
    set_in_shim(true);
    libc::free(entry as *mut c_void);
    set_in_shim(false);
}

/// Append a new entry to buf.ptrs[], bump count, re-NUL-terminate, push onto owned[].
/// Returns false if either the ptrs cap or the owned tracker would be exceeded.
/// On false return the caller is responsible for freeing new_entry.
unsafe fn envbuf_push(buf: &mut EnvBuf, new_entry: *mut c_char) -> bool {
    // Need count + 1 entries + 1 NUL terminator <= cap.
    if buf.count + 1 >= buf.cap {
        return false;
    }
    if buf.owned_count >= buf.owned_cap {
        return false;
    }
    *buf.ptrs.add(buf.count) = new_entry as *const c_char;
    buf.count += 1;
    *buf.ptrs.add(buf.count) = ptr::null(); // re-NUL-terminate.
    *buf.owned.add(buf.owned_count) = new_entry;
    buf.owned_count += 1;
    true
}

/// Remove EVERY entry whose `NAME=` prefix matches `name` from buf.  Returns
/// true if at least one entry was found and removed.  If a removed entry
/// was owned (i.e. previously inserted via envbuf_set_at / envbuf_push), it
/// is freed and removed from the owned tracker.  The ptrs[] slots are
/// shifted down to preserve density and the new tail slot is re-NUL-terminated.
///
/// SECURITY: must be exhaustive over duplicates.  A naive raw envp produced
/// by an attacker can contain multiple `SCRIPT_JAIL_LOG_FILE=…` entries; if
/// only the first match were removed, the second (attacker-controlled) value
/// would survive into the child and the audit log would be redirected.  The
/// sticky-var re-injection loop relies on this being exhaustive so that
/// `overwrite_env` (which itself rebuilds via remove-all + push) lands the
/// canonical value in exactly one slot.
///
/// Recursion-guard contract: callers MUST hold set_in_shim(true) only for
/// the libc::free call, which this helper wraps internally — matching the
/// pattern used by free_entry / free_envbuf.
unsafe fn envbuf_remove(buf: &mut EnvBuf, name: &[u8]) -> bool {
    let mut removed_any = false;
    // Re-scan from index 0 on every iteration: removing an entry shifts the
    // tail down, so a fresh scan is the simplest correct way to find the
    // next duplicate without book-keeping the prior position.  envp arrays
    // are short (bounded by MAX_ENVP_GROWTH + the caller's envp_in size),
    // so the O(n^2) worst case here is negligible.
    loop {
        let idx = match envbuf_find(buf, name) {
            Some(i) => i,
            None => break,
        };

        let entry = *buf.ptrs.add(idx);

        // If this entry was owned (we malloc'd it earlier in this same
        // envbuf, e.g. via envbuf_push), free it and compact the owned
        // tracker.  Compare by raw pointer equality — that is the same
        // identity the owned table records.
        if !entry.is_null() {
            for j in 0..buf.owned_count {
                let owned_ptr = *buf.owned.add(j) as *const c_char;
                if owned_ptr == entry {
                    // Free the entry under the recursion guard, then shift the
                    // remaining owned entries down one slot.
                    set_in_shim(true);
                    libc::free(*buf.owned.add(j) as *mut c_void);
                    set_in_shim(false);
                    for k in j..buf.owned_count - 1 {
                        *buf.owned.add(k) = *buf.owned.add(k + 1);
                    }
                    buf.owned_count -= 1;
                    // NULL the now-stale tail so any subsequent free_envbuf
                    // walk does not double-free.
                    *buf.owned.add(buf.owned_count) = ptr::null_mut();
                    break;
                }
            }
        }

        // Shift ptrs[idx+1..count] down by one slot, then re-NUL-terminate.
        for k in idx..buf.count - 1 {
            *buf.ptrs.add(k) = *buf.ptrs.add(k + 1);
        }
        buf.count -= 1;
        *buf.ptrs.add(buf.count) = ptr::null();
        removed_any = true;
    }
    removed_any
}

/// Malloc a new `NAME=VALUE\0` C string.  Returns NULL on malloc failure.
/// Wrapped in the recursion guard to protect against glibc malloc reading
/// MALLOC_* env vars.
unsafe fn make_entry(name: &[u8], value: &[u8]) -> *mut c_char {
    // name.len() + '=' + value.len() + NUL
    let total = name.len() + 1 + value.len() + 1;
    set_in_shim(true);
    let buf = libc::malloc(total) as *mut u8;
    set_in_shim(false);
    if buf.is_null() {
        return ptr::null_mut();
    }
    // Write: name '=' value '\0'
    core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
    *buf.add(name.len()) = b'=';
    if !value.is_empty() {
        core::ptr::copy_nonoverlapping(value.as_ptr(), buf.add(name.len() + 1), value.len());
    }
    *buf.add(name.len() + 1 + value.len()) = 0u8;
    buf as *mut c_char
}

/// Overwrite `name` in buf with the canonical `value`, leaving exactly one
/// `name=value` entry behind.
///
/// SECURITY: a raw envp produced by an attacker can contain multiple
/// `NAME=…` entries.  Replacing only the first match (envbuf_find returns
/// the first index) would leave any subsequent attacker-controlled
/// duplicates intact, and execve/posix_spawn pass the whole array through —
/// the child sees the duplicate and (depending on libc) may resolve to
/// either value.  To make the canonical value authoritative we first remove
/// EVERY existing entry for `name`, then push the freshly-malloc'd
/// `name=value`.  The exhaustive removal lives in envbuf_remove.
///
/// Unlike ensure_env (which preserved the caller's value), this enforces
/// that the audit chain's runtime config (SCRIPT_JAIL_LOG_FILE, log fd,
/// preload path, etc.) cannot be redirected by a malicious envp_in.
///
/// Returns false only on malloc/push failure (the in-place rewrite is
/// best-effort: if push fails after the removals succeed, the buffer has
/// no entry for `name` at all, which is still safer than leaving an
/// attacker-supplied duplicate live).
///
/// EMPTY VALUE: when `value` is empty, this collapses to an exhaustive
/// remove with no push — mirrors the sticky-var loop's "empty canon →
/// strip caller entries" semantics so a single overwrite_env call is the
/// uniform mechanism for "make canonical authoritative" regardless of
/// whether the canonical itself is empty.  Always returns true in that
/// case (envbuf_remove cannot fail).
unsafe fn overwrite_env(buf: &mut EnvBuf, name: &[u8], value: &[u8]) -> bool {
    if value.is_empty() {
        // Exhaustively remove every entry for `name`; pushing an empty
        // `NAME=` would leak an empty-valued entry into the child, which
        // is a different observable shape than "name is unset".
        let _ = envbuf_remove(buf, name);
        return true;
    }
    let entry = make_entry(name, value);
    if entry.is_null() {
        return false;
    }
    // Remove all existing matches so we cannot leak a duplicate.  Discard
    // the return value: zero existing entries is fine — we're about to
    // push the canonical one.
    let _ = envbuf_remove(buf, name);
    if !envbuf_push(buf, entry) {
        free_entry(entry);
        return false;
    }
    true
}

// ── JSON escape ────────────────────────────────────────────────────────────

// Writes an escaped JSON string body (no surrounding quotes) for `src` into
// `dst`. Returns bytes written. Reserves enough trailing space for the
// "<truncated>" marker so forensic readers can detect overflow.
unsafe fn json_escape(dst: &mut [u8], src: *const c_char) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let reserve = TRUNC_MARKER.len() + 1;
    if src.is_null() {
        if dst.len() >= 4 {
            dst[..4].copy_from_slice(b"null");
            return 4;
        }
        return 0;
    }
    let mut n = 0usize;
    let mut truncated = false;
    let mut p = 0usize;
    loop {
        let c = *src.add(p);
        if c == 0 {
            break;
        }
        let c = c as u8;
        let needed: usize = if c == b'"' || c == b'\\' {
            2
        } else if c < 0x20 {
            6
        } else {
            1
        };
        if n + needed + reserve > dst.len() {
            truncated = true;
            break;
        }
        if c == b'"' {
            dst[n] = b'\\';
            dst[n + 1] = b'"';
            n += 2;
        } else if c == b'\\' {
            dst[n] = b'\\';
            dst[n + 1] = b'\\';
            n += 2;
        } else if c < 0x20 {
            dst[n] = b'\\';
            dst[n + 1] = b'u';
            dst[n + 2] = b'0';
            dst[n + 3] = b'0';
            dst[n + 4] = HEX[((c >> 4) & 0xf) as usize];
            dst[n + 5] = HEX[(c & 0xf) as usize];
            n += 6;
        } else {
            dst[n] = c;
            n += 1;
        }
        p += 1;
    }
    // The loop's `n + needed + reserve > dst.len()` guard keeps a full
    // `reserve = TRUNC_MARKER.len() + 1` bytes free after every char it writes,
    // so a loop-driven truncation always leaves room for the marker.  The one
    // exception is an immediate truncation at `n == 0` when `dst` itself is
    // narrower than the marker (a value slice < TRUNC_MARKER.len()); without
    // this fit-check the copy_from_slice below would run past `dst` and abort
    // the shim.  Callers should size the slice ≥ TRUNC_MARKER.len()
    // (append_canon_field does), but guarding here removes the out-of-bounds
    // primitive for every caller — on a too-small slice we simply emit nothing.
    if truncated && n + TRUNC_MARKER.len() <= dst.len() {
        dst[n..n + TRUNC_MARKER.len()].copy_from_slice(TRUNC_MARKER);
        n += TRUNC_MARKER.len();
    }
    n
}

// ── number formatting (avoids core::fmt to keep the binary small) ──────────

// Writes a non-negative i64 in decimal into `dst`. Returns bytes written.
fn write_u64(dst: &mut [u8], mut v: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    let mut out = 0usize;
    for i in (0..n).rev() {
        dst[out] = tmp[i];
        out += 1;
    }
    out
}

fn write_i64(dst: &mut [u8], v: i64) -> usize {
    if v < 0 {
        dst[0] = b'-';
        // Use u64 magnitude to handle i64::MIN safely.
        let mag = (v as i128).unsigned_abs() as u64;
        1 + write_u64(&mut dst[1..], mag)
    } else {
        write_u64(dst, v as u64)
    }
}

// ── atomic write ───────────────────────────────────────────────────────────

unsafe fn write_all(fd: c_int, mut buf: &[u8]) {
    while !buf.is_empty() {
        let n = libc::write(fd, buf.as_ptr() as *const c_void, buf.len());
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return;
        }
        let n = n as usize;
        if n >= buf.len() {
            return;
        }
        buf = &buf[n..];
    }
}

// ── emit one JSONL env_read line ───────────────────────────────────────────

unsafe fn emit(name: *const c_char, hidden: bool) {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;
    let pid = libc::getpid();

    let mut buf = [0u8; JSONL_BUF];
    let mut pos = 0usize;

    // Reserve trailing budget for: ","pid":<20>,"ts":<20>,"hidden":<5>}\n ≈ 71 B
    // (pid is written via write_i64 which can emit up to 20 chars for signed i64).
    const SUFFIX_RESERVE: usize = 80;

    let prefix = br#"{"kind":"env_read","name":""#;
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    let escape_budget_end = JSONL_BUF.saturating_sub(SUFFIX_RESERVE);
    if pos < escape_budget_end {
        let written = json_escape(&mut buf[pos..escape_budget_end], name);
        pos += written;
    }

    let mid1 = br#"","pid":"#;
    buf[pos..pos + mid1.len()].copy_from_slice(mid1);
    pos += mid1.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    let mid2 = br#","ts":"#;
    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    pos += write_i64(&mut buf[pos..], ns);

    let mid3 = br#","hidden":"#;
    buf[pos..pos + mid3.len()].copy_from_slice(mid3);
    pos += mid3.len();
    let bool_str: &[u8] = if hidden { b"true" } else { b"false" };
    buf[pos..pos + bool_str.len()].copy_from_slice(bool_str);
    pos += bool_str.len();

    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    if pos > 0 && pos <= JSONL_BUF {
        write_all(log_fd, &buf[..pos]);
    }
}

unsafe fn emit_node_startup_done() {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;
    let pid = libc::getpid();

    // 1024 (== CANON_BUF_LEN) holds the fixed prefix/pid/ts (~80 B) plus the
    // three optional npm attribution fields.  capture_canon caps EACH field at
    // CANON_BUF_LEN-1 bytes, so a single field can never exceed the buffer; the
    // size + the field ORDER below guarantee the attribution-critical pair fits.
    // Every append is independently bounds-guarded (append_canon_field omits a
    // field that would not fit while leaving room for the closing `}\n`), so an
    // oversized value is safely omitted rather than overflowing this buffer.
    let mut buf = [0u8; 1024];
    let mut pos = 0usize;
    let prefix = br#"{"kind":"node_startup_done","pid":"#;
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    let mid = br#","ts":"#;
    buf[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += write_i64(&mut buf[pos..], ns);

    // npm lifecycle attribution (deterministic, in-process, reap-proof) — the
    // SAME ctor snapshot stamped into `exec` records (see emit_exec_for_pid).
    // It lets the guest seed this pid's attribution the instant env-spy signals
    // node-startup-done, BEFORE any post-bootstrap env read is dispatched, so a
    // short-lived spawned Node child (e.g. puppeteer's `node install.mjs`) whose
    // /proc is reaped before its env reads are tailed still attributes those
    // reads to the right package instead of dropping them — the env_read analog
    // of the reaped-helper exec fix.  Each field is omitted when its CanonBuf is
    // empty (non-lifecycle process such as npm/pnpm itself), keeping
    // non-lifecycle markers byte-identical to the pre-change output.
    //
    // ORDER MATTERS (do not reorder to match emit_exec_for_pid): the guest's
    // shimNodeStartupAttribution requires BOTH npm_package_name AND a canonical
    // npm_lifecycle_event to seed at all — npm_package_version is only the
    // render suffix.  append_canon_field reserves room solely for the field it
    // is writing plus the closing `}\n`; it does NOT pre-reserve space for
    // later fields.  capture_canon caps each value at CANON_BUF_LEN-1 and does
    // NOT enforce npm's 214-byte name limit, so a child-controlled overlong
    // npm_package_name (or version) could otherwise consume the buffer.  We
    // therefore write the SMALLEST attribution-critical field FIRST:
    //   1. npm_lifecycle_event — canonical, ≤ ~12 bytes, needs no escaping;
    //      written into a near-empty buffer it ALWAYS fits, so the seed's
    //      go/no-go gate (canonical lifecycle) can never be silently dropped.
    //   2. npm_package_name — required for the pkg; ≤214 B for any real npm
    //      name, far under the buffer, so it fits in full alongside lifecycle.
    //   3. npm_package_version — OPTIONAL render suffix, LAST: a pathologically
    //      long value truncates/omits only itself and never starves 1 or 2.
    // Net: for any realistic package all three fit; a pathological field can
    // only ever cost the optional version, never the deterministic seed (which
    // would otherwise fall back to /proc on the reaped-child path this fixes).
    pos = append_canon_field(
        &mut buf,
        pos,
        b"npm_lifecycle_event",
        &CANON_NPM_LIFECYCLE_EVENT,
    );
    pos = append_canon_field(&mut buf, pos, b"npm_package_name", &CANON_NPM_PACKAGE_NAME);
    pos = append_canon_field(
        &mut buf,
        pos,
        b"npm_package_version",
        &CANON_NPM_PACKAGE_VERSION,
    );

    // Closing `}\n`.  append_canon_field guarantees ≥3 trailing bytes remain (it
    // reserves the value-closing quote plus this tail), but guard defensively so
    // a future buffer-size change can never overflow the no_std shim.
    if pos + 2 > buf.len() {
        return;
    }
    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    write_all(log_fd, &buf[..pos]);
}

// ── MACOS fs + connect emit + path resolution ──────────────────────────────
//
// Linux gets fs (read/write) and connect events from strace; macOS has no
// strace, so the shim must emit them itself.  These functions are the Mach-O
// analog of strace-parser.ts's read/write/connect rows.  They are
// zero-allocation (raw stack buffers + write_all), matching the macOS hot-path
// discipline proven necessary by the spike (getenv/file ops can fire during
// libSystem/malloc bootstrap, before the Rust allocator is live).

/// Access classification for a file-op event.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub(crate) enum FsKind {
    Read,
    Write,
}

/// errno to surface on a failed file-op.  Only ENOENT / EACCES are carried
/// (matching schema.ts FsReadEvent/FsWriteEvent.errno enum); everything else is
/// treated as success-shaped (no errno field) so protected-paths.ts's
/// ENOENT-drop and the macOS noise filter behave like the strace path.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub(crate) enum FsErrno {
    None,
    Enoent,
    Eacces,
}

/// Map a raw errno into the carried subset.  Anything other than ENOENT/EACCES
/// is reported as None (no errno field).
#[cfg(target_os = "macos")]
pub(crate) fn classify_fs_errno(e: c_int) -> FsErrno {
    if e == libc::ENOENT {
        FsErrno::Enoent
    } else if e == libc::EACCES {
        FsErrno::Eacces
    } else {
        FsErrno::None
    }
}

/// Emit one JSONL fs event:
///   {"kind":"read"|"write","path":"<esc>","pid":N,"ts":N,"hidden":false[,"errno":"ENOENT"|"EACCES"]}
/// matching `FsReadEvent`/`FsWriteEvent` in src/lock/schema.ts.  `path` is the
/// already-resolved absolute path as a NUL-terminated C string.  `hidden` is
/// always false from the shim (protected-paths.ts decides hiding host-side).
#[cfg(target_os = "macos")]
pub(crate) unsafe fn emit_fs(kind: FsKind, path: *const c_char, errno_kind: FsErrno) {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;
    let pid = libc::getpid();

    let mut buf = [0u8; JSONL_BUF];
    let mut pos = 0usize;

    // Reserve trailing budget for ","pid":...,"ts":...,"hidden":false,"errno":"EACCES"}\n
    const SUFFIX_RESERVE: usize = 96;

    let prefix: &[u8] = match kind {
        FsKind::Read => br#"{"kind":"read","path":""#,
        FsKind::Write => br#"{"kind":"write","path":""#,
    };
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    let escape_budget_end = JSONL_BUF.saturating_sub(SUFFIX_RESERVE);
    if pos < escape_budget_end {
        let written = json_escape(&mut buf[pos..escape_budget_end], path);
        pos += written;
    }

    let mid1 = br#"","pid":"#;
    buf[pos..pos + mid1.len()].copy_from_slice(mid1);
    pos += mid1.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    let mid2 = br#","ts":"#;
    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    pos += write_i64(&mut buf[pos..], ns);

    let mid3 = br#","hidden":false"#;
    buf[pos..pos + mid3.len()].copy_from_slice(mid3);
    pos += mid3.len();

    match errno_kind {
        FsErrno::None => {}
        FsErrno::Enoent => {
            let e = br#","errno":"ENOENT""#;
            buf[pos..pos + e.len()].copy_from_slice(e);
            pos += e.len();
        }
        FsErrno::Eacces => {
            let e = br#","errno":"EACCES""#;
            buf[pos..pos + e.len()].copy_from_slice(e);
            pos += e.len();
        }
    }

    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    if pos > 0 && pos <= JSONL_BUF {
        write_all(log_fd, &buf[..pos]);
    }
}

/// connect() result classification.  Mirrors strace-parser.ts (round-12 F3):
///   rc == 0, or EINPROGRESS / EALREADY / EISCONN (egress in flight or
///                                    established — SYN already sent) → "ok"
///   any genuine failure (refused / timed out / unreachable / denied) → "blocked"
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub(crate) enum ConnectResult {
    Ok,
    Blocked,
}

/// Emit one JSONL connect event:
///   {"kind":"connect","host":"<ip>","port":N,"result":"ok"|"blocked","pid":N,"ts":N}
/// matching `NetworkEvent` in src/lock/schema.ts.  `host` is the already
/// hand-formatted IP literal (IPv4 dotted-quad or IPv6 colon form) as a
/// NUL-terminated C string; `port` is host-order.
#[cfg(target_os = "macos")]
pub(crate) unsafe fn emit_connect(host: *const c_char, port: u16, result: ConnectResult) {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;
    let pid = libc::getpid();

    let mut buf = [0u8; JSONL_BUF];
    let mut pos = 0usize;

    const SUFFIX_RESERVE: usize = 96;

    let prefix = br#"{"kind":"connect","host":""#;
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    let escape_budget_end = JSONL_BUF.saturating_sub(SUFFIX_RESERVE);
    if pos < escape_budget_end {
        let written = json_escape(&mut buf[pos..escape_budget_end], host);
        pos += written;
    }

    let mid1 = br#"","port":"#;
    buf[pos..pos + mid1.len()].copy_from_slice(mid1);
    pos += mid1.len();
    pos += write_i64(&mut buf[pos..], port as i64);

    let result_tail: &[u8] = match result {
        ConnectResult::Ok => br#","result":"ok""#,
        ConnectResult::Blocked => br#","result":"blocked""#,
    };
    buf[pos..pos + result_tail.len()].copy_from_slice(result_tail);
    pos += result_tail.len();

    let mid2 = br#","pid":"#;
    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    let mid3 = br#","ts":"#;
    buf[pos..pos + mid3.len()].copy_from_slice(mid3);
    pos += mid3.len();
    pos += write_i64(&mut buf[pos..], ns);

    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    if pos > 0 && pos <= JSONL_BUF {
        write_all(log_fd, &buf[..pos]);
    }
}

/// Resolve `(dirfd, path)` to an ABSOLUTE NUL-terminated path written into
/// `out`, returning the length (excluding NUL) on success or None on overflow /
/// unresolvable dirfd.  Mirrors fspy `convert.rs` `ToAbsolutePath`:
///   - an absolute `path` (leading '/') is copied verbatim;
///   - `AT_FDCWD` resolves the relative path against getcwd();
///   - a numeric dirfd resolves via fcntl(F_GETPATH) then joins the relative.
/// Zero-allocation: `out` is a caller stack buffer (size PATH_MAX+1 expected).
#[cfg(target_os = "macos")]
pub(crate) unsafe fn abs_path_into(
    dirfd: c_int,
    path: *const c_char,
    out: &mut [u8],
) -> Option<usize> {
    if path.is_null() {
        return None;
    }
    // Absolute path → copy verbatim.
    if *path as u8 == b'/' {
        return copy_cstr_into(path, out);
    }

    // Relative path: resolve the base directory.
    let mut base = [0u8; (libc::PATH_MAX as usize) + 1];
    let base_len = if dirfd == libc::AT_FDCWD {
        if libc::getcwd(base.as_mut_ptr() as *mut c_char, base.len()).is_null() {
            return None;
        }
        cstr_len(base.as_ptr() as *const c_char)
    } else {
        // F_GETPATH writes the fd's path into a PATH_MAX buffer.
        if libc::fcntl(dirfd, libc::F_GETPATH, base.as_mut_ptr() as *mut c_char) != 0 {
            return None;
        }
        cstr_len(base.as_ptr() as *const c_char)
    };

    // Join `<base>/<path>`.  An empty `path` (e.g. AT_EMPTY_PATH style) yields
    // just the base.
    let path_len = cstr_len(path);
    // base + '/' + path + NUL
    let need = base_len + 1 + path_len + 1;
    if need > out.len() {
        return None;
    }
    out[..base_len].copy_from_slice(&base[..base_len]);
    let mut pos = base_len;
    if path_len > 0 {
        out[pos] = b'/';
        pos += 1;
        core::ptr::copy_nonoverlapping(path as *const u8, out.as_mut_ptr().add(pos), path_len);
        pos += path_len;
    }
    out[pos] = 0;
    Some(pos)
}

/// Copy a NUL-terminated C string into `out` (with its NUL), returning the
/// length excluding NUL, or None if it would overflow.
#[cfg(target_os = "macos")]
pub(crate) unsafe fn copy_cstr_into(s: *const c_char, out: &mut [u8]) -> Option<usize> {
    let len = cstr_len(s);
    if len + 1 > out.len() {
        return None;
    }
    core::ptr::copy_nonoverlapping(s as *const u8, out.as_mut_ptr(), len);
    out[len] = 0;
    Some(len)
}

/// Length of a NUL-terminated C string (excluding the NUL).
#[cfg(target_os = "macos")]
pub(crate) unsafe fn cstr_len(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}

// ── constructor ────────────────────────────────────────────────────────────

#[ctor::ctor]
unsafe fn shim_init() {
    // 1. Create the pthread key BEFORE any call that might invoke getenv.
    //    pthread_key_create itself does not call getenv on glibc/musl.
    let mut key: libc::pthread_key_t = 0;
    let key_created = libc::pthread_key_create(&mut key as *mut libc::pthread_key_t, None) == 0;
    if key_created {
        IN_SHIM_KEY.store(key as usize, Ordering::Release);
        KEY_READY.store(true, Ordering::Release);
        // 2. Mark this thread as inside the shim so any re-entrant getenv
        //    during init takes the bypass branch.
        set_in_shim(true);
    }

    // 3. Resolve real symbols unconditionally (LINUX only). dlsym may
    //    internally call getenv; if the key was created our wrapper sees
    //    in_shim==true and forwards. If the key was NOT created, INIT_DONE is
    //    still false so the wrapper takes the pre-init bypass path and forwards
    //    to real_getenv_raw (null-safe when REAL_GETENV is still NULL).
    //
    //    MACOS does NOT do this: there is no `RTLD_NEXT` shadow chain to walk —
    //    dyld `__interpose` rebinds the audited binary's call sites, and our
    //    replacements reach the real symbol via a direct `libc::<fn>` reference
    //    (proven non-recursive — see real_getenv_raw's macos branch).
    #[cfg(target_os = "linux")]
    {
        let getenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"getenv\0".as_ptr() as *const c_char);
        REAL_GETENV.store(getenv_ptr as *mut c_void, Ordering::Release);

        let mut sec_ptr = libc::dlsym(
            libc::RTLD_NEXT,
            b"secure_getenv\0".as_ptr() as *const c_char,
        );
        if sec_ptr.is_null() {
            sec_ptr = libc::dlsym(
                libc::RTLD_NEXT,
                b"__secure_getenv\0".as_ptr() as *const c_char,
            );
        }
        REAL_SECURE_GETENV.store(sec_ptr as *mut c_void, Ordering::Release);

        let clearenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"clearenv\0".as_ptr() as *const c_char);
        REAL_CLEARENV.store(clearenv_ptr as *mut c_void, Ordering::Release);

        let execve_ptr = libc::dlsym(libc::RTLD_NEXT, b"execve\0".as_ptr() as *const c_char);
        REAL_EXECVE.store(execve_ptr as *mut c_void, Ordering::Release);

        let execv_ptr = libc::dlsym(libc::RTLD_NEXT, b"execv\0".as_ptr() as *const c_char);
        REAL_EXECV.store(execv_ptr as *mut c_void, Ordering::Release);

        let execvp_ptr = libc::dlsym(libc::RTLD_NEXT, b"execvp\0".as_ptr() as *const c_char);
        REAL_EXECVP.store(execvp_ptr as *mut c_void, Ordering::Release);

        let execvpe_ptr = libc::dlsym(libc::RTLD_NEXT, b"execvpe\0".as_ptr() as *const c_char);
        REAL_EXECVPE.store(execvpe_ptr as *mut c_void, Ordering::Release);

        let execveat_ptr = libc::dlsym(libc::RTLD_NEXT, b"execveat\0".as_ptr() as *const c_char);
        REAL_EXECVEAT.store(execveat_ptr as *mut c_void, Ordering::Release);

        let fexecve_ptr = libc::dlsym(libc::RTLD_NEXT, b"fexecve\0".as_ptr() as *const c_char);
        REAL_FEXECVE.store(fexecve_ptr as *mut c_void, Ordering::Release);

        let posix_spawn_ptr =
            libc::dlsym(libc::RTLD_NEXT, b"posix_spawn\0".as_ptr() as *const c_char);
        REAL_POSIX_SPAWN.store(posix_spawn_ptr as *mut c_void, Ordering::Release);

        let posix_spawnp_ptr =
            libc::dlsym(libc::RTLD_NEXT, b"posix_spawnp\0".as_ptr() as *const c_char);
        REAL_POSIX_SPAWNP.store(posix_spawnp_ptr as *mut c_void, Ordering::Release);

        let putenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"putenv\0".as_ptr() as *const c_char);
        REAL_PUTENV.store(putenv_ptr as *mut c_void, Ordering::Release);

        let setenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"setenv\0".as_ptr() as *const c_char);
        REAL_SETENV.store(setenv_ptr as *mut c_void, Ordering::Release);

        let unsetenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"unsetenv\0".as_ptr() as *const c_char);
        REAL_UNSETENV.store(unsetenv_ptr as *mut c_void, Ordering::Release);
    }

    // Without a working pthread key we cannot safely guard recursion in the
    // audit path; degrade to transparent passthrough by leaving INIT_DONE
    // false so all wrapper calls forward to the resolved real symbol.
    if !key_created {
        return;
    }

    // 4. Resolve the log destination via the now-resolved real_getenv.
    //    Prefer SCRIPT_JAIL_LOG_FILE (file path, the production case);
    //    fall back to SCRIPT_JAIL_LOG_FD (legacy fd from tests).
    let mut log_fd: c_int = -1;
    let path = real_getenv_raw(b"SCRIPT_JAIL_LOG_FILE\0".as_ptr() as *const c_char);
    if !cstr_is_empty(path) {
        let fd = libc::open(
            path,
            libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT,
            0o644 as c_uint,
        );
        if fd >= 0 {
            log_fd = fd;
        }
    }
    if log_fd < 0 {
        let fd_str = real_getenv_raw(b"SCRIPT_JAIL_LOG_FD\0".as_ptr() as *const c_char);
        if !cstr_is_empty(fd_str) {
            let n = parse_fd(fd_str);
            if n >= 0 {
                log_fd = n;
            }
        }
    }
    LOG_FD.store(log_fd, Ordering::Release);

    // 5. Capture canonical sticky env-var values for exec wrappers (Task 4/5).
    //    Must happen before the protect-list is loaded so we can source the
    //    protected names from CANON_PROTECTED_ENV_NAMES (Finding 4 — the
    //    list lives directly in an env var, not in a /tmp file).  Both
    //    canon-capture and the resulting protect-list load run before
    //    INIT_DONE is set, so exec wrappers can read them safely via
    //    Acquire on INIT_DONE.
    unsafe fn capture_canon(buf: &CanonBuf, name: *const c_char) {
        let val = real_getenv_raw(name);
        if val.is_null() || *val as u8 == 0 {
            return;
        }
        // Walk to NUL, copy at most CANON_BUF_LEN-1 bytes, NUL-terminate.
        let mut n = 0usize;
        while n < CANON_BUF_LEN - 1 && *val.add(n) as u8 != 0 {
            n += 1;
        }
        // SAFETY: ctor-only writer; no concurrent readers (INIT_DONE is false).
        let dst = &mut *buf.bytes.get();
        core::ptr::copy_nonoverlapping(val as *const u8, dst.as_mut_ptr(), n);
        dst[n] = 0;
        buf.len.store(n, Ordering::Release);
    }
    capture_canon(
        &CANON_NODE_OPTIONS,
        b"SCRIPT_JAIL_NODE_OPTIONS\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_PRELOAD_PATH,
        b"SCRIPT_JAIL_PRELOAD_PATH\0".as_ptr() as *const c_char,
    );
    // Fallback canon for launcher/test paths that load the shim via
    // LD_PRELOAD only (no SCRIPT_JAIL_PRELOAD_PATH / SCRIPT_JAIL_NODE_OPTIONS
    // explicit canonicals).  Capturing here is safe: shim_init runs at
    // LD_PRELOAD load time, before any user code has had a chance to mutate
    // `environ`, so the values read via real_getenv_raw are trustworthy.
    //
    // SECURITY: without this fallback, rewrite_envp's empty-canon branch
    // would preserve a caller-supplied `LD_PRELOAD=/tmp/evil.so` (or
    // `LD_PRELOAD=/lib/libscriptjail.so:/tmp/evil.so`) verbatim.  With the
    // fallback, CANON_PRELOAD_PATH is non-empty whenever the shim was
    // actually loaded by the parent — the only way both canons stay empty
    // is when the parent never set either var, which means the shim is not
    // expected to propagate and the empty-canon → "remove all" branch is
    // the correct behavior.
    if CANON_PRELOAD_PATH.len.load(Ordering::Acquire) == 0 {
        capture_canon(
            &CANON_PRELOAD_PATH,
            b"LD_PRELOAD\0".as_ptr() as *const c_char,
        );
    }
    if CANON_NODE_OPTIONS.len.load(Ordering::Acquire) == 0 {
        capture_canon(
            &CANON_NODE_OPTIONS,
            b"NODE_OPTIONS\0".as_ptr() as *const c_char,
        );
    }
    // The remaining sticky SCRIPT_JAIL_* vars are also snapshotted here so
    // exec-time rewrite_envp never has to consult the (mutable) live environ.
    // See the CANON_LOG_FILE / CANON_LOG_FD / ... static defs for rationale.
    capture_canon(
        &CANON_LOG_FILE,
        b"SCRIPT_JAIL_LOG_FILE\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_LOG_FD,
        b"SCRIPT_JAIL_LOG_FD\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_PROTECTED_ENV_NAMES,
        b"SCRIPT_JAIL_PROTECTED_ENV_NAMES\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_SPOOF_PLATFORM,
        b"SCRIPT_JAIL_SPOOF_PLATFORM\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_SPOOF_ARCH,
        b"SCRIPT_JAIL_SPOOF_ARCH\0".as_ptr() as *const c_char,
    );
    // MACOS only: the re-signed shell/coreutils shim directory used by
    // sip_redirect.  Captured (and re-injected) like every other sticky var so
    // a descendant cannot strip it.  No-op / absent on Linux.
    #[cfg(target_os = "macos")]
    capture_canon(
        &CANON_SHELL_SHIM_DIR,
        b"SCRIPT_JAIL_SHELL_SHIM_DIR\0".as_ptr() as *const c_char,
    );
    // MACOS only: snapshot THIS process's own executable dir (the provisioned
    // node's bin/) so is_external_system_tool can keep node-spawned-node + the
    // package-manager shims audited.  Done at ctor (before user code can chdir
    // or re-exec), reading via _NSGetExecutablePath + lexical_canon — no env var,
    // so it survives the lifecycle env scrub.  See CANON_SELF_EXEC_DIR.
    #[cfg(target_os = "macos")]
    capture_self_exec_dir();
    // MACOS only: snapshot the install cwd NOW — before any lifecycle script can
    // chdir — so is_external_system_tool keeps package-owned helpers under the
    // install root audited even after a malicious/legit `chdir` away (the
    // chdir-then-exec-absolute-helper false-strip finding).  See CANON_INIT_CWD.
    #[cfg(target_os = "macos")]
    capture_init_cwd();
    // MACOS only: snapshot the install/repo root from SCRIPT_JAIL_WORK_DIR (the
    // agent's config.work_dir) so is_external_system_tool keeps the WHOLE install
    // tree — incl. top-level node_modules/.bin helpers that are SIBLINGS of a
    // lifecycle child's chdir'd cwd — audited.  Captured (and re-injected via
    // STICKY_VARS) like every other sticky var.  See CANON_WORK_DIR.
    #[cfg(target_os = "macos")]
    capture_work_dir();
    #[cfg(target_os = "macos")]
    {
        let audit_ops = real_getenv_raw(b"SCRIPT_JAIL_MACOS_AUDIT_OPS\0".as_ptr() as *const c_char);
        capture_canon(
            &CANON_MACOS_AUDIT_OPS,
            b"SCRIPT_JAIL_MACOS_AUDIT_OPS\0".as_ptr() as *const c_char,
        );
        MACOS_AUDIT_OPS.store(cstr_eq_bytes(audit_ops, b"1"), Ordering::Release);
    }
    // npm lifecycle attribution — snapshotted from this process's own environ
    // so emit_exec_for_pid can stamp the owning package into every exec record
    // (deterministic, reap-proof in-process attribution; see the CANON_NPM_*
    // static defs).  Same ctor-time safety rationale as the SCRIPT_JAIL_* vars.
    capture_canon(
        &CANON_NPM_PACKAGE_NAME,
        b"npm_package_name\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_NPM_PACKAGE_VERSION,
        b"npm_package_version\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_NPM_LIFECYCLE_EVENT,
        b"npm_lifecycle_event\0".as_ptr() as *const c_char,
    );

    // 6. Load the protect-list FROM the captured env-var snapshot (Finding 4).
    //    Reading the names directly out of CANON_PROTECTED_ENV_NAMES means
    //    no /tmp file is involved at any point — same-UID lifecycle scripts
    //    cannot weaken the list because the bytes live inside the shim's
    //    private CanonBuf (written exactly once here, observed by every
    //    descendant via overwrite_env at exec-time).
    let proto_bytes = canon_bytes(&CANON_PROTECTED_ENV_NAMES);
    if !proto_bytes.is_empty() {
        load_protect_list_from_bytes(proto_bytes);
    }

    // 7. Open for business.
    INIT_DONE.store(true, Ordering::Release);
    set_in_shim(false);
}

// ── wrapped functions ──────────────────────────────────────────────────────

// IMPORTANT:
//   - On re-entrant calls (in_shim()), forward to the real implementation
//     without logging or protection checks.
//   - Before init has completed (INIT_DONE==false), bypass — the protect-list
//     and log fd are not yet resolved.
//   - In the normal path, set in_shim BEFORE any work that might re-enter
//     getenv (e.g., emit's clock_gettime / write), and clear it before
//     returning so the next call audits.

// Shared body for the getenv family.  Both the Linux `#[no_mangle]` export
// (reached via LD_PRELOAD shadowing) and the macOS interpose wrapper (reached
// via the __interpose table) call this so the audit/hide behaviour is
// byte-identical across platforms.  `secure` selects the real forwarder; the
// audit/hide logic is the same either way.
#[inline]
unsafe fn getenv_impl(name: *const c_char, secure: bool) -> *mut c_char {
    let real = |n: *const c_char| -> *mut c_char {
        if secure {
            real_secure_getenv_raw(n)
        } else {
            real_getenv_raw(n)
        }
    };
    if in_shim() {
        return real(name);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real(name);
    }
    set_in_shim(true);
    let hidden = is_protected(name);
    emit(name, hidden);
    let val = if hidden { ptr::null_mut() } else { real(name) };
    set_in_shim(false);
    val
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    getenv_impl(name, false)
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    getenv_impl(name, true)
}

// __secure_getenv is a deprecated glibc alias for secure_getenv.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __secure_getenv(name: *const c_char) -> *mut c_char {
    getenv_impl(name, true)
}

// MACOS: getenv interpose wrapper.  macOS has NO secure_getenv /
// __secure_getenv, so only `getenv` is interposed.  `secure=false`.
#[cfg(target_os = "macos")]
unsafe extern "C" fn getenv_interpose(name: *const c_char) -> *mut c_char {
    getenv_impl(name, false)
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_GETENV,
    getenv_interpose,
    libc::getenv,
    unsafe extern "C" fn(*const c_char) -> *mut c_char
);

// ── exec wrappers ──────────────────────────────────────────────────────────
//
// All exec-family entry points funnel through `dispatch_exec` (which forwards
// to real_execve) or `dispatch_spawn` (which forwards to real posix_spawn /
// posix_spawnp).  Each wrapper is responsible for:
//   1. The standard guard preamble (in_shim / INIT_DONE) and set_in_shim
//      bracketing.
//   2. Resolving the program name to an absolute path when PATH search is
//      required (execvp / execvpe / posix_spawnp / execveat / fexecve).
//   3. Calling the dispatch helper with the resolved prog and original argv.
//
// `dispatch_exec` rewrites envp via the EnvBuf helpers — re-injecting
// LD_PRELOAD, NODE_OPTIONS, and the SCRIPT_JAIL_* sticky vars — emits an
// "exec" JSONL audit line, then forwards to real_execve.  On real_execve
// failure return it frees the EnvBuf and propagates the error.

// ── real-symbol callers (transmute wrappers around the AtomicPtr slots) ────

#[cfg(target_os = "linux")]
type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;
#[cfg(target_os = "linux")]
type PosixSpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const libc::posix_spawn_file_actions_t,
    *const libc::posix_spawnattr_t,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;

#[cfg(target_os = "linux")]
unsafe fn real_execve_raw(
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let p = REAL_EXECVE.load(Ordering::Acquire);
    if p.is_null() {
        // dlsym failed — return -1 with errno=ENOSYS, the safest forwarding
        // semantics for a missing exec implementation.
        unsafe {
            *libc::__errno_location() = libc::ENOSYS;
        }
        return -1;
    }
    let f: ExecveFn = transmute(p);
    f(prog, argv, envp)
}

// MACOS: direct same-image libc reference (no interpose recursion — R8).
#[cfg(target_os = "macos")]
unsafe fn real_execve_raw(
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    libc::execve(prog, argv, envp)
}

#[cfg(target_os = "linux")]
unsafe fn real_posix_spawn_raw(
    slot: &AtomicPtr<c_void>,
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let p = slot.load(Ordering::Acquire);
    if p.is_null() {
        return libc::ENOSYS;
    }
    let f: PosixSpawnFn = transmute(p);
    f(pid, path, file_actions, attrp, argv, envp)
}

// MACOS: `which` selects the real posix_spawn vs posix_spawnp (the macOS
// dispatch path passes a bool rather than an AtomicPtr slot since there are no
// dlsym slots).  Direct libc references, non-recursive (R8).
#[cfg(target_os = "macos")]
unsafe fn real_posix_spawn_raw_macos(
    spawnp: bool,
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if spawnp {
        libc::posix_spawnp(pid, path, file_actions, attrp, argv, envp)
    } else {
        libc::posix_spawn(pid, path, file_actions, attrp, argv, envp)
    }
}

// ── environ access ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
unsafe extern "C" {
    static environ: *const *const c_char;
}

#[cfg(target_os = "linux")]
unsafe fn environ_ptr() -> *const *const c_char {
    environ
}

// MACOS: the loader does NOT export a public `environ` symbol the way glibc
// does; the supported accessor is `_NSGetEnviron()`, which returns a pointer to
// the process's `char ***environ` cell.  Dereference once to get the live
// `char **`.
#[cfg(target_os = "macos")]
unsafe fn environ_ptr() -> *const *const c_char {
    let p = libc::_NSGetEnviron();
    if p.is_null() {
        return ptr::null();
    }
    *p as *const *const c_char
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
unsafe fn environ_ptr() -> *const *const c_char {
    ptr::null()
}

// ── audit emit for exec events ─────────────────────────────────────────────

// Audit-trust Finding (high, 2026-05-18): the shim's exec event carries an
// explicit `result` field so the phase-install cross-check can ignore
// failed-attempt shim events when pairing against successful strace
// execves.  Before this fix, `dispatch_exec` emitted exactly one event
// BEFORE calling real_execve (the only place the calling pid is still
// known) — and that event counted toward `shimExecCountByPid` even when
// real_execve subsequently returned -1 ENOENT.  An attacker could then
// pad the shim count with failed wrapped execves and the matching
// strace count from a real raw-syscall bypass produced no positive
// delta — the bypass detector synthesised zero `<SYSCALL_EXEC_BYPASS>`
// entries and the lockfile diff stayed clean.
//
// Wire shape: the shim emits a pre-call event with `result:"ok"`
// (`dispatch_exec`) or a post-call success event with `result:"ok"`
// (`dispatch_spawn` on rc==0).  On failure return (only reachable for
// `dispatch_exec` when real_execve returns and for `dispatch_spawn`
// when rc!=0 or envp_alloc_failed), the shim emits an additional event
// with `result:"failed"`.  The phase-install cross-check computes
// `okEvents - failedEvents` per pid; failed-attempt shim events thus
// cancel out and only true successful libc-wrapper paths contribute to
// the cross-check denominator.
#[repr(u8)]
enum ExecResult {
    Ok,
    Failed,
}

// On Linux the trailing macOS-only params (`argv`, `exec_errno`) are unused —
// the ELF JSONL must stay byte-identical, so they are never serialized there.
// They are still threaded through the signature so the shared call sites in the
// exec/spawn dispatchers compile on both targets.
unsafe fn emit_exec(
    prog: *const c_char,
    argv0: *const c_char,
    envp_alloc_failed: bool,
    result: ExecResult,
    audit_blind: bool,
    argv: *const *const c_char,
    exec_errno: c_int,
) {
    let pid = libc::getpid();
    emit_exec_for_pid(
        prog,
        argv0,
        envp_alloc_failed,
        pid,
        result,
        audit_blind,
        argv,
        exec_errno,
    );
}

/// Append `,"<key>":"<json-escaped value>"` from a CanonBuf into the JSONL
/// scratch buffer at `pos`, returning the new write position.  Omits the field
/// entirely (returns `pos` unchanged) when the CanonBuf is empty OR the field
/// would not fit while leaving room for the closing `}\n` — the guest agent
/// treats a missing attribution field as "no shim attribution" and falls back
/// to its /proc walk, so omission is always safe.  The value is json-escaped
/// (it originates from the process's environ, which a lifecycle script can set
/// to arbitrary bytes) and truncated safely by `json_escape` if pathologically
/// long.
unsafe fn append_canon_field(
    buf: &mut [u8],
    mut pos: usize,
    key: &[u8],
    canon: &CanonBuf,
) -> usize {
    if canon.len.load(Ordering::Acquire) == 0 {
        return pos;
    }
    // Opening run is `,"<key>":"` = key.len() + 5 bytes.  Reserve 3 trailing
    // bytes: the closing value quote (1) and the record's `}\n` tail (2).  Bail
    // (omit) unless the opening run plus at least one value byte plus the
    // reserve all fit.
    let open_len = key.len() + 5;
    // Bail (omit) unless the opening run, a value region at least
    // TRUNC_MARKER.len() bytes wide, and the 3-byte reserve (the closing value
    // quote + the record's `}\n` tail) all fit.  json_escape writes its
    // TRUNC_MARKER on truncation; a value slice narrower than the marker would
    // (absent json_escape's own fit-check) copy it past the slice and abort the
    // no_std shim.  Requiring marker-width here keeps the slice handed to
    // json_escape always ≥ the marker, so it never has to drop the marker and
    // never produces a malformed value.  A long argv0 + long npm_package_name
    // can otherwise leave npm_package_version with only a handful of value
    // bytes while still clearing a `>= 1 byte` guard — exactly the panic this
    // closes.  Omission is safe: the guest treats a missing attribution field
    // as "no shim attribution" and falls back to its /proc walk.
    if pos + open_len + 3 + TRUNC_MARKER.len() > buf.len() {
        return pos;
    }
    buf[pos] = b',';
    pos += 1;
    buf[pos] = b'"';
    pos += 1;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos] = b'"';
    pos += 1;
    buf[pos] = b':';
    pos += 1;
    buf[pos] = b'"';
    pos += 1;
    // Escape the value into the space that remains after reserving the closing
    // quote (1) and the `}\n` tail (2).  json_escape never writes past the
    // slice it is given and truncates with its own marker if needed.
    let value_end = buf.len() - 3;
    let canon_ptr = (*canon.bytes.get()).as_ptr() as *const c_char;
    let written = json_escape(&mut buf[pos..value_end], canon_ptr);
    pos += written;
    buf[pos] = b'"';
    pos += 1;
    pos
}

/// macOS-only: append `,"argv":["<esc>","<esc>",…]` (the FULL argv vector) to the
/// exec JSONL record.  Linux drops exec events in normalize.ts and its goldens
/// must not move, so this field is gated to `target_os = "macos"` and never
/// emitted on the ELF build.
///
/// Determinism + bounds: the caller passes a 3-byte reserve in `tail_reserve`
/// (the record's closing `}\n` plus any optional fields emitted after argv).
/// Every byte is bounds-checked against `buf.len() - tail_reserve`; if the next
/// element (or the next byte of an element) would not fit, the array is closed
/// EARLY and we return.  The element COUNT is capped at MAX_ARGV_ELEMS and each
/// element body at MAX_ARGV_ELEM_LEN escaped bytes, so the output is identical
/// regardless of how the script timed its exec.  Returns the new write position;
/// on any failure to fit it leaves a well-formed (possibly truncated) array.
#[cfg(target_os = "macos")]
unsafe fn append_argv_field(
    buf: &mut [u8],
    mut pos: usize,
    argv: *const *const c_char,
    tail_reserve: usize,
) -> usize {
    // Hard ceiling every write must respect so the caller's tail (`}\n` + any
    // post-argv field) always fits.  saturating_sub keeps the limit valid even
    // if the buffer were ever smaller than the reserve.
    let limit = buf.len().saturating_sub(tail_reserve);

    // Opening run `,"argv":[` — bail entirely (omit the field) if it would not
    // fit, leaving `pos` untouched so the caller still produces valid JSON.
    let open = br#","argv":["#;
    if pos + open.len() > limit {
        return pos;
    }
    buf[pos..pos + open.len()].copy_from_slice(open);
    pos += open.len();

    if argv.is_null() {
        // Null argv → empty array `[]`.  The opening `[` is already written.
        if pos < limit {
            buf[pos] = b']';
            pos += 1;
        }
        return pos;
    }

    let mut first = true;
    let mut i = 0usize;
    while i < MAX_ARGV_ELEMS {
        let elem = *argv.add(i);
        if elem.is_null() {
            break; // NULL terminator → end of argv.
        }
        // Separator + opening quote for this element.  Need at least
        // `[,]"` (≤2) + the closing `"` + closing `]` to fit; if the element
        // opener can't fit we stop and close the array deterministically.
        let sep_len = if first { 1 } else { 2 }; // `"` or `,"`
        // Need: sep+open quote (sep_len) + at least the closing value quote (1)
        // + the array close `]` (1).  If even an empty element won't fit, stop.
        if pos + sep_len + 1 + 1 > limit {
            break;
        }
        if !first {
            buf[pos] = b',';
            pos += 1;
        }
        buf[pos] = b'"';
        pos += 1;
        first = false;

        // Escape the element body into the space that remains AFTER reserving the
        // closing value quote (1) and the array close `]` (1).  json_escape never
        // writes past the slice it is given and clamps with its own marker if
        // needed.  Additionally clamp the slice to MAX_ARGV_ELEM_LEN so a single
        // huge arg cannot dominate the whole budget — keeping later elements'
        // presence deterministic up to the buffer limit.
        let value_end_cap = (pos + MAX_ARGV_ELEM_LEN).min(limit.saturating_sub(1));
        let value_end = value_end_cap.max(pos); // never < pos
        let written = json_escape(&mut buf[pos..value_end], elem);
        pos += written;

        // Closing value quote — guaranteed to fit by the `+1` reserve above.
        buf[pos] = b'"';
        pos += 1;
        i += 1;
    }

    // Close the array.  The element loop reserved a byte for `]` on every entry,
    // and the opening-run check reserved room too, so this fits; guard anyway so
    // a degenerate buffer can never write out of bounds.
    if pos < limit {
        buf[pos] = b']';
        pos += 1;
    }
    pos
}

/// macOS-only: map a (positive) errno to the short uppercase string the Linux
/// strace-parser emits (`ENOENT` / `EACCES`).  normalize.ts only renders the two
/// blocked spawn results derived from these; any other errno yields `None` so the
/// guest synth drops the failed exec rather than inventing a spurious result.
#[cfg(target_os = "macos")]
fn exec_errno_str(e: c_int) -> Option<&'static [u8]> {
    if e == libc::ENOENT {
        Some(b"ENOENT")
    } else if e == libc::EACCES {
        Some(b"EACCES")
    } else {
        None
    }
}

// Audit-trust Finding 1 (high): posix_spawn dispatch must emit the shim
// `exec` event tagged with the CHILD pid (the one strace records the
// child's execve under), not the parent pid.  Otherwise the
// per-pid strace-vs-shim cross-check in phase-install treats every
// successful posix_spawn as a syscall bypass (`<SYSCALL_EXEC_BYPASS>`).
// `dispatch_spawn` uses this helper after `real_posix_spawn_raw`
// returns; `dispatch_exec` keeps using `emit_exec` (the calling pid IS
// the pid strace records the execve under for execve/execv/execvp/…).
unsafe fn emit_exec_for_pid(
    prog: *const c_char,
    argv0: *const c_char,
    envp_alloc_failed: bool,
    pid: libc::pid_t,
    result: ExecResult,
    // macOS-only: `true` when this exec ran a SIP-protected system binary the
    // shim could NOT redirect to a bundled substitute (the real arm64e image
    // runs with DYLD_INSERT_LIBRARIES stripped, so it + its descendants execute
    // outside the audit envelope).  Serialized as `"audit_blind":true` ONLY when
    // true so non-blind records — and every Linux record — stay byte-identical.
    audit_blind: bool,
    // macOS-only: the FULL argv vector for this exec.  Serialized as
    // `"argv":[…]` ONLY on macOS so the guest can synthesize a spawn whose
    // command line matches Linux's full strace argv.  Linux never serializes it
    // (its ELF JSONL must stay byte-identical and normalize drops exec events).
    // `_argv` so the Linux build (which ignores it) does not warn.
    _argv: *const *const c_char,
    // macOS-only: on a FAILED exec, the errno (execve) or rc-as-errno
    // (posix_spawn).  Serialized as `"exec_errno":"ENOENT"|"EACCES"` ONLY on
    // macOS, ONLY for ExecResult::Failed, and ONLY for errnos Linux's strace
    // parser would record.  Linux passes 0 and never serializes it.
    _exec_errno: c_int,
) {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;

    let mut buf = [0u8; JSONL_BUF];
    let mut pos = 0usize;

    // Reserve trailing budget for the suffix: closing argv0 quote (or "null"),
    // ","pid":<20>,"ts":<20>,"envp_alloc_failed":<5>,"result":"failed", the
    // three optional npm attribution fields, and the closing `}\n`.
    // npm_package_name is ≤214 bytes (npm naming limit) and needs no escaping
    // in practice; with the field keys + version + lifecycle the attribution
    // run is ~320 bytes worst-case.  512 reserves comfortably for it plus the
    // fixed pid/ts/result tail without crowding the prog/argv0 budget (the
    // 4096-byte buffer still leaves ~1.7 KiB each for prog and argv0).  Every
    // append below is independently bounds-guarded, so an oversized value is
    // safely truncated/omitted regardless of this reserve.
    const SUFFIX_RESERVE: usize = 512;

    let prefix = br#"{"kind":"exec","prog":""#;
    if prefix.len() > buf.len() {
        return;
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    // Compute a per-string escape budget so neither prog nor argv0 can starve
    // the other.  Allow half of the remaining budget for prog.
    let total_budget_end = JSONL_BUF.saturating_sub(SUFFIX_RESERVE);
    let prog_budget_end = pos + (total_budget_end.saturating_sub(pos)) / 2;
    if pos < prog_budget_end {
        let written = json_escape(&mut buf[pos..prog_budget_end], prog);
        pos += written;
    }

    // argv0 field: emit `"argv0":null` for a NULL pointer (no surrounding quotes),
    // otherwise emit `"argv0":"<escaped>"`.
    if argv0.is_null() {
        let mid = br#"","argv0":null"#;
        if pos + mid.len() > buf.len() {
            return;
        }
        buf[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
    } else {
        let mid = br#"","argv0":""#;
        if pos + mid.len() > buf.len() {
            return;
        }
        buf[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        if pos < total_budget_end {
            let written = json_escape(&mut buf[pos..total_budget_end], argv0);
            pos += written;
        }
        if pos + 1 > buf.len() {
            return;
        }
        buf[pos] = b'"';
        pos += 1;
    }

    let mid1 = br#","pid":"#;
    if pos + mid1.len() > buf.len() {
        return;
    }
    buf[pos..pos + mid1.len()].copy_from_slice(mid1);
    pos += mid1.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    let mid2 = br#","ts":"#;
    if pos + mid2.len() > buf.len() {
        return;
    }
    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    pos += write_i64(&mut buf[pos..], ns);

    let mid3 = br#","envp_alloc_failed":"#;
    if pos + mid3.len() > buf.len() {
        return;
    }
    buf[pos..pos + mid3.len()].copy_from_slice(mid3);
    pos += mid3.len();
    let bool_str: &[u8] = if envp_alloc_failed { b"true" } else { b"false" };
    if pos + bool_str.len() > buf.len() {
        return;
    }
    buf[pos..pos + bool_str.len()].copy_from_slice(bool_str);
    pos += bool_str.len();

    // Audit-trust Finding (2026-05-18): emit `"result":"ok"` or
    // `"result":"failed"` so the phase-install cross-check can ignore
    // failed-attempt shim events when pairing against strace's
    // successful-execve count.  See `enum ExecResult` for context.
    let result_tail: &[u8] = match result {
        ExecResult::Ok => br#","result":"ok""#,
        ExecResult::Failed => br#","result":"failed""#,
    };
    if pos + result_tail.len() + 2 > buf.len() {
        return;
    }
    buf[pos..pos + result_tail.len()].copy_from_slice(result_tail);
    pos += result_tail.len();

    // macOS audit-blind signal.  Emitted ONLY when true so non-blind records and
    // every Linux record are byte-identical to the pre-change shim output.  A
    // blind exec ran a real, SIP-de-privileged system binary (under /bin or
    // /usr/bin) the shim could not instrument; normalize.ts surfaces it as an
    // `<AUDIT_BLIND>` prefix in spawn_attempts so the lock diff exposes the
    // un-audited subtree.  `+ 2` reserves the closing `}\n`.
    if audit_blind {
        let audit_blind_tail = br#","audit_blind":true"#;
        if pos + audit_blind_tail.len() + 2 <= buf.len() {
            buf[pos..pos + audit_blind_tail.len()].copy_from_slice(audit_blind_tail);
            pos += audit_blind_tail.len();
        }
    }

    // macOS-only: full argv array + failed-exec errno.  Both are gated to
    // `target_os = "macos"` so the Linux ELF JSONL stays byte-identical (Linux
    // normalize drops exec events and its goldens must not move).  argv is
    // emitted BEFORE the npm attribution fields so field ordering is fixed; its
    // `tail_reserve` is SUFFIX_RESERVE, which already budgets the npm attribution
    // run (~320 B worst case) + the optional exec_errno field + the `}\n` tail,
    // so neither argv nor the attribution fields can crowd the closing bytes.
    #[cfg(target_os = "macos")]
    {
        pos = append_argv_field(&mut buf, pos, _argv, SUFFIX_RESERVE);
        // exec_errno: emitted ONLY for a failed exec and ONLY for an errno Linux's
        // strace parser would record (ENOENT / EACCES).  The guest synth turns
        // this into a `<ENOENT>`/`<EACCES>` spawn_blocked entry; an unmapped errno
        // is omitted (the failed exec is then dropped, matching Linux).
        if matches!(result, ExecResult::Failed) {
            if let Some(errno_str) = exec_errno_str(_exec_errno) {
                // `,"exec_errno":"<str>"` ; `+ 2` reserves the closing `}\n`.
                let open = br#","exec_errno":""#;
                if pos + open.len() + errno_str.len() + 1 + 2 <= buf.len() {
                    buf[pos..pos + open.len()].copy_from_slice(open);
                    pos += open.len();
                    buf[pos..pos + errno_str.len()].copy_from_slice(errno_str);
                    pos += errno_str.len();
                    buf[pos] = b'"';
                    pos += 1;
                }
            }
        }
    }

    // npm lifecycle attribution (deterministic, in-process, reap-proof).  Each
    // field is omitted when its CanonBuf is empty (process is not inside a
    // lifecycle script — e.g. npm/pnpm itself) so non-lifecycle exec records
    // are byte-identical to the pre-change shim output.  The guest agent
    // composes `pkg = npm_package_name[@npm_package_version]` and uses it to
    // attribute the strace-observed spawn for this pid, matching
    // Attribution.buildPkg exactly.
    pos = append_canon_field(&mut buf, pos, b"npm_package_name", &CANON_NPM_PACKAGE_NAME);
    pos = append_canon_field(
        &mut buf,
        pos,
        b"npm_package_version",
        &CANON_NPM_PACKAGE_VERSION,
    );
    pos = append_canon_field(
        &mut buf,
        pos,
        b"npm_lifecycle_event",
        &CANON_NPM_LIFECYCLE_EVENT,
    );

    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    if pos > 0 && pos <= JSONL_BUF {
        write_all(log_fd, &buf[..pos]);
    }
}

// ── envp rewrite (shared by exec + spawn dispatchers) ──────────────────────
//
// INVARIANT: all SCRIPT_JAIL_* sticky vars are snapshotted at shim_init from
// the parent's trusted environ (see capture_canon in the ctor).  Exec-time
// reads via real_getenv_raw / libc::getenv are FORBIDDEN here because the
// live `environ` array is mutable — a native attacker can poke
// `environ[i] = "SCRIPT_JAIL_LOG_FILE=/dev/null"` directly, bypassing
// setenv/putenv/unsetenv guards, and the poisoned value would otherwise be
// stamped into the child's env as canonical.  The CanonBuf statics are
// written exactly once in the ctor (before INIT_DONE flips) and are read
// here via an Acquire load — making the snapshot tamper-proof.

/// Pairs each sticky SCRIPT_JAIL_* env-var name (without NUL) with the
/// init-time CanonBuf that holds its canonical value.  rewrite_envp reads
/// values exclusively through these CanonBufs; it does NOT consult the live
/// process environ for sticky vars.
struct StickyVar {
    name: &'static [u8],
    canon: &'static CanonBuf,
}

const STICKY_VARS: &[StickyVar] = &[
    StickyVar {
        name: b"SCRIPT_JAIL_LOG_FILE",
        canon: &CANON_LOG_FILE,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_LOG_FD",
        canon: &CANON_LOG_FD,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_PROTECTED_ENV_NAMES",
        canon: &CANON_PROTECTED_ENV_NAMES,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_SPOOF_PLATFORM",
        canon: &CANON_SPOOF_PLATFORM,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_SPOOF_ARCH",
        canon: &CANON_SPOOF_ARCH,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_PRELOAD_PATH",
        canon: &CANON_PRELOAD_PATH,
    },
    StickyVar {
        name: b"SCRIPT_JAIL_NODE_OPTIONS",
        canon: &CANON_NODE_OPTIONS,
    },
    // MACOS only: the re-signed shell/coreutils shim dir consulted by
    // sip_redirect.  Re-injected on every exec so a descendant can't strip it.
    #[cfg(target_os = "macos")]
    StickyVar {
        name: b"SCRIPT_JAIL_SHELL_SHIM_DIR",
        canon: &CANON_SHELL_SHIM_DIR,
    },
    // MACOS only: the install/repo root used as is_external_system_tool keep-root
    // #6 (covers top-level node_modules/.bin helpers after a lifecycle chdir).
    // Re-injected on every exec from the init-time CanonBuf — NOT the live envp —
    // so a descendant that unsets SCRIPT_JAIL_WORK_DIR cannot defeat the keep-root
    // for KEPT children (and the unset is itself audited as env_tamper).
    #[cfg(target_os = "macos")]
    StickyVar {
        name: b"SCRIPT_JAIL_WORK_DIR",
        canon: &CANON_WORK_DIR,
    },
    #[cfg(target_os = "macos")]
    StickyVar {
        name: b"SCRIPT_JAIL_MACOS_AUDIT_OPS",
        canon: &CANON_MACOS_AUDIT_OPS,
    },
];

/// Build a rewritten EnvBuf from the input envp.  `envp_in` may be NULL — that
/// is treated semantically as "caller asked for an empty env"; we still
/// re-inject our own LD_PRELOAD/NODE_OPTIONS/SCRIPT_JAIL_* entries because
/// otherwise the shim chain breaks in the child.  We do NOT fold in the
/// current process's `environ` — preserving the caller's intent.
///
/// Returns None on any allocation failure: caller must emit
/// `envp_alloc_failed:true` and forward the original envp_in untouched.
///
/// The returned buf is the caller's responsibility to `free_envbuf` on real_*
/// return.
unsafe fn rewrite_envp(envp_in: *const *const c_char, external: bool) -> Option<EnvBuf> {
    // `external` only gates the macOS un-shim path below; on Linux every spawn
    // is in-microVM and always re-shimmed (no external-tool concept), so the
    // arg is unused there.
    #[cfg(not(target_os = "macos"))]
    let _ = external;
    // Read canon values BEFORE envbuf_from — those helpers do not hold the
    // recursion guard across calls.  canon_bytes is a memory read.
    let preload = canon_bytes(&CANON_PRELOAD_PATH);
    let node_opts = canon_bytes(&CANON_NODE_OPTIONS);

    let mut buf = envbuf_from(envp_in)?;

    // MACOS Option B (2026-06): the spawn target was classified as an EXTERNAL
    // SYSTEM TOOL — a binary resolved OUTSIDE every "keep-audited" root (the
    // provisioned-node bin dir, the bundled shell/coreutils shim dir, and the
    // install cwd).  Examples: /opt/homebrew/bin/git, /usr/bin/sed, /usr/bin/perl.
    //
    // These tools are NOT package code; Linux records only the spawn line for
    // them and never audits their internals (strace pairs the spawn but the
    // tool's own getenv/open reads are not in the lock).  On a non-SIP path like
    // Homebrew git, dyld does NOT strip DYLD_INSERT_LIBRARIES, so the shim WOULD
    // load into git and leak 30-40 of git's own GIT_* getenv reads + its
    // open($HOME/.gitconfig) into the lock under the spawning package's
    // attribution — pure macOS-only noise that breaks the parity gate.
    //
    // Fix: strip the dynamic-linker injection AND the sticky SCRIPT_JAIL_* vars
    // from the child env so the shim never loads into the tool and the WHOLE
    // subtree it spawns stays un-shimmed (matches the SIP-stripped Linux/audit-
    // blind target).  The exec record is also marked audit_blind:true by the
    // caller, so the spawn line renders `<AUDIT_BLIND> git config …` (already
    // waived in scripts/parity-diff.ts).
    //
    // We do NOT re-inject PRELOAD_VAR / NODE_OPTIONS / the sticky vars below;
    // we remove every entry for each instead.  The linker-strip vars
    // (DYLD_LIBRARY_PATH / DYLD_FRAMEWORK_PATH) and DYLD_FORCE_FLAT_NAMESPACE
    // are also removed so no residual dyld surface survives into the tool.
    #[cfg(target_os = "macos")]
    if external {
        envbuf_remove(&mut buf, PRELOAD_VAR); // DYLD_INSERT_LIBRARIES
        envbuf_remove(&mut buf, b"DYLD_FORCE_FLAT_NAMESPACE");
        envbuf_remove(&mut buf, b"NODE_OPTIONS");
        for name in LINKER_STRIP_VARS {
            envbuf_remove(&mut buf, name);
        }
        for sticky in STICKY_VARS {
            envbuf_remove(&mut buf, sticky.name);
        }
        return Some(buf);
    }

    // Re-inject LD_PRELOAD and NODE_OPTIONS.  We OVERWRITE rather than
    // merge: an earlier implementation prepended the canonical value to
    // whatever the caller supplied (so our wrappers' symbols / require
    // modules would still load first).  That was unsafe — ld.so still
    // executes the ELF constructor of any attacker-supplied .so before
    // our wrappers shadow its symbols, and Node still loads any
    // attacker-supplied `--require=` module right after ours.  Either is
    // enough for arbitrary code to run inside the audit envelope.
    //
    // There is no legitimate reason for an npm lifecycle script to set
    // LD_PRELOAD, and no realistic legitimate reason inside this microVM
    // to honor caller-supplied NODE_OPTIONS — the audit envelope is the
    // whole point.  Drop caller-supplied values for both; overwrite_env
    // strips every existing entry for the name and pushes exactly one
    // canonical entry.
    //
    // EMPTY CANON: shim_init captures the parent's LD_PRELOAD /
    // NODE_OPTIONS as fallback canonicals when the explicit
    // SCRIPT_JAIL_PRELOAD_PATH / SCRIPT_JAIL_NODE_OPTIONS are unset.
    // So in practice the canon is non-empty whenever the shim was
    // actually loaded by the parent.  The only way both canons stay
    // empty is when the parent never set either var — in that case
    // overwrite_env's empty-value branch exhaustively removes any
    // caller-supplied entry, which is the desired behavior (we won't
    // honor an attacker-controlled LD_PRELOAD/NODE_OPTIONS that the
    // parent never sanctioned).  No special-casing in this function.
    if !overwrite_env(&mut buf, PRELOAD_VAR, preload) {
        free_envbuf(&mut buf);
        return None;
    }
    if !overwrite_env(&mut buf, b"NODE_OPTIONS", node_opts) {
        free_envbuf(&mut buf);
        return None;
    }

    // Audit-trust Finding 2 (2026-05-18): LD_AUDIT and LD_LIBRARY_PATH survive
    // env rewriting unless we strip them explicitly.
    //
    //   - `LD_AUDIT=/tmp/evil.so` makes glibc's ld.so load the named DSO via
    //     the rtld-audit API BEFORE any LD_PRELOAD entries and before the
    //     program's own constructor.  Even though our shim is the canonical
    //     LD_PRELOAD, an attacker-controlled audit module runs first and can
    //     do anything the process can — read protected env, intercept syscalls,
    //     exfiltrate secrets, etc.
    //   - `LD_LIBRARY_PATH=/tmp/attacker_libs:` is searched by ld.so BEFORE
    //     the canonical RUNPATH/DT_NEEDED resolution, so dropping a same-name
    //     .so under that prefix can shadow legitimate libraries the audited
    //     install relies on (libcurl, libcrypto, libz, etc.).
    //
    // There is no legitimate reason for an npm lifecycle script to set either
    // var inside this microVM — the audit envelope owns the dynamic-linker
    // surface end-to-end.  Strip exhaustively (envbuf_remove walks every
    // duplicate, not just the first match).  envbuf_remove with no value to
    // push cannot fail.
    //
    // Both names are also added to AUDIT_PROTECTED_NAMES so the env-mutator
    // wrappers (setenv/unsetenv/putenv) refuse to set them in-process; this
    // closes the in-process mutation path that would otherwise let a script
    // restore the value AFTER the shim's exec-time strip.
    //
    // MACOS dyld uses DYLD_LIBRARY_PATH / DYLD_FRAMEWORK_PATH for the same
    // attacker primitive; LINKER_STRIP_VARS selects the right pair per loader.
    for name in LINKER_STRIP_VARS {
        envbuf_remove(&mut buf, name);
    }

    // Re-inject SCRIPT_JAIL_* sticky values from the init-time CanonBufs.
    //
    // SECURITY: do NOT read these via libc::getenv / real_getenv_raw at
    // exec-time.  The live `environ` is freely mutable by native code
    // (direct `environ[i] = ...` writes bypass our setenv/putenv guards),
    // so any getenv-at-rewrite would let an attacker redirect the child's
    // audit log, protect-list path, or platform/arch spoof.  The CanonBufs
    // are snapshotted from the trusted parent environ inside shim_init
    // BEFORE any user code has had a chance to mutate it.
    //
    // Use overwrite_env (not ensure_env) so a malicious caller cannot pass
    // e.g. `SCRIPT_JAIL_LOG_FILE=/dev/null` in envp_in and shadow the
    // canonical value.  The CanonBuf snapshot is authoritative.
    for sticky in STICKY_VARS {
        let val = canon_bytes(sticky.canon);
        if val.is_empty() {
            // Canonical is empty (parent never set this sticky var, or it
            // was unset at shim_init).  Any caller-supplied entry for this
            // name must be REMOVED — leaving it in place would let an
            // attacker poison the child's audit chain (e.g. by injecting
            // SCRIPT_JAIL_LOG_FILE=/tmp/evil when the parent only set
            // SCRIPT_JAIL_LOG_FD).  envbuf_remove returns false if no
            // entry was present, which is the desired no-op.
            envbuf_remove(&mut buf, sticky.name);
            continue;
        }
        if !overwrite_env(&mut buf, sticky.name, val) {
            free_envbuf(&mut buf);
            return None;
        }
    }

    Some(buf)
}

// ── dispatch_exec: shared funnel for execve-family wrappers ────────────────
//
// Each wrapper supplies its own `forward` closure-like callback through the
// `RealExecForward` enum so the real libc function actually invoked matches
// the wrapper's contract (e.g. execvp keeps glibc's PATH search; execveat
// keeps the kernel's AT_FDCWD / AT_EMPTY_PATH / flags handling).
//
// On return from rewrite_envp, the recursion guard is undefined (helpers
// clobber it).  We re-assert it before emit_exec and the real forward so
// emit/real_* internals (clock_gettime, write, libc init paths) do not
// reenter the audited path.

// LINUX: the full execve-family forwarder.  macOS funnels every exec through a
// single `real_execve_raw` (libSystem routes execl*/execvp/execv through the
// public execve, proven by the spike), so it does NOT need this enum or the
// execvpe/execveat/fexecve variants — see the `dispatch_exec` macos branch.
#[cfg(target_os = "linux")]
enum RealExecForward {
    Execve,  // real_execve(prog, argv, envp)
    Execvpe, // real_execvpe(prog, argv, envp)
    Execveat {
        // real_execveat(dirfd, prog, argv, envp, flags)
        dirfd: c_int,
        flags: c_int,
    },
    Fexecve {
        // real_fexecve(fd, argv, envp); prog is unused
        fd: c_int,
    },
}

#[cfg(target_os = "linux")]
type ExecvFn = unsafe extern "C" fn(*const c_char, *const *const c_char) -> c_int;
#[cfg(target_os = "linux")]
type ExecveatFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    *const *const c_char,
    *const *const c_char,
    c_int,
) -> c_int;
#[cfg(target_os = "linux")]
type FexecveFn = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;

#[cfg(target_os = "linux")]
unsafe fn forward_to_real(
    kind: &RealExecForward,
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    match kind {
        RealExecForward::Execve => real_execve_raw(prog, argv, envp),
        RealExecForward::Execvpe => {
            let p = REAL_EXECVPE.load(Ordering::Acquire);
            if !p.is_null() {
                let f: ExecveFn = transmute(p);
                return f(prog, argv, envp);
            }
            // glibc-only ABI.  If absent, the most-correct fallback is to
            // hand off to real_execve and skip PATH search.  Better than
            // silently dropping the call.
            real_execve_raw(prog, argv, envp)
        }
        RealExecForward::Execveat { dirfd, flags } => {
            let p = REAL_EXECVEAT.load(Ordering::Acquire);
            if !p.is_null() {
                let f: ExecveatFn = transmute(p);
                return f(*dirfd, prog, argv, envp, *flags);
            }
            // Older glibc: no execveat libc wrapper.  Fall back to syscall.
            #[cfg(target_os = "linux")]
            {
                let rc =
                    libc::syscall(libc::SYS_execveat, *dirfd, prog, argv, envp, *flags) as c_int;
                return rc;
            }
            #[cfg(not(target_os = "linux"))]
            {
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = libc::ENOSYS;
                }
                -1
            }
        }
        RealExecForward::Fexecve { fd } => {
            let p = REAL_FEXECVE.load(Ordering::Acquire);
            if !p.is_null() {
                let f: FexecveFn = transmute(p);
                return f(*fd, argv, envp);
            }
            // Fallback: use /proc/self/fd/<fd> with real_execve.  This is
            // exactly how glibc itself implements fexecve internally.
            let mut buf = [0u8; 64];
            match proc_fd_only(*fd, &mut buf) {
                Some(_) => real_execve_raw(buf.as_ptr() as *const c_char, argv, envp),
                None => {
                    #[cfg(target_os = "linux")]
                    unsafe {
                        *libc::__errno_location() = libc::ENOSYS;
                    }
                    #[cfg(target_os = "macos")]
                    unsafe {
                        *libc::__error() = libc::ENOSYS;
                    }
                    -1
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn dispatch_exec(
    kind: RealExecForward,
    prog: *const c_char,
    argv: *const *const c_char,
    envp_in: *const *const c_char,
) -> c_int {
    let argv0 = if argv.is_null() { ptr::null() } else { *argv };

    match rewrite_envp(envp_in, false) {
        Some(mut buf) => {
            // Re-assert the recursion guard: rewrite_envp's helpers cleared
            // it on each malloc, so we are now `in_shim==false`.
            set_in_shim(true);
            // Audit-trust Finding (2026-05-18): emit `result:"ok"` BEFORE
            // forward_to_real.  Successful execs replace the process image
            // and never return here, so this is the only opportunity to
            // record the attempt with the calling pid (the pid strace
            // records the execve under).  If real_* returns at all, the
            // exec FAILED — we emit a second event with `result:"failed"`
            // below so the phase-install cross-check can cancel out the
            // pre-call optimistic event when computing per-pid counts.
            // Linux: argv/exec_errno are ignored (the ELF JSONL must stay
            // byte-identical), so pass null/0.
            emit_exec(prog, argv0, false, ExecResult::Ok, false, ptr::null(), 0);
            let rewritten = buf.ptrs as *const *const c_char;
            let rc = forward_to_real(&kind, prog, argv, rewritten);
            // real_* only returns on failure.  Emit the failure marker
            // BEFORE freeing the envbuf so any allocator-side errno
            // change inside free_envbuf can't clobber the value strace
            // reports for the failed exec.
            emit_exec(prog, argv0, false, ExecResult::Failed, false, ptr::null(), 0);
            free_envbuf(&mut buf);
            set_in_shim(false);
            rc
        }
        None => {
            // Fail closed: rewrite_envp returned None because either the
            // input envp exceeded MAX_ENVP_SANITY or an allocation failed.
            // Forwarding the unmodified attacker envp would let a hostile
            // script bypass the audit chain entirely (the child would run
            // without LD_PRELOAD/NODE_OPTIONS/SCRIPT_JAIL_* re-injected).
            // Emit the audit event so the attempt is visible, then return
            // -1 with errno=ENOMEM to refuse the exec.
            //
            // This path never reaches a real exec (we refuse), so the
            // event is tagged `result:"failed"` — the child never ran.
            set_in_shim(true);
            emit_exec(prog, argv0, true, ExecResult::Failed, false, ptr::null(), 0);
            set_errno(libc::ENOMEM);
            set_in_shim(false);
            -1
        }
    }
}

// ── dispatch_spawn: shared funnel for posix_spawn / posix_spawnp ───────────
//
// Unlike dispatch_exec, posix_spawn does NOT replace the process image; it
// forks+execs a child and returns control to the parent regardless of
// outcome.  The parent owns the rewritten EnvBuf and frees it on return.

#[cfg(target_os = "linux")]
unsafe fn dispatch_spawn(
    real_slot: &AtomicPtr<c_void>,
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp_in: *const *mut c_char,
) -> c_int {
    let argv0 = if argv.is_null() {
        ptr::null()
    } else {
        *argv as *const c_char
    };

    match rewrite_envp(envp_in as *const *const c_char, false) {
        Some(mut buf) => {
            // Audit-trust Finding 1 (high, 2026-05-18): defer the audit
            // event until AFTER `real_posix_spawn_raw` returns.  Unlike
            // execve (which replaces the process image, so the calling
            // pid IS the pid strace records the execve under),
            // posix_spawn forks a child and writes the child pid into
            // `*pid`.  Strace records the child's execve under that
            // child pid.  If we emit the shim event using the parent
            // pid here, the per-pid strace-vs-shim cross-check in
            // src/guest/phase-install.ts treats every legitimate
            // posix_spawn / posix_spawnp as `<SYSCALL_EXEC_BYPASS>`.
            //
            // On failure (`rc != 0`) we emit NO audit event — that
            // matches the existing dispatch_exec failure path (the
            // shim doesn't emit when execve returns -1 either, because
            // the child never runs).
            set_in_shim(true);
            let rc = real_posix_spawn_raw(
                real_slot,
                pid,
                path,
                file_actions,
                attrp,
                argv,
                buf.ptrs as *const *mut c_char,
            );
            if rc == 0 {
                // `pid` is the user-provided `pid_t *` output param.
                // posix_spawn is required to write the spawned child's
                // pid here on success.  When the caller passes NULL
                // (allowed by POSIX), there is no way to recover the
                // child pid, so fall back to the parent pid; this is
                // a degraded but better-than-nothing audit signal and
                // matches the pre-fix behaviour for that rare case.
                let child_pid = if !pid.is_null() { *pid } else { libc::getpid() };
                emit_exec_for_pid(
                    path,
                    argv0,
                    false,
                    child_pid,
                    ExecResult::Ok,
                    false,
                    ptr::null(),
                    0,
                );
            } else {
                // Audit-trust Finding (2026-05-18): record failed
                // posix_spawn attempts so the phase-install cross-check
                // doesn't conflate them with successful libc-wrapper
                // execs.  No child pid is available (rc != 0 means
                // posix_spawn never wrote *pid), so the failure event
                // is tagged with the parent pid.  Strace will never
                // record an execve under the parent pid for this
                // attempt (no child was created), so this event is
                // purely a forensic marker and contributes 0 net to
                // the cross-check (no matching strace observation).
                emit_exec(path, argv0, false, ExecResult::Failed, false, ptr::null(), 0);
            }
            free_envbuf(&mut buf);
            set_in_shim(false);
            rc
        }
        None => {
            // Fail closed: rewrite_envp returned None, so spawning with the
            // unmodified attacker envp would let the child bypass the audit
            // chain.  Emit the audit event with envp_alloc_failed:true and
            // return ENOMEM.  posix_spawn returns the errno code as int
            // (does NOT set errno + return -1), so just return libc::ENOMEM.
            //
            // No child pid is available here (the spawn never ran), so
            // we emit with the parent pid.  The cross-check in
            // phase-install treats envp_alloc_failed=true events as a
            // separate signal (`envp_alloc_failed`), not as part of the
            // strace/shim pairing for `<SYSCALL_EXEC_BYPASS>`.
            set_in_shim(true);
            emit_exec(path, argv0, true, ExecResult::Failed, false, ptr::null(), 0);
            set_in_shim(false);
            libc::ENOMEM
        }
    }
}

// ── execve(prog, argv, envp) ───────────────────────────────────────────────
//
// LINUX wrappers (reached via LD_PRELOAD symbol shadowing).  The macOS exec /
// spawn interpose wrappers live in the `#[cfg(target_os = "macos")]` block
// further below — they share dispatch_exec_macos / dispatch_spawn_macos /
// rewrite_envp / emit_exec but use direct libc real calls and the __interpose
// table instead of dlsym slots.

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if in_shim() {
        return real_execve_raw(prog, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_execve_raw(prog, argv, envp);
    }
    set_in_shim(true);
    let rc = dispatch_exec(RealExecForward::Execve, prog, argv, envp);
    set_in_shim(false);
    rc
}

// ── execv(prog, argv) ──────────────────────────────────────────────────────
//
// The audit invariant is that every exec-family entry goes through
// rewrite_envp so the child's env is sanitised before it runs.  Native code
// can poison the parent's environ directly (e.g. `environ[i] =
// "LD_PRELOAD=/tmp/evil.so"`) without touching our setenv/unsetenv/putenv
// guards, then call execv("node", argv) and the unmodified environ would
// carry the poison into the child.  Snapshot environ here and route through
// dispatch_exec so the snapshot is rewritten and the audit chain survives.
// We forward to real_execve (not real_execv) so the rewritten envp is the
// one the child sees; execv historically just calls execve with environ
// under the hood, so this preserves API semantics.

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(prog: *const c_char, argv: *const *const c_char) -> c_int {
    if in_shim() {
        // Re-entrant: forward to real execv (or real_execve with environ).
        let p = REAL_EXECV.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecvFn = transmute(p);
            return f(prog, argv);
        }
        return real_execve_raw(prog, argv, environ_ptr());
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        let p = REAL_EXECV.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecvFn = transmute(p);
            return f(prog, argv);
        }
        return real_execve_raw(prog, argv, environ_ptr());
    }
    set_in_shim(true);
    let rc = dispatch_exec(RealExecForward::Execve, prog, argv, environ_ptr());
    set_in_shim(false);
    rc
}

// ── execvp(file, argv) ─────────────────────────────────────────────────────
//
// Same rationale as execv: snapshot environ, run it through rewrite_envp,
// then forward through real_execvpe so glibc's PATH search semantics
// (ENOEXEC fallback, EACCES preservation, multi-candidate retry) still
// apply.  Skipping rewrite_envp here would let a native script bypass the
// audit chain by mutating environ directly and then calling execvp.

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    if in_shim() {
        let p = REAL_EXECVP.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecvFn = transmute(p);
            return f(file, argv);
        }
        return real_execve_raw(file, argv, environ_ptr());
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        let p = REAL_EXECVP.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecvFn = transmute(p);
            return f(file, argv);
        }
        return real_execve_raw(file, argv, environ_ptr());
    }
    set_in_shim(true);
    let rc = dispatch_exec(RealExecForward::Execvpe, file, argv, environ_ptr());
    set_in_shim(false);
    rc
}

// ── execvpe(file, argv, envp) ──────────────────────────────────────────────
// LINUX only — macOS libc has no execvpe (and PATH-resolving execvp is handled
// in-process by the macOS execvp interpose wrapper).

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if in_shim() {
        let p = REAL_EXECVPE.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecveFn = transmute(p);
            return f(file, argv, envp);
        }
        return real_execve_raw(file, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        let p = REAL_EXECVPE.load(Ordering::Acquire);
        if !p.is_null() {
            let f: ExecveFn = transmute(p);
            return f(file, argv, envp);
        }
        return real_execve_raw(file, argv, envp);
    }
    set_in_shim(true);
    // Forward through real_execvpe so glibc's PATH-search semantics
    // (ENOEXEC fallback, EACCES handling, multi-candidate retry) are
    // preserved.  Rewrite envp first so the child still has our shim vars.
    let rc = dispatch_exec(RealExecForward::Execvpe, file, argv, envp);
    set_in_shim(false);
    rc
}

// ── execveat(dirfd, pathname, argv, envp, flags) ───────────────────────────
// LINUX only — macOS has no execveat syscall/libc wrapper.

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execveat(
    dirfd: c_int,
    pathname: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    flags: c_int,
) -> c_int {
    let argv_const = argv as *const *const c_char;
    let envp_const = envp as *const *const c_char;
    if in_shim() {
        return forward_to_real(
            &RealExecForward::Execveat { dirfd, flags },
            pathname,
            argv_const,
            envp_const,
        );
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return forward_to_real(
            &RealExecForward::Execveat { dirfd, flags },
            pathname,
            argv_const,
            envp_const,
        );
    }
    set_in_shim(true);
    let rc = dispatch_exec(
        RealExecForward::Execveat { dirfd, flags },
        pathname,
        argv_const,
        envp_const,
    );
    set_in_shim(false);
    rc
}

// ── fexecve(fd, argv, envp) ────────────────────────────────────────────────
// LINUX only — macOS fexecve has no `/proc/self/fd` fallback and is not
// exercised by the audited install path, so it is not interposed (the exec
// attempt would still be visible if it routed through execve).

#[cfg(target_os = "linux")]
unsafe fn proc_fd_only(fd: c_int, out_buf: &mut [u8; 64]) -> Option<usize> {
    let prefix = b"/proc/self/fd/";
    let mut pos = 0usize;
    if pos + prefix.len() >= out_buf.len() {
        return None;
    }
    out_buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let n = write_i64(&mut out_buf[pos..], fd as i64);
    pos += n;
    if pos >= out_buf.len() {
        return None;
    }
    out_buf[pos] = 0;
    Some(pos)
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fexecve(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if in_shim() {
        return forward_to_real(&RealExecForward::Fexecve { fd }, ptr::null(), argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return forward_to_real(&RealExecForward::Fexecve { fd }, ptr::null(), argv, envp);
    }
    set_in_shim(true);
    let rc = dispatch_exec(RealExecForward::Fexecve { fd }, ptr::null(), argv, envp);
    set_in_shim(false);
    rc
}

// ── posix_spawn(pid, path, file_actions, attrp, argv, envp) ────────────────

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if in_shim() {
        return real_posix_spawn_raw(
            &REAL_POSIX_SPAWN,
            pid,
            path,
            file_actions,
            attrp,
            argv,
            envp,
        );
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_posix_spawn_raw(
            &REAL_POSIX_SPAWN,
            pid,
            path,
            file_actions,
            attrp,
            argv,
            envp,
        );
    }
    set_in_shim(true);
    let rc = dispatch_spawn(
        &REAL_POSIX_SPAWN,
        pid,
        path,
        file_actions,
        attrp,
        argv,
        envp,
    );
    set_in_shim(false);
    rc
}

// ── posix_spawnp(pid, file, file_actions, attrp, argv, envp) ───────────────

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if in_shim() {
        return real_posix_spawn_raw(
            &REAL_POSIX_SPAWNP,
            pid,
            file,
            file_actions,
            attrp,
            argv,
            envp,
        );
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_posix_spawn_raw(
            &REAL_POSIX_SPAWNP,
            pid,
            file,
            file_actions,
            attrp,
            argv,
            envp,
        );
    }
    set_in_shim(true);
    // Forward through real_posix_spawnp so glibc's PATH search runs in the
    // child with file_actions (cwd changes etc.) already applied — anything
    // we resolve in the parent would race with file_actions.
    let rc = dispatch_spawn(
        &REAL_POSIX_SPAWNP,
        pid,
        file,
        file_actions,
        attrp,
        argv,
        envp,
    );
    set_in_shim(false);
    rc
}

// ── MACOS exec / spawn dispatch + interpose wrappers ───────────────────────
//
// macOS funnels every exec-family entry through a single `real_execve_raw`
// (libSystem routes execl* / execvp / execv through the public, interposable
// execve — proven by the spike), so there is no execvpe/execveat/fexecve and
// no PATH-resolving libc forwarder.  dispatch_exec_macos / dispatch_spawn_macos
// mirror the Linux dispatchers (same emit/rewrite_envp/fail-closed semantics)
// but call libc directly and run sip_redirect on the program path first.

#[cfg(target_os = "macos")]
unsafe fn dispatch_exec_macos(
    prog: *const c_char,
    argv: *const *const c_char,
    envp_in: *const *const c_char,
) -> c_int {
    let argv0 = if argv.is_null() { ptr::null() } else { *argv };

    // SIP redirect: when prog is /bin/{sh,bash} or a /usr/bin coreutil, dyld
    // strips DYLD_INSERT_LIBRARIES on exec, so the child would run un-audited.
    // Rewrite to the bundled plain-arm64 substitute (bash / coreutils) if one
    // covers it; otherwise the real arm64e binary runs and we mark it
    // audit_blind below.  The buffer is stack-local and outlives the exec call.
    let mut canon_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let canon = lexical_canon(prog, &mut canon_buf);
    let mut redirect_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    // Match/redirect against the CANONICAL path (so `/tmp/../bin/sh` redirects and
    // `/tmp/../usr/bin/find` is classified), but keep exec'ing the caller's
    // ORIGINAL `prog` when no substitute applies (same binary, minimal change).
    let redirected = sip_redirect(canon, &mut redirect_buf);
    let (prog, audit_blind, external) = if redirected != canon {
        // Canon matched a shell/coreutil → run the instrumented substitute.
        // A substituted shell is one of OUR bundled binaries under the shim dir;
        // it is always a keep-audited root (external == false).
        (redirected, false, false)
    } else {
        // No substitute → the real binary runs.  It is audit-blind when EITHER:
        //   - the canonical path is under a SIP system bin dir (/bin, /usr/bin):
        //     dyld strips DYLD_INSERT_LIBRARIES on exec, so it ran un-audited; OR
        //   - the canonical path is an EXTERNAL SYSTEM TOOL — resolved outside
        //     every keep-audited root (provisioned-node bin, shell-shim dir, cwd).
        //     On a non-SIP path (Homebrew git, /usr/local, …) dyld would NOT
        //     strip DYLD, so we must strip it ourselves in rewrite_envp to keep
        //     the tool + its subtree un-shimmed (matches Linux spawn-only).
        let external = is_external_system_tool(canon);
        (prog, is_under_sip_bin_dir(canon) || external, external)
    };

    match rewrite_envp(envp_in, external) {
        Some(mut buf) => {
            set_in_shim(true);
            // result:"ok" emitted BEFORE the real exec — a successful exec
            // replaces the image and never returns, so this is the only chance
            // to record the attempt with the calling pid.  Pass the FULL argv so
            // the macOS record carries the complete command line (Fix E); errno
            // is irrelevant for the optimistic event so pass 0.
            emit_exec(prog, argv0, false, ExecResult::Ok, audit_blind, argv, 0);
            let rewritten = buf.ptrs as *const *const c_char;
            let rc = real_execve_raw(prog, argv, rewritten);
            // Only reached on failure.  Capture errno IMMEDIATELY (before any
            // other libc call can clobber it) so the failed-exec record can carry
            // `exec_errno` (ENOENT/EACCES → `<ENOENT>`/`<EACCES>` spawn_blocked).
            let exec_errno = errno();
            emit_exec(
                prog,
                argv0,
                false,
                ExecResult::Failed,
                audit_blind,
                argv,
                exec_errno,
            );
            free_envbuf(&mut buf);
            set_in_shim(false);
            rc
        }
        None => {
            set_in_shim(true);
            // envp alloc failed: the child never ran, so there is no exec errno.
            emit_exec(prog, argv0, true, ExecResult::Failed, audit_blind, argv, 0);
            set_errno(libc::ENOMEM);
            set_in_shim(false);
            -1
        }
    }
}

// ── posix_spawn child-cwd (chdir) action tracking (macOS) ──────────────────
//
// Adversarial-review HIGH (2026-06).  A `posix_spawn` resolves a RELATIVE program
// path against the CHILD's cwd, which a `posix_spawn_file_actions_add{,f}chdir`
// action (the `_np` 10.15 variant OR the macOS-26 non-`_np` replacement) can move
// away from this (parent) process's cwd BEFORE the exec.  is_external_system_tool
// resolves a relative path against OUR cwd, so when a chdir action is present its
// classification is for the WRONG directory and the child could resolve `./tool`
// to a SIP binary (or symlink to one) that runs un-audited with NO marker.  There
// is no public API to read a file_actions object back, so we OBSERVE chdir actions
// by interposing the functions that add them and recording the file_actions HANDLE.
// dispatch_spawn_macos then marks a relative-program spawn audit_blind IFF its
// file_actions handle is tracked here — firing ONLY on a real child-cwd change,
// never on the stdio-only file_actions libuv attaches to every spawn.
//
// KEY = the file_actions HANDLE address (the `posix_spawn_file_actions_t *` the
// caller passes — `actions` in the add/init/destroy wrappers, `file_actions` in
// dispatch), NOT the heap object behind it.  The object pointer (`*actions`) is
// NOT stable: appending later actions (`addopen`/`addclose`/`adddup2`) REALLOCs
// it, so the value captured at `addchdir` time differs from `*file_actions` at
// spawn time (adversarial-review: `after_chdir != final`).  The handle address is
// stable for the file_actions' lifetime.  Lifecycle: insert on add{,f}chdir{,_np};
// CLEAR on `posix_spawn_file_actions_init` (a fresh init re-uses a stack/heap
// handle address from a prior, possibly-undestroyed file_actions); remove on
// `..._destroy`.  Residual: a caller that copies the opaque handle VALUE into a
// second variable and spawns with `&copy` presents a different handle address —
// not tracked (the type is opaque; copying it is unsupported and `destroy` would
// double-free).  See docs/divergence.md.
//
// Fixed capacity + spinlock (no_std, no heap growth).  Live count is ~0-2 in a real
// install (one file_actions built, spawned, destroyed), so 64 is far more than
// enough; OVERFLOW fails CLOSED — once the table is full, `contains` returns true
// for every handle so a chdir can never be silently dropped.  All ops are cold
// (file_actions construction is not a hot path).
#[cfg(target_os = "macos")]
const CHDIR_FA_CAP: usize = 64;
#[cfg(target_os = "macos")]
static CHDIR_FA_SLOTS: [AtomicUsize; CHDIR_FA_CAP] =
    [const { AtomicUsize::new(0) }; CHDIR_FA_CAP];
#[cfg(target_os = "macos")]
static CHDIR_FA_LOCK: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
static CHDIR_FA_OVERFLOW: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
unsafe fn chdir_fa_lock() {
    while CHDIR_FA_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "macos")]
unsafe fn chdir_fa_unlock() {
    CHDIR_FA_LOCK.store(false, Ordering::Release);
}

// Record that the file_actions handle `key` carries a child-cwd change.  Idempotent.
#[cfg(target_os = "macos")]
unsafe fn chdir_fa_insert(key: usize) {
    if key == 0 {
        return;
    }
    chdir_fa_lock();
    let mut free: isize = -1;
    let mut present = false;
    let mut i = 0;
    while i < CHDIR_FA_CAP {
        let v = CHDIR_FA_SLOTS[i].load(Ordering::Relaxed);
        if v == key {
            present = true;
            break;
        }
        if v == 0 && free < 0 {
            free = i as isize;
        }
        i += 1;
    }
    if !present {
        if free >= 0 {
            CHDIR_FA_SLOTS[free as usize].store(key, Ordering::Relaxed);
        } else {
            CHDIR_FA_OVERFLOW.store(true, Ordering::Relaxed);
        }
    }
    chdir_fa_unlock();
}

// Drop handle `key` from the tracking set (on file_actions init/destroy).
#[cfg(target_os = "macos")]
unsafe fn chdir_fa_remove(key: usize) {
    if key == 0 {
        return;
    }
    chdir_fa_lock();
    let mut i = 0;
    while i < CHDIR_FA_CAP {
        if CHDIR_FA_SLOTS[i].load(Ordering::Relaxed) == key {
            CHDIR_FA_SLOTS[i].store(0, Ordering::Relaxed);
        }
        i += 1;
    }
    chdir_fa_unlock();
}

// True if file_actions handle `key` is known to carry a child-cwd change.
// Fails CLOSED on overflow (treat unknown as "has chdir").
#[cfg(target_os = "macos")]
unsafe fn chdir_fa_contains(key: usize) -> bool {
    if key == 0 {
        return false;
    }
    if CHDIR_FA_OVERFLOW.load(Ordering::Relaxed) {
        return true;
    }
    chdir_fa_lock();
    let mut found = false;
    let mut i = 0;
    while i < CHDIR_FA_CAP {
        if CHDIR_FA_SLOTS[i].load(Ordering::Relaxed) == key {
            found = true;
            break;
        }
        i += 1;
    }
    chdir_fa_unlock();
    found
}

// C-side entry point for the macOS-26 non-`_np` add{,f}chdir interposes (see
// src/sj_spawn_chdir_np2.c).  Those symbols are weak-imported in C — they bind on
// macOS 26+ and resolve NULL on older macOS, where their C interpose is an inert
// no-op — so the non-`_np` chdir adds feed the SAME tracking set as the `_np`
// (Rust) ones.  `handle` is the file_actions handle address (`(uintptr_t)fa`).
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sj_note_chdir_handle(handle: usize) {
    chdir_fa_insert(handle);
}

// Force the linker to pull in src/sj_spawn_chdir_np2.c from its static archive:
// that object's only contents are static `__DATA,__interpose` tuples (data, not
// called from anywhere), so without a referenced symbol the archive link semantics
// would drop the whole object — and the non-`_np` interposes with it.  Referencing
// this anchor via a `#[used]` static keeps the relocation, which forces inclusion.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sj_spawn_chdir_np2_anchor();
}
#[cfg(target_os = "macos")]
#[used]
static SJ_SPAWN_CHDIR_NP2_ANCHOR: unsafe extern "C" fn() = sj_spawn_chdir_np2_anchor;

// True when `canon` is a cwd-RELATIVE program path (non-NULL, no leading '/').  A
// relative posix_spawn target is resolved by the kernel against the child's cwd;
// an absolute one is cwd-independent (a chdir action cannot move it).
#[cfg(target_os = "macos")]
unsafe fn is_relative_prog(canon: *const c_char) -> bool {
    !canon.is_null() && *canon as u8 != b'/'
}

#[cfg(target_os = "macos")]
unsafe fn dispatch_spawn_macos(
    spawnp: bool,
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp_in: *const *mut c_char,
) -> c_int {
    let argv0 = if argv.is_null() {
        ptr::null()
    } else {
        *argv as *const c_char
    };

    let mut canon_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let canon = lexical_canon(path, &mut canon_buf);
    let mut redirect_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    // Same canonical-match rule as dispatch_exec_macos.
    let redirected = sip_redirect(canon, &mut redirect_buf);
    let (path, audit_blind, external) = if redirected != canon {
        (redirected, false, false)
    } else {
        // Same external-system-tool classification as dispatch_exec_macos.
        let mut external = is_external_system_tool(canon);
        // posix_spawn-only (adversarial-review HIGH 2026-06): unlike execve, a
        // posix_spawn can carry a `posix_spawn_file_actions_add{,f}chdir{,_np}`
        // action that moves the CHILD's cwd before it resolves a RELATIVE program
        // path, so the cwd is_external_system_tool resolved against (ours) is NOT
        // the cwd the kernel execs from — `./tool` could resolve under the chdir
        // target to a SIP binary / symlink that runs un-audited with NO marker.  We
        // OBSERVE chdir actions by interposing the functions that add them (see
        // CHDIR_FA_SLOTS); when this spawn's file_actions handle is tracked AND the
        // program path is relative, the target is unprovable.  Fires ONLY on
        // relative-prog + a real child-cwd change — never on the stdio-only
        // file_actions libuv attaches to every spawn.  Absolute targets are
        // cwd-independent → unaffected.  See docs/divergence.md.
        let chdir_unprovable =
            is_relative_prog(canon) && chdir_fa_contains(file_actions as usize);
        // CRITICAL (adversarial-review HIGH): when the target is unprovable we must
        // NOT trust `external` either — is_external_system_tool realpath'd the
        // relative path in OUR cwd, the WRONG directory.  A parent-cwd EXTERNAL
        // symlink decoy (`./tool` → /opt/homebrew/...) would set external=true and
        // STRIP DYLD, blinding the PACKAGE-owned binary the child actually execs
        // after the chdir.  Force external=false so DYLD stays for an auditable
        // child; rely solely on audit_blind to surface the unprovable subtree
        // (honest "could not see"), never on env stripping.
        if chdir_unprovable {
            external = false;
        }
        let audit_blind = is_under_sip_bin_dir(canon) || external || chdir_unprovable;
        (path, audit_blind, external)
    };

    match rewrite_envp(envp_in as *const *const c_char, external) {
        Some(mut buf) => {
            set_in_shim(true);
            let rc = real_posix_spawn_raw_macos(
                spawnp,
                pid,
                path,
                file_actions,
                attrp,
                argv,
                buf.ptrs as *const *mut c_char,
            );
            // posix_spawn takes `char *const argv[]` (*const *mut c_char); the
            // emit helpers want `*const *const c_char`.  The cast is read-only
            // (the serializer never mutates argv), so it is sound.
            let argv_const = argv as *const *const c_char;
            if rc == 0 {
                // posix_spawn writes the child pid; the strace-equivalent
                // attribution wants the CHILD pid (matches Linux dispatch).
                let child_pid = if !pid.is_null() { *pid } else { libc::getpid() };
                emit_exec_for_pid(
                    path,
                    argv0,
                    false,
                    child_pid,
                    ExecResult::Ok,
                    audit_blind,
                    argv_const,
                    0,
                );
            } else {
                // posix_spawn RETURNS the errno (it does NOT set errno + return
                // -1), so `rc` IS the exec errno (e.g. ENOENT).
                emit_exec(
                    path,
                    argv0,
                    false,
                    ExecResult::Failed,
                    audit_blind,
                    argv_const,
                    rc,
                );
            }
            free_envbuf(&mut buf);
            set_in_shim(false);
            rc
        }
        None => {
            set_in_shim(true);
            // envp alloc failed: the child never ran, so there is no exec errno.
            emit_exec(
                path,
                argv0,
                true,
                ExecResult::Failed,
                audit_blind,
                argv as *const *const c_char,
                0,
            );
            set_in_shim(false);
            libc::ENOMEM
        }
    }
}

// True when `prog` lies under a SIP-protected system bin dir (/bin/ or
// /usr/bin/).  The macOS dispatchers call this on the LEXICALLY-CANONICALIZED
// path (see lexical_canon) together with "did sip_redirect rewrite the path?"
// to compute audit_blind: a canonical path under these dirs that sip_redirect
// left UNCHANGED ran the real arm64e image (DYLD stripped) and is therefore
// audit-blind.  Uses the SAME prefixes as sip_redirect_target so the two stay
// in lockstep.  Correct even when sip_redirect bails on buffer overflow for a
// covered applet: the real SIP binary genuinely ran, so flagging it blind is
// accurate (more so than re-walking the applet set).
#[cfg(target_os = "macos")]
unsafe fn is_under_sip_bin_dir(prog: *const c_char) -> bool {
    if prog.is_null() {
        return false;
    }
    const SYS_BIN_DIRS: &[&[u8]] = &[b"/usr/bin/", b"/bin/"];
    for prefix in SYS_BIN_DIRS {
        let mut i = 0usize;
        let mut matched = true;
        while i < prefix.len() {
            if *prog.add(i) as u8 != prefix[i] {
                matched = false;
                break;
            }
            i += 1;
        }
        if matched {
            return true;
        }
    }
    false
}

// True when NUL-terminated `canon` is the directory `root` (a byte slice, no
// trailing slash) OR lies strictly under it — i.e. `canon` starts with `root`
// AND the next byte is '/' or the NUL terminator.  The boundary check prevents
// `/a/binutils` from matching root `/a/bin` (a plain byte-prefix would).  Zero
// alloc.  An empty `root` never matches (avoids matching everything).
//
// LENGTH-AWARE (adversarial-review #2): `cstr_len` first, then bail when `canon`
// is shorter than `root`.  This makes the bound self-evident: lexical_canon can
// return the ORIGINAL caller pointer (on overflow/depth), and although a valid
// C string would terminate before any over-read, the explicit length guard
// removes all doubt and cannot read past the NUL even if `canon` were crafted.
#[cfg(target_os = "macos")]
unsafe fn canon_under_dir(canon: *const c_char, root: &[u8]) -> bool {
    if canon.is_null() || root.is_empty() {
        return false;
    }
    let canon_len = cstr_len(canon);
    if canon_len < root.len() {
        return false;
    }
    let canon_slice = core::slice::from_raw_parts(canon as *const u8, canon_len);
    if &canon_slice[..root.len()] != root {
        return false;
    }
    // `canon` matched all of `root`; require a path boundary at root.len()
    // (either the NUL terminator — exact dir match — or a '/' — strictly under).
    canon_len == root.len() || canon_slice[root.len()] == b'/'
}

// MACOS only: capture THIS process's executable directory into
// CANON_SELF_EXEC_DIR.  Reads the path via _NSGetExecutablePath, lexically
// canonicalizes it (collapse `.` / `..` / `//`, same residual class as
// lexical_canon — symlinks not resolved), then trims the trailing `/<basename>`
// so the stored value is the BIN DIRECTORY (not the node binary itself).  On any
// failure (oversized path, no '/' segment) the buf stays empty and
// is_external_system_tool's empty-anchor fail-safe keeps everything audited.
// ctor-only writer; no concurrent readers (INIT_DONE is still false).
//
// `#[allow(deprecated)]`: libc deprecates `_NSGetExecutablePath` in favor of the
// `mach2` crate, but it is a stable libSystem symbol and adding a dependency to
// this `#![no_std]` cdylib for one call is not worth it.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn capture_self_exec_dir() {
    // _NSGetExecutablePath wants a buffer + an in/out u32 size; PATH_MAX+1 is
    // ample for the provisioned-node path.
    let mut raw = [0u8; (libc::PATH_MAX as usize) + 1];
    let mut size = raw.len() as u32;
    if libc::_NSGetExecutablePath(raw.as_mut_ptr() as *mut c_char, &mut size as *mut u32) != 0 {
        return; // buffer too small (returns required size in `size`) → give up
    }
    // NUL-terminate defensively (the API NUL-terminates, but be explicit).
    let raw_len = cstr_len(raw.as_ptr() as *const c_char);
    if raw_len == 0 || raw_len >= raw.len() {
        return;
    }
    // Lexically canonicalize into a second buffer.
    let mut canon_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let canon = lexical_canon(raw.as_ptr() as *const c_char, &mut canon_buf);
    let canon_len = cstr_len(canon);
    if canon_len == 0 || *canon as u8 != b'/' {
        return; // relative / unresolved → no usable anchor
    }
    // Trim the trailing `/<basename>` to get the directory.  Walk back to the
    // last '/'; the dir is canon[..last_slash] (kept WITHOUT a trailing slash to
    // match the other keep roots' format).
    let mut last_slash: Option<usize> = None;
    let mut i = 0usize;
    while i < canon_len {
        if *canon.add(i) as u8 == b'/' {
            last_slash = Some(i);
        }
        i += 1;
    }
    let dir_len = match last_slash {
        // The leading '/' is at index 0; a dir of just "/" (slash at 0) means the
        // executable sits at root — keep "/" (len 1) so canon_under_dir works.
        Some(0) => 1,
        Some(n) => n,
        None => return, // no '/' at all → not absolute (shouldn't happen here)
    };
    if dir_len >= CANON_BUF_LEN {
        return; // would not fit the CanonBuf → leave empty (fail-safe keeps audit)
    }
    let dst = &mut *CANON_SELF_EXEC_DIR.bytes.get();
    core::ptr::copy_nonoverlapping(canon as *const u8, dst.as_mut_ptr(), dir_len);
    dst[dir_len] = 0;
    CANON_SELF_EXEC_DIR.len.store(dir_len, Ordering::Release);
}

// MACOS only: capture THIS process's working directory ONCE at shim_init into
// CANON_INIT_CWD.  Reads it via getcwd, lexically canonicalizes it (collapse
// `.` / `..` / `//`, same residual class as lexical_canon — symlinks not
// resolved), and stores the directory itself (no trailing-basename trim: a cwd
// IS a directory).  For the root audited process this is the install root,
// captured before any lifecycle `chdir`.  On any failure (getcwd error,
// oversized path, relative result) the buf stays empty and the keep-root check
// in is_external_system_tool ignores it (empty root never matches).  ctor-only
// writer; no concurrent readers (INIT_DONE is still false).
//
// See CANON_INIT_CWD for WHY the immutable snapshot is needed alongside the live
// getcwd() read (the chdir false-strip finding).
#[cfg(target_os = "macos")]
unsafe fn capture_init_cwd() {
    let mut raw = [0u8; (libc::PATH_MAX as usize) + 1];
    if libc::getcwd(raw.as_mut_ptr() as *mut c_char, raw.len()).is_null() {
        return; // getcwd failed (e.g. cwd unlinked) → leave empty, fall back
    }
    let raw_len = cstr_len(raw.as_ptr() as *const c_char);
    if raw_len == 0 || raw_len >= raw.len() {
        return;
    }
    // Lexically canonicalize into a second buffer (match the other anchors'
    // canonical form so the private-aware comparison reconciles).
    let mut canon_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let canon = lexical_canon(raw.as_ptr() as *const c_char, &mut canon_buf);
    let canon_len = cstr_len(canon);
    if canon_len == 0 || *canon as u8 != b'/' {
        return; // relative / unresolved → no usable anchor
    }
    if canon_len >= CANON_BUF_LEN {
        return; // would not fit the CanonBuf → leave empty (fail-safe ignores it)
    }
    let dst = &mut *CANON_INIT_CWD.bytes.get();
    core::ptr::copy_nonoverlapping(canon as *const u8, dst.as_mut_ptr(), canon_len);
    dst[canon_len] = 0;
    CANON_INIT_CWD.len.store(canon_len, Ordering::Release);
}

// MACOS only: capture the install/repo root from the SCRIPT_JAIL_WORK_DIR env
// var ONCE at shim_init into CANON_WORK_DIR.  Reads the var via real_getenv_raw
// (trusted parent environ at ctor — before any user code runs), lexically
// canonicalizes it (collapse `.` / `..` / `//`, same residual class as
// lexical_canon — symlinks not resolved) so the stored value reconciles with the
// lexically-canon'd spawn targets is_external_system_tool compares against, and
// stores the directory itself (a work_dir IS a directory, no trailing-basename
// trim).  On any failure (var absent/empty, oversized path, relative result) the
// buf stays empty and the keep-root check in is_external_system_tool ignores it
// (empty root never matches) — fall back to the other anchors, NEVER "keep all".
// ctor-only writer; no concurrent readers (INIT_DONE is still false).
//
// See CANON_WORK_DIR for WHY this whole-install-tree anchor is needed alongside
// the per-package init-cwd snapshot (the top-level node_modules/.bin false-strip
// after a lifecycle chdir).
#[cfg(target_os = "macos")]
unsafe fn capture_work_dir() {
    let val = real_getenv_raw(b"SCRIPT_JAIL_WORK_DIR\0".as_ptr() as *const c_char);
    if cstr_is_empty(val) {
        return; // var absent/empty → leave empty, fall back to the other anchors
    }
    // Lexically canonicalize into a scratch buffer (match the other anchors'
    // canonical form so the private-aware comparison reconciles).
    let mut canon_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let canon = lexical_canon(val, &mut canon_buf);
    let canon_len = cstr_len(canon);
    if canon_len == 0 || *canon as u8 != b'/' {
        return; // relative / unresolved → no usable anchor
    }
    if canon_len >= CANON_BUF_LEN {
        return; // would not fit the CanonBuf → leave empty (fail-safe ignores it)
    }
    let dst = &mut *CANON_WORK_DIR.bytes.get();
    core::ptr::copy_nonoverlapping(canon as *const u8, dst.as_mut_ptr(), canon_len);
    dst[canon_len] = 0;
    CANON_WORK_DIR.len.store(canon_len, Ordering::Release);
}

// Strip a leading `/private` SEGMENT from an absolute path, returning the
// remaining slice.  On macOS `/var`, `/tmp`, and `/etc` are symlinks into
// `/private`, and `getcwd()` / F_GETPATH resolve through them while a lexically-
// canonicalized argv path does NOT — so the same directory can surface as
// `/private/tmp/x` from one source and `/tmp/x` from another.  Mirrors
// normalize.ts's darwin `/private` strip (segment-bounded: `/private/var`
// strips, `/privatevar` does not).  Returns the input unchanged when there is
// no `/private` segment.  Pure slice math, no alloc.
#[cfg(target_os = "macos")]
fn strip_private_prefix(path: &[u8]) -> &[u8] {
    const P: &[u8] = b"/private";
    if path.len() >= P.len() && &path[..P.len()] == P {
        // Require a segment boundary after "/private": next byte is '/' or end.
        if path.len() == P.len() {
            return &path[P.len()..]; // exactly "/private" → ""
        }
        if path[P.len()] == b'/' {
            return &path[P.len()..]; // "/private/..." → "/..."
        }
    }
    path
}

// `/private`-aware variant of canon_under_dir: matches if `canon` lies under
// `root` after BOTH have had an optional leading `/private` segment stripped, so
// a `/private/tmp/...` root and a `/tmp/...` target (or vice versa) reconcile.
// `canon` is NUL-terminated; we read its byte length to slice it.
#[cfg(target_os = "macos")]
unsafe fn canon_under_dir_private_aware(canon: *const c_char, root: &[u8]) -> bool {
    if root.is_empty() {
        return false;
    }
    // Fast path: exact (private-inclusive) match first.
    if canon_under_dir(canon, root) {
        return true;
    }
    let canon_len = cstr_len(canon);
    if canon_len == 0 {
        return false;
    }
    let canon_slice = core::slice::from_raw_parts(canon as *const u8, canon_len);
    let cs = strip_private_prefix(canon_slice);
    let rs = strip_private_prefix(root);
    // Compare cs under rs with a directory boundary, mirroring canon_under_dir.
    if rs.is_empty() || cs.len() < rs.len() {
        return false;
    }
    if &cs[..rs.len()] != rs {
        return false;
    }
    cs.len() == rs.len() || cs[rs.len()] == b'/'
}

// Return the parent directory of `dir` (a byte slice, no trailing slash) by
// trimming the trailing `/<basename>`.  `/a/b/c` → `/a/b`; `/a` → `/` (root);
// `/` or empty → empty (no parent).  Used to derive the provisioned-toolchain
// root from the sticky shell-shim dir.  Pure slice math.
#[cfg(target_os = "macos")]
fn parent_dir(dir: &[u8]) -> &[u8] {
    if dir.is_empty() {
        return dir;
    }
    // Find the last '/'.
    let mut last = None;
    let mut i = 0usize;
    while i < dir.len() {
        if dir[i] == b'/' {
            last = Some(i);
        }
        i += 1;
    }
    match last {
        Some(0) => &dir[..1], // parent is root "/"
        Some(n) => &dir[..n],
        None => &[], // no '/' (not absolute) → no usable parent
    }
}

// MACOS Option B classifier (2026-06).  True when the LEXICALLY-CANONICALIZED
// spawn target `canon` is an EXTERNAL SYSTEM TOOL — an ABSOLUTE path that lies
// OUTSIDE every "keep-audited" root.  When true, the macOS dispatchers strip the
// dyld injection + sticky vars from the child env (rewrite_envp's `external`
// path) and mark the exec record audit_blind, so the tool + its whole subtree
// run un-shimmed and emit nothing — matching the Linux source-of-truth, which
// records only the spawn line for such tools (git, sed, awk, perl, python3,
// under /usr, /opt/homebrew, /bin, /sbin, /Library, /System, /nix, …).
//
// KEEP-AUDITED roots (return false → keep DYLD, audit the child):
//   1. PROVISION ROOT (PRIMARY) = parent of CANON_SHELL_SHIM_DIR.  The shell-shim
//      dir is a STICKY var re-injected into every audited child, so its parent —
//      the provisioned-toolchain root `.../node-<ver>-<arch>-vp<v>/` — is the SAME
//      value in the orchestrator node, the substituted bash, AND every
//      node-spawned-node.  That root holds BOTH `vp-home/.../bin/node` (the node
//      + corepack/pnpm/npm/npx shims) AND `shell-shim/` (bash/coreutils).  This
//      MUST be process-independent: when bash (self-exec = shell-shim) spawns the
//      node, a per-process self-exec keep would FALSE-STRIP node and blind the
//      whole lifecycle subtree — proven against vuejs/core locally.
//   2. CANON_SELF_EXEC_DIR (secondary) — this process's own exec dir; covers the
//      orchestrator before shell-shim is known and same-dir sibling re-spawns.
//   3. CANON_SHELL_SHIM_DIR — the bundled bash/coreutils substitutes (also under
//      the provision root; kept explicit).
//   4. getcwd() (LIVE) — the CURRENT install cwd: node_modules/.bin, the in-repo
//      .pnpm-store, and any native helper a package ships and runs from its own
//      subdir.  Linux audits these (strace + preload), so macOS must too.
//   5. CANON_INIT_CWD (IMMUTABLE) — the cwd snapshotted at ctor (the install
//      root, before any lifecycle chdir).  UNION'd with #4 to close the
//      adversarial-review chdir false-strip: lifecycle code can `chdir('/tmp')`
//      then exec an ABSOLUTE package-owned helper still under the ORIGINAL
//      install root, which #4 (cwd now /tmp) would miss and FALSE-STRIP.  The
//      union only EXPANDS the keep set, so it can never newly false-strip
//      anything #1–#4 keep — it only ADDS protection.  See CANON_INIT_CWD.
//
// SYMLINK RESOLUTION (adversarial-review HIGH, 2026-06): the keep-root checks run
// against the REAL realpath of `canon`, not its surface bytes.  `canon` is only
// LEXICALLY canonicalized (lexical_canon collapses `.`/`..`/`//` but does NOT
// resolve symlinks), so a package could plant an in-tree symlink
// `node_modules/.bin/git` → `/opt/homebrew/bin/git` (or `/usr/bin/git`): the
// lexical path lies under a keep root (#4 live-cwd / #5 init-cwd / #6 work_dir),
// so a lexical-only classify would KEEP it — running a NON-SIP external tool
// (Homebrew git) SHIMMED and leaking its GIT_* reads (the exact leak audit_blind
// exists to stop), or a SIP target un-instrumented with NO `<AUDIT_BLIND>` marker.
// Resolving symlinks first re-anchors the classify on the tool's TRUE location, so
// such a symlink classifies EXTERNAL (audit_blind).
//
// WHY THIS DOES NOT FALSE-STRIP LEGIT PACKAGE / TOOLCHAIN CODE (verified):
//   * pnpm's content-addressed store is pinned IN-TREE at `${work_dir}/.pnpm-store`
//     (phase-install-macos.ts: `--store-dir=${cwd}/.pnpm-store`, cwd == work_dir ==
//     SCRIPT_JAIL_WORK_DIR == keep root #6).  So pnpm's `node_modules/<pkg>` →
//     `<work>/.pnpm-store/...` symlinks RESOLVE to a path still UNDER work_dir →
//     stay KEPT.
//   * The provisioned toolchain path has NO non-`/private` symlink component (every
//     dir is real, node + bundled bash/coreutils are copied files), so the realpath
//     of an audited toolchain binary differs from its lexical canon ONLY by a
//     leading `/tmp`→`/private/tmp` bridge — which the `/private`-aware keep-root
//     checks below already reconcile.  No legit kept path's realpath escapes the
//     keep roots.
//
// RELATIVE PATHS are resolved too (adversarial review).  `real_realpath_raw`
// runs FIRST — it absolutizes a relative path against THIS process's live cwd AND
// resolves symlinks — so a RELATIVE symlink (`./node_modules/.bin/git` →
// `/opt/homebrew/bin/git`, or a relative/empty PATH-search hit) cannot skip the
// resolved-target classify by being non-absolute.  For an execve the live cwd IS
// the cwd the kernel resolves against (execve does not change cwd), so this is
// exact.  For a posix_spawn it is NOT necessarily exact: an `add{,f}chdir_np` file
// action can move the CHILD's cwd, so a relative target is handled conservatively
// by the SPAWN dispatcher (it marks the spawn audit_blind — DYLD kept — when the
// file_actions object is tracked as carrying a chdir; see CHDIR_FA_SLOTS), NOT by
// stripping in this classifier.  ERR TOWARD KEEP only when realpath FAILS: a NULL result
// (ENOENT / ELOOP / oversized / not-yet-existing target) on a relative input
// leaves the path non-absolute → return false (keep) — a leaked system-tool read
// is a parity nuisance whereas blinding package behavior is a security +
// byte-divergence regression.  (A bare-name spawn is also PATH-resolved by
// resolve_path_search before this runs, so the residual is narrow — a broken/
// nonexistent relative symlink only.)  On an ABSOLUTE input a realpath failure
// falls back to the lexical `canon`, preserving the prior (lexical) behavior —
// NEVER strip when resolution is unsure.
//
// EMPTY-ANCHOR FAIL-SAFE: if BOTH CANON_SHELL_SHIM_DIR and CANON_SELF_EXEC_DIR are
// empty (no toolchain anchor established at init), return false unconditionally —
// never strip DYLD when we cannot tell which tree is ours.
#[cfg(target_os = "macos")]
unsafe fn is_external_system_tool(canon_in: *const c_char) -> bool {
    if canon_in.is_null() {
        return false;
    }
    // Resolve via REAL realpath FIRST (before the absolute-path gate): this BOTH
    // absolutizes a relative path (against the live cwd — the same cwd the kernel
    // uses for a relative exec) AND resolves symlinks, so neither a relative
    // symlink nor a relative PATH-search hit can skip the resolved-target classify
    // (see RELATIVE PATHS above).  No malloc (non-NULL resolved arg; PATH_MAX+1
    // buffer, the size macOS realpath requires).  The caller (dispatch_{exec,
    // spawn}_macos) holds set_in_shim(true), so this real call does not re-enter
    // the audit, and realpath is not interposed regardless.
    let mut resolved_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let resolved = real_realpath_raw(canon_in, resolved_buf.as_mut_ptr() as *mut c_char);
    // realpath guarantees a NUL-terminated absolute result on success; defend
    // anyway (a non-'/' or empty result is treated as a failure → keep lexical).
    let canon: *const c_char = if !resolved.is_null() && *resolved as u8 == b'/' {
        resolved as *const c_char
    } else {
        canon_in
    };
    // Classify ABSOLUTE paths only.  realpath yields one on success; if it FAILED
    // and the lexical input was relative, `canon` is still non-absolute → ERR
    // TOWARD KEEP (see above).
    if *canon as u8 != b'/' {
        return false;
    }
    // PRIMARY anchor: the bundled shell/coreutils shim dir, which is a STICKY var
    // (re-injected into every audited child) so it is the SAME value in the
    // orchestrator node, the substituted bash, AND every node-spawned-node.  Its
    // PARENT is the provisioned-toolchain root
    //   <cacheDir>/script-jail-node-mac/node-<ver>-<arch>-vp<v>/
    // which contains BOTH `shell-shim/` AND `vp-home/.../bin/node`.  Anchoring on
    // this (not the PER-PROCESS self-exec dir) is essential: when the substituted
    // BASH spawns the provisioned node, bash's self-exec dir is `shell-shim/`, so
    // a self-exec-only keep would FALSE-STRIP the node and blind the whole
    // lifecycle subtree.  See the provision-root keep below.
    let shell_shim_dir = canon_bytes(&CANON_SHELL_SHIM_DIR);
    let self_exec_dir = canon_bytes(&CANON_SELF_EXEC_DIR);
    if shell_shim_dir.is_empty() && self_exec_dir.is_empty() {
        // Fail-safe: no audited-toolchain anchor at all → keep everything.
        return false;
    }
    // All keep-root checks are `/private`-aware (see canon_under_dir_private_aware):
    // getcwd()/F_GETPATH resolve the /tmp,/var,/etc → /private symlinks while a
    // lexical argv path does not, so a raw byte match would FALSE-STRIP a package
    // binary whose cwd surfaces as /private/... — a security + parity regression.
    // ERR TOWARD KEEP.
    //
    // Keep root #1 (PRIMARY): the provisioned-toolchain root = parent of the
    // shell-shim dir.  Covers the provisioned node, corepack/pnpm/npm shims, AND
    // the bundled bash/coreutils — process-independent (sticky), so it holds no
    // matter which audited process is doing the spawning.
    let provision_root = parent_dir(shell_shim_dir);
    if canon_under_dir_private_aware(canon, provision_root) {
        return false;
    }
    // Keep root #2: this process's own executable dir (secondary anchor).  Covers
    // the orchestrator node BEFORE shell-shim is known, and any audited binary
    // that re-spawns a sibling in its own dir.
    if canon_under_dir_private_aware(canon, self_exec_dir) {
        return false;
    }
    // Keep root #3: the bundled shell/coreutils shim dir itself (also covered by
    // the provision root, kept explicit for clarity + for the unusual case where
    // the shim dir is NOT under a single provision parent).
    if canon_under_dir_private_aware(canon, shell_shim_dir) {
        return false;
    }
    // Keep root #4: the install cwd (node_modules/.bin, .pnpm-store, package
    // native helpers).  getcwd() is read live: the install runner does not
    // chdir away mid-run, and reading it here (in_shim is asserted by the
    // caller) does not re-enter the audit.
    let mut cwd = [0u8; (libc::PATH_MAX as usize) + 1];
    if !libc::getcwd(cwd.as_mut_ptr() as *mut c_char, cwd.len()).is_null() {
        let cwd_len = cstr_len(cwd.as_ptr() as *const c_char);
        if cwd_len > 0 && canon_under_dir_private_aware(canon, &cwd[..cwd_len]) {
            return false;
        }
    }
    // Keep root #5: the IMMUTABLE init cwd (the install root, snapshotted at ctor
    // before any lifecycle chdir; see CANON_INIT_CWD).  Closes the adversarial-
    // review chdir false-strip (high, 2026-06): lifecycle code can `chdir('/tmp')`
    // and THEN exec an ABSOLUTE package-owned helper still living under the
    // ORIGINAL install root.  The live getcwd() check above would miss it (cwd is
    // now /tmp) and the provision/self-exec/shell-shim roots don't cover a
    // package's own dir, so the helper would be FALSE-STRIPPED and run un-shimmed
    // — a security + byte-divergence regression vs Linux, which still audits it.
    // Matching against the immutable init cwd keeps any helper under the install
    // root audited REGARDLESS of a runtime chdir.  This is a UNION with the live
    // check (it only EXPANDS the keep set), and the empty-root guard in
    // canon_under_dir_private_aware means a failed capture simply doesn't match.
    let init_cwd = canon_bytes(&CANON_INIT_CWD);
    if canon_under_dir_private_aware(canon, init_cwd) {
        return false;
    }
    // Keep root #6: the install/repo root (SCRIPT_JAIL_WORK_DIR = the agent's
    // config.work_dir; see CANON_WORK_DIR).  This is the WHOLE install tree, so
    // it covers BOTH node_modules/<pkg> AND its SIBLING node_modules/.bin/<helper>.
    // Closes the top-level-.bin false-strip: after a lifecycle script `chdir`s
    // into node_modules/<pkg>, a top-level node_modules/.bin/<helper> is a SIBLING
    // of that per-package init-cwd anchor (not UNDER it), so roots #4/#5 miss it —
    // the helper would be FALSE-STRIPPED of DYLD and run un-shimmed, blinding it
    // (and its subtree) and producing a spurious parity GATE FAILURE vs Linux,
    // which still audits it.  This is a UNION with the other roots (it only
    // EXPANDS the keep set, never newly false-strips), and does NOT over-broaden:
    // a real system tool (/usr/bin/git, /opt/homebrew/bin/git) lives OUTSIDE
    // work_dir → still external → the git-leak audit-blind fix stays intact.  The
    // empty-root guard in canon_under_dir_private_aware means an absent var simply
    // doesn't match (NOT "keep all").
    let work_dir = canon_bytes(&CANON_WORK_DIR);
    if canon_under_dir_private_aware(canon, work_dir) {
        return false;
    }
    // Absolute, and under NONE of the keep roots → external system tool.
    true
}

// Lexically canonicalize an ABSOLUTE path — collapse `.`, `..`, and `//` — into
// `out` as a NUL-terminated string, returning the `out` pointer.  Returns `prog`
// unchanged for a relative or NULL path (no cwd is available in the hot path) or
// on overflow / pathological depth.  Used ONLY to CLASSIFY a path for SIP
// redirect + audit_blind (the exec still runs the caller's original path), so a
// crafted `/tmp/../usr/bin/find` is matched on its real target rather than its
// surface bytes — closing the trivial `..` evasion of both the redirect and the
// audit_blind marker.  Purely lexical: it does NOT resolve symlinks (a symlink
// INTO a SIP dir, or a deep relative `..` path, remains a documented bare-backend
// residual — see docs/divergence.md).  Zero-alloc, no syscalls — safe to call
// before set_in_shim without polluting the audit or re-entering the shim.
#[cfg(target_os = "macos")]
unsafe fn lexical_canon(prog: *const c_char, out: &mut [u8]) -> *const c_char {
    if prog.is_null() || *prog as u8 != b'/' {
        return prog; // relative / NULL → leave as-is (classification residual)
    }
    // Record the write-cursor start of each emitted segment so `..` can pop one.
    let mut seg_starts = [0usize; 64];
    let mut nseg = 0usize;
    let mut w = 0usize;
    let mut i = 0usize;
    loop {
        // Skip a run of '/'.
        while *prog.add(i) as u8 == b'/' {
            i += 1;
        }
        if *prog.add(i) as u8 == 0 {
            break;
        }
        // Measure the next segment [seg, seg+len).
        let seg = i;
        let mut len = 0usize;
        loop {
            let ch = *prog.add(seg + len) as u8;
            if ch == 0 || ch == b'/' {
                break;
            }
            len += 1;
        }
        i = seg + len;
        if len == 1 && *prog.add(seg) as u8 == b'.' {
            // "." → drop.
        } else if len == 2 && *prog.add(seg) as u8 == b'.' && *prog.add(seg + 1) as u8 == b'.' {
            // ".." → pop one segment (clamp at root).
            if nseg > 0 {
                nseg -= 1;
                w = seg_starts[nseg];
            }
        } else {
            // Normal segment → append "/<seg>".
            if nseg >= seg_starts.len() || w + 1 + len + 1 > out.len() {
                return prog; // too deep / would overflow → leave un-canonicalized
            }
            seg_starts[nseg] = w;
            nseg += 1;
            out[w] = b'/';
            w += 1;
            core::ptr::copy_nonoverlapping(
                prog.add(seg) as *const u8,
                out.as_mut_ptr().add(w),
                len,
            );
            w += len;
        }
    }
    if w == 0 {
        // Everything collapsed to root.
        if out.len() < 2 {
            return prog;
        }
        out[0] = b'/';
        w = 1;
    }
    out[w] = 0;
    out.as_ptr() as *const c_char
}

// SIP redirect (macOS).  System binaries under /bin and /usr/bin run with
// DYLD_INSERT_LIBRARIES stripped (SIP), so the shim would never load into a
// child shell or coreutil.  If SCRIPT_JAIL_SHELL_SHIM_DIR is set and `prog` is
// one of the covered system binaries, rewrite the path to one of TWO bundled,
// ad-hoc-signed multi-call binaries that DO honor DYLD:
//   * `<dir>/bash`      — bash built from source; covers both /bin/sh (sh-compat
//     mode via argv[0]) and /bin/bash.
//   * `<dir>/coreutils` — the uutils single multi-call binary; covers every
//     uutils applet under /bin or /usr/bin.
// argv[0] is preserved by the caller so each binary dispatches to the right
// shell mode / applet via basename(argv[0]).  Returns `prog` unchanged when no
// redirect applies (non-system binary, dir unset, or the formatted path would
// overflow `out`).  Callers pass the LEXICALLY-CANONICALIZED path so a crafted
// `/tmp/../bin/sh` still redirects.
//
// `out` must outlive the returned pointer (the caller stack-allocates it for
// the duration of the exec/spawn).  Zero-alloc (no heap) per the macOS hot-path
// discipline.
#[cfg(target_os = "macos")]
unsafe fn sip_redirect(prog: *const c_char, out: &mut [u8]) -> *const c_char {
    if prog.is_null() {
        return prog;
    }
    let dir = canon_bytes(&CANON_SHELL_SHIM_DIR);
    if dir.is_empty() {
        return prog;
    }
    // Only redirect known system-binary paths.  We match the FULL path against
    // /bin/sh, /bin/bash, and /{usr/,}bin/<coreutil>.  The returned target is a
    // FIXED multi-call binary name — "bash" for shells, "coreutils" for any
    // uutils applet — NOT the original applet basename (argv[0] still carries
    // that, see below).
    let target = match sip_redirect_target(prog) {
        Some(t) => t,
        None => return prog,
    };
    // Format `<dir>/<target>\0` into `out` (e.g. <dir>/bash or <dir>/coreutils).
    // Bail (no redirect) on overflow.
    let need = dir.len() + 1 + target.len() + 1;
    if need > out.len() {
        return prog;
    }
    let mut pos = 0usize;
    out[..dir.len()].copy_from_slice(dir);
    pos += dir.len();
    out[pos] = b'/';
    pos += 1;
    out[pos..pos + target.len()].copy_from_slice(target);
    pos += target.len();
    out[pos] = 0;
    // argv[0] is intentionally left UNCHANGED by the caller: uutils and bash are
    // multi-call binaries that dispatch on basename(argv[0]), so the original
    // program path must reach the child for it to behave as the right applet.
    out.as_ptr() as *const c_char
}

// The shells whose system copies SIP de-privileges.  Both /bin/sh and /bin/bash
// redirect to the SAME bundled binary: a bash built from source (plain arm64,
// ad-hoc signed) materialized as `bash` inside SCRIPT_JAIL_SHELL_SHIM_DIR.  It
// honors sh-compat mode when invoked as `sh` (basename(argv[0]) is preserved),
// so one binary covers both shells.
#[cfg(target_os = "macos")]
static SIP_SHELLS: &[(&[u8], &[u8])] = &[(b"/bin/sh", b"bash"), (b"/bin/bash", b"bash")];

// The coreutils applets whose system copies SIP de-privileges.  Every entry
// redirects to the SINGLE bundled `coreutils` multi-call binary (uutils 0.4.0),
// which dispatches on basename(argv[0]).  This is the AUTHORITATIVE uutils 0.4.0
// applet set (108 names, starting with the test bracket "[").  Names NOT shipped
// by uutils (sed/awk/grep/find/xargs/which/cmp, …) are deliberately absent: a
// redirect for them would resolve to an "unknown applet" inside coreutils.
#[cfg(target_os = "macos")]
static SIP_COREUTILS: &[&[u8]] = &[
    b"[",
    b"arch",
    b"b2sum",
    b"base32",
    b"base64",
    b"basename",
    b"basenc",
    b"cat",
    b"chgrp",
    b"chmod",
    b"chown",
    b"chroot",
    b"cksum",
    b"comm",
    b"cp",
    b"csplit",
    b"cut",
    b"date",
    b"dd",
    b"df",
    b"dir",
    b"dircolors",
    b"dirname",
    b"du",
    b"echo",
    b"env",
    b"expand",
    b"expr",
    b"factor",
    b"false",
    b"fmt",
    b"fold",
    b"groups",
    b"hashsum",
    b"head",
    b"hostid",
    b"hostname",
    b"id",
    b"install",
    b"join",
    b"kill",
    b"link",
    b"ln",
    b"logname",
    b"ls",
    b"md5sum",
    b"mkdir",
    b"mkfifo",
    b"mknod",
    b"mktemp",
    b"more",
    b"mv",
    b"nice",
    b"nl",
    b"nohup",
    b"nproc",
    b"numfmt",
    b"od",
    b"paste",
    b"pathchk",
    b"pinky",
    b"pr",
    b"printenv",
    b"printf",
    b"ptx",
    b"pwd",
    b"readlink",
    b"realpath",
    b"rm",
    b"rmdir",
    b"seq",
    b"sha1sum",
    b"sha224sum",
    b"sha256sum",
    b"sha384sum",
    b"sha512sum",
    b"shred",
    b"shuf",
    b"sleep",
    b"sort",
    b"split",
    b"stat",
    b"stdbuf",
    b"stty",
    b"sum",
    b"sync",
    b"tac",
    b"tail",
    b"tee",
    b"test",
    b"timeout",
    b"touch",
    b"tr",
    b"true",
    b"truncate",
    b"tsort",
    b"tty",
    b"uname",
    b"unexpand",
    b"uniq",
    b"unlink",
    b"uptime",
    b"users",
    b"vdir",
    b"wc",
    b"who",
    b"whoami",
    b"yes",
];

// Returns the FIXED bundled-binary name to redirect to if `prog` is a covered
// system binary, else None.  Two multi-call binaries cover everything:
//   * shells  — /bin/sh and /bin/bash both map to "bash" (bash-from-source).
//   * coreutils — any uutils applet under /bin or /usr/bin maps to "coreutils"
//     (the single uutils multi-call binary), NOT the applet's own basename.
// The applet identity is carried by argv[0] (left unchanged by the caller), so
// the multi-call binary dispatches to the right applet on basename(argv[0]).
// Both /usr/bin and /bin are SIP-protected and coreutils live under both on
// macOS (e.g. /bin/cat, /bin/echo, /bin/test as well as /usr/bin/...).
#[cfg(target_os = "macos")]
unsafe fn sip_redirect_target(prog: *const c_char) -> Option<&'static [u8]> {
    for (full, target) in SIP_SHELLS {
        if cstr_eq_bytes(prog, full) {
            return Some(target);
        }
    }
    // Try each covered system bin dir prefix; on a match, compare the tail
    // against the uutils applet set.  Any hit redirects to the single
    // "coreutils" multi-call binary (the applet name lives in argv[0]).
    const SYS_BIN_DIRS: &[&[u8]] = &[b"/usr/bin/", b"/bin/"];
    for prefix in SYS_BIN_DIRS {
        let mut i = 0usize;
        let mut matched = true;
        while i < prefix.len() {
            if *prog.add(i) as u8 != prefix[i] {
                matched = false;
                break;
            }
            i += 1;
        }
        if !matched {
            continue;
        }
        let tail = prog.add(prefix.len());
        for name in SIP_COREUTILS {
            if cstr_eq_bytes(tail, name) {
                return Some(b"coreutils");
            }
        }
    }
    None
}

// ── MACOS exec interpose wrappers ──────────────────────────────────────────
//
// execve / execv / execvp interpose the public libc symbols.  execvp resolves
// PATH IN-PROCESS to an absolute path, then dispatches through the SAME
// dispatch_exec_macos(Execve) so the "every exec goes through rewrite_envp"
// invariant holds.

#[cfg(target_os = "macos")]
unsafe extern "C" fn execve_interpose(
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if in_shim() {
        return real_execve_raw(prog, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_execve_raw(prog, argv, envp);
    }
    set_in_shim(true);
    let rc = dispatch_exec_macos(prog, argv, envp);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_EXECVE,
    execve_interpose,
    libc::execve,
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int
);

#[cfg(target_os = "macos")]
unsafe extern "C" fn execv_interpose(prog: *const c_char, argv: *const *const c_char) -> c_int {
    if in_shim() {
        return libc::execv(prog, argv);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return libc::execv(prog, argv);
    }
    set_in_shim(true);
    // execv runs with the current environ; route through dispatch_exec_macos so
    // the snapshot is rewritten and the audit chain survives into the child.
    let rc = dispatch_exec_macos(prog, argv, environ_ptr());
    set_in_shim(false);
    rc
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_EXECV,
    execv_interpose,
    libc::execv,
    unsafe extern "C" fn(*const c_char, *const *const c_char) -> c_int
);

#[cfg(target_os = "macos")]
unsafe extern "C" fn execvp_interpose(file: *const c_char, argv: *const *const c_char) -> c_int {
    if in_shim() {
        return libc::execvp(file, argv);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return libc::execvp(file, argv);
    }
    set_in_shim(true);
    // Resolve PATH in-process to an absolute prog, then dispatch through the
    // Execve path so rewrite_envp + sip_redirect + emit all apply.  On
    // resolution failure forward to the real execvp (which sets ENOENT/EACCES).
    let mut resolved = [0u8; (libc::PATH_MAX as usize) + 1];
    let prog = resolve_path_search(file, &mut resolved);
    let rc = match prog {
        Some(p) => dispatch_exec_macos(p, argv, environ_ptr()),
        None => {
            set_in_shim(false);
            return libc::execvp(file, argv);
        }
    };
    set_in_shim(false);
    rc
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_EXECVP,
    execvp_interpose,
    libc::execvp,
    unsafe extern "C" fn(*const c_char, *const *const c_char) -> c_int
);

// In-process PATH search for execvp (macOS).  If `file` already contains a '/'
// it is returned verbatim (no PATH search, per execvp semantics).  Otherwise
// each PATH entry is joined with `file` and probed with access(X_OK); the first
// executable match is written NUL-terminated into `out` and returned.  Returns
// None when no candidate is found (caller forwards to the real execvp).
// Zero-alloc; reads PATH via real_getenv_raw (we hold in_shim).
#[cfg(target_os = "macos")]
unsafe fn resolve_path_search(file: *const c_char, out: &mut [u8]) -> Option<*const c_char> {
    if file.is_null() {
        return None;
    }
    // Contains a slash → no PATH search.
    let mut i = 0usize;
    let flen = loop {
        let c = *file.add(i) as u8;
        if c == 0 {
            break i;
        }
        if c == b'/' {
            return Some(file);
        }
        i += 1;
        if i > out.len() {
            return None;
        }
    };
    if flen == 0 {
        return None;
    }
    let path_var = real_getenv_raw(b"PATH\0".as_ptr() as *const c_char);
    // POSIX: when PATH is unset, use a default.  Keep it minimal.
    // NUL-terminated: the scanner below treats this as a C string and stops at
    // the trailing 0.  Without the \0 the final "/bin" segment is not terminated
    // and the scan reads PAST the literal into adjacent memory (adversarial-review
    // HIGH 2026-06).  Only used when PATH is unset.
    let default_path = b"/usr/bin:/bin\0";
    let mut p = if path_var.is_null() {
        default_path.as_ptr()
    } else {
        path_var as *const u8
    };
    loop {
        // Read one PATH entry (up to ':' or NUL).
        let seg_start = p;
        let mut seg_len = 0usize;
        loop {
            let c = *seg_start.add(seg_len);
            if c == 0 || c == b':' {
                break;
            }
            seg_len += 1;
        }
        // Build `<seg>/<file>\0`.  Empty segment means "current dir" (".").
        let dir_len = if seg_len == 0 { 1 } else { seg_len };
        let need = dir_len + 1 + flen + 1;
        if need <= out.len() {
            let mut pos = if seg_len == 0 {
                out[0] = b'.';
                1
            } else {
                core::ptr::copy_nonoverlapping(seg_start, out.as_mut_ptr(), seg_len);
                seg_len
            };
            out[pos] = b'/';
            pos += 1;
            core::ptr::copy_nonoverlapping(file as *const u8, out.as_mut_ptr().add(pos), flen);
            pos += flen;
            out[pos] = 0;
            if libc::access(out.as_ptr() as *const c_char, libc::X_OK) == 0 {
                return Some(out.as_ptr() as *const c_char);
            }
        }
        // Advance past this segment.
        let term = *seg_start.add(seg_len);
        if term == 0 {
            return None;
        }
        p = seg_start.add(seg_len + 1);
    }
}

// PATH resolution for the posix_spawnp-under-tracked-chdir case (macOS).  The
// real spawnp runs its PATH search AFTER the child cwd change, so any PATH entry
// whose meaning depends on the cwd — an empty entry (POSIX "." == cwd) or a
// relative dir — could resolve to a DIFFERENT binary than the parent sees and is
// unprovable.  But an ABSOLUTE PATH dir is cwd-independent: a chdir cannot move
// it.  So (adversarial-review HIGH 2026-06, refining the earlier blanket skip):
//   * resolve through ABSOLUTE dirs; a match reached BEFORE any cwd-dependent
//     segment is the binary the kernel will run regardless of the chdir → return
//     it, so the caller dispatches it normally (sip_redirect to the bundled shell
//     and the external/SIP marking all apply, exactly as without a chdir — this
//     is what keeps a cwd-bearing `sh`/`node` spawn PROVABLE instead of falsely
//     `<AUDIT_BLIND>`);
//   * at the FIRST cwd-dependent segment (empty or relative), STOP and return
//     None: the kernel searches it post-chdir, BEFORE any later absolute segment,
//     and we cannot predict the result → the caller keeps the bare name so
//     dispatch_spawn_macos marks it audit_blind via the relative-program rule;
//   * PATH exhausted with no absolute match → None (same as resolve_path_search).
// A path already containing '/' is returned verbatim; a cwd-relative such path
// (`./tool`) is then caught by the is_relative_prog chdir_unprovable rule.
#[cfg(target_os = "macos")]
unsafe fn resolve_path_search_chdir_safe(
    file: *const c_char,
    out: &mut [u8],
) -> Option<*const c_char> {
    if file.is_null() {
        return None;
    }
    // Contains a slash → no PATH search (verbatim), like resolve_path_search.
    let mut i = 0usize;
    let flen = loop {
        let c = *file.add(i) as u8;
        if c == 0 {
            break i;
        }
        if c == b'/' {
            return Some(file);
        }
        i += 1;
        if i > out.len() {
            return None;
        }
    };
    if flen == 0 {
        return None;
    }
    let path_var = real_getenv_raw(b"PATH\0".as_ptr() as *const c_char);
    // NUL-terminated: the scanner below treats this as a C string and stops at
    // the trailing 0.  Without the \0 the final "/bin" segment is not terminated
    // and the scan reads PAST the literal into adjacent memory (adversarial-review
    // HIGH 2026-06).  Only used when PATH is unset.
    let default_path = b"/usr/bin:/bin\0";
    let mut p = if path_var.is_null() {
        default_path.as_ptr()
    } else {
        path_var as *const u8
    };
    loop {
        let seg_start = p;
        let mut seg_len = 0usize;
        loop {
            let c = *seg_start.add(seg_len);
            if c == 0 || c == b':' {
                break;
            }
            seg_len += 1;
        }
        // A cwd-DEPENDENT segment — empty ("." == cwd) or relative (no leading
        // '/') — is searched by the real spawnp AFTER the child chdir, and BEFORE
        // any later absolute segment.  We cannot prove its result, so stop here
        // and report unprovable (None → caller keeps the bare name).
        if seg_len == 0 || *seg_start != b'/' {
            return None;
        }
        // Absolute segment: cwd-independent → safe to probe.
        let need = seg_len + 1 + flen + 1;
        if need <= out.len() {
            core::ptr::copy_nonoverlapping(seg_start, out.as_mut_ptr(), seg_len);
            let mut pos = seg_len;
            out[pos] = b'/';
            pos += 1;
            core::ptr::copy_nonoverlapping(file as *const u8, out.as_mut_ptr().add(pos), flen);
            pos += flen;
            out[pos] = 0;
            if libc::access(out.as_ptr() as *const c_char, libc::X_OK) == 0 {
                return Some(out.as_ptr() as *const c_char);
            }
        }
        let term = *seg_start.add(seg_len);
        if term == 0 {
            return None;
        }
        p = seg_start.add(seg_len + 1);
    }
}

// ── MACOS posix_spawn / posix_spawnp interpose wrappers ────────────────────

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_interpose(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if in_shim() {
        return real_posix_spawn_raw_macos(false, pid, path, file_actions, attrp, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_posix_spawn_raw_macos(false, pid, path, file_actions, attrp, argv, envp);
    }
    set_in_shim(true);
    let rc = dispatch_spawn_macos(false, pid, path, file_actions, attrp, argv, envp);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWN,
    posix_spawn_interpose,
    libc::posix_spawn,
    unsafe extern "C" fn(
        *mut libc::pid_t,
        *const c_char,
        *const libc::posix_spawn_file_actions_t,
        *const libc::posix_spawnattr_t,
        *const *mut c_char,
        *const *mut c_char,
    ) -> c_int
);

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawnp_interpose(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if in_shim() {
        return real_posix_spawn_raw_macos(true, pid, file, file_actions, attrp, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_posix_spawn_raw_macos(true, pid, file, file_actions, attrp, argv, envp);
    }
    set_in_shim(true);
    // Resolve a bare-name spawnp via PATH IN-PROCESS (mirrors execvp_interpose) so
    // sip_redirect + audit_blind see the absolute /bin·/usr/bin target instead of a
    // bare "sh"/"find" that matches nothing — which would otherwise run the real
    // SIP binary un-redirected AND unmarked.  resolve_path_search returns `file`
    // verbatim when it already contains '/', and None when no PATH entry matches
    // (then fall back to `file` and let the real spawnp do its own search).
    //
    // EXCEPTION (adversarial-review HIGH 2026-06): when this spawn's file_actions
    // carries a tracked child-cwd change, the REAL spawnp runs its PATH search
    // AFTER the chdir, so a PATH entry whose meaning depends on the cwd — an empty
    // "." entry or a relative dir — could resolve a DIFFERENT binary than the
    // parent sees.  We must NOT pre-resolve such an entry against the parent cwd.
    // But an ABSOLUTE PATH dir is cwd-independent (a chdir cannot move it), so we
    // STILL resolve through absolute dirs via resolve_path_search_chdir_safe,
    // stopping at the first cwd-dependent segment.  This keeps an ordinary
    // cwd-bearing `sh` / `node` spawn PROVABLE (resolved → sip_redirect to the
    // bundled shell, correct external/SIP marking — NOT a false `<AUDIT_BLIND>`),
    // while a bare name the kernel could only find via a cwd-dependent segment
    // stays bare → dispatch_spawn_macos sees is_relative_prog()==true, marks it
    // audit_blind and keeps DYLD, and the real spawnp does its own post-chdir
    // search.  A path that already contains '/' is returned verbatim either way.
    let mut spawnp_buf = [0u8; (libc::PATH_MAX as usize) + 1];
    let resolved = if chdir_fa_contains(file_actions as usize) {
        resolve_path_search_chdir_safe(file, &mut spawnp_buf).unwrap_or(file)
    } else {
        resolve_path_search(file, &mut spawnp_buf).unwrap_or(file)
    };
    let rc = dispatch_spawn_macos(true, pid, resolved, file_actions, attrp, argv, envp);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWNP,
    posix_spawnp_interpose,
    libc::posix_spawnp,
    unsafe extern "C" fn(
        *mut libc::pid_t,
        *const c_char,
        *const libc::posix_spawn_file_actions_t,
        *const libc::posix_spawnattr_t,
        *const *mut c_char,
        *const *mut c_char,
    ) -> c_int
);

// ── posix_spawn child-cwd (chdir) action interpose wrappers (macOS) ─────────
//
// We interpose the two functions that add a child-cwd change to a file_actions
// object, plus its destructor, to track which objects carry a chdir (see
// CHDIR_FA_SLOTS / dispatch_spawn_macos).  addchdir_np / addfchdir_np are NOT in
// the pinned libc crate (0.2.186), so they are declared here; the real symbols
// resolve from libSystem at link time, and a same-image call inside the
// replacement reaches the REAL function without re-entering the interpose table
// (the "R8" finding — see interpose.rs).  These wrappers emit nothing and never
// re-enter the audit, so they run unconditionally (no in_shim / INIT_DONE gate):
// the tracking set must be complete by the time a later posix_spawn consults it.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const c_char,
    ) -> c_int;
    fn posix_spawn_file_actions_addfchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        filedes: c_int,
    ) -> c_int;
}

// Key on the HANDLE (`actions`), not `*actions`: the object pointer reallocs as
// later actions are appended (see CHDIR_FA_SLOTS), so a value captured here would
// not match `*file_actions` at spawn time.  The handle address is stable.
#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_fa_addchdir_interpose(
    actions: *mut libc::posix_spawn_file_actions_t,
    path: *const c_char,
) -> c_int {
    let rc = posix_spawn_file_actions_addchdir_np(actions, path);
    if rc == 0 {
        chdir_fa_insert(actions as usize);
    }
    rc
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_fa_addfchdir_interpose(
    actions: *mut libc::posix_spawn_file_actions_t,
    filedes: c_int,
) -> c_int {
    let rc = posix_spawn_file_actions_addfchdir_np(actions, filedes);
    if rc == 0 {
        chdir_fa_insert(actions as usize);
    }
    rc
}

// Clear the handle on a fresh init: a stack/heap `posix_spawn_file_actions_t`
// address is routinely re-used by a later, distinct file_actions, and init starts
// it with NO actions — so any chdir tracked for a prior occupant of this address
// must not leak forward.  (destroy also clears; init covers the no-destroy reuse.)
#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_fa_init_interpose(
    actions: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let rc = libc::posix_spawn_file_actions_init(actions);
    chdir_fa_remove(actions as usize);
    rc
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn posix_spawn_fa_destroy_interpose(
    actions: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    chdir_fa_remove(actions as usize);
    libc::posix_spawn_file_actions_destroy(actions)
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWN_FA_ADDCHDIR,
    posix_spawn_fa_addchdir_interpose,
    posix_spawn_file_actions_addchdir_np,
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, *const c_char) -> c_int
);

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWN_FA_ADDFCHDIR,
    posix_spawn_fa_addfchdir_interpose,
    posix_spawn_file_actions_addfchdir_np,
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, c_int) -> c_int
);

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWN_FA_INIT,
    posix_spawn_fa_init_interpose,
    libc::posix_spawn_file_actions_init,
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t) -> c_int
);

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_POSIX_SPAWN_FA_DESTROY,
    posix_spawn_fa_destroy_interpose,
    libc::posix_spawn_file_actions_destroy,
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t) -> c_int
);

// ── env mutator guards ──────────────────────────────────────────────────────
//
// These wrappers intercept setenv/unsetenv/putenv/clearenv to refuse in-process
// tampering with the 9 audit-chain env-var names.  A lifecycle script calling
// e.g. `delete process.env.LD_PRELOAD` compiles to `unsetenv("LD_PRELOAD")`
// and would silently break the shim chain without this guard.
//
// On a refused call the wrapper emits a JSONL `env_tamper` event and returns 0
// (pretend success — many callers discard the return value, and we want to
// silently neuter the tamper rather than signal an error that might abort the
// script).  clearenv is always refused; the other three refuse only when the
// target name is in AUDIT_PROTECTED_NAMES.

/// The 9 env-var names whose values must remain canonical for the audit chain
/// to survive.  Stored as byte-slice literals (no NUL terminator) so we can
/// walk them with cstr_eq_bytes / cstr_starts_with_eq_or_nul.
static AUDIT_PROTECTED_NAMES: &[&[u8]] = &[
    // PRELOAD_VAR per platform: LD_PRELOAD (linux) / DYLD_INSERT_LIBRARIES (macos).
    #[cfg(target_os = "linux")]
    b"LD_PRELOAD",
    #[cfg(target_os = "macos")]
    b"DYLD_INSERT_LIBRARIES",
    b"NODE_OPTIONS",
    b"SCRIPT_JAIL_LOG_FILE",
    b"SCRIPT_JAIL_LOG_FD",
    b"SCRIPT_JAIL_PROTECTED_ENV_NAMES",
    b"SCRIPT_JAIL_SPOOF_PLATFORM",
    b"SCRIPT_JAIL_SPOOF_ARCH",
    b"SCRIPT_JAIL_PRELOAD_PATH",
    b"SCRIPT_JAIL_NODE_OPTIONS",
    // Audit-trust Finding 2 (2026-05-18): LD_AUDIT loads an attacker-supplied
    // DSO BEFORE LD_PRELOAD via the rtld-audit API; LD_LIBRARY_PATH redirects
    // ld.so's library lookup to attacker-controlled directories.  Both are
    // stripped from the child envp by rewrite_envp at exec-time AND refused
    // in-process via the setenv/unsetenv/putenv guards below, so a script
    // cannot restore them between the strip and the next exec.  On macOS dyld
    // the equivalents are DYLD_LIBRARY_PATH / DYLD_FRAMEWORK_PATH.
    #[cfg(target_os = "linux")]
    b"LD_AUDIT",
    #[cfg(target_os = "linux")]
    b"LD_LIBRARY_PATH",
    #[cfg(target_os = "macos")]
    b"DYLD_LIBRARY_PATH",
    #[cfg(target_os = "macos")]
    b"DYLD_FRAMEWORK_PATH",
    // MACOS only: the re-signed shell/coreutils shim dir consulted by
    // sip_redirect must stay canonical — a script restoring/redirecting it
    // could steer execs at an attacker-controlled binary.
    #[cfg(target_os = "macos")]
    b"SCRIPT_JAIL_SHELL_SHIM_DIR",
    // MACOS only: the install/repo root keep-root (is_external_system_tool #6).
    // A script unsetting/redirecting it must be refused + audited as env_tamper —
    // it could otherwise try to FALSE-STRIP DYLD off a package-owned helper.  (The
    // keep-root is sourced from the init-time CanonBuf either way, so the in-env
    // value is non-authoritative; refusing the mutation closes the in-process path
    // and surfaces the tamper.)
    #[cfg(target_os = "macos")]
    b"SCRIPT_JAIL_WORK_DIR",
    #[cfg(target_os = "macos")]
    b"SCRIPT_JAIL_MACOS_AUDIT_OPS",
];

/// Compare a C-string against a Rust byte slice (no NUL in `bytes`).
/// Returns true iff the C-string is exactly `bytes` (same bytes + NUL).
unsafe fn cstr_eq_bytes(c_str: *const c_char, bytes: &[u8]) -> bool {
    if c_str.is_null() {
        return false;
    }
    let mut i = 0usize;
    while i < bytes.len() {
        let c = *c_str.add(i) as u8;
        if c != bytes[i] {
            return false;
        }
        i += 1;
    }
    // Must terminate exactly at this position.
    *c_str.add(i) == 0
}

/// Check whether a C-string name is in the audit-protected set.
unsafe fn is_audit_protected_env_name(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    for &protected in AUDIT_PROTECTED_NAMES {
        if cstr_eq_bytes(name, protected) {
            return true;
        }
    }
    false
}

/// Copy the NAME portion of a `putenv` argument (everything before the first
/// `=`, or the entire string if no `=` is present) into `dst` and
/// NUL-terminate it.  Returns Some(written_excluding_nul) on success, or
/// None if `dst` is too small to hold the name + trailing NUL.
///
/// SECURITY: the audit pipeline emits the original `putenv` argument
/// straight into the lockfile.  When that argument is `NAME=<long
/// attacker-controlled-or-secret value>`, leaking the VALUE component into
/// a committed YAML file is a real attack surface (poison-leakage and
/// data-exfil).  This helper lets the putenv wrapper hand emit_tamper a
/// stack-buffer-backed C string that contains ONLY the name, matching the
/// shape used by setenv/unsetenv events.
unsafe fn putenv_copy_name(string: *const c_char, dst: &mut [u8]) -> Option<usize> {
    if string.is_null() {
        return None;
    }
    // Reserve one byte for the trailing NUL.
    let cap = dst.len().checked_sub(1)?;
    let mut n = 0usize;
    while n < cap {
        let b = *string.add(n) as u8;
        if b == 0 || b == b'=' {
            break;
        }
        dst[n] = b;
        n += 1;
    }
    // If we hit `cap` without seeing '=' or NUL, the name is longer than
    // our buffer can hold — refuse to truncate (a truncated name would be
    // worse than no name at all for downstream interpretation).
    if n == cap {
        let next = *string.add(n) as u8;
        if next != 0 && next != b'=' {
            return None;
        }
    }
    dst[n] = 0;
    Some(n)
}

/// For `putenv("NAME=VALUE")` or `putenv("NAME")` (bare, treated as unsetenv):
/// check whether the NAME portion (up to '=' or NUL) is in the protected set.
///
/// Walks the input bytes matching against each protected name's bytes.  The
/// input must have '=' or NUL exactly at index `name_bytes.len()` to match.
unsafe fn is_putenv_name_protected(string: *mut c_char) -> bool {
    if string.is_null() {
        return false;
    }
    for &name_bytes in AUDIT_PROTECTED_NAMES {
        let len = name_bytes.len();
        // Check that the first `len` bytes match.
        let mut matched = true;
        for i in 0..len {
            if (*string.add(i) as u8) != name_bytes[i] {
                matched = false;
                break;
            }
        }
        if matched {
            // The byte at index `len` must be '=' or NUL for this to be an
            // exact name match (not a prefix of a longer name).
            let next = *string.add(len) as u8;
            if next == b'=' || next == 0 {
                return true;
            }
        }
    }
    false
}

/// Emit a JSONL `env_tamper` audit event.
///
/// `op`   — the operation name as bytes (e.g. b"setenv", b"unsetenv").
/// `name` — Some(ptr) emits `"name":"<escaped>"`.  None omits the field.
unsafe fn emit_tamper(op: &[u8], name: Option<*const c_char>) {
    let log_fd = LOG_FD.load(Ordering::Acquire);
    if log_fd < 0 {
        return;
    }

    let mut ts: libc::timespec = core::mem::zeroed();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    let ns: i64 = (ts.tv_sec as i64) * 1_000_000_000i64 + ts.tv_nsec as i64;
    let pid = libc::getpid();

    let mut buf = [0u8; JSONL_BUF];
    let mut pos = 0usize;

    // {"kind":"env_tamper","op":"
    let prefix = br#"{"kind":"env_tamper","op":""#;
    if prefix.len() > buf.len() {
        return;
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    // op value (trusted ASCII — no escaping needed)
    if pos + op.len() + 1 > buf.len() {
        return;
    }
    buf[pos..pos + op.len()].copy_from_slice(op);
    pos += op.len();
    buf[pos] = b'"';
    pos += 1;

    // optional "name":"<escaped>" field
    if let Some(name_ptr) = name {
        // ,"name":"
        let mid = br#","name":""#;
        if pos + mid.len() > buf.len() {
            return;
        }
        buf[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();

        // Reserve space for closing quote + ,"refused":true,"pid":...,"ts":...}\n
        // Worst case suffix is ~71 B; 80 leaves 9 B of margin.
        const SUFFIX_RESERVE: usize = 80;
        const _: () = assert!(
            SUFFIX_RESERVE >= 71,
            "emit_tamper SUFFIX_RESERVE too small for closing fields",
        );
        let budget_end = JSONL_BUF.saturating_sub(SUFFIX_RESERVE);
        if pos < budget_end {
            let written = json_escape(&mut buf[pos..budget_end], name_ptr);
            pos += written;
        }
        if pos + 1 > buf.len() {
            return;
        }
        buf[pos] = b'"';
        pos += 1;
    }

    // ,"refused":true
    let refused = br#","refused":true"#;
    if pos + refused.len() > buf.len() {
        return;
    }
    buf[pos..pos + refused.len()].copy_from_slice(refused);
    pos += refused.len();

    // ,"pid":<N>
    let mid1 = br#","pid":"#;
    if pos + mid1.len() > buf.len() {
        return;
    }
    buf[pos..pos + mid1.len()].copy_from_slice(mid1);
    pos += mid1.len();
    pos += write_i64(&mut buf[pos..], pid as i64);

    // ,"ts":<N>
    let mid2 = br#","ts":"#;
    if pos + mid2.len() > buf.len() {
        return;
    }
    buf[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    pos += write_i64(&mut buf[pos..], ns);

    // }\n
    if pos + 2 > buf.len() {
        return;
    }
    buf[pos] = b'}';
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;

    write_all(log_fd, &buf[..pos]);
}

// Raw forwarders for the env-mutator real symbols.
//
// LINUX uses the dlsym'd AtomicPtr slots; MACOS calls libc directly (same-image
// reference, non-recursive — R8).  macOS has NO `clearenv` (and no dlsym
// chain), so the clearenv path is Linux-only.

#[cfg(target_os = "linux")]
type SetenvFn = unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int;
#[cfg(target_os = "linux")]
type UnsetenvFn = unsafe extern "C" fn(*const c_char) -> c_int;
#[cfg(target_os = "linux")]
type PutenvFn = unsafe extern "C" fn(*mut c_char) -> c_int;
#[cfg(target_os = "linux")]
type ClearenvFn = unsafe extern "C" fn() -> c_int;

#[cfg(target_os = "linux")]
unsafe fn real_setenv_raw(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    let p = REAL_SETENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: SetenvFn = transmute(p);
    f(name, value, overwrite)
}

#[cfg(target_os = "macos")]
unsafe fn real_setenv_raw(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    libc::setenv(name, value, overwrite)
}

#[cfg(target_os = "linux")]
unsafe fn real_unsetenv_raw(name: *const c_char) -> c_int {
    let p = REAL_UNSETENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: UnsetenvFn = transmute(p);
    f(name)
}

#[cfg(target_os = "macos")]
unsafe fn real_unsetenv_raw(name: *const c_char) -> c_int {
    libc::unsetenv(name)
}

#[cfg(target_os = "linux")]
unsafe fn real_putenv_raw(string: *mut c_char) -> c_int {
    let p = REAL_PUTENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: PutenvFn = transmute(p);
    f(string)
}

#[cfg(target_os = "macos")]
unsafe fn real_putenv_raw(string: *mut c_char) -> c_int {
    libc::putenv(string)
}

#[cfg(target_os = "linux")]
unsafe fn real_clearenv_raw() -> c_int {
    let p = REAL_CLEARENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: ClearenvFn = transmute(p);
    f()
}

// ── setenv(name, value, overwrite) ─────────────────────────────────────────

#[inline]
unsafe fn setenv_impl(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    if in_shim() {
        return real_setenv_raw(name, value, overwrite);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_setenv_raw(name, value, overwrite);
    }
    set_in_shim(true);
    if cstr_eq_bytes(name, NODE_STARTUP_DONE_ENV) {
        emit_node_startup_done();
        set_in_shim(false);
        return 0;
    }
    if is_audit_protected_env_name(name) {
        emit_tamper(b"setenv", Some(name));
        set_in_shim(false);
        return 0;
    }
    let rc = real_setenv_raw(name, value, overwrite);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    setenv_impl(name, value, overwrite)
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn setenv_interpose(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    setenv_impl(name, value, overwrite)
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_SETENV,
    setenv_interpose,
    libc::setenv,
    unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int
);

// ── unsetenv(name) ──────────────────────────────────────────────────────────

#[inline]
unsafe fn unsetenv_impl(name: *const c_char) -> c_int {
    if in_shim() {
        return real_unsetenv_raw(name);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_unsetenv_raw(name);
    }
    set_in_shim(true);
    if is_audit_protected_env_name(name) {
        emit_tamper(b"unsetenv", Some(name));
        set_in_shim(false);
        return 0;
    }
    let rc = real_unsetenv_raw(name);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    unsetenv_impl(name)
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn unsetenv_interpose(name: *const c_char) -> c_int {
    unsetenv_impl(name)
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_UNSETENV,
    unsetenv_interpose,
    libc::unsetenv,
    unsafe extern "C" fn(*const c_char) -> c_int
);

// ── putenv("NAME=VALUE") ────────────────────────────────────────────────────

#[inline]
unsafe fn putenv_impl(string: *mut c_char) -> c_int {
    if in_shim() {
        return real_putenv_raw(string);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_putenv_raw(string);
    }
    set_in_shim(true);
    if putenv_name_eq_bytes(string, NODE_STARTUP_DONE_ENV) {
        emit_node_startup_done();
        set_in_shim(false);
        return 0;
    }
    if is_putenv_name_protected(string) {
        // Copy the bare name into a stack buffer so emit_tamper only ever
        // sees `NAME` — never `NAME=<attacker-controlled value>`.  All
        // protected names in AUDIT_PROTECTED_NAMES are short ASCII
        // identifiers; 256 bytes is comfortably above the worst case.
        let mut name_buf: [u8; 256] = [0; 256];
        let name_ptr = match putenv_copy_name(string as *const c_char, &mut name_buf) {
            Some(_) => name_buf.as_ptr() as *const c_char,
            // Buffer too small (shouldn't happen for AUDIT_PROTECTED_NAMES,
            // but degrade safely by omitting the name field rather than
            // leaking the full string).
            None => ptr::null(),
        };
        if name_ptr.is_null() {
            emit_tamper(b"putenv", None);
        } else {
            emit_tamper(b"putenv", Some(name_ptr));
        }
        set_in_shim(false);
        return 0;
    }
    let rc = real_putenv_raw(string);
    set_in_shim(false);
    rc
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    putenv_impl(string)
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn putenv_interpose(string: *mut c_char) -> c_int {
    putenv_impl(string)
}

#[cfg(target_os = "macos")]
interpose::interpose_entry!(
    SJ_PUTENV,
    putenv_interpose,
    libc::putenv,
    unsafe extern "C" fn(*mut c_char) -> c_int
);

// ── clearenv() ──────────────────────────────────────────────────────────────
// LINUX only — macOS libc has no clearenv.

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clearenv() -> c_int {
    if in_shim() {
        return real_clearenv_raw();
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_clearenv_raw();
    }
    set_in_shim(true);
    // clearenv is always refused — there is no legitimate reason for an npm
    // lifecycle script to wipe the entire env, and re-injection would be brittle.
    emit_tamper(b"clearenv", None);
    set_in_shim(false);
    0
}

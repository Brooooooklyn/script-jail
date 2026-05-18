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

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::transmute;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};

// ── panic handler ──────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { libc::abort() }
}

// ── tunables ───────────────────────────────────────────────────────────────

const MAX_PROTECTED: usize = 64;
const NAME_MAX_LEN: usize = 256;
const JSONL_BUF: usize = 4096;
const TRUNC_MARKER: &[u8] = b"<truncated>";
const CANON_BUF_LEN: usize = 1024;
/// Room for: LD_PRELOAD + NODE_OPTIONS + 7 × SCRIPT_JAIL_* injected entries
/// (must be >= 2 + STICKY_VARS.len()).  Margin keeps small future additions
/// safe.
const MAX_ENVP_GROWTH: usize = 12;
/// Sanity cap on input envp length — rejects hostile or corrupted envps.
const MAX_ENVP_SANITY: usize = 8192;

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

static CANON_PROTECTED_ENV_FILE: CanonBuf = CanonBuf {
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

/// Returns the live byte slice of a CanonBuf (without the NUL terminator).
/// Safe to call after INIT_DONE is observed via Acquire — by then the ctor has
/// finished writing and `len` is stable.
unsafe fn canon_bytes(buf: &CanonBuf) -> &[u8] {
    let len = buf.len.load(Ordering::Acquire);
    let bytes = &*buf.bytes.get();
    &bytes[..len]
}

// ── log fd ─────────────────────────────────────────────────────────────────

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

// ── real symbol pointers (resolved via dlsym at ctor time) ─────────────────

type GetenvFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

static REAL_CLEARENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_EXECV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_EXECVEAT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_EXECVP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_EXECVPE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_FEXECVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_GETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_POSIX_SPAWN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_POSIX_SPAWNP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_PUTENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_SECURE_GETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_SETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_UNSETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

unsafe fn real_getenv_raw(name: *const c_char) -> *mut c_char {
    let p = REAL_GETENV.load(Ordering::Acquire);
    if p.is_null() {
        return ptr::null_mut();
    }
    let f: GetenvFn = transmute(p);
    f(name)
}

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
    if !saw_digit {
        -1
    } else {
        result
    }
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

// Behaviour: reads the file line by line. Lines beginning with '#' and blank
// lines are skipped. Lines longer than NAME_MAX_LEN-1 bytes are discarded
// (matches the C "overlong" drain path for entries that straddle fgets reads;
// the C path additionally truncated names of exactly NAME_MAX_LEN-1..=257
// bytes within a single fgets call — this Rust impl discards them uniformly).
unsafe fn load_protect_list(path: *const c_char) {
    let fd = libc::open(path, libc::O_RDONLY);
    if fd < 0 {
        return;
    }

    let mut chunk = [0u8; 4096];
    let mut line = [0u8; NAME_MAX_LEN];
    let mut line_len: usize = 0;
    let mut overlong = false;
    let mut count: usize = 0;

    fn commit(
        line: &[u8],
        len: usize,
        count: &mut usize,
    ) {
        // Strip trailing CR (LF was already the line terminator).
        let mut len = len;
        while len > 0 && line[len - 1] == b'\r' {
            len -= 1;
        }
        if len == 0 || line[0] == b'#' {
            return;
        }
        if *count < MAX_PROTECTED {
            // SAFETY: ctor-only writer; no concurrent readers (INIT_DONE is
            // false until after this routine returns).
            unsafe {
                let table = &mut *PROTECTED.names.get();
                let dst = &mut table[*count];
                let take = len.min(NAME_MAX_LEN - 1);
                dst[..take].copy_from_slice(&line[..take]);
                dst[take] = 0;
            }
            *count += 1;
        }
    }

    loop {
        let n = loop {
            let r = libc::read(fd, chunk.as_mut_ptr() as *mut c_void, chunk.len());
            if r < 0 && errno() == libc::EINTR {
                continue;
            }
            break r;
        };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        for &byte in &chunk[..n] {
            if byte == b'\n' {
                if overlong {
                    overlong = false;
                    line_len = 0;
                    continue;
                }
                commit(&line, line_len, &mut count);
                line_len = 0;
            } else {
                if overlong {
                    continue;
                }
                if line_len >= NAME_MAX_LEN {
                    overlong = true;
                    line_len = 0;
                    continue;
                }
                line[line_len] = byte;
                line_len += 1;
            }
        }
    }
    // Trailing line without newline at EOF.
    if !overlong && line_len > 0 {
        commit(&line, line_len, &mut count);
    }
    let _ = libc::close(fd);

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
//   envbuf_from / append_path_env / ensure_env: after they return, in_shim()
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
        core::ptr::copy_nonoverlapping(
            envp_in as *const *const c_char,
            ptrs_raw,
            count_in,
        );
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

/// Replace ptrs[idx] with new_entry and push new_entry onto owned[].
/// Caller must have malloc'd new_entry already (via make_entry).
/// Returns false if the owned tracker is full — in that case the slot is
/// NOT updated and the caller is responsible for freeing new_entry, because
/// otherwise free_envbuf would never reach the leaked entry on exec failure.
unsafe fn envbuf_set_at(buf: &mut EnvBuf, idx: usize, new_entry: *mut c_char) -> bool {
    // Owned-tracker capacity is sized as MAX_ENVP_GROWTH + 1, generous against
    // the at-most-MAX_ENVP_GROWTH writes per envbuf. Bail loudly rather than
    // silently leaking on overflow.
    if buf.owned_count >= buf.owned_cap {
        return false;
    }
    *buf.ptrs.add(idx) = new_entry as *const c_char;
    *buf.owned.add(buf.owned_count) = new_entry;
    buf.owned_count += 1;
    true
}

/// Append a new entry to buf.ptrs[], bump count, re-NUL-terminate, push onto owned[].
/// Returns false if either the ptrs cap or the owned tracker would be exceeded.
/// On false return the caller is responsible for freeing new_entry — see envbuf_set_at.
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

/// Remove the entry whose `NAME=` prefix matches `name` from buf.  Returns
/// true if an entry was found and removed.  If the entry was owned (i.e.
/// previously inserted via envbuf_set_at / envbuf_push), it is freed and
/// removed from the owned tracker.  The ptrs[] slot is shifted down to
/// preserve density and the new tail slot is re-NUL-terminated.
///
/// SECURITY: this exists so the sticky-var re-injection loop can delete a
/// caller-supplied entry when the canonical buffer is empty.  Without it, a
/// malicious envp_in entry (e.g. `SCRIPT_JAIL_LOG_FILE=/tmp/evil`) would
/// survive into the child whenever the parent did not snapshot that var at
/// shim_init time.
///
/// Recursion-guard contract: callers MUST hold set_in_shim(true) only for
/// the libc::free call, which this helper wraps internally — matching the
/// pattern used by free_entry / free_envbuf.
unsafe fn envbuf_remove(buf: &mut EnvBuf, name: &[u8]) -> bool {
    let idx = match envbuf_find(buf, name) {
        Some(i) => i,
        None => return false,
    };

    let entry = *buf.ptrs.add(idx);

    // If this entry was owned (we malloc'd it earlier in this same envbuf),
    // free it and compact the owned tracker.  Compare by raw pointer
    // equality — that is the same identity the owned table records.
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
    true
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

/// Whether `append_path_env` writes the new chunk at the front or back of
/// the existing value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Result: `existing + sep + new`.  Idempotency check matches a trailing
    /// `sep + new`.  Use when ordering is semantically left-to-right and
    /// existing entries should win first.  Retained as part of the helper's
    /// contract so future call sites have an obvious knob — current call
    /// sites all prepend.
    #[allow(dead_code)]
    Append,
    /// Result: `new + sep + existing`.  Idempotency check matches a leading
    /// `new + sep`.  Use for vars where ld.so / Node load left-to-right and
    /// our injection must take precedence over caller-supplied entries
    /// (LD_PRELOAD, NODE_OPTIONS).
    Prepend,
}

/// Ensure `name` is set in buf to a value that includes `to_append`,
/// concatenated at the position dictated by `order`.
///
/// - If `to_append` is empty, return true immediately (no-op).
/// - If `name` is absent: add a new `name=to_append` entry.
/// - If `name` is present and already contains `to_append` at the correct
///   end (trailing for Append, leading for Prepend): leave it unchanged.
/// - Otherwise: concatenate per `order`, separated by `separator`.
///
/// Returns false only on malloc failure.
unsafe fn append_path_env(
    buf: &mut EnvBuf,
    name: &[u8],
    to_append: &[u8],
    separator: u8,
    order: Order,
) -> bool {
    if to_append.is_empty() {
        return true;
    }

    match envbuf_find(buf, name) {
        None => {
            // Not present — add a fresh entry.
            let entry = make_entry(name, to_append);
            if entry.is_null() {
                return false;
            }
            if !envbuf_push(buf, entry) {
                free_entry(entry);
                return false;
            }
            true
        }
        Some(idx) => {
            // Present — get a slice of the existing value (after the '=').
            let raw = *buf.ptrs.add(idx);
            // Advance past `name=`.
            let val_ptr = raw.add(name.len() + 1);
            // Compute value length.
            let mut val_len = 0usize;
            while *val_ptr.add(val_len) != 0 {
                val_len += 1;
            }
            let existing = core::slice::from_raw_parts(val_ptr as *const u8, val_len);

            // Idempotency: already exactly to_append.
            if existing == to_append {
                return true;
            }
            // Order-specific idempotency: trailing for Append, leading for
            // Prepend.  In both cases we require the separator immediately
            // adjacent to the to_append slice.
            match order {
                Order::Append => {
                    if val_len >= to_append.len() + 1 {
                        let tail = &existing[val_len - to_append.len() - 1..];
                        if tail[0] == separator && &tail[1..] == to_append {
                            return true;
                        }
                    }
                }
                Order::Prepend => {
                    if val_len >= to_append.len() + 1
                        && &existing[..to_append.len()] == to_append
                        && existing[to_append.len()] == separator
                    {
                        return true;
                    }
                }
            }

            // Build new value.  When existing is non-empty we need a
            // separator between the two halves.
            let sep_len = if val_len > 0 { 1usize } else { 0usize };
            let new_val_len = val_len + sep_len + to_append.len();
            let total = name.len() + 1 + new_val_len + 1;
            set_in_shim(true);
            let raw_buf = libc::malloc(total) as *mut u8;
            set_in_shim(false);
            if raw_buf.is_null() {
                return false;
            }
            let mut off = 0usize;
            core::ptr::copy_nonoverlapping(name.as_ptr(), raw_buf, name.len());
            off += name.len();
            *raw_buf.add(off) = b'=';
            off += 1;
            match order {
                Order::Append => {
                    if val_len > 0 {
                        core::ptr::copy_nonoverlapping(
                            val_ptr as *const u8,
                            raw_buf.add(off),
                            val_len,
                        );
                        off += val_len;
                        *raw_buf.add(off) = separator;
                        off += 1;
                    }
                    core::ptr::copy_nonoverlapping(
                        to_append.as_ptr(),
                        raw_buf.add(off),
                        to_append.len(),
                    );
                    off += to_append.len();
                }
                Order::Prepend => {
                    core::ptr::copy_nonoverlapping(
                        to_append.as_ptr(),
                        raw_buf.add(off),
                        to_append.len(),
                    );
                    off += to_append.len();
                    if val_len > 0 {
                        *raw_buf.add(off) = separator;
                        off += 1;
                        core::ptr::copy_nonoverlapping(
                            val_ptr as *const u8,
                            raw_buf.add(off),
                            val_len,
                        );
                        off += val_len;
                    }
                }
            }
            *raw_buf.add(off) = 0u8;

            if !envbuf_set_at(buf, idx, raw_buf as *mut c_char) {
                free_entry(raw_buf as *mut c_char);
                return false;
            }
            true
        }
    }
}

/// Overwrite `name` in buf with the canonical `value`.
///
/// - If `name` is present: replace the entry at the existing slot with a
///   freshly-malloc'd `name=value` string (the previous entry pointer was
///   either from the caller's envp_in or from a prior owned alloc — in
///   either case we just swap the slot pointer, and the new alloc joins
///   the owned tracker so free_envbuf reclaims it).
/// - If `name` is absent: push a new entry.
///
/// Unlike ensure_env (which preserved the caller's value), this enforces
/// that the audit chain's runtime config (SCRIPT_JAIL_LOG_FILE, log fd,
/// preload path, etc.) cannot be redirected by a malicious envp_in.
///
/// Returns false only on malloc failure.
unsafe fn overwrite_env(buf: &mut EnvBuf, name: &[u8], value: &[u8]) -> bool {
    let entry = make_entry(name, value);
    if entry.is_null() {
        return false;
    }
    match envbuf_find(buf, name) {
        Some(idx) => {
            if !envbuf_set_at(buf, idx, entry) {
                free_entry(entry);
                return false;
            }
        }
        None => {
            if !envbuf_push(buf, entry) {
                free_entry(entry);
                return false;
            }
        }
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
    if truncated {
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

// ── constructor ────────────────────────────────────────────────────────────

#[ctor::ctor]
unsafe fn shim_init() {
    // 1. Create the pthread key BEFORE any call that might invoke getenv.
    //    pthread_key_create itself does not call getenv on glibc/musl.
    let mut key: libc::pthread_key_t = 0;
    let key_created =
        libc::pthread_key_create(&mut key as *mut libc::pthread_key_t, None) == 0;
    if key_created {
        IN_SHIM_KEY.store(key as usize, Ordering::Release);
        KEY_READY.store(true, Ordering::Release);
        // 2. Mark this thread as inside the shim so any re-entrant getenv
        //    during init takes the bypass branch.
        set_in_shim(true);
    }

    // 3. Resolve real symbols unconditionally. dlsym may internally call
    //    getenv; if the key was created our wrapper sees in_shim==true and
    //    forwards. If the key was NOT created, INIT_DONE is still false so
    //    the wrapper takes the pre-init bypass path and forwards to
    //    real_getenv_raw (null-safe when REAL_GETENV is still NULL).
    let getenv_ptr = libc::dlsym(libc::RTLD_NEXT, b"getenv\0".as_ptr() as *const c_char);
    REAL_GETENV.store(getenv_ptr as *mut c_void, Ordering::Release);

    let mut sec_ptr =
        libc::dlsym(libc::RTLD_NEXT, b"secure_getenv\0".as_ptr() as *const c_char);
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

    // 5. Load protect-list.
    let list_path =
        real_getenv_raw(b"SCRIPT_JAIL_PROTECTED_ENV_FILE\0".as_ptr() as *const c_char);
    if !cstr_is_empty(list_path) {
        load_protect_list(list_path);
    }

    // 6. Capture canonical sticky env-var values for exec wrappers (Task 4/5).
    //    Must happen after the protect-list is loaded and before INIT_DONE is
    //    set, so exec wrappers can read them safely via Acquire on INIT_DONE.
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
        &CANON_PROTECTED_ENV_FILE,
        b"SCRIPT_JAIL_PROTECTED_ENV_FILE\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_SPOOF_PLATFORM,
        b"SCRIPT_JAIL_SPOOF_PLATFORM\0".as_ptr() as *const c_char,
    );
    capture_canon(
        &CANON_SPOOF_ARCH,
        b"SCRIPT_JAIL_SPOOF_ARCH\0".as_ptr() as *const c_char,
    );

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

#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    if in_shim() {
        return real_getenv_raw(name);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_getenv_raw(name);
    }
    set_in_shim(true);
    let hidden = is_protected(name);
    emit(name, hidden);
    let val = if hidden {
        ptr::null_mut()
    } else {
        real_getenv_raw(name)
    };
    set_in_shim(false);
    val
}

#[no_mangle]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    if in_shim() {
        return real_secure_getenv_raw(name);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_secure_getenv_raw(name);
    }
    set_in_shim(true);
    let hidden = is_protected(name);
    emit(name, hidden);
    let val = if hidden {
        ptr::null_mut()
    } else {
        real_secure_getenv_raw(name)
    };
    set_in_shim(false);
    val
}

// __secure_getenv is a deprecated glibc alias for secure_getenv.
#[no_mangle]
pub unsafe extern "C" fn __secure_getenv(name: *const c_char) -> *mut c_char {
    secure_getenv(name)
}

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

type ExecveFn =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int;
type PosixSpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const libc::posix_spawn_file_actions_t,
    *const libc::posix_spawnattr_t,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;

unsafe fn real_execve_raw(
    prog: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let p = REAL_EXECVE.load(Ordering::Acquire);
    if p.is_null() {
        // dlsym failed — return -1 with errno=ENOSYS, the safest forwarding
        // semantics for a missing exec implementation.
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = libc::ENOSYS;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = libc::ENOSYS;
        }
        return -1;
    }
    let f: ExecveFn = transmute(p);
    f(prog, argv, envp)
}

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

// ── environ access ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
extern "C" {
    static environ: *const *const c_char;
}

#[cfg(target_os = "linux")]
unsafe fn environ_ptr() -> *const *const c_char {
    environ
}

#[cfg(not(target_os = "linux"))]
unsafe fn environ_ptr() -> *const *const c_char {
    ptr::null()
}

// ── audit emit for exec events ─────────────────────────────────────────────

unsafe fn emit_exec(
    prog: *const c_char,
    argv0: *const c_char,
    envp_alloc_failed: bool,
) {
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

    // Reserve trailing budget for the suffix: closing argv0 quote (or "null"),
    // ","pid":<20>,"ts":<20>,"envp_alloc_failed":<5>}\n.
    const SUFFIX_RESERVE: usize = 96;

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
    if pos + bool_str.len() + 2 > buf.len() {
        return;
    }
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
        name: b"SCRIPT_JAIL_PROTECTED_ENV_FILE",
        canon: &CANON_PROTECTED_ENV_FILE,
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
unsafe fn rewrite_envp(envp_in: *const *const c_char) -> Option<EnvBuf> {
    // Read canon values BEFORE envbuf_from — those helpers do not hold the
    // recursion guard across calls.  canon_bytes is a memory read.
    let preload = canon_bytes(&CANON_PRELOAD_PATH);
    let node_opts = canon_bytes(&CANON_NODE_OPTIONS);

    let mut buf = envbuf_from(envp_in)?;

    // Re-inject LD_PRELOAD and NODE_OPTIONS.  Both ld.so and Node consume
    // these left-to-right with first-symbol/first-require winning, so a
    // caller-supplied prefix (e.g. an attacker `LD_PRELOAD=/tmp/evil.so:...`)
    // would shadow our wrappers if we appended.  Prepend instead so our
    // entries take precedence.  append_path_env is a no-op for empty
    // to_append, so if a canon buf is empty this contributes nothing.
    if !append_path_env(&mut buf, b"LD_PRELOAD", preload, b':', Order::Prepend) {
        free_envbuf(&mut buf);
        return None;
    }
    if !append_path_env(&mut buf, b"NODE_OPTIONS", node_opts, b' ', Order::Prepend) {
        free_envbuf(&mut buf);
        return None;
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

enum RealExecForward {
    Execve,    // real_execve(prog, argv, envp)
    Execvpe,   // real_execvpe(prog, argv, envp)
    Execveat { // real_execveat(dirfd, prog, argv, envp, flags)
        dirfd: c_int,
        flags: c_int,
    },
    Fexecve { // real_fexecve(fd, argv, envp); prog is unused
        fd: c_int,
    },
}

type ExecvFn = unsafe extern "C" fn(*const c_char, *const *const c_char) -> c_int;
type ExecveatFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    *const *const c_char,
    *const *const c_char,
    c_int,
) -> c_int;
type FexecveFn =
    unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;

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
                let rc = libc::syscall(
                    libc::SYS_execveat,
                    *dirfd,
                    prog,
                    argv,
                    envp,
                    *flags,
                ) as c_int;
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

unsafe fn dispatch_exec(
    kind: RealExecForward,
    prog: *const c_char,
    argv: *const *const c_char,
    envp_in: *const *const c_char,
) -> c_int {
    let argv0 = if argv.is_null() {
        ptr::null()
    } else {
        *argv
    };

    match rewrite_envp(envp_in) {
        Some(mut buf) => {
            // Re-assert the recursion guard: rewrite_envp's helpers cleared
            // it on each malloc, so we are now `in_shim==false`.
            set_in_shim(true);
            emit_exec(prog, argv0, false);
            let rewritten = buf.ptrs as *const *const c_char;
            let rc = forward_to_real(&kind, prog, argv, rewritten);
            // real_* only returns on failure.
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
            set_in_shim(true);
            emit_exec(prog, argv0, true);
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

    match rewrite_envp(envp_in as *const *const c_char) {
        Some(mut buf) => {
            set_in_shim(true);
            emit_exec(path, argv0, false);
            let rc = real_posix_spawn_raw(
                real_slot,
                pid,
                path,
                file_actions,
                attrp,
                argv,
                buf.ptrs as *const *mut c_char,
            );
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
            set_in_shim(true);
            emit_exec(path, argv0, true);
            set_in_shim(false);
            libc::ENOMEM
        }
    }
}

// ── execve(prog, argv, envp) ───────────────────────────────────────────────

#[no_mangle]
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

#[no_mangle]
pub unsafe extern "C" fn execv(
    prog: *const c_char,
    argv: *const *const c_char,
) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn execvp(
    file: *const c_char,
    argv: *const *const c_char,
) -> c_int {
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

#[no_mangle]
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

#[no_mangle]
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

#[no_mangle]
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

#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if in_shim() {
        return real_posix_spawn_raw(&REAL_POSIX_SPAWN, pid, path, file_actions, attrp, argv, envp);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_posix_spawn_raw(&REAL_POSIX_SPAWN, pid, path, file_actions, attrp, argv, envp);
    }
    set_in_shim(true);
    let rc = dispatch_spawn(&REAL_POSIX_SPAWN, pid, path, file_actions, attrp, argv, envp);
    set_in_shim(false);
    rc
}

// ── posix_spawnp(pid, file, file_actions, attrp, argv, envp) ───────────────

#[no_mangle]
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
    let rc = dispatch_spawn(&REAL_POSIX_SPAWNP, pid, file, file_actions, attrp, argv, envp);
    set_in_shim(false);
    rc
}

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
    b"LD_PRELOAD",
    b"NODE_OPTIONS",
    b"SCRIPT_JAIL_LOG_FILE",
    b"SCRIPT_JAIL_LOG_FD",
    b"SCRIPT_JAIL_PROTECTED_ENV_FILE",
    b"SCRIPT_JAIL_SPOOF_PLATFORM",
    b"SCRIPT_JAIL_SPOOF_ARCH",
    b"SCRIPT_JAIL_PRELOAD_PATH",
    b"SCRIPT_JAIL_NODE_OPTIONS",
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

// Raw forwarders for the 4 env-mutator real symbols.

type SetenvFn = unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int;
type UnsetenvFn = unsafe extern "C" fn(*const c_char) -> c_int;
type PutenvFn = unsafe extern "C" fn(*mut c_char) -> c_int;
type ClearenvFn = unsafe extern "C" fn() -> c_int;

unsafe fn real_setenv_raw(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    let p = REAL_SETENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: SetenvFn = transmute(p);
    f(name, value, overwrite)
}

unsafe fn real_unsetenv_raw(name: *const c_char) -> c_int {
    let p = REAL_UNSETENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: UnsetenvFn = transmute(p);
    f(name)
}

unsafe fn real_putenv_raw(string: *mut c_char) -> c_int {
    let p = REAL_PUTENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: PutenvFn = transmute(p);
    f(string)
}

unsafe fn real_clearenv_raw() -> c_int {
    let p = REAL_CLEARENV.load(Ordering::Acquire);
    if p.is_null() {
        return 0;
    }
    let f: ClearenvFn = transmute(p);
    f()
}

// ── setenv(name, value, overwrite) ─────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    if in_shim() {
        return real_setenv_raw(name, value, overwrite);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_setenv_raw(name, value, overwrite);
    }
    set_in_shim(true);
    if is_audit_protected_env_name(name) {
        emit_tamper(b"setenv", Some(name));
        set_in_shim(false);
        return 0;
    }
    let rc = real_setenv_raw(name, value, overwrite);
    set_in_shim(false);
    rc
}

// ── unsetenv(name) ──────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
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

// ── putenv("NAME=VALUE") ────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    if in_shim() {
        return real_putenv_raw(string);
    }
    if !INIT_DONE.load(Ordering::Acquire) {
        return real_putenv_raw(string);
    }
    set_in_shim(true);
    if is_putenv_name_protected(string) {
        emit_tamper(b"putenv", Some(string as *const c_char));
        set_in_shim(false);
        return 0;
    }
    let rc = real_putenv_raw(string);
    set_in_shim(false);
    rc
}

// ── clearenv() ──────────────────────────────────────────────────────────────

#[no_mangle]
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

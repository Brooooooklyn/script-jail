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
/// Room for: LD_PRELOAD + NODE_OPTIONS + 6 × SCRIPT_JAIL_* injected entries.
const MAX_ENVP_GROWTH: usize = 8;
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
static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
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

/// Ensure `name` is set in buf to a value that contains `to_append`.
///
/// - If `to_append` is empty, return true immediately (no-op).
/// - If `name` is absent: add a new `name=to_append` entry.
/// - If `name` is present but already ends with `to_append` (accounting for
///   the separator): leave it unchanged (idempotent).
/// - Otherwise: concatenate `existing + separator + to_append`.
///
/// Returns false only on malloc failure.
unsafe fn append_path_env(
    buf: &mut EnvBuf,
    name: &[u8],
    to_append: &[u8],
    separator: u8,
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

            // Idempotency: already exactly to_append, or ends with sep+to_append.
            if existing == to_append {
                return true;
            }
            if val_len >= to_append.len() + 1 {
                let tail = &existing[val_len - to_append.len() - 1..];
                if tail[0] == separator && &tail[1..] == to_append {
                    return true;
                }
            }

            // Build new value: existing + separator + to_append.
            // But only add separator if existing is non-empty.
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
            if val_len > 0 {
                core::ptr::copy_nonoverlapping(val_ptr as *const u8, raw_buf.add(off), val_len);
                off += val_len;
                *raw_buf.add(off) = separator;
                off += 1;
            }
            core::ptr::copy_nonoverlapping(to_append.as_ptr(), raw_buf.add(off), to_append.len());
            off += to_append.len();
            *raw_buf.add(off) = 0u8;

            if !envbuf_set_at(buf, idx, raw_buf as *mut c_char) {
                free_entry(raw_buf as *mut c_char);
                return false;
            }
            true
        }
    }
}

/// Ensure `name` is set in buf.  If already present, leave it unchanged.
/// If absent, add `name=value`.  Returns false only on malloc failure.
unsafe fn ensure_env(buf: &mut EnvBuf, name: &[u8], value: &[u8]) -> bool {
    if envbuf_find(buf, name).is_some() {
        return true; // preserve caller's value, do not overwrite.
    }
    let entry = make_entry(name, value);
    if entry.is_null() {
        return false;
    }
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

// script-jail — macOS file-op interpose hooks.
//
// Linux gets file reads/writes from strace.  macOS has no strace and no /proc,
// so the shim must observe them itself.  This module interposes the libc file
// entry points and emits the EXACT `FsReadEvent`/`FsWriteEvent` shapes from
// src/lock/schema.ts (via crate::emit_fs):
//
//   read side : open/openat (O_RDONLY), creat is write-only, fopen/freopen ("r")
//   write side: open/openat (O_WRONLY|O_RDWR|O_CREAT), creat, fopen/freopen
//               ("w"/"a"), plus unlink/unlinkat/rename/renameat/mkdir/mkdirat.
//
// Hooks resolve the path to ABSOLUTE in-process (F_GETPATH for a dirfd, getcwd
// for AT_FDCWD) and carry errno (ENOENT/EACCES only) on failure so
// protected-paths.ts's ENOENT-drop and the macOS noise filter behave like the
// strace path.  All hooks are zero-allocation (raw stack buffers) per the macOS
// hot-path discipline.
//
// `open`/`openat` are variadic and need a C bridge on Apple arm64: Darwin's
// arm64 variadic ABI does not pass the trailing `mode` where a fixed-arity Rust
// replacement expects it.  The C bridge reads mode with `va_arg` and then calls
// the fixed-ABI Rust implementation below.
#![cfg(target_os = "macos")]

use core::ffi::{c_char, c_int, c_uint};

use libc::{FILE, mode_t};

use crate::interpose::{interpose_entry, interpose_entry_raw};
use crate::{
    FsErrno, FsKind, INIT_DONE, abs_path_into, classify_fs_errno, emit_fs, errno, in_shim,
    macos_audit_ops_enabled, set_errno,
};

use core::sync::atomic::Ordering;

const PATH_BUF: usize = (libc::PATH_MAX as usize) + 1;

unsafe extern "C" {
    fn script_jail_open_variadic();
    fn script_jail_openat_variadic();
}

/// Classify open()/openat() flags into read vs write.  Matches fspy
/// convert.rs: O_WRONLY → write, O_RDWR → write (mutates), else read.
#[inline]
fn open_kind(flags: c_int) -> FsKind {
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY | libc::O_RDWR => FsKind::Write,
        _ => {
            // O_CREAT/O_TRUNC without an explicit write mode still mutate the
            // file's existence/contents; treat as write.
            if flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
                FsKind::Write
            } else {
                FsKind::Read
            }
        }
    }
}

/// Classify an fopen/freopen mode string ("r"/"w"/"a"/"r+"/...).  fspy ModeStr:
/// 'w' or 'a' present → write; 'r' alone → read.
#[inline]
unsafe fn fopen_kind(mode: *const c_char) -> FsKind {
    if mode.is_null() {
        return FsKind::Read;
    }
    let mut i = 0usize;
    let mut has_write = false;
    loop {
        let c = *mode.add(i) as u8;
        if c == 0 {
            break;
        }
        if c == b'w' || c == b'a' || c == b'+' {
            has_write = true;
        }
        i += 1;
        if i > 16 {
            break;
        }
    }
    if has_write {
        FsKind::Write
    } else {
        FsKind::Read
    }
}

/// Guard preamble shared by every file hook: returns true when we should audit
/// (init done and not re-entrant).  When false the caller forwards to libc
/// without emitting.
#[inline]
fn should_audit() -> bool {
    macos_audit_ops_enabled() && !in_shim() && INIT_DONE.load(Ordering::Acquire)
}

/// Resolve `(dirfd, path)` and emit one fs event with the rc-derived errno.
/// `rc_failed`/`raw_errno` come from the just-completed real call.
#[inline]
unsafe fn audit_path(
    kind: FsKind,
    dirfd: c_int,
    path: *const c_char,
    rc_failed: bool,
    raw_errno: c_int,
) {
    let errno_kind: FsErrno = if rc_failed {
        classify_fs_errno(raw_errno)
    } else {
        FsErrno::None
    };
    let mut buf = [0u8; PATH_BUF];
    if abs_path_into(dirfd, path, &mut buf).is_some() {
        // Never record file ops on our OWN events file (env-spy writes
        // node_startup_done JSONL there).  That is audit infrastructure, not
        // lifecycle-script behaviour, and would otherwise leak into the lock as
        // a spurious read/write of the events-file path.
        if crate::path_is_audit_log(buf.as_ptr() as *const c_char) {
            return;
        }
        emit_fs(kind, buf.as_ptr() as *const c_char, errno_kind);
    }
}

// ── open / openat (C variadic bridge) ──────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn script_jail_open_impl(
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> c_int {
    // Forward FIRST so errno reflects the real outcome before we read it.
    let rc = libc::open(path, flags, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        // Re-assert the guard for the emit (errno read + abs-path resolution +
        // write all) so the resolution's own libc calls don't re-enter us.
        crate::set_in_shim(true);
        audit_path(open_kind(flags), libc::AT_FDCWD, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry_raw!(SJ_OPEN, script_jail_open_variadic, libc::open);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn script_jail_openat_impl(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> c_int {
    let rc = libc::openat(dirfd, path, flags, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(open_kind(flags), dirfd, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry_raw!(SJ_OPENAT, script_jail_openat_variadic, libc::openat);

// ── creat (always write) ───────────────────────────────────────────────────

unsafe extern "C" fn creat_interpose(path: *const c_char, mode: mode_t) -> c_int {
    let rc = libc::creat(path, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, libc::AT_FDCWD, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_CREAT,
    creat_interpose,
    libc::creat,
    unsafe extern "C" fn(*const c_char, mode_t) -> c_int
);

// ── fopen / freopen ────────────────────────────────────────────────────────

unsafe extern "C" fn fopen_interpose(path: *const c_char, mode: *const c_char) -> *mut FILE {
    let rc = libc::fopen(path, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(
            fopen_kind(mode),
            libc::AT_FDCWD,
            path,
            rc.is_null(),
            saved_errno,
        );
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_FOPEN,
    fopen_interpose,
    libc::fopen,
    unsafe extern "C" fn(*const c_char, *const c_char) -> *mut FILE
);

unsafe extern "C" fn freopen_interpose(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut FILE,
) -> *mut FILE {
    let rc = libc::freopen(path, mode, stream);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(
            fopen_kind(mode),
            libc::AT_FDCWD,
            path,
            rc.is_null(),
            saved_errno,
        );
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_FREOPEN,
    freopen_interpose,
    libc::freopen,
    unsafe extern "C" fn(*const c_char, *const c_char, *mut FILE) -> *mut FILE
);

// ── write-side: unlink / unlinkat ──────────────────────────────────────────

unsafe extern "C" fn unlink_interpose(path: *const c_char) -> c_int {
    let rc = libc::unlink(path);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, libc::AT_FDCWD, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_UNLINK,
    unlink_interpose,
    libc::unlink,
    unsafe extern "C" fn(*const c_char) -> c_int
);

unsafe extern "C" fn unlinkat_interpose(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    let rc = libc::unlinkat(dirfd, path, flags);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, dirfd, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_UNLINKAT,
    unlinkat_interpose,
    libc::unlinkat,
    unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int
);

// ── write-side: rename / renameat ──────────────────────────────────────────
//
// A rename mutates BOTH paths (the new path is created; the old path is
// removed).  strace-parser.ts emits read(old)+write(new) for a plain rename;
// to keep macOS faithful to "what the destination becomes" and avoid silently
// missing a write, we emit a write for BOTH the source and the destination.
// (protected-paths.ts cares about writes that ESCAPE; over-reporting the
// source as a write is the safe direction.)

unsafe extern "C" fn rename_interpose(old: *const c_char, new: *const c_char) -> c_int {
    let rc = libc::rename(old, new);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, libc::AT_FDCWD, old, rc < 0, saved_errno);
        audit_path(FsKind::Write, libc::AT_FDCWD, new, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_RENAME,
    rename_interpose,
    libc::rename,
    unsafe extern "C" fn(*const c_char, *const c_char) -> c_int
);

unsafe extern "C" fn renameat_interpose(
    oldfd: c_int,
    old: *const c_char,
    newfd: c_int,
    new: *const c_char,
) -> c_int {
    let rc = libc::renameat(oldfd, old, newfd, new);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, oldfd, old, rc < 0, saved_errno);
        audit_path(FsKind::Write, newfd, new, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_RENAMEAT,
    renameat_interpose,
    libc::renameat,
    unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int
);

// ── write-side: mkdir / mkdirat ────────────────────────────────────────────

unsafe extern "C" fn mkdir_interpose(path: *const c_char, mode: mode_t) -> c_int {
    let rc = libc::mkdir(path, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, libc::AT_FDCWD, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_MKDIR,
    mkdir_interpose,
    libc::mkdir,
    unsafe extern "C" fn(*const c_char, mode_t) -> c_int
);

unsafe extern "C" fn mkdirat_interpose(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    let rc = libc::mkdirat(dirfd, path, mode);
    let saved_errno = errno();
    let audit = should_audit();
    if audit {
        crate::set_in_shim(true);
        audit_path(FsKind::Write, dirfd, path, rc < 0, saved_errno);
        crate::set_in_shim(false);
    }
    set_errno(saved_errno);
    rc
}
interpose_entry!(
    SJ_MKDIRAT,
    mkdirat_interpose,
    libc::mkdirat,
    unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int
);

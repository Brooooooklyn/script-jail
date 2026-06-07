// script-jail — Mach-O dyld `__interpose` machinery (macOS only)
//
// Linux uses `LD_PRELOAD` + symbol-shadowing: the dynamic linker resolves a
// libc call (e.g. `getenv`) to OUR exported `#[no_mangle]` symbol because the
// preloaded object comes first in the search order.  macOS uses a two-level
// namespace, so symbol shadowing does NOT work — a `DYLD_INSERT_LIBRARIES`
// dylib must instead publish a `__DATA,__interpose` section: an array of
// `{ replacement, original }` function-pointer pairs that dyld rewrites into
// the binding tables at load time.
//
// This file is the Mach-O analog of the Linux `#[no_mangle]` export list.  It
// is `#[cfg(target_os = "macos")]` end-to-end; the Linux build never sees it.
//
// Ported (technique only — NOT a dependency) from fspy
// `crates/fspy_preload_unix/src/macros/macos.rs`.  The proven spike at
// /tmp/sj-macos-spike confirmed: dyld DOES rewrite the `connect`/`getenv`
// bindings of the audited process to point at our replacements, and a DIRECT
// `libc::<fn>` reference inside the replacement reaches the REAL symbol WITHOUT
// re-entering the interpose table (same-image refs bypass it — the "R8"
// finding).  That is why every `real_*` on macOS is a direct `libc::` call.
#![cfg(target_os = "macos")]

use core::ffi::c_void;

/// One `__interpose` table entry.  Layout MUST be `{ replacement, original }`
/// (two pointer-wide fields, replacement first) — dyld reads the section as a
/// flat array of these.
#[repr(C)]
pub struct InterposeEntry {
    pub replacement: *const c_void,
    pub original: *const c_void,
}

// SAFETY: the entry holds two raw function pointers that are never mutated
// after the static is materialized in the read-only `__DATA,__interpose`
// section.  No interior mutability; sharing across threads is sound.
unsafe impl Sync for InterposeEntry {}

/// Emit a `__DATA,__interpose` entry binding `$new` (our replacement) over
/// `$old` (the real libc symbol, referenced directly so the linker records the
/// genuine target).  `$new` and `$old` must have identical ABI; we additionally
/// pin that with a `const _: $sig = ...;` assertion so a signature drift is a
/// compile error rather than a silent UB interpose.
///
/// Usage:
///   interpose_entry!(SJ_CONNECT, connect_interpose, libc::connect,
///       unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int);
macro_rules! interpose_entry {
    ($entry:ident, $new:path, $old:path, $sig:ty) => {
        const _: $sig = $new;
        const _: $sig = $old;

        #[used]
        #[unsafe(link_section = "__DATA,__interpose")]
        static $entry: $crate::interpose::InterposeEntry = $crate::interpose::InterposeEntry {
            replacement: $new as *const ::core::ffi::c_void,
            original: $old as *const ::core::ffi::c_void,
        };
    };
}

pub(crate) use interpose_entry;

/// Like `interpose_entry!` but WITHOUT the ABI-equality `const` assertion.
/// Required for variadic libc symbols (`open`, `openat`, `creat`*, …) where the
/// replacement uses the fixed-arity "accept and ignore the trailing mode arg"
/// trick: the genuine `libc::<fn>` is variadic (`fn(..., ...) -> _`) and would
/// not type-check against a fixed-arity replacement signature, even though the
/// register-level ABI is compatible on arm64/x86_64 (the SysV/AAPCS calling
/// convention lets a callee read a fixed register slot the caller may or may
/// not have populated).  Both pointers are erased to `*const c_void` for the
/// table; correctness of the trick is the caller's responsibility.
macro_rules! interpose_entry_raw {
    ($entry:ident, $new:path, $old:path) => {
        #[used]
        #[unsafe(link_section = "__DATA,__interpose")]
        static $entry: $crate::interpose::InterposeEntry = $crate::interpose::InterposeEntry {
            replacement: $new as *const ::core::ffi::c_void,
            original: $old as *const ::core::ffi::c_void,
        };
    };
}

pub(crate) use interpose_entry_raw;

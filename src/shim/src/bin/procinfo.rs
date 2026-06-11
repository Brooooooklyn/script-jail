// script-jail — `sj-procinfo` helper (macOS only).
//
// The guest layer's MacOSProcReader has no /proc to read a child's ppid from.
// `KERN_PROCARGS2` is SIP-fragile and fails for reaped pids, so the plan reads
// the ppid via `proc_pidinfo(PROC_PIDTBSDINFO)` instead — same-uid-safe and
// SIP-safe.  This tiny binary exposes exactly that: given a pid argument it
// prints the parent pid to stdout (or exits non-zero / prints nothing if the
// pid is gone or not permitted).
//
// It is a SEPARATE bin target, NOT the `#![no_std]` cdylib, so it freely uses
// std.  It is never injected into an audited process — the guest spawns it as
// a short-lived child.  On non-macOS it compiles to a no-op stub so the
// workspace (Linux ELF cdylib build) still builds.

#[cfg(target_os = "macos")]
fn main() {
    use std::ffi::c_void;
    use std::process::exit;

    let mut args = std::env::args().skip(1);
    let pid: i32 = match args.next().and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("usage: sj-procinfo <pid>");
            exit(2);
        }
    };

    // SAFETY: proc_pidinfo writes at most size_of::<proc_bsdinfo>() bytes into
    // the zeroed struct; we pass that exact size as the capacity.
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let rc = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut c_void,
            size,
        );
        if rc != size {
            // pid gone, not permitted, or short write — let the guest fall back
            // to the shim event seed (readPpid -> null).
            exit(1);
        }
        println!("{}", info.pbi_ppid);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    // sj-procinfo is a macOS-only helper; on other platforms it is a no-op so
    // the workspace still builds the Linux ELF cdylib.
    std::process::exit(0);
}

// script-jail — src/host-mac/src/lib.rs
//
// Library crate for the macOS host runner.  The binary at `src/main.rs`
// pulls everything together; the library exists so `cargo test
// -p script-jail-host-mac` can exercise pure logic (config parsing, frame
// parsing) without compiling/linking the binary's main() and without
// requiring a live Virtualization.framework session.

// Rust 2024 promoted `unsafe_op_in_unsafe_fn` from allow to warn.  The vsock
// + dispatch glue calls into objc2 / GCD C APIs from `unsafe extern "C"`
// callbacks; wrapping each FFI call site in a nested `unsafe { }` block adds
// noise without changing the soundness story (every external entry is
// already an unsafe surface).  Suppress at crate root to preserve the 2021
// semantics this crate was authored against.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod cli;
pub mod config;
pub mod delegate;
pub mod disks;
pub mod dispatch;
pub mod frames;
pub mod vm;
pub mod vsock;

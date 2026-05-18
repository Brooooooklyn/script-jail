// Shared constant between the TypeScript guest agent and the Rust LD_PRELOAD
// shim (`src/shim/src/lib.rs`).  The shim snapshots sticky `SCRIPT_JAIL_*`
// env vars into a fixed-size buffer (`CanonBuf`) at `shim_init` so exec-time
// rewrites cannot be poisoned by post-init mutations to `environ[]`.  The
// buffer is `CANON_BUF_LEN = 1024` bytes including the trailing NUL, leaving
// `CANON_BUF_LEN - 1 = 1023` bytes of payload.
//
// `SCRIPT_JAIL_PROTECTED_ENV_NAMES` is the only sticky var whose value is
// user-controllable (Finding 4 in the audit-trust series: the comma-joined
// list of env-var names the shim must hide from getenv).  If the host
// composes a list whose UTF-8 encoding exceeds `CANON_PROTECTED_ENV_NAMES_MAX_LEN`,
// the shim's `capture_canon` would silently truncate the suffix and the
// dropped names would NOT be in the protect list — they would leak through
// env-spy / shim getenv unannotated.
//
// To prevent that silent failure, the agent rejects an over-long list at
// `buildChildEnv` time (BEFORE any audit begins, on the trusted host side).
// This constant is the load-bearing source of truth on the TS side.
//
// CONTRACT: this MUST stay in lockstep with `CANON_BUF_LEN` in
// `src/shim/src/lib.rs`.  Both values are intentionally hard-coded (rather
// than read via FFI / build-time codegen) because the shim is `#![no_std]`
// and the agent has no path to call into the cdylib for a constant.  A
// mismatch only breaks the over-long-list rejection (the shim already
// truncates silently in that case), but it would re-introduce the silent-
// truncation bug, so any change here MUST be mirrored in lib.rs and
// vice-versa.
export const CANON_PROTECTED_ENV_NAMES_MAX_LEN = 1023;

// script-jail — macOS connect() + connectx() interpose hooks (observe-only).
//
// Linux gets outbound connection attempts from strace's `connect` rows AND runs
// Phase B under `unshare -n`, so the install subtree is OFFLINE: every observed
// connect is recorded `<BLOCKED>`.  macOS has no strace and no network namespace;
// the shim interposes the connect-family libc entry points and emits the EXACT
// `NetworkEvent` shape from src/lock/schema.ts (via crate::emit_connect):
//   {"kind":"connect","host":"<ip>","port":N,"result":"ok"|"blocked",...}
//
// OBSERVE-ONLY (the macOS-bare model — user decision 3): the shim does NOT
// enforce offline.  macOS stays ONLINE; the real connect/connectx is ALWAYS
// forwarded and the shim only RECORDS the attempt with its TRUE result (an
// online connect succeeds → "ok").  Parity with Linux's offline Phase B is
// reconciled AT DIFF TIME: scripts/parity-diff.ts strips the `<BLOCKED> ` prefix
// so a Linux blocked connect and a macOS online connect both reduce to
// `connect <host>:<port>` and match.  This backend does NOT cover audit-blind
// SIP children or raw syscalls — Firecracker remains the high-assurance backend
// (see docs/divergence.md for the full enforcement-boundary disclosure).
//
// PHASE GATE (macos_audit_ops_enabled()):
//   - Phase A (fetch, gate FALSE): forward, record NOTHING — Phase A is the
//     online fetch and its connects are expected/benign.
//   - Phase B (install, gate TRUE): forward, RECORD the connect with its true
//     result.  AF_UNIX / other families (pnpm store IPC, daemons) are never inet
//     → dropped, matching strace-parser.ts which only parses the inet families.
//
// The IP literal is hand-formatted into a stack buffer (no heap, no getnameinfo)
// per the macOS hot-path discipline.
//
// CRASH SAFETY (adversarial review round-10, finding F4): the destination
// sockaddr is read ONLY AFTER the real call has been forwarded.  By then the
// kernel has validated the pointer — a bad/hostile pointer makes the real call
// return EFAULT, which we detect and skip — so a truncated or hostile address
// can never make the shim segfault.  Result classification mirrors
// strace-parser.ts exactly (round-12 finding F3): rc==0 → "ok"; an in-flight or
// already-established non-blocking connect (EINPROGRESS / EALREADY / EISCONN)
// also → "ok" (the SYN is on the wire — egress HAPPENED); only a genuine
// failure → "blocked".
#![cfg(target_os = "macos")]

use core::ffi::{c_char, c_int, c_uint};

use libc::{iovec, sa_endpoints_t, sae_associd_t, sae_connid_t, size_t, sockaddr, socklen_t};

use crate::interpose::interpose_entry;
use crate::{
    ConnectResult, INIT_DONE, emit_connect, errno, in_shim, macos_audit_ops_enabled, set_errno,
};

use core::sync::atomic::Ordering;

// connect() interpose — observe-only.  Forward FIRST so errno reflects the real
// outcome, then record the attempt (Phase B only) with its true result.
unsafe extern "C" fn connect_interpose(
    sockfd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    let rc = libc::connect(sockfd, addr, addrlen);
    let saved_errno = errno();
    if record_gate_open() && addr_was_consumed(addr, rc, saved_errno) {
        record_connect_observed(addr, addrlen, rc, saved_errno);
    }
    set_errno(saved_errno);
    rc
}

interpose_entry!(
    SJ_CONNECT,
    connect_interpose,
    libc::connect,
    unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
);

// connectx() interpose — observe-only.  connectx() is the Darwin connect-
// equivalent: it establishes a connection to `endpoints->sae_dstaddr` (optionally
// sending an initial payload via `iov`).  A connect-only interpose would miss it,
// so we observe it too and emit the SAME NetworkEvent shape as connect.  Same
// forward-first discipline: the kernel validates `endpoints` and the nested
// sae_dstaddr during the forwarded call, so we read them only afterwards and only
// when the call did not fault (finding F4).
unsafe extern "C" fn connectx_interpose(
    socket: c_int,
    endpoints: *const sa_endpoints_t,
    associd: sae_associd_t,
    flags: c_uint,
    iov: *const iovec,
    iovcnt: c_uint,
    len: *mut size_t,
    connid: *mut sae_connid_t,
) -> c_int {
    let rc = libc::connectx(socket, endpoints, associd, flags, iov, iovcnt, len, connid);
    let saved_errno = errno();
    // Reading `endpoints` (and the nested sae_dstaddr) is only safe when the
    // forwarded call actually consumed them — same allow-list as connect.  A
    // pre-address failure (EBADF/ENOTSOCK/EINVAL/EFAULT) leaves both unread, so
    // we skip rather than dereference a possibly-hostile pointer.
    if record_gate_open() && addr_was_consumed(endpoints as *const sockaddr, rc, saved_errno) {
        let dst = (*endpoints).sae_dstaddr;
        let dstlen = (*endpoints).sae_dstaddrlen;
        if addr_was_consumed(dst, rc, saved_errno) {
            record_connect_observed(dst, dstlen, rc, saved_errno);
        }
    }
    set_errno(saved_errno);
    rc
}

interpose_entry!(
    SJ_CONNECTX,
    connectx_interpose,
    libc::connectx,
    unsafe extern "C" fn(
        c_int,
        *const sa_endpoints_t,
        sae_associd_t,
        c_uint,
        *const iovec,
        c_uint,
        *mut size_t,
        *mut sae_connid_t,
    ) -> c_int
);

/// Phase gate shared by connect/connectx: record iff we are NOT re-entrant, init
/// is complete, and we are in the audited Phase-B window.  Pre-init / re-entrant
/// / Phase-A → never record.
#[inline]
unsafe fn record_gate_open() -> bool {
    !in_shim() && INIT_DONE.load(Ordering::Acquire) && macos_audit_ops_enabled()
}

/// Pointer-safety predicate (round-10 finding F4, hardened for round-11 finding
/// F1): the destination sockaddr is safe to read ONLY when the forwarded call
/// actually CONSUMED it.  An errno≠EFAULT check is NOT sufficient — failures
/// decided BEFORE the kernel copies in the address (`EBADF`/`ENOTSOCK`/`EINVAL`/
/// `EAFNOSUPPORT`, and `EFAULT` itself) leave `addr` unread, so dereferencing a
/// hostile pointer would still segfault (e.g. `connect(-1, 0x1, 16)` returns
/// `EBADF`, not `EFAULT`).  Fail-safe ALLOW-LIST: read only on success (rc==0) or
/// on a connection-attempt errno that proves the kernel parsed the address.  Any
/// other outcome → skip: we may miss recording a degenerate connect, but we never
/// crash, and a one-sided miss fails the parity gate CLOSED (surfaces) rather than
/// laundering.
#[inline]
unsafe fn addr_was_consumed(addr: *const sockaddr, rc: c_int, e: c_int) -> bool {
    if addr.is_null() {
        return false;
    }
    if rc == 0 {
        return true;
    }
    // rc != 0: only these errnos are reached AFTER the kernel has copied in and
    // parsed the destination sockaddr (the connection was actually attempted).
    matches!(
        e,
        libc::ECONNREFUSED
            | libc::ETIMEDOUT
            | libc::ENETUNREACH
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::EHOSTDOWN
            | libc::EADDRNOTAVAIL
            | libc::EADDRINUSE
            | libc::EINPROGRESS
            | libc::EALREADY
            | libc::EISCONN
            | libc::EACCES
            | libc::EPERM
            | libc::ECONNRESET
            | libc::EAGAIN
            | libc::ENOBUFS
    )
}

/// Emit the NetworkEvent for an observed connect/connectx to `addr`.  Result
/// classification mirrors strace-parser.ts exactly: `rc==0` → "ok"; a non-
/// blocking connect still IN FLIGHT or already established (`EINPROGRESS` /
/// `EALREADY` / `EISCONN`) also → "ok" because the SYN is already on the wire —
/// egress HAPPENED; any genuine failure (refused / timed out / unreachable /
/// denied) → "blocked" (round-12 finding F3).  Re-checks the family-specific
/// struct size before casting so a too-short sockaddr is dropped rather than
/// over-read.  Wrapped in `set_in_shim` because emit_connect re-enters libc
/// (write).
unsafe fn record_connect_observed(addr: *const sockaddr, addrlen: socklen_t, rc: c_int, e: c_int) {
    crate::set_in_shim(true);

    let alen = addrlen as usize;
    // EINPROGRESS is the COMMON case on online macOS: libuv (all Node
    // networking) issues non-blocking connects, so connect returns -1 while the
    // connection proceeds asynchronously.  Recording that — or EALREADY /
    // EISCONN — as "blocked" would log a successful reach-out as prevented, the
    // wrong direction for an exfil-detection audit.  Treat egress-occurred as
    // "ok"; only a real failure is "blocked".
    let result = if rc == 0
        || e == libc::EINPROGRESS
        || e == libc::EALREADY
        || e == libc::EISCONN
    {
        ConnectResult::Ok
    } else {
        ConnectResult::Blocked
    };

    // Bounds guard: need ≥ 2 bytes for the family field, then the full family-
    // specific struct size before casting.  IPv4: dotted-quad.  IPv6: colon-hex.
    if alen >= 2 {
        let family = (*addr).sa_family as c_int;
        let mut host = [0u8; 64];
        let mut n = 0usize;

        if family == libc::AF_INET && alen >= core::mem::size_of::<libc::sockaddr_in>() {
            let sin = addr as *const libc::sockaddr_in;
            let port = u16::from_be((*sin).sin_port);
            let ip = u32::from_be((*sin).sin_addr.s_addr);
            write_u8dec(&mut host, &mut n, ((ip >> 24) & 0xff) as u8);
            push(&mut host, &mut n, b'.');
            write_u8dec(&mut host, &mut n, ((ip >> 16) & 0xff) as u8);
            push(&mut host, &mut n, b'.');
            write_u8dec(&mut host, &mut n, ((ip >> 8) & 0xff) as u8);
            push(&mut host, &mut n, b'.');
            write_u8dec(&mut host, &mut n, (ip & 0xff) as u8);
            host[n] = 0;
            emit_connect(host.as_ptr() as *const c_char, port, result);
        } else if family == libc::AF_INET6 && alen >= core::mem::size_of::<libc::sockaddr_in6>() {
            let sin6 = addr as *const libc::sockaddr_in6;
            let port = u16::from_be((*sin6).sin6_port);
            let seg = (*sin6).sin6_addr.s6_addr; // [u8; 16], network order
            format_ipv6(&seg, &mut host, &mut n);
            host[n] = 0;
            emit_connect(host.as_ptr() as *const c_char, port, result);
        }
        // else: AF_UNIX / other family / sockaddr too short for its family → drop.
    }

    crate::set_in_shim(false);
}

// ── hand formatting (zero-alloc) ───────────────────────────────────────────

#[inline]
fn push(buf: &mut [u8], n: &mut usize, b: u8) {
    if *n < buf.len() {
        buf[*n] = b;
        *n += 1;
    }
}

fn write_u8dec(buf: &mut [u8], n: &mut usize, v: u8) {
    let v = v as u16;
    if v >= 100 {
        push(buf, n, b'0' + (v / 100) as u8);
    }
    if v >= 10 {
        push(buf, n, b'0' + ((v / 10) % 10) as u8);
    }
    push(buf, n, b'0' + (v % 10) as u8);
}

fn write_hex16(buf: &mut [u8], n: &mut usize, v: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Lowercase, no leading zeros (canonical-ish; the host canonicalizes).
    let mut started = false;
    for shift in [12u32, 8, 4, 0] {
        let nib = ((v >> shift) & 0xf) as usize;
        if nib != 0 || started || shift == 0 {
            push(buf, n, HEX[nib]);
            started = true;
        }
    }
}

/// Format a 16-byte IPv6 address (network order) into `buf` as 8 colon-
/// separated hextets.  No `::` zero-run compression — the host-side tokenizer /
/// noise filter does not require it, and a faithful expanded form keeps the
/// shim allocation- and branch-light.
fn format_ipv6(seg: &[u8; 16], buf: &mut [u8], n: &mut usize) {
    for i in 0..8usize {
        if i > 0 {
            push(buf, n, b':');
        }
        let hextet = ((seg[i * 2] as u16) << 8) | (seg[i * 2 + 1] as u16);
        write_hex16(buf, n, hextet);
    }
}

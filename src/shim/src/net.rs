// script-jail — macOS connect() interpose hook (observe-only).
//
// Linux gets outbound connection attempts from strace's `connect` rows.  macOS
// has no strace, so the shim interposes `connect` itself and emits the EXACT
// `NetworkEvent` shape from src/lock/schema.ts (via crate::emit_connect):
//   {"kind":"connect","host":"<ip>","port":N,"result":"ok"|"blocked",...}
//
// Only AF_INET / AF_INET6 are recorded — AF_UNIX and other families are local
// IPC, not egress, and are dropped (matching strace-parser.ts which only parses
// the inet families).  The IP literal is hand-formatted into a stack buffer
// (no heap, no getnameinfo) per the macOS hot-path discipline.
//
// Per the plan (observe-only, stay online), the real connect is always
// forwarded — the shim records the attempt but never blocks it.  result
// classification mirrors strace-parser.ts:739 exactly: rc==0 → "ok"; any error
// (INCLUDING EINPROGRESS on a non-blocking socket) → "blocked".
#![cfg(target_os = "macos")]

use core::ffi::{c_char, c_int};

use libc::{sockaddr, socklen_t};

use crate::interpose::interpose_entry;
use crate::{emit_connect, in_shim, ConnectResult, INIT_DONE};

use core::sync::atomic::Ordering;

unsafe extern "C" fn connect_interpose(
    sockfd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    // Forward FIRST (observe-only) so errno reflects the real outcome.
    let rc = libc::connect(sockfd, addr, addrlen);

    if in_shim() || !INIT_DONE.load(Ordering::Acquire) {
        return rc;
    }
    if addr.is_null() {
        return rc;
    }

    crate::set_in_shim(true);

    let result = if rc == 0 {
        ConnectResult::Ok
    } else {
        // Any error — including EINPROGRESS (non-blocking connect in flight) —
        // is "blocked", matching strace-parser.ts.  The errno value itself is
        // not needed: a non-zero rc alone classifies the attempt as blocked.
        ConnectResult::Blocked
    };

    // Bounds guard.  The kernel already validated `addr`/`addrlen` in the
    // forwarded connect() above, but we re-check before OUR OWN reads so a
    // truncated or hostile sockaddr can never make us read past `addrlen`:
    // need ≥ 2 bytes for the family field, then the full family-specific struct
    // size before casting.  A too-short addr falls through to the drop path.
    let alen = addrlen as usize;
    if alen < 2 {
        crate::set_in_shim(false);
        return rc;
    }
    let family = (*addr).sa_family as c_int;
    // IPv4: dotted-quad.  IPv6: colon-hex.  Hand-formatted into a stack buffer
    // wide enough for the longest IPv6 literal (45 chars) + NUL.
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

    crate::set_in_shim(false);
    rc
}

interpose_entry!(
    SJ_CONNECT,
    connect_interpose,
    libc::connect,
    unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
);

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

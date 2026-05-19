// script-jail — src/host-mac/src/vsock.rs
//
// Host-side virtio-socket listener.  Boots a VZVirtioSocketListener with a
// delegate that:
//
//   1. Accepts connections only on the configured port (10242 by default,
//      matching the action's vsock.ts).  All other ports are rejected.
//   2. On accept, drains the connection's file descriptor on a dedicated OS
//      thread and forwards JSONL frames to a `Sender<Frame>` channel.
//
// Outbound writes (the host's "go\n" handshake) are done via the same fd —
// the connection structure keeps ownership of the fd, so the writer side
// runs in the accept callback's worker thread.

use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use crossbeam_channel::Sender;
use objc2::rc::Retained;
use objc2::runtime::{Bool, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass};
use objc2_foundation::{NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketListener,
    VZVirtioSocketListenerDelegate,
};

use crate::frames::Frame;

#[derive(Default)]
pub struct VsockListenerIvars {
    /// The vsock port we accept on; anything else is bounced.
    ///
    /// `OnceLock` (rather than `OnceCell`) because VZ fires the listener
    /// delegate's `shouldAcceptNewConnection:` on its GCD queue thread while
    /// the host's main thread populates these ivars right after `alloc/init`.
    /// `OnceCell` is `!Sync`, so the cross-thread visibility of the write
    /// would be UB; the Send/Sync violation is invisible to rustc because
    /// the delegate moves across the Obj-C FFI boundary.
    pub port: OnceLock<u32>,
    /// Where to forward parsed frames.  See `port` for why this is OnceLock.
    pub frame_tx: OnceLock<Sender<Frame>>,
    /// Active connection's writable fd.  Wrapped in Arc<Mutex<>> so the
    /// helper's main thread can post "go\n" while the reader thread is
    /// blocking on read().  None until a connection has been accepted.
    pub conn_writer: Mutex<Option<Arc<Mutex<OwnedFd>>>>,
}

define_class!(
    // SAFETY:
    // - The superclass NSObject has no subclassing requirements.
    // - We don't implement Drop, so no super-method ordering issues.
    // - Method signatures match the protocol declarations exactly.
    #[unsafe(super(NSObject))]
    #[ivars = VsockListenerIvars]
    pub struct VsockListenerDelegate;

    unsafe impl NSObjectProtocol for VsockListenerDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for VsockListenerDelegate {
        #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
        fn should_accept(
            &self,
            _listener: &VZVirtioSocketListener,
            connection: &VZVirtioSocketConnection,
            _device: &VZVirtioSocketDevice,
        ) -> Bool {
            // SAFETY: VZ guarantees `connection` is alive for the duration
            // of this callback; destinationPort + fileDescriptor are
            // plain-old-data accessors.
            let dest_port = unsafe { connection.destinationPort() };
            let expected = self.ivars().port.get().copied().unwrap_or(10242);
            if dest_port != expected {
                eprintln!(
                    "script-jail-vm: vsock connection on unexpected port {dest_port} (expected {expected}) — rejecting"
                );
                return Bool::NO;
            }

            // SAFETY: fileDescriptor returns the OS fd backing the
            // connection.  VZ owns and will eventually close the fd, so
            // we dup() it before taking ownership.
            let raw = unsafe { connection.fileDescriptor() };
            if raw < 0 {
                eprintln!("script-jail-vm: vsock connection has invalid fd; rejecting");
                return Bool::NO;
            }
            // SAFETY: dup(2) on a live POSIX fd.
            let read_fd = match unsafe { dup_fd(raw) } {
                Some(fd) => fd,
                None => {
                    eprintln!(
                        "script-jail-vm: vsock dup(reader) failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return Bool::NO;
                }
            };
            let write_fd = match unsafe { dup_fd(raw) } {
                Some(fd) => fd,
                None => {
                    eprintln!(
                        "script-jail-vm: vsock dup(writer) failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return Bool::NO;
                }
            };

            // Stash the writer handle so post_go() can reach it.
            if let Ok(mut slot) = self.ivars().conn_writer.lock() {
                *slot = Some(Arc::new(Mutex::new(write_fd)));
            }

            // Spawn a reader thread that drains the fd line-by-line.
            let frame_tx = match self.ivars().frame_tx.get() {
                Some(tx) => tx.clone(),
                None => {
                    eprintln!("script-jail-vm: vsock delegate missing frame_tx — rejecting");
                    return Bool::NO;
                }
            };

            std::thread::Builder::new()
                .name("script-jail-vsock-reader".into())
                .spawn(move || {
                    reader_loop(read_fd, frame_tx);
                })
                .ok();

            Bool::YES
        }
    }
);

impl VsockListenerDelegate {
    pub fn new(port: u32, frame_tx: Sender<Frame>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(VsockListenerIvars::default());
        let me: Retained<Self> = unsafe { msg_send![super(this), init] };
        let _ = me.ivars().port.set(port);
        let _ = me.ivars().frame_tx.set(frame_tx);
        me
    }

    pub fn as_protocol(&self) -> &ProtocolObject<dyn VZVirtioSocketListenerDelegate> {
        ProtocolObject::from_ref(self)
    }

    /// Write `go\n` to the active vsock connection, if any.  Returns
    /// `Ok(false)` if no connection has been accepted yet — callers should
    /// retry once the guest has handshaked.
    pub fn post_go(&self) -> std::io::Result<bool> {
        let writer = match self.ivars().conn_writer.lock() {
            Ok(slot) => slot.as_ref().cloned(),
            Err(_) => None,
        };
        let Some(writer) = writer else {
            return Ok(false);
        };
        let guard = writer
            .lock()
            .map_err(|_| std::io::Error::other("vsock writer mutex poisoned"))?;
        let fd_raw = guard.as_raw_fd();
        // SAFETY: writing to a live, owned fd; raw bytes are ASCII.
        let n = unsafe { write_fd(fd_raw, b"go\n") };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(true)
    }
}

/// Build the VZ listener object and wire our delegate to it.
pub fn build_listener(delegate: &VsockListenerDelegate) -> Retained<VZVirtioSocketListener> {
    let listener = unsafe { VZVirtioSocketListener::new() };
    unsafe { listener.setDelegate(Some(delegate.as_protocol())) };
    listener
}

/// Reader loop running on its own OS thread.  Owns its OwnedFd outright;
/// dropping the fd at the end closes our duplicated handle but not the
/// VZ-owned original.
fn reader_loop(fd: OwnedFd, tx: Sender<Frame>) {
    // FdReader is a thin wrapper that implements `Read` by calling read(2)
    // on our owned fd without ever closing it via File::drop.
    let reader = FdReader { fd };
    let mut buf = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        match buf.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim_end();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Frame>(trimmed) {
                    Ok(frame) => {
                        if tx.send(frame).is_err() {
                            break; // consumer dropped
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "script-jail-vm: malformed vsock frame: {err} :: {}",
                            &trimmed[..trimmed.len().min(200)]
                        );
                    }
                }
            }
            Err(err) => {
                eprintln!("script-jail-vm: vsock read error: {err}");
                break;
            }
        }
    }
}

/// Read-side adaptor over an OwnedFd.  We deliberately don't build a
/// `std::fs::File`: File's Drop closes the fd, and we want OwnedFd to own
/// that responsibility.
struct FdReader {
    fd: OwnedFd,
}

impl Read for FdReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: fd is non-negative (OwnedFd invariant); buf pointer/len
        // are valid for the writes the syscall will make.
        let n = unsafe { read_fd(self.fd.as_raw_fd(), buf) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

// --------------------------------------------------------------------------
// Thin libc shims.  Avoiding the `libc` crate as a hard dependency for the
// few calls we make; the FFI signatures are ABI-stable on macOS.
// --------------------------------------------------------------------------

unsafe extern "C" {
    fn dup(fildes: core::ffi::c_int) -> core::ffi::c_int;
    fn read(fd: core::ffi::c_int, buf: *mut core::ffi::c_void, count: usize) -> isize;
    fn write(fd: core::ffi::c_int, buf: *const core::ffi::c_void, count: usize) -> isize;
}

unsafe fn dup_fd(raw: RawFd) -> Option<OwnedFd> {
    let dup_raw = unsafe { dup(raw) };
    if dup_raw < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(dup_raw) })
    }
}

unsafe fn write_fd(fd: RawFd, bytes: &[u8]) -> isize {
    unsafe { write(fd, bytes.as_ptr() as *const _, bytes.len()) }
}

unsafe fn read_fd(fd: RawFd, buf: &mut [u8]) -> isize {
    unsafe { read(fd, buf.as_mut_ptr() as *mut _, buf.len()) }
}

#[cfg(test)]
mod sync_tests {
    //! Compile-time guard that the delegate is `Send + Sync`.  VZ moves the
    //! object across an Obj-C FFI boundary that hides any non-Send/Sync ivar
    //! from rustc, so this assertion is the only place such a regression
    //! would be caught.  If anyone swaps `OnceLock` back to a `!Sync` cell
    //! (e.g. `std::cell::OnceCell`) this module will fail to compile.
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn vsock_delegate_is_send_sync() {
        assert_send::<VsockListenerDelegate>();
        assert_sync::<VsockListenerDelegate>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    unsafe extern "C" {
        fn pipe(fds: *mut core::ffi::c_int) -> core::ffi::c_int;
        fn close(fd: core::ffi::c_int) -> core::ffi::c_int;
    }

    #[test]
    fn delegate_new_attaches_ivars() {
        let (tx, _rx) = unbounded::<Frame>();
        let d = VsockListenerDelegate::new(10242, tx);
        assert_eq!(d.ivars().port.get().copied(), Some(10242));
        assert!(d.ivars().frame_tx.get().is_some());
    }

    #[test]
    fn post_go_returns_false_before_connection() {
        let (tx, _rx) = unbounded::<Frame>();
        let d = VsockListenerDelegate::new(10242, tx);
        let sent = d.post_go().expect("post_go should not error");
        assert!(
            !sent,
            "no connection accepted yet — post_go should report false"
        );
    }

    #[test]
    fn reader_loop_parses_jsonl_from_pipe() {
        // Build a self-pipe so we can drive the reader loop without VZ.
        let mut fds: [core::ffi::c_int; 2] = [0; 2];
        let rc = unsafe { pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed");
        let read_owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_raw = fds[1];

        let (tx, rx) = unbounded::<Frame>();
        let handle = std::thread::spawn(move || reader_loop(read_owned, tx));

        let payload = b"{\"kind\":\"handshake\",\"phase\":\"fetch_done\"}\n";
        let n = unsafe { write_fd(write_raw, payload) };
        assert_eq!(n, payload.len() as isize, "write() into pipe failed");

        // Close the writer to signal EOF and let the reader thread exit.
        unsafe { close(write_raw) };
        handle.join().expect("reader thread joined");

        // The reader should have surfaced one Handshake frame.
        let frame = rx.try_recv().expect("frame should have been forwarded");
        match frame {
            Frame::Handshake(h) => assert_eq!(h.phase, "fetch_done"),
            other => panic!("expected Handshake, got {other:?}"),
        }
    }
}

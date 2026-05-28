// script-jail — src/host-mac/src/delegate.rs
//
// VmDelegate: an Obj-C object that conforms to VZVirtualMachineDelegate.
// Lives for the duration of the VM.  Its only job is to translate VZ's
// asynchronous lifecycle callbacks (guest stopped cleanly, guest crashed,
// network attachment dropped) into entries on a crossbeam channel so the
// main thread can react synchronously.
//
// The matching VZVirtualMachine instance retains the delegate via
// `setDelegate:` (a *weak* property in the framework), which is why the
// caller — vm.rs — must keep its own strong reference (`VmHandle._delegate`).

use std::sync::OnceLock;

use crossbeam_channel::Sender;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{AnyThread, DefinedClass, define_class, msg_send};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol};
use objc2_virtualization::{VZVirtualMachine, VZVirtualMachineDelegate};

/// Cross-thread message from a VZ delegate callback back to whoever owns
/// the helper process.  Always treat any variant as a terminal event for
/// the current boot — the VM is no longer running once we see one.
#[derive(Debug, Clone)]
pub enum DelegateEvent {
    /// Guest invoked `poweroff` or otherwise initiated a clean shutdown.
    GuestStopped,
    /// VZ reports the VM died due to host-side error or a guest panic.
    /// The `String` is `NSError.localizedDescription` lifted to UTF-8.
    StoppedWithError(String),
}

/// Top-level shutdown reason exit codes for the helper.  Mirrors the
/// taxonomy in main.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Guest finished cleanly — exit 0.
    GuestStopped,
    /// VZ reported an error — exit 2.
    VzError,
    /// Helper-level error before VZ took over — exit 64 typically.
    PreBootFailure,
}

/// Ivars for the Obj-C subclass.  `OnceLock` lets us defer setting the
/// channel until after `Self::alloc().init()` returns, which is necessary
/// because we don't have the channel at the moment alloc happens (the
/// channel is created higher up the stack and threaded through).
///
/// `OnceLock` (rather than the unsynchronised `std::cell::OnceCell`)
/// because VZ delivers delegate callbacks on the GCD queue thread while the
/// host's main thread populates this ivar right after `alloc/init`.  The
/// `Sync` guarantee is what gives us the happens-before edge between the
/// two writes; rustc cannot catch a regression here because the delegate
/// moves across the Obj-C FFI boundary.
#[derive(Default)]
pub struct VmDelegateIvars {
    pub tx: OnceLock<Sender<DelegateEvent>>,
}

define_class!(
    // SAFETY:
    // - The superclass NSObject has no subclassing requirements.
    // - VmDelegate does not implement Drop.
    // - All Obj-C method signatures are checked against the protocol's
    //   declarations in objc2-virtualization.
    #[unsafe(super(NSObject))]
    #[ivars = VmDelegateIvars]
    pub struct VmDelegate;

    unsafe impl NSObjectProtocol for VmDelegate {}

    unsafe impl VZVirtualMachineDelegate for VmDelegate {
        #[unsafe(method(guestDidStopVirtualMachine:))]
        fn guest_did_stop(&self, _vm: &VZVirtualMachine) {
            if let Some(tx) = self.ivars().tx.get() {
                let _ = tx.send(DelegateEvent::GuestStopped);
            }
        }

        #[unsafe(method(virtualMachine:didStopWithError:))]
        fn did_stop_with_error(&self, _vm: &VZVirtualMachine, err: &NSError) {
            // localizedDescription is a safe NSError accessor in
            // objc2-foundation 0.3 — no `unsafe` needed.
            let desc = err.localizedDescription().to_string();
            let msg = if desc.is_empty() {
                format!("{err:?}")
            } else {
                desc
            };
            if let Some(tx) = self.ivars().tx.get() {
                let _ = tx.send(DelegateEvent::StoppedWithError(msg));
            }
        }
    }
);

impl VmDelegate {
    /// Build a fresh delegate.  The crossbeam Sender is attached after
    /// allocation via `attach_tx`; this two-step is here because VZ has to
    /// see the object already-formed at `setDelegate:` time.
    pub fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(VmDelegateIvars::default());
        // SAFETY: `NSObject`'s `init` has the standard init signature.
        unsafe { msg_send![super(this), init] }
    }

    /// Install the channel side that delegate callbacks will post to.
    /// Idempotent in the sense that we drop subsequent calls (OnceCell);
    /// callers should treat that as a programming error.
    pub fn attach_tx(&self, tx: Sender<DelegateEvent>) {
        // Ignore an already-set channel — the helper should call this once,
        // and a second call is benign in tests.
        let _ = self.ivars().tx.set(tx);
    }

    /// Coerce a typed delegate handle into the ProtocolObject reference
    /// VZ wants for `setDelegate:`.
    pub fn as_protocol(&self) -> &ProtocolObject<dyn VZVirtualMachineDelegate> {
        ProtocolObject::from_ref(self)
    }
}

#[cfg(test)]
mod sync_tests {
    //! Compile-time guard that the delegate is `Send + Sync`.  See the
    //! matching module in `vsock.rs` for why this matters.
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn vm_delegate_is_send_sync() {
        assert_send::<VmDelegate>();
        assert_sync::<VmDelegate>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    #[test]
    fn delegate_attaches_channel_once() {
        let d = VmDelegate::new();
        let (tx, _rx) = unbounded::<DelegateEvent>();
        d.attach_tx(tx);
        // A second attach is a no-op (silent — see attach_tx).  We can't
        // observe it from outside without exposing the cell, so just
        // verify no panic.
        let (tx2, _rx2) = unbounded::<DelegateEvent>();
        d.attach_tx(tx2);
    }

    #[test]
    fn delegate_as_protocol_succeeds() {
        let d = VmDelegate::new();
        // Just confirm the cast compiles + returns a non-null reference.
        let _proto = d.as_protocol();
    }
}

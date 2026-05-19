// script-jail — src/host-mac/src/dispatch.rs
//
// Owns the Grand Central Dispatch (GCD) serial queue that backs every VZ
// delegate callback.  Virtualization.framework runs every delegate
// invocation on the queue you pass to `initWithConfiguration:queue:`; the
// queue must be serial.  We keep one in-process for the lifetime of the VM.
//
// Communication with the rest of the helper is done via crossbeam channels;
// the queue itself does no work other than holding a strong reference for
// VZ to schedule on.

use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};

/// Cloneable handle to the helper's serial dispatch queue.  Multiple owners
/// (the VM, the delegate, the smoke-runner shim) all need to keep the queue
/// alive — dropping the last `Handle` releases the underlying object.
///
/// `DispatchRetained<DispatchQueue>` already wraps GCD's
/// `dispatch_retain` / `dispatch_release` so its `Clone` impl bumps the
/// underlying refcount.  We deliberately do **not** wrap it in `Arc`: that
/// would add a redundant second layer of reference counting on top of the
/// one GCD already maintains.
pub struct Handle {
    queue: DispatchRetained<DispatchQueue>,
}

impl Handle {
    /// Build a fresh serial queue labelled for diagnostics.  The label is
    /// visible in macOS profiling tools (Instruments, dtrace) and helps
    /// distinguish our queue from Apple's internals.
    pub fn new() -> Self {
        let queue = DispatchQueue::new("one.lyn.script-jail.vm", DispatchQueueAttr::SERIAL);
        Self { queue }
    }

    /// Borrow the underlying queue for handoff into VZ APIs that expect a
    /// `&DispatchQueue` reference.
    pub fn queue(&self) -> &DispatchQueue {
        &self.queue
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        // `DispatchRetained::clone` calls `dispatch_retain` under the hood;
        // both handles end up pointing at the same GCD queue object.
        Self {
            queue: self.queue.clone(),
        }
    }
}

impl Default for Handle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_new_returns_a_serial_queue() {
        // We can't introspect the queue's label without crossing into private
        // GCD API, but constructing one and dereferencing the wrapper at
        // least proves the dispatch2 plumbing links.
        let h = Handle::new();
        let _q: &DispatchQueue = h.queue();
    }

    #[test]
    fn handle_clones_share_storage() {
        // GCD's refcount isn't observable from Rust, so we can only assert
        // that cloning + dereferencing both handles yields the same pointer.
        let h = Handle::new();
        let h2 = h.clone();
        let p1: *const DispatchQueue = h.queue();
        let p2: *const DispatchQueue = h2.queue();
        assert_eq!(p1, p2, "clones should reference the same dispatch queue");
        drop(h2);
        // Original handle still usable after the clone goes away.
        let _q: &DispatchQueue = h.queue();
    }
}

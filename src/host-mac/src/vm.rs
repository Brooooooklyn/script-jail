// script-jail — src/host-mac/src/vm.rs
//
// Assemble a VZVirtualMachineConfiguration from a VmConfig and own the
// lifecycle of the resulting VZVirtualMachine.  The helper's main()
// orchestrates this: parse config -> build_config -> boot -> wait on a
// shutdown channel -> exit with the right code.

use std::time::Duration;

use block2::RcBlock;
use crossbeam_channel::Sender;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZFileHandleSerialPortAttachment, VZLinuxBootLoader, VZMACAddress,
    VZNATNetworkDeviceAttachment, VZNetworkDeviceConfiguration, VZSerialPortConfiguration,
    VZSocketDeviceConfiguration, VZStorageDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioNetworkDeviceConfiguration,
    VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};

use crate::config::VmConfig;
use crate::delegate::{DelegateEvent, ShutdownReason, VmDelegate};
use crate::disks::{self, DiskError};
use crate::dispatch;
use crate::frames::Frame;
use crate::vsock::{self, VsockListenerDelegate};

/// How long `boot()` waits on VZ's start completion handler before giving
/// up.  VZ's `startWithCompletionHandler:` normally fires within a second
/// or two; a generous ceiling here just prevents a wedged start (e.g. a
/// kernel that never returns from the bootloader) from hanging the helper
/// forever.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// How long `stop()` waits on VZ's stop completion handler before giving
/// up.  Force-stop is near-instant; the bounded wait just keeps a wedged
/// VZ callback from hanging teardown forever.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Move-only wrapper that asserts `Send` for objc2 `Retained<T>` handles.
///
/// SAFETY: objc2 `Retained<T>` of Virtualization.framework classes
/// (`VZVirtualMachineConfiguration`, `VZVirtioSocketListener`,
/// `VZVirtualMachine`, …) are deliberately `!Send` because VZ requires
/// every method call on the VM and its devices to happen on the single
/// serial dispatch queue passed to `initWithConfiguration:queue:`.
///
/// We uphold that contract by hand: the wrapped objects are only ever
/// *constructed and used* inside `queue.exec_sync` closures, i.e. on that
/// one serial queue.  The only thing that crosses a thread boundary is
/// ownership transfer — the wrapper is built on the queue thread and the
/// owning channel/handle is later picked up on the main thread purely to
/// keep it alive and, eventually, drop it.  Objective-C `release` (what
/// `Retained`'s `Drop` runs) is itself thread-safe.  No VZ method is ever
/// invoked off-queue through this wrapper, so moving the owning handle is
/// sound.
struct AssertSend<T>(T);

// SAFETY: see the doc comment on `AssertSend` above.
unsafe impl<T> Send for AssertSend<T> {}

#[derive(Debug)]
pub enum VmError {
    /// One of the disk paths failed VZ initialization (most often: file
    /// not found, even though config validation already checked the
    /// kernel path).
    Disk(DiskError),
    /// `validateWithError:` rejected the config — typically a mismatch
    /// between vcpu/memory and the host's capabilities, or an unsupported
    /// device combination.
    Validation(String),
    /// VZ's start callback returned non-nil error.
    Boot(String),
    /// A required input file is missing.  Distinguished from Validation
    /// so the smoke test's grep on "kernel_path" can latch onto it.
    FileNotFound(String),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::Disk(e) => write!(f, "{e}"),
            VmError::Validation(msg) => write!(f, "vm validation error: {msg}"),
            VmError::Boot(msg) => write!(f, "vm boot error: {msg}"),
            VmError::FileNotFound(msg) => write!(f, "vm file not found: {msg}"),
        }
    }
}

impl std::error::Error for VmError {}

impl From<DiskError> for VmError {
    fn from(e: DiskError) -> Self {
        VmError::Disk(e)
    }
}

/// Strong references the helper has to keep alive for the duration of the
/// VM.  In particular, VZVirtualMachine's `delegate` property is *weak*,
/// so dropping `_delegate` would silently dis-arm guest callbacks.
pub struct VmHandle {
    pub vm: Retained<VZVirtualMachine>,
    pub _delegate: Retained<VmDelegate>,
    pub _listener_delegate: Retained<VsockListenerDelegate>,
    pub _dispatch: dispatch::Handle,
    /// JoinHandle for the `script-jail-shutdown-router` thread.  Stashed
    /// here so a future `Drop` impl can join on shutdown to keep the router
    /// from racing against `main()`'s exit on error paths.  Wrapped in
    /// `Option<_>` so that future `Drop` impl can `.take()` it.
    pub _router_thread: Option<std::thread::JoinHandle<()>>,
}

impl VmHandle {
    /// Forward the host's `go\n` handshake to the guest's vsock connection.
    ///
    /// Returns `Ok(false)` if the guest has not connected yet — callers
    /// should retry briefly.  `VsockListenerDelegate` is `Send + Sync`, so
    /// the underlying delegate can equally be reached from another thread.
    pub fn post_go(&self) -> std::io::Result<bool> {
        self._listener_delegate.post_go()
    }

    /// Hand out a cloned strong reference to the vsock listener delegate.
    ///
    /// `VsockListenerDelegate` is `Send + Sync` (guarded by the
    /// `assert_send`/`assert_sync` tests in `vsock.rs`), so the returned
    /// `Retained` can be moved into another thread — e.g. `main.rs`'s
    /// stdin-forwarding thread, which calls `post_go()` on it.
    pub fn listener_delegate(&self) -> Retained<VsockListenerDelegate> {
        Retained::clone(&self._listener_delegate)
    }

    /// Force-stop the VZ VM so the helper can exit without orphaning a VM
    /// process.  Synchronous: blocks on VZ's stop completion handler (with a
    /// bounded timeout) before returning.
    ///
    /// `main.rs` calls this after its frame loop ends.  The guest never
    /// powers itself off cleanly on the success path (orchestrate.sh exit ->
    /// PID 1 exit -> kernel panic-reboot), so without an explicit stop the
    /// VM would keep running after the helper had everything it needs.  If
    /// the guest *did* halt itself (early-FATAL `busybox poweroff`), the VM
    /// is already Stopped/Error and `canStop` is false — this is then a
    /// no-op.
    pub fn stop(&self) {
        // VZ requires every VZVirtualMachine method to run on the serial
        // queue from `initWithConfiguration:queue:`.  The `Retained` is
        // `!Send`, so wrap a clone in `AssertSend` to move it into the
        // `exec_sync` closure (see `AssertSend`'s doc comment).
        let vm = AssertSend(Retained::clone(&self.vm));
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);

        self._dispatch.queue().exec_sync(move || {
            let vm = vm;
            // SAFETY: `canStop` is a property read on a valid VZVirtualMachine;
            // this closure body runs on the VM's serial queue.
            if !unsafe { vm.0.canStop() } {
                // Already Stopped/Error (guest powered itself off).  Nothing
                // to do — signal completion so the caller stops waiting.
                let _ = done_tx.send(());
                return;
            }

            // The completion handler runs later on this same serial queue.
            let done_tx = done_tx.clone();
            let completion = RcBlock::new(move |err: *mut NSError| {
                if !err.is_null() {
                    // SAFETY: VZ passes a non-null, autoreleased NSError
                    // valid for the duration of this callback.
                    let nserror: &NSError = unsafe { &*err };
                    eprintln!(
                        "script-jail-vm: VZ stop reported error: {}",
                        nserror.localizedDescription()
                    );
                }
                let _ = done_tx.send(());
            });
            // SAFETY: `vm` is a valid VZVirtualMachine; `stopWithCompletionHandler:`
            // must run on the VM's queue, which is where we are.  The
            // RcBlock outlives the call (VZ retains it until it fires).
            unsafe { vm.0.stopWithCompletionHandler(&completion) };
        });

        // Block until the completion handler fires, bounded so a wedged VZ
        // callback can't hang teardown forever.
        if done_rx.recv_timeout(STOP_TIMEOUT).is_err() {
            eprintln!("script-jail-vm: VZ stop completion timed out after {STOP_TIMEOUT:?}");
        }
    }
}

/// Pure builder for the VZVirtualMachineConfiguration that VZ will accept.
///
/// Returns the assembled config or an error if any of the per-device
/// builders rejected the input.  The caller is responsible for invoking
/// `validateWithError:` (we don't here — it requires Virtualization.framework
/// to be available, which prevents tests from exercising the assembly
/// surface on machines without the entitlement).
pub fn build_config(cfg: &VmConfig) -> Result<Retained<VZVirtualMachineConfiguration>, VmError> {
    // Pre-flight: cover the obvious file-not-found cases before we touch
    // VZ.  Validation in config::parse already verifies kernel_path, so
    // this layer is just a defense-in-depth + clearer error site for the
    // disk paths.
    for (label, path) in [
        ("rootfs_disk_path", &cfg.rootfs_disk_path),
        ("repo_disk_path", &cfg.repo_disk_path),
    ] {
        if !path.exists() {
            return Err(VmError::FileNotFound(format!(
                "{label} does not exist: {}",
                path.display()
            )));
        }
    }

    // SAFETY: each unsafe block is annotated with the specific contract
    // we're upholding.  All Retained<T> handles live until the function
    // returns or are consumed by an `init`-family method that takes
    // ownership.

    let config = unsafe { VZVirtualMachineConfiguration::new() };

    // Boot loader: Linux kernel + optional initramfs.
    let kernel_str = NSString::from_str(&cfg.kernel_path.to_string_lossy());
    // `fileURLWithPath:` is a safe Foundation class method.
    let kernel_url: Retained<NSURL> = NSURL::fileURLWithPath(&kernel_str);

    let bootloader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    let cmdline = NSString::from_str(&cfg.kernel_cmdline);
    unsafe { bootloader.setCommandLine(&cmdline) };

    if let Some(initramfs_path) = cfg.initramfs_path.as_ref() {
        let initramfs_str = NSString::from_str(&initramfs_path.to_string_lossy());
        let initramfs_url: Retained<NSURL> = NSURL::fileURLWithPath(&initramfs_str);
        unsafe { bootloader.setInitialRamdiskURL(Some(&initramfs_url)) };
    }

    // SAFETY: bootloader is a concrete VZBootLoader subclass; setBootLoader
    // takes Option<&VZBootLoader>.
    unsafe { config.setBootLoader(Some(&bootloader)) };

    // CPU + memory.  VZ validates the ranges at validateWithError: time.
    unsafe { config.setCPUCount(cfg.vcpu_count as usize) };
    unsafe { config.setMemorySize(cfg.memory_mb * 1024 * 1024) };

    // Storage devices: rootfs (rw), repo (rw).
    let rootfs = disks::make_block_device(&cfg.rootfs_disk_path, false)?;
    let repo = disks::make_block_device(&cfg.repo_disk_path, false)?;
    // Best-effort identifier assignment — failure here is non-fatal (VZ
    // accepts an empty identifier), but the guest's by-id symlinks are
    // nicer when these are present.  Surface failures via stderr so a
    // mismatched identifier is at least visible during triage instead of
    // silently broken.
    //
    // VZ caps virtio block-device identifiers at 20 bytes, so keep these
    // short.
    for (device, ident) in [(&rootfs, "script-jail-rootfs"), (&repo, "script-jail-repo")] {
        if let Err(err) = disks::set_identifier(device, ident) {
            eprintln!("script-jail-vm: warning: set_identifier({ident}) failed: {err}");
        }
    }

    // SAFETY: each `cast_unchecked` upcasts a concrete VZVirtio*Configuration
    // to its abstract superclass, which is always valid for these types
    // (verified by objc2-virtualization's extern_class declarations).
    let storage_devices: Retained<NSArray<VZStorageDeviceConfiguration>> = unsafe {
        NSArray::from_retained_slice(&[
            Retained::cast_unchecked::<VZStorageDeviceConfiguration>(rootfs),
            Retained::cast_unchecked::<VZStorageDeviceConfiguration>(repo),
        ])
    };
    unsafe { config.setStorageDevices(&storage_devices) };

    // Kernel-console serial port.  The guest's `console=hvc0` cmdline
    // routes early-boot + kernel log output to this virtio console; we
    // attach its *writing* end to the helper's stderr so guest boot logs
    // are visible during triage.  Reading is None — the kernel console is
    // output-only from the host's point of view.
    let console_serial = unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() };
    // `fileHandleWithStandardError` is a safe Foundation class method.
    let stderr_handle: Retained<NSFileHandle> = NSFileHandle::fileHandleWithStandardError();
    // SAFETY: stderr_handle is a valid NSFileHandle with a live fd; the
    // attachment retains its own strong reference.  Passing None for the
    // reading handle is explicitly allowed by the API contract.
    let console_attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            None,
            Some(&stderr_handle),
        )
    };
    // SAFETY: console_attachment is a concrete VZSerialPortAttachment
    // subclass; setAttachment takes Option<&VZSerialPortAttachment>.
    unsafe { console_serial.setAttachment(Some(&console_attachment)) };
    // SAFETY: VZVirtioConsoleDeviceSerialPortConfiguration inherits from
    // VZSerialPortConfiguration.
    let serial_ports: Retained<NSArray<VZSerialPortConfiguration>> = unsafe {
        NSArray::from_retained_slice(&[Retained::cast_unchecked::<VZSerialPortConfiguration>(
            console_serial,
        )])
    };
    unsafe { config.setSerialPorts(&serial_ports) };

    // Vsock device.  Listener registration happens at boot time (vm.rs's
    // `boot()` after VZ has materialised the socketDevice).
    let vsock_device = unsafe { VZVirtioSocketDeviceConfiguration::new() };
    // SAFETY: VZVirtioSocketDeviceConfiguration inherits from
    // VZSocketDeviceConfiguration.
    let socket_devices: Retained<NSArray<VZSocketDeviceConfiguration>> = unsafe {
        NSArray::from_retained_slice(&[Retained::cast_unchecked::<VZSocketDeviceConfiguration>(
            vsock_device,
        )])
    };
    unsafe { config.setSocketDevices(&socket_devices) };

    // Optional NAT network device.
    if cfg.enable_network {
        let net_attachment = unsafe { VZNATNetworkDeviceAttachment::new() };
        let net_device = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
        // SAFETY: net_attachment is a valid VZNetworkDeviceAttachment; we
        // also assign a stable, locally-administered MAC so the guest's
        // dhclient lease is reproducible across runs.  The 06: prefix
        // signals a locally-administered unicast address.
        let mac_str = NSString::from_str("06:00:ac:10:00:02");
        let mac = unsafe { VZMACAddress::initWithString(VZMACAddress::alloc(), &mac_str) };
        if let Some(mac) = mac {
            unsafe { net_device.setMACAddress(&mac) };
        }
        unsafe { net_device.setAttachment(Some(&net_attachment)) };
        // SAFETY: VZVirtioNetworkDeviceConfiguration inherits from
        // VZNetworkDeviceConfiguration.
        let net_devices: Retained<NSArray<VZNetworkDeviceConfiguration>> = unsafe {
            NSArray::from_retained_slice(&[
                Retained::cast_unchecked::<VZNetworkDeviceConfiguration>(net_device),
            ])
        };
        unsafe { config.setNetworkDevices(&net_devices) };
    }

    Ok(config)
}

/// Boot the configured VM on the supplied dispatch queue.  Synchronous
/// startup: blocks on the GCD start callback before returning.  The
/// returned VmHandle owns every strong reference needed to keep the VM
/// alive; dropping it abandons the VM (which will shut down asynchronously).
///
/// VZ requires every operation on a `VZVirtualMachine` and its devices to
/// run on the serial dispatch queue passed to `initWithConfiguration:queue:`
/// — calling them off-queue trips `_dispatch_assert_queue_fail`.  So VM
/// construction, delegate wiring, vsock-listener registration and the start
/// call all happen inside a single `queue.exec_sync` block.  Config
/// validation may run off-queue and is done first.
pub fn boot(
    cfg: &VmConfig,
    config: Retained<VZVirtualMachineConfiguration>,
    dispatch_handle: dispatch::Handle,
    shutdown_tx: Sender<ShutdownReason>,
    frame_tx: Sender<Frame>,
) -> Result<VmHandle, VmError> {
    // Wire the delegate before constructing the VM so VZ sees a fully-
    // formed delegate object at setDelegate: time.
    let delegate = VmDelegate::new();
    let (event_tx, event_rx) = crossbeam_channel::unbounded::<DelegateEvent>();
    delegate.attach_tx(event_tx);

    // Bridge DelegateEvent -> ShutdownReason on a small router thread.
    // We stash the JoinHandle in VmHandle (below) so teardown can join on
    // it rather than detaching the thread.
    let router_thread = std::thread::Builder::new()
        .name("script-jail-shutdown-router".into())
        .spawn(move || {
            for ev in event_rx {
                let reason = match ev {
                    DelegateEvent::GuestStopped => ShutdownReason::GuestStopped,
                    DelegateEvent::StoppedWithError(msg) => {
                        eprintln!("script-jail-vm: VZ stopped with error: {msg}");
                        ShutdownReason::VzError
                    }
                };
                if shutdown_tx.send(reason).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| VmError::Boot(format!("failed to spawn router thread: {e}")))?;

    // Validate the assembled config before handing it to initWithConfiguration:.
    // This is safe to run off the dispatch queue.
    // SAFETY: config is a fully-formed VZVirtualMachineConfiguration.
    unsafe { config.validateWithError() }.map_err(|err| VmError::Validation(format!("{err:?}")))?;

    // Build the vsock listener up-front.  `VsockListenerDelegate` is
    // `Send + Sync`, so it (and the listener built from it) can cross into
    // the `exec_sync` closure without an `AssertSend` wrapper for the
    // delegate itself — but the `Retained<VZVirtioSocketListener>` is a
    // framework object, so it needs the wrapper.
    let listener_delegate = VsockListenerDelegate::new(cfg.vsock_port, frame_tx);
    let listener = vsock::build_listener(&listener_delegate);

    // Channels carrying values *out of* the dispatch queue:
    //   - `vm_tx`/`vm_rx`: the constructed VZVirtualMachine handle.
    //   - `start_tx`/`start_rx`: VZ's asynchronous start result.
    let (vm_tx, vm_rx) = crossbeam_channel::bounded::<AssertSend<Retained<VZVirtualMachine>>>(1);
    let (start_tx, start_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);

    // The closure must be `Send`; `config`, `listener` and the delegate's
    // `as_protocol()` reference are objc objects, so we move them across as
    // `AssertSend`.  See `AssertSend`'s doc comment for why this is sound:
    // every VZ call below runs on the serial queue.
    let vsock_port = cfg.vsock_port;
    let config = AssertSend(config);
    let listener = AssertSend(listener);
    let delegate_for_queue = AssertSend(Retained::clone(&delegate));
    // The closure both runs *on* the serial queue and needs a handle to
    // *that same queue* to pass to `initWithConfiguration:queue:`.  Drive
    // `exec_sync` through `dispatch_handle` (which `boot()` keeps) and move
    // a separate clone into the closure for VM construction.
    let queue_handle = dispatch_handle.clone();

    dispatch_handle.queue().exec_sync(move || {
        let config = config;
        let listener = listener;
        let delegate_for_queue = delegate_for_queue;

        // Build the VM on the dispatch queue.
        // SAFETY: `queue_handle` wraps the serial queue we created and own;
        // this closure body runs on that queue.
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &config.0,
                queue_handle.queue(),
            )
        };
        // SAFETY: delegate is a fully-formed VZVirtualMachineDelegate.
        unsafe { vm.setDelegate(Some(delegate_for_queue.0.as_protocol())) };

        // Register the vsock listener on the configured port.
        // SAFETY: socketDevices is non-empty (build_config added one).
        let socket_devices = unsafe { vm.socketDevices() };
        if let Some(socket_device) = socket_devices.firstObject() {
            // Downcast to the concrete VZVirtioSocketDevice so we can call
            // setSocketListener:forPort:.
            // SAFETY: VZVirtualMachine.socketDevices is documented to
            // contain VZVirtioSocketDevice instances when a
            // VZVirtioSocketDeviceConfiguration was added (the only kind we
            // add).  setSocketListener:forPort: must run on the VM's queue,
            // which is exactly where this closure executes.
            let virtio_socket =
                unsafe { Retained::cast_unchecked::<VZVirtioSocketDevice>(socket_device) };
            unsafe { virtio_socket.setSocketListener_forPort(&listener.0, vsock_port) };
        }

        // Kick off start.  The completion handler is called later, also on
        // this serial queue; it forwards the result to `start_rx`.
        let start_tx = start_tx.clone();
        let completion = RcBlock::new(move |err: *mut NSError| {
            let result = if err.is_null() {
                Ok(())
            } else {
                // SAFETY: VZ passes a non-null, autoreleased NSError that
                // is valid for the duration of this callback.
                let nserror: &NSError = unsafe { &*err };
                Err(nserror.localizedDescription().to_string())
            };
            let _ = start_tx.send(result);
        });
        // SAFETY: `vm` is a valid VZVirtualMachine; `startWithCompletionHandler:`
        // must be invoked on the VM's queue, which is where we are.  The
        // RcBlock outlives the call (VZ retains it until it fires).
        unsafe { vm.startWithCompletionHandler(&completion) };

        // Hand the VM handle back out to `boot()`.  `vm_tx` is bounded(1)
        // and we send exactly once, so this never blocks.
        let _ = vm_tx.send(AssertSend(vm));
    });

    // `exec_sync` has returned: the VM exists and start has been kicked off.
    let vm = vm_rx
        .recv()
        .map_err(|_| VmError::Boot("VM handle channel disconnected".into()))?
        .0;

    // Block on VZ's start completion handler.  A generous timeout keeps a
    // wedged start from hanging the helper indefinitely.
    match start_rx.recv_timeout(START_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => return Err(VmError::Boot(msg)),
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
            return Err(VmError::Boot("start timed out".into()));
        }
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
            return Err(VmError::Boot(
                "start completion channel disconnected".into(),
            ));
        }
    }

    Ok(VmHandle {
        vm,
        _delegate: delegate,
        _listener_delegate: listener_delegate,
        _dispatch: dispatch_handle,
        _router_thread: Some(router_thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("script-jail-host-mac-vm-test-{name}"));
        let _ = fs::File::create(&p).and_then(|mut f| f.write_all(b""));
        p
    }

    fn base_cfg(kernel: &std::path::Path, rootfs: &std::path::Path) -> VmConfig {
        VmConfig {
            kernel_path: kernel.to_path_buf(),
            initramfs_path: None,
            kernel_cmdline: "console=hvc0".into(),
            rootfs_disk_path: rootfs.to_path_buf(),
            repo_disk_path: rootfs.to_path_buf(),
            vsock_uds_path: "/tmp/script-jail-vsock".into(),
            vsock_port: 10242,
            vcpu_count: 2,
            memory_mb: 2048,
            enable_network: true,
        }
    }

    #[test]
    fn build_config_errors_on_missing_rootfs() {
        let kernel = tmp("vm-kernel-missing-rootfs");
        let mut cfg = base_cfg(&kernel, &kernel);
        cfg.rootfs_disk_path = "/no/such/rootfs.img".into();
        match build_config(&cfg) {
            Err(VmError::FileNotFound(msg)) => {
                assert!(msg.contains("rootfs_disk_path"), "got: {msg}");
            }
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn build_config_errors_on_missing_repo_disk() {
        let kernel = tmp("vm-kernel-missing-repo");
        let rootfs = tmp("vm-rootfs-missing-repo");
        let mut cfg = base_cfg(&kernel, &rootfs);
        cfg.repo_disk_path = "/no/such/repo.img".into();
        match build_config(&cfg) {
            Err(VmError::FileNotFound(msg)) => {
                assert!(msg.contains("repo_disk_path"), "got: {msg}");
            }
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }

    // NOTE: a "happy-path" build_config test would require Virtualization.framework
    // to be reachable AND a real entitlement. The file-not-found branch is the
    // reliable CI smoke path; real boot coverage is artifact-gated.
}

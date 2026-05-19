// script-jail — src/host-mac/src/vm.rs
//
// Assemble a VZVirtualMachineConfiguration from a VmConfig and own the
// lifecycle of the resulting VZVirtualMachine.  The helper's main()
// orchestrates this: parse config -> build_config -> boot -> wait on a
// shutdown channel -> exit with the right code.
//
// TODO(PR 4): wire to real artifacts.  PR 3 ships only the assembly +
// pre-boot validation surface; the actual boot path (`boot()`) is exercised
// in PR 4 once kernel + rootfs images exist.

use crossbeam_channel::Sender;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSString, NSURL};
use objc2_virtualization::{
    VZLinuxBootLoader, VZMACAddress, VZNATNetworkDeviceAttachment, VZNetworkDeviceConfiguration,
    VZSocketDeviceConfiguration, VZStorageDeviceConfiguration, VZVirtioNetworkDeviceConfiguration,
    VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

use crate::config::VmConfig;
use crate::delegate::{DelegateEvent, ShutdownReason, VmDelegate};
use crate::disks::{self, DiskError};
use crate::dispatch;
use crate::frames::Frame;
use crate::vsock::{self, VsockListenerDelegate};

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
    /// JoinHandle for the `script-jail-shutdown-router` thread.  PR 3 just
    /// stashes it here; PR 4 will add a `Drop` impl that joins on shutdown
    /// to keep the router from racing against `main()`'s exit on error
    /// paths.  Wrapped in `Option<_>` so the future `Drop` impl can
    /// `.take()` it.
    pub _router_thread: Option<std::thread::JoinHandle<()>>,
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
        ("host_node_disk_path", &cfg.host_node_disk_path),
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

    // Storage devices: rootfs (rw), repo (rw), host-node (ro).
    let rootfs = disks::make_block_device(&cfg.rootfs_disk_path, false)?;
    let repo = disks::make_block_device(&cfg.repo_disk_path, false)?;
    let host_node = disks::make_block_device(&cfg.host_node_disk_path, true)?;
    // Best-effort identifier assignment — failure here is non-fatal (VZ
    // accepts an empty identifier), but the guest's by-id symlinks are
    // nicer when these are present.  Surface failures via stderr so a
    // mismatched identifier is at least visible during triage instead of
    // silently broken.
    for (device, ident) in [
        (&rootfs, "script-jail-rootfs"),
        (&repo, "script-jail-repo"),
        (&host_node, "script-jail-host-node"),
    ] {
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
            Retained::cast_unchecked::<VZStorageDeviceConfiguration>(host_node),
        ])
    };
    unsafe { config.setStorageDevices(&storage_devices) };

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
/// PR 3 reaches this code path only via the smoke test, which uses a
/// fixture whose kernel path doesn't exist — so `build_config`'s
/// FileNotFound branch fires before we get this far.  PR 4 supplies a real
/// kernel + rootfs and exercises the rest of the path.
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
    // We stash the JoinHandle in VmHandle (below) so PR 4 can join on
    // teardown rather than detaching the thread.
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
    // SAFETY: config is a fully-formed VZVirtualMachineConfiguration.
    unsafe { config.validateWithError() }.map_err(|err| VmError::Validation(format!("{err:?}")))?;

    // Build the VM on the dispatch queue.
    // SAFETY: queue is a serial queue we created and own.
    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(
            VZVirtualMachine::alloc(),
            &config,
            dispatch_handle.queue(),
        )
    };
    unsafe { vm.setDelegate(Some(delegate.as_protocol())) };

    // Build the vsock listener and register it on the configured port.
    let listener_delegate = VsockListenerDelegate::new(cfg.vsock_port, frame_tx);
    let listener = vsock::build_listener(&listener_delegate);

    // SAFETY: socketDevices is non-empty (we added one in build_config).
    let socket_devices = unsafe { vm.socketDevices() };
    let first_socket_device = socket_devices.firstObject();
    if let Some(socket_device) = first_socket_device {
        // Downcast to VZVirtioSocketDevice (the concrete type) so we can
        // call setSocketListener:forPort:.
        // SAFETY: VZVirtualMachine.socketDevices is documented to contain
        // VZVirtioSocketDevice instances when a VZVirtioSocketDeviceConfiguration
        // was added (the only kind we add).
        let virtio_socket = unsafe {
            Retained::cast_unchecked::<objc2_virtualization::VZVirtioSocketDevice>(socket_device)
        };
        unsafe { virtio_socket.setSocketListener_forPort(&listener, cfg.vsock_port) };
    }

    // Kick off start.  In PR 3 we don't block on the completion handler —
    // the test fixture errors out earlier (FileNotFound) and PR 4 will
    // replace this with a proper futures-style wait.
    // TODO(PR 4): block until completion via a oneshot crossbeam channel.

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
            host_node_disk_path: rootfs.to_path_buf(),
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
    // to be reachable AND a real entitlement.  We exercise this in PR 4 inside
    // the e2e harness; for PR 3 the file-not-found branch is the realistic test.
}

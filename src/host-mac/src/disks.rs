// script-jail — src/host-mac/src/disks.rs
//
// Pure builders for VZVirtioBlockDeviceConfiguration.  Each call wires a
// VZDiskImageStorageDeviceAttachment to a fresh Virtio block device.
//
// Three of these are attached to the VM in src/host-mac/src/vm.rs:
//   - rootfs  (rw)  — ubuntu ext4 image, mounted as `/` in the guest.
//   - repo    (rw)  — host repo bind-mounted at `/work/repo` in the guest.
//   - host-node (ro) — Node toolchain ext4 image, mounted at `/work/node`.
//
// PR 3 only builds these; the test in vm.rs verifies the assembly compiles
// and the API contracts hold.  Real boot is PR 4-5.

use std::path::Path;

use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZStorageDeviceAttachment, VZVirtioBlockDeviceConfiguration,
};

#[derive(Debug)]
pub enum DiskError {
    /// VZ initWithURL:readOnly:error: returned non-nil error — the disk
    /// path may be unreadable, the file may have an unsupported format,
    /// or sandbox entitlements may be missing.
    Attachment(String),
}

impl std::fmt::Display for DiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskError::Attachment(msg) => write!(f, "disk attachment error: {msg}"),
        }
    }
}

impl std::error::Error for DiskError {}

/// Build a Virtio block device backed by a raw disk image on disk.
///
/// SAFETY: All calls into objc2-virtualization are `unsafe` because the
/// underlying Obj-C contracts are not encodable in Rust.  We uphold them by
/// (a) only constructing on macOS — caller-enforced via target_os = "macos",
/// (b) keeping `Retained<T>` around until the VM config has consumed it,
/// and (c) passing well-formed NSURL/NSString objects.
pub fn make_block_device(
    path: &Path,
    read_only: bool,
) -> Result<Retained<VZVirtioBlockDeviceConfiguration>, DiskError> {
    let path_str = NSString::from_str(&path.to_string_lossy());

    // `fileURLWithPath:` is a safe Foundation class method in objc2-foundation
    // 0.3 — no `unsafe` needed.
    let url: Retained<NSURL> = NSURL::fileURLWithPath(&path_str);

    // SAFETY: `url` is a valid file URL.  VZ may return an NSError if the
    // file is unreadable; we wrap that into our DiskError so the caller
    // gets a typed result rather than an Obj-C exception.
    let attachment = unsafe {
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &url,
            read_only,
        )
    }
    .map_err(|err| DiskError::Attachment(format!("{err:?}")))?;

    // Up-cast to the abstract VZStorageDeviceAttachment expected by the
    // block-device initializer.
    let abstract_attachment: &VZStorageDeviceAttachment = &attachment;

    // SAFETY: `abstract_attachment` is non-null and lives at least as long
    // as this call; the block device retains its own strong reference.
    let block_device = unsafe {
        VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            abstract_attachment,
        )
    };

    Ok(block_device)
}

/// Convenience helper: tell the block-device about its identifier (used to
/// surface a stable `/dev/disk/by-id/...` symlink inside the guest).
///
/// This is wrapped out so vm.rs can stay short.  `identifier` must satisfy
/// VZ's validation (lowercase, 1..=20 chars, alnum + dash); the caller
/// supplies a fixed literal.
pub fn set_identifier(
    device: &VZVirtioBlockDeviceConfiguration,
    identifier: &str,
) -> Result<(), DiskError> {
    let ns_id = NSString::from_str(identifier);
    // SAFETY: device and ns_id are non-null; VZ validates the value.
    unsafe {
        VZVirtioBlockDeviceConfiguration::validateBlockDeviceIdentifier_error(&ns_id)
            .map_err(|e| DiskError::Attachment(format!("invalid block identifier: {e:?}")))?;
        device.setBlockDeviceIdentifier(&ns_id);
    }
    Ok(())
}

// disks.rs has no unit tests of its own — every call into VZ requires a
// live framework session, which CI runners can't always give us.  vm.rs's
// `build_config` test exercises this module indirectly with a fixture.

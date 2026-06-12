// script-jail — src/host-mac/src/config.rs
//
// VmConfig: the JSON document the Node CLI hands to the Rust helper.  The
// shape mirrors src/cli/spawn-vm.ts's VmConfig plus the extra fields the VZ
// runner needs (kernel path, vsock port, vCPU/memory). Keeping the schema
// in Rust separate from the TS one is intentional: it keeps the helper's
// validation boundary independent of the Node-side type.
//
// Validation runs at parse time: bad files fail fast with a clear message
// before we touch Virtualization.framework.  The `Validation` variant carries
// the offending field name + reason so the CLI catch-path can surface it
// verbatim.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VmConfig {
    pub kernel_path: PathBuf,
    #[serde(default)]
    pub initramfs_path: Option<PathBuf>,
    pub kernel_cmdline: String,
    pub rootfs_disk_path: PathBuf,
    pub repo_disk_path: PathBuf,
    /// Scratch ext4 the guest mounts at `/scratch` for audit artifacts
    /// (strace logs, events JSONL).  Keeps large-repo runs from filling the
    /// guest's small /tmp tmpfs.  Required — the Node CLI always supplies
    /// it, exactly like `repo_disk_path`.
    pub scratch_disk_path: PathBuf,
    /// Reserved for parity with the Linux runner (src/action/firecracker/vsock.ts).
    /// VZ does not consume a host UDS path — the listener lives in-process —
    /// but the field travels with the config so consumers don't have to
    /// branch on host OS when constructing it.
    pub vsock_uds_path: PathBuf,
    pub vsock_port: u32,
    pub vcpu_count: u32,
    pub memory_mb: u64,
    pub enable_network: bool,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Parse(serde_json::Error),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config io error: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
            ConfigError::Validation(msg) => write!(f, "config validation error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Parse(e)
    }
}

/// Parse + validate a VmConfig from a JSON file on disk.
///
/// The two failure axes (file-not-found vs JSON-malformed vs
/// semantically-invalid) are kept distinct so callers can distinguish "user
/// pointed at the wrong file" from "the file is corrupt".
pub fn parse(path: &Path) -> Result<VmConfig, ConfigError> {
    let bytes = fs::read(path)?;
    let cfg: VmConfig = serde_json::from_slice(&bytes)?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Run the semantic validation pass.  Pure — does not touch the network or
/// any artifact other than the kernel path (which must exist on disk before
/// VZ is ever asked to boot).
pub fn validate(cfg: &VmConfig) -> Result<(), ConfigError> {
    if !cfg.kernel_path.exists() {
        return Err(ConfigError::Validation(format!(
            "kernel_path does not exist: {}",
            cfg.kernel_path.display()
        )));
    }
    if let Some(initramfs) = cfg.initramfs_path.as_ref() {
        if !initramfs.exists() {
            return Err(ConfigError::Validation(format!(
                "initramfs_path does not exist: {}",
                initramfs.display()
            )));
        }
    }
    if !(1..=32).contains(&cfg.vcpu_count) {
        return Err(ConfigError::Validation(format!(
            "vcpu_count out of range (1..=32): {}",
            cfg.vcpu_count
        )));
    }
    if !(128..=65_536).contains(&cfg.memory_mb) {
        return Err(ConfigError::Validation(format!(
            "memory_mb out of range (128..=65536): {}",
            cfg.memory_mb
        )));
    }
    if !(1..=65_535).contains(&cfg.vsock_port) {
        return Err(ConfigError::Validation(format!(
            "vsock_port out of range (1..=65535): {}",
            cfg.vsock_port
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_file(name: &str, body: &str) -> PathBuf {
        // Build a path inside the cargo target dir so concurrent tests
        // don't collide and so cleanup is automatic when the dir is wiped.
        let mut p = std::env::temp_dir();
        p.push(format!("script-jail-host-mac-test-{name}"));
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    fn touch(name: &str) -> PathBuf {
        tmp_file(name, "")
    }

    fn base_json(kernel: &Path) -> String {
        format!(
            r#"{{
              "kernel_path": "{}",
              "kernel_cmdline": "console=hvc0",
              "rootfs_disk_path": "/tmp/rootfs.img",
              "repo_disk_path": "/tmp/repo.img",
              "scratch_disk_path": "/tmp/scratch.img",
              "vsock_uds_path": "/tmp/vsock",
              "vsock_port": 10242,
              "vcpu_count": 2,
              "memory_mb": 2048,
              "enable_network": true
            }}"#,
            kernel.display()
        )
    }

    #[test]
    fn parse_returns_ok_for_well_formed_config() {
        let kernel = touch("kernel-ok.bin");
        let cfg_path = tmp_file("config-ok.json", &base_json(&kernel));
        let cfg = parse(&cfg_path).expect("config should parse");
        assert_eq!(cfg.scratch_disk_path, PathBuf::from("/tmp/scratch.img"));
        assert_eq!(cfg.vcpu_count, 2);
        assert_eq!(cfg.memory_mb, 2048);
        assert_eq!(cfg.vsock_port, 10242);
        assert!(cfg.enable_network);
    }

    #[test]
    fn parse_returns_io_for_missing_file() {
        let err = parse(Path::new("/no/such/file.json")).expect_err("missing file");
        assert!(matches!(err, ConfigError::Io(_)), "got {err:?}");
    }

    #[test]
    fn parse_returns_parse_for_malformed_json() {
        let cfg_path = tmp_file("config-malformed.json", "{ not json");
        let err = parse(&cfg_path).expect_err("malformed json");
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn parse_rejects_config_without_scratch_disk_path() {
        // `scratch_disk_path` is required, exactly like `repo_disk_path`:
        // serde rejects the document at parse time with a missing-field
        // error naming the field.
        let kernel = touch("kernel-no-scratch.bin");
        let body = base_json(&kernel).replace("\"scratch_disk_path\": \"/tmp/scratch.img\",", "");
        let cfg_path = tmp_file("config-no-scratch.json", &body);
        let err = parse(&cfg_path).expect_err("missing scratch_disk_path");
        match err {
            ConfigError::Parse(e) => {
                let msg = e.to_string();
                assert!(msg.contains("scratch_disk_path"), "got: {msg}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_config_without_repo_disk_path() {
        // Companion to the scratch test above: documents that the new field
        // fails the same way the existing required disk field does.
        let kernel = touch("kernel-no-repo.bin");
        let body = base_json(&kernel).replace("\"repo_disk_path\": \"/tmp/repo.img\",", "");
        let cfg_path = tmp_file("config-no-repo.json", &body);
        let err = parse(&cfg_path).expect_err("missing repo_disk_path");
        match err {
            ConfigError::Parse(e) => {
                let msg = e.to_string();
                assert!(msg.contains("repo_disk_path"), "got: {msg}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_kernel() {
        let body = base_json(Path::new("/no/such/kernel"));
        let cfg_path = tmp_file("config-bad-kernel.json", &body);
        let err = parse(&cfg_path).expect_err("missing kernel");
        match err {
            ConfigError::Validation(msg) => assert!(
                msg.contains("kernel_path"),
                "message should mention kernel_path, got: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_zero_vcpu() {
        let kernel = touch("kernel-vcpu.bin");
        let mut body = base_json(&kernel);
        body = body.replace("\"vcpu_count\": 2", "\"vcpu_count\": 0");
        let cfg_path = tmp_file("config-bad-vcpu.json", &body);
        let err = parse(&cfg_path).expect_err("zero vcpu");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("vcpu_count"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_low_memory() {
        let kernel = touch("kernel-mem.bin");
        let mut body = base_json(&kernel);
        body = body.replace("\"memory_mb\": 2048", "\"memory_mb\": 64");
        let cfg_path = tmp_file("config-bad-mem.json", &body);
        let err = parse(&cfg_path).expect_err("low memory");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("memory_mb"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_vsock_port_zero() {
        let kernel = touch("kernel-port.bin");
        let mut body = base_json(&kernel);
        body = body.replace("\"vsock_port\": 10242", "\"vsock_port\": 0");
        let cfg_path = tmp_file("config-bad-port.json", &body);
        let err = parse(&cfg_path).expect_err("port=0");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("vsock_port"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}

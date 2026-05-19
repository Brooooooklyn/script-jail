// script-jail — src/host-mac/src/main.rs
//
// `script-jail-vm`: the macOS-side helper binary spawned by the Node CLI.
// PR 3 ships the full entrypoint, but the actual VM boot is gated on
// artifacts that don't exist until PR 4-5.  The `--smoke` mode exists to
// give CI a regression target: it must reject the fixture config with a
// clear "kernel_path not found" error and exit 64.
//
// Wire conventions:
//   - stdin :  expects a "go\n" line at handshake time, forwarded verbatim
//              to the guest vsock connection.
//   - stdout:  JSONL frames from the guest, one per line.  We never write
//              free-form diagnostics here.
//   - stderr:  every host-side log line.
//
// Exit codes:
//   - 0  : success (guest finished and emitted a `final` frame)
//   - 2  : VZ-side error (boot failure, guest crash)
//   - 64 : pre-boot configuration / argv error (mirrors sysexits EX_USAGE)

use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::thread;

use crossbeam_channel::{select, unbounded};

use script_jail_host_mac::cli::{SubCommand, parse_args, print_usage};
use script_jail_host_mac::config::{self, ConfigError, VmConfig};
use script_jail_host_mac::delegate::ShutdownReason;
use script_jail_host_mac::dispatch;
use script_jail_host_mac::frames::Frame;
use script_jail_host_mac::vm::{self, VmError};

const EXIT_OK: u8 = 0;
const EXIT_VZ_ERROR: u8 = 2;
const EXIT_USAGE: u8 = 64;

fn run() -> u8 {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("script-jail-vm: {msg}");
            print_usage();
            return EXIT_USAGE;
        }
    };

    if args.subcommand == SubCommand::Help {
        print_usage();
        return EXIT_OK;
    }

    // Parse + validate the config document.  Validation errors short-circuit
    // before we touch Virtualization.framework so the CI smoke test can
    // assert on the specific "kernel_path" message.
    let cfg: VmConfig = match config::parse(&args.config_path) {
        Ok(cfg) => cfg,
        Err(ConfigError::Validation(msg)) => {
            eprintln!("script-jail-vm: config validation error: {msg}");
            return EXIT_USAGE;
        }
        Err(err) => {
            eprintln!("script-jail-vm: failed to load config: {err}");
            return EXIT_USAGE;
        }
    };

    if args.smoke {
        eprintln!(
            "script-jail-vm: smoke mode — kernel={} memory_mb={} vcpu_count={}",
            cfg.kernel_path.display(),
            cfg.memory_mb,
            cfg.vcpu_count
        );
    }

    // Build channels for delegate -> shutdown and vsock -> stdout.
    let (shutdown_tx, shutdown_rx) = unbounded::<ShutdownReason>();
    let (frame_tx, frame_rx) = unbounded::<Frame>();
    let dispatch_handle = dispatch::Handle::new();

    // Assemble the VZ configuration.  This is the most likely place for
    // PR 3's smoke test to bail out, because the disk paths in the
    // fixture don't exist.
    let vm_config = match vm::build_config(&cfg) {
        Ok(c) => c,
        Err(VmError::FileNotFound(msg)) => {
            // FileNotFound usually comes from the disk paths; the kernel
            // path was already validated in config::parse, so this branch
            // primarily fires on rootfs/repo/host-node mismatch.
            eprintln!("script-jail-vm: {msg}");
            return EXIT_USAGE;
        }
        Err(err) => {
            eprintln!("script-jail-vm: failed to build VM config: {err}");
            return EXIT_VZ_ERROR;
        }
    };

    // Move (not clone) `frame_tx` into `vm::boot`.  `vm::boot` then owns the
    // only `Sender<Frame>` — apart from the clones the listener delegate
    // makes internally for the reader thread — so when the returned
    // `VmHandle` drops at function exit, all Senders are released and
    // `frame_rx.recv()` returns `Err(Disconnected)`.  That's how the main
    // loop below knows the VM has finished.
    let _handle = match vm::boot(
        &cfg,
        vm_config,
        dispatch_handle,
        shutdown_tx.clone(),
        frame_tx,
    ) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("script-jail-vm: VM boot failed: {err}");
            return EXIT_VZ_ERROR;
        }
    };

    // Forward stdin "go\n" lines to the vsock connection.
    let stdin_thread = thread::Builder::new()
        .name("script-jail-stdin".into())
        .spawn(move || {
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            let mut line = String::new();
            loop {
                line.clear();
                match handle.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if line.trim() == "go" {
                            // TODO(PR 4): post "go" through the vsock writer.
                            // The handle's listener delegate already owns
                            // the fd; PR 4 will route this via a shared
                            // ref + post_go().
                        }
                    }
                }
            }
        })
        .expect("spawn stdin thread");

    // Main loop: ferry frames out to stdout and watch for shutdown.
    //
    // Termination paths:
    //   - `shutdown_rx` carries a ShutdownReason from the router thread when
    //     VZ fires `guestDidStopVirtualMachine:` or `didStopWithError:`.
    //   - `frame_rx.recv()` returns `Err(Disconnected)` once every Sender
    //     held by `vm::boot` (and its listener delegate clones) has dropped
    //     — i.e. the VM teardown has finished.  We treat that as EXIT_OK
    //     because the shutdown branch is the authoritative source of error
    //     reasons; a sender-disconnect with no prior shutdown event would
    //     mean the VM exited without an event-bearing callback, which we
    //     interpret as a clean stop.
    let exit_code = loop {
        select! {
            recv(frame_rx) -> msg => match msg {
                Ok(frame) => {
                    if let Err(e) = emit_frame(&frame) {
                        eprintln!("script-jail-vm: failed to write frame to stdout: {e}");
                        break EXIT_VZ_ERROR;
                    }
                }
                Err(_) => break EXIT_OK,
            },
            recv(shutdown_rx) -> reason => match reason {
                Ok(ShutdownReason::GuestStopped) => break EXIT_OK,
                Ok(ShutdownReason::VzError) => break EXIT_VZ_ERROR,
                Ok(ShutdownReason::PreBootFailure) => break EXIT_USAGE,
                Err(_) => break EXIT_OK,
            },
        }
    };

    let _ = stdin_thread.join();
    exit_code
}

/// Re-serialize a frame to stdout exactly once.  We don't reuse the inbound
/// JSON bytes because the guest may have used compact spacing that varies
/// across boots — re-emitting via serde_json gives us a canonical form the
/// Node-side reader can parse.
fn emit_frame(frame: &Frame) -> io::Result<()> {
    let s = serde_json::to_string(frame).map_err(io::Error::other)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(s.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn main() -> ExitCode {
    ExitCode::from(run())
}

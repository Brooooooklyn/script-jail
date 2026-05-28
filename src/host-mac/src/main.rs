// script-jail — src/host-mac/src/main.rs
//
// `script-jail-vm`: the macOS-side helper binary spawned by the Node CLI.
// The `--smoke` mode gives CI a regression target: it must reject the fixture
// config with a clear "kernel_path not found" error and exit 64.
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

/// Maximum gap the main loop tolerates between frames before declaring the
/// guest wedged.  `crossbeam_channel::after` yields a fresh receiver each
/// `select!` iteration, so this resets whenever a frame arrives.  The
/// longest legitimate gap is boot -> first `handshake`/`fetch_done` while
/// Phase A downloads the Node toolchain and dependencies; 15 minutes is a
/// generous ceiling.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

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

    // Assemble the VZ configuration. This is the most likely place for the
    // smoke fixture to bail out, because the disk paths do not exist.
    let vm_config = match vm::build_config(&cfg) {
        Ok(c) => c,
        Err(VmError::FileNotFound(msg)) => {
            // FileNotFound usually comes from the disk paths; the kernel
            // path was already validated in config::parse, so this branch
            // primarily fires on rootfs/repo mismatch.
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

    // Forward stdin "go\n" lines to the vsock connection.  We grab a
    // cloned, `Send` strong reference to the listener delegate *before*
    // spawning the thread and move it in — `VmHandle` itself is not `Send`.
    //
    // The `JoinHandle` is deliberately detached (not stored): on the
    // success path the CLI never closes our stdin, so this thread stays
    // parked in `read_line()` with no EOF.  Joining it would deadlock.  It
    // does no cleanup that matters; the OS reaps it when `run()` returns.
    let listener_delegate = _handle.listener_delegate();
    thread::Builder::new()
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
                            // Route "go" through the vsock writer.  The
                            // guest connects before it emits `fetch_done`,
                            // so by the time the host sends "go" the
                            // connection normally exists — but a short
                            // retry covers the brief accept-callback race.
                            let mut posted = false;
                            for attempt in 0..20 {
                                match listener_delegate.post_go() {
                                    Ok(true) => {
                                        posted = true;
                                        break;
                                    }
                                    Ok(false) => {
                                        if attempt == 0 {
                                            continue;
                                        }
                                        thread::sleep(std::time::Duration::from_millis(50));
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "script-jail-vm: failed to post 'go' to guest: {e}"
                                        );
                                        break;
                                    }
                                }
                            }
                            if !posted {
                                eprintln!(
                                    "script-jail-vm: 'go' not delivered — no vsock connection"
                                );
                            }
                        }
                    }
                }
            }
        })
        .expect("spawn stdin thread");

    // Main loop: ferry frames out to stdout and watch for shutdown.
    //
    // Termination paths:
    //   - A terminal frame (`final`, or a `fatal` `error`) means the guest
    //     is done.  The guest never powers itself off cleanly on these
    //     paths (orchestrate.sh exit -> PID 1 exit -> kernel panic-reboot),
    //     so `guestDidStop` never fires; the host must break here and tear
    //     the VM down itself — mirroring how the Firecracker host works.
    //   - `shutdown_rx` carries a ShutdownReason from the router thread when
    //     VZ fires `guestDidStopVirtualMachine:` or `didStopWithError:`
    //     (e.g. the early-FATAL `busybox poweroff` path).
    //   - `frame_rx.recv()` returns `Err(Disconnected)` once every Sender
    //     held by `vm::boot` (and its listener delegate clones) has dropped.
    //     We treat that as EXIT_OK because the shutdown branch is the
    //     authoritative source of error reasons.
    //   - The idle watchdog caps the gap between frames; a wedged guest
    //     that emits nothing for `IDLE_TIMEOUT` is declared a VZ error.
    let exit_code = loop {
        select! {
            recv(frame_rx) -> msg => match msg {
                Ok(frame) => {
                    if let Err(e) = emit_frame(&frame) {
                        eprintln!("script-jail-vm: failed to write frame to stdout: {e}");
                        break EXIT_VZ_ERROR;
                    }
                    // A `final` frame, or a `fatal` error frame, is terminal:
                    // the guest agent exits and the kernel panic-reboots, so
                    // no clean power-off / `guestDidStop` follows.  Emit the
                    // frame first (done above), then break.
                    match &frame {
                        Frame::Final(_) => break EXIT_OK,
                        Frame::Error(e) if e.fatal => break EXIT_OK,
                        _ => {}
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
            recv(crossbeam_channel::after(IDLE_TIMEOUT)) -> _ => {
                eprintln!(
                    "script-jail-vm: no guest frame for {IDLE_TIMEOUT:?} — guest appears wedged"
                );
                break EXIT_VZ_ERROR;
            },
        }
    };

    // Tear the VM down regardless of which break path was taken — the guest
    // does not reliably power itself off, so without this the VZ VM would
    // outlive the helper.
    _handle.stop();

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

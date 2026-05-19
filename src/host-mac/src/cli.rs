// script-jail — src/host-mac/src/cli.rs
//
// CLI argument parsing for the `script-jail-vm` binary.  Lives in the
// library crate (rather than `main.rs`) so `cargo test -p
// script-jail-host-mac` can exercise it without compiling the binary
// entrypoint.
//
// The grammar is intentionally tiny — we don't depend on `clap` here
// because the helper is invoked exclusively by the Node CLI; the surface
// only has to be predictable enough that PR 4/5's spawn-vm.ts can construct
// argv without surprises.

use std::path::PathBuf;

/// Parsed CLI invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub subcommand: SubCommand,
    pub config_path: PathBuf,
    pub smoke: bool,
}

/// Subcommand selector.  `Help` short-circuits the rest of the surface; it
/// carries no config path.
#[derive(Debug, PartialEq, Eq)]
pub enum SubCommand {
    Boot,
    Help,
}

/// Write the usage banner to stderr.  Free function so both `main.rs`'s
/// error paths and `--help` can call it without owning a logger.
pub fn print_usage() {
    eprintln!("script-jail-vm — macOS host runner for the script-jail audit");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  script-jail-vm boot --config <path> [--smoke]");
    eprintln!("  script-jail-vm --help");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --config <path>    Path to the VmConfig JSON document.");
    eprintln!("  --smoke            Smoke-test marker; does not change behaviour but");
    eprintln!("                     is whitelisted by CI for the no-fixture exit case.");
    eprintln!("  --help, -h         Show this help and exit 0.");
}

/// Convenience entrypoint used by `main.rs`: collects `std::env::args()`
/// and forwards to [`parse_args_from`].
pub fn parse_args() -> Result<CliArgs, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_args_from(argv.iter().map(String::as_str))
}

/// Core parser.  Takes any iterator of `&str` arguments (already skipping
/// `argv[0]`) so the tests can drive it without touching the real process
/// argv.
pub fn parse_args_from<'a, I>(args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut iter = args.into_iter();
    let subcommand = SubCommand::Boot;
    let mut config_path: Option<PathBuf> = None;
    let mut smoke = false;

    // First positional may be a subcommand; if absent, assume `boot`.
    let mut first = iter.next();
    if let Some(arg) = first {
        match arg {
            "boot" => {
                // "boot" is the default subcommand — already set above; consume the token.
                first = None;
            }
            "--help" | "-h" => {
                return Ok(CliArgs {
                    subcommand: SubCommand::Help,
                    config_path: PathBuf::new(),
                    smoke: false,
                });
            }
            // Otherwise it's an option to the implicit `boot` subcommand;
            // fall through so the loop below picks it up.
            _ => {}
        }
    }

    // Combine the carried-over first token (if any) with the rest.
    let leftovers: Box<dyn Iterator<Item = &str>> = match first {
        Some(s) => Box::new(std::iter::once(s).chain(iter)),
        None => Box::new(iter),
    };

    let mut iter = leftovers.into_iter();
    while let Some(arg) = iter.next() {
        match arg {
            "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--config requires a path argument".to_string())?;
                config_path = Some(PathBuf::from(value));
            }
            "--smoke" => smoke = true,
            "--help" | "-h" => {
                return Ok(CliArgs {
                    subcommand: SubCommand::Help,
                    config_path: PathBuf::new(),
                    smoke: false,
                });
            }
            other => {
                return Err(format!("unrecognised argument: {other}"));
            }
        }
    }

    let config_path = config_path.ok_or_else(|| "--config <path> is required".to_string())?;
    Ok(CliArgs {
        subcommand,
        config_path,
        smoke,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_with_config() {
        let args = parse_args_from(["boot", "--config", "foo.json"]).expect("should parse");
        assert_eq!(args.subcommand, SubCommand::Boot);
        assert_eq!(args.config_path, PathBuf::from("foo.json"));
        assert!(!args.smoke);
    }

    #[test]
    fn help_long_flag() {
        let args = parse_args_from(["--help"]).expect("should parse");
        assert_eq!(args.subcommand, SubCommand::Help);
        // Help carries no config path.
        assert_eq!(args.config_path, PathBuf::new());
    }

    #[test]
    fn help_short_flag() {
        let args = parse_args_from(["-h"]).expect("should parse");
        assert_eq!(args.subcommand, SubCommand::Help);
    }

    #[test]
    fn boot_missing_config_errors() {
        let err = parse_args_from(["boot"]).expect_err("missing config");
        assert!(err.contains("--config"), "got: {err}");
    }

    #[test]
    fn config_without_value_errors() {
        let err = parse_args_from(["boot", "--config"]).expect_err("missing config value");
        assert!(
            err.contains("--config requires"),
            "expected value-required message, got: {err}"
        );
    }

    #[test]
    fn boot_with_smoke_flag() {
        let args = parse_args_from(["boot", "--smoke", "--config", "foo.json"])
            .expect("should parse with smoke flag");
        assert_eq!(args.subcommand, SubCommand::Boot);
        assert_eq!(args.config_path, PathBuf::from("foo.json"));
        assert!(args.smoke);
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = parse_args_from(["nonsense"]).expect_err("unknown subcommand");
        assert!(
            err.contains("unrecognised argument"),
            "expected unrecognised-argument message, got: {err}"
        );
    }

    #[test]
    fn extra_positional_after_config_errors() {
        // Current behaviour: any unrecognised positional token is rejected;
        // the parser does not silently swallow trailing garbage.
        let err =
            parse_args_from(["boot", "--config", "x", "extra"]).expect_err("trailing positional");
        assert!(
            err.contains("unrecognised argument: extra"),
            "expected trailing-arg rejection, got: {err}"
        );
    }

    #[test]
    fn implicit_boot_subcommand_works() {
        // Skipping the explicit `boot` token is the documented shorthand.
        let args = parse_args_from(["--config", "foo.json"]).expect("implicit boot");
        assert_eq!(args.subcommand, SubCommand::Boot);
        assert_eq!(args.config_path, PathBuf::from("foo.json"));
    }
}

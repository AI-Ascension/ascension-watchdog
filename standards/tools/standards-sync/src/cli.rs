//! Command-line parsing, help text, and fatal error reporting.

use crate::Result;
use std::env;
use std::path::PathBuf;
use std::process;

#[derive(Debug, Default)]
pub(crate) struct Cli {
    pub(crate) command: String,
    pub(crate) root: PathBuf,
    pub(crate) source_root: PathBuf,
    pub(crate) target_root: PathBuf,
    pub(crate) repository: String,
    pub(crate) profile_id: String,
    pub(crate) owner: String,
    pub(crate) source_commit: String,
    pub(crate) as_of: Option<String>,
}

pub(crate) fn fail(error: &str) -> ! {
    eprintln!("standards-sync: error: {error}");
    process::exit(1);
}

pub(crate) fn print_help() {
    println!(
        "standards-sync/1\n\nCommands:\n  validate [--root PATH] [--as-of YYYY-MM-DD]\n  fixture-check --root standards/conformance\n  check-bootstrap [--root PATH]\n  sync --source-root PATH --target-root PATH --repository OWNER/NAME --profile-id ID --owner OWNER --source-commit COMMIT\n\nAll operations are local and read-only except sync's deterministic copy into its target."
    );
}

pub(crate) fn parse_cli() -> Result<Cli> {
    let mut values = env::args().skip(1);
    let command = values.next().unwrap_or_else(|| "help".to_owned());
    let mut cli = Cli {
        command,
        root: PathBuf::from("."),
        ..Cli::default()
    };

    while let Some(flag) = values.next() {
        let mut value = || {
            values
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--root" => cli.root = PathBuf::from(value()?),
            "--source-root" => cli.source_root = PathBuf::from(value()?),
            "--target-root" => cli.target_root = PathBuf::from(value()?),
            "--repository" => cli.repository = value()?,
            "--profile-id" => cli.profile_id = value()?,
            "--owner" => cli.owner = value()?,
            "--source-commit" => cli.source_commit = value()?,
            "--as-of" => cli.as_of = Some(value()?),
            flag => return Err(format!("unknown option '{flag}'")),
        }
    }

    Ok(cli)
}

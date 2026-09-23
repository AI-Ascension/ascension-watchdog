//! Small dependency-free operational CLI.

use crate::error::{Result, WatchdogError};
use std::path::PathBuf;

const DEFAULT_CONFIG: &str = "config/watchdog.json";

mod config;
mod job;
mod operator;
mod qualification;
mod release;

/// Execute the command line and return a process exit code.
pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    match execute(args.into_iter().map(Into::into).collect()) {
        Ok(Some(output)) => {
            println!("{output}");
            0
        }
        Ok(None) => 0,
        Err(error) => {
            if let WatchdogError::VerificationFailed(report) = error {
                println!("{report}");
                return 1;
            }
            eprintln!("watchdog: {error}");
            1
        }
    }
}

/// Execute one parsed command and return optional JSON output.
pub fn execute(args: Vec<String>) -> Result<Option<String>> {
    let mut args = args;
    if args.first().is_some_and(|arg| {
        !matches!(
            arg.as_str(),
            "config"
                | "init"
                | "migrate"
                | "doctor"
                | "diagnostics"
                | "components"
                | "preflight"
                | "qualification"
                | "release"
                | "restore"
                | "status"
                | "start"
                | "pause"
                | "resume"
                | "drain"
                | "stop"
                | "quarantine"
                | "retry"
                | "reconcile"
                | "backup"
                | "daemon"
                | "run"
                | "service"
                | "job"
                | "attempt"
                | "help"
                | "version"
                | "--help"
                | "--version"
        )
    }) {
        args.remove(0);
    }
    if args.is_empty() || args[0] == "--help" || args[0] == "help" {
        return Ok(Some(usage().to_string()));
    }
    if args[0] == "--version" || args[0] == "version" {
        return Ok(Some(env!("CARGO_PKG_VERSION").to_string()));
    }
    if args[0] == "migrate" {
        config::require_migration_config(&args)?;
    }
    #[cfg(windows)]
    if args.first().is_some_and(|arg| arg == "service")
        && args
            .iter()
            .position(|arg| arg == "--config")
            .is_some_and(|index| index + 1 >= args.len())
    {
        return Err(WatchdogError::InvalidInput(
            "service --config requires an absolute path".to_owned(),
        ));
    }
    let config_path = take_option(&mut args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let command = args.remove(0);
    match command.as_str() {
        "config" => config::config_command(&mut args, &config_path),
        "init" => config::init_command(&mut args, &config_path),
        "migrate" => config::migration_command(&args, &config_path),
        "doctor" => config::doctor_command(&config_path),
        "diagnostics" => config::diagnostics_command(&config_path),
        "components" => config::components_command(&config_path),
        "preflight" => config::preflight_command(&mut args),
        "qualification" => qualification::qualification_command(&mut args),
        "release" => release::release_command(&mut args, &config_path),
        "restore" => release::restore_command(&mut args, &config_path),
        "status" | "start" | "pause" | "resume" | "drain" | "stop" | "quarantine" | "retry"
        | "reconcile" | "backup" => operator::operator_command(&command, &mut args, &config_path),
        "daemon" | "run" => operator::daemon_command(&mut args, &config_path),
        #[cfg(windows)]
        "service" => crate::windows_service::service_command(&mut args, &config_path),
        #[cfg(not(windows))]
        "service" => Err(WatchdogError::Unsupported(
            "Windows service commands are unavailable on this target".to_owned(),
        )),
        "job" => job::job_command(&mut args, &config_path),
        "attempt" => job::attempt_command(&mut args, &config_path),
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown command {other}; try `watchdog help`"
        ))),
    }
}

fn take_option(args: &mut Vec<String>, name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    args.remove(index);
    (index < args.len()).then(|| args.remove(index))
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    args.iter()
        .position(|arg| arg == name)
        .is_some_and(|index| {
            args.remove(index);
            true
        })
}

fn usage() -> &'static str {
    concat!(
        "ascension-watchdog\n\nUsage:\n",
        "  watchdog config validate [PATH]\n",
        "  watchdog config sample [PATH]\n",
        "  watchdog preflight --state-directory PATH [--reserve-bytes N] [--staging-bytes N] [--backup-bytes N]\n",
        "  watchdog qualification verify-native --evidence PATH --receipt PATH --expected-source-revision SHA\n",
        "  watchdog qualification write-synthetic --source-revision SHA --os OS --receipt-sha256 SHA256 --output PATH\n",
        "  watchdog release inspect --config PATH --release-id ID\n",
        "  watchdog release inspect --manifest PATH --root PATH\n",
        "  watchdog release source-set verify --manifest PATH --repo NAME=PATH [...] [--artifact NAME=PATH [...]]\n",
        "  watchdog release build-set --manifest PATH --plan PATH --repo NAME=PATH [...] [--artifact NAME=PATH [...]] [--scratch PATH]\n",
        "  watchdog release stage-set --manifest PATH --catalog PATH --release-id ID --config PATH --compatibility PATH --role NAME=PATH [...] --repo NAME=PATH [...]\n",
        "  watchdog release activate --config PATH --release-id ID --expected-release-digest DIGEST --idempotency-key KEY\n",
        "  watchdog release rollback --config PATH --release-id ID --expected-release-digest DIGEST --idempotency-key KEY\n",
        "  watchdog restore --config PATH --backup PATH [--database PATH] --rekey\n",
        "  watchdog init --config PATH [--database PATH]\n",
        "  watchdog migrate gateway-health --config PATH\n",
        "  watchdog diagnostics --config PATH\n",
        "  watchdog components --config PATH\n",
        "  watchdog doctor|status|start|pause|resume|drain|stop --config PATH\n",
        "  watchdog quarantine --config PATH --idempotency-key KEY --attempt-id ID --reason REASON\n",
        "  watchdog retry --config PATH --idempotency-key KEY --attempt-id ID [--policy requeue|reconstruction]\n",
        "  watchdog reconcile --config PATH --idempotency-key KEY --target deployment|component|job|attempt [--id ID]\n",
        "  watchdog backup --config PATH --idempotency-key KEY --backup-id ID\n",
        "  watchdog daemon --config PATH [--once]\n",
        "  watchdog service install --config PATH [--executable PATH] [--account NAME]\n",
        "  watchdog service uninstall --config PATH\n",
        "  watchdog job submit --config PATH --idempotency-key KEY --kind KIND [--payload JSON|--payload-file PATH]\n",
        "  watchdog job list|claim|complete|fail --config PATH ...\n\n",
        "Read-only status and doctor never initialize missing state."
    )
}

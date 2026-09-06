//! Small dependency-free operational CLI.

use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::runtime::Supervisor;
use crate::storage::{Store, now_unix_ms};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG: &str = "config/watchdog.json";

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
                | "doctor"
                | "preflight"
                | "release"
                | "status"
                | "start"
                | "pause"
                | "resume"
                | "drain"
                | "stop"
                | "daemon"
                | "run"
                | "job"
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
    let config_path = take_option(&mut args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let command = args.remove(0);
    match command.as_str() {
        "config" => config_command(&mut args, &config_path),
        "init" => init_command(&mut args, &config_path),
        "doctor" => doctor_command(&config_path),
        "preflight" => preflight_command(&mut args),
        "release" => release_command(&mut args),
        "status" => status_command(&config_path),
        "start" => mode_command(&config_path, DesiredMode::Running),
        "pause" => mode_command(&config_path, DesiredMode::Paused),
        "resume" => mode_command(&config_path, DesiredMode::Running),
        "drain" => mode_command(&config_path, DesiredMode::Draining),
        "stop" => mode_command(&config_path, DesiredMode::Stopped),
        "daemon" | "run" => daemon_command(&mut args, &config_path),
        "job" => job_command(&mut args, &config_path),
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown command {other}; try `watchdog help`"
        ))),
    }
}

fn config_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let subcommand = args.first().map(String::as_str).unwrap_or("validate");
    match subcommand {
        "validate" => {
            let path = args.get(1).map_or(config_path, Path::new);
            let config = WatchdogConfig::from_file(path)?;
            Ok(Some(
                json!({
                    "valid": true,
                    "path": path,
                    "deployment_id": config.deployment_id,
                    "database": config.database,
                    "config_digest": config.digest()?,
                })
                .to_string(),
            ))
        }
        "sample" => {
            let path = args.get(1).map_or(config_path, Path::new);
            let config = WatchdogConfig::default();
            config.to_file(path)?;
            Ok(Some(
                json!({"written": path, "config_digest": config.digest()?}).to_string(),
            ))
        }
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown config command {other}"
        ))),
    }
}

fn init_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let mut config = WatchdogConfig::from_file(config_path)?;
    if let Some(database) = take_option(args, "--database") {
        config.database = PathBuf::from(database);
        config.validate()?;
    }
    let supervisor = Supervisor::initialize(config.clone())?;
    Ok(Some(serde_json::to_string(&supervisor.status()?)?))
}

fn release_command(args: &mut Vec<String>) -> Result<Option<String>> {
    if args.first().map(String::as_str) != Some("inspect") {
        return Err(WatchdogError::InvalidInput(
            "release requires inspect".to_owned(),
        ));
    }
    args.remove(0);
    let manifest = take_option(args, "--manifest").ok_or_else(|| {
        WatchdogError::InvalidInput("release inspect requires --manifest".to_owned())
    })?;
    let root = take_option(args, "--root")
        .ok_or_else(|| WatchdogError::InvalidInput("release inspect requires --root".to_owned()))?;
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected release inspect argument".to_owned(),
        ));
    }
    let inspection = crate::release::ReleaseManifest::inspect_document(
        std::fs::File::open(manifest)?,
        Path::new(&root),
    )
    .map_err(WatchdogError::InvalidInput)?;
    Ok(Some(serde_json::to_string(&inspection)?))
}

fn preflight_command(args: &mut Vec<String>) -> Result<Option<String>> {
    let directory = take_option(args, "--state-directory").ok_or_else(|| {
        WatchdogError::InvalidInput("preflight requires --state-directory".to_owned())
    })?;
    let requirements = crate::preflight::DiskRequirements {
        runtime_reserve_bytes: preflight_bytes(args, "--reserve-bytes", 1_073_741_824)?,
        staging_bytes: preflight_bytes(args, "--staging-bytes", 0)?,
        backup_bytes: preflight_bytes(args, "--backup-bytes", 0)?,
    };
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected preflight argument".to_owned(),
        ));
    }
    let inspection = requirements
        .inspect(Path::new(&directory))
        .map_err(WatchdogError::InvalidInput)?;
    if !inspection.admitted {
        return Err(WatchdogError::Conflict(format!(
            "disk headroom insufficient: available={} required={}",
            inspection.available_bytes, inspection.required_bytes
        )));
    }
    Ok(Some(serde_json::to_string(&inspection)?))
}

fn preflight_bytes(args: &mut Vec<String>, option: &str, default: u64) -> Result<u64> {
    take_option(args, option).map_or(Ok(default), |value| {
        value.parse::<u64>().map_err(|_| {
            WatchdogError::InvalidInput(format!("{option} requires an unsigned byte count"))
        })
    })
}

fn doctor_command(config_path: &Path) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let store = Store::open(&config.database, &config)?;
    let integrity_ok = store.integrity_check()?;
    let status = store.status()?;
    Ok(Some(
        json!({
            "config_valid": true,
            "initialized": true,
            "integrity_ok": integrity_ok,
            "durability": status.durability,
            "wal_full": status.durability.is_wal_full(),
            "database": config.database,
        })
        .to_string(),
    ))
}

fn status_command(config_path: &Path) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let store = Store::open(&config.database, &config)?;
    Ok(Some(serde_json::to_string(&store.status()?)?))
}

fn mode_command(config_path: &Path, mode: DesiredMode) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let mut store = Store::open(&config.database, &config)?;
    // The transaction commits intent before a daemon can observe and enact it.
    store.set_desired_mode(mode)?;
    Ok(Some(
        json!({"desired_mode": mode, "database": config.database}).to_string(),
    ))
}

fn daemon_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let once = take_flag(args, "--once");
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(format!(
            "unexpected daemon argument {}",
            args[0]
        )));
    }
    let config = WatchdogConfig::from_file(config_path)?;
    let mut supervisor = Supervisor::open(config)?;
    if once {
        let report = supervisor.reconcile_once(now_unix_ms())?;
        return Ok(Some(serde_json::to_string(&report)?));
    }
    supervisor.run_until_stopped()?;
    Ok(None)
}

fn job_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let subcommand = args.first().map(String::as_str).ok_or_else(|| {
        WatchdogError::InvalidInput("job requires submit/list/claim/complete/fail".to_string())
    })?;
    let config = WatchdogConfig::from_file(config_path)?;
    let mut store = Store::open(&config.database, &config)?;
    match subcommand {
        "submit" => {
            let kind = take_option(args, "--kind")
                .or_else(|| args.get(1).cloned())
                .ok_or_else(|| {
                    WatchdogError::InvalidInput("job submit requires --kind".to_string())
                })?;
            let payload_text = take_option(args, "--payload")
                .or_else(|| args.get(2).cloned())
                .unwrap_or_else(|| "{}".to_string());
            let payload: Value = serde_json::from_str(&payload_text)?;
            Ok(Some(serde_json::to_string(
                &store.submit_job(&kind, &payload)?,
            )?))
        }
        "list" => {
            let limit = take_option(args, "--limit")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|error| {
                    WatchdogError::InvalidInput(format!("invalid job limit: {error}"))
                })?
                .unwrap_or(100);
            Ok(Some(serde_json::to_string(&store.list_jobs(limit)?)?))
        }
        "claim" => {
            let worker = take_option(args, "--worker").unwrap_or_else(|| "cli-worker".to_string());
            Ok(Some(serde_json::to_string(
                &store.claim_next_job(&worker, now_unix_ms())?,
            )?))
        }
        "complete" => {
            let id = args.get(1).cloned().ok_or_else(|| {
                WatchdogError::InvalidInput("job complete requires job id".to_string())
            })?;
            let attempt = args.get(2).cloned().ok_or_else(|| {
                WatchdogError::InvalidInput("job complete requires attempt id".to_string())
            })?;
            let result: Value = serde_json::from_str(args.get(3).map_or("{}", String::as_str))?;
            Ok(Some(serde_json::to_string(
                &store.complete_job(&id, &attempt, &result)?,
            )?))
        }
        "fail" => {
            let id = args.get(1).cloned().ok_or_else(|| {
                WatchdogError::InvalidInput("job fail requires job id".to_string())
            })?;
            let attempt = args.get(2).cloned().ok_or_else(|| {
                WatchdogError::InvalidInput("job fail requires attempt id".to_string())
            })?;
            let error = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| "worker failure".to_string());
            let status = store.fail_job_at(&id, &attempt, &error, None, now_unix_ms())?;
            Ok(Some(serde_json::to_string(&status)?))
        }
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown job command {other}"
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
    "ascension-watchdog\n\nUsage:\n  watchdog config validate [PATH]\n  watchdog config sample [PATH]\n  watchdog preflight --state-directory PATH [--reserve-bytes N] [--staging-bytes N] [--backup-bytes N]\n  watchdog release inspect --manifest PATH --root PATH\n  watchdog init --config PATH [--database PATH]\n  watchdog doctor|status|start|pause|resume|drain|stop --config PATH\n  watchdog daemon --config PATH [--once]\n  watchdog job submit|list|claim|complete|fail --config PATH ...\n\nRead-only status and doctor never initialize missing state."
}

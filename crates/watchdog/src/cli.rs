//! Small dependency-free operational CLI.

use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::runtime::Supervisor;
use crate::storage::{Store, now_unix_ms};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path, PathBuf};

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
                | "migrate"
                | "doctor"
                | "preflight"
                | "release"
                | "status"
                | "start"
                | "pause"
                | "resume"
                | "drain"
                | "stop"
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
        require_migration_config(&args)?;
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
        "config" => config_command(&mut args, &config_path),
        "init" => init_command(&mut args, &config_path),
        "migrate" => migration_command(&args, &config_path),
        "doctor" => doctor_command(&config_path),
        "preflight" => preflight_command(&mut args),
        "release" => release_command(&mut args),
        "status" | "start" | "pause" | "resume" | "drain" | "stop" | "backup" => {
            operator_command(&command, &mut args, &config_path)
        }
        "daemon" | "run" => daemon_command(&mut args, &config_path),
        #[cfg(windows)]
        "service" => crate::windows_service::service_command(&mut args, &config_path),
        #[cfg(not(windows))]
        "service" => Err(WatchdogError::Unsupported(
            "Windows service commands are unavailable on this target".to_owned(),
        )),
        "job" => job_command(&mut args, &config_path),
        "attempt" => attempt_command(&mut args, &config_path),
        other => Err(WatchdogError::InvalidInput(format!(
            "unknown command {other}; try `watchdog help`"
        ))),
    }
}

fn operator_command(name: &str, args: &mut Vec<String>, path: &Path) -> Result<Option<String>> {
    use crate::admin::{
        AdminClient, AdminClientConfig, AdminCommand, BackupRequest, Capability, EmptyParams,
        ReplyStatus,
    };
    let key = take_option(args, "--idempotency-key");
    let backup_id =
        if name == "backup" {
            Some(take_option(args, "--backup-id").ok_or_else(|| {
                WatchdogError::InvalidInput("backup requires --backup-id".to_owned())
            })?)
        } else {
            None
        };
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected operator command argument".to_owned(),
        ));
    }
    let config = WatchdogConfig::from_file(path)?;
    let Some(admin) = config.admin else {
        if name == "backup" {
            return Err(WatchdogError::Unauthorized(
                "backup requires authenticated admin configuration".to_owned(),
            ));
        }
        if name == "status" {
            return status_command(path);
        }
        if !config.allow_synthetic_children {
            return Err(WatchdogError::Unauthorized(
                "mutating commands require authenticated admin configuration".to_owned(),
            ));
        }
        let mode = match name {
            "start" | "resume" => DesiredMode::Running,
            "pause" => DesiredMode::Paused,
            "drain" => DesiredMode::Draining,
            "stop" => DesiredMode::Stopped,
            _ => {
                return Err(WatchdogError::InvalidInput(
                    "unknown lifecycle command".to_owned(),
                ));
            }
        };
        return mode_command(path, mode);
    };
    let command = match name {
        "status" => AdminCommand::Status(EmptyParams {}),
        "start" => AdminCommand::Start(EmptyParams {}),
        "resume" => AdminCommand::Resume(EmptyParams {}),
        "pause" => AdminCommand::Pause(EmptyParams {}),
        "drain" => AdminCommand::Drain(EmptyParams {}),
        "stop" => AdminCommand::Stop(EmptyParams {}),
        "backup" => AdminCommand::Backup(BackupRequest {
            backup_id: backup_id.ok_or_else(|| {
                WatchdogError::InvalidInput("backup requires --backup-id".to_owned())
            })?,
        }),
        _ => {
            return Err(WatchdogError::InvalidInput(
                "unknown lifecycle command".to_owned(),
            ));
        }
    };
    let (capability, token, key) = if name == "status" {
        (
            Capability::Read,
            admin.read_token_path,
            key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        )
    } else {
        (Capability::Admin, admin.admin_token_path, key.ok_or_else(|| WatchdogError::InvalidInput(
            "mutating commands require --idempotency-key; reuse it after an uncertain response".to_owned()))?)
    };
    let client = AdminClient::new(AdminClientConfig::new(admin.endpoint, token, capability)?)?;
    let response = client.execute(&key, command)?;
    if !matches!(response.status, ReplyStatus::Ok | ReplyStatus::Accepted) {
        return Err(WatchdogError::Conflict(format!(
            "administrative request returned {:?}; idempotency key {key}",
            response.status
        )));
    }
    Ok(Some(serde_json::to_string(&response)?))
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

fn require_migration_config(args: &[String]) -> Result<()> {
    let config_options = args.iter().filter(|arg| arg.as_str() == "--config").count();
    let has_config_value = args
        .iter()
        .position(|arg| arg == "--config")
        .is_some_and(|index| {
            args.get(index + 1)
                .is_some_and(|value| !value.is_empty() && !value.starts_with("--"))
        });
    if config_options != 1 || !has_config_value {
        return Err(WatchdogError::InvalidInput(
            "migrate requires exactly one --config PATH".to_owned(),
        ));
    }
    Ok(())
}

fn migration_command(args: &[String], config_path: &Path) -> Result<Option<String>> {
    if args != ["gateway-health"] {
        return Err(WatchdogError::InvalidInput(
            "migrate requires exactly gateway-health".to_owned(),
        ));
    }
    // Offline maintenance uses the state directory's OS ownership boundary.
    // Never contend with a daemon or alter desired mode to permit migration.
    let config = WatchdogConfig::from_file(config_path)?;
    let owner = crate::storage::SingletonLock::acquire(&config.database)?;
    let mut store = Store::open(&config.database, &config)?;
    store.migrate_gateway_health(&owner)?;
    Ok(Some(
        json!({"gateway_health_schema": 1, "desired_mode": "stopped"}).to_string(),
    ))
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
    let store = Store::open_read_only(&config.database, &config)?;
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
    let store = Store::open_read_only(&config.database, &config)?;
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
    let probe_interval = std::time::Duration::from_millis(config.probe_interval_ms);
    let mut supervisor = Supervisor::open(config)?;
    if once {
        let report = supervisor.reconcile_once(now_unix_ms())?;
        return Ok(Some(serde_json::to_string(&report)?));
    }
    crate::service::ServiceLoop::new(supervisor, probe_interval)?.run_until_stopped()?;
    Ok(None)
}

fn job_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let subcommand = args.first().map(String::as_str).ok_or_else(|| {
        WatchdogError::InvalidInput("job requires submit/list/claim/complete/fail".to_string())
    })?;
    let config = WatchdogConfig::from_file(config_path)?;
    if subcommand == "list" {
        return list_jobs_command(args, &config);
    }
    if subcommand == "submit" && config.admin.is_some() {
        return authenticated_job_submit_command(args, &config);
    }
    if config.admin.is_some() || !config.allow_synthetic_children {
        return Err(WatchdogError::Unauthorized(
            "direct job mutations are restricted to unauthenticated synthetic fixtures; use authenticated job submit"
                .to_owned(),
        ));
    }
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

fn authenticated_job_submit_command(
    args: &mut Vec<String>,
    config: &WatchdogConfig,
) -> Result<Option<String>> {
    use crate::admin::{
        AdminClient, AdminClientConfig, AdminCommand, Capability, JobSubmitRequest, ReplyStatus,
    };

    args.remove(0);
    let key = take_option(args, "--idempotency-key").ok_or_else(|| {
        WatchdogError::InvalidInput(
            "job submit requires --idempotency-key; reuse it after an uncertain response"
                .to_owned(),
        )
    })?;
    let kind = take_option(args, "--kind")
        .ok_or_else(|| WatchdogError::InvalidInput("job submit requires --kind".to_owned()))?;
    let payload_arg = take_option(args, "--payload");
    let payload_file = take_option(args, "--payload-file");
    if payload_arg.is_some() && payload_file.is_some() {
        return Err(WatchdogError::InvalidInput(
            "job submit accepts only one of --payload or --payload-file".to_owned(),
        ));
    }
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected job submit argument".to_owned(),
        ));
    }
    let payload_text = if let Some(path) = payload_file {
        read_protected_job_payload(Path::new(&path))?
    } else {
        payload_arg.unwrap_or_else(|| "{}".to_owned())
    };
    let payload: Value = serde_json::from_str(&payload_text)?;
    let request = JobSubmitRequest::new(kind, payload).map_err(WatchdogError::InvalidInput)?;
    let admin = config
        .admin
        .as_ref()
        .ok_or_else(|| WatchdogError::Unauthorized("admin configuration missing".to_owned()))?;
    let client = AdminClient::new(AdminClientConfig::new(
        admin.endpoint.clone(),
        admin.admin_token_path.clone(),
        Capability::Admin,
    )?)?;
    let response = client.execute(&key, AdminCommand::JobSubmit(request))?;
    if !matches!(response.status, ReplyStatus::Ok | ReplyStatus::Accepted) {
        return Err(WatchdogError::Conflict(format!(
            "job submission returned {:?}; idempotency key {key}",
            response.status
        )));
    }
    Ok(Some(serde_json::to_string(&response)?))
}

fn read_protected_job_payload(path: &Path) -> Result<String> {
    validate_job_payload_path(path)?;
    #[cfg(target_os = "linux")]
    {
        let file = open_linux_job_payload(path)?;
        let mut bytes = Vec::new();
        file.take((crate::admin::MAX_JOB_PAYLOAD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > crate::admin::MAX_JOB_PAYLOAD_BYTES {
            Err(WatchdogError::InvalidInput(
                "job payload file exceeds the payload bound".to_owned(),
            ))
        } else {
            String::from_utf8(bytes).map_err(|_| {
                WatchdogError::InvalidInput("job payload file is not UTF-8".to_owned())
            })
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        Err(WatchdogError::Unsupported(
            "--payload-file requires the Linux protected file-handle reader on Unix".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        let bytes = ascension_platform_windows::read_protected_payload_file(
            path,
            crate::admin::MAX_JOB_PAYLOAD_BYTES,
        )
        .map_err(|error| match error {
            ascension_platform_windows::PlatformError::IdentityMismatch(message) => {
                WatchdogError::Unauthorized(message)
            }
            ascension_platform_windows::PlatformError::Invalid(message) => {
                WatchdogError::InvalidInput(message)
            }
            other => WatchdogError::Unsupported(other.to_string()),
        })?;
        String::from_utf8(bytes)
            .map_err(|_| WatchdogError::InvalidInput("job payload file is not UTF-8".to_owned()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(WatchdogError::Unsupported(
            "--payload-file is unsupported on this platform".to_owned(),
        ))
    }
}

fn validate_job_payload_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > 4 * 1024
        || path.as_os_str().to_string_lossy().contains('\0')
        || path.components().any(|component| match component {
            Component::CurDir | Component::ParentDir => true,
            Component::Prefix(prefix) => !valid_job_payload_prefix(prefix),
            _ => false,
        })
    {
        return Err(WatchdogError::InvalidInput(
            "job payload file must be an absolute path without traversal".to_owned(),
        ));
    }
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized == "/mnt"
        || normalized.starts_with("/mnt/")
        || normalized.starts_with("//wsl")
        || normalized == "/proc"
        || normalized.starts_with("/proc/")
        || normalized == "/sys"
        || normalized.starts_with("/sys/")
        || normalized == "/dev"
        || normalized.starts_with("/dev/")
    {
        return Err(WatchdogError::InvalidInput(
            "job payload file must remain on an owner-local filesystem".to_owned(),
        ));
    }
    if path.file_name().is_none_or(std::ffi::OsStr::is_empty) {
        return Err(WatchdogError::InvalidInput(
            "job payload file must name a regular file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_linux_job_payload(path: &Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    // Open every path component relative to a directory handle. O_NOFOLLOW
    // applies to each component and the final read is performed only through
    // the returned file handle, closing both ancestor and leaf replacement
    // windows. These Linux values are stable fcntl constants; no libc/unsafe
    // boundary is needed here.
    const O_DIRECTORY: i32 = 0o200_000;
    const O_NONBLOCK: i32 = 0o4_000;
    const O_NOFOLLOW: i32 = 0o400_000;
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
        .open("/")?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let mut anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        anchored.push(component);
        if index + 1 == components.len() {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW | O_NONBLOCK)
                .open(anchored)?;
            validate_linux_job_payload_handle(&file)?;
            return Ok(file);
        }
        directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
            .open(anchored)?;
    }
    Err(WatchdogError::InvalidInput(
        "job payload file must name a regular file".to_owned(),
    ))
}

#[cfg(windows)]
fn valid_job_payload_prefix(prefix: std::path::PrefixComponent<'_>) -> bool {
    matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
}

#[cfg(not(windows))]
fn valid_job_payload_prefix(_prefix: std::path::PrefixComponent<'_>) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn validate_linux_job_payload_handle(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(WatchdogError::InvalidInput(
            "job payload file must be a regular non-symlink file".to_owned(),
        ));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(WatchdogError::Unauthorized(
            "job payload file must be owner-only".to_owned(),
        ));
    }
    Ok(())
}

fn list_jobs_command(args: &mut Vec<String>, config: &WatchdogConfig) -> Result<Option<String>> {
    use crate::admin::{AdminCommand, JobFilter, JobsRequest};
    args.remove(0);
    let limit = take_option(args, "--limit")
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| WatchdogError::InvalidInput("invalid job limit".to_owned()))?
        .unwrap_or(64);
    let filter = match take_option(args, "--filter").as_deref().unwrap_or("all") {
        "all" => JobFilter::All,
        "queued" => JobFilter::Queued,
        "running" => JobFilter::Running,
        "completed" => JobFilter::Completed,
        "failed" => JobFilter::Failed,
        "quarantined" => JobFilter::Quarantined,
        _ => return Err(WatchdogError::InvalidInput("invalid job filter".to_owned())),
    };
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected job list argument".to_owned(),
        ));
    }
    let command = AdminCommand::Jobs(JobsRequest { filter, limit });
    command.validate().map_err(WatchdogError::InvalidInput)?;
    if config.admin.is_some() {
        return read_admin_command(config, command);
    }
    let filter = match filter {
        JobFilter::All => None,
        JobFilter::Queued => Some(crate::storage::JobStatus::Queued),
        JobFilter::Running => Some(crate::storage::JobStatus::Running),
        JobFilter::Completed => Some(crate::storage::JobStatus::Completed),
        JobFilter::Failed => Some(crate::storage::JobStatus::Failed),
        JobFilter::Quarantined => Some(crate::storage::JobStatus::Quarantined),
    };
    let store = Store::open_read_only(&config.database, config)?;
    Ok(Some(serde_json::to_string(
        &store.job_summaries(filter, limit)?,
    )?))
}

fn attempt_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    if args.len() != 1 {
        return Err(WatchdogError::InvalidInput(
            "attempt requires one attempt id".to_owned(),
        ));
    }
    let config = WatchdogConfig::from_file(config_path)?;
    let attempt_id = args.remove(0);
    let command = crate::admin::AdminCommand::Attempt(crate::admin::AttemptRequest {
        attempt_id: attempt_id.clone(),
    });
    command.validate().map_err(WatchdogError::InvalidInput)?;
    if config.admin.is_some() {
        return read_admin_command(&config, command);
    }
    let store = Store::open_read_only(&config.database, &config)?;
    let summary = store
        .attempt_summary(&attempt_id)?
        .ok_or_else(|| WatchdogError::NotFound("attempt not found".to_owned()))?;
    Ok(Some(serde_json::to_string(&summary)?))
}

fn read_admin_command(
    config: &WatchdogConfig,
    command: crate::admin::AdminCommand,
) -> Result<Option<String>> {
    use crate::admin::{AdminClient, AdminClientConfig, Capability, ReplyStatus};
    let admin = config
        .admin
        .as_ref()
        .ok_or_else(|| WatchdogError::Unauthorized("admin configuration missing".to_owned()))?;
    let client = AdminClient::new(AdminClientConfig::new(
        admin.endpoint.clone(),
        admin.read_token_path.clone(),
        Capability::Read,
    )?)?;
    let response = client.execute(&uuid::Uuid::new_v4().to_string(), command)?;
    if response.status != ReplyStatus::Ok {
        return Err(WatchdogError::Conflict(format!(
            "administrative inspection returned {:?}",
            response.status
        )));
    }
    Ok(Some(serde_json::to_string(&response)?))
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
    "ascension-watchdog\n\nUsage:\n  watchdog config validate [PATH]\n  watchdog config sample [PATH]\n  watchdog preflight --state-directory PATH [--reserve-bytes N] [--staging-bytes N] [--backup-bytes N]\n  watchdog release inspect --manifest PATH --root PATH\n  watchdog init --config PATH [--database PATH]\n  watchdog migrate gateway-health --config PATH\n  watchdog doctor|status|start|pause|resume|drain|stop --config PATH\n  watchdog backup --config PATH --idempotency-key KEY --backup-id ID\n  watchdog daemon --config PATH [--once]\n  watchdog service install --config PATH [--executable PATH] [--account NAME]\n  watchdog service uninstall --config PATH\n  watchdog job submit --config PATH --idempotency-key KEY --kind KIND [--payload JSON|--payload-file PATH]\n  watchdog job list|claim|complete|fail --config PATH ...\n\nRead-only status and doctor never initialize missing state."
}

//! Job submission, inspection and protected payload handling.
use super::take_option;
use crate::config::WatchdogConfig;
use crate::error::{Result, WatchdogError};
use crate::storage::{Store, now_unix_ms};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path};

pub(super) fn job_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
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

pub(super) fn authenticated_job_submit_command(
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

pub(super) fn read_protected_job_payload(path: &Path) -> Result<String> {
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

pub(super) fn validate_job_payload_path(path: &Path) -> Result<()> {
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
pub(super) fn open_linux_job_payload(path: &Path) -> Result<std::fs::File> {
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
pub(super) fn valid_job_payload_prefix(prefix: std::path::PrefixComponent<'_>) -> bool {
    matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
}

#[cfg(not(windows))]
pub(super) fn valid_job_payload_prefix(_prefix: std::path::PrefixComponent<'_>) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(super) fn validate_linux_job_payload_handle(file: &std::fs::File) -> Result<()> {
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

pub(super) fn list_jobs_command(
    args: &mut Vec<String>,
    config: &WatchdogConfig,
) -> Result<Option<String>> {
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

pub(super) fn attempt_command(
    args: &mut Vec<String>,
    config_path: &Path,
) -> Result<Option<String>> {
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

pub(super) fn read_admin_command(
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

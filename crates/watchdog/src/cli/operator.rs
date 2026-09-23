//! Operator lifecycle, status and daemon commands.
use super::{take_flag, take_option};
use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::runtime::Supervisor;
use crate::storage::{Store, now_unix_ms};
use serde_json::json;
use std::path::Path;

pub(super) fn operator_command(
    name: &str,
    args: &mut Vec<String>,
    path: &Path,
) -> Result<Option<String>> {
    use crate::admin::{
        AdminClient, AdminClientConfig, AdminCommand, BackupRequest, Capability, EmptyParams,
        QuarantineRequest, ReconcileRequest, ReconcileTarget, ReplyStatus, RetryPolicy,
        RetryRequest,
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
    let retry_attempt_id =
        if name == "retry" {
            Some(take_option(args, "--attempt-id").ok_or_else(|| {
                WatchdogError::InvalidInput("retry requires --attempt-id".to_owned())
            })?)
        } else {
            None
        };
    let quarantine_attempt_id = if name == "quarantine" {
        Some(take_option(args, "--attempt-id").ok_or_else(|| {
            WatchdogError::InvalidInput("quarantine requires --attempt-id".to_owned())
        })?)
    } else {
        None
    };
    let quarantine_reason = if name == "quarantine" {
        Some(take_option(args, "--reason").ok_or_else(|| {
            WatchdogError::InvalidInput("quarantine requires --reason".to_owned())
        })?)
    } else {
        None
    };
    let retry_policy = if name == "retry" {
        match take_option(args, "--policy")
            .as_deref()
            .unwrap_or("requeue")
        {
            "requeue" => Some(RetryPolicy::Requeue),
            "reconstruction" => Some(RetryPolicy::Reconstruction),
            _ => {
                return Err(WatchdogError::InvalidInput(
                    "retry policy must be requeue or reconstruction".to_owned(),
                ));
            }
        }
    } else {
        None
    };
    let reconcile_target = if name == "reconcile" {
        let target = match take_option(args, "--target")
            .as_deref()
            .unwrap_or("deployment")
        {
            "deployment" => ReconcileTarget::Deployment,
            "component" => ReconcileTarget::Component,
            "job" => ReconcileTarget::Job,
            "attempt" => ReconcileTarget::Attempt,
            _ => {
                return Err(WatchdogError::InvalidInput(
                    "reconcile target must be deployment, component, job, or attempt".to_owned(),
                ));
            }
        };
        Some((target, take_option(args, "--id")))
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
        if name == "reconcile" {
            return Err(WatchdogError::Unauthorized(
                "reconcile requires authenticated admin configuration".to_owned(),
            ));
        }
        if name == "quarantine" {
            return Err(WatchdogError::Unauthorized(
                "quarantine requires authenticated admin configuration".to_owned(),
            ));
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
        "quarantine" => AdminCommand::Quarantine(QuarantineRequest {
            attempt_id: quarantine_attempt_id.ok_or_else(|| {
                WatchdogError::InvalidInput("quarantine requires --attempt-id".to_owned())
            })?,
            reason: quarantine_reason.ok_or_else(|| {
                WatchdogError::InvalidInput("quarantine requires --reason".to_owned())
            })?,
        }),
        "retry" => AdminCommand::Retry(RetryRequest {
            attempt_id: retry_attempt_id.ok_or_else(|| {
                WatchdogError::InvalidInput("retry requires --attempt-id".to_owned())
            })?,
            policy: retry_policy.unwrap_or(RetryPolicy::Requeue),
        }),
        "reconcile" => {
            let (target, id) = reconcile_target.ok_or_else(|| {
                WatchdogError::InvalidInput("reconcile requires --target".to_owned())
            })?;
            AdminCommand::Reconcile(ReconcileRequest { target, id })
        }
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

pub(super) fn status_command(config_path: &Path) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let store = Store::open_read_only(&config.database, &config)?;
    Ok(Some(serde_json::to_string(&store.status()?)?))
}

pub(super) fn mode_command(config_path: &Path, mode: DesiredMode) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let mut store = Store::open(&config.database, &config)?;
    // The transaction commits intent before a daemon can observe and enact it.
    store.set_desired_mode(mode)?;
    Ok(Some(
        json!({"desired_mode": mode, "database": config.database}).to_string(),
    ))
}

pub(super) fn daemon_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
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

//! Configuration, migration, preflight and read-only diagnostic commands.
use super::take_option;
use crate::config::WatchdogConfig;
use crate::error::{Result, WatchdogError};
use crate::runtime::Supervisor;
use crate::storage::Store;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(super) fn config_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
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

pub(super) fn require_migration_config(args: &[String]) -> Result<()> {
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

pub(super) fn migration_command(args: &[String], config_path: &Path) -> Result<Option<String>> {
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

pub(super) fn init_command(args: &mut Vec<String>, config_path: &Path) -> Result<Option<String>> {
    let mut config = WatchdogConfig::from_file(config_path)?;
    if let Some(database) = take_option(args, "--database") {
        config.database = PathBuf::from(database);
        config.validate()?;
    }
    let supervisor = Supervisor::initialize(config.clone())?;
    Ok(Some(serde_json::to_string(&supervisor.status()?)?))
}

pub(super) fn preflight_command(args: &mut Vec<String>) -> Result<Option<String>> {
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

pub(super) fn preflight_bytes(args: &mut Vec<String>, option: &str, default: u64) -> Result<u64> {
    take_option(args, option).map_or(Ok(default), |value| {
        value.parse::<u64>().map_err(|_| {
            WatchdogError::InvalidInput(format!("{option} requires an unsigned byte count"))
        })
    })
}

pub(super) fn doctor_command(config_path: &Path) -> Result<Option<String>> {
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

/// Emit a bounded, read-only diagnostic bundle.  This deliberately stays
/// local to the owner store: it does not contact supervised processes, read
/// job payloads/results, or make a recovery decision.
pub(super) fn components_command(config_path: &Path) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let store = Store::open_read_only(&config.database, &config)?;
    Ok(Some(serde_json::to_string(&store.components()?)?))
}

pub(super) fn diagnostics_command(config_path: &Path) -> Result<Option<String>> {
    let config = WatchdogConfig::from_file(config_path)?;
    let store = Store::open_read_only(&config.database, &config)?;
    let status = store.status()?;
    let integrity_ok = store.integrity_check()?;
    let release_selection = store.release_selection()?;
    let operator_receipts_retained = store.operator_command_count()?;
    Ok(Some(
        json!({
            "diagnostics_version": 1,
            "config_valid": true,
            "initialized": true,
            "integrity_ok": integrity_ok,
            "durability": status.durability,
            "database": status.database,
            "deployment_id": status.deployment_id,
            "desired_mode": status.desired_mode,
            "schema_version": status.schema_version,
            "restart_generation": status.restart_generation,
            "config_digest": status.config_digest,
            "approved_release_digest": status.approved_release_digest,
            "jobs": {
                "queued": status.jobs_queued,
                "running": status.jobs_running,
                "completed": status.jobs_completed,
                "quarantined": status.jobs_quarantined,
            },
            "operator_receipts_retained": operator_receipts_retained,
            "release_selection": release_selection,
            "admin_configured": config.admin.is_some(),
        })
        .to_string(),
    ))
}

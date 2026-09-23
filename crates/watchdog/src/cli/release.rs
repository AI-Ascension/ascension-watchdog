//! Release set inspection, staging, activation and owner-local restore.
use super::{take_flag, take_option};
use crate::config::WatchdogConfig;
use crate::error::{Result, WatchdogError};
use crate::storage::Store;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(super) fn release_command(
    args: &mut Vec<String>,
    config_path: &Path,
) -> Result<Option<String>> {
    let subcommand = args.first().map(String::as_str).ok_or_else(|| {
        WatchdogError::InvalidInput(
            "release requires inspect, source-set, build-set, stage-set, activate, or rollback"
                .to_owned(),
        )
    })?;
    if subcommand == "source-set" {
        args.remove(0);
        return source_set_command(args);
    }
    if subcommand == "build-set" {
        args.remove(0);
        return build_set_command(args);
    }
    if subcommand == "stage-set" {
        args.remove(0);
        return stage_set_command(args, config_path);
    }
    if matches!(subcommand, "activate" | "rollback") {
        let rollback = subcommand == "rollback";
        args.remove(0);
        let release_id = take_option(args, "--release-id").ok_or_else(|| {
            WatchdogError::InvalidInput("release activation requires --release-id".to_owned())
        })?;
        let expected_release_digest =
            take_option(args, "--expected-release-digest").ok_or_else(|| {
                WatchdogError::InvalidInput(
                    "release activation requires --expected-release-digest".to_owned(),
                )
            })?;
        let key = take_option(args, "--idempotency-key").ok_or_else(|| {
            WatchdogError::InvalidInput(
                "release activation requires --idempotency-key; reuse it after an uncertain response"
                    .to_owned(),
            )
        })?;
        if !args.is_empty() {
            return Err(WatchdogError::InvalidInput(
                "unexpected release activation argument".to_owned(),
            ));
        }
        let config = WatchdogConfig::from_file(config_path)?;
        let admin = config.admin.as_ref().ok_or_else(|| {
            WatchdogError::Unauthorized(
                "authenticated admin configuration is required for release activation".to_owned(),
            )
        })?;
        let command =
            crate::admin::AdminCommand::ReleaseActivate(crate::admin::ReleaseActivateRequest {
                release_id,
                expected_release_digest,
                rollback,
            });
        command.validate().map_err(WatchdogError::InvalidInput)?;
        let client = crate::admin::AdminClient::new(crate::admin::AdminClientConfig::new(
            admin.endpoint.clone(),
            admin.admin_token_path.clone(),
            crate::admin::Capability::Admin,
        )?)?;
        let response = client.execute(&key, command)?;
        if !matches!(
            response.status,
            crate::admin::ReplyStatus::Ok | crate::admin::ReplyStatus::Accepted
        ) {
            return Err(WatchdogError::Conflict(format!(
                "release activation returned {:?}; idempotency key {key}",
                response.status
            )));
        }
        return Ok(Some(serde_json::to_string(&response)?));
    }
    if subcommand != "inspect" {
        return Err(WatchdogError::InvalidInput(
            "release requires inspect, source-set, activate, or rollback".to_owned(),
        ));
    }
    args.remove(0);
    if let Some(release_id) = take_option(args, "--release-id") {
        if !args.is_empty() {
            return Err(WatchdogError::InvalidInput(
                "unexpected release inspect argument".to_owned(),
            ));
        }
        let config = WatchdogConfig::from_file(config_path)?;
        if config.admin.is_none() {
            return Err(WatchdogError::Unauthorized(
                "authenticated admin configuration is required for catalog release inspection"
                    .to_owned(),
            ));
        }
        let command =
            crate::admin::AdminCommand::ReleaseInspect(crate::admin::ReleaseInspectRequest {
                release_id,
            });
        command.validate().map_err(WatchdogError::InvalidInput)?;
        return super::job::read_admin_command(&config, command);
    }
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

pub(super) fn source_set_command(args: &mut Vec<String>) -> Result<Option<String>> {
    let operation = args.first().map(String::as_str).ok_or_else(|| {
        WatchdogError::InvalidInput("release source-set requires verify".to_owned())
    })?;
    if operation != "verify" {
        return Err(WatchdogError::InvalidInput(
            "release source-set requires verify".to_owned(),
        ));
    }
    args.remove(0);
    let manifest = take_option(args, "--manifest").ok_or_else(|| {
        WatchdogError::InvalidInput("release source-set verify requires --manifest".to_owned())
    })?;
    let repository_paths = keyed_paths(args, "--repo")?;
    let artifact_paths = keyed_paths(args, "--artifact")?;
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected release source-set argument".to_owned(),
        ));
    }
    let report = crate::source_set::verify_document(
        Path::new(&manifest),
        &repository_paths,
        &artifact_paths,
    )
    .map_err(WatchdogError::InvalidInput)?;
    let output = serde_json::to_string(&report)?;
    if report.admitted {
        Ok(Some(output))
    } else {
        Err(WatchdogError::VerificationFailed(output))
    }
}

pub(super) fn build_set_command(args: &mut Vec<String>) -> Result<Option<String>> {
    let manifest = take_option(args, "--manifest").ok_or_else(|| {
        WatchdogError::InvalidInput("release build-set requires --manifest".to_owned())
    })?;
    let plan = take_option(args, "--plan").ok_or_else(|| {
        WatchdogError::InvalidInput("release build-set requires --plan".to_owned())
    })?;
    let repository_paths = keyed_paths(args, "--repo")?;
    let artifact_paths = keyed_paths(args, "--artifact")?;
    let scratch = take_option(args, "--scratch")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected release build-set argument".to_owned(),
        ));
    }
    let report = crate::build_set::run_build_set(
        Path::new(&manifest),
        Path::new(&plan),
        &repository_paths,
        &artifact_paths,
        &scratch,
    )
    .map_err(WatchdogError::InvalidInput)?;
    let output = serde_json::to_string(&report)?;
    if report.admitted && report.built && report.issues.is_empty() {
        Ok(Some(output))
    } else {
        Err(WatchdogError::VerificationFailed(output))
    }
}

pub(super) fn stage_set_command(
    args: &mut Vec<String>,
    config_path: &Path,
) -> Result<Option<String>> {
    let manifest = take_option(args, "--manifest").ok_or_else(|| {
        WatchdogError::InvalidInput("release stage-set requires --manifest".to_owned())
    })?;
    let catalog = take_option(args, "--catalog").ok_or_else(|| {
        WatchdogError::InvalidInput("release stage-set requires --catalog".to_owned())
    })?;
    let release_id = take_option(args, "--release-id").ok_or_else(|| {
        WatchdogError::InvalidInput("release stage-set requires --release-id".to_owned())
    })?;
    let compatibility = take_option(args, "--compatibility").ok_or_else(|| {
        WatchdogError::InvalidInput("release stage-set requires --compatibility".to_owned())
    })?;
    let role_sources = keyed_paths(args, "--role")?;
    let repository_paths = keyed_paths(args, "--repo")?;
    let artifact_paths = keyed_paths(args, "--artifact")?;
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected release stage-set argument".to_owned(),
        ));
    }
    let report = crate::release_stage_set::stage_release_set(
        Path::new(&manifest),
        Path::new(&catalog),
        &release_id,
        config_path,
        Path::new(&compatibility),
        &role_sources,
        &repository_paths,
        &artifact_paths,
    )
    .map_err(WatchdogError::InvalidInput)?;
    Ok(Some(serde_json::to_string(&report)?))
}

pub(super) fn keyed_paths(
    args: &mut Vec<String>,
    option: &str,
) -> Result<std::collections::BTreeMap<String, PathBuf>> {
    let mut values = std::collections::BTreeMap::new();
    while let Some(value) = take_option(args, option) {
        let (name, path) = value
            .split_once('=')
            .ok_or_else(|| WatchdogError::InvalidInput(format!("{option} requires NAME=PATH")))?;
        if name.is_empty() || path.is_empty() {
            return Err(WatchdogError::InvalidInput(format!(
                "{option} requires non-empty NAME=PATH"
            )));
        }
        if values
            .insert(name.to_owned(), PathBuf::from(path))
            .is_some()
        {
            return Err(WatchdogError::InvalidInput(format!(
                "{option} contains a duplicate name"
            )));
        }
    }
    Ok(values)
}

/// Restore a verified owner-local snapshot into a new, explicitly rekeyed
/// watchdog namespace.  This is intentionally an offline command: a running
/// daemon must not have its store swapped underneath the reconciliation loop.
pub(super) fn restore_command(
    args: &mut Vec<String>,
    config_path: &Path,
) -> Result<Option<String>> {
    let backup = take_option(args, "--backup")
        .ok_or_else(|| WatchdogError::InvalidInput("restore requires --backup PATH".to_owned()))?;
    let destination = take_option(args, "--database");
    if !take_flag(args, "--rekey") {
        return Err(WatchdogError::InvalidInput(
            "restore requires explicit --rekey".to_owned(),
        ));
    }
    if !args.is_empty() {
        return Err(WatchdogError::InvalidInput(
            "unexpected restore argument".to_owned(),
        ));
    }
    let mut config = WatchdogConfig::from_file(config_path)?;
    if let Some(destination) = destination {
        config.database = PathBuf::from(destination);
        config.validate()?;
    }
    let restored = Store::restore_from(&backup, &config.database, &config)?;
    let status = restored.status()?;
    Ok(Some(
        json!({
            "restored": true,
            "rekeyed": true,
            "blocked_until_fenced": true,
            "status": status,
        })
        .to_string(),
    ))
}

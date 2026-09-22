//! Response, handoff and witness validation for the worker client.
//!
//! Every check here is fail-closed: a response must correlate exactly with
//! its request and the configured worker binding, and durable witnesses must
//! match the configured identity, digests and boot ids before use.

use crate::error::{Result, WatchdogError};
use crate::storage::{
    WorkerClaimWitness, WorkerControlMode, WorkerControlWitness, WorkerHandoff, WorkerHandoffState,
    WorkerHandoffTuple, WorkerTerminalReceipt, WorkerTerminalStatus,
};
use crate::worker_protocol::{
    CONTRACT, ControlScope, Direction, EMPTY_PARAMETERS_DIGEST, HandoffTuple, Header,
    OPERATION_RUNTIME_V3_EPISODE, SCHEMA_DIGEST, TerminalReceipt, TerminalStatus, WorkerMode,
};
use serde_json::Value;
use std::time::Duration;
use uuid::{Uuid, Variant};

use super::config::DEFAULT_TIMEOUT_MS;
use super::session::WorkerClient;

pub(super) fn validate_response_header(
    request: &Header,
    response: &Header,
    expected_worker_boot_id: Option<&str>,
) -> Result<()> {
    let worker_boot_matches = match expected_worker_boot_id {
        Some(expected) => response.worker_boot_id.as_deref() == Some(expected),
        // A probe does not target a worker boot, so the live boot is selected
        // by the worker and must be returned as a fresh, valid identity.
        None => response
            .worker_boot_id
            .as_deref()
            .map(|value| validate_uuid4(value, "worker boot id"))
            .transpose()?
            .is_some(),
    };
    if response.direction != Direction::Response
        || response.command != request.command
        || response.scope != request.scope
        || response.contract != CONTRACT
        || response.schema_digest != SCHEMA_DIGEST
        || response.request_id != request.request_id
        || response.watchdog_boot_id != request.watchdog_boot_id
        || response.timeout_ms != request.timeout_ms
        || !worker_boot_matches
    {
        return Err(WatchdogError::IdentityMismatch(
            "worker response identity or correlation does not match the request".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn protocol_tuple(handoff: &WorkerHandoff) -> HandoffTuple {
    HandoffTuple {
        handoff_id: handoff.handoff_id.clone(),
        deployment_id: handoff.deployment_id.clone(),
        job_id: handoff.job_id.clone(),
        attempt_id: handoff.attempt_id.clone(),
        attempt_number: u64::from(handoff.attempt_number),
        worker_owner_id: handoff.worker_owner_id.clone(),
        worker_profile_digest: handoff.worker_profile_digest.clone(),
        run_id: handoff.run_id.clone(),
        episode_id: handoff.episode_id.clone(),
        trajectory_id: handoff.trajectory_id.clone(),
        payload_digest: handoff.payload_digest.clone(),
    }
}

pub(super) fn protocol_tuple_from_storage(tuple: &WorkerHandoffTuple) -> HandoffTuple {
    HandoffTuple {
        handoff_id: tuple.handoff_id.clone(),
        deployment_id: tuple.deployment_id.clone(),
        job_id: tuple.job_id.clone(),
        attempt_id: tuple.attempt_id.clone(),
        attempt_number: u64::from(tuple.attempt_number),
        worker_owner_id: tuple.worker_owner_id.clone(),
        worker_profile_digest: tuple.worker_profile_digest.clone(),
        run_id: tuple.run_id.clone(),
        episode_id: tuple.episode_id.clone(),
        trajectory_id: tuple.trajectory_id.clone(),
        payload_digest: tuple.payload_digest.clone(),
    }
}

pub(super) fn validate_handoff_for_client(
    client: &WorkerClient,
    handoff: &WorkerHandoff,
) -> Result<()> {
    if handoff.state != WorkerHandoffState::MayHaveBeenDispatched {
        return Err(WatchdogError::Conflict(
            "worker dispatch requires a committed may_have_been_dispatched handoff".to_owned(),
        ));
    }
    if handoff.operation != OPERATION_RUNTIME_V3_EPISODE
        || handoff.parameters != Value::Object(serde_json::Map::new())
        || handoff.payload_digest != EMPTY_PARAMETERS_DIGEST
        || handoff.job.worker_id.as_deref() != Some(handoff.worker_owner_id.as_str())
    {
        return Err(WatchdogError::Conflict(
            "worker handoff is not the configured empty runtime-v3 episode".to_owned(),
        ));
    }
    if handoff.watchdog_boot_id != client.watchdog_boot_id {
        return Err(WatchdogError::Conflict(
            "worker handoff is not bound to this watchdog session".to_owned(),
        ));
    }
    validate_storage_tuple(&handoff.tuple())?;
    validate_tuple_for_client(client, &handoff.tuple())?;
    validate_uuid4(&handoff.worker_boot_id, "worker boot id")?;
    if handoff.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker mode sequence must be positive".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_tuple_for_client(
    client: &WorkerClient,
    tuple: &WorkerHandoffTuple,
) -> Result<()> {
    if tuple.deployment_id != client.config.binding.deployment_id
        || tuple.worker_owner_id != client.config.binding.worker_owner_id
        || tuple.worker_profile_digest != client.config.binding.worker_profile_digest
    {
        return Err(WatchdogError::Conflict(
            "worker handoff tuple differs from the configured worker".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_claim_witness_for_client(
    client: &WorkerClient,
    witness: &WorkerClaimWitness,
) -> Result<()> {
    if witness.deployment_id != client.config.binding.deployment_id
        || witness.worker_owner_id != client.config.binding.worker_owner_id
        || witness.worker_profile_digest != client.config.binding.worker_profile_digest
        || witness.release_digest != client.config.binding.release_digest
        || witness.config_digest != client.config.binding.config_digest
        || witness.schema_digest != client.config.binding.schema_digest
        || witness.watchdog_boot_id != client.watchdog_boot_id
    {
        return Err(WatchdogError::Conflict(
            "worker claim witness differs from the configured client binding".to_owned(),
        ));
    }
    validate_uuid4(&witness.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&witness.worker_boot_id, "worker boot id")?;
    if witness.watchdog_boot_id == witness.worker_boot_id || witness.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker claim witness has an invalid boot or mode sequence".to_owned(),
        ));
    }
    for (digest, field) in [
        (&witness.worker_profile_digest, "worker profile digest"),
        (&witness.release_digest, "worker release digest"),
        (&witness.config_digest, "worker config digest"),
        (&witness.schema_digest, "worker schema digest"),
    ] {
        crate::config::validate_digest(digest).map_err(|message| {
            WatchdogError::InvalidInput(format!("{field} is invalid: {message}"))
        })?;
    }
    Ok(())
}

pub(super) fn validate_recovery_witness_for_client(
    client: &WorkerClient,
    recovery: &WorkerControlWitness,
) -> Result<()> {
    if recovery.deployment_id != client.config.binding.deployment_id
        || recovery.worker_owner_id != client.config.binding.worker_owner_id
        || recovery.worker_profile_digest != client.config.binding.worker_profile_digest
        || recovery.watchdog_boot_id != client.watchdog_boot_id
    {
        return Err(WatchdogError::Conflict(
            "worker recovery witness differs from the configured client binding".to_owned(),
        ));
    }
    validate_uuid4(&recovery.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&recovery.worker_boot_id, "worker boot id")?;
    if recovery.watchdog_boot_id == recovery.worker_boot_id || recovery.mode_sequence == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker recovery witness has an invalid boot or mode sequence".to_owned(),
        ));
    }
    crate::config::validate_digest(&recovery.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })?;
    Ok(())
}

pub(super) fn validate_storage_tuple(tuple: &WorkerHandoffTuple) -> Result<()> {
    for (value, field) in [
        (&tuple.handoff_id, "handoff id"),
        (&tuple.run_id, "run id"),
        (&tuple.episode_id, "episode id"),
        (&tuple.trajectory_id, "trajectory id"),
    ] {
        validate_uuid4(value, field)?;
    }
    if tuple.handoff_id == tuple.run_id
        || tuple.handoff_id == tuple.episode_id
        || tuple.handoff_id == tuple.trajectory_id
        || tuple.run_id == tuple.episode_id
        || tuple.run_id == tuple.trajectory_id
        || tuple.episode_id == tuple.trajectory_id
    {
        return Err(WatchdogError::InvalidInput(
            "worker handoff tuple UUIDs must be pairwise distinct".to_owned(),
        ));
    }
    if tuple.attempt_number == 0 || tuple.payload_digest != EMPTY_PARAMETERS_DIGEST {
        return Err(WatchdogError::InvalidInput(
            "worker handoff tuple has an invalid attempt or payload digest".to_owned(),
        ));
    }
    crate::config::validate_digest(&tuple.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })?;
    crate::config::validate_digest(&tuple.payload_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("payload digest is invalid: {message}"))
    })?;
    Ok(())
}

pub(crate) fn storage_receipt(receipt: &TerminalReceipt) -> WorkerTerminalReceipt {
    WorkerTerminalReceipt {
        status: match receipt.status {
            TerminalStatus::Completed => WorkerTerminalStatus::Completed,
            TerminalStatus::Failed => WorkerTerminalStatus::Failed,
        },
        checkpoint_sequence: receipt.checkpoint_sequence,
        terminal_ref: receipt.terminal_ref.clone(),
        result_digest: receipt.result_digest.clone(),
    }
}

pub(super) fn storage_control_mode(mode: WorkerMode) -> WorkerControlMode {
    match mode {
        WorkerMode::Running => WorkerControlMode::Running,
        WorkerMode::Paused => WorkerControlMode::Paused,
        WorkerMode::Draining => WorkerControlMode::Draining,
        WorkerMode::Stopped => WorkerControlMode::Stopped,
    }
}

pub(super) fn validate_control_scope(scope: &ControlScope) -> Result<()> {
    if scope.deployment_id.is_empty()
        || scope.worker_owner_id.is_empty()
        || scope.worker_profile_digest.len() != 64
        || scope.mode_sequence == 0
    {
        return Err(WatchdogError::InvalidInput(
            "worker control scope is outside its bounds".to_owned(),
        ));
    }
    crate::config::validate_digest(&scope.worker_profile_digest).map_err(|message| {
        WatchdogError::InvalidInput(format!("worker profile digest is invalid: {message}"))
    })
}

pub(super) fn validate_uuid4(value: &str, field: &str) -> Result<()> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| WatchdogError::InvalidInput(format!("{field} must be a canonical UUIDv4")))?;
    if uuid.get_version_num() != 4
        || uuid.get_variant() != Variant::RFC4122
        || uuid.to_string() != value
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{field} must be a lowercase canonical UUIDv4"
        )));
    }
    Ok(())
}

pub(super) fn duration_millis(timeout: Duration) -> u64 {
    let millis = timeout.as_millis();
    match u64::try_from(millis) {
        Ok(value) => value,
        Err(_) => DEFAULT_TIMEOUT_MS,
    }
}

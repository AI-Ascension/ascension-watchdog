//! Worker identity, tuple, and incarnation validation.

use super::storage_worker_claims_state::{binding_from_tx, control_from_tx};
use super::storage_worker_queries_handoff::RawHandoff;
use super::storage_worker_queries_terminal::validate_uuid4;
use super::storage_worker_schema::{
    MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_PAYLOAD_DIGEST, WORKER_HANDOFF_SCHEMA_DIGEST,
};
use super::storage_worker_types::{
    WorkerBinding, WorkerClaimWitness, WorkerControlMode, WorkerControlWitness, WorkerHandoffTuple,
};
use super::{metadata_from_conn, validate_name};
use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, Transaction};

pub(super) fn validate_binding(conn: &Connection, binding: &WorkerBinding) -> Result<()> {
    let deployment_id = metadata_from_conn(conn, "deployment_id")?
        .ok_or_else(|| WatchdogError::Conflict("deployment_id metadata is missing".to_owned()))?;
    validate_worker_identity(&binding.deployment_id, "worker deployment id")?;
    if binding.deployment_id != deployment_id {
        return Err(WatchdogError::Conflict(
            "worker binding deployment differs from the owner-local store".to_owned(),
        ));
    }
    validate_worker_identity(&binding.worker_owner_id, "worker owner id")?;
    for (value, field) in [
        (&binding.worker_profile_digest, "worker profile digest"),
        (&binding.release_digest, "worker release digest"),
        (&binding.config_digest, "worker config digest"),
        (&binding.schema_digest, "worker schema digest"),
    ] {
        validate_digest_value(value, field)?;
    }
    if binding.schema_digest != WORKER_HANDOFF_SCHEMA_DIGEST {
        return Err(WatchdogError::Conflict(
            "worker binding schema digest is not the frozen worker-handoff-v1 schema".to_owned(),
        ));
    }
    let stored_config = metadata_from_conn(conn, "config_digest")?
        .ok_or_else(|| WatchdogError::Conflict("config_digest metadata is missing".to_owned()))?;
    if binding.config_digest != stored_config {
        return Err(WatchdogError::Conflict(
            "worker binding config digest differs from the owner-local configuration".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_control(control: &WorkerControlWitness) -> Result<()> {
    validate_worker_identity(&control.deployment_id, "worker control deployment id")?;
    validate_worker_identity(&control.worker_owner_id, "worker control owner id")?;
    validate_digest_value(
        &control.worker_profile_digest,
        "worker control profile digest",
    )?;
    validate_uuid4(&control.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&control.worker_boot_id, "worker boot id")?;
    if control.watchdog_boot_id == control.worker_boot_id {
        return Err(WatchdogError::InvalidInput(
            "watchdog and worker boot identities must be distinct".to_owned(),
        ));
    }
    if control.mode_sequence == 0 || control.mode_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(WatchdogError::InvalidInput(
            "worker control mode sequence must be positive and fit the wire integer bound"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_claim_witness(witness: &WorkerClaimWitness) -> Result<()> {
    validate_worker_identity(&witness.deployment_id, "worker claim deployment id")?;
    validate_worker_identity(&witness.worker_owner_id, "worker claim owner id")?;
    for (value, field) in [
        (&witness.worker_profile_digest, "worker profile digest"),
        (&witness.release_digest, "worker release digest"),
        (&witness.config_digest, "worker config digest"),
        (&witness.schema_digest, "worker schema digest"),
    ] {
        validate_digest_value(value, field)?;
    }
    validate_uuid4(&witness.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&witness.worker_boot_id, "worker boot id")?;
    if witness.watchdog_boot_id == witness.worker_boot_id {
        return Err(WatchdogError::InvalidInput(
            "watchdog and worker boot identities must be distinct".to_owned(),
        ));
    }
    if witness.mode_sequence == 0 || witness.mode_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(WatchdogError::InvalidInput(
            "worker claim mode sequence must be positive and fit the wire integer bound".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_tuple(tuple: &WorkerHandoffTuple) -> Result<()> {
    for (value, field) in [
        (&tuple.handoff_id, "handoff id"),
        (&tuple.attempt_id, "attempt id"),
        (&tuple.run_id, "run id"),
        (&tuple.episode_id, "episode id"),
        (&tuple.trajectory_id, "trajectory id"),
    ] {
        validate_uuid4(value, field)?;
    }
    validate_worker_identity(&tuple.deployment_id, "deployment id")?;
    validate_name(&tuple.job_id, "job id", 128)?;
    if tuple.attempt_number == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker attempt number must be positive".to_owned(),
        ));
    }
    validate_worker_identity(&tuple.worker_owner_id, "worker owner id")?;
    validate_digest_value(&tuple.worker_profile_digest, "worker profile digest")?;
    validate_digest_value(&tuple.payload_digest, "payload digest")?;
    if tuple.payload_digest != WORKER_HANDOFF_PAYLOAD_DIGEST {
        return Err(WatchdogError::InvalidInput(
            "worker payload digest is not the frozen empty-parameters digest".to_owned(),
        ));
    }
    let ids = [
        tuple.handoff_id.as_str(),
        tuple.attempt_id.as_str(),
        tuple.run_id.as_str(),
        tuple.episode_id.as_str(),
        tuple.trajectory_id.as_str(),
    ];
    for (index, id) in ids.iter().enumerate() {
        if ids[index + 1..].contains(id) {
            return Err(WatchdogError::InvalidInput(
                "worker handoff tuple UUIDs must be pairwise distinct".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_digest_value(value: &str, field: &str) -> Result<()> {
    validate_digest(value)
        .map_err(|message| WatchdogError::InvalidInput(format!("{field} is invalid: {message}")))
}

pub(super) fn validate_worker_identity(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WatchdogError::InvalidInput(format!(
            "{field} must be a bounded ASCII worker identity"
        )));
    }
    Ok(())
}

pub(super) fn validate_control_against_binding(
    control: &WorkerControlWitness,
    binding: &WorkerBinding,
) -> Result<()> {
    if control.deployment_id != binding.deployment_id
        || control.worker_owner_id != binding.worker_owner_id
        || control.worker_profile_digest != binding.worker_profile_digest
    {
        return Err(WatchdogError::Conflict(
            "worker control scope differs from its configured binding".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_claim_witness_tx(
    tx: &Transaction<'_>,
    witness: &WorkerClaimWitness,
) -> Result<()> {
    let binding = binding_from_tx(tx)?
        .ok_or_else(|| WatchdogError::Conflict("worker binding is not configured".to_owned()))?;
    let expected_binding = WorkerBinding {
        deployment_id: witness.deployment_id.clone(),
        worker_owner_id: witness.worker_owner_id.clone(),
        worker_profile_digest: witness.worker_profile_digest.clone(),
        release_digest: witness.release_digest.clone(),
        config_digest: witness.config_digest.clone(),
        schema_digest: witness.schema_digest.clone(),
    };
    if binding != expected_binding {
        return Err(WatchdogError::Conflict(
            "worker claim witness differs from its configured binding".to_owned(),
        ));
    }
    let control = control_from_tx(tx)?.ok_or_else(|| {
        WatchdogError::Conflict("worker control has not been acknowledged".to_owned())
    })?;
    let expected_control = WorkerControlWitness {
        deployment_id: witness.deployment_id.clone(),
        worker_owner_id: witness.worker_owner_id.clone(),
        worker_profile_digest: witness.worker_profile_digest.clone(),
        watchdog_boot_id: witness.watchdog_boot_id.clone(),
        worker_boot_id: witness.worker_boot_id.clone(),
        mode: WorkerControlMode::Running,
        mode_sequence: witness.mode_sequence,
    };
    if control != expected_control {
        return Err(WatchdogError::Conflict(
            "worker claim witness differs from acknowledged worker control".to_owned(),
        ));
    }
    let desired = metadata_from_conn(tx, "desired_mode")?
        .ok_or_else(|| WatchdogError::Conflict("desired mode metadata is missing".to_owned()))?;
    if super::parse_mode(&desired)? != crate::config::DesiredMode::Running {
        return Err(WatchdogError::Conflict(
            "durable desired mode does not authorize worker claims".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_dispatch_control_tx(
    tx: &Transaction<'_>,
    handoff: &RawHandoff,
) -> Result<()> {
    let desired = metadata_from_conn(tx, "desired_mode")?
        .ok_or_else(|| WatchdogError::Conflict("desired mode metadata is missing".to_owned()))?;
    if super::parse_mode(&desired)? != crate::config::DesiredMode::Running {
        return Err(WatchdogError::Conflict(
            "durable desired mode no longer authorizes dispatch".to_owned(),
        ));
    }
    let binding = binding_from_tx(tx)?
        .ok_or_else(|| WatchdogError::Conflict("worker binding is not configured".to_owned()))?;
    if binding.deployment_id != handoff.deployment_id
        || binding.worker_owner_id != handoff.worker_owner_id
        || binding.worker_profile_digest != handoff.worker_profile_digest
    {
        return Err(WatchdogError::Conflict(
            "worker binding no longer matches the prepared handoff".to_owned(),
        ));
    }
    let Some(control) = control_from_tx(tx)? else {
        return Err(WatchdogError::Conflict(
            "worker control has not been acknowledged".to_owned(),
        ));
    };
    if control.mode != WorkerControlMode::Running
        || control.deployment_id != handoff.deployment_id
        || control.worker_owner_id != handoff.worker_owner_id
        || control.worker_profile_digest != handoff.worker_profile_digest
        || control.watchdog_boot_id != handoff.watchdog_boot_id
        || control.worker_boot_id != handoff.worker_boot_id
        || control.mode_sequence != handoff.mode_sequence
    {
        return Err(WatchdogError::Conflict(
            "worker control no longer matches the prepared handoff".to_owned(),
        ));
    }
    Ok(())
}

/// Admission and terminal reports are valid only from the watchdog/worker
/// incarnation that was durably bound before dispatch.  A changed mode or
/// sequence may close admission while an already-dispatched operation settles,
/// but a fresh watchdog or worker boot must never complete an older lineage.
pub(super) fn validate_current_worker_incarnation_tx(
    tx: &Transaction<'_>,
    handoff: &RawHandoff,
) -> Result<()> {
    let binding = binding_from_tx(tx)?
        .ok_or_else(|| WatchdogError::Conflict("worker binding is not configured".to_owned()))?;
    if binding.deployment_id != handoff.deployment_id
        || binding.worker_owner_id != handoff.worker_owner_id
        || binding.worker_profile_digest != handoff.worker_profile_digest
    {
        return Err(WatchdogError::Conflict(
            "worker binding no longer matches the worker handoff".to_owned(),
        ));
    }
    let Some(control) = control_from_tx(tx)? else {
        return Err(WatchdogError::Conflict(
            "worker control has not been acknowledged".to_owned(),
        ));
    };
    if control.deployment_id != handoff.deployment_id
        || control.worker_owner_id != handoff.worker_owner_id
        || control.worker_profile_digest != handoff.worker_profile_digest
        || control.watchdog_boot_id != handoff.watchdog_boot_id
        || control.worker_boot_id != handoff.worker_boot_id
    {
        return Err(WatchdogError::Conflict(
            "worker report belongs to a stale watchdog or worker boot".to_owned(),
        ));
    }
    Ok(())
}

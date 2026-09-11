//! Bounded worker binding/control projections and timestamp helpers.

use super::storage_worker_claims_validation::{validate_binding, validate_control};
use super::storage_worker_claims_validation::{validate_digest_value, validate_worker_identity};
use super::storage_worker_schema::WORKER_HANDOFF_SCHEMA_DIGEST;
use super::storage_worker_types::{WorkerBinding, WorkerControlMode, WorkerControlWitness};
use super::{sqlite_u64, to_sqlite_error};
use crate::error::Result;
use crate::error::WatchdogError;
use rusqlite::{Connection, OptionalExtension, Transaction};

pub(super) const BINDING_SELECT: &str = "SELECT
    CASE WHEN typeof(deployment_id)='text' AND length(CAST(deployment_id AS BLOB)) <= 128 THEN deployment_id END,
    CASE WHEN typeof(worker_owner_id)='text' AND length(CAST(worker_owner_id AS BLOB)) <= 128 THEN worker_owner_id END,
    CASE WHEN typeof(worker_profile_digest)='text' AND length(CAST(worker_profile_digest AS BLOB)) <= 64 THEN worker_profile_digest END,
    CASE WHEN typeof(release_digest)='text' AND length(CAST(release_digest AS BLOB)) <= 64 THEN release_digest END,
    CASE WHEN typeof(config_digest)='text' AND length(CAST(config_digest AS BLOB)) <= 64 THEN config_digest END,
    CASE WHEN typeof(schema_digest)='text' AND length(CAST(schema_digest AS BLOB)) <= 64 THEN schema_digest END,
    updated_at_ms
    FROM worker_bindings WHERE singleton=1";

pub(super) fn unresolved_handoff_exists(tx: &Transaction<'_>) -> Result<bool> {
    let value: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM worker_handoffs WHERE state IN ('prepared','may_have_been_dispatched','admitted') LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.is_some())
}

pub(super) fn binding_from_conn(conn: &Connection) -> Result<Option<WorkerBinding>> {
    let binding = conn
        .query_row(BINDING_SELECT, [], binding_from_row)
        .optional()?;
    if let Some(binding) = &binding {
        validate_binding(conn, binding)?;
    }
    Ok(binding)
}

pub(super) fn binding_from_tx(tx: &Transaction<'_>) -> Result<Option<WorkerBinding>> {
    let binding = tx
        .query_row(BINDING_SELECT, [], binding_from_row)
        .optional()?;
    if let Some(binding) = &binding {
        validate_binding(tx, binding)?;
    }
    Ok(binding)
}

pub(super) fn control_from_conn(conn: &Connection) -> Result<Option<WorkerControlWitness>> {
    conn.query_row(CONTROL_SELECT, [], control_from_row)
        .optional()
        .map_err(Into::into)
}

pub(super) fn control_from_tx(tx: &Transaction<'_>) -> Result<Option<WorkerControlWitness>> {
    tx.query_row(CONTROL_SELECT, [], control_from_row)
        .optional()
        .map_err(Into::into)
}

pub(super) fn control_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkerControlWitness> {
    let control = WorkerControlWitness {
        deployment_id: bounded_required_text(row, 0, "control deployment id")?,
        worker_owner_id: bounded_required_text(row, 1, "control owner id")?,
        worker_profile_digest: bounded_required_text(row, 2, "control profile digest")?,
        watchdog_boot_id: bounded_required_text(row, 3, "control watchdog boot id")?,
        worker_boot_id: bounded_required_text(row, 4, "control worker boot id")?,
        mode: WorkerControlMode::parse(&bounded_required_text(row, 5, "control mode")?)
            .map_err(to_sqlite_error)?,
        mode_sequence: sqlite_u64(row.get(6)?, "worker control mode sequence")?,
    };
    validate_control(&control).map_err(to_sqlite_error)?;
    sqlite_u64(row.get(7)?, "worker control updated_at_ms")?;
    Ok(control)
}

pub(super) const CONTROL_SELECT: &str = "SELECT
    CASE WHEN typeof(deployment_id)='text' AND length(CAST(deployment_id AS BLOB)) <= 128 THEN deployment_id END,
    CASE WHEN typeof(worker_owner_id)='text' AND length(CAST(worker_owner_id AS BLOB)) <= 128 THEN worker_owner_id END,
    CASE WHEN typeof(worker_profile_digest)='text' AND length(CAST(worker_profile_digest AS BLOB)) <= 64 THEN worker_profile_digest END,
    CASE WHEN typeof(watchdog_boot_id)='text' AND length(CAST(watchdog_boot_id AS BLOB)) <= 36 THEN watchdog_boot_id END,
    CASE WHEN typeof(worker_boot_id)='text' AND length(CAST(worker_boot_id AS BLOB)) <= 36 THEN worker_boot_id END,
    CASE WHEN typeof(mode)='text' AND length(CAST(mode AS BLOB)) <= 32 THEN mode END,
    mode_sequence,
    updated_at_ms FROM worker_control WHERE singleton=1";

pub(super) fn binding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkerBinding> {
    let binding = WorkerBinding {
        deployment_id: bounded_required_text(row, 0, "binding deployment id")?,
        worker_owner_id: bounded_required_text(row, 1, "binding owner id")?,
        worker_profile_digest: bounded_required_text(row, 2, "binding profile digest")?,
        release_digest: bounded_required_text(row, 3, "binding release digest")?,
        config_digest: bounded_required_text(row, 4, "binding config digest")?,
        schema_digest: bounded_required_text(row, 5, "binding schema digest")?,
    };
    validate_worker_identity(&binding.deployment_id, "worker binding deployment id")
        .map_err(to_sqlite_error)?;
    validate_worker_identity(&binding.worker_owner_id, "worker binding owner id")
        .map_err(to_sqlite_error)?;
    for (value, field) in [
        (&binding.worker_profile_digest, "worker profile digest"),
        (&binding.release_digest, "worker release digest"),
        (&binding.config_digest, "worker config digest"),
        (&binding.schema_digest, "worker schema digest"),
    ] {
        validate_digest_value(value, field).map_err(to_sqlite_error)?;
    }
    if binding.schema_digest != WORKER_HANDOFF_SCHEMA_DIGEST {
        return Err(to_sqlite_error(
            "worker binding schema digest is not the frozen worker-handoff-v1 schema",
        ));
    }
    sqlite_u64(row.get(6)?, "worker binding updated_at_ms")?;
    Ok(binding)
}

fn bounded_required_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    field: &str,
) -> rusqlite::Result<String> {
    row.get::<_, Option<String>>(index)?.ok_or_else(|| {
        to_sqlite_error(format!(
            "worker {field} is missing, non-text, or exceeds its bound"
        ))
    })
}

pub(super) fn ensure_phase_time_at_least(now_ms: u64, previous: i64, field: &str) -> Result<()> {
    let previous = sqlite_u64(previous, &format!("{field} updated_at_ms"))?;
    if now_ms < previous {
        return Err(WatchdogError::Conflict(format!(
            "{field} timestamp moves backwards"
        )));
    }
    Ok(())
}

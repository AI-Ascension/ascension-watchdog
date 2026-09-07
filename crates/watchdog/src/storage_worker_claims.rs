//! Worker binding, control witness, and atomic claim admission.

use super::storage_worker_queries::{
    RawHandoff, empty_parameters, new_uuid4, new_uuid4_distinct, validate_uuid4,
};
use super::storage_worker_schema::{
    MAX_WORKER_WIRE_INTEGER, WORKER_HANDOFF_OPERATION, WORKER_HANDOFF_PAYLOAD_DIGEST,
    WORKER_HANDOFF_SCHEMA_DIGEST,
};
use super::storage_worker_types::{
    WorkerBinding, WorkerClaimWitness, WorkerControlMode, WorkerControlWitness, WorkerHandoff,
    WorkerHandoffTuple,
};
use super::{
    Store, insert_audit_tx, metadata_from_conn, sqlite_timestamp, sqlite_u64, to_sqlite_error,
    validate_name,
};
use crate::config::validate_digest;
use crate::error::{Result, WatchdogError};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

impl Store {
    /// Configure the immutable worker binding used by every future claim.
    /// Repeating the exact binding is idempotent; replacing any digest or
    /// stable owner requires an explicit owner-local store migration.
    pub fn configure_worker_binding_at(
        &mut self,
        binding: &WorkerBinding,
        now_ms: u64,
    ) -> Result<WorkerBinding> {
        validate_binding(&self.conn, binding)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<WorkerBinding> = tx
            .query_row(
                "SELECT deployment_id, worker_owner_id, worker_profile_digest, release_digest, config_digest, schema_digest FROM worker_bindings WHERE singleton=1",
                [],
                |row| {
                    Ok(WorkerBinding {
                        deployment_id: row.get(0)?,
                        worker_owner_id: row.get(1)?,
                        worker_profile_digest: row.get(2)?,
                        release_digest: row.get(3)?,
                        config_digest: row.get(4)?,
                        schema_digest: row.get(5)?,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != *binding {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "worker binding is immutable; explicit owner migration is required".to_owned(),
                ));
            }
            tx.execute(
                "UPDATE worker_bindings SET updated_at_ms=? WHERE singleton=1",
                params![sqlite_timestamp(now_ms)?],
            )?;
        } else {
            tx.execute(
                "INSERT INTO worker_bindings (singleton, deployment_id, worker_owner_id, worker_profile_digest, release_digest, config_digest, schema_digest, updated_at_ms) VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    binding.deployment_id,
                    binding.worker_owner_id,
                    binding.worker_profile_digest,
                    binding.release_digest,
                    binding.config_digest,
                    binding.schema_digest,
                    sqlite_timestamp(now_ms)?
                ],
            )?;
            insert_audit_tx(
                &tx,
                "worker_binding_configured",
                &binding.worker_owner_id,
                now_ms,
            )?;
        }
        tx.commit()?;
        Ok(binding.clone())
    }

    /// Wall-clock convenience wrapper around [`Self::configure_worker_binding_at`].
    pub fn configure_worker_binding(&mut self, binding: &WorkerBinding) -> Result<WorkerBinding> {
        self.configure_worker_binding_at(binding, super::now_unix_ms())
    }

    /// Commit an authenticated control witness.  Sequence numbers are
    /// monotonic for the owner-local worker control row; an exact repeat is
    /// harmless and a same-sequence mismatch is rejected.
    pub fn set_worker_control_at(
        &mut self,
        control: &WorkerControlWitness,
        now_ms: u64,
    ) -> Result<WorkerControlWitness> {
        validate_control(control)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let binding = binding_from_tx(&tx)?.ok_or_else(|| {
            WatchdogError::Conflict("worker binding is not configured".to_owned())
        })?;
        validate_control_against_binding(control, &binding)?;
        let existing: Option<WorkerControlWitness> = tx
            .query_row(
                "SELECT deployment_id, worker_owner_id, worker_profile_digest, watchdog_boot_id, worker_boot_id, mode, mode_sequence FROM worker_control WHERE singleton=1",
                [],
                control_from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if control.mode_sequence < existing.mode_sequence {
                tx.rollback()?;
                return Err(WatchdogError::Conflict(
                    "worker control sequence is older than the durable sequence".to_owned(),
                ));
            }
            if control.mode_sequence == existing.mode_sequence {
                if *control != existing {
                    tx.rollback()?;
                    return Err(WatchdogError::Conflict(
                        "worker control reuses a sequence with a different scope".to_owned(),
                    ));
                }
                tx.commit()?;
                return Ok(control.clone());
            }
        }
        tx.execute(
            "INSERT INTO worker_control (singleton, deployment_id, worker_owner_id, worker_profile_digest, watchdog_boot_id, worker_boot_id, mode, mode_sequence, updated_at_ms) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET deployment_id=excluded.deployment_id, worker_owner_id=excluded.worker_owner_id, worker_profile_digest=excluded.worker_profile_digest, watchdog_boot_id=excluded.watchdog_boot_id, worker_boot_id=excluded.worker_boot_id, mode=excluded.mode, mode_sequence=excluded.mode_sequence, updated_at_ms=excluded.updated_at_ms",
            params![
                control.deployment_id,
                control.worker_owner_id,
                control.worker_profile_digest,
                control.watchdog_boot_id,
                control.worker_boot_id,
                control.mode.as_str(),
                sqlite_timestamp(control.mode_sequence)?,
                sqlite_timestamp(now_ms)?
            ],
        )?;
        insert_audit_tx(
            &tx,
            "worker_control_mode_set",
            &format!("{}:{}", control.mode.as_str(), control.mode_sequence),
            now_ms,
        )?;
        tx.commit()?;
        Ok(control.clone())
    }

    /// Wall-clock convenience wrapper around [`Self::set_worker_control_at`].
    pub fn set_worker_control(
        &mut self,
        control: &WorkerControlWitness,
    ) -> Result<WorkerControlWitness> {
        self.set_worker_control_at(control, super::now_unix_ms())
    }

    /// Return the currently admissible claim witness.  Missing configuration,
    /// non-running control, and a paused/stopped durable mode produce `None`.
    pub fn current_worker_claim_witness(&self) -> Result<Option<WorkerClaimWitness>> {
        let binding = binding_from_conn(&self.conn)?;
        let Some(binding) = binding else {
            return Ok(None);
        };
        let control = control_from_conn(&self.conn)?;
        let Some(control) = control else {
            return Ok(None);
        };
        if control.mode != WorkerControlMode::Running
            || super::parse_mode(&metadata_from_conn(&self.conn, "desired_mode")?.ok_or_else(
                || WatchdogError::Conflict("desired mode metadata is missing".to_owned()),
            )?)? != crate::config::DesiredMode::Running
        {
            return Ok(None);
        }
        Ok(Some(WorkerClaimWitness {
            deployment_id: binding.deployment_id,
            worker_owner_id: binding.worker_owner_id,
            worker_profile_digest: binding.worker_profile_digest,
            release_digest: binding.release_digest,
            config_digest: binding.config_digest,
            schema_digest: binding.schema_digest,
            watchdog_boot_id: control.watchdog_boot_id,
            worker_boot_id: control.worker_boot_id,
            mode_sequence: control.mode_sequence,
        }))
    }

    /// Atomically claim the next eligible runtime-v3 episode and persist its
    /// complete tuple plus a `prepared` handoff before any worker IPC.
    pub fn claim_next_worker_handoff(
        &mut self,
        witness: &WorkerClaimWitness,
        now_ms: u64,
    ) -> Result<Option<WorkerHandoff>> {
        validate_claim_witness(witness)?;
        let payload_read_limit = self
            .max_payload_bytes
            .checked_add(1)
            .and_then(|limit| i64::try_from(limit).ok())
            .ok_or_else(|| {
                WatchdogError::InvalidInput("job payload bound exceeds SQLite range".to_owned())
            })?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_claim_witness_tx(&tx, witness)?;
        let unresolved_attempt: Option<String> = tx
            .query_row(
                "SELECT id FROM attempts WHERE status IN ('running','unknown') ORDER BY started_at_ms, sequence, id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if unresolved_attempt.is_some() || unresolved_handoff_exists(&tx)? {
            tx.commit()?;
            return Ok(None);
        }
        let row: Option<(String, String, String, String, i64, i64)> = tx
            .query_row(
                "SELECT id, kind, substr(payload, 1, ?2), payload_digest, created_at_ms, attempt_count FROM jobs WHERE status='queued' AND next_retry_at_ms IS NOT NULL AND next_retry_at_ms <= ?1 AND kind=?3 AND payload_digest=?4 ORDER BY created_at_ms, id LIMIT 1",
                params![
                    sqlite_timestamp(now_ms)?,
                    payload_read_limit,
                    WORKER_HANDOFF_OPERATION,
                    WORKER_HANDOFF_PAYLOAD_DIGEST
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((job_id, kind, payload_text, payload_digest, created_at, attempt_count)) = row
        else {
            tx.commit()?;
            return Ok(None);
        };
        validate_name(&job_id, "job id", 128)?;
        if kind != WORKER_HANDOFF_OPERATION {
            tx.commit()?;
            return Ok(None);
        }
        let payload =
            super::validate_claim_payload(&payload_text, &payload_digest, self.max_payload_bytes)?;
        if payload != empty_parameters() {
            tx.commit()?;
            return Ok(None);
        }
        let _created_at_ms = u64::try_from(created_at)
            .map_err(|_| WatchdogError::Conflict("job creation timestamp is invalid".to_owned()))?;
        let attempt_number = u32::try_from(attempt_count)
            .map_err(|_| WatchdogError::Conflict("job attempt counter overflow".to_owned()))?
            .checked_add(1)
            .ok_or_else(|| WatchdogError::Conflict("job attempt counter exhausted".to_owned()))?;
        let handoff_id = new_uuid4();
        let attempt_id = new_uuid4_distinct(&[&handoff_id]);
        let run_id = new_uuid4_distinct(&[&handoff_id, &attempt_id]);
        let episode_id = new_uuid4_distinct(&[&handoff_id, &attempt_id, &run_id]);
        let trajectory_id = new_uuid4_distinct(&[&handoff_id, &attempt_id, &run_id, &episode_id]);
        let changed = tx.execute(
            "UPDATE jobs SET status='running', claimed_at_ms=?, worker_id=?, attempt_count=? WHERE id=? AND status='queued' AND next_retry_at_ms IS NOT NULL AND next_retry_at_ms <= ?",
            params![
                sqlite_timestamp(now_ms)?,
                witness.worker_owner_id,
                i64::from(attempt_number),
                job_id,
                sqlite_timestamp(now_ms)?
            ],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO attempts (id, job_id, sequence, lineage, status, started_at_ms, worker_id) VALUES (?, ?, ?, ?, 'running', ?, ?)",
            params![
                attempt_id,
                job_id,
                i64::from(attempt_number),
                format!("{job_id}:{attempt_number}"),
                sqlite_timestamp(now_ms)?,
                witness.worker_owner_id
            ],
        )?;
        tx.execute(
            "INSERT INTO worker_handoffs (handoff_id, deployment_id, job_id, attempt_id, attempt_number, worker_owner_id, worker_profile_digest, run_id, episode_id, trajectory_id, payload_digest, watchdog_boot_id, worker_boot_id, mode_sequence, operation, parameters, state, ack_intent, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', 0, ?, ?)",
            params![
                handoff_id,
                witness.deployment_id,
                job_id,
                attempt_id,
                i64::from(attempt_number),
                witness.worker_owner_id,
                witness.worker_profile_digest,
                run_id,
                episode_id,
                trajectory_id,
                payload_digest,
                witness.watchdog_boot_id,
                witness.worker_boot_id,
                sqlite_timestamp(witness.mode_sequence)?,
                WORKER_HANDOFF_OPERATION,
                serde_json::to_string(&payload)?,
                sqlite_timestamp(now_ms)?,
                sqlite_timestamp(now_ms)?
            ],
        )?;
        insert_audit_tx(
            &tx,
            "worker_handoff_prepared",
            &format!("{job_id}:{attempt_id}:{handoff_id}"),
            now_ms,
        )?;
        tx.commit()?;
        self.worker_handoff(&handoff_id)?
            .ok_or_else(|| {
                WatchdogError::Conflict("worker handoff disappeared after commit".to_owned())
            })
            .map(Some)
    }

    /// Convenience wrapper using the current wall clock.
    pub fn claim_next_worker_handoff_now(
        &mut self,
        witness: &WorkerClaimWitness,
    ) -> Result<Option<WorkerHandoff>> {
        self.claim_next_worker_handoff(witness, super::now_unix_ms())
    }
}

fn validate_binding(conn: &Connection, binding: &WorkerBinding) -> Result<()> {
    let deployment_id = metadata_from_conn(conn, "deployment_id")?
        .ok_or_else(|| WatchdogError::Conflict("deployment_id metadata is missing".to_owned()))?;
    validate_name(&binding.deployment_id, "worker deployment id", 128)?;
    if binding.deployment_id != deployment_id {
        return Err(WatchdogError::Conflict(
            "worker binding deployment differs from the owner-local store".to_owned(),
        ));
    }
    validate_name(&binding.worker_owner_id, "worker owner id", 128)?;
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

fn validate_control(control: &WorkerControlWitness) -> Result<()> {
    validate_name(&control.deployment_id, "worker control deployment id", 128)?;
    validate_name(&control.worker_owner_id, "worker control owner id", 128)?;
    validate_digest_value(
        &control.worker_profile_digest,
        "worker control profile digest",
    )?;
    validate_uuid4(&control.watchdog_boot_id, "watchdog boot id")?;
    validate_uuid4(&control.worker_boot_id, "worker boot id")?;
    if control.mode_sequence == 0 || control.mode_sequence > MAX_WORKER_WIRE_INTEGER {
        return Err(WatchdogError::InvalidInput(
            "worker control mode sequence must be positive and fit the wire integer bound"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_claim_witness(witness: &WorkerClaimWitness) -> Result<()> {
    validate_name(&witness.deployment_id, "worker claim deployment id", 128)?;
    validate_name(&witness.worker_owner_id, "worker claim owner id", 128)?;
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
    validate_name(&tuple.deployment_id, "deployment id", 128)?;
    validate_name(&tuple.job_id, "job id", 128)?;
    if tuple.attempt_number == 0 {
        return Err(WatchdogError::InvalidInput(
            "worker attempt number must be positive".to_owned(),
        ));
    }
    validate_name(&tuple.worker_owner_id, "worker owner id", 128)?;
    validate_digest_value(&tuple.worker_profile_digest, "worker profile digest")?;
    validate_digest_value(&tuple.payload_digest, "payload digest")?;
    Ok(())
}

pub(super) fn validate_digest_value(value: &str, field: &str) -> Result<()> {
    validate_digest(value)
        .map_err(|message| WatchdogError::InvalidInput(format!("{field} is invalid: {message}")))
}

fn validate_control_against_binding(
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

fn validate_claim_witness_tx(tx: &Transaction<'_>, witness: &WorkerClaimWitness) -> Result<()> {
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

fn unresolved_handoff_exists(tx: &Transaction<'_>) -> Result<bool> {
    let value: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM worker_handoffs WHERE state IN ('prepared','may_have_been_dispatched','admitted') LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.is_some())
}

fn binding_from_conn(conn: &Connection) -> Result<Option<WorkerBinding>> {
    conn.query_row(
        "SELECT deployment_id, worker_owner_id, worker_profile_digest, release_digest, config_digest, schema_digest FROM worker_bindings WHERE singleton=1",
        [],
        |row| {
            Ok(WorkerBinding {
                deployment_id: row.get(0)?,
                worker_owner_id: row.get(1)?,
                worker_profile_digest: row.get(2)?,
                release_digest: row.get(3)?,
                config_digest: row.get(4)?,
                schema_digest: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn binding_from_tx(tx: &Transaction<'_>) -> Result<Option<WorkerBinding>> {
    tx.query_row(
        "SELECT deployment_id, worker_owner_id, worker_profile_digest, release_digest, config_digest, schema_digest FROM worker_bindings WHERE singleton=1",
        [],
        |row| {
            Ok(WorkerBinding {
                deployment_id: row.get(0)?,
                worker_owner_id: row.get(1)?,
                worker_profile_digest: row.get(2)?,
                release_digest: row.get(3)?,
                config_digest: row.get(4)?,
                schema_digest: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn control_from_conn(conn: &Connection) -> Result<Option<WorkerControlWitness>> {
    conn.query_row(
        "SELECT deployment_id, worker_owner_id, worker_profile_digest, watchdog_boot_id, worker_boot_id, mode, mode_sequence FROM worker_control WHERE singleton=1",
        [],
        control_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn control_from_tx(tx: &Transaction<'_>) -> Result<Option<WorkerControlWitness>> {
    tx.query_row(
        "SELECT deployment_id, worker_owner_id, worker_profile_digest, watchdog_boot_id, worker_boot_id, mode, mode_sequence FROM worker_control WHERE singleton=1",
        [],
        control_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn control_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkerControlWitness> {
    let mode: String = row.get(5)?;
    Ok(WorkerControlWitness {
        deployment_id: row.get(0)?,
        worker_owner_id: row.get(1)?,
        worker_profile_digest: row.get(2)?,
        watchdog_boot_id: row.get(3)?,
        worker_boot_id: row.get(4)?,
        mode: WorkerControlMode::parse(&mode).map_err(to_sqlite_error)?,
        mode_sequence: sqlite_u64(row.get(6)?, "worker control mode sequence")?,
    })
}

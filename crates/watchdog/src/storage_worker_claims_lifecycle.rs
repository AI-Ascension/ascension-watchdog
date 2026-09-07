//! Worker binding and durable worker-control admission.

use super::storage_worker_claims_state::{
    BINDING_SELECT, CONTROL_SELECT, binding_from_conn, binding_from_row, binding_from_tx,
    control_from_conn, control_from_row, ensure_phase_time_at_least,
};
use super::storage_worker_claims_validation::{
    validate_binding, validate_control, validate_control_against_binding,
};
use super::storage_worker_types::{
    WorkerBinding, WorkerClaimWitness, WorkerControlMode, WorkerControlWitness,
};
use super::{Store, insert_audit_tx, metadata_from_conn, sqlite_timestamp};
use crate::error::{Result, WatchdogError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

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
            .query_row(BINDING_SELECT, [], binding_from_row)
            .optional()?;
        if let Some(existing) = existing {
            let previous_updated_at: i64 = tx.query_row(
                "SELECT updated_at_ms FROM worker_bindings WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            ensure_phase_time_at_least(now_ms, previous_updated_at, "worker binding")?;
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

    /// Wall-clock convenience wrapper around the configure_worker_binding_at method.
    pub fn configure_worker_binding(&mut self, binding: &WorkerBinding) -> Result<WorkerBinding> {
        self.configure_worker_binding_at(binding, super::now_unix_ms())
    }

    /// Commit an authenticated control witness. Sequence numbers are
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
            .query_row(CONTROL_SELECT, [], control_from_row)
            .optional()?;
        if let Some(existing) = existing {
            let previous_updated_at: i64 = tx.query_row(
                "SELECT updated_at_ms FROM worker_control WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            ensure_phase_time_at_least(now_ms, previous_updated_at, "worker control")?;
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

    /// Wall-clock convenience wrapper around the set_worker_control_at method.
    pub fn set_worker_control(
        &mut self,
        control: &WorkerControlWitness,
    ) -> Result<WorkerControlWitness> {
        self.set_worker_control_at(control, super::now_unix_ms())
    }

    /// Return the currently admissible claim witness. Missing configuration,
    /// non-running control, and a paused/stopped durable mode produce None.
    pub fn current_worker_claim_witness(&self) -> Result<Option<WorkerClaimWitness>> {
        let binding = binding_from_conn(&self.conn)?;
        let Some(binding) = binding else {
            return Ok(None);
        };
        let control = control_from_conn(&self.conn)?;
        let Some(control) = control else {
            return Ok(None);
        };
        validate_control_against_binding(&control, &binding)?;
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
}

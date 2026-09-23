//! Host fencing and lease authority for the synthetic fixture.
//!
//! Owns the bootstrap/fence/lease request handlers and the current-fence and
//! current-lease authority checks.  Extracted verbatim from `lib.rs` by the
//! host-fencing-and-lease-authority split (issue #75); the crate root keeps the
//! `DurableHost` struct definition, the `handle` dispatcher and every other
//! responsibility.

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    DurableHost, FIXTURE_TIMESTAMP, FIXTURE_TOKEN, FixtureError, Frame, MAX_RUNTIME_INTEGER,
    RUNTIME_V3_SCHEMA_DIGEST, ResponseAction, current_tick, digest, fence_json, field_i64,
    field_string, require_capability, status, timestamp_for_tick, valid_v4, validate_boot_context,
    validate_host_fence, validate_lease_context, validate_lease_policy_values, validate_policy,
};

impl DurableHost {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn bootstrap(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "bootstrap")?;
        let deployment_id = field_string(&frame.payload, "deployment_id")?;
        let instance_id = field_string(&frame.payload, "instance_id")?;
        let incarnation = field_string(&frame.payload, "instance_incarnation")?;
        let policy = frame
            .payload
            .get("lease_policy")
            .ok_or_else(|| FixtureError::Invalid("lease policy missing".to_owned()))?;
        validate_policy(policy)?;
        let ttl_seconds = field_i64(policy, "ttl_seconds")?;
        let renewal_interval_seconds = field_i64(policy, "renewal_interval_seconds")?;
        valid_v4(&deployment_id)?;
        valid_v4(&instance_id)?;
        valid_v4(&incarnation)?;
        let current: Option<i64> = self
            .connection
            .query_row(
                "SELECT authority_generation FROM fence WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let generation = match current {
            None => 1,
            Some(value) if (1..MAX_RUNTIME_INTEGER).contains(&value) => value + 1,
            Some(_) => {
                return Err(FixtureError::Invalid(
                    "authority generation exhausted".to_owned(),
                ));
            }
        };
        let boot_id = Uuid::new_v4().to_string();
        let fence_id = Uuid::new_v4().to_string();
        let tx = self.connection.transaction().map_err(FixtureError::Sql)?;
        let fence_counter: Option<i64> = tx
            .query_row(
                "SELECT lease_epoch_counter FROM fence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let history_counter: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(lease_epoch),0) FROM lease_history",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let lease_epoch_counter = fence_counter.unwrap_or(0).max(history_counter);
        if !(0..=MAX_RUNTIME_INTEGER).contains(&lease_epoch_counter) {
            return Err(FixtureError::Invalid(
                "lease epoch history exhausted".to_owned(),
            ));
        }
        tx.execute(
            "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
            [],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        // Authority replacement makes every previously admitted runtime item
        // uncertain. Keep its journal row but remove the executable queue.
        tx.execute(
            "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
            params![FIXTURE_TIMESTAMP],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
            [],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
            params![FIXTURE_TIMESTAMP],
        )
        .map_err(FixtureError::Sql)?;
        tx.execute(
            "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
            [],
        )
        .map_err(FixtureError::Sql)?;
        let updated = tx
            .execute(
                "UPDATE fence SET deployment_id=?1,instance_id=?2,boot_id=?3,instance_incarnation=?4,authority_generation=?5,host_fence_id=?6,fence_generation=?5,authority_state='FENCE_REQUIRED',lease_epoch_counter=?7,lease_ttl_seconds=?8,lease_renewal_interval_seconds=?9 WHERE singleton=1",
                params![
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    generation,
                    fence_id,
                    lease_epoch_counter,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO fence(singleton,deployment_id,instance_id,boot_id,instance_incarnation,authority_generation,host_fence_id,fence_generation,authority_state,lease_epoch_counter,lease_ttl_seconds,lease_renewal_interval_seconds)
                 VALUES(1,?1,?2,?3,?4,?5,?6,?5,'FENCE_REQUIRED',?7,?8,?9)",
                params![
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    generation,
                    fence_id,
                    lease_epoch_counter,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        }
        tx.commit().map_err(FixtureError::Sql)?;
        let boot = json!({
            "deployment_id": deployment_id,
            "instance_id": instance_id,
            "instance_incarnation": incarnation,
            "boot_id": boot_id,
            "authority_generation": generation,
            "release": frame.payload.get("release").cloned().unwrap_or_else(|| json!({
                "release_digest": digest("release"), "config_digest": digest("config"),
                "profile_digest": digest("profile"), "runtime_v3_schema_digest": RUNTIME_V3_SCHEMA_DIGEST
            })),
            "created_at": FIXTURE_TIMESTAMP,
            "state": "FENCE_REQUIRED"
        });
        let fence = json!({
            "host_fence_id": fence_id,
            "deployment_id": boot["deployment_id"],
            "instance_id": boot["instance_id"],
            "instance_incarnation": boot["instance_incarnation"],
            "boot_id": boot["boot_id"],
            "authority_generation": generation,
            "fence_generation": generation,
            "created_at": FIXTURE_TIMESTAMP
        });
        Ok((
            frame.response(
                "bootstrap_response",
                json!({"result":status("BOOT_AUTHORITY_CREATED"),"boot":boot,"fence":fence}),
            ),
            ResponseAction::Send,
        ))
    }

    pub(crate) fn host_fence(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "host_fence")?;
        let boot = frame
            .payload
            .get("boot")
            .ok_or_else(|| FixtureError::Invalid("boot missing".to_owned()))?;
        validate_boot_context(boot)?;
        let deployment_id = field_string(boot, "deployment_id")?;
        let instance_id = field_string(boot, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let incarnation = field_string(boot, "instance_incarnation")?;
        let generation = field_i64(boot, "authority_generation")?;
        let current: Option<(String, String, String, String, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id, instance_id, boot_id, instance_incarnation, authority_generation, authority_state FROM fence WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_boot,
            current_incarnation,
            current_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if deployment_id != current_deployment
            || instance_id != current_instance
            || boot_id != current_boot
            || incarnation != current_incarnation
            || generation != current_generation
        {
            return Err(FixtureError::Stale("boot"));
        }
        if !matches!(authority_state.as_str(), "FENCE_REQUIRED" | "READY") {
            return Err(FixtureError::HostNotReady);
        }
        // Fencing is the explicit transition that makes the freshly
        // bootstrapped authority usable. A restarted host remains blocked
        // until bootstrap replaces the old boot/fence fields.
        let changed = self
            .connection
            .execute(
                "UPDATE fence SET authority_state='READY' WHERE singleton=1 AND deployment_id=?1 AND instance_id=?2 AND boot_id=?3 AND instance_incarnation=?4 AND authority_generation=?5 AND authority_state IN ('FENCE_REQUIRED','READY')",
                params![deployment_id, instance_id, boot_id, incarnation, generation],
            )
            .map_err(FixtureError::Sql)?;
        if changed != 1 {
            return Err(FixtureError::HostNotReady);
        }
        let fence: (String, i64) = self
            .connection
            .query_row(
                "SELECT host_fence_id, fence_generation FROM fence WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(FixtureError::Sql)?;
        Ok((
            frame.response(
                "host_fence_response",
                json!({
                    "result": status("FENCE_ACCEPTED"),
                    "fence": fence_json(boot, &fence.0, fence.1)
                }),
            ),
            ResponseAction::Send,
        ))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn lease_acquire(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_acquire")?;
        let boot = frame
            .payload
            .get("boot")
            .ok_or_else(|| FixtureError::Invalid("boot missing".to_owned()))?;
        let fence = frame
            .payload
            .get("fence")
            .ok_or_else(|| FixtureError::Invalid("fence missing".to_owned()))?;
        self.validate_fence_pair(boot, fence)?;
        validate_boot_context(boot)?;
        validate_host_fence(fence)?;
        let lease_id = Uuid::new_v4().to_string();
        let token = FIXTURE_TOKEN;
        let deployment_id = field_string(boot, "deployment_id")?;
        let instance_id = field_string(boot, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let incarnation = field_string(boot, "instance_incarnation")?;
        let host_fence_id = field_string(fence, "host_fence_id")?;
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        let (counter, ttl_seconds, renewal_interval_seconds, authority_state): (i64, i64, i64, String) =
            transaction
                .query_row(
                    "SELECT lease_epoch_counter,lease_ttl_seconds,lease_renewal_interval_seconds,authority_state FROM fence WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(FixtureError::Sql)?
                .ok_or(FixtureError::HostNotReady)?;
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        validate_lease_policy_values(ttl_seconds, renewal_interval_seconds)?;
        let history_counter: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(lease_epoch),0) FROM lease_history",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let counter = counter.max(history_counter);
        if !(0..MAX_RUNTIME_INTEGER).contains(&counter) {
            return Err(FixtureError::Invalid("lease epoch exhausted".to_owned()));
        }
        let epoch = counter + 1;
        let issued_tick: i64 = transaction
            .query_row(
                "SELECT tick FROM fixture_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(FixtureError::Sql)?;
        let expires_tick = issued_tick.saturating_add(ttl_seconds);
        let issued_at = timestamp_for_tick(issued_tick);
        let expires_at = timestamp_for_tick(expires_tick);

        // Reacquiring in one fenced boot revokes the prior projection while
        // retaining its immutable history row. Any queued work under that
        // lease is now uncertain and must not remain executable.
        transaction
            .execute(
                "INSERT OR IGNORE INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 SELECT lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,?1,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                params![digest(token)],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id IN (SELECT lease_id FROM lease WHERE singleton=1)",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute("UPDATE lease SET revoked=1 WHERE singleton=1", [])
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE runtime_operations SET status='UNKNOWN',updated_at=?1 WHERE status IN ('ADMITTED','EXECUTING')",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM runtime_queue WHERE operation_id IN (SELECT operation_id FROM runtime_operations WHERE status='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE operations SET state='UNKNOWN',uncertainty_reason='authority_rotated',ticket_json=json_set(ticket_json,'$.state','UNKNOWN'),updated_at=?1 WHERE state='MAY_HAVE_BEEN_DISPATCHED'",
                params![FIXTURE_TIMESTAMP],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "DELETE FROM queue WHERE operation_id IN (SELECT operation_id FROM operations WHERE state='UNKNOWN')",
                [],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fence SET lease_epoch_counter=?1 WHERE singleton=1",
                params![epoch],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO lease_history(lease_id,lease_epoch,deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,fence_token_digest,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0,0)",
                params![
                    lease_id,
                    epoch,
                    deployment_id,
                    instance_id,
                    boot_id,
                    incarnation,
                    host_fence_id,
                    digest(token),
                    issued_at,
                    expires_at,
                    issued_tick,
                    expires_tick,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "INSERT INTO lease(singleton,deployment_id,instance_id,lease_id,lease_epoch,boot_id,instance_incarnation,host_fence_id,fence_token,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked)
                 VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0,0)
                 ON CONFLICT(singleton) DO UPDATE SET deployment_id=excluded.deployment_id,instance_id=excluded.instance_id,lease_id=excluded.lease_id,lease_epoch=excluded.lease_epoch,boot_id=excluded.boot_id,instance_incarnation=excluded.instance_incarnation,host_fence_id=excluded.host_fence_id,fence_token=excluded.fence_token,issued_at=excluded.issued_at,expires_at=excluded.expires_at,issued_tick=excluded.issued_tick,expires_tick=excluded.expires_tick,ttl_seconds=excluded.ttl_seconds,renewal_interval_seconds=excluded.renewal_interval_seconds,renew_sequence=excluded.renew_sequence,revoked=excluded.revoked",
                params![
                    deployment_id,
                    instance_id,
                    lease_id,
                    epoch,
                    boot_id,
                    incarnation,
                    host_fence_id,
                    token,
                    issued_at,
                    expires_at,
                    issued_tick,
                    expires_tick,
                    ttl_seconds,
                    renewal_interval_seconds,
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        let lease = json!({
            "deployment_id": boot["deployment_id"], "instance_id": boot["instance_id"],
            "instance_incarnation": boot["instance_incarnation"], "boot_id": boot["boot_id"],
            "authority_generation": boot["authority_generation"], "lease_id": lease_id,
            "lease_epoch": epoch,
            "fence_token": token, "issued_at": issued_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds, "renewal_interval_seconds": renewal_interval_seconds
        });
        Ok((
            frame.response(
                "lease_acquire_response",
                json!({"result":status("LEASE_ACTIVE"),"lease":lease}),
            ),
            ResponseAction::Send,
        ))
    }

    pub(crate) fn lease_renew(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_renew")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let renew_sequence = field_i64(&frame.payload, "renew_sequence")?;
        let (current_sequence, ttl_seconds, renewal_interval_seconds, expires_tick): (i64, i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT renew_sequence,ttl_seconds,renewal_interval_seconds,expires_tick FROM lease WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(FixtureError::Sql)?;
        if renew_sequence != current_sequence.saturating_add(1) {
            return Err(FixtureError::Conflict);
        }
        let now_tick = current_tick(&self.connection)?
            .saturating_add(renewal_interval_seconds)
            .max(expires_tick.saturating_sub(ttl_seconds));
        let new_expires_tick = now_tick.saturating_add(ttl_seconds);
        let new_expires_at = timestamp_for_tick(new_expires_tick);
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE fixture_clock SET tick=?1 WHERE singleton=1",
                params![now_tick],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease SET expires_at=?1,expires_tick=?2,renew_sequence=?3 WHERE singleton=1 AND lease_id=?4",
                params![new_expires_at, new_expires_tick, renew_sequence, field_string(lease, "lease_id")?],
            )
            .map_err(FixtureError::Sql)?;
        let history_changed = transaction
            .execute(
                "UPDATE lease_history SET expires_at=?1,expires_tick=?2,renew_sequence=?3 WHERE lease_id=?4",
                params![new_expires_at, new_expires_tick, renew_sequence, field_string(lease, "lease_id")?],
            )
            .map_err(FixtureError::Sql)?;
        if history_changed != 1 {
            return Err(FixtureError::Conflict);
        }
        transaction.commit().map_err(FixtureError::Sql)?;
        let mut renewed = lease.clone();
        renewed["expires_at"] = Value::String(new_expires_at);
        Ok((
            frame.response(
                "lease_renew_response",
                json!({"result":status("LEASE_RENEWED"),"lease":renewed}),
            ),
            ResponseAction::Send,
        ))
    }

    pub(crate) fn lease_revoke(
        &mut self,
        frame: &Frame,
    ) -> Result<(Frame, ResponseAction), FixtureError> {
        require_capability(frame, "lease_revoke")?;
        let lease = frame
            .payload
            .get("lease")
            .ok_or_else(|| FixtureError::Invalid("lease missing".to_owned()))?;
        self.validate_lease(lease)?;
        let transaction = self.connection.transaction().map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease SET revoked=1 WHERE singleton=1 AND lease_id=?1 AND lease_epoch=?2",
                params![
                    field_string(lease, "lease_id")?,
                    field_i64(lease, "lease_epoch")?
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction
            .execute(
                "UPDATE lease_history SET revoked=1 WHERE lease_id=?1 AND lease_epoch=?2",
                params![
                    field_string(lease, "lease_id")?,
                    field_i64(lease, "lease_epoch")?
                ],
            )
            .map_err(FixtureError::Sql)?;
        transaction.commit().map_err(FixtureError::Sql)?;
        Ok((
            frame.response(
                "lease_revoke_response",
                json!({"result":status("LEASE_REVOKED")}),
            ),
            ResponseAction::Send,
        ))
    }
}

impl DurableHost {
    fn validate_fence_pair(&self, boot: &Value, fence: &Value) -> Result<(), FixtureError> {
        validate_boot_context(boot)?;
        validate_host_fence(fence)?;
        let boot_deployment = field_string(boot, "deployment_id")?;
        let fence_deployment = field_string(fence, "deployment_id")?;
        let boot_instance = field_string(boot, "instance_id")?;
        let fence_instance = field_string(fence, "instance_id")?;
        let boot_id = field_string(boot, "boot_id")?;
        let fence_boot = field_string(fence, "boot_id")?;
        if boot_deployment != fence_deployment
            || boot_instance != fence_instance
            || boot_id != fence_boot
            || field_string(boot, "instance_incarnation")?
                != field_string(fence, "instance_incarnation")?
            || field_i64(boot, "authority_generation")? != field_i64(fence, "authority_generation")?
        {
            return Err(FixtureError::Stale("boot"));
        }
        self.validate_current_fence(fence)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn validate_current_fence(&self, fence: &Value) -> Result<(), FixtureError> {
        validate_host_fence(fence)?;
        let supplied = field_string(fence, "host_fence_id")?;
        let current: Option<(String, String, String, String, String, i64, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id, instance_id, boot_id, instance_incarnation, host_fence_id, authority_generation, fence_generation, authority_state FROM fence WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            deployment_id,
            instance_id,
            boot_id,
            incarnation,
            current_fence,
            authority_generation,
            fence_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        if current_fence != supplied
            || field_string(fence, "deployment_id")? != deployment_id
            || field_string(fence, "instance_id")? != instance_id
            || field_string(fence, "boot_id")? != boot_id
            || field_string(fence, "instance_incarnation")? != incarnation
            || field_i64(fence, "authority_generation")? != authority_generation
            || field_i64(fence, "fence_generation")? != fence_generation
        {
            return Err(FixtureError::Stale("fence"));
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn validate_lease(&self, lease: &Value) -> Result<(), FixtureError> {
        validate_lease_context(lease)?;
        let lease_id = field_string(lease, "lease_id")?;
        let epoch = field_i64(lease, "lease_epoch")?;
        let current: Option<(
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        )> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,lease_id,lease_epoch,boot_id,instance_incarnation,host_fence_id,fence_token,issued_at,expires_at,issued_tick,expires_tick,ttl_seconds,renewal_interval_seconds,renew_sequence,revoked FROM lease WHERE singleton=1",
                [],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?,
                )),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_id,
            current_epoch,
            current_boot,
            current_incarnation,
            current_fence,
            current_token,
            issued_at,
            expires_at,
            _issued_tick,
            expires_tick,
            ttl_seconds,
            renewal_interval_seconds,
            renew_sequence,
            revoked,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        validate_lease_policy_values(ttl_seconds, renewal_interval_seconds)?;
        if revoked != 0 {
            return Err(FixtureError::Stale("revoked lease"));
        }
        if lease_id != current_id
            || epoch != current_epoch
            || field_string(lease, "deployment_id")? != current_deployment
            || field_string(lease, "instance_id")? != current_instance
            || field_string(lease, "boot_id")? != current_boot
            || field_string(lease, "instance_incarnation")? != current_incarnation
            || field_string(lease, "fence_token")? != current_token
            || field_string(lease, "issued_at")? != issued_at
            || field_string(lease, "expires_at")? != expires_at
            || field_i64(lease, "ttl_seconds")? != ttl_seconds
            || field_i64(lease, "renewal_interval_seconds")? != renewal_interval_seconds
            || current_tick(&self.connection)? >= expires_tick
        {
            return Err(FixtureError::Stale("lease"));
        }
        self.validate_current_fence_fields(
            &field_string(lease, "deployment_id")?,
            &field_string(lease, "instance_id")?,
            &field_string(lease, "boot_id")?,
            &field_string(lease, "instance_incarnation")?,
            field_i64(lease, "authority_generation")?,
            &current_fence,
        )?;
        let _ = (renew_sequence, expires_at);
        Ok(())
    }

    fn validate_current_fence_fields(
        &self,
        deployment_id: &str,
        instance_id: &str,
        boot_id: &str,
        incarnation: &str,
        authority_generation: i64,
        fence_id: &str,
    ) -> Result<(), FixtureError> {
        let current: Option<(String, String, String, String, String, i64, String)> = self
            .connection
            .query_row(
                "SELECT deployment_id,instance_id,boot_id,instance_incarnation,host_fence_id,authority_generation,authority_state FROM fence WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .optional()
            .map_err(FixtureError::Sql)?;
        let Some((
            current_deployment,
            current_instance,
            current_boot,
            current_incarnation,
            current_fence,
            current_generation,
            authority_state,
        )) = current
        else {
            return Err(FixtureError::HostNotReady);
        };
        if authority_state != "READY" {
            return Err(FixtureError::HostNotReady);
        }
        if deployment_id != current_deployment
            || instance_id != current_instance
            || boot_id != current_boot
            || incarnation != current_incarnation
            || authority_generation != current_generation
            || fence_id != current_fence
        {
            return Err(FixtureError::Stale("lease"));
        }
        Ok(())
    }
}

//! Read-only projection of the durable release selector.
//!
//! Status, recovery and every owner/read-only open read the selector through
//! this module.  Nothing here writes metadata: a malformed selector is
//! reported as a conflict instead of being repaired, defaulted or recreated.

use super::super::{Store, WatchdogError, metadata_from_conn, validate_digest, validate_name};
use super::identity::{
    ACTIVE_DIGEST_KEY, ACTIVE_ID_KEY, PENDING_DIGEST_KEY, PENDING_ID_KEY, PENDING_IDEMPOTENCY_KEY,
    PENDING_PREVIOUS_DIGEST_KEY, PENDING_PREVIOUS_ID_KEY, PENDING_REQUEST_KEY,
    PENDING_ROLLBACK_KEY, PREVIOUS_DIGEST_KEY, PREVIOUS_ID_KEY, PendingReleaseActivation,
    ReleaseIdentity, ReleaseSelection, ReleaseSelectionState, STATE_KEY, read_identity,
    read_identity_values,
};
use crate::error::Result;

impl Store {
    /// Read and validate the durable selector without changing state.
    pub fn release_selection(&self) -> Result<ReleaseSelection> {
        read_selection(&self.conn)
    }

    /// Validate selector metadata during every owner/read-only open. Missing
    /// optional keys mean the store has never selected a release; malformed or
    /// half-written pairs are corruption, never defaults.
    pub(crate) fn validate_release_selection_metadata(&self) -> Result<()> {
        let _ = self.release_selection()?;
        Ok(())
    }
}

pub(super) fn read_selection(conn: &rusqlite::Connection) -> Result<ReleaseSelection> {
    let state_text = metadata_from_conn(conn, STATE_KEY)?.unwrap_or_else(|| "none".to_owned());
    let state = match state_text.as_str() {
        "none" => ReleaseSelectionState::None,
        "prepared" => ReleaseSelectionState::Prepared,
        "active" => ReleaseSelectionState::Active,
        _ => {
            return Err(WatchdogError::Conflict(
                "release selector state is malformed".to_owned(),
            ));
        }
    };
    let active = read_identity(conn, ACTIVE_ID_KEY, ACTIVE_DIGEST_KEY, "active release")?;
    let previous = read_identity(
        conn,
        PREVIOUS_ID_KEY,
        PREVIOUS_DIGEST_KEY,
        "previous release",
    )?;
    let pending_id = metadata_from_conn(conn, PENDING_ID_KEY)?;
    let pending_digest = metadata_from_conn(conn, PENDING_DIGEST_KEY)?;
    let pending_rollback = metadata_from_conn(conn, PENDING_ROLLBACK_KEY)?;
    let pending_request = metadata_from_conn(conn, PENDING_REQUEST_KEY)?;
    let pending_key = metadata_from_conn(conn, PENDING_IDEMPOTENCY_KEY)?;
    let pending_previous_id = metadata_from_conn(conn, PENDING_PREVIOUS_ID_KEY)?;
    let pending_previous_digest = metadata_from_conn(conn, PENDING_PREVIOUS_DIGEST_KEY)?;
    let any_pending = pending_id.is_some()
        || pending_digest.is_some()
        || pending_rollback.is_some()
        || pending_request.is_some()
        || pending_key.is_some()
        || pending_previous_id.is_some()
        || pending_previous_digest.is_some();
    let pending = if any_pending {
        let (Some(id), Some(digest), Some(rollback), Some(request_id), Some(idempotency_key)) = (
            pending_id,
            pending_digest,
            pending_rollback,
            pending_request,
            pending_key,
        ) else {
            return Err(WatchdogError::Conflict(
                "release selector pending marker is incomplete".to_owned(),
            ));
        };
        validate_name(&id, "pending release id", 128)?;
        validate_digest(&digest).map_err(WatchdogError::Conflict)?;
        let rollback = match rollback.as_str() {
            "0" => false,
            "1" => true,
            _ => {
                return Err(WatchdogError::Conflict(
                    "pending release rollback marker is malformed".to_owned(),
                ));
            }
        };
        validate_name(&request_id, "pending release request id", 128)?;
        validate_name(&idempotency_key, "pending release idempotency key", 128)?;
        let previous = read_identity_values(
            pending_previous_id,
            pending_previous_digest,
            "pending previous release",
        )?;
        Some(PendingReleaseActivation {
            release: ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            },
            rollback,
            request_id,
            idempotency_key,
            previous,
        })
    } else {
        None
    };
    if state == ReleaseSelectionState::Prepared && pending.is_none() {
        return Err(WatchdogError::Conflict(
            "prepared release selector has no pending marker".to_owned(),
        ));
    }
    if state != ReleaseSelectionState::Prepared && pending.is_some() {
        return Err(WatchdogError::Conflict(
            "non-prepared release selector has a pending marker".to_owned(),
        ));
    }
    if state == ReleaseSelectionState::Active && active.is_none() {
        return Err(WatchdogError::Conflict(
            "active release selector has no active identity".to_owned(),
        ));
    }
    if state == ReleaseSelectionState::None && active.is_some() {
        return Err(WatchdogError::Conflict(
            "empty release selector has an active identity".to_owned(),
        ));
    }
    Ok(ReleaseSelection {
        state,
        active,
        previous,
        pending,
    })
}

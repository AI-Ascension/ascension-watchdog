//! Durable release-selector identities and their strict parsing.
//!
//! This module owns the release-selector metadata key namespace, the selector
//! value types and the exact parse and validation rules for every identity
//! stored in it.  Release bytes are validated by the protected catalog before
//! these values are read; this module only decides whether the durable
//! selector itself can be trusted.  A malformed, half-written or mismatched
//! identity is corruption, never a default.

use super::super::{WatchdogError, metadata_from_conn, validate_digest, validate_name};
use crate::error::Result;
use serde::{Deserialize, Serialize};

pub(super) const STATE_KEY: &str = "release_selection_state";
pub(super) const ACTIVE_ID_KEY: &str = "active_release_id";
pub(super) const ACTIVE_DIGEST_KEY: &str = "approved_release_digest";
pub(super) const PREVIOUS_ID_KEY: &str = "previous_release_id";
pub(super) const PREVIOUS_DIGEST_KEY: &str = "previous_release_digest";
pub(super) const PENDING_ID_KEY: &str = "pending_release_id";
pub(super) const PENDING_DIGEST_KEY: &str = "pending_release_digest";
pub(super) const PENDING_ROLLBACK_KEY: &str = "pending_release_rollback";
pub(super) const PENDING_REQUEST_KEY: &str = "pending_release_request_id";
pub(super) const PENDING_IDEMPOTENCY_KEY: &str = "pending_release_idempotency_key";
pub(super) const PENDING_PREVIOUS_ID_KEY: &str = "pending_release_previous_id";
pub(super) const PENDING_PREVIOUS_DIGEST_KEY: &str = "pending_release_previous_digest";

/// Durable selector state. `Prepared` means an activation was admitted and
/// must be retried with its exact request after an interrupted final check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSelectionState {
    None,
    Prepared,
    Active,
}

/// One immutable release identity. The digest is the exact manifest-byte
/// digest, not a reserialized representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release_id: String,
    pub release_digest: String,
}

/// A pending activation marker retained across process and machine restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingReleaseActivation {
    pub release: ReleaseIdentity,
    pub rollback: bool,
    pub request_id: String,
    pub idempotency_key: String,
    pub previous: Option<ReleaseIdentity>,
}

/// Read-only selector projection for status, recovery and tests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSelection {
    pub state: ReleaseSelectionState,
    pub active: Option<ReleaseIdentity>,
    pub previous: Option<ReleaseIdentity>,
    pub pending: Option<PendingReleaseActivation>,
}

pub(super) fn read_identity(
    conn: &rusqlite::Connection,
    id_key: &str,
    digest_key: &str,
    label: &str,
) -> Result<Option<ReleaseIdentity>> {
    let id = metadata_from_conn(conn, id_key)?;
    let digest = metadata_from_conn(conn, digest_key)?;
    match (id, digest) {
        (None, None) => Ok(None),
        (Some(id), Some(digest)) => {
            validate_name(&id, label, 128)?;
            validate_digest(&digest).map_err(WatchdogError::Conflict)?;
            Ok(Some(ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            }))
        }
        _ => Err(WatchdogError::Conflict(format!(
            "{label} identity is incomplete"
        ))),
    }
}

pub(super) fn read_identity_values(
    id: Option<String>,
    digest: Option<String>,
    label: &str,
) -> Result<Option<ReleaseIdentity>> {
    match (id, digest) {
        (None, None) => Ok(None),
        (Some(id), Some(digest)) => {
            validate_name(&id, label, 128)?;
            validate_digest(&digest).map_err(WatchdogError::Conflict)?;
            Ok(Some(ReleaseIdentity {
                release_id: id,
                release_digest: digest,
            }))
        }
        _ => Err(WatchdogError::Conflict(format!(
            "{label} identity is incomplete"
        ))),
    }
}

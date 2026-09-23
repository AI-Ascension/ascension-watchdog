//! In-memory reference host used to pin the stateful lifecycle rules.
//!
//! The host models persisted grants (token replaced by its digest), renew
//! identity, restart, expiry and duplicate/conflict lineage exactly as before.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::frame::validate_request_semantics;
use crate::support::{canonical, object, sha256_hex, string};
use crate::time::{TimestampKey, derive_deadline, timestamp_key};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceStatus {
    Installed,
    Duplicate,
    Renewed,
    RenewDuplicate,
    Revoked,
    RevokeDuplicate,
    Conflict,
    Missing,
    Expired,
    Invalid,
}

#[derive(Clone, Debug)]
struct PreparedRequest {
    installation_id: String,
    grant_digest: String,
    persisted_grant: Value,
    renewal_identity: Value,
    token_digest: String,
    lease_id: String,
    expires: TimestampKey,
    sequence: Option<u64>,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StoredInstallation {
    initial_grant_digest: String,
    initial_persisted_grant: Value,
    current_grant_digest: String,
    pub current_persisted_grant: Value,
    current_renewal_identity: Value,
    token_digest: String,
    lease_id: String,
    expires: TimestampKey,
    renewal_sequence: u64,
    pub active: bool,
    revoked_reason: Option<String>,
    restarted: bool,
    deadline: Option<u64>,
}

#[derive(Default)]
pub struct ReferenceHost {
    pub installations: BTreeMap<String, StoredInstallation>,
    lease_installations: BTreeMap<String, String>,
}

fn persisted_grant(value: &Value) -> Result<(Value, String), String> {
    let mut persisted = value.clone();
    let grant = persisted.as_object_mut().ok_or("grant must be an object")?;
    let lease = grant
        .get_mut("lease")
        .and_then(Value::as_object_mut)
        .ok_or("grant.lease must be an object")?;
    let token = lease
        .get("fence_token")
        .and_then(Value::as_str)
        .ok_or("grant.lease.fence_token missing")?
        .to_owned();
    lease.remove("fence_token");
    let token_digest = sha256_hex(token.as_bytes());
    lease.insert(
        "fence_token_digest".to_owned(),
        Value::String(token_digest.clone()),
    );
    Ok((persisted, token_digest))
}

fn renewal_identity(value: &Value) -> Result<Value, String> {
    let (mut persisted, _) = persisted_grant(value)?;
    persisted
        .get_mut("lease")
        .and_then(Value::as_object_mut)
        .ok_or("persisted grant.lease missing")?
        .remove("expires_at");
    Ok(persisted)
}

fn request_parts<'a>(value: &'a Value, kind: &str) -> Result<&'a Map<String, Value>, String> {
    validate_request_semantics(value, kind)?;
    let frame = object(value, "frame")?;
    object(frame.get("payload").ok_or("payload missing")?, "payload")
}

fn prepare_request(value: &Value, kind: &str) -> Result<PreparedRequest, String> {
    let payload = request_parts(value, kind)?;
    let grant = payload.get("grant").ok_or("grant missing")?;
    let (persisted, token_digest) = persisted_grant(grant)?;
    let expires = timestamp_key(
        string(
            object(
                grant.get("lease").ok_or("grant.lease missing")?,
                "grant.lease",
            )?,
            "expires_at",
            "grant.lease",
        )?,
        "grant.lease.expires_at",
    )?;
    let lease = object(
        grant.get("lease").ok_or("grant.lease missing")?,
        "grant.lease",
    )?;
    let sequence = payload.get("renew_sequence").and_then(Value::as_u64);
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(PreparedRequest {
        installation_id: string(payload, "installation_id", "payload")?.to_owned(),
        grant_digest: string(payload, "grant_digest", "payload")?.to_owned(),
        renewal_identity: renewal_identity(grant)?,
        persisted_grant: persisted,
        token_digest,
        lease_id: string(lease, "lease_id", "grant.lease")?.to_owned(),
        expires,
        sequence,
        reason,
    })
}

impl ReferenceHost {
    pub fn install(
        &mut self,
        request: &Value,
        received_at: &str,
        received_at_monotonic: u64,
    ) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_install_request") else {
            return ReferenceStatus::Invalid;
        };
        let Ok(received) = timestamp_key(received_at, "received_at") else {
            return ReferenceStatus::Invalid;
        };
        if let Some(existing) = self.installations.get_mut(&prepared.installation_id) {
            if existing.initial_grant_digest == prepared.grant_digest
                && existing.initial_persisted_grant == prepared.persisted_grant
            {
                // A retry replays the retained install identity. It must never
                // reactivate a revoked or restart-invalidated tombstone.
                return if existing.restarted {
                    ReferenceStatus::Conflict
                } else {
                    ReferenceStatus::Duplicate
                };
            }
            return ReferenceStatus::Conflict;
        }
        if self.lease_installations.contains_key(&prepared.lease_id) {
            return ReferenceStatus::Conflict;
        }
        let ttl = request
            .pointer("/payload/grant/lease/ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let Ok(deadline) = derive_deadline(received, prepared.expires, ttl, received_at_monotonic)
        else {
            return ReferenceStatus::Expired;
        };
        let stored = StoredInstallation {
            initial_grant_digest: prepared.grant_digest.clone(),
            initial_persisted_grant: prepared.persisted_grant.clone(),
            current_grant_digest: prepared.grant_digest.clone(),
            current_persisted_grant: prepared.persisted_grant,
            current_renewal_identity: prepared.renewal_identity,
            token_digest: prepared.token_digest,
            lease_id: prepared.lease_id.clone(),
            expires: prepared.expires,
            renewal_sequence: 0,
            active: true,
            revoked_reason: None,
            restarted: false,
            deadline: Some(deadline),
        };
        self.lease_installations
            .insert(prepared.lease_id, prepared.installation_id.clone());
        self.installations.insert(prepared.installation_id, stored);
        ReferenceStatus::Installed
    }

    pub fn renew(
        &mut self,
        request: &Value,
        received_at: &str,
        received_at_monotonic: u64,
    ) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_renew_request") else {
            return ReferenceStatus::Invalid;
        };
        let Ok(received) = timestamp_key(received_at, "received_at") else {
            return ReferenceStatus::Invalid;
        };
        let Some(existing) = self.installations.get_mut(&prepared.installation_id) else {
            return ReferenceStatus::Missing;
        };
        let Some(sequence) = prepared.sequence else {
            return ReferenceStatus::Invalid;
        };
        if !existing.active {
            return if existing.restarted {
                ReferenceStatus::Conflict
            } else {
                ReferenceStatus::Missing
            };
        }
        if existing.lease_id != prepared.lease_id
            || existing.token_digest != prepared.token_digest
            || existing.current_renewal_identity != prepared.renewal_identity
        {
            return ReferenceStatus::Conflict;
        }
        if sequence == existing.renewal_sequence
            && existing.current_grant_digest == prepared.grant_digest
            && existing.current_persisted_grant == prepared.persisted_grant
        {
            return ReferenceStatus::RenewDuplicate;
        }
        let ttl = request
            .pointer("/payload/grant/lease/ttl_seconds")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let Ok(deadline) = derive_deadline(received, prepared.expires, ttl, received_at_monotonic)
        else {
            return ReferenceStatus::Expired;
        };
        if sequence <= existing.renewal_sequence || prepared.expires <= existing.expires {
            return ReferenceStatus::Conflict;
        }
        existing.current_grant_digest = prepared.grant_digest;
        existing.current_persisted_grant = prepared.persisted_grant;
        existing.current_renewal_identity = prepared.renewal_identity;
        existing.expires = prepared.expires;
        existing.renewal_sequence = sequence;
        existing.deadline = Some(deadline);
        ReferenceStatus::Renewed
    }

    pub fn revoke(&mut self, request: &Value) -> ReferenceStatus {
        let Ok(prepared) = prepare_request(request, "lease_revoke_request") else {
            return ReferenceStatus::Invalid;
        };
        let Some(existing) = self.installations.get_mut(&prepared.installation_id) else {
            return ReferenceStatus::Missing;
        };
        if existing.lease_id != prepared.lease_id
            || existing.token_digest != prepared.token_digest
            || existing.current_grant_digest != prepared.grant_digest
            || existing.current_persisted_grant != prepared.persisted_grant
        {
            return ReferenceStatus::Conflict;
        }
        if !existing.active {
            return if existing.revoked_reason == prepared.reason {
                ReferenceStatus::RevokeDuplicate
            } else {
                ReferenceStatus::Conflict
            };
        }
        existing.active = false;
        existing.deadline = None;
        existing.revoked_reason = prepared.reason;
        ReferenceStatus::Revoked
    }

    pub fn restart(&mut self) {
        for installation in self.installations.values_mut() {
            if installation.active {
                installation.restarted = true;
            }
            installation.active = false;
            installation.deadline = None;
        }
    }

    pub fn deadline(&self, installation_id: &str) -> Option<u64> {
        self.installations
            .get(installation_id)
            .and_then(|installation| installation.deadline)
    }
}

pub fn set_grant_digest(request: &mut Value) -> Result<(), String> {
    let grant = request
        .pointer("/payload/grant")
        .ok_or("request grant missing")?;
    let digest = sha256_hex(canonical(grant)?.as_bytes());
    *request
        .pointer_mut("/payload/grant_digest")
        .ok_or("request grant digest missing")? = Value::String(digest);
    Ok(())
}

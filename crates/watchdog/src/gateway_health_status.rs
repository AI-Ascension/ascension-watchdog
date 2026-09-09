//! Closed gateway-owned status schema, validated after response authentication.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{HealthError, MAX_BODY_BYTES, valid_nonce};

/// Independently configured release/instance identity for one owned launch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHealthBinding {
    pub deployment_id: String,
    pub instance_id: String,
    pub launch_nonce: Uuid,
    pub release_digest: String,
    pub config_digest: String,
    pub profile_digest: String,
    pub runtime_v3_schema_digest: String,
}

impl GatewayHealthBinding {
    pub(super) fn validate(&self) -> Result<(), HealthError> {
        if !valid_id(&self.deployment_id)
            || !valid_id(&self.instance_id)
            || !valid_nonce(self.launch_nonce)
            || [
                &self.release_digest,
                &self.config_digest,
                &self.profile_digest,
                &self.runtime_v3_schema_digest,
            ]
            .iter()
            .any(|value| !valid_digest(value))
        {
            return Err(HealthError::Configuration);
        }
        Ok(())
    }
}

// Unlike Option<T> directly on a struct, this wrapper requires the JSON member
// to exist even when its value may explicitly be null.
#[derive(Debug, PartialEq)]
struct Nullable<T>(Option<T>);

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Nullable<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Nullable)
}

/// Authenticated diagnostics only. `ready` does not grant a game lease and
/// `gateway_worker` progress does not prove game-thread progress.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHealthStatus {
    contract: String,
    liveness: String,
    process_binding: String,
    readiness: String,
    phase: String,
    #[serde(deserialize_with = "required_nullable")]
    phase_deadline: Nullable<String>,
    progress: Progress,
    identity: Identity,
    lease: Lease,
    queue: Queue,
    #[serde(deserialize_with = "required_nullable")]
    pending_operation_count: Nullable<u64>,
    downstream_readiness: String,
    shutdown_requested: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    heartbeat_sequence: u64,
    #[serde(deserialize_with = "required_nullable")]
    heartbeat_age_ms: Nullable<u64>,
    #[serde(deserialize_with = "required_nullable")]
    meaningful_progress_age_ms: Nullable<u64>,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    #[serde(deserialize_with = "required_nullable")]
    deployment_id: Nullable<String>,
    instance_id: String,
    #[serde(deserialize_with = "required_nullable")]
    instance_incarnation: Nullable<String>,
    #[serde(deserialize_with = "required_nullable")]
    boot_id: Nullable<String>,
    #[serde(deserialize_with = "required_nullable")]
    authority_generation: Nullable<u64>,
    #[serde(deserialize_with = "required_nullable")]
    launch_nonce: Nullable<String>,
    release: Release,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    #[serde(rename = "release_digest", deserialize_with = "required_nullable")]
    artifact: Nullable<String>,
    #[serde(rename = "config_digest", deserialize_with = "required_nullable")]
    config: Nullable<String>,
    #[serde(rename = "profile_digest", deserialize_with = "required_nullable")]
    profile: Nullable<String>,
    #[serde(
        rename = "runtime_v3_schema_digest",
        deserialize_with = "required_nullable"
    )]
    schema: Nullable<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    #[serde(deserialize_with = "required_nullable")]
    remaining_ms: Nullable<u64>,
    #[serde(deserialize_with = "required_nullable")]
    expires_at: Nullable<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Queue {
    capacity: u64,
    depth: u64,
    #[serde(deserialize_with = "required_nullable")]
    age_ms: Nullable<u64>,
}

impl GatewayHealthStatus {
    pub fn heartbeat_sequence(&self) -> u64 {
        self.progress.heartbeat_sequence
    }
    pub fn heartbeat_age_ms(&self) -> Option<u64> {
        self.progress.heartbeat_age_ms.0
    }
    pub fn meaningful_progress_age_ms(&self) -> Option<u64> {
        self.progress.meaningful_progress_age_ms.0
    }
    pub fn phase(&self) -> &str {
        &self.phase
    }
    pub fn readiness(&self) -> &str {
        &self.readiness
    }
    pub fn phase_deadline(&self) -> Option<&str> {
        self.phase_deadline.0.as_deref()
    }
    pub fn queue_depth(&self) -> u64 {
        self.queue.depth
    }
    pub fn queue_age_ms(&self) -> Option<u64> {
        self.queue.age_ms.0
    }
    pub fn pending_operation_count(&self) -> Option<u64> {
        self.pending_operation_count.0
    }
    pub fn lease_remaining_ms(&self) -> Option<u64> {
        self.lease.remaining_ms.0
    }
    pub fn instance_incarnation(&self) -> Option<&str> {
        self.identity.instance_incarnation.0.as_deref()
    }
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    fn validate(&self, expected: &GatewayHealthBinding) -> Result<(), HealthError> {
        if self.contract != "sts2-gateway-health-v1"
            || self.liveness != "live"
            || self.process_binding != "launch_nonce"
            || !matches!(self.readiness.as_str(), "ready" | "blocked" | "unknown")
            || !matches!(self.phase.as_str(), "running" | "blocked" | "draining")
            || self.progress.source != "gateway_worker"
            || self.downstream_readiness != "not_sampled"
            || self.queue.capacity == 0
            || self.queue.capacity > 1_000_000
            || self.queue.depth > self.queue.capacity
            || self.phase_deadline != self.lease.expires_at
            || (self.shutdown_requested
                && (self.phase != "draining" || self.readiness != "blocked"))
            || (self.phase == "blocked" && self.readiness != "blocked")
        {
            return Err(HealthError::Schema);
        }
        if self
            .phase_deadline
            .0
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
            || (self.lease.remaining_ms.0.is_some() && self.lease.expires_at.0.is_none())
        {
            return Err(HealthError::Schema);
        }
        if self.progress.heartbeat_sequence == 0 || self.progress.heartbeat_age_ms.0.is_none() {
            return Err(HealthError::Unavailable);
        }
        if self.identity.deployment_id.0.as_ref() != Some(&expected.deployment_id)
            || self.identity.instance_id != expected.instance_id
            || self.identity.launch_nonce.0.as_deref()
                != Some(expected.launch_nonce.to_string().as_str())
            || !self
                .identity
                .boot_id
                .0
                .as_deref()
                .is_some_and(canonical_nonce)
            || !self
                .identity
                .instance_incarnation
                .0
                .as_deref()
                .is_some_and(canonical_nonce)
            || self
                .identity
                .authority_generation
                .0
                .is_none_or(|value| value == 0)
            || self.identity.release.artifact.0.as_ref() != Some(&expected.release_digest)
            || self.identity.release.config.0.as_ref() != Some(&expected.config_digest)
            || self.identity.release.profile.0.as_ref() != Some(&expected.profile_digest)
            || self.identity.release.schema.0.as_ref() != Some(&expected.runtime_v3_schema_digest)
        {
            return Err(HealthError::Identity);
        }
        Ok(())
    }
}

pub(super) fn decode(
    body: &[u8],
    expected: &GatewayHealthBinding,
) -> Result<GatewayHealthStatus, HealthError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(HealthError::Bounds);
    }
    let status: GatewayHealthStatus =
        serde_json::from_slice(body).map_err(|_| HealthError::Schema)?;
    status.validate(expected)?;
    Ok(status)
}

fn canonical_nonce(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|nonce| valid_nonce(nonce) && nonce.to_string() == value)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let separator = match index {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 => Some(b'.'),
            23 => Some(b'Z'),
            _ => None,
        };
        if separator.map_or(!byte.is_ascii_digit(), |expected| *byte != expected) {
            return false;
        }
    }
    let number = |start: usize, end: usize| value[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= days && hour < 24 && minute < 60 && second < 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullable_members_are_required_and_duplicate_fields_are_rejected() {
        assert!(serde_json::from_str::<Queue>(r#"{"capacity":1,"depth":0}"#).is_err());
        assert!(serde_json::from_str::<Queue>(r#"{"capacity":1,"depth":0,"age_ms":null}"#).is_ok());
        assert!(
            serde_json::from_str::<Queue>(r#"{"capacity":1,"depth":0,"depth":0,"age_ms":null}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Queue>(r#"{"capacity":1,"depth":0,"age_ms":null,"extra":0}"#)
                .is_err()
        );
    }

    #[test]
    fn diagnostic_timestamps_are_canonical_and_calendar_valid() {
        assert!(valid_timestamp("2026-09-09T12:00:00.000Z"));
        assert!(valid_timestamp("2024-02-29T12:00:00.000Z"));
        for invalid in [
            "2026-02-29T12:00:00.000Z",
            "2026-09-09T24:00:00.000Z",
            "2026-09-09T12:00:00Z",
            "2026-09-09T12:00:00.000+00:00",
        ] {
            assert!(!valid_timestamp(invalid));
        }
    }
}

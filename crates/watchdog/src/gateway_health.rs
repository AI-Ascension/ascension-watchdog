//! Bounded, mutually authenticated gateway health reads.
//!
//! This client never transmits a reusable bearer or the launch key. A result
//! proves possession of the dedicated launch key, not native process ownership,
//! host readiness, or mutation authority. The runtime must additionally bind it
//! to its retained child before and after the exchange. No restart, lease, or
//! journal mutation is performed here.

use base64::Engine;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use uuid::{Uuid, Variant, Version};
use zeroize::{Zeroize, Zeroizing};

#[path = "gateway_health_codec.rs"]
mod codec;
#[path = "gateway_health_http.rs"]
mod http;
#[path = "gateway_health_status.rs"]
mod status;
pub use status::{GatewayHealthBinding, GatewayHealthStatus};

/// Fixed wire-body limit, independent of any advertised Content-Length.
pub const MAX_BODY_BYTES: usize = 128 * 1024;

/// Credential-independent errors; untrusted responses are never echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthError {
    Configuration,
    Deadline,
    Bounds,
    Transport,
    Framing,
    Authentication,
    Identity,
    Schema,
    Sequence,
    Unavailable,
}

impl std::fmt::Display for HealthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid gateway health configuration",
            Self::Deadline => "gateway health deadline elapsed",
            Self::Bounds => "gateway health bounds exceeded",
            Self::Transport => "gateway health transport failed",
            Self::Framing => "invalid gateway health HTTP framing",
            Self::Authentication => "gateway health authentication failed",
            Self::Identity => "gateway health identity mismatch",
            Self::Schema => "invalid gateway health status schema",
            Self::Sequence => "gateway health sequence did not advance",
            Self::Unavailable => "gateway health status unavailable",
        })
    }
}

impl std::error::Error for HealthError {}

/// Per-launch client state. Do not reconstruct it with a surviving launch key:
/// request-sequence state lives for exactly the same lifetime as that key.
/// Deliberately neither cloneable, serializable, nor Debug-printable.
pub struct GatewayHealthClient {
    address: SocketAddr,
    key: Zeroizing<[u8; 32]>,
    binding: GatewayHealthBinding,
    timeout: Duration,
    sequence: u64,
    last_heartbeat: Option<u64>,
}

impl GatewayHealthClient {
    /// Bind an owner-provisioned launch key to a fixed loopback endpoint and
    /// independently approved identity. This does not open the endpoint.
    pub fn new(
        address: SocketAddr,
        mut key: [u8; 32],
        binding: GatewayHealthBinding,
        timeout: Duration,
    ) -> Result<Self, HealthError> {
        let protected_key = Zeroizing::new(key);
        key.zeroize();
        if !address.ip().is_loopback()
            || address.port() == 0
            || timeout.is_zero()
            || timeout > Duration::from_secs(2)
            || protected_key.iter().all(|byte| *byte == 0)
        {
            return Err(HealthError::Configuration);
        }
        binding.validate()?;
        Ok(Self {
            address,
            key: protected_key,
            binding,
            timeout,
            sequence: 0,
            last_heartbeat: None,
        })
    }

    /// Perform exactly one exchange, without retrying. The caller's child
    /// validator must use live retained native ownership, never a PID alone.
    /// A failed request still consumes its sequence; no stale response is kept.
    pub fn probe<F>(
        &mut self,
        mut validate_owned_child: F,
    ) -> Result<GatewayHealthStatus, HealthError>
    where
        F: FnMut() -> Result<(), HealthError>,
    {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(HealthError::Deadline)?;
        validate_owned_child()?;
        self.sequence = self.sequence.checked_add(1).ok_or(HealthError::Sequence)?;
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| HealthError::Authentication)?;
        let tag = codec::request_tag(
            &self.key,
            &challenge,
            self.binding.launch_nonce.as_bytes(),
            self.sequence,
        )?;
        let challenge_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let request = format!(
            "GET /health/status/v1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\nX-STS2-Health-Challenge: {}\r\nX-STS2-Health-Sequence: {}\r\nX-STS2-Health-Request: {}\r\n\r\n",
            self.address, challenge_header, self.sequence, tag
        );
        let response = http::exchange(self.address, request.as_bytes(), deadline)?;
        codec::verify_response(
            &self.key,
            &challenge,
            response.status,
            &response.body,
            &response.tag,
        )?;
        remaining(deadline)?;
        let status = status::decode(&response.body, &self.binding)?;
        validate_owned_child()?;
        remaining(deadline)?;
        if self
            .last_heartbeat
            .is_some_and(|last| status.heartbeat_sequence() <= last)
        {
            return Err(HealthError::Sequence);
        }
        self.last_heartbeat = Some(status.heartbeat_sequence());
        Ok(status)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, HealthError> {
    let value = deadline.saturating_duration_since(Instant::now());
    if value.is_zero() {
        Err(HealthError::Deadline)
    } else {
        Ok(value)
    }
}

fn valid_nonce(nonce: Uuid) -> bool {
    nonce.get_variant() == Variant::RFC4122 && nonce.get_version() == Some(Version::Random)
}

//! Immutable, typed launch bindings for the Linux broker bootstrap payload.
//!
//! The broker transport owns authentication and admission.  This module only
//! decodes an already bounded frame, binds its non-secret identity to one
//! [`super::BrokerRequest`], and retains an immutable, zeroizing copy of the
//! bytes that the native backend will give to PID 1.  Constructing a launch
//! value does not consult durable state and does not grant process authority.

use super::{BrokerComponent, BrokerError, BrokerRequest, BrokerResult};
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::worker_bootstrap::{
    BootstrapError, ExpectedPeer, LinuxPeer, WorkerBootstrapLaunch, decode_frame,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::{Uuid, Variant, Version};
use zeroize::Zeroizing;

/// Version of the broker bootstrap binding envelope.
pub const BOOTSTRAP_BINDING_VERSION: u8 = 2;

/// Maximum complete worker bootstrap frame accepted by this binding codec.
pub const MAX_BOOTSTRAP_FRAME_BYTES: usize = crate::worker_bootstrap::MAX_FRAME_BYTES;

/// The fixed bootstrap role carried by a broker binding.
///
/// Serde names are deliberately closed and stable because this value crosses a
/// separately versioned broker boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapKind {
    GatewayHealth,
    Worker,
}

/// Non-secret identity of one broker bootstrap frame.
///
/// The frame itself is never serialized.  In particular, the Gateway health
/// key is represented only indirectly by its SHA-256 digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerBootstrapBinding {
    pub version: u8,
    pub kind: BootstrapKind,
    pub watchdog_boot_id: String,
    pub frame_sha256: String,
}

impl BrokerBootstrapBinding {
    /// Validate this binding against the complete broker launch identity.
    ///
    /// This checks syntax and the fixed role mapping only.  It does not look
    /// up a launch intent, authenticate a peer, or establish durable launch
    /// admission.
    pub fn validate(&self, request: &BrokerRequest) -> BrokerResult<()> {
        request.validate()?;
        if self.version != BOOTSTRAP_BINDING_VERSION {
            return Err(invalid("unsupported broker bootstrap binding version"));
        }
        let expected_component = match self.kind {
            BootstrapKind::GatewayHealth => BrokerComponent::Gateway,
            BootstrapKind::Worker => BrokerComponent::Harness,
        };
        if request.component != expected_component {
            return Err(invalid("broker bootstrap role does not match the request"));
        }
        validate_uuid4(&request.nonce, "broker bootstrap launch nonce")?;
        validate_uuid4(&self.watchdog_boot_id, "broker bootstrap watchdog boot id")?;
        validate_digest(&self.frame_sha256)?;
        Ok(())
    }
}

/// An immutable, zeroizing copy of one validated bootstrap frame and binding.
///
/// This value intentionally does not implement `Clone`, `Serialize`, or
/// `Deserialize`: copying it would create another secret-bearing frame, and
/// serializing it could accidentally put Gateway key material on a control
/// channel.  Its [`Debug`] implementation redacts the frame bytes.
pub struct BrokerBootstrapLaunch {
    binding: BrokerBootstrapBinding,
    frame: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for BrokerBootstrapLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerBootstrapLaunch")
            .field("binding", &self.binding)
            .field("frame", &"<redacted>")
            .finish()
    }
}

impl BrokerBootstrapLaunch {
    /// Decode and immutably bind one exact raw frame to a broker request.
    ///
    /// The input is copied only after all bounded decoding and binding checks
    /// pass.  Codec errors are intentionally collapsed to stable messages and
    /// never include frame bytes, key bytes, or parser text.
    pub fn from_frame(
        request: &BrokerRequest,
        binding: BrokerBootstrapBinding,
        frame: &[u8],
    ) -> BrokerResult<Self> {
        binding.validate(request)?;
        if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME_BYTES {
            return Err(invalid("broker bootstrap frame exceeds its size bound"));
        }

        match binding.kind {
            BootstrapKind::GatewayHealth => {
                validate_gateway_frame(request, &binding, frame)?;
            }
            BootstrapKind::Worker => {
                validate_worker_frame(request, &binding, frame)?;
            }
        }

        Ok(Self {
            binding,
            frame: Zeroizing::new(frame.to_vec()),
        })
    }

    /// Build a Gateway health launch binding from its already typed frame.
    pub fn for_gateway(
        request: &BrokerRequest,
        watchdog_boot_id: &str,
        frame: &GatewayHealthBootstrap,
    ) -> BrokerResult<Self> {
        let binding = BrokerBootstrapBinding {
            version: BOOTSTRAP_BINDING_VERSION,
            kind: BootstrapKind::GatewayHealth,
            watchdog_boot_id: watchdog_boot_id.to_owned(),
            frame_sha256: frame.frame_sha256(),
        };
        let encoded = frame.encoded_frame();
        Self::from_frame(request, binding, encoded.as_ref())
    }

    /// Build a Worker launch binding from its already typed frame.
    pub fn for_worker(
        request: &BrokerRequest,
        frame: &WorkerBootstrapLaunch,
    ) -> BrokerResult<Self> {
        // Decode the exact bytes rather than trusting a separately retained
        // typed value.  This keeps the broker binding tied to what the native
        // backend will actually receive.
        let decoded = decode_frame(frame.frame()).map_err(map_worker_error)?;
        let binding = BrokerBootstrapBinding {
            version: BOOTSTRAP_BINDING_VERSION,
            kind: BootstrapKind::Worker,
            watchdog_boot_id: decoded.watchdog_boot_id.to_string(),
            frame_sha256: frame.frame_sha256().to_owned(),
        };
        Self::from_frame(request, binding, frame.frame())
    }

    /// Return the non-secret immutable binding.
    #[must_use]
    pub fn binding(&self) -> &BrokerBootstrapBinding {
        &self.binding
    }

    /// Return the exact bytes for the native backend's sealed stdin payload.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        self.frame.as_slice()
    }

    /// Revalidate the immutable value against a request before a native effect.
    ///
    /// Rechecking is intentionally pure and does not turn this codec into an
    /// admission or persistence authority.
    pub fn validate_for_request(&self, request: &BrokerRequest) -> BrokerResult<()> {
        Self::from_frame(request, self.binding.clone(), self.frame.as_slice()).map(|_| ())
    }

    /// Return the Linux expected peer from a Worker frame, if this is a Worker.
    ///
    /// The peer remains an expected policy value.  The broker transport must
    /// compare it with its authenticated controller before admitting commands.
    pub fn worker_expected_peer(&self) -> BrokerResult<Option<LinuxPeer>> {
        if self.binding.kind != BootstrapKind::Worker {
            return Ok(None);
        }
        let decoded = decode_frame(self.frame.as_slice()).map_err(map_worker_error)?;
        match decoded.expected_peer {
            ExpectedPeer::Linux(peer) => Ok(Some(peer)),
            ExpectedPeer::Windows(_) => Err(invalid(
                "broker worker bootstrap expected peer is not Linux",
            )),
        }
    }
}

fn validate_gateway_frame(
    request: &BrokerRequest,
    binding: &BrokerBootstrapBinding,
    frame: &[u8],
) -> BrokerResult<()> {
    let decoded = GatewayHealthBootstrap::from_frame(frame)
        .map_err(|_| invalid("broker Gateway health bootstrap frame is invalid"))?;
    if decoded.launch_nonce().to_string() != request.nonce {
        return Err(invalid("broker Gateway health bootstrap nonce differs"));
    }
    validate_frame_digest(binding, frame)
}

fn validate_worker_frame(
    request: &BrokerRequest,
    binding: &BrokerBootstrapBinding,
    frame: &[u8],
) -> BrokerResult<()> {
    let decoded = decode_frame(frame).map_err(map_worker_error)?;
    if decoded.launch_nonce.to_string() != request.nonce {
        return Err(invalid("broker worker bootstrap nonce differs"));
    }
    if decoded.watchdog_boot_id.to_string() != binding.watchdog_boot_id {
        return Err(invalid("broker worker bootstrap watchdog boot differs"));
    }
    if decoded.component_id != request.instance {
        return Err(invalid("broker worker bootstrap component differs"));
    }
    if !matches!(decoded.expected_peer, ExpectedPeer::Linux(_)) {
        return Err(invalid(
            "broker worker bootstrap expected peer is not Linux",
        ));
    }
    validate_frame_digest(binding, frame)
}

fn validate_frame_digest(binding: &BrokerBootstrapBinding, frame: &[u8]) -> BrokerResult<()> {
    let digest = sha256_hex(frame);
    if digest != binding.frame_sha256 {
        return Err(invalid("broker bootstrap frame digest differs"));
    }
    Ok(())
}

fn validate_uuid4(value: &str, label: &'static str) -> BrokerResult<Uuid> {
    let uuid = Uuid::parse_str(value).map_err(|_| invalid(label))?;
    if uuid.is_nil()
        || uuid.get_variant() != Variant::RFC4122
        || uuid.get_version() != Some(Version::Random)
        || uuid.to_string() != value
    {
        return Err(invalid(label));
    }
    Ok(uuid)
}

fn validate_digest(value: &str) -> BrokerResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid("broker bootstrap frame digest is invalid"));
    }
    Ok(())
}

fn sha256_hex(frame: &[u8]) -> String {
    let digest = Sha256::digest(frame);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        // Writing to a String cannot fail.
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn map_worker_error(_: BootstrapError) -> BrokerError {
    invalid("broker worker bootstrap frame is invalid")
}

fn invalid(message: &'static str) -> BrokerError {
    BrokerError::Invalid(message.to_owned())
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod bootstrap_tests;

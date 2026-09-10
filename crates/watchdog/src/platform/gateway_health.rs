//! Fixed, one-shot Gateway health bootstrap material.
//!
//! This is deliberately a separate protocol from the dynamic worker bootstrap
//! and from the Linux helper request/GO control stream.  The frame contains no
//! role field or length field: the fixed `STS2GH01` domain is only meaningful
//! when the launch being authorized is the exact Gateway launch whose nonce is
//! carried by the frame.

use super::contract::{AdapterError, ComponentKind, LaunchSpec};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::{Uuid, Variant, Version};
use zeroize::Zeroizing;

/// Eight-byte Gateway health bootstrap protocol marker.
pub const MAGIC: &[u8; 8] = b"STS2GH01";
/// Number of bytes in the fixed health bootstrap frame.
pub const FRAME_BYTES: usize = MAGIC.len() + NONCE_BYTES + KEY_BYTES;
/// Number of bytes in the UUID launch nonce portion of the frame.
pub const NONCE_BYTES: usize = 16;
/// Number of bytes in the one-shot health attestation key.
pub const KEY_BYTES: usize = 32;

/// Errors from the fixed Gateway health bootstrap codec and launch binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHealthBootstrapError {
    /// The supplied nonce is not a canonical, non-nil UUIDv4.
    InvalidNonce,
    /// The supplied key is all zero and cannot authenticate a channel.
    InvalidKey,
    /// The supplied frame is not exactly one fixed-size frame.
    InvalidLength,
    /// The frame marker is not the Gateway health marker.
    InvalidMagic,
    /// The frame has a nil or non-v4 UUID nonce.
    InvalidFrameNonce,
    /// The health bootstrap was used for a non-Gateway launch.
    WrongRole,
    /// The frame nonce does not match the launch nonce.
    NonceMismatch,
}

impl fmt::Display for GatewayHealthBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidNonce => "Gateway health bootstrap nonce is not a UUIDv4",
            Self::InvalidKey => "Gateway health bootstrap key is invalid",
            Self::InvalidLength => "Gateway health bootstrap frame has an invalid length",
            Self::InvalidMagic => "Gateway health bootstrap frame has invalid magic",
            Self::InvalidFrameNonce => "Gateway health bootstrap frame nonce is invalid",
            Self::WrongRole => "Gateway health bootstrap requires the Gateway role",
            Self::NonceMismatch => "Gateway health bootstrap nonce differs from the launch",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for GatewayHealthBootstrapError {}

/// A fixed Gateway health frame whose key bytes are zeroized on drop.
///
/// This type intentionally does not implement `Debug`, `Serialize`, or
/// `Deserialize`.  The key is only available through the bounded frame copy
/// returned by [`Self::encoded_frame`], which is itself zeroized on drop.
#[derive(Eq)]
pub struct GatewayHealthBootstrap {
    launch_nonce: Uuid,
    key: Zeroizing<[u8; KEY_BYTES]>,
}

impl PartialEq for GatewayHealthBootstrap {
    fn eq(&self, other: &Self) -> bool {
        self.launch_nonce == other.launch_nonce && self.key.as_ref() == other.key.as_ref()
    }
}

impl GatewayHealthBootstrap {
    /// Construct one validated Gateway health bootstrap from a UUIDv4 nonce.
    pub fn new(
        launch_nonce: Uuid,
        key: [u8; KEY_BYTES],
    ) -> Result<Self, GatewayHealthBootstrapError> {
        // Move the caller-provided key into zeroizing storage before any
        // validation branch can return.  This type is intentionally not
        // Clone: duplicating key material creates additional secret copies.
        let key = Zeroizing::new(key);
        Self::from_zeroizing_key(launch_nonce, key)
    }

    /// Construct health material bound to an exact Gateway [`LaunchSpec`].
    ///
    /// The launch specification is validated before any frame is made.  A
    /// Harness, Synthetic, or HostBroker request cannot opt into this protocol
    /// by supplying a familiar nonce or executable.
    pub fn for_launch(
        specification: &LaunchSpec,
        key: [u8; KEY_BYTES],
    ) -> Result<Self, AdapterError> {
        let key = Zeroizing::new(key);
        if specification.component != ComponentKind::Gateway {
            return Err(AdapterError::Unsupported(
                "Gateway health bootstrap requires the Gateway role".to_owned(),
            ));
        }
        let launch_nonce = parse_canonical_nonce(&specification.launch_nonce)?;
        // Identity errors are checked before platform-specific launch syntax,
        // but no bootstrap is issued until the complete specification passes
        // validation below. This keeps fail-closed diagnostics stable across
        // Windows and Unix path semantics without weakening launch checks.
        specification.validate()?;
        let bootstrap = Self::from_zeroizing_key(launch_nonce, key).map_err(|error| {
            AdapterError::Invalid(format!("Gateway health bootstrap is invalid: {error}"))
        })?;
        bootstrap.validate_for_launch(specification)?;
        Ok(bootstrap)
    }

    /// Decode exactly one fixed frame and zeroize its key on drop.
    pub fn from_frame(frame: &[u8]) -> Result<Self, GatewayHealthBootstrapError> {
        if frame.len() != FRAME_BYTES {
            return Err(GatewayHealthBootstrapError::InvalidLength);
        }
        if frame[..MAGIC.len()] != *MAGIC {
            return Err(GatewayHealthBootstrapError::InvalidMagic);
        }
        let nonce_start = MAGIC.len();
        let nonce_end = nonce_start + NONCE_BYTES;
        let nonce_bytes: [u8; NONCE_BYTES] = frame[nonce_start..nonce_end]
            .try_into()
            .map_err(|_| GatewayHealthBootstrapError::InvalidFrameNonce)?;
        let launch_nonce = Uuid::from_bytes(nonce_bytes);
        validate_nonce(launch_nonce).map_err(|_| GatewayHealthBootstrapError::InvalidFrameNonce)?;
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        key.copy_from_slice(&frame[nonce_end..]);
        Self::from_zeroizing_key(launch_nonce, key)
    }

    fn from_zeroizing_key(
        launch_nonce: Uuid,
        key: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Result<Self, GatewayHealthBootstrapError> {
        validate_nonce(launch_nonce).map_err(|_| GatewayHealthBootstrapError::InvalidNonce)?;
        validate_key(key.as_ref())?;
        Ok(Self { launch_nonce, key })
    }

    /// Return the launch nonce carried by this bootstrap.
    #[must_use]
    pub const fn launch_nonce(&self) -> Uuid {
        self.launch_nonce
    }

    /// Return the exact fixed frame in zeroizing storage.
    #[must_use]
    pub fn encoded_frame(&self) -> Zeroizing<[u8; FRAME_BYTES]> {
        let mut frame = Zeroizing::new([0_u8; FRAME_BYTES]);
        frame[..MAGIC.len()].copy_from_slice(MAGIC);
        let nonce_start = MAGIC.len();
        frame[nonce_start..nonce_start + NONCE_BYTES].copy_from_slice(self.launch_nonce.as_bytes());
        frame[nonce_start + NONCE_BYTES..].copy_from_slice(self.key.as_ref());
        frame
    }

    /// Return the lowercase SHA-256 of the exact encoded frame.
    ///
    /// A digest is safe to persist as a launch binding; the key itself is
    /// never included in diagnostics or serialized configuration.
    #[must_use]
    pub fn frame_sha256(&self) -> String {
        let frame = self.encoded_frame();
        let digest = Sha256::digest(frame.as_ref());
        let mut output = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    /// Verify the fixed Gateway role and exact canonical launch nonce.
    pub fn validate_for_launch(&self, specification: &LaunchSpec) -> Result<(), AdapterError> {
        if specification.component != ComponentKind::Gateway {
            return Err(AdapterError::Unsupported(
                GatewayHealthBootstrapError::WrongRole.to_string(),
            ));
        }
        let expected = parse_canonical_nonce(&specification.launch_nonce)?;
        if expected != self.launch_nonce {
            return Err(AdapterError::IdentityMismatch(
                GatewayHealthBootstrapError::NonceMismatch.to_string(),
            ));
        }
        // Compare the persisted identity before platform-specific launch
        // syntax so a changed nonce cannot be obscured by an unrelated path
        // error. A matching identity still passes the complete validation.
        specification.validate()?;
        Ok(())
    }
}

/// A non-secret, observed frame binding passed to an independent authorizer.
///
/// It is intentionally separate from [`GatewayHealthBootstrap`]: seeing a
/// frame on a pipe does not authorize a launch.  The root-owned authorizer must
/// compare this observed digest and nonce with its independently persisted
/// launch-intent binding before returning process authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHealthFrameBinding {
    launch_nonce: Uuid,
    frame_sha256: String,
}

impl GatewayHealthFrameBinding {
    /// Derive an observed binding from decoded frame bytes.
    pub(crate) fn from_bootstrap(bootstrap: &GatewayHealthBootstrap) -> Self {
        Self {
            launch_nonce: bootstrap.launch_nonce,
            frame_sha256: bootstrap.frame_sha256(),
        }
    }

    /// Return the observed frame nonce.
    #[must_use]
    pub const fn launch_nonce(&self) -> Uuid {
        self.launch_nonce
    }

    /// Return the observed frame digest.
    #[must_use]
    pub fn frame_sha256(&self) -> &str {
        &self.frame_sha256
    }
}

/// Independently persisted Gateway health launch binding.
///
/// This stores only the launch nonce and frame digest.  The constructor merely
/// validates values supplied by the caller; it does not perform a store lookup
/// or turn an observed transport frame into authorization.  The root-owned
/// helper authorizer must load this value from its owner-local launch-intent
/// store and compare it with the observed binding before authorizing a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHealthAuthorization {
    launch_nonce: Uuid,
    frame_sha256: String,
}

impl GatewayHealthAuthorization {
    /// Construct from values loaded from the owner-local launch-intent store.
    pub fn from_persisted(
        launch_nonce: Uuid,
        frame_sha256: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        validate_nonce(launch_nonce).map_err(|_| {
            AdapterError::Invalid("Gateway launch nonce is not a UUIDv4".to_owned())
        })?;
        let frame_sha256 = frame_sha256.into();
        if !is_lowercase_sha256(&frame_sha256) {
            return Err(AdapterError::Invalid(
                "Gateway health frame binding is not SHA-256".to_owned(),
            ));
        }
        Ok(Self {
            launch_nonce,
            frame_sha256,
        })
    }

    /// Return the persisted launch nonce.
    #[must_use]
    pub const fn launch_nonce(&self) -> Uuid {
        self.launch_nonce
    }

    /// Return the persisted frame digest.
    #[must_use]
    pub fn frame_sha256(&self) -> &str {
        &self.frame_sha256
    }

    /// Match an observed pipe frame to this independently persisted binding.
    pub fn matches(&self, observed: &GatewayHealthFrameBinding) -> Result<(), AdapterError> {
        if self.launch_nonce != observed.launch_nonce || self.frame_sha256 != observed.frame_sha256
        {
            return Err(AdapterError::IdentityMismatch(
                "Gateway health frame differs from the persisted launch binding".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_nonce(nonce: Uuid) -> Result<(), GatewayHealthBootstrapError> {
    if nonce.is_nil()
        || nonce.get_version() != Some(Version::Random)
        || nonce.get_variant() != Variant::RFC4122
    {
        return Err(GatewayHealthBootstrapError::InvalidNonce);
    }
    Ok(())
}

fn validate_key(key: &[u8]) -> Result<(), GatewayHealthBootstrapError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(GatewayHealthBootstrapError::InvalidKey);
    }
    Ok(())
}

fn parse_canonical_nonce(value: &str) -> Result<Uuid, AdapterError> {
    let nonce = Uuid::parse_str(value)
        .map_err(|_| AdapterError::Invalid("Gateway launch nonce is not a UUIDv4".to_owned()))?;
    validate_nonce(nonce)
        .map_err(|_| AdapterError::Invalid("Gateway launch nonce is not a UUIDv4".to_owned()))?;
    if nonce.to_string() != value {
        return Err(AdapterError::Invalid(
            "Gateway launch nonce is not canonical UUIDv4 text".to_owned(),
        ));
    }
    Ok(nonce)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::contract::SessionSelector;
    use std::path::PathBuf;
    use std::time::Duration;

    fn nonce() -> Uuid {
        Uuid::new_v4()
    }

    fn specification(component: ComponentKind, nonce: Uuid) -> LaunchSpec {
        LaunchSpec {
            deployment_id: "deployment".to_owned(),
            instance_id: "gateway".to_owned(),
            component,
            incarnation: "incarnation".to_owned(),
            launch_nonce: nonce.to_string(),
            executable: PathBuf::from("/bin/true"),
            executable_sha256: "a".repeat(64),
            arguments: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            session: SessionSelector::Explicit(0),
            graceful_timeout: Duration::from_secs(1),
            force_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn fixed_frame_round_trips_without_debug_or_serialization() {
        let bootstrap =
            GatewayHealthBootstrap::new(nonce(), [7_u8; KEY_BYTES]).expect("valid bootstrap");
        let frame = bootstrap.encoded_frame();
        assert_eq!(frame.len(), FRAME_BYTES);
        let decoded = GatewayHealthBootstrap::from_frame(frame.as_ref()).expect("valid frame");
        assert!(decoded == bootstrap);
        assert_eq!(&frame[..MAGIC.len()], MAGIC);
    }

    #[test]
    fn malformed_magic_length_nonce_and_zero_key_fail_closed() {
        let bootstrap =
            GatewayHealthBootstrap::new(nonce(), [7_u8; KEY_BYTES]).expect("valid bootstrap");
        let frame = bootstrap.encoded_frame();
        assert!(matches!(
            GatewayHealthBootstrap::from_frame(&frame[..FRAME_BYTES - 1]),
            Err(GatewayHealthBootstrapError::InvalidLength)
        ));
        let mut wrong_magic = *frame;
        wrong_magic[0] ^= 1;
        assert!(matches!(
            GatewayHealthBootstrap::from_frame(&wrong_magic),
            Err(GatewayHealthBootstrapError::InvalidMagic)
        ));
        let mut nil_nonce = *frame;
        nil_nonce[MAGIC.len()..MAGIC.len() + NONCE_BYTES].fill(0);
        assert!(matches!(
            GatewayHealthBootstrap::from_frame(&nil_nonce),
            Err(GatewayHealthBootstrapError::InvalidFrameNonce)
        ));
        assert!(matches!(
            GatewayHealthBootstrap::new(nonce(), [0_u8; KEY_BYTES]),
            Err(GatewayHealthBootstrapError::InvalidKey)
        ));
    }

    #[test]
    fn wrong_role_and_nonce_are_rejected() {
        let nonce = nonce();
        let bootstrap =
            GatewayHealthBootstrap::new(nonce, [1_u8; KEY_BYTES]).expect("valid bootstrap");
        let mut harness = specification(ComponentKind::Harness, nonce);
        assert!(matches!(
            bootstrap.validate_for_launch(&harness),
            Err(AdapterError::Unsupported(_))
        ));
        harness.component = ComponentKind::Gateway;
        harness.launch_nonce = Uuid::new_v4().to_string();
        assert!(matches!(
            bootstrap.validate_for_launch(&harness),
            Err(AdapterError::IdentityMismatch(_))
        ));
        assert!(matches!(
            GatewayHealthBootstrap::for_launch(
                &specification(ComponentKind::Harness, nonce),
                [1_u8; KEY_BYTES]
            ),
            Err(AdapterError::Unsupported(_))
        ));
    }

    #[test]
    fn launch_nonce_must_be_canonical_lowercase_uuid_text() {
        let nonce = nonce();
        let mut uppercase = specification(ComponentKind::Gateway, nonce);
        uppercase.launch_nonce = uppercase.launch_nonce.to_uppercase();
        assert!(matches!(
            GatewayHealthBootstrap::for_launch(&uppercase, [1_u8; KEY_BYTES]),
            Err(AdapterError::Invalid(message))
                if message.contains("canonical UUIDv4")
        ));

        let mut noncanonical = specification(ComponentKind::Gateway, nonce);
        noncanonical.launch_nonce = format!("{}\n", noncanonical.launch_nonce);
        assert!(matches!(
            GatewayHealthBootstrap::for_launch(&noncanonical, [1_u8; KEY_BYTES]),
            Err(AdapterError::Invalid(_))
        ));
    }

    #[test]
    fn persisted_binding_does_not_accept_an_observed_different_frame() {
        let nonce = nonce();
        let first = GatewayHealthBootstrap::new(nonce, [1_u8; KEY_BYTES]).expect("valid");
        let second = GatewayHealthBootstrap::new(nonce, [2_u8; KEY_BYTES]).expect("valid");
        let persisted = GatewayHealthAuthorization::from_persisted(nonce, first.frame_sha256())
            .expect("valid persisted binding");
        let observed = GatewayHealthFrameBinding::from_bootstrap(&second);
        assert!(matches!(
            persisted.matches(&observed),
            Err(AdapterError::IdentityMismatch(_))
        ));
    }
}

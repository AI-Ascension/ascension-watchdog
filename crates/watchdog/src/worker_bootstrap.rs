//! The bounded, unauthenticated worker-startup bootstrap frame.
//!
//! This module owns only the wire codec and policy validation for the dynamic
//! startup frame described by `docs/worker-bootstrap-v1.md`. It does not open
//! a pipe, authenticate a peer, launch a process, or authorize a worker. A
//! decoded [`WorkerBootstrap`] is an expected identity and must still be
//! checked against a held operating-system process identity by the transport
//! owner before any command is admitted.

use serde_json::{Map, Number, Value};
use std::fmt;
use uuid::Uuid;

mod json;
pub mod launch;
mod validation;

pub use launch::WorkerBootstrapLaunch;

use self::json::parse_strict_json;
use self::validation::{
    parse_creation_token, parse_expected_peer, parse_uuid, require_exact_fields, string_field,
    unsigned_number, validate_component_id, validate_linux_peer, validate_uuid,
    validate_windows_peer,
};

/// The fixed eight-byte frame preamble.
pub const MAGIC: &[u8; 8] = b"ASC-WB01";
/// Bootstrap protocol version.
pub const VERSION: u64 = 1;
/// Maximum UTF-8 JSON payload length, excluding the twelve-byte frame prefix.
pub const MAX_PAYLOAD_BYTES: usize = 16_384;
/// Number of bytes occupied by [`MAGIC`] and the big-endian length field.
pub const FRAME_PREFIX_BYTES: usize = MAGIC.len() + std::mem::size_of::<u32>();
/// Maximum complete encoded frame size.
pub const MAX_FRAME_BYTES: usize = FRAME_PREFIX_BYTES + MAX_PAYLOAD_BYTES;
/// Maximum component identifier length in ASCII bytes.
pub const MAX_COMPONENT_ID_BYTES: usize = 128;
/// Maximum peer executable path length in UTF-8 bytes.
pub const MAX_EXECUTABLE_PATH_BYTES: usize = 4_096;
/// Maximum numeric SID length in ASCII bytes.
pub const MAX_SID_BYTES: usize = 184;
/// Maximum number of Windows SID subauthorities.
pub const MAX_SID_SUBAUTHORITIES: usize = 15;
/// Maximum Windows SID identifier authority (`2^48 - 1`).
pub const MAX_SID_AUTHORITY: u64 = (1_u64 << 48) - 1;

/// Errors produced by bounded bootstrap framing and policy validation.
///
/// Error values deliberately contain no untrusted JSON, path, SID, or field
/// text. This keeps diagnostics bounded and avoids reflecting attacker-
/// supplied payloads into logs or control responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// The complete frame or JSON payload exceeds its fixed bound.
    FrameTooLarge,
    /// The frame does not begin with [`MAGIC`].
    InvalidMagic,
    /// The input ends before the declared frame or JSON payload is complete.
    Truncated,
    /// The declared payload length is zero or above [`MAX_PAYLOAD_BYTES`].
    InvalidLength,
    /// Bytes remain after the one declared frame.
    TrailingBytes,
    /// The payload is not one strict JSON value.
    InvalidJson,
    /// The payload has the wrong closed object shape or value type.
    InvalidSchema,
    /// A UUID is not a canonical lowercase UUIDv4.
    InvalidUuid,
    /// The component identifier violates its ASCII identity bound.
    InvalidComponent,
    /// A platform peer object is malformed or has the wrong platform.
    InvalidPeer,
    /// A peer executable path is not an allowed bounded absolute path.
    InvalidPath,
    /// An executable digest is not 64 lowercase hexadecimal characters.
    InvalidDigest,
    /// A decimal creation token is not canonical, positive, or u64-bounded.
    InvalidToken,
    /// A JSON numeric value is not an unsigned bounded integer.
    InvalidNumber,
    /// Encoding the already validated value failed unexpectedly.
    Serialization,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::FrameTooLarge => "worker bootstrap frame exceeds its size bound",
            Self::InvalidMagic => "worker bootstrap frame has an invalid magic",
            Self::Truncated => "worker bootstrap frame is truncated",
            Self::InvalidLength => "worker bootstrap frame has an invalid payload length",
            Self::TrailingBytes => "worker bootstrap frame has trailing bytes",
            Self::InvalidJson => "worker bootstrap payload is invalid JSON",
            Self::InvalidSchema => "worker bootstrap payload has an invalid closed schema",
            Self::InvalidUuid => "worker bootstrap payload has an invalid UUID",
            Self::InvalidComponent => "worker bootstrap component identifier is invalid",
            Self::InvalidPeer => "worker bootstrap expected peer is invalid",
            Self::InvalidPath => "worker bootstrap executable path is invalid",
            Self::InvalidDigest => "worker bootstrap executable digest is invalid",
            Self::InvalidToken => "worker bootstrap creation token is invalid",
            Self::InvalidNumber => "worker bootstrap numeric value is invalid",
            Self::Serialization => "worker bootstrap payload could not be encoded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BootstrapError {}

/// A typed v1 worker startup frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerBootstrap {
    /// The protocol version. Encoded values must contain [`VERSION`].
    pub version: u64,
    /// Fresh identity for this worker process launch.
    pub launch_nonce: Uuid,
    /// Identity generated once by the owning Supervisor.
    pub watchdog_boot_id: Uuid,
    /// Approved component identity, not a filesystem path or provider value.
    pub component_id: String,
    /// Expected peer policy to be checked by the native transport owner.
    pub expected_peer: ExpectedPeer,
}

/// Platform-specific expected process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedPeer {
    /// Linux identity and per-frame credentials.
    Linux(LinuxPeer),
    /// Windows identity and numeric account SID.
    Windows(WindowsPeer),
}

/// Expected Linux watchdog/controller process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxPeer {
    /// Positive process identifier.
    pub pid: u32,
    /// Canonical decimal `/proc/<pid>/stat` start-time ticks.
    pub creation_token: String,
    /// Absolute UTF-8 executable path.
    pub executable: String,
    /// Exact lowercase SHA-256 of the executable image.
    pub executable_sha256: String,
    /// Expected peer effective UID.
    pub uid: u32,
    /// Expected peer effective GID.
    pub gid: u32,
}

/// Expected Windows watchdog/controller process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPeer {
    /// Positive process identifier.
    pub pid: u32,
    /// Canonical decimal Windows creation time.
    pub creation_token: String,
    /// Absolute drive-rooted UTF-8 executable path.
    pub executable: String,
    /// Exact lowercase SHA-256 of the executable image.
    pub executable_sha256: String,
    /// Expected process session identifier.
    pub session_id: u32,
    /// Canonical numeric Windows SID.
    pub sid: String,
}

impl WorkerBootstrap {
    /// Construct and validate a v1 worker bootstrap frame.
    pub fn new(
        launch_nonce: Uuid,
        watchdog_boot_id: Uuid,
        component_id: impl Into<String>,
        expected_peer: ExpectedPeer,
    ) -> Result<Self, BootstrapError> {
        let frame = Self {
            version: VERSION,
            launch_nonce,
            watchdog_boot_id,
            component_id: component_id.into(),
            expected_peer,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Construct and validate a Linux v1 worker bootstrap frame.
    pub fn linux(
        launch_nonce: Uuid,
        watchdog_boot_id: Uuid,
        component_id: impl Into<String>,
        peer: LinuxPeer,
    ) -> Result<Self, BootstrapError> {
        Self::new(
            launch_nonce,
            watchdog_boot_id,
            component_id,
            ExpectedPeer::Linux(peer),
        )
    }

    /// Construct and validate a Windows v1 worker bootstrap frame.
    pub fn windows(
        launch_nonce: Uuid,
        watchdog_boot_id: Uuid,
        component_id: impl Into<String>,
        peer: WindowsPeer,
    ) -> Result<Self, BootstrapError> {
        Self::new(
            launch_nonce,
            watchdog_boot_id,
            component_id,
            ExpectedPeer::Windows(peer),
        )
    }

    /// Validate all version, identity, and platform policy fields.
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if self.version != VERSION {
            return Err(BootstrapError::InvalidSchema);
        }
        validate_uuid(self.launch_nonce)?;
        validate_uuid(self.watchdog_boot_id)?;
        validate_component_id(&self.component_id)?;
        match &self.expected_peer {
            ExpectedPeer::Linux(peer) => validate_linux_peer(peer),
            ExpectedPeer::Windows(peer) => validate_windows_peer(peer),
        }
    }
}

impl LinuxPeer {
    /// Construct and validate a Linux expected peer.
    pub fn new(
        pid: u32,
        creation_token: impl Into<String>,
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
        uid: u32,
        gid: u32,
    ) -> Result<Self, BootstrapError> {
        let peer = Self {
            pid,
            creation_token: creation_token.into(),
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            uid,
            gid,
        };
        validate_linux_peer(&peer)?;
        Ok(peer)
    }

    /// Return the already validated creation token as a numeric value.
    pub fn creation_token_u64(&self) -> Result<u64, BootstrapError> {
        parse_creation_token(&self.creation_token)
    }
}

impl WindowsPeer {
    /// Construct and validate a Windows expected peer.
    pub fn new(
        pid: u32,
        creation_token: impl Into<String>,
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
        session_id: u32,
        sid: impl Into<String>,
    ) -> Result<Self, BootstrapError> {
        let peer = Self {
            pid,
            creation_token: creation_token.into(),
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            session_id,
            sid: sid.into(),
        };
        validate_windows_peer(&peer)?;
        Ok(peer)
    }

    /// Return the already validated creation token as a numeric value.
    pub fn creation_token_u64(&self) -> Result<u64, BootstrapError> {
        parse_creation_token(&self.creation_token)
    }
}

impl ExpectedPeer {
    /// Construct a Linux expected peer variant.
    #[must_use]
    pub const fn linux(peer: LinuxPeer) -> Self {
        Self::Linux(peer)
    }

    /// Construct a Windows expected peer variant.
    #[must_use]
    pub const fn windows(peer: WindowsPeer) -> Self {
        Self::Windows(peer)
    }
}

/// Encode one complete `ASC-WB01` frame.
pub fn encode_frame(frame: &WorkerBootstrap) -> Result<Vec<u8>, BootstrapError> {
    frame.validate()?;
    let payload =
        serde_json::to_vec(&to_value(frame)).map_err(|_| BootstrapError::Serialization)?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(BootstrapError::FrameTooLarge);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| BootstrapError::InvalidLength)?;
    let mut frame_bytes = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
    frame_bytes.extend_from_slice(MAGIC);
    frame_bytes.extend_from_slice(&payload_len.to_be_bytes());
    frame_bytes.extend_from_slice(&payload);
    Ok(frame_bytes)
}

/// Decode exactly one complete `ASC-WB01` frame.
pub fn decode_frame(bytes: &[u8]) -> Result<WorkerBootstrap, BootstrapError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(BootstrapError::FrameTooLarge);
    }
    if bytes.len() < FRAME_PREFIX_BYTES {
        return Err(BootstrapError::Truncated);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(BootstrapError::InvalidMagic);
    }
    let length_offset = MAGIC.len();
    let payload_len = u32::from_be_bytes([
        bytes[length_offset],
        bytes[length_offset + 1],
        bytes[length_offset + 2],
        bytes[length_offset + 3],
    ]) as usize;
    if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
        return Err(BootstrapError::InvalidLength);
    }
    let expected_len = FRAME_PREFIX_BYTES + payload_len;
    match bytes.len().cmp(&expected_len) {
        std::cmp::Ordering::Less => return Err(BootstrapError::Truncated),
        std::cmp::Ordering::Greater => return Err(BootstrapError::TrailingBytes),
        std::cmp::Ordering::Equal => {}
    }
    decode_payload(&bytes[FRAME_PREFIX_BYTES..])
}

fn decode_payload(payload: &[u8]) -> Result<WorkerBootstrap, BootstrapError> {
    let value = parse_strict_json(payload)?;
    let object = value.as_object().ok_or(BootstrapError::InvalidSchema)?;
    require_exact_fields(object, TOP_LEVEL_FIELDS, TOP_LEVEL_FIELDS.len())?;

    let version = unsigned_number(object.get("version"))?;
    if version != VERSION {
        return Err(BootstrapError::InvalidSchema);
    }
    let launch_nonce = parse_uuid(string_field(object, "launch_nonce")?)?;
    let watchdog_boot_id = parse_uuid(string_field(object, "watchdog_boot_id")?)?;
    let component_id = string_field(object, "component_id")?.to_owned();
    validate_component_id(&component_id)?;
    let expected_peer = parse_expected_peer(object.get("expected_peer"))?;

    let frame = WorkerBootstrap {
        version,
        launch_nonce,
        watchdog_boot_id,
        component_id,
        expected_peer,
    };
    frame.validate()?;
    Ok(frame)
}

const TOP_LEVEL_FIELDS: &[&str] = &[
    "version",
    "launch_nonce",
    "watchdog_boot_id",
    "component_id",
    "expected_peer",
];

fn to_value(frame: &WorkerBootstrap) -> Value {
    let mut object = Map::new();
    object.insert(
        "component_id".to_owned(),
        Value::String(frame.component_id.clone()),
    );
    object.insert(
        "expected_peer".to_owned(),
        peer_to_value(&frame.expected_peer),
    );
    object.insert(
        "launch_nonce".to_owned(),
        Value::String(frame.launch_nonce.to_string()),
    );
    object.insert(
        "version".to_owned(),
        Value::Number(Number::from(frame.version)),
    );
    object.insert(
        "watchdog_boot_id".to_owned(),
        Value::String(frame.watchdog_boot_id.to_string()),
    );
    Value::Object(object)
}

fn peer_to_value(peer: &ExpectedPeer) -> Value {
    let mut object = Map::new();
    match peer {
        ExpectedPeer::Linux(peer) => {
            object.insert(
                "creation_token".to_owned(),
                Value::String(peer.creation_token.clone()),
            );
            object.insert(
                "executable".to_owned(),
                Value::String(peer.executable.clone()),
            );
            object.insert(
                "executable_sha256".to_owned(),
                Value::String(peer.executable_sha256.clone()),
            );
            object.insert("gid".to_owned(), Value::Number(Number::from(peer.gid)));
            object.insert("pid".to_owned(), Value::Number(Number::from(peer.pid)));
            object.insert("platform".to_owned(), Value::String("linux".to_owned()));
            object.insert("uid".to_owned(), Value::Number(Number::from(peer.uid)));
        }
        ExpectedPeer::Windows(peer) => {
            object.insert(
                "creation_token".to_owned(),
                Value::String(peer.creation_token.clone()),
            );
            object.insert(
                "executable".to_owned(),
                Value::String(peer.executable.clone()),
            );
            object.insert(
                "executable_sha256".to_owned(),
                Value::String(peer.executable_sha256.clone()),
            );
            object.insert("pid".to_owned(), Value::Number(Number::from(peer.pid)));
            object.insert("platform".to_owned(), Value::String("windows".to_owned()));
            object.insert(
                "session_id".to_owned(),
                Value::Number(Number::from(peer.session_id)),
            );
            object.insert("sid".to_owned(), Value::String(peer.sid.clone()));
        }
    }
    Value::Object(object)
}

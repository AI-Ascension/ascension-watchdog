//! Portable, bounded values shared by the native Windows implementation.

use std::collections::BTreeMap;
use std::path::PathBuf;

const MAX_ID_BYTES: usize = 128;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 8 * 1024;
const MAX_PIPE_NAME_BYTES: usize = 192;
const MAX_COMMAND_LINE_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_UNITS: usize = 32_767;
const MAX_LIFECYCLE_NONCE_BYTES: usize = 96;

/// Fixed roles the broker is allowed to supervise.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ComponentKind {
    Gateway,
    Harness,
    HostBroker,
    Synthetic,
}

/// Explicit Windows session selection.  No automatic login or credential
/// capture is represented by this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSelector {
    /// Keep a non-graphical component in the service's current session.
    /// This is normally session 0 for an SCM service and never performs login.
    CurrentService,
    ActiveUser,
    Explicit(u32),
}

/// A fixed lifecycle request accepted by the local broker.  It cannot encode
/// an arbitrary executable, shell command, scheduler action, or lease grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleRequest {
    Start {
        component: ComponentKind,
        instance_id: String,
        incarnation: String,
    },
    Stop {
        component: ComponentKind,
        instance_id: String,
        incarnation: String,
    },
    Heartbeat {
        instance_id: String,
        incarnation: String,
        sequence: u64,
    },
}

/// Capability carried by a lifecycle frame.  The capability is deliberately
/// tied to the closed request kind; it is not an arbitrary string that a
/// caller can smuggle through the pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCapability {
    Start,
    Stop,
    Heartbeat,
}

impl LifecycleCapability {
    fn code(self) -> u8 {
        match self {
            Self::Start => 1,
            Self::Stop => 2,
            Self::Heartbeat => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, PlatformError> {
        match code {
            1 => Ok(Self::Start),
            2 => Ok(Self::Stop),
            3 => Ok(Self::Heartbeat),
            _ => Err(PlatformError::Invalid(
                "unknown lifecycle capability".to_owned(),
            )),
        }
    }
}

/// Authenticated lifecycle frame metadata.
///
/// The request payload alone is not a transport authorization.  The native
/// pipe requires this envelope after peer authentication and checks the
/// configured nonce/epoch plus a strictly increasing sequence before exposing
/// the request to a caller.  A new durable epoch or nonce is required after
/// authority replacement; a reconnect cannot reset the sequence window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleFrame {
    pub nonce: String,
    pub epoch: u64,
    pub sequence: u64,
    pub capability: LifecycleCapability,
    pub request: LifecycleRequest,
}

impl LifecycleFrame {
    const MAGIC: [u8; 4] = *b"AWLF";
    const VERSION: u8 = 1;

    /// Construct a frame with the capability derived from its request.
    pub fn new(
        nonce: impl Into<String>,
        epoch: u64,
        sequence: u64,
        request: LifecycleRequest,
    ) -> Self {
        let capability = request.capability();
        Self {
            nonce: nonce.into(),
            epoch,
            sequence,
            capability,
            request,
        }
    }

    /// Validate the replay and capability fields before transport.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_lifecycle_nonce(&self.nonce)?;
        if self.epoch == 0 || self.sequence == 0 {
            return Err(PlatformError::Invalid(
                "lifecycle epoch and sequence must be non-zero".to_owned(),
            ));
        }
        if self.capability != self.request.capability() {
            return Err(PlatformError::IdentityMismatch(
                "lifecycle capability does not match request kind".to_owned(),
            ));
        }
        self.request.validate()
    }

    /// Encode the authenticated envelope as one complete bounded payload.
    pub fn encode_payload(&self) -> Result<Vec<u8>, PlatformError> {
        self.validate()?;
        let request = self.request.encode_payload()?;
        let mut bytes = Vec::with_capacity(32 + self.nonce.len() + request.len());
        bytes.extend_from_slice(&Self::MAGIC);
        bytes.push(Self::VERSION);
        bytes.push(self.capability.code());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        put_lifecycle_nonce(&mut bytes, &self.nonce)?;
        let request_len = u16::try_from(request.len()).map_err(|_| {
            PlatformError::Invalid("lifecycle request exceeds frame bounds".to_owned())
        })?;
        bytes.extend_from_slice(&request_len.to_le_bytes());
        bytes.extend_from_slice(&request);
        if bytes.len() > MAX_ENVIRONMENT_BYTES {
            return Err(PlatformError::Invalid(
                "lifecycle frame exceeds bounds".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Decode one complete authenticated envelope.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, PlatformError> {
        let mut cursor = Cursor::new(payload);
        let magic = [
            cursor.byte()?,
            cursor.byte()?,
            cursor.byte()?,
            cursor.byte()?,
        ];
        if magic != Self::MAGIC || cursor.byte()? != Self::VERSION {
            return Err(PlatformError::Invalid(
                "lifecycle frame version is unsupported".to_owned(),
            ));
        }
        let capability = LifecycleCapability::from_code(cursor.byte()?)?;
        let epoch = cursor.u64()?;
        let sequence = cursor.u64()?;
        let nonce = cursor.lifecycle_nonce()?;
        let request_len = usize::from(u16::from_le_bytes([cursor.byte()?, cursor.byte()?]));
        let request = cursor.bytes(request_len)?;
        if !cursor.is_empty() {
            return Err(PlatformError::Invalid(
                "lifecycle frame contains trailing bytes".to_owned(),
            ));
        }
        let request = LifecycleRequest::decode_payload(request)?;
        let frame = Self {
            nonce,
            epoch,
            sequence,
            capability,
            request,
        };
        frame.validate()?;
        Ok(frame)
    }
}

impl LifecycleRequest {
    pub(crate) fn capability(&self) -> LifecycleCapability {
        match self {
            Self::Start { .. } => LifecycleCapability::Start,
            Self::Stop { .. } => LifecycleCapability::Stop,
            Self::Heartbeat { .. } => LifecycleCapability::Heartbeat,
        }
    }
    /// Validate the closed, bounded request surface.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Invalid`] when an identity is empty, contains
    /// control characters, or exceeds the fixed request bound.
    pub fn validate(&self) -> Result<(), PlatformError> {
        match self {
            Self::Heartbeat {
                instance_id,
                incarnation,
                ..
            }
            | Self::Start {
                instance_id,
                incarnation,
                ..
            }
            | Self::Stop {
                instance_id,
                incarnation,
                ..
            } => {
                validate_id("instance", instance_id)?;
                validate_id("incarnation", incarnation)?;
            }
        }
        Ok(())
    }

    /// Encode one length-delimited binary frame payload.  The caller supplies
    /// the outer length prefix and must enforce `MAX_FRAME_BYTES`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Invalid`] when a request field cannot be
    /// represented within the bounded frame.
    pub fn encode_payload(&self) -> Result<Vec<u8>, PlatformError> {
        self.validate()?;
        let mut bytes = Vec::new();
        match self {
            Self::Start {
                component,
                instance_id,
                incarnation,
            } => {
                bytes.push(1);
                bytes.push(component_code(*component));
                put_string(&mut bytes, instance_id)?;
                put_string(&mut bytes, incarnation)?;
            }
            Self::Stop {
                component,
                instance_id,
                incarnation,
            } => {
                bytes.push(2);
                bytes.push(component_code(*component));
                put_string(&mut bytes, instance_id)?;
                put_string(&mut bytes, incarnation)?;
            }
            Self::Heartbeat {
                instance_id,
                incarnation,
                sequence,
            } => {
                bytes.push(3);
                put_string(&mut bytes, instance_id)?;
                put_string(&mut bytes, incarnation)?;
                bytes.extend_from_slice(&sequence.to_le_bytes());
            }
        }
        if bytes.len() > MAX_ENVIRONMENT_BYTES {
            return Err(PlatformError::Invalid(
                "lifecycle request exceeds frame bounds".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Decode one complete payload; trailing or malformed bytes are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Invalid`] for unknown tags, malformed UTF-8,
    /// truncated fields, or trailing bytes.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, PlatformError> {
        let mut cursor = Cursor::new(payload);
        let tag = cursor.byte()?;
        let request = match tag {
            1 => Self::Start {
                component: component_from_code(cursor.byte()?)?,
                instance_id: cursor.string()?,
                incarnation: cursor.string()?,
            },
            2 => Self::Stop {
                component: component_from_code(cursor.byte()?)?,
                instance_id: cursor.string()?,
                incarnation: cursor.string()?,
            },
            3 => Self::Heartbeat {
                instance_id: cursor.string()?,
                incarnation: cursor.string()?,
                sequence: cursor.u64()?,
            },
            _ => {
                return Err(PlatformError::Invalid(
                    "unknown lifecycle request tag".to_owned(),
                ));
            }
        };
        if !cursor.is_empty() {
            return Err(PlatformError::Invalid(
                "lifecycle request contains trailing bytes".to_owned(),
            ));
        }
        request.validate()?;
        Ok(request)
    }
}

/// Exact process creation identity.  PID alone is never an authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time_100ns: u64,
    pub launch_nonce: String,
    pub executable: PathBuf,
    /// SHA-256 of the immutable executable file held by the owner.
    pub executable_sha256: String,
    pub session_id: u32,
}

impl ProcessIdentity {
    /// Validate a persisted Windows process identity before reopening its
    /// named Job Object.  This is intentionally portable so a watchdog can
    /// reject malformed storage before any Win32 handle is opened.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_id("launch nonce", &self.launch_nonce)?;
        if self.pid == 0 || self.creation_time_100ns == 0 || self.session_id == u32::MAX {
            return Err(PlatformError::Invalid(
                "Windows process identity contains an invalid creation/session token".to_owned(),
            ));
        }
        if !self.executable.is_absolute() || self.executable.as_os_str().is_empty() {
            return Err(PlatformError::Invalid(
                "Windows process identity executable must be absolute".to_owned(),
            ));
        }
        if self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PlatformError::Invalid(
                "Windows process identity executable digest is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Direct process launch request.  The native implementation never interprets
/// this as a shell command and never accepts an executable outside the role
/// allowlist in [`WindowsPlatformConfig`].
#[derive(Clone, Eq, PartialEq)]
pub struct WindowsLaunchSpec {
    pub component: ComponentKind,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: Option<PathBuf>,
    pub session: SessionSelector,
    pub launch_nonce: String,
    pub graceful_timeout_ms: u32,
    pub force_timeout_ms: u32,
}

impl std::fmt::Debug for WindowsLaunchSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsLaunchSpec")
            .field("component", &self.component)
            .field("executable", &self.executable)
            .field("argument_count", &self.arguments.len())
            .field("environment_count", &self.environment.len())
            .field("working_directory", &self.working_directory)
            .field("session", &self.session)
            .field("launch_nonce", &self.launch_nonce)
            .field("graceful_timeout_ms", &self.graceful_timeout_ms)
            .field("force_timeout_ms", &self.force_timeout_ms)
            .finish()
    }
}

impl WindowsLaunchSpec {
    /// Validate bounded strings, direct paths, and ordered stop deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Invalid`] when a path, argument, environment,
    /// session, or timeout is outside the configured bounds.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self, config: &WindowsPlatformConfig) -> Result<(), PlatformError> {
        config.validate()?;
        validate_id("launch nonce", &self.launch_nonce)?;
        if !self.executable.is_absolute() || self.executable.as_os_str().is_empty() {
            return Err(PlatformError::Invalid(
                "Windows executable must be an absolute path".to_owned(),
            ));
        }
        if self.arguments.len() > config.max_arguments
            || self.arguments.iter().any(|value| {
                value.is_empty() || value.len() > MAX_ARGUMENT_BYTES || value.contains('\0')
            })
        {
            return Err(PlatformError::Invalid(
                "Windows launch arguments exceed bounds".to_owned(),
            ));
        }
        if self.environment.len() > config.max_environment
            || self.environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.contains('=')
                    || name.contains('\0')
                    || value.contains('\0')
                    || name.len() > MAX_ID_BYTES
                    || value.len() > MAX_ENVIRONMENT_BYTES
            })
        {
            return Err(PlatformError::Invalid(
                "Windows environment exceeds bounds".to_owned(),
            ));
        }
        // CreateProcessW has a UTF-16 command-line bound.  Account for the
        // worst-case quote/backslash expansion here, before any native call;
        // the native builder repeats the exact check after Windows quoting.
        let executable_units = self
            .executable
            .to_string_lossy()
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .saturating_add(4);
        let command_units = self
            .arguments
            .iter()
            .try_fold(executable_units, |total, argument| {
                total
                    .checked_add(
                        argument
                            .encode_utf16()
                            .count()
                            .saturating_mul(2)
                            .saturating_add(4),
                    )
                    .ok_or(())
            });
        if command_units.map_or(true, |units| units > MAX_COMMAND_LINE_UNITS) {
            return Err(PlatformError::Invalid(
                "Windows command line exceeds the CreateProcessW bound".to_owned(),
            ));
        }
        let environment_units =
            self.environment
                .iter()
                .try_fold(1_usize, |total, (name, value)| {
                    total
                        .checked_add(name.encode_utf16().count())
                        .and_then(|total| total.checked_add(1))
                        .and_then(|total| total.checked_add(value.encode_utf16().count()))
                        .and_then(|total| total.checked_add(1))
                        .ok_or(())
                });
        if environment_units.map_or(true, |units| units > MAX_ENVIRONMENT_UNITS) {
            return Err(PlatformError::Invalid(
                "Windows environment block exceeds the CreateProcessW bound".to_owned(),
            ));
        }
        if self.graceful_timeout_ms == 0
            || self.force_timeout_ms == 0
            || self.force_timeout_ms < self.graceful_timeout_ms
        {
            return Err(PlatformError::Invalid(
                "Windows stop deadlines are invalid".to_owned(),
            ));
        }
        match (self.component, self.session) {
            (ComponentKind::HostBroker, SessionSelector::ActiveUser)
            | (
                ComponentKind::Gateway | ComponentKind::Harness | ComponentKind::Synthetic,
                SessionSelector::CurrentService | SessionSelector::Explicit(_),
            ) => {}
            (ComponentKind::HostBroker, _) => {
                return Err(PlatformError::Unsupported(
                    "graphical HostBroker requires an approved active user session".to_owned(),
                ));
            }
            (_, SessionSelector::ActiveUser) => {
                return Err(PlatformError::Unsupported(
                    "background Windows components cannot target the interactive user session"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Configuration consumed by the native boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPlatformConfig {
    pub service_name: String,
    pub pipe_name: String,
    pub allowlisted_executables: BTreeMap<ComponentKind, PathBuf>,
    /// SHA-256 digests approved for each role's allowlisted executable.
    ///
    /// The path allowlist and this digest map are one closed identity: every
    /// role must appear in both maps, and a launch is rejected when the bytes
    /// held by the native integrity guard do not match this value.
    pub approved_executable_sha256: BTreeMap<ComponentKind, String>,
    pub authorized_peer_executable: PathBuf,
    pub max_arguments: usize,
    pub max_environment: usize,
    pub max_processes: u32,
}

impl WindowsPlatformConfig {
    /// Validate immutable names and resource bounds before native calls.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Invalid`] when a service/pipe name, allowlist,
    /// or resource bound is outside the fixed platform contract.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_id("service", &self.service_name)?;
        if self.pipe_name.len() > MAX_PIPE_NAME_BYTES
            || !self.pipe_name.starts_with(r"\\.\pipe\ascension-watchdog-")
            || self.pipe_name.contains(['\0', '\r', '\n'])
        {
            return Err(PlatformError::Invalid(
                "pipe name is outside the fixed local namespace".to_owned(),
            ));
        }
        if self.allowlisted_executables.is_empty()
            || self
                .allowlisted_executables
                .values()
                .any(|path| !path.is_absolute())
            || !self.authorized_peer_executable.is_absolute()
            || self.approved_executable_sha256.len() != self.allowlisted_executables.len()
            || self
                .allowlisted_executables
                .keys()
                .any(|component| !self.approved_executable_sha256.contains_key(component))
            || self
                .approved_executable_sha256
                .values()
                .any(|digest| !is_sha256_digest(digest))
        {
            return Err(PlatformError::Invalid(
                "Windows executable allowlist and approved digests are incomplete".to_owned(),
            ));
        }
        if self.max_arguments == 0
            || self.max_arguments > MAX_ARGUMENTS
            || self.max_environment == 0
            || self.max_environment > MAX_ENVIRONMENT
            || self.max_processes == 0
            || self.max_processes > 128
        {
            return Err(PlatformError::Invalid(
                "Windows process resource bounds are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Errors preserve the distinction between invalid input, unavailable native
/// capability, identity mismatch, and Win32 failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Invalid(String),
    Unsupported(String),
    Unavailable(String),
    IdentityMismatch(String),
    Timeout(String),
    Win32 { operation: String, code: u32 },
    Io(String),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid Windows request: {message}"),
            Self::Unsupported(message) => write!(formatter, "Windows unsupported: {message}"),
            Self::Unavailable(message) => write!(formatter, "Windows unavailable: {message}"),
            Self::IdentityMismatch(message) => {
                write!(formatter, "Windows identity mismatch: {message}")
            }
            Self::Timeout(message) => write!(formatter, "Windows timeout: {message}"),
            Self::Win32 { operation, code } => write!(formatter, "{operation} failed with {code}"),
            Self::Io(message) => write!(formatter, "Windows I/O failure: {message}"),
        }
    }
}

impl std::error::Error for PlatformError {}

fn validate_id(label: &str, value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains(['\0', '\r', '\n'])
        || value.chars().any(char::is_control)
    {
        return Err(PlatformError::Invalid(format!(
            "{label} identity is outside bounds"
        )));
    }
    Ok(())
}

fn validate_lifecycle_nonce(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_LIFECYCLE_NONCE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(PlatformError::Invalid(
            "lifecycle nonce is outside bounds".to_owned(),
        ));
    }
    Ok(())
}

fn put_lifecycle_nonce(bytes: &mut Vec<u8>, nonce: &str) -> Result<(), PlatformError> {
    validate_lifecycle_nonce(nonce)?;
    let length = u8::try_from(nonce.len())
        .map_err(|_| PlatformError::Invalid("lifecycle nonce exceeds bounds".to_owned()))?;
    bytes.push(length);
    bytes.extend_from_slice(nonce.as_bytes());
    Ok(())
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), PlatformError> {
    validate_id("lifecycle", value)?;
    let length = u16::try_from(value.len())
        .map_err(|_| PlatformError::Invalid("lifecycle string exceeds frame bounds".to_owned()))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn component_code(component: ComponentKind) -> u8 {
    match component {
        ComponentKind::Gateway => 1,
        ComponentKind::Harness => 2,
        ComponentKind::HostBroker => 3,
        ComponentKind::Synthetic => 4,
    }
}

fn component_from_code(code: u8) -> Result<ComponentKind, PlatformError> {
    match code {
        1 => Ok(ComponentKind::Gateway),
        2 => Ok(ComponentKind::Harness),
        3 => Ok(ComponentKind::HostBroker),
        4 => Ok(ComponentKind::Synthetic),
        _ => Err(PlatformError::Invalid(
            "unknown lifecycle component".to_owned(),
        )),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, PlatformError> {
        let byte = self.bytes.get(self.offset).copied().ok_or_else(|| {
            PlatformError::Invalid("lifecycle frame ended unexpectedly".to_owned())
        })?;
        self.offset += 1;
        Ok(byte)
    }

    fn u64(&mut self) -> Result<u64, PlatformError> {
        let end = self
            .offset
            .checked_add(8)
            .ok_or_else(|| PlatformError::Invalid("lifecycle frame offset overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| PlatformError::Invalid("lifecycle sequence is truncated".to_owned()))?;
        self.offset = end;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(slice);
        Ok(u64::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, PlatformError> {
        let length = usize::from(u16::from_le_bytes([self.byte()?, self.byte()?]));
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| PlatformError::Invalid("lifecycle string offset overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| PlatformError::Invalid("lifecycle string is truncated".to_owned()))?;
        self.offset = end;
        let value = std::str::from_utf8(slice)
            .map_err(|_| PlatformError::Invalid("lifecycle string is not UTF-8".to_owned()))?;
        validate_id("lifecycle", value)?;
        Ok(value.to_owned())
    }

    fn lifecycle_nonce(&mut self) -> Result<String, PlatformError> {
        let length = usize::from(self.byte()?);
        let slice = self.bytes(length)?;
        let value = std::str::from_utf8(slice)
            .map_err(|_| PlatformError::Invalid("lifecycle nonce is not UTF-8".to_owned()))?;
        validate_lifecycle_nonce(value)?;
        Ok(value.to_owned())
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], PlatformError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| PlatformError::Invalid("lifecycle frame offset overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| PlatformError::Invalid("lifecycle frame is truncated".to_owned()))?;
        self.offset = end;
        Ok(slice)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_frame_round_trip_is_closed_and_bounded() -> Result<(), PlatformError> {
        let request = LifecycleRequest::Heartbeat {
            instance_id: "instance-1".to_owned(),
            incarnation: "incarnation-1".to_owned(),
            sequence: 7,
        };
        let encoded = request.encode_payload()?;
        assert_eq!(LifecycleRequest::decode_payload(&encoded)?, request);
        Ok(())
    }

    #[test]
    fn arbitrary_component_and_trailing_bytes_are_rejected() {
        assert!(component_from_code(99).is_err());
        assert!(LifecycleRequest::decode_payload(&[1, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn lifecycle_envelope_binds_capability_epoch_nonce_and_sequence() -> Result<(), PlatformError> {
        let request = LifecycleRequest::Stop {
            component: ComponentKind::Gateway,
            instance_id: "instance-1".to_owned(),
            incarnation: "incarnation-1".to_owned(),
        };
        let frame = LifecycleFrame::new("session-nonce", 4, 9, request.clone());
        let encoded = frame.encode_payload()?;
        assert_eq!(LifecycleFrame::decode_payload(&encoded)?, frame);

        let mut wrong_capability = frame.clone();
        wrong_capability.capability = LifecycleCapability::Start;
        assert!(wrong_capability.encode_payload().is_err());

        let mut replayable = frame;
        replayable.sequence = 0;
        assert!(replayable.encode_payload().is_err());
        Ok(())
    }

    #[test]
    fn process_identity_rejects_untrusted_persisted_values() {
        let identity = ProcessIdentity {
            pid: 1,
            creation_time_100ns: 1,
            launch_nonce: "nonce".to_owned(),
            executable: PathBuf::from("relative.exe"),
            executable_sha256: "0".repeat(64),
            session_id: 1,
        };
        assert!(identity.validate().is_err());
    }
}

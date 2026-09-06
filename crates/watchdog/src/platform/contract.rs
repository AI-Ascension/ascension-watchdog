//! Stable, bounded contract between reconciliation and an OS process adapter.
//!
//! A returned [`OwnedProcess`] is an authority-bearing observation, not merely
//! a PID.  Implementations must retain a live containment owner and must reject
//! an identity mismatch before observation or termination.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

const MAX_IDENTITY_BYTES: usize = 256;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 8 * 1024;

/// Fixed process roles known to the watchdog.  An adapter must not become an
/// arbitrary command runner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ComponentKind {
    Gateway,
    Harness,
    HostBroker,
    Synthetic,
}

/// A process-control containment object owned by one adapter instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainmentId(String);

impl ContainmentId {
    /// Construct a validated opaque containment identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, AdapterError> {
        let value = value.into();
        validate_identity("containment", &value)?;
        Ok(Self(value))
    }

    /// Return the opaque identifier for persistence and diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Platform-independent session selection for a graphical host broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSelector {
    /// Use the explicitly approved active user session, if one exists.
    ActiveUser,
    /// Use one operator-approved session number.
    Explicit(u32),
}

/// OS process creation identity.  PID is deliberately only one field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessCreation {
    /// Platform creation timestamp or equivalent immutable process-start token.
    pub token: String,
    /// PID observed at launch; never sufficient by itself for authorization.
    pub pid: u32,
}

/// Identity persisted with a supervised process record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub deployment_id: String,
    pub instance_id: String,
    pub component: ComponentKind,
    pub incarnation: String,
    pub launch_nonce: String,
    pub creation: ProcessCreation,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub containment: ContainmentId,
    pub session: Option<u32>,
}

/// Direct, bounded child launch request.  Secret values must be supplied by a
/// protected runtime source and never serialized into this type's audit text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSpec {
    pub deployment_id: String,
    pub instance_id: String,
    pub component: ComponentKind,
    pub incarnation: String,
    pub launch_nonce: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub environment: Vec<(String, String)>,
    pub session: SessionSelector,
    pub graceful_timeout: Duration,
    pub force_timeout: Duration,
}

impl LaunchSpec {
    /// Validate the closed launch surface before any filesystem or process call.
    pub fn validate(&self) -> Result<(), AdapterError> {
        validate_identity("deployment", &self.deployment_id)?;
        validate_identity("instance", &self.instance_id)?;
        validate_identity("incarnation", &self.incarnation)?;
        validate_identity("launch nonce", &self.launch_nonce)?;
        validate_identity("executable digest", &self.executable_sha256)?;
        if !self.executable.is_absolute() || self.executable.as_os_str().is_empty() {
            return Err(AdapterError::Invalid(
                "executable must be absolute".to_owned(),
            ));
        }
        if self.arguments.len() > MAX_ARGUMENTS
            || self
                .arguments
                .iter()
                .any(|argument| argument.len() > MAX_ARGUMENT_BYTES || argument.contains('\0'))
        {
            return Err(AdapterError::Invalid("arguments exceed bounds".to_owned()));
        }
        if self.environment.len() > MAX_ENVIRONMENT
            || self.environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > MAX_ENVIRONMENT_NAME_BYTES
                    || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
                    || name.contains('\0')
                    || value.contains('\0')
            })
        {
            return Err(AdapterError::Invalid(
                "environment exceeds bounds".to_owned(),
            ));
        }
        if self.graceful_timeout.is_zero()
            || self.force_timeout.is_zero()
            || self.force_timeout < self.graceful_timeout
        {
            return Err(AdapterError::Invalid(
                "stop deadlines must be non-zero and ordered".to_owned(),
            ));
        }
        if let SessionSelector::Explicit(session) = self.session
            && session == 0
        {
            return Err(AdapterError::Invalid(
                "session number is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A process transferred to the adapter only after containment and identity
/// capture have succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedProcess {
    pub identity: ProcessIdentity,
}

/// Bounded result of inspecting an owned process.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    Running(ProcessIdentity),
    Exited { code: Option<i32> },
    Missing,
    IdentityMismatch,
    Ambiguous,
}

/// Bounded result of a stop request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    Exited,
    AlreadyExited,
    TimedOut,
}

/// Errors are explicit so an unavailable native platform cannot be reported as
/// a healthy no-op.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    Invalid(String),
    Unsupported(String),
    Unavailable(String),
    IdentityMismatch(String),
    Timeout(String),
    Io(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid platform request: {message}"),
            Self::Unsupported(message) => write!(formatter, "platform unsupported: {message}"),
            Self::Unavailable(message) => write!(formatter, "platform unavailable: {message}"),
            Self::IdentityMismatch(message) => {
                write!(formatter, "platform identity mismatch: {message}")
            }
            Self::Timeout(message) => write!(formatter, "platform timeout: {message}"),
            Self::Io(message) => write!(formatter, "platform I/O failure: {message}"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Adapter boundary owned by the watchdog.  `inventory` must consult the
/// designated containment authority and never discover children by name.
pub trait ProcessAdapter {
    /// Reconcile durable identities with live containment ownership.
    fn inventory(&mut self, expected: &[OwnedProcess]) -> Result<Vec<Observation>, AdapterError>;

    /// Launch directly and transfer ownership only after all proofs succeed.
    fn launch(&mut self, specification: &LaunchSpec) -> Result<OwnedProcess, AdapterError>;

    /// Inspect one exact owned process.
    fn inspect(&mut self, process: &OwnedProcess) -> Result<Observation, AdapterError>;

    /// Request graceful shutdown, bounded by `graceful_timeout`.
    fn graceful_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError>;

    /// Force-stop only the verified containment owner and its descendants.
    fn force_stop(&mut self, process: &OwnedProcess) -> Result<StopOutcome, AdapterError>;
}

fn validate_identity(label: &str, value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(AdapterError::Invalid(format!(
            "{label} identity is outside bounds"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specification() -> LaunchSpec {
        LaunchSpec {
            deployment_id: "deployment-1".to_owned(),
            instance_id: "instance-1".to_owned(),
            component: ComponentKind::Synthetic,
            incarnation: "incarnation-1".to_owned(),
            launch_nonce: "nonce-1".to_owned(),
            executable: PathBuf::from("/bin/true"),
            executable_sha256: "a".repeat(64),
            arguments: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            session: SessionSelector::ActiveUser,
            graceful_timeout: Duration::from_secs(1),
            force_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn launch_spec_rejects_unordered_deadlines_and_nul_arguments() {
        let mut invalid = specification();
        invalid.force_timeout = Duration::from_millis(500);
        assert!(invalid.validate().is_err());
        invalid = specification();
        invalid.arguments.push("bad\0argument".to_owned());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn launch_spec_accepts_bounded_direct_request() {
        assert!(specification().validate().is_ok());
    }
}

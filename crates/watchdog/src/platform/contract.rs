//! Stable, bounded contract between reconciliation and an OS process adapter.
//!
//! A returned [`OwnedProcess`] is an authority-bearing observation, not merely
//! a PID.  Implementations must retain a live containment owner and must reject
//! an identity mismatch before observation or termination.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

const MAX_IDENTITY_BYTES: usize = 256;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 8 * 1024;
const MAX_LAUNCH_BYTES: usize = 32 * 1024;

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
    /// Use one operator-approved session number.  Session zero is the
    /// service session and is valid only for non-graphical roles.
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
#[derive(Clone, Eq, PartialEq)]
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
        validate_sha256("executable digest", &self.executable_sha256)?;
        if !self.executable.is_absolute() || self.executable.as_os_str().is_empty() {
            return Err(AdapterError::Invalid(
                "executable must be absolute".to_owned(),
            ));
        }
        if let Some(working_directory) = &self.working_directory
            && (!working_directory.is_absolute() || working_directory.as_os_str().is_empty())
        {
            return Err(AdapterError::Invalid(
                "working directory must be absolute".to_owned(),
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
        if self.environment.len() > MAX_ENVIRONMENT {
            return Err(AdapterError::Invalid(
                "environment exceeds bounds".to_owned(),
            ));
        }
        let mut environment_names = BTreeSet::new();
        for (name, value) in &self.environment {
            if name.is_empty()
                || name.len() > MAX_ENVIRONMENT_NAME_BYTES
                || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
                || name.contains(['=', '\0'])
                || name.chars().any(char::is_control)
                || value.contains('\0')
                || value.chars().any(char::is_control)
                || !environment_names.insert(name)
            {
                return Err(AdapterError::Invalid(
                    "environment contains an invalid or duplicate name/value".to_owned(),
                ));
            }
        }
        let launch_bytes = self
            .arguments
            .iter()
            .map(String::len)
            .try_fold(0_usize, usize::checked_add)
            .and_then(|total| {
                self.environment
                    .iter()
                    .try_fold(total, |total, (name, value)| {
                        total
                            .checked_add(name.len())
                            .and_then(|total| total.checked_add(value.len()))
                    })
            });
        if launch_bytes.is_none_or(|bytes| bytes > MAX_LAUNCH_BYTES) {
            return Err(AdapterError::Invalid(
                "launch arguments and environment exceed aggregate bounds".to_owned(),
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
        match (self.component, self.session) {
            (ComponentKind::HostBroker, SessionSelector::ActiveUser) => {}
            (ComponentKind::HostBroker, SessionSelector::Explicit(session)) if session != 0 => {}
            (ComponentKind::HostBroker, _) => {
                return Err(AdapterError::Unsupported(
                    "graphical HostBroker requires an approved nonzero user session".to_owned(),
                ));
            }
            (
                ComponentKind::Gateway | ComponentKind::Harness | ComponentKind::Synthetic,
                SessionSelector::Explicit(_),
            ) => {}
            (_, SessionSelector::ActiveUser) => {
                return Err(AdapterError::Unsupported(
                    "background components cannot target the interactive user session".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for LaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchSpec")
            .field("deployment_id", &self.deployment_id)
            .field("instance_id", &self.instance_id)
            .field("component", &self.component)
            .field("incarnation", &self.incarnation)
            .field("launch_nonce", &self.launch_nonce)
            .field("executable", &self.executable)
            .field("executable_sha256", &self.executable_sha256)
            .field("argument_count", &self.arguments.len())
            .field("working_directory", &self.working_directory)
            .field("environment_count", &self.environment.len())
            .field("session", &self.session)
            .field("graceful_timeout", &self.graceful_timeout)
            .field("force_timeout", &self.force_timeout)
            .finish()
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

fn validate_sha256(label: &str, value: &str) -> Result<(), AdapterError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AdapterError::Invalid(format!(
            "{label} must be a 64-character SHA-256 hexadecimal digest"
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
            executable: std::env::current_exe().expect("test executable"),
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

    #[test]
    fn launch_spec_rejects_bad_digest_duplicate_environment_and_aggregate_overflow() {
        let mut invalid = specification();
        invalid.executable_sha256 = "not-a-digest".to_owned();
        assert!(matches!(
            invalid.validate(),
            Err(AdapterError::Invalid(message)) if message.contains("SHA-256")
        ));

        invalid = specification();
        invalid.environment = vec![
            ("PATH".to_owned(), "/one".to_owned()),
            ("PATH".to_owned(), "/two".to_owned()),
        ];
        assert!(invalid.validate().is_err());

        invalid = specification();
        invalid.arguments = vec!["x".repeat(MAX_LAUNCH_BYTES)];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn launch_spec_applies_role_specific_session_policy() {
        let mut background = specification();
        assert!(background.validate().is_ok());
        background.session = SessionSelector::ActiveUser;
        assert!(matches!(
            background.validate(),
            Err(AdapterError::Unsupported(_))
        ));

        background.component = ComponentKind::HostBroker;
        background.session = SessionSelector::Explicit(0);
        assert!(matches!(
            background.validate(),
            Err(AdapterError::Unsupported(_))
        ));
        background.session = SessionSelector::Explicit(7);
        assert!(background.validate().is_ok());
    }

    #[test]
    fn launch_spec_debug_does_not_include_environment_values() {
        let mut specification = specification();
        specification.environment = vec![("TOKEN".to_owned(), "super-secret".to_owned())];
        let debug = format!("{specification:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("environment_count"));
    }
}

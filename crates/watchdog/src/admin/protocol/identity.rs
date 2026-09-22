//! Contract identity: capability classes, authenticated principal classes and
//! the closed command-name set.

use serde::{Deserialize, Serialize};

/// The two credentials are intentionally separate.  `Admin` is required for
/// every desired-state or recovery transition; a read credential can never
/// claim that capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Status, jobs, attempts and release inspection only.
    Read,
    /// Desired-state, recovery, backup, restore and activation operations.
    Admin,
}

/// Coarse identity of the principal that passed transport authentication.
///
/// This value is deliberately an enum rather than a token, SID, path, or
/// arbitrary provider claim.  It is safe to persist in a watchdog audit row
/// and is the only credential-related value that crosses the queue boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedPrincipalClass {
    /// The owner-local read credential authenticated the request.
    ReadToken,
    /// The owner-local administrator credential authenticated the request.
    AdminToken,
    /// The protected Windows named-pipe peer SID authenticated the request.
    WindowsOperator,
}

impl Capability {
    /// Whether this capability may satisfy the required capability.
    #[must_use]
    pub const fn includes(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Admin, _) | (Self::Read, Self::Read)
        )
    }
}

/// Fixed command names.  There is deliberately no `play`, `dispatch`,
/// `settle`, `send`, `mutate`, or generic proxy command in this enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandName {
    Status,
    Start,
    Pause,
    Resume,
    Drain,
    Stop,
    Jobs,
    JobSubmit,
    Attempt,
    Quarantine,
    Retry,
    Reconcile,
    Backup,
    Restore,
    ReleaseInspect,
    ReleaseActivate,
}

impl CommandName {
    /// Capability required by a command.
    #[must_use]
    pub const fn required_capability(self) -> Capability {
        match self {
            Self::Status | Self::Jobs | Self::Attempt | Self::ReleaseInspect => Capability::Read,
            Self::Start
            | Self::Pause
            | Self::Resume
            | Self::Drain
            | Self::Stop
            | Self::Quarantine
            | Self::Retry
            | Self::Reconcile
            | Self::Backup
            | Self::Restore
            | Self::ReleaseActivate
            | Self::JobSubmit => Capability::Admin,
        }
    }
}

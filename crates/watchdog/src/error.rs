//! Error types shared by the watchdog's policy, storage, and process layers.

use std::path::PathBuf;

/// The result type used by the watchdog library.
pub type Result<T> = std::result::Result<T, WatchdogError>;

/// Errors are intentionally classified so callers can keep a persistence
/// outage, an operator mistake, and an unsafe process identity distinct.
#[derive(Debug)]
pub enum WatchdogError {
    /// A required initialized store does not exist.  Read-only commands use
    /// this variant instead of creating state as a side effect.
    MissingState(PathBuf),
    /// A second mutating controller already owns the store lock.
    Busy(PathBuf),
    /// A configuration or API value is outside its bounded contract.
    InvalidInput(String),
    /// A requested entity was not found.
    NotFound(String),
    /// An operation would violate a durable uniqueness or state transition.
    Conflict(String),
    /// The caller lacks the capability required for the requested operation.
    Unauthorized(String),
    /// A process identity no longer matches the exact child that was launched.
    IdentityMismatch(String),
    /// A bounded operation exceeded its deadline.
    Timeout(String),
    /// The requested platform operation is not available in this build.
    Unsupported(String),
    /// SQLite reported a failure.  The original error is retained for
    /// diagnostics and, importantly, does not trigger an implicit reset.
    Sqlite(rusqlite::Error),
    /// The filesystem or process layer reported a failure.
    Io(std::io::Error),
    /// JSON/configuration encoding failed.
    Json(serde_json::Error),
    /// A structured verification report failed its admission gate. The
    /// payload is emitted unchanged by the CLI so automation can retain all
    /// fail-closed findings while still receiving a nonzero exit code.
    VerificationFailed(String),
}

impl std::fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingState(path) => {
                write!(f, "watchdog state is not initialized: {}", path.display())
            }
            Self::Busy(path) => write!(f, "watchdog store is already owned: {}", path.display()),
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
            Self::NotFound(name) => write!(f, "not found: {name}"),
            Self::Conflict(message) => write!(f, "conflict: {message}"),
            Self::Unauthorized(message) => write!(f, "unauthorized: {message}"),
            Self::IdentityMismatch(message) => write!(f, "process identity mismatch: {message}"),
            Self::Timeout(message) => write!(f, "timed out: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Sqlite(error) => write!(f, "sqlite error: {error}"),
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::VerificationFailed(report) => write!(f, "{report}"),
        }
    }
}

impl std::error::Error for WatchdogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for WatchdogError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for WatchdogError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for WatchdogError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl WatchdogError {
    /// Returns true when a command should report that initialization is
    /// required rather than treating the store as corrupt or empty.
    #[must_use]
    pub fn is_missing_state(&self) -> bool {
        matches!(self, Self::MissingState(_))
    }
}

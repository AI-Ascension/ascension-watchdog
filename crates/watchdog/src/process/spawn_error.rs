//! Spawn-failure classification for the restricted process adapter.
//!
//! `ProcessSpawnError` keeps the historical `WatchdogError` contract while
//! distinguishing a rejected launch from a launch whose exact containment
//! cleanup could not be proven before the bounded deadline.

use crate::error::WatchdogError;

/// Failure from the portable child launcher. `CleanupUncertain` means that
/// the launch may have created a process group whose cleanup could not be
/// proven before the bounded deadline; callers must retain/quarantine the
/// corresponding launch intent instead of treating this as an ordinary
/// rejected launch.
#[derive(Debug)]
pub enum ProcessSpawnError {
    Ordinary(WatchdogError),
    CleanupUncertain(WatchdogError),
}

impl ProcessSpawnError {
    /// Convert to the legacy process error used by callers that do not need
    /// cleanup classification.
    #[must_use]
    pub fn into_watchdog_error(self) -> WatchdogError {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => error,
        }
    }

    /// True when process creation may have left exact containment unsettled.
    #[must_use]
    pub fn is_cleanup_uncertain(&self) -> bool {
        matches!(self, Self::CleanupUncertain(_))
    }
}

impl std::fmt::Display for ProcessSpawnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary(error) => write!(formatter, "ordinary process spawn failure: {error}"),
            Self::CleanupUncertain(error) => {
                write!(formatter, "process spawn cleanup is uncertain: {error}")
            }
        }
    }
}

impl std::error::Error for ProcessSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => Some(error),
        }
    }
}

impl From<WatchdogError> for ProcessSpawnError {
    fn from(error: WatchdogError) -> Self {
        Self::Ordinary(error)
    }
}

impl From<std::io::Error> for ProcessSpawnError {
    fn from(error: std::io::Error) -> Self {
        Self::Ordinary(WatchdogError::Io(error))
    }
}

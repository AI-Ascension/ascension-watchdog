//! OS-facing boundaries for the watchdog.
//!
//! The portable contract contains no process-launch implementation.  Platform
//! modules are responsible for proving ownership before they return a handle;
//! the reconciler remains responsible for durable intent and policy.

pub mod contract;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod linux_process;
pub mod wsl;

pub use contract::{
    AdapterError, ComponentKind, ContainmentId, LaunchSpec, Observation, OwnedProcess,
    ProcessAdapter, ProcessCreation, ProcessIdentity, SessionSelector, StopOutcome,
};
#[cfg(target_os = "linux")]
pub use linux::{NotificationResult, SystemdNotifier};
#[cfg(target_os = "linux")]
pub use linux_process::LinuxProcessAdapter;
pub use wsl::{WslInvocation, WslInvocationError};

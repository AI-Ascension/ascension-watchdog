//! Native Windows boundary for Ascension watchdog.
//!
//! This crate is deliberately standalone so the small reviewed FFI surface is
//! not mixed into the portable watchdog package.  On Windows it provides SCM
//! service status, a fixed ACL named-pipe lifecycle channel, an explicit user
//! session selector, and Job Object process ownership.  On other platforms it
//! exposes only capability/error types; no unsupported operation reports
//! success.

#![allow(clippy::missing_errors_doc)]

mod contract;
pub use contract::{
    ComponentKind, LifecycleCapability, LifecycleFrame, LifecycleRequest, PlatformError,
    ProcessIdentity, SessionSelector, WindowsLaunchSpec, WindowsPlatformConfig,
};

#[cfg(windows)]
mod admin_pipe;
#[cfg(windows)]
pub use admin_pipe::{
    AdminPipeClient, AdminPipePeer, AdminPipeServer, MAX_ADMIN_PIPE_FRAME,
    read_protected_payload_file, validate_protected_credential_file,
};

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{
    ActiveSession, JobOwnedProcess, NamedPipePeer, NamedPipeServer, ScmHealthChecker,
    ServiceInstallPlan, ServiceRuntime, StopOutcome, WindowsLaunchError, WindowsProcessLauncher,
    select_active_session,
};

/// Report whether this crate's native Windows boundary is available.
pub fn ensure_native_platform() -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::Unsupported(
            "the native Windows boundary is unavailable on this target".to_owned(),
        ))
    }
}

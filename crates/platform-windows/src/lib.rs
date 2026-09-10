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
mod native_gateway_health_bootstrap;
mod native_worker_bootstrap;
pub mod service_command;
pub use contract::{
    ComponentKind, LifecycleCapability, LifecycleFrame, LifecycleRequest, PlatformError,
    ProcessIdentity, SessionSelector, WindowsLaunchSpec, WindowsPlatformConfig,
};
pub use native_gateway_health_bootstrap::{
    GATEWAY_HEALTH_BOOTSTRAP_FRAME_BYTES, GatewayHealthBootstrapLaunch,
};
pub use native_worker_bootstrap::{MAX_WORKER_BOOTSTRAP_FRAME_BYTES, WorkerBootstrapLaunch};

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
    ActiveSession, CurrentControllerIdentity, JobOwnedProcess, NamedPipePeer, NamedPipeServer,
    ProtectedDirectoryHandle, ScmHealthChecker, ServiceBinding, ServiceInstallPlan, ServiceRuntime,
    StopOutcome, StoppedServiceWitness, WindowsLaunchError, WindowsProcessLauncher,
    capture_current_controller, executable_sha256, open_protected_directory, select_active_session,
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

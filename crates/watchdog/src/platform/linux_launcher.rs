//! Race-free Linux launch handoff.
//!
//! A normal `Command::spawn` starts the requested program before a caller can
//! write its PID to a cgroup.  That ordering is not an ownership proof.  This
//! module instead starts the trusted watchdog executable in a barrier mode.
//! The helper accepts one bounded request frame, waits for a nonce-bound `GO`,
//! and only then starts the approved component.  The parent places the helper
//! in the durable cgroup and verifies membership before sending `GO`.
//!
//! The helper calls the safe Unix `CommandExt::exec` operation only after the
//! complete request and cgroup membership have been checked.  `exec` replaces
//! the helper in place, preserving the PID and all inherited stream handles;
//! there is no second target process or post-spawn PID move to authorize.

mod protected_bootstrap;
pub use protected_bootstrap::{
    LinuxHelperBootstrap, helper_argument, helper_invocation_requested, protected_config_argument,
};
mod parent_launcher;
pub(crate) use parent_launcher::PendingLaunch;
pub use parent_launcher::{LauncherStreams, OutputMode, TrustedLinuxLauncher};
mod helper_authorization;
pub use helper_authorization::{
    LinuxHelperAuthorization, LinuxHelperRequest, run_hidden_helper_if_requested,
    run_hidden_helper_if_requested_with_bootstrap_and_gateway_health_authorizer,
    run_hidden_helper_if_requested_with_bootstrap_authorizer,
    run_hidden_helper_if_requested_with_health_authorizer, run_hidden_helper_with_authorizer,
    run_hidden_helper_with_bootstrap_and_gateway_health_authorizer,
    run_hidden_helper_with_bootstrap_authorizer,
};
mod cgroup;
mod executable_snapshot;
mod framed_protocol;

use std::os::fd::RawFd;
use std::time::Duration;

const FRAME_MAGIC: &[u8; 8] = b"ASC-LNX1";
const FRAME_VERSION: u8 = 1;
const GO_MAGIC: &[u8; 8] = b"ASC-GO01";
const READY_MAGIC: &[u8; 8] = b"ASC-RDY1";
const HELPER_ARGUMENT: &str = "--ascension-linux-launch-helper";
const PARENT_BOOTSTRAP_PID_ARGUMENT: &str = "--ascension-linux-parent-bootstrap-pid";
const PROTECTED_CONFIG_ARGUMENT: &str = "--ascension-linux-protected-config";
const DELEGATED_CGROUP_ROOT_ARGUMENT: &str = "--ascension-linux-delegated-cgroup-root";
const WORKER_PIPE_ARGUMENT: &str = "--ascension-linux-worker-pipe";
const WORKER_BOOT_ID_ARGUMENT: &str = "--ascension-linux-worker-boot-id";
const WORKER_FRAME_SHA256_ARGUMENT: &str = "--ascension-linux-worker-frame-sha256";
const GATEWAY_HEALTH_PIPE_ARGUMENT: &str = "--ascension-linux-gateway-health-pipe";
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 64;
const MAX_ENVIRONMENT: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);
const CHILD_CLEANUP_POLL: Duration = Duration::from_millis(10);
const MIN_INHERITED_FD: RawFd = 3;
const O_DIRECTORY: i32 = 0o200_000;
const O_NONBLOCK: i32 = 0o4_000;
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

#[cfg(test)]
mod tests;

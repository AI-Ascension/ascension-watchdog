//! OS-facing boundaries for the watchdog.
//!
//! The portable contract contains no process-launch implementation.  Platform
//! modules are responsible for proving ownership before they return a handle;
//! the reconciler remains responsible for durable intent and policy.

pub mod contract;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod linux_broker;
#[cfg(target_os = "linux")]
pub mod linux_launcher;
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
pub use linux_broker::{
    BrokerClient, BrokerComponent, BrokerLedger, BrokerPolicy, BrokerRequest, LaunchReceipt,
    LinuxSystemdBroker, PeerCredentials,
};
#[cfg(target_os = "linux")]
pub use linux_launcher::{
    LauncherStreams, LinuxHelperAuthorization, LinuxHelperBootstrap, LinuxHelperRequest,
    OutputMode, TrustedLinuxLauncher, helper_argument, helper_invocation_requested,
    protected_config_argument, run_hidden_helper_if_requested,
    run_hidden_helper_if_requested_with_bootstrap_authorizer, run_hidden_helper_with_authorizer,
    run_hidden_helper_with_bootstrap_authorizer,
};
#[cfg(target_os = "linux")]
pub use linux_process::LinuxProcessAdapter;
pub use wsl::{WslInvocation, WslInvocationError};

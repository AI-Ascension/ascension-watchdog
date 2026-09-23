//! Native backend dispatch and platform conversions.
//!
//! This child owns the single native-process dispatch point used by the
//! supervision facade: the `NativeBackend` enum and its create/launch/reopen/
//! inspect/stop/force-cleanup implementation over the Linux adapter, the Linux
//! broker client and the Windows job backend, the `NativeChild` handle, the
//! retained broker receipt, and the platform observation/stop/error
//! conversions.  It owns no containment policy of its own: broker request and
//! receipt binding stay in the coordinator, and every platform authority call
//! goes through the existing adapters.
//!
//! The module is well below the 1,000-line target.  The body is a verbatim
//! move; the only edits are `pub(super)` on the items the coordinator still
//! calls (their effective visibility is unchanged) and module-local imports.
//! The coordinator imports `NativeBackend`/`NativeChild` back so `runtime.rs`,
//! the sibling runtime modules and the existing regression tests are
//! unchanged.

use crate::config::WatchdogConfig;
use crate::error::{Result, WatchdogError};
#[cfg(windows)]
use crate::platform::SessionSelector as PlatformSessionSelector;
#[cfg(target_os = "linux")]
use crate::platform::{
    AdapterError, ContainmentId, Observation as PlatformObservation, OwnedProcess, ProcessAdapter,
    ProcessCreation, ProcessIdentity as PlatformProcessIdentity,
    StopOutcome as PlatformStopOutcome,
};
use crate::platform::{ComponentKind as PlatformComponentKind, LaunchSpec};
use crate::process::ProcessIdentity;
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use super::NATIVE_GRACEFUL_TIMEOUT;
use super::native_allowlist;
#[cfg(target_os = "linux")]
use super::platform_component_kind;
use super::{OwnershipProof, RuntimeLaunchError, RuntimeObservation, RuntimeStopOutcome};
#[cfg(target_os = "linux")]
use super::{
    broker_planned_containment_for, broker_planned_containment_for_request, broker_request_for,
    broker_request_from_planned_containment, broker_request_from_proof,
    map_broker_bootstrap_launch_error, map_broker_error, verify_broker_receipt,
    verify_broker_receipt_against_proof, verify_broker_receipt_binding,
};

const NATIVE_MAX_PROCESSES: u32 = 64;
#[cfg(windows)]
const NATIVE_FORCE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) enum NativeChild {
    #[cfg(target_os = "linux")]
    Linux(OwnedProcess),
    #[cfg(target_os = "linux")]
    LinuxBroker(BrokerOwnedProcess),
    #[cfg(windows)]
    Windows(ascension_platform_windows::JobOwnedProcess),
}

/// Exact broker receipt retained with the child.  The broker is the process
/// authority; the runtime never reconstructs a unit from a PID or executable
/// name after this receipt has been obtained.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(super) struct BrokerOwnedProcess {
    receipt: crate::platform::LaunchReceipt,
}

#[derive(Debug)]
pub(super) enum NativeBackend {
    #[cfg(target_os = "linux")]
    Linux(Box<crate::platform::LinuxProcessAdapter>),
    #[cfg(target_os = "linux")]
    LinuxBroker(crate::platform::BrokerClient),
    #[cfg(windows)]
    Windows(WindowsBackend),
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsBackend {
    launcher: ascension_platform_windows::WindowsProcessLauncher,
}

impl NativeBackend {
    #[allow(clippy::needless_return)]
    pub(super) fn create(config: &WatchdogConfig) -> Result<Self> {
        let allowlist = native_allowlist(config)?;
        #[cfg(target_os = "linux")]
        {
            if let Some(broker) = config.linux_broker.as_ref() {
                let client = crate::platform::BrokerClient::new(
                    broker.socket_path().to_path_buf(),
                    broker.timeout(),
                )
                .map_err(map_broker_error)?;
                return Ok(NativeBackend::LinuxBroker(client));
            }
            let allowlist: BTreeMap<PlatformComponentKind, PathBuf> = allowlist
                .into_iter()
                .map(|(kind, (path, _digest))| (kind, path))
                .collect();
            let probe = crate::platform::LinuxProcessAdapter::new(allowlist.clone())
                .map_err(map_adapter_error)?;
            let root = probe.cgroup_root().to_path_buf();
            let launcher = crate::platform::TrustedLinuxLauncher::current_executable()
                .map_err(map_adapter_error)?;
            let launcher = match &config.source_path {
                Some(path) => launcher
                    .with_protected_config_path(path)
                    .and_then(|launcher| launcher.with_delegated_cgroup_root(&root))
                    .map_err(map_adapter_error)?,
                None => launcher,
            };
            crate::platform::LinuxProcessAdapter::with_cgroup_root_and_limit_and_launcher(
                root,
                allowlist,
                NATIVE_MAX_PROCESSES as usize,
                launcher,
            )
            .map(|adapter| NativeBackend::Linux(Box::new(adapter)))
            .map_err(map_adapter_error)
        }
        #[cfg(windows)]
        {
            let (allowlisted_executables, approved_executable_sha256): (
                BTreeMap<_, _>,
                BTreeMap<_, _>,
            ) = allowlist
                .into_iter()
                .map(|(kind, (path, digest))| ((kind, path), (kind, digest)))
                .unzip();
            let launcher = ascension_platform_windows::WindowsProcessLauncher::new(
                ascension_platform_windows::WindowsPlatformConfig {
                    service_name: "ascension-watchdog".to_owned(),
                    pipe_name: r"\\.\pipe\ascension-watchdog-runtime".to_owned(),
                    allowlisted_executables: allowlisted_executables
                        .into_iter()
                        .map(|(kind, path)| (windows_component_kind(kind), path))
                        .collect(),
                    approved_executable_sha256: approved_executable_sha256
                        .into_iter()
                        .map(|(kind, digest)| (windows_component_kind(kind), digest))
                        .collect(),
                    authorized_peer_executable: std::env::current_exe()?,
                    max_arguments: 64,
                    max_environment: 64,
                    max_processes: NATIVE_MAX_PROCESSES,
                },
            )
            .map_err(map_windows_error)?;
            return Ok(NativeBackend::Windows(WindowsBackend { launcher }));
        }
    }

    pub(super) fn launch(
        &mut self,
        config: &WatchdogConfig,
        specification: &LaunchSpec,
        planned_containment: &str,
        worker: Option<&crate::worker_bootstrap::WorkerBootstrapLaunch>,
        gateway_health: Option<&crate::platform::gateway_health::GatewayHealthBootstrap>,
        watchdog_boot_id: &str,
    ) -> std::result::Result<NativeChild, RuntimeLaunchError> {
        #[cfg(not(windows))]
        let _ = (config, watchdog_boot_id);
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(adapter) => {
                let containment = ContainmentId::new(planned_containment.to_owned())
                    .map_err(|error| RuntimeLaunchError::Ordinary(map_adapter_error(error)))?;
                let launched = match (worker, gateway_health) {
                    (Some(worker), None) => adapter
                        .launch_with_planned_containment_and_worker_bootstrap(
                            specification,
                            &containment,
                            worker,
                        ),
                    (None, Some(health)) => adapter
                        .launch_with_planned_containment_and_gateway_health_bootstrap(
                            specification,
                            &containment,
                            health,
                        ),
                    (None, None) => {
                        adapter.launch_with_planned_containment(specification, &containment)
                    }
                    (Some(_), Some(_)) => {
                        return Err(RuntimeLaunchError::Ordinary(WatchdogError::InvalidInput(
                            "ambiguous native bootstrap".to_owned(),
                        )));
                    }
                };
                launched.map(NativeChild::Linux).map_err(|error| {
                    if crate::platform::linux_process::is_cleanup_uncertain(&error) {
                        RuntimeLaunchError::CleanupUncertain(map_adapter_error(error))
                    } else {
                        RuntimeLaunchError::Ordinary(map_adapter_error(error))
                    }
                })
            }
            #[cfg(target_os = "linux")]
            Self::LinuxBroker(client) => {
                let request =
                    broker_request_for(specification).map_err(RuntimeLaunchError::Ordinary)?;
                let expected_containment = broker_planned_containment_for(specification)
                    .map_err(RuntimeLaunchError::Ordinary)?;
                if planned_containment != expected_containment {
                    return Err(RuntimeLaunchError::Ordinary(
                        WatchdogError::IdentityMismatch(
                            "planned Linux broker identity differs from the launch request"
                                .to_owned(),
                        ),
                    ));
                }
                let receipt = match (worker, gateway_health) {
                    (Some(worker), None) => {
                        let bootstrap = crate::platform::linux_broker::bootstrap::BrokerBootstrapLaunch::for_worker(
                            &request,
                            worker,
                        )
                        .map_err(map_broker_error)
                        .map_err(RuntimeLaunchError::Ordinary)?;
                        client
                            .launch_with_bootstrap(&request, &bootstrap)
                            .map_err(map_broker_bootstrap_launch_error)?
                    }
                    (None, Some(health)) => {
                        let bootstrap = crate::platform::linux_broker::bootstrap::BrokerBootstrapLaunch::for_gateway(
                            &request,
                            watchdog_boot_id,
                            health,
                        )
                        .map_err(map_broker_error)
                        .map_err(RuntimeLaunchError::Ordinary)?;
                        client
                            .launch_with_bootstrap(&request, &bootstrap)
                            .map_err(map_broker_bootstrap_launch_error)?
                    }
                    (None, None) => client.launch(&request).map_err(|error| {
                        // The legacy client intentionally exposes one error
                        // type for failures before and after transport write.
                        // Treat every failed call as uncertain so a receipt
                        // that may have been committed is reconciled by the
                        // same request identity rather than relaunched.
                        RuntimeLaunchError::CleanupUncertain(map_broker_error(error))
                    })?,
                    (Some(_), Some(_)) => {
                        return Err(RuntimeLaunchError::Ordinary(WatchdogError::InvalidInput(
                            "ambiguous Linux broker bootstrap".to_owned(),
                        )));
                    }
                };
                verify_broker_receipt(specification, planned_containment, &receipt)
                    .map_err(RuntimeLaunchError::Ordinary)?;
                Ok(NativeChild::LinuxBroker(BrokerOwnedProcess { receipt }))
            }
            #[cfg(windows)]
            Self::Windows(backend) => {
                let expected = format!("windows-job:{}", specification.launch_nonce);
                if planned_containment != expected {
                    return Err(RuntimeLaunchError::Ordinary(
                        WatchdogError::IdentityMismatch(
                            "planned Windows Job authority differs from the launch nonce"
                                .to_owned(),
                        ),
                    ));
                }
                let windows_spec =
                    windows_launch_spec(specification).map_err(RuntimeLaunchError::Ordinary)?;
                let launched = if let Some(worker) = worker {
                    let native_frame = ascension_platform_windows::WorkerBootstrapLaunch::new(
                        worker.frame().to_vec(),
                    )
                    .map_err(|error| RuntimeLaunchError::Ordinary(map_windows_error(error)))?;
                    backend.launcher.launch_with_worker_bootstrap_and_barrier(
                        &windows_spec,
                        &native_frame,
                        || {
                            super::super::runtime_worker_admission::authorize(
                                config,
                                specification,
                                planned_containment,
                                worker,
                                std::time::Instant::now() + Duration::from_secs(5),
                            )
                            .map_err(|error| {
                                ascension_platform_windows::PlatformError::IdentityMismatch(
                                    format!("worker pre-resume admission rejected: {error}"),
                                )
                            })
                        },
                    )
                } else if let Some(health) = gateway_health {
                    let frame = health.encoded_frame();
                    let native_frame =
                        ascension_platform_windows::GatewayHealthBootstrapLaunch::from_frame(
                            *frame,
                        )
                        .map_err(|error| RuntimeLaunchError::Ordinary(map_windows_error(error)))?;
                    backend
                        .launcher
                        .launch_with_gateway_health_bootstrap_and_barrier(
                            &windows_spec,
                            &native_frame,
                            || {
                                super::super::runtime_gateway_health_admission::authorize_windows(
                                    config,
                                    specification,
                                    planned_containment,
                                    health,
                                    watchdog_boot_id,
                                    std::time::Instant::now() + Duration::from_secs(5),
                                )
                                .map_err(|error| {
                                    ascension_platform_windows::PlatformError::IdentityMismatch(
                                        format!("gateway pre-resume admission rejected: {error}"),
                                    )
                                })
                            },
                        )
                } else {
                    backend.launcher.launch(&windows_spec)
                };
                launched
                    .map(NativeChild::Windows)
                    .map_err(|error| match error {
                        ascension_platform_windows::WindowsLaunchError::Ordinary(error) => {
                            RuntimeLaunchError::Ordinary(map_windows_error(error))
                        }
                        ascension_platform_windows::WindowsLaunchError::CleanupUncertain(error) => {
                            RuntimeLaunchError::CleanupUncertain(map_windows_error(error))
                        }
                    })
            }
        }
    }

    pub(super) fn force_cleanup_planned_containment(
        &mut self,
        planned_containment: &str,
    ) -> Result<RuntimeStopOutcome> {
        #[cfg(windows)]
        let _ = planned_containment;
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(adapter) => {
                let containment = ContainmentId::new(planned_containment.to_owned())
                    .map_err(map_adapter_error)?;
                adapter
                    .force_cleanup_planned_containment(&containment)
                    .map(map_stop_outcome)
                    .map_err(map_adapter_error)
            }
            #[cfg(target_os = "linux")]
            Self::LinuxBroker(client) => {
                let request = broker_request_from_planned_containment(planned_containment)?;
                // Stop is idempotent for a committed or terminal receipt and
                // also gives the broker a chance to cancel an exact queued
                // job for a still-pending reservation. An Inspect-first
                // branch would turn that pending cancellation into a
                // read-only conflict and leave the manager job untouched.
                client
                    .stop(&request)
                    .map(|receipt| {
                        if receipt.state
                            == crate::platform::linux_broker::BrokerLifecycleState::Stopped
                        {
                            if receipt.duplicate {
                                RuntimeStopOutcome::AlreadyExited
                            } else {
                                RuntimeStopOutcome::Exited(None)
                            }
                        } else {
                            RuntimeStopOutcome::TimedOut
                        }
                    })
                    .map_err(map_broker_error)
            }
            #[cfg(windows)]
            Self::Windows(backend) => backend
                .launcher
                .force_cleanup_planned_containment(planned_containment, NATIVE_FORCE_TIMEOUT)
                .map(|outcome| match outcome {
                    ascension_platform_windows::StopOutcome::Exited => {
                        RuntimeStopOutcome::Exited(None)
                    }
                    ascension_platform_windows::StopOutcome::AlreadyExited => {
                        RuntimeStopOutcome::AlreadyExited
                    }
                    ascension_platform_windows::StopOutcome::TimedOut => {
                        RuntimeStopOutcome::TimedOut
                    }
                })
                .map_err(map_windows_error),
        }
    }

    pub(super) fn reopen(&mut self, proof: &OwnershipProof) -> Result<NativeChild> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(_) => {
                let identity = PlatformProcessIdentity {
                    deployment_id: proof.deployment_id.clone(),
                    instance_id: proof.instance_id.clone(),
                    component: platform_component_kind(&proof.component)?,
                    incarnation: proof.incarnation.clone(),
                    launch_nonce: proof.launch_nonce.clone(),
                    creation: ProcessCreation {
                        token: proof.creation_token.clone(),
                        pid: proof.pid,
                    },
                    executable: proof.executable.clone(),
                    executable_sha256: proof.executable_sha256.clone(),
                    containment: ContainmentId::new(proof.containment_id.clone())
                        .map_err(map_adapter_error)?,
                    session: proof.session_id,
                };
                Ok(NativeChild::Linux(OwnedProcess { identity }))
            }
            #[cfg(target_os = "linux")]
            Self::LinuxBroker(client) => {
                let request = broker_request_from_proof(proof)?;
                let expected_containment = broker_planned_containment_for_request(&request)?;
                if proof.containment_id != expected_containment {
                    return Err(WatchdogError::IdentityMismatch(
                        "Linux broker proof containment is not bound to its request".to_owned(),
                    ));
                }
                let lifecycle = client.inspect(&request).map_err(map_broker_error)?;
                if lifecycle.state != crate::platform::linux_broker::BrokerLifecycleState::Active {
                    return Err(WatchdogError::Conflict(
                        "Linux broker receipt is not active during recovery".to_owned(),
                    ));
                }
                verify_broker_receipt_against_proof(&lifecycle.receipt, proof)?;
                Ok(NativeChild::LinuxBroker(BrokerOwnedProcess {
                    receipt: lifecycle.receipt,
                }))
            }
            #[cfg(windows)]
            Self::Windows(_) => {
                let identity = windows_process_identity(proof)?;
                ascension_platform_windows::JobOwnedProcess::reopen(
                    identity,
                    NATIVE_MAX_PROCESSES,
                    NATIVE_GRACEFUL_TIMEOUT,
                    NATIVE_FORCE_TIMEOUT,
                )
                .map(NativeChild::Windows)
                .map_err(map_windows_error)
            }
        }
    }

    pub(super) fn inspect(&mut self, child: &mut NativeChild) -> Result<RuntimeObservation> {
        match (self, child) {
            #[cfg(target_os = "linux")]
            (Self::Linux(adapter), NativeChild::Linux(process)) => adapter
                .inspect(process)
                .map(|observation| map_platform_observation(&observation))
                .map_err(map_adapter_error),
            #[cfg(target_os = "linux")]
            (Self::LinuxBroker(client), NativeChild::LinuxBroker(process)) => {
                let lifecycle = client
                    .inspect(&process.receipt.request)
                    .map_err(map_broker_error)?;
                verify_broker_receipt_binding(&lifecycle.receipt, &process.receipt)?;
                Ok(match lifecycle.state {
                    crate::platform::linux_broker::BrokerLifecycleState::Active => {
                        RuntimeObservation::Running
                    }
                    crate::platform::linux_broker::BrokerLifecycleState::Stopped => {
                        RuntimeObservation::Exited { code: None }
                    }
                })
            }
            #[cfg(target_os = "linux")]
            (Self::Linux(_), NativeChild::LinuxBroker(_))
            | (Self::LinuxBroker(_), NativeChild::Linux(_)) => Err(WatchdogError::Conflict(
                "native process backend and child authority differ".to_owned(),
            )),
            #[cfg(windows)]
            (Self::Windows(_), NativeChild::Windows(process)) => process
                .is_running()
                .map(|running| {
                    if running {
                        RuntimeObservation::Running
                    } else {
                        RuntimeObservation::Exited { code: None }
                    }
                })
                .map_err(map_windows_error),
        }
    }

    pub(super) fn stop(&mut self, child: &mut NativeChild) -> Result<RuntimeStopOutcome> {
        match (self, child) {
            #[cfg(target_os = "linux")]
            (Self::Linux(adapter), NativeChild::Linux(process)) => {
                let graceful = adapter.graceful_stop(process);
                let outcome = match graceful {
                    Ok(PlatformStopOutcome::Exited) => Ok(PlatformStopOutcome::Exited),
                    Ok(PlatformStopOutcome::AlreadyExited) => {
                        Ok(PlatformStopOutcome::AlreadyExited)
                    }
                    Ok(PlatformStopOutcome::TimedOut)
                    | Err(AdapterError::Unavailable(_) | AdapterError::Unsupported(_)) => {
                        adapter.force_stop(process)
                    }
                    Err(error) => Err(error),
                }
                .map_err(map_adapter_error)?;
                Ok(map_stop_outcome(outcome))
            }
            #[cfg(target_os = "linux")]
            (Self::LinuxBroker(client), NativeChild::LinuxBroker(process)) => {
                let lifecycle = client
                    .stop(&process.receipt.request)
                    .map_err(map_broker_error)?;
                verify_broker_receipt_binding(&lifecycle.receipt, &process.receipt)?;
                if lifecycle.state != crate::platform::linux_broker::BrokerLifecycleState::Stopped {
                    return Err(WatchdogError::Conflict(
                        "Linux broker stop did not reach a terminal state".to_owned(),
                    ));
                }
                Ok(if lifecycle.duplicate {
                    RuntimeStopOutcome::AlreadyExited
                } else {
                    RuntimeStopOutcome::Exited(None)
                })
            }
            #[cfg(target_os = "linux")]
            (Self::Linux(_), NativeChild::LinuxBroker(_))
            | (Self::LinuxBroker(_), NativeChild::Linux(_)) => Err(WatchdogError::Conflict(
                "native process backend and child authority differ".to_owned(),
            )),
            #[cfg(windows)]
            (Self::Windows(_), NativeChild::Windows(process)) => {
                let graceful = process.graceful_stop();
                let outcome = match graceful {
                    Ok(ascension_platform_windows::StopOutcome::Exited) => {
                        Ok(ascension_platform_windows::StopOutcome::Exited)
                    }
                    Ok(ascension_platform_windows::StopOutcome::AlreadyExited) => {
                        Ok(ascension_platform_windows::StopOutcome::AlreadyExited)
                    }
                    Ok(ascension_platform_windows::StopOutcome::TimedOut)
                    | Err(ascension_platform_windows::PlatformError::Unsupported(_)) => {
                        process.force_stop()
                    }
                    Err(error) => Err(error),
                }
                .map_err(map_windows_error)?;
                Ok(match outcome {
                    ascension_platform_windows::StopOutcome::Exited => {
                        RuntimeStopOutcome::Exited(None)
                    }
                    ascension_platform_windows::StopOutcome::AlreadyExited => {
                        RuntimeStopOutcome::AlreadyExited
                    }
                    ascension_platform_windows::StopOutcome::TimedOut => {
                        RuntimeStopOutcome::TimedOut
                    }
                })
            }
        }
    }
}

impl NativeChild {
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn identity(
        &self,
        intent_id: &str,
        specification: &LaunchSpec,
        planned_containment: &str,
        now_ms: u64,
    ) -> Result<(ProcessIdentity, OwnershipProof)> {
        #[cfg(windows)]
        let _ = planned_containment;
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(process) => {
                let identity = process.identity.clone();
                let proof = OwnershipProof::from_platform(
                    "linux",
                    intent_id,
                    specification,
                    planned_containment,
                    &identity,
                    now_ms,
                )?;
                Ok((proof.portable_identity(), proof))
            }
            #[cfg(target_os = "linux")]
            Self::LinuxBroker(process) => {
                let proof = OwnershipProof::from_broker_receipt(
                    "linux",
                    intent_id,
                    specification,
                    planned_containment,
                    &process.receipt,
                    now_ms,
                )?;
                Ok((proof.portable_identity(), proof))
            }
            #[cfg(windows)]
            Self::Windows(process) => {
                let identity = process.identity();
                let portable = ProcessIdentity {
                    pid: identity.pid,
                    launch_nonce: identity.launch_nonce.clone(),
                    executable: identity.executable.clone(),
                    executable_digest: identity.executable_sha256.clone(),
                    started_at_ms: now_ms,
                    creation_fingerprint: Some(identity.creation_time_100ns.to_string()),
                };
                let proof = OwnershipProof {
                    version: 1,
                    backend: "windows".to_owned(),
                    intent_id: intent_id.to_owned(),
                    deployment_id: specification.deployment_id.clone(),
                    instance_id: specification.instance_id.clone(),
                    component: specification.instance_id.clone(),
                    incarnation: specification.incarnation.clone(),
                    launch_nonce: specification.launch_nonce.clone(),
                    containment_id: format!("windows-job:{}", specification.launch_nonce),
                    pid: identity.pid,
                    creation_token: identity.creation_time_100ns.to_string(),
                    executable: identity.executable.clone(),
                    executable_sha256: identity.executable_sha256.clone(),
                    session_id: Some(identity.session_id),
                    started_at_ms: now_ms,
                };
                Ok((portable, proof))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn map_platform_observation(observation: &PlatformObservation) -> RuntimeObservation {
    match observation {
        PlatformObservation::Running(_) => RuntimeObservation::Running,
        PlatformObservation::Exited { code } => RuntimeObservation::Exited { code: *code },
        PlatformObservation::Missing => RuntimeObservation::Missing,
        PlatformObservation::IdentityMismatch => RuntimeObservation::IdentityMismatch,
        PlatformObservation::Ambiguous => RuntimeObservation::Ambiguous,
    }
}

#[cfg(target_os = "linux")]
fn map_stop_outcome(outcome: PlatformStopOutcome) -> RuntimeStopOutcome {
    match outcome {
        PlatformStopOutcome::Exited => RuntimeStopOutcome::Exited(None),
        PlatformStopOutcome::AlreadyExited => RuntimeStopOutcome::AlreadyExited,
        PlatformStopOutcome::TimedOut => RuntimeStopOutcome::TimedOut,
    }
}

#[cfg(target_os = "linux")]
pub(super) fn map_adapter_error(error: AdapterError) -> WatchdogError {
    match error {
        AdapterError::Invalid(message) => WatchdogError::InvalidInput(message),
        AdapterError::Unsupported(message) | AdapterError::Unavailable(message) => {
            WatchdogError::Unsupported(message)
        }
        AdapterError::IdentityMismatch(message) => WatchdogError::IdentityMismatch(message),
        AdapterError::Timeout(message) => WatchdogError::Timeout(message),
        AdapterError::Io(message) => WatchdogError::Io(std::io::Error::other(message)),
    }
}

#[cfg(windows)]
fn map_windows_error(error: ascension_platform_windows::PlatformError) -> WatchdogError {
    use ascension_platform_windows::PlatformError;
    match error {
        PlatformError::Invalid(message) => WatchdogError::InvalidInput(message),
        PlatformError::Unsupported(message) | PlatformError::Unavailable(message) => {
            WatchdogError::Unsupported(message)
        }
        PlatformError::IdentityMismatch(message) => WatchdogError::IdentityMismatch(message),
        PlatformError::Timeout(message) => WatchdogError::Timeout(message),
        PlatformError::Win32 { operation, code } => {
            WatchdogError::Unsupported(format!("{operation} failed with Win32 error {code}"))
        }
        PlatformError::Io(message) => WatchdogError::Io(std::io::Error::other(message)),
    }
}

#[cfg(windows)]
fn windows_component_kind(
    component: PlatformComponentKind,
) -> ascension_platform_windows::ComponentKind {
    match component {
        PlatformComponentKind::Gateway => ascension_platform_windows::ComponentKind::Gateway,
        PlatformComponentKind::Harness => ascension_platform_windows::ComponentKind::Harness,
        PlatformComponentKind::HostBroker => ascension_platform_windows::ComponentKind::HostBroker,
        PlatformComponentKind::Synthetic => ascension_platform_windows::ComponentKind::Synthetic,
    }
}

#[cfg(windows)]
fn windows_launch_spec(
    specification: &LaunchSpec,
) -> Result<ascension_platform_windows::WindowsLaunchSpec> {
    Ok(ascension_platform_windows::WindowsLaunchSpec {
        component: windows_component_kind(specification.component),
        executable: specification.executable.clone(),
        arguments: specification.arguments.clone(),
        environment: specification.environment.iter().cloned().collect(),
        working_directory: specification.working_directory.clone(),
        session: match specification.session {
            PlatformSessionSelector::ActiveUser => {
                ascension_platform_windows::SessionSelector::ActiveUser
            }
            PlatformSessionSelector::Explicit(session) => {
                ascension_platform_windows::SessionSelector::Explicit(session)
            }
        },
        launch_nonce: specification.launch_nonce.clone(),
        graceful_timeout_ms: u32::try_from(specification.graceful_timeout.as_millis())
            .map_err(|_| WatchdogError::InvalidInput("graceful timeout overflow".to_owned()))?,
        force_timeout_ms: u32::try_from(specification.force_timeout.as_millis())
            .map_err(|_| WatchdogError::InvalidInput("force timeout overflow".to_owned()))?,
    })
}

#[cfg(windows)]
fn windows_process_identity(
    proof: &OwnershipProof,
) -> Result<ascension_platform_windows::ProcessIdentity> {
    Ok(ascension_platform_windows::ProcessIdentity {
        pid: proof.pid,
        creation_time_100ns: proof.creation_token.parse::<u64>().map_err(|_| {
            WatchdogError::IdentityMismatch(
                "Windows creation token in launch proof is invalid".to_owned(),
            )
        })?,
        launch_nonce: proof.launch_nonce.clone(),
        executable: proof.executable.clone(),
        executable_sha256: proof.executable_sha256.clone(),
        session_id: proof.session_id.ok_or_else(|| {
            WatchdogError::IdentityMismatch(
                "Windows launch proof has no persisted session identity".to_owned(),
            )
        })?,
    })
}

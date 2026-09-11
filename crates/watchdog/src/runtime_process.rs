//! Process ownership for the durable watchdog runtime.
//!
//! Synthetic children are retained only for explicitly opted-in fixtures.
//! Production children are launched through the platform containment
//! authority and carry a bounded, versioned proof in the launch-intent row.

#[cfg(target_os = "linux")]
use crate::config::DesiredMode;
#[cfg(target_os = "linux")]
use crate::config::hex_digest;
use crate::config::{ComponentConfig, WatchdogConfig, validate_digest};
use crate::error::{Result, WatchdogError};
#[cfg(any(windows, test))]
use crate::platform::SessionSelector as PlatformSessionSelector;
#[cfg(target_os = "linux")]
use crate::platform::{
    AdapterError, ContainmentId, Observation as PlatformObservation, OwnedProcess, ProcessAdapter,
    ProcessCreation, ProcessIdentity as PlatformProcessIdentity,
    StopOutcome as PlatformStopOutcome,
};
use crate::platform::{ComponentKind as PlatformComponentKind, LaunchSpec};
use crate::process::{OutputSnapshot, OwnedChild, ProcessIdentity, ProcessSpawnError};
#[cfg(target_os = "linux")]
use crate::storage::Store;
use crate::storage::{LaunchIntent, LaunchIntentState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(target_os = "linux")]
use sha2::Digest;
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

const MAX_NATIVE_PROOF_BYTES: usize = 8 * 1024;
const NATIVE_MAX_PROCESSES: u32 = 64;
const NATIVE_GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const NATIVE_FORCE_TIMEOUT: Duration = Duration::from_secs(10);
const INCARNATION_PREFIX: &str = "watchdog-generation-";

/// A child together with the durable intent which admitted it.
pub(crate) struct RuntimeChild {
    portable_identity: ProcessIdentity,
    intent_id: String,
    ownership: OwnershipProof,
    worker_bootstrap_binding: Option<crate::storage::WorkerBootstrapBinding>,
    gateway_health_client: Option<crate::gateway_health::GatewayHealthClient>,
    handle: RuntimeChildHandle,
}

impl std::fmt::Debug for RuntimeChild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeChild")
            .field("portable_identity", &self.portable_identity)
            .field("intent_id", &self.intent_id)
            .field("backend", &self.ownership.backend)
            .finish_non_exhaustive()
    }
}

enum RuntimeChildHandle {
    Synthetic(OwnedChild),
    Native(NativeChild),
}

impl std::fmt::Debug for RuntimeChildHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synthetic(child) => formatter.debug_tuple("Synthetic").field(child).finish(),
            Self::Native(child) => formatter.debug_tuple("Native").field(child).finish(),
        }
    }
}

#[derive(Debug)]
enum NativeChild {
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
struct BrokerOwnedProcess {
    receipt: crate::platform::LaunchReceipt,
}

/// Closed proof tying a platform process authority to a launch intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnershipProof {
    version: u32,
    backend: String,
    intent_id: String,
    deployment_id: String,
    instance_id: String,
    component: String,
    incarnation: String,
    launch_nonce: String,
    containment_id: String,
    pid: u32,
    creation_token: String,
    executable: PathBuf,
    executable_sha256: String,
    session_id: Option<u32>,
    started_at_ms: u64,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeObservation {
    Running,
    Exited { code: Option<i32> },
    Missing,
    IdentityMismatch,
    Ambiguous,
}

#[derive(Debug)]
pub(crate) struct RuntimeProcessManager {
    synthetic: bool,
    backend: Option<NativeBackend>,
    #[cfg(test)]
    injected_stop_result: Option<std::result::Result<RuntimeStopOutcome, String>>,
}

#[derive(Debug)]
enum NativeBackend {
    #[cfg(target_os = "linux")]
    Linux(Box<crate::platform::LinuxProcessAdapter>),
    #[cfg(target_os = "linux")]
    LinuxBroker(crate::platform::BrokerClient),
    #[cfg(windows)]
    Windows(WindowsBackend),
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsBackend {
    launcher: ascension_platform_windows::WindowsProcessLauncher,
}

impl RuntimeProcessManager {
    pub(crate) fn new(config: &WatchdogConfig) -> Self {
        Self {
            synthetic: config.allow_synthetic_children,
            backend: None,
            #[cfg(test)]
            injected_stop_result: None,
        }
    }

    /// Inject one bounded stop result for the in-crate supervision regression
    /// tests. This hook is compiled out of production binaries so the runtime
    /// process manager always delegates to the real owned-child authority.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn inject_stop_result(
        &mut self,
        result: std::result::Result<RuntimeStopOutcome, String>,
    ) {
        self.injected_stop_result = Some(result);
    }

    pub(crate) fn ensure_ready(&mut self, config: &WatchdogConfig) -> Result<()> {
        if self.synthetic {
            return Ok(());
        }
        self.ensure_native(config).map(|_| ())
    }

    pub(crate) fn planned_containment(
        &mut self,
        config: &WatchdogConfig,
        specification: &LaunchSpec,
    ) -> Result<String> {
        if self.synthetic {
            return Ok(format!("synthetic-child:{}", specification.launch_nonce));
        }
        match self.ensure_native(config)? {
            #[cfg(target_os = "linux")]
            NativeBackend::Linux(_) => {
                crate::platform::LinuxProcessAdapter::planned_containment_for(specification)
                    .map(|id| id.as_str().to_owned())
                    .map_err(map_adapter_error)
            }
            #[cfg(target_os = "linux")]
            NativeBackend::LinuxBroker(_) => broker_planned_containment_for(specification),
            #[cfg(windows)]
            NativeBackend::Windows(_) => Ok(format!("windows-job:{}", specification.launch_nonce)),
        }
    }

    pub(crate) fn launch(
        &mut self,
        config: &WatchdogConfig,
        component: &ComponentConfig,
        specification: &LaunchSpec,
        planned_containment: &str,
        intent_id: &str,
        now_ms: u64,
        worker: Option<&crate::worker_bootstrap::WorkerBootstrapLaunch>,
        gateway_health: Option<&crate::platform::gateway_health::GatewayHealthBootstrap>,
        watchdog_boot_id: &str,
    ) -> std::result::Result<RuntimeChild, RuntimeLaunchError> {
        if worker.is_some() && gateway_health.is_some() {
            return Err(RuntimeLaunchError::Ordinary(WatchdogError::InvalidInput(
                "worker and gateway health bootstraps are mutually exclusive".to_owned(),
            )));
        }
        if self.synthetic {
            if worker.is_some() || gateway_health.is_some() {
                return Err(RuntimeLaunchError::Ordinary(WatchdogError::InvalidInput(
                    "synthetic launcher cannot consume native worker bootstrap".to_owned(),
                )));
            }
            preflight_synthetic_proof_budget(intent_id, specification, planned_containment)
                .map_err(RuntimeLaunchError::Ordinary)?;
            let child = OwnedChild::spawn_with_cleanup_status(component, now_ms)
                .map_err(RuntimeLaunchError::from)?;
            let mut portable_identity = child.identity().clone();
            portable_identity
                .launch_nonce
                .clone_from(&specification.launch_nonce);
            let ownership = OwnershipProof::synthetic(
                intent_id,
                specification,
                planned_containment,
                &portable_identity,
            )
            // The process already exists at this point.  A proof-size failure
            // therefore keeps the launch intent unsettled until exact
            // containment is reconciled instead of becoming an ordinary
            // rejected launch.
            .map_err(RuntimeLaunchError::CleanupUncertain)?;
            return Ok(RuntimeChild {
                portable_identity,
                intent_id: intent_id.to_owned(),
                ownership,
                worker_bootstrap_binding: None,
                gateway_health_client: None,
                handle: RuntimeChildHandle::Synthetic(child),
            });
        }
        let native = self
            .ensure_native(config)
            .map_err(RuntimeLaunchError::Ordinary)?
            .launch(
                config,
                specification,
                planned_containment,
                worker,
                gateway_health,
                watchdog_boot_id,
            )?;
        let mut child = self.finish_native_launch(native, |native| {
            native.identity(intent_id, specification, planned_containment, now_ms)
        })?;
        child.worker_bootstrap_binding =
            worker.map(|worker| crate::storage::WorkerBootstrapBinding {
                watchdog_boot_id: worker.bootstrap().watchdog_boot_id.to_string(),
                frame_sha256: worker.frame_sha256().to_owned(),
            });
        Ok(child)
    }

    fn finish_native_launch<F>(
        &mut self,
        mut native: NativeChild,
        identify: F,
    ) -> std::result::Result<RuntimeChild, RuntimeLaunchError>
    where
        F: FnOnce(&NativeChild) -> Result<(ProcessIdentity, OwnershipProof)>,
    {
        let (portable_identity, ownership) = match identify(&native) {
            Ok(value) => value,
            Err(identity_error) => {
                let cleanup = self.backend.as_mut().map_or_else(
                    || {
                        Err(WatchdogError::Conflict(
                            "native process backend disappeared while proving launch cleanup"
                                .to_owned(),
                        ))
                    },
                    |backend| backend.stop(&mut native),
                );
                return Err(classify_native_identity_failure(identity_error, cleanup));
            }
        };
        Ok(RuntimeChild {
            portable_identity,
            intent_id: ownership.intent_id.clone(),
            ownership,
            worker_bootstrap_binding: None,
            gateway_health_client: None,
            handle: RuntimeChildHandle::Native(native),
        })
    }

    /// Reconcile a prepared launch intent by its exact planned platform
    /// containment.  A prepared intent has no process identity, so callers
    /// must never attempt PID-based cleanup or invent a replacement child.
    pub(crate) fn cleanup_planned_containment(
        &mut self,
        config: &WatchdogConfig,
        planned_containment: &str,
    ) -> Result<RuntimeStopOutcome> {
        if self.synthetic {
            return Err(WatchdogError::Unsupported(
                "synthetic launch intents have no recoverable containment authority".to_owned(),
            ));
        }
        self.ensure_native(config)?
            .force_cleanup_planned_containment(planned_containment)
    }

    pub(crate) fn recover_intent(
        &mut self,
        config: &WatchdogConfig,
        intent: &LaunchIntent,
    ) -> Result<Option<RuntimeChild>> {
        if intent.state == LaunchIntentState::Prepared {
            return Ok(None);
        }
        let proof_value = intent.ownership_proof_json.as_ref().ok_or_else(|| {
            WatchdogError::Conflict(format!(
                "launch intent {} is {:?} without an ownership proof",
                intent.id, intent.state
            ))
        })?;
        if serde_json::to_vec(proof_value)?.len() > MAX_NATIVE_PROOF_BYTES {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof exceeds runtime bound".to_owned(),
            ));
        }
        let proof: OwnershipProof = serde_json::from_value(proof_value.clone())?;
        if proof.backend == "synthetic" && !self.synthetic {
            return Err(WatchdogError::Unsupported(
                "synthetic launch proof cannot be recovered by the native authority".to_owned(),
            ));
        }
        if proof.backend == "synthetic" {
            if proof.version != 1
                || proof.intent_id != intent.id
                || proof.deployment_id != intent.deployment_id
                || proof.component != intent.component_id
                || proof.launch_nonce != intent.launch_nonce
            {
                return Err(WatchdogError::IdentityMismatch(
                    "synthetic launch proof is not bound to its durable intent".to_owned(),
                ));
            }
            return Ok(None);
        }
        #[cfg(target_os = "linux")]
        if proof.backend != "linux" {
            return Err(WatchdogError::Unsupported(
                "a non-Linux launch proof cannot be adopted by the Linux authority".to_owned(),
            ));
        }
        #[cfg(windows)]
        if proof.backend != "windows" {
            return Err(WatchdogError::Unsupported(
                "a non-Windows launch proof cannot be adopted by the Windows authority".to_owned(),
            ));
        }
        validate_proof(config, intent, &proof)?;
        if self.synthetic {
            return Err(WatchdogError::Conflict(
                "native launch proof cannot be recovered in synthetic mode".to_owned(),
            ));
        }
        let native = self.ensure_native(config)?.reopen(&proof)?;
        Ok(Some(RuntimeChild {
            portable_identity: proof.portable_identity(),
            intent_id: intent.id.clone(),
            ownership: proof,
            worker_bootstrap_binding: None,
            gateway_health_client: None,
            handle: RuntimeChildHandle::Native(native),
        }))
    }

    pub(crate) fn inspect(&mut self, child: &mut RuntimeChild) -> Result<RuntimeObservation> {
        match &mut child.handle {
            RuntimeChildHandle::Synthetic(process) => match process.try_wait()? {
                Some(status) => Ok(RuntimeObservation::Exited {
                    code: status.code(),
                }),
                None => Ok(RuntimeObservation::Running),
            },
            RuntimeChildHandle::Native(native) => self
                .backend
                .as_mut()
                .ok_or_else(|| {
                    WatchdogError::Conflict("native process backend was not initialized".to_owned())
                })?
                .inspect(native),
        }
    }

    pub(crate) fn stop(&mut self, child: &mut RuntimeChild) -> Result<RuntimeStopOutcome> {
        #[cfg(test)]
        if let Some(result) = self.injected_stop_result.take() {
            return result.map_err(WatchdogError::Conflict);
        }
        match &mut child.handle {
            RuntimeChildHandle::Synthetic(process) => {
                let status = process.terminate(NATIVE_GRACEFUL_TIMEOUT)?;
                Ok(RuntimeStopOutcome::Exited(status.code()))
            }
            RuntimeChildHandle::Native(native) => self
                .backend
                .as_mut()
                .ok_or_else(|| {
                    WatchdogError::Conflict("native process backend was not initialized".to_owned())
                })?
                .stop(native),
        }
    }

    pub(crate) fn ownership_proof(child: &RuntimeChild) -> Result<Value> {
        let value = serde_json::to_value(&child.ownership)?;
        if serde_json::to_vec(&value)?.len() > MAX_NATIVE_PROOF_BYTES {
            return Err(WatchdogError::InvalidInput(
                "launch ownership proof exceeds runtime bound".to_owned(),
            ));
        }
        Ok(value)
    }

    pub(crate) fn probe_gateway_health(
        &mut self,
        child: &mut RuntimeChild,
    ) -> std::result::Result<
        crate::gateway_health::GatewayHealthStatus,
        crate::gateway_health::HealthError,
    > {
        use crate::gateway_health::HealthError;
        if !child.is_native() {
            return Err(HealthError::Identity);
        }
        let expected = child.identity().clone();
        let mut client = child
            .gateway_health_client
            .take()
            .ok_or(HealthError::Configuration)?;
        let result = client.probe(|| {
            if child.identity() != &expected
                || !matches!(self.inspect(child), Ok(RuntimeObservation::Running))
            {
                return Err(HealthError::Identity);
            }
            Ok(())
        });
        // Failed exchanges retain their consumed sequence. Never reconstruct a
        // client with sequence zero for a surviving launch key.
        child.gateway_health_client = Some(client);
        result
    }
}

impl RuntimeChild {
    pub(crate) fn set_gateway_health_client(
        &mut self,
        client: Option<crate::gateway_health::GatewayHealthClient>,
    ) {
        self.gateway_health_client = client;
    }
    pub(crate) fn worker_bootstrap_binding(
        &self,
    ) -> Option<&crate::storage::WorkerBootstrapBinding> {
        self.worker_bootstrap_binding.as_ref()
    }
    #[cfg(windows)]
    pub(crate) fn worker_account_identity(&self) -> Result<(String, u32)> {
        match &self.handle {
            RuntimeChildHandle::Native(NativeChild::Windows(process)) => process
                .account_identity()
                .map_err(|error| WatchdogError::IdentityMismatch(error.to_string())),
            RuntimeChildHandle::Synthetic(_) => Err(WatchdogError::IdentityMismatch(
                "Windows worker requires a native owned account identity".to_owned(),
            )),
        }
    }

    pub(crate) fn identity(&self) -> &ProcessIdentity {
        &self.portable_identity
    }

    pub(crate) fn intent_id(&self) -> &str {
        &self.intent_id
    }

    pub(crate) fn is_native(&self) -> bool {
        matches!(&self.handle, RuntimeChildHandle::Native(_))
    }

    pub(crate) fn output(&self) -> OutputSnapshot {
        match &self.handle {
            RuntimeChildHandle::Synthetic(process) => process.output(),
            RuntimeChildHandle::Native(_) => OutputSnapshot {
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
        }
    }

    /// Native platform launchers currently use null standard streams and the
    /// platform-owned child handle does not expose a drain API.  Keep this
    /// explicit so an empty snapshot is never reported as captured output.
    pub(crate) fn captures_output(&self) -> bool {
        matches!(&self.handle, RuntimeChildHandle::Synthetic(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStopOutcome {
    Exited(Option<i32>),
    AlreadyExited,
    TimedOut,
}

/// Launch admission failure classification. A Linux uncertain-cleanup
/// failure means the platform retained a planned containment authority even
/// though no child handle was returned; the durable intent must remain
/// unsettled until that exact containment is reconciled.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum RuntimeLaunchError {
    Ordinary(WatchdogError),
    CleanupUncertain(WatchdogError),
}

impl From<ProcessSpawnError> for RuntimeLaunchError {
    fn from(error: ProcessSpawnError) -> Self {
        match error {
            ProcessSpawnError::Ordinary(error) => Self::Ordinary(error),
            ProcessSpawnError::CleanupUncertain(error) => Self::CleanupUncertain(error),
        }
    }
}

impl std::fmt::Display for RuntimeLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary(error) | Self::CleanupUncertain(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RuntimeLaunchError {}

fn classify_native_identity_failure(
    identity_error: WatchdogError,
    cleanup: Result<RuntimeStopOutcome>,
) -> RuntimeLaunchError {
    match cleanup {
        Ok(RuntimeStopOutcome::Exited(_) | RuntimeStopOutcome::AlreadyExited) => {
            RuntimeLaunchError::Ordinary(identity_error)
        }
        Ok(RuntimeStopOutcome::TimedOut) => {
            RuntimeLaunchError::CleanupUncertain(WatchdogError::Conflict(format!(
                "native launch identity proof failed ({identity_error}); exact native cleanup timed out"
            )))
        }
        Err(cleanup_error) => {
            RuntimeLaunchError::CleanupUncertain(WatchdogError::Conflict(format!(
                "native launch identity proof failed ({identity_error}); exact native cleanup failed: {cleanup_error}"
            )))
        }
    }
}

impl RuntimeProcessManager {
    fn ensure_native(&mut self, config: &WatchdogConfig) -> Result<&mut NativeBackend> {
        if self.backend.is_none() {
            self.backend = Some(NativeBackend::create(config)?);
        }
        self.backend.as_mut().ok_or_else(|| {
            WatchdogError::Conflict("native process backend was not initialized".to_owned())
        })
    }
}

impl NativeBackend {
    #[allow(clippy::needless_return)]
    fn create(config: &WatchdogConfig) -> Result<Self> {
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

    fn launch(
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
                            super::runtime_worker_admission::authorize(
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
                                super::runtime_gateway_health_admission::authorize_windows(
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

    fn force_cleanup_planned_containment(
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

    fn reopen(&mut self, proof: &OwnershipProof) -> Result<NativeChild> {
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

    fn inspect(&mut self, child: &mut NativeChild) -> Result<RuntimeObservation> {
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

    fn stop(&mut self, child: &mut NativeChild) -> Result<RuntimeStopOutcome> {
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
    fn identity(
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

impl OwnershipProof {
    #[cfg(target_os = "linux")]
    fn from_platform(
        backend: &str,
        intent_id: &str,
        specification: &LaunchSpec,
        planned_containment: &str,
        identity: &PlatformProcessIdentity,
        now_ms: u64,
    ) -> Result<Self> {
        let proof = Self {
            version: 1,
            backend: backend.to_owned(),
            intent_id: intent_id.to_owned(),
            deployment_id: identity.deployment_id.clone(),
            instance_id: identity.instance_id.clone(),
            component: specification.instance_id.clone(),
            incarnation: identity.incarnation.clone(),
            launch_nonce: identity.launch_nonce.clone(),
            containment_id: planned_containment.to_owned(),
            pid: identity.creation.pid,
            creation_token: identity.creation.token.clone(),
            executable: identity.executable.clone(),
            executable_sha256: identity.executable_sha256.clone(),
            session_id: identity.session,
            started_at_ms: now_ms,
        };
        if proof.deployment_id != specification.deployment_id
            || proof.instance_id != specification.instance_id
            || proof.launch_nonce != specification.launch_nonce
            || proof.containment_id != identity.containment.as_str()
        {
            return Err(WatchdogError::IdentityMismatch(
                "platform returned an identity different from the launch request".to_owned(),
            ));
        }
        bound_proof(proof)
    }

    #[cfg(target_os = "linux")]
    fn from_broker_receipt(
        backend: &str,
        intent_id: &str,
        specification: &LaunchSpec,
        planned_containment: &str,
        receipt: &crate::platform::LaunchReceipt,
        now_ms: u64,
    ) -> Result<Self> {
        verify_broker_receipt(specification, planned_containment, receipt)?;
        let proof = Self {
            version: 1,
            backend: backend.to_owned(),
            intent_id: intent_id.to_owned(),
            deployment_id: specification.deployment_id.clone(),
            instance_id: specification.instance_id.clone(),
            component: specification.instance_id.clone(),
            incarnation: specification.incarnation.clone(),
            launch_nonce: specification.launch_nonce.clone(),
            containment_id: planned_containment.to_owned(),
            pid: receipt.pid,
            creation_token: receipt.creation_token.clone(),
            executable: receipt.executable.clone(),
            executable_sha256: receipt.executable_sha256.clone(),
            session_id: None,
            started_at_ms: now_ms,
        };
        bound_proof(proof)
    }

    fn synthetic(
        intent_id: &str,
        specification: &LaunchSpec,
        planned_containment: &str,
        portable: &ProcessIdentity,
    ) -> Result<Self> {
        bound_proof(Self {
            version: 1,
            backend: "synthetic".to_owned(),
            intent_id: intent_id.to_owned(),
            deployment_id: specification.deployment_id.clone(),
            instance_id: specification.instance_id.clone(),
            component: specification.instance_id.clone(),
            incarnation: specification.incarnation.clone(),
            launch_nonce: specification.launch_nonce.clone(),
            containment_id: planned_containment.to_owned(),
            pid: portable.pid,
            creation_token: portable
                .creation_fingerprint
                .clone()
                .unwrap_or_else(|| format!("synthetic:{}", portable.pid)),
            executable: portable.executable.clone(),
            executable_sha256: portable.executable_digest.clone(),
            session_id: None,
            started_at_ms: portable.started_at_ms,
        })
    }

    fn portable_identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            launch_nonce: self.launch_nonce.clone(),
            executable: self.executable.clone(),
            executable_digest: self.executable_sha256.clone(),
            started_at_ms: self.started_at_ms,
            creation_fingerprint: Some(self.creation_token.clone()),
        }
    }
}

fn bound_proof(proof: OwnershipProof) -> Result<OwnershipProof> {
    if serde_json::to_vec(&proof)?.len() > MAX_NATIVE_PROOF_BYTES {
        return Err(WatchdogError::InvalidInput(
            "launch ownership proof exceeds runtime bound".to_owned(),
        ));
    }
    Ok(proof)
}

/// Check the synthetic proof envelope before creating a child.  The runtime
/// still repeats the real check after spawn because the child identity is part
/// of the persisted proof; that second failure is classified as cleanup
/// uncertainty by the caller.
fn preflight_synthetic_proof_budget(
    intent_id: &str,
    specification: &LaunchSpec,
    planned_containment: &str,
) -> Result<()> {
    // The real synthetic identity is produced only after the child exists.
    // Use the largest scalar identity values here so a proof that can pass
    // this preflight cannot become oversized merely because the OS selected a
    // larger PID, creation token, or timestamp.  The executable is resolved
    // with the same canonicalization used by the child launcher when possible;
    // retaining the requested path on lookup failure still lets this check
    // reject an oversized request before process creation.
    let executable = std::fs::canonicalize(&specification.executable)
        .unwrap_or_else(|_| specification.executable.clone());
    let portable = ProcessIdentity {
        pid: u32::MAX,
        launch_nonce: specification.launch_nonce.clone(),
        executable,
        executable_digest: specification.executable_sha256.clone(),
        started_at_ms: u64::MAX,
        // Linux's /proc start time is an unsigned 64-bit decimal value; the
        // non-Linux fallback is shorter. Twenty decimal digits therefore
        // conservatively cover either identity source.
        creation_fingerprint: Some("9".repeat(20)),
    };
    OwnershipProof::synthetic(intent_id, specification, planned_containment, &portable).map(|_| ())
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
fn map_adapter_error(error: AdapterError) -> WatchdogError {
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

#[cfg(target_os = "linux")]
const BROKER_CONTAINMENT_PREFIX: &str = "linux-broker-v1";

#[cfg(target_os = "linux")]
fn map_broker_error(error: crate::platform::linux_broker::BrokerError) -> WatchdogError {
    use crate::platform::linux_broker::BrokerError;
    match error {
        BrokerError::Invalid(message) => WatchdogError::InvalidInput(message),
        BrokerError::Unauthorized(message) => WatchdogError::Unauthorized(message),
        BrokerError::Conflict(message) => WatchdogError::Conflict(message),
        BrokerError::Unavailable(message) => WatchdogError::Unsupported(message),
        BrokerError::Io(message) => WatchdogError::Io(std::io::Error::other(message)),
    }
}

#[cfg(target_os = "linux")]
fn map_broker_bootstrap_launch_error(
    error: crate::platform::linux_broker::BrokerBootstrapLaunchError,
) -> RuntimeLaunchError {
    use crate::platform::linux_broker::BrokerBootstrapLaunchError;
    match error {
        BrokerBootstrapLaunchError::NotDispatched(error) => {
            RuntimeLaunchError::Ordinary(map_broker_error(error))
        }
        BrokerBootstrapLaunchError::Unknown(error) => {
            RuntimeLaunchError::CleanupUncertain(map_broker_error(error))
        }
    }
}

#[cfg(target_os = "linux")]
fn broker_component(component: PlatformComponentKind) -> crate::platform::BrokerComponent {
    match component {
        PlatformComponentKind::Gateway => crate::platform::BrokerComponent::Gateway,
        PlatformComponentKind::Harness => crate::platform::BrokerComponent::Harness,
        PlatformComponentKind::HostBroker => crate::platform::BrokerComponent::HostBroker,
        PlatformComponentKind::Synthetic => crate::platform::BrokerComponent::Synthetic,
    }
}

#[cfg(target_os = "linux")]
fn broker_component_name(component: crate::platform::BrokerComponent) -> &'static str {
    match component {
        crate::platform::BrokerComponent::Gateway => "gateway",
        crate::platform::BrokerComponent::Harness => "harness",
        crate::platform::BrokerComponent::HostBroker => "hostbroker",
        crate::platform::BrokerComponent::Synthetic => "synthetic",
    }
}

#[cfg(target_os = "linux")]
fn broker_component_from_name(value: &str) -> Result<crate::platform::BrokerComponent> {
    match value {
        "gateway" => Ok(crate::platform::BrokerComponent::Gateway),
        "harness" => Ok(crate::platform::BrokerComponent::Harness),
        "hostbroker" => Ok(crate::platform::BrokerComponent::HostBroker),
        "synthetic" => Ok(crate::platform::BrokerComponent::Synthetic),
        _ => Err(WatchdogError::InvalidInput(
            "Linux broker containment has an unsupported component".to_owned(),
        )),
    }
}

#[cfg(target_os = "linux")]
fn valid_broker_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(target_os = "linux")]
fn validate_broker_request(request: &crate::platform::BrokerRequest) -> Result<()> {
    if !valid_broker_identity(&request.instance)
        || !valid_broker_identity(&request.incarnation)
        || !valid_broker_identity(&request.nonce)
    {
        return Err(WatchdogError::InvalidInput(
            "Linux broker request identity is outside its bounded contract".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn broker_request_for(specification: &LaunchSpec) -> Result<crate::platform::BrokerRequest> {
    specification
        .validate()
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    let request = crate::platform::BrokerRequest {
        component: broker_component(specification.component),
        instance: specification.instance_id.clone(),
        incarnation: specification.incarnation.clone(),
        nonce: specification.launch_nonce.clone(),
    };
    validate_broker_request(&request)?;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn broker_unit_name(request: &crate::platform::BrokerRequest) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(broker_component_name(request.component).as_bytes());
    hasher.update([0]);
    hasher.update(request.instance.as_bytes());
    hasher.update([0]);
    hasher.update(request.incarnation.as_bytes());
    hasher.update([0]);
    hasher.update(request.nonce.as_bytes());
    let digest = hasher.finalize();
    format!(
        "ascension-watchdog-{}-{}.service",
        broker_component_name(request.component),
        &hex_digest(&digest)[..24]
    )
}

#[cfg(target_os = "linux")]
fn broker_planned_containment_for(specification: &LaunchSpec) -> Result<String> {
    let request = broker_request_for(specification)?;
    broker_planned_containment_for_request(&request)
}

#[cfg(target_os = "linux")]
fn broker_planned_containment_for_request(
    request: &crate::platform::BrokerRequest,
) -> Result<String> {
    validate_broker_request(request)?;
    let value = format!(
        "{BROKER_CONTAINMENT_PREFIX}:{}:{}:{}:{}",
        broker_component_name(request.component),
        request.instance,
        request.incarnation,
        request.nonce
    );
    if value.len() > 512 {
        return Err(WatchdogError::InvalidInput(
            "Linux broker containment identity exceeds its bound".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn broker_request_from_planned_containment(value: &str) -> Result<crate::platform::BrokerRequest> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != BROKER_CONTAINMENT_PREFIX {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker planned containment is not a complete request identity".to_owned(),
        ));
    }
    let request = crate::platform::BrokerRequest {
        component: broker_component_from_name(parts[1])?,
        instance: parts[2].to_owned(),
        incarnation: parts[3].to_owned(),
        nonce: parts[4].to_owned(),
    };
    if broker_planned_containment_for_request(&request)?.as_str() != value {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker planned containment does not round-trip its request".to_owned(),
        ));
    }
    Ok(request)
}

#[cfg(target_os = "linux")]
fn broker_request_from_proof(proof: &OwnershipProof) -> Result<crate::platform::BrokerRequest> {
    let request = crate::platform::BrokerRequest {
        component: broker_component(platform_component_kind(&proof.component)?),
        instance: proof.instance_id.clone(),
        incarnation: proof.incarnation.clone(),
        nonce: proof.launch_nonce.clone(),
    };
    let planned = broker_planned_containment_for_request(&request)?;
    if proof.containment_id != planned {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker proof containment does not match its request".to_owned(),
        ));
    }
    Ok(request)
}

#[cfg(target_os = "linux")]
fn verify_broker_receipt(
    specification: &LaunchSpec,
    planned_containment: &str,
    receipt: &crate::platform::LaunchReceipt,
) -> Result<()> {
    let request = broker_request_for(specification)?;
    if planned_containment != broker_planned_containment_for_request(&request)? {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker planned containment differs from its launch request".to_owned(),
        ));
    }
    verify_broker_receipt_request(&request, receipt)?;
    let executable_matches = receipt.executable == specification.executable
        || std::fs::canonicalize(&receipt.executable)
            .ok()
            .zip(std::fs::canonicalize(&specification.executable).ok())
            .is_some_and(|(actual, expected)| actual == expected);
    if !executable_matches || receipt.executable_sha256 != specification.executable_sha256 {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker receipt executable differs from the launch specification".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_broker_receipt_request(
    request: &crate::platform::BrokerRequest,
    receipt: &crate::platform::LaunchReceipt,
) -> Result<()> {
    let expected_unit = broker_unit_name(request);
    if receipt.request != *request
        || receipt.unit != expected_unit
        || receipt.pid == 0
        || receipt.creation_token.is_empty()
        || !receipt.executable.is_absolute()
        || validate_digest(&receipt.executable_sha256).is_err()
        || receipt.uid == 0
        || receipt.gid == 0
        || receipt.capability_bounding_set != 0
        || receipt.ambient_capabilities != 0
        || !receipt
            .control_group
            .ends_with(&format!("/{expected_unit}"))
    {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker receipt does not correlate to the exact request".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_broker_receipt_against_proof(
    receipt: &crate::platform::LaunchReceipt,
    proof: &OwnershipProof,
) -> Result<()> {
    let request = broker_request_from_proof(proof)?;
    verify_broker_receipt_request(&request, receipt)?;
    if receipt.pid != proof.pid
        || receipt.creation_token != proof.creation_token
        || receipt.executable != proof.executable
        || receipt.executable_sha256 != proof.executable_sha256
    {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker recovery receipt differs from the persisted process proof".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_broker_receipt_binding(
    actual: &crate::platform::LaunchReceipt,
    expected: &crate::platform::LaunchReceipt,
) -> Result<()> {
    verify_broker_receipt_request(&expected.request, actual)?;
    if actual.pid != expected.pid
        || actual.creation_token != expected.creation_token
        || actual.executable != expected.executable
        || actual.executable_sha256 != expected.executable_sha256
        || actual.uid != expected.uid
        || actual.gid != expected.gid
        || actual.capability_bounding_set != expected.capability_bounding_set
        || actual.ambient_capabilities != expected.ambient_capabilities
        || actual.control_group != expected.control_group
    {
        return Err(WatchdogError::IdentityMismatch(
            "Linux broker lifecycle receipt changed its process binding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_proof(
    config: &WatchdogConfig,
    intent: &LaunchIntent,
    proof: &OwnershipProof,
) -> Result<()> {
    if proof.version != 1
        || proof.intent_id != intent.id
        || proof.deployment_id != intent.deployment_id
        || proof.component != intent.component_id
        || proof.launch_nonce != intent.launch_nonce
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof is not bound to its durable intent".to_owned(),
        ));
    }
    let planned = intent.planned_containment_id.as_deref().ok_or_else(|| {
        WatchdogError::Conflict(
            "launch intent has no planned containment for proof recovery".to_owned(),
        )
    })?;
    if planned != proof.containment_id
        && !(proof.backend == "windows" && planned == format!("windows-job:{}", proof.launch_nonce))
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof containment differs from durable intent".to_owned(),
        ));
    }
    if proof.pid == 0
        || proof.creation_token.is_empty()
        || !proof.executable.is_absolute()
        || validate_digest(&proof.executable_sha256).is_err()
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof identity is incomplete".to_owned(),
        ));
    }
    if proof.backend != "synthetic" && !matches!(proof.backend.as_str(), "linux" | "windows") {
        return Err(WatchdogError::Unsupported(
            "launch ownership proof backend is unsupported".to_owned(),
        ));
    }
    let component = config
        .components
        .iter()
        .find(|component| component.id == proof.component)
        .ok_or_else(|| WatchdogError::Conflict("proof component is not configured".to_owned()))?;
    let expected_path = std::fs::canonicalize(&component.executable).map_err(|error| {
        WatchdogError::IdentityMismatch(format!(
            "approved executable cannot be resolved during proof recovery: {error}"
        ))
    })?;
    let expected_digest = component.executable_sha256.as_deref().ok_or_else(|| {
        WatchdogError::Unsupported("proof component has no approved executable digest".to_owned())
    })?;
    if proof.instance_id != component.id
        || proof.executable != expected_path
        || expected_digest != proof.executable_sha256
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof differs from approved component bytes".to_owned(),
        ));
    }
    if proof.incarnation.is_empty() {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof has no incarnation".to_owned(),
        ));
    }
    // The incarnation is part of the platform containment derivation.  A
    // proof that merely has a plausible-looking generation string is not
    // enough: rebuild the complete launch request and require the persisted
    // containment identity to be the one derived from that request.  This
    // prevents a proof from being rebound to another generation or nonce.
    let specification = super::launch_spec_for(
        config,
        component,
        intent.launch_nonce.clone(),
        proof.incarnation.clone(),
    )?;
    let expected_containment = expected_containment_for(config, &specification)?;
    if expected_containment != proof.containment_id {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof containment is not derived from its incarnation and request"
                .to_owned(),
        ));
    }
    if proof.backend == "linux" && proof.session_id.is_some() {
        return Err(WatchdogError::IdentityMismatch(
            "Linux launch proof unexpectedly contains a session identity".to_owned(),
        ));
    }
    if proof.backend == "windows" && proof.session_id != Some(0) {
        return Err(WatchdogError::IdentityMismatch(
            "Windows service launch proof is not bound to session zero".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn expected_containment_for(config: &WatchdogConfig, specification: &LaunchSpec) -> Result<String> {
    if config.linux_broker.is_some() {
        return broker_planned_containment_for(specification);
    }
    crate::platform::LinuxProcessAdapter::planned_containment_for(specification)
        .map(|containment| containment.as_str().to_owned())
        .map_err(map_adapter_error)
}

#[cfg(windows)]
fn expected_containment_for(
    _config: &WatchdogConfig,
    specification: &LaunchSpec,
) -> Result<String> {
    specification
        .validate()
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    Ok(format!("windows-job:{}", specification.launch_nonce))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn expected_containment_for(
    _config: &WatchdogConfig,
    _specification: &LaunchSpec,
) -> Result<String> {
    Err(WatchdogError::Unsupported(
        "native process containment is unsupported on this platform".to_owned(),
    ))
}

fn component_kind(component: &ComponentConfig) -> Result<PlatformComponentKind> {
    platform_component_kind(&component.id)
}

pub(crate) fn platform_component_kind(value: &str) -> Result<PlatformComponentKind> {
    match value {
        "gateway" => Ok(PlatformComponentKind::Gateway),
        "harness" => Ok(PlatformComponentKind::Harness),
        "host-broker" | "host_broker" => Ok(PlatformComponentKind::HostBroker),
        "synthetic" => Ok(PlatformComponentKind::Synthetic),
        _ => Err(WatchdogError::InvalidInput(format!(
            "component role {value} is not supported by the native authority"
        ))),
    }
}

fn native_allowlist(
    config: &WatchdogConfig,
) -> Result<BTreeMap<PlatformComponentKind, (PathBuf, String)>> {
    let mut allowlist = BTreeMap::new();
    for component in &config.components {
        let kind = component_kind(component)?;
        let digest = component.executable_sha256.clone().ok_or_else(|| {
            WatchdogError::InvalidInput(format!(
                "native component {} requires an approved executable hash",
                component.id
            ))
        })?;
        if allowlist
            .insert(kind, (component.executable.clone(), digest))
            .is_some()
        {
            return Err(WatchdogError::Conflict(format!(
                "native role {kind:?} has multiple executable allowlist entries"
            )));
        }
    }
    if allowlist.is_empty() {
        return Err(WatchdogError::Unsupported(
            "native process authority has no approved component roles".to_owned(),
        ));
    }
    Ok(allowlist)
}

/// Stable incarnation shared by launch construction and helper authorization.
pub(crate) fn runtime_incarnation(restart_generation: i64) -> Result<String> {
    if restart_generation <= 0 {
        return Err(WatchdogError::Conflict(
            "restart generation must be positive before native launch".to_owned(),
        ));
    }
    Ok(format!("{INCARNATION_PREFIX}{restart_generation}"))
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

#[cfg(target_os = "linux")]
pub fn run_linux_helper_if_requested() -> Result<Option<i32>> {
    crate::platform::linux_launcher::run_hidden_helper_if_requested_with_health_authorizer(
        authorize_linux_helper_with_health,
    )
    .map_err(map_adapter_error)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub fn run_linux_helper_if_requested() -> Result<Option<i32>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn authorize_linux_helper_with_health(
    request: &crate::platform::LinuxHelperRequest,
    bootstrap: &crate::platform::LinuxHelperBootstrap,
    observed_health: Option<&crate::platform::gateway_health::GatewayHealthFrameBinding>,
) -> std::result::Result<(crate::platform::LinuxHelperAuthorization, Store), AdapterError> {
    let config = protected_config_from_bootstrap(bootstrap)?;
    // Serialize durable Stop with target exec just as Windows admission holds
    // its reservation through ResumeThread. This is a read-only transaction
    // in terms of row effects, but it intentionally reserves the writer slot.
    let store = Store::open(&config.database, &config)
        .and_then(Store::reserve_launch_admission)
        .map_err(watchdog_to_adapter_error)?;
    let status = store.status().map_err(watchdog_to_adapter_error)?;
    if status.desired_mode != DesiredMode::Running {
        return Err(AdapterError::Unavailable(
            "durable running intent was revoked before Linux helper release".to_owned(),
        ));
    }
    let expected_incarnation =
        runtime_incarnation(status.restart_generation).map_err(watchdog_to_adapter_error)?;
    let component = config
        .components
        .iter()
        .find(|component| {
            component.id == request.specification.instance_id
                && component_kind(component)
                    .map(|kind| kind == request.specification.component)
                    .unwrap_or(false)
        })
        .ok_or_else(|| {
            AdapterError::IdentityMismatch(
                "Linux helper component is not in the protected configuration".to_owned(),
            )
        })?;
    component.executable_sha256.as_deref().ok_or_else(|| {
        AdapterError::Unsupported(
            "Linux helper component has no approved executable digest".to_owned(),
        )
    })?;
    let expected = super::launch_spec_for(
        &config,
        component,
        request.specification.launch_nonce.clone(),
        expected_incarnation,
    )
    .map_err(watchdog_to_adapter_error)?;
    if request.specification != expected {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper request differs from protected component configuration".to_owned(),
        ));
    }
    let planned = crate::platform::LinuxProcessAdapter::planned_containment_for(&expected)?;
    let health_required = config
        .gateway_health
        .as_ref()
        .is_some_and(|health| health.component_id == component.id);
    match (health_required, observed_health) {
        (true, Some(observed)) => {
            super::runtime_gateway_health_admission::authorize_stored(
                &config,
                &store,
                &expected,
                planned.as_str(),
                observed,
                None,
            )
            .map_err(watchdog_to_adapter_error)?;
        }
        (false, None) => {}
        _ => {
            return Err(AdapterError::IdentityMismatch(
                "gateway health pipe presence differs from approved configuration".to_owned(),
            ));
        }
    }
    let intents = store
        .unsettled_launch_intents()
        .map_err(watchdog_to_adapter_error)?;
    let matches = intents
        .iter()
        .filter(|intent| {
            intent.deployment_id == status.deployment_id
                && intent.component_id == component.id
                && intent.launch_nonce == request.specification.launch_nonce
                && intent.planned_containment_id.as_deref() == Some(planned.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].state != LaunchIntentState::Prepared {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper has no unique prepared durable launch intent".to_owned(),
        ));
    }
    let worker_required = config
        .worker
        .as_ref()
        .is_some_and(|worker| worker.component_id == component.id);
    let binding = if worker_required {
        store
            .worker_bootstrap_binding(&matches[0].id)
            .map_err(watchdog_to_adapter_error)?
    } else {
        None
    };
    super::runtime_worker_bootstrap::verify_binding(
        binding.as_ref(),
        worker_required,
        bootstrap.worker_boot_id(),
        bootstrap.worker_frame_sha256(),
    )
    .map_err(watchdog_to_adapter_error)?;
    validate_planned_cgroup_leaf(&request.cgroup_path, planned.as_str())?;
    let delegated_root = bootstrap.delegated_cgroup_root_path().ok_or_else(|| {
        AdapterError::IdentityMismatch(
            "Linux helper has no trusted delegated cgroup root bootstrap".to_owned(),
        )
    })?;
    verify_current_cgroup_full_path(&request.cgroup_path, delegated_root)?;
    if !request.cgroup_path.is_absolute() {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper cgroup path is not absolute".to_owned(),
        ));
    }
    let mut allowlisted_executables = BTreeMap::new();
    for configured in &config.components {
        if let Ok(kind) = component_kind(configured)
            && configured.executable_sha256.is_some()
        {
            allowlisted_executables.insert(kind, configured.executable.clone());
        }
    }
    Ok((
        crate::platform::LinuxHelperAuthorization {
            specification: expected,
            cgroup_path: request.cgroup_path.clone(),
            allowlisted_executables,
        },
        store,
    ))
}

/// Bind the requested leaf to the exact containment persisted before launch.
#[cfg(target_os = "linux")]
fn validate_planned_cgroup_leaf(
    requested: &Path,
    planned: &str,
) -> std::result::Result<(), AdapterError> {
    let leaf = planned
        .strip_prefix("cgroup-v2:")
        .filter(|leaf| !leaf.is_empty())
        .ok_or_else(|| {
            AdapterError::Invalid("Linux containment identity is malformed".to_owned())
        })?;
    if requested.file_name().and_then(|name| name.to_str()) != Some(leaf) {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper cgroup path differs from durable containment intent".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn protected_config_from_bootstrap(
    bootstrap: &crate::platform::LinuxHelperBootstrap,
) -> std::result::Result<WatchdogConfig, AdapterError> {
    let mut bytes = Vec::new();
    bootstrap
        .protected_config_file()?
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            AdapterError::Io(format!("Linux protected config read failed: {error}"))
        })?;
    if bytes.len() > 65_536 {
        return Err(AdapterError::Invalid(
            "Linux protected config exceeds the bounded read size".to_owned(),
        ));
    }
    let mut config: WatchdogConfig = serde_json::from_slice(&bytes).map_err(|error| {
        AdapterError::Invalid(format!("Linux protected config is invalid: {error}"))
    })?;
    config.source_path = Some(bootstrap.protected_config_path().to_path_buf());
    config.validate().map_err(watchdog_to_adapter_error)?;
    Ok(config)
}

#[cfg(target_os = "linux")]
/// Also verify actual membership using the complete cgroup path.
fn verify_current_cgroup_full_path(
    requested: &Path,
    delegated_root: &Path,
) -> std::result::Result<(), AdapterError> {
    if !requested.is_absolute() {
        return Err(AdapterError::Invalid(
            "Linux helper cgroup path must be absolute".to_owned(),
        ));
    }
    let current_relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| {
            AdapterError::Unavailable(format!("Linux cgroup membership unavailable: {error}"))
        })?
        .lines()
        .find_map(|line| {
            let mut fields = line.splitn(3, ':');
            let hierarchy = fields.next()?;
            let controllers = fields.next()?;
            let path = fields.next()?;
            (hierarchy == "0" && controllers.is_empty()).then_some(path.to_owned())
        })
        .ok_or_else(|| {
            AdapterError::Unavailable("Linux cgroup v2 membership entry is unavailable".to_owned())
        })?;
    let mountpoint = cgroup_v2_mountpoint()?;
    let relative = current_relative.trim_start_matches('/');
    let current = mountpoint.join(relative);
    let expected = validate_exact_cgroup_child(requested, delegated_root)?;
    let actual = fs::canonicalize(&current).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux current cgroup path cannot be resolved: {error}"
        ))
    })?;
    if expected != actual {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper is not in the authorized full cgroup path".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_exact_cgroup_child(
    requested: &Path,
    delegated_root: &Path,
) -> std::result::Result<PathBuf, AdapterError> {
    let expected = fs::canonicalize(requested).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux authorized cgroup path cannot be resolved: {error}"
        ))
    })?;
    let trusted_root = fs::canonicalize(delegated_root).map_err(|error| {
        AdapterError::Unavailable(format!(
            "Linux delegated cgroup root cannot be resolved: {error}"
        ))
    })?;
    if expected != requested || expected.parent() != Some(trusted_root.as_path()) {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper cgroup is not the exact child of the trusted delegated root".to_owned(),
        ));
    }
    Ok(expected)
}

#[cfg(target_os = "linux")]
fn cgroup_v2_mountpoint() -> std::result::Result<PathBuf, AdapterError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        AdapterError::Unavailable(format!("Linux mountinfo unavailable: {error}"))
    })?;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let post_fields = after.split_whitespace().collect::<Vec<_>>();
        if post_fields.first().copied() != Some("cgroup2") {
            continue;
        }
        let fields = before.split_whitespace().collect::<Vec<_>>();
        let Some(mountpoint) = fields.get(4) else {
            continue;
        };
        return Ok(PathBuf::from(unescape_mountinfo(mountpoint)));
    }
    Err(AdapterError::Unavailable(
        "Linux cgroup v2 mountpoint is unavailable".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\134", "\\")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\040", " ")
}

#[cfg(target_os = "linux")]
fn watchdog_to_adapter_error(error: WatchdogError) -> AdapterError {
    match error {
        WatchdogError::InvalidInput(message) => AdapterError::Invalid(message),
        WatchdogError::Unauthorized(message) | WatchdogError::Conflict(message) => {
            AdapterError::IdentityMismatch(message)
        }
        WatchdogError::MissingState(path) => AdapterError::Unavailable(format!(
            "protected watchdog state is missing: {}",
            path.display()
        )),
        WatchdogError::NotFound(message) | WatchdogError::Unsupported(message) => {
            AdapterError::Unavailable(message)
        }
        WatchdogError::Busy(path) => AdapterError::Unavailable(format!(
            "protected watchdog state is busy: {}",
            path.display()
        )),
        WatchdogError::IdentityMismatch(message) => AdapterError::IdentityMismatch(message),
        WatchdogError::Timeout(message) => AdapterError::Timeout(message),
        WatchdogError::Sqlite(error) => AdapterError::Io(error.to_string()),
        WatchdogError::Io(error) => AdapterError::Io(error.to_string()),
        WatchdogError::Json(error) => AdapterError::Invalid(error.to_string()),
        WatchdogError::VerificationFailed(report) => AdapterError::Invalid(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_cleanup_uncertainty_survives_runtime_admission_mapping() {
        let error = WatchdogError::Conflict("unproven synthetic containment".to_owned());
        assert!(matches!(
            RuntimeLaunchError::from(ProcessSpawnError::CleanupUncertain(error)),
            RuntimeLaunchError::CleanupUncertain(_)
        ));
        let error = WatchdogError::InvalidInput("rejected before spawn".to_owned());
        assert!(matches!(
            RuntimeLaunchError::from(ProcessSpawnError::Ordinary(error)),
            RuntimeLaunchError::Ordinary(_)
        ));
    }

    #[test]
    fn synthetic_proof_preflight_accounts_for_runtime_identity_width() {
        let mut specification = LaunchSpec {
            deployment_id: "deployment".to_owned(),
            instance_id: "synthetic".to_owned(),
            component: PlatformComponentKind::Synthetic,
            incarnation: "incarnation".to_owned(),
            launch_nonce: "nonce".to_owned(),
            executable: PathBuf::from("/bin/true"),
            executable_sha256: "a".repeat(64),
            arguments: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            session: PlatformSessionSelector::Explicit(0),
            graceful_timeout: Duration::from_secs(1),
            force_timeout: Duration::from_secs(2),
        };
        // Leave enough room for the normal proof fields while making the
        // executable itself consume the remaining envelope. The preflight
        // must account for the maximal post-spawn identity values rather than
        // accepting a short synthetic placeholder.
        let mut length = 7_700;
        loop {
            specification.executable = PathBuf::from(format!("/{:0width$}", 7, width = length));
            if preflight_synthetic_proof_budget("intent", &specification, "containment").is_err() {
                break;
            }
            length += 1;
            assert!(length < 8_192, "proof preflight accepted an unbounded path");
        }
    }

    #[test]
    fn native_recovery_rejects_a_synthetic_launch_proof() {
        let intent = LaunchIntent {
            id: "intent".to_owned(),
            deployment_id: "deployment".to_owned(),
            component_id: "gateway".to_owned(),
            launch_nonce: "nonce".to_owned(),
            expected_incarnation: Some("incarnation".to_owned()),
            expected_launch_spec_digest: Some("a".repeat(64)),
            planned_containment_id: Some("synthetic-child:nonce".to_owned()),
            state: LaunchIntentState::Active,
            ownership_proof_json: Some(
                serde_json::to_value(OwnershipProof {
                    version: 1,
                    backend: "synthetic".to_owned(),
                    intent_id: "intent".to_owned(),
                    deployment_id: "deployment".to_owned(),
                    instance_id: "gateway".to_owned(),
                    component: "gateway".to_owned(),
                    incarnation: "incarnation".to_owned(),
                    launch_nonce: "nonce".to_owned(),
                    containment_id: "synthetic-child:nonce".to_owned(),
                    pid: 1,
                    creation_token: "synthetic:1".to_owned(),
                    executable: PathBuf::from("/bin/true"),
                    executable_sha256: "a".repeat(64),
                    session_id: None,
                    started_at_ms: 1,
                })
                .expect("synthetic proof serializes"),
            ),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        let mut manager = RuntimeProcessManager {
            synthetic: false,
            backend: None,
            injected_stop_result: None,
        };

        let result = manager.recover_intent(&WatchdogConfig::default(), &intent);
        assert!(matches!(
            result,
            Err(WatchdogError::Unsupported(message))
                if message.contains("synthetic launch proof")
        ));
    }

    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_membership_cannot_substitute_another_planned_containment() {
        assert!(
            validate_planned_cgroup_leaf(Path::new("/sys/fs/cgroup/owned"), "cgroup-v2:owned")
                .is_ok()
        );
        assert!(
            validate_planned_cgroup_leaf(Path::new("/sys/fs/cgroup/other"), "cgroup-v2:owned")
                .is_err()
        );
        assert!(
            validate_planned_cgroup_leaf(Path::new("/sys/fs/cgroup/owned"), "cgroup-v2:").is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_leaf_under_a_sibling_root_is_rejected()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let trusted = directory.path().join("trusted");
        let sibling = directory.path().join("sibling");
        fs::create_dir(&trusted)?;
        fs::create_dir(&sibling)?;
        let trusted_leaf = trusted.join("cgroup-v2-owned");
        let sibling_leaf = sibling.join("cgroup-v2-owned");
        fs::create_dir(&trusted_leaf)?;
        fs::create_dir(&sibling_leaf)?;

        assert!(validate_exact_cgroup_child(&trusted_leaf, &trusted).is_ok());
        assert!(validate_exact_cgroup_child(&sibling_leaf, &trusted).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_containment_round_trips_the_complete_request_identity() {
        let request = crate::platform::BrokerRequest {
            component: crate::platform::BrokerComponent::Gateway,
            instance: "gateway".to_owned(),
            incarnation: "watchdog-generation-7".to_owned(),
            nonce: "12345678-1234-4234-8234-123456789abc".to_owned(),
        };
        let planned = broker_planned_containment_for_request(&request).expect("planned identity");
        assert_eq!(
            broker_request_from_planned_containment(&planned).expect("request identity"),
            request
        );
        let malformed = planned.replace(&request.nonce, "bad:nonce");
        assert!(broker_request_from_planned_containment(&malformed).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_receipt_correlation_rejects_changed_process_binding() {
        let request = crate::platform::BrokerRequest {
            component: crate::platform::BrokerComponent::Harness,
            instance: "harness".to_owned(),
            incarnation: "watchdog-generation-2".to_owned(),
            nonce: "22345678-1234-4234-8234-123456789abc".to_owned(),
        };
        let unit = broker_unit_name(&request);
        let receipt = crate::platform::LaunchReceipt {
            request: request.clone(),
            unit: unit.clone(),
            pid: 42,
            creation_token: "boot:kernel:start".to_owned(),
            executable: PathBuf::from("/usr/local/lib/ascension/harness"),
            executable_sha256: "a".repeat(64),
            uid: 1001,
            gid: 1002,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            control_group: format!("/system.slice/{unit}"),
            duplicate: false,
        };
        verify_broker_receipt_request(&request, &receipt).expect("valid receipt");
        let mut changed = receipt.clone();
        changed.pid = receipt.pid + 1;
        assert!(verify_broker_receipt_binding(&changed, &receipt).is_err());
        changed = receipt.clone();
        changed.request.nonce = "32345678-1234-4234-8234-123456789abc".to_owned();
        assert!(verify_broker_receipt_binding(&changed, &receipt).is_err());
    }

    #[test]
    fn incarnation_requires_positive_generation() {
        assert_eq!(
            runtime_incarnation(7).expect("positive generation"),
            "watchdog-generation-7"
        );
        assert!(runtime_incarnation(0).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn injected_native_identity_proof_failure_is_cleanup_uncertain_without_backend() {
        let mut manager = RuntimeProcessManager {
            synthetic: false,
            backend: None,
            injected_stop_result: None,
        };
        let native = NativeChild::Linux(OwnedProcess {
            identity: PlatformProcessIdentity {
                deployment_id: "deployment".to_owned(),
                instance_id: "gateway".to_owned(),
                component: PlatformComponentKind::Gateway,
                incarnation: "watchdog-generation-1".to_owned(),
                launch_nonce: "nonce".to_owned(),
                creation: ProcessCreation {
                    token: "boot:1".to_owned(),
                    pid: 1,
                },
                executable: PathBuf::from("/bin/true"),
                executable_sha256: "a".repeat(64),
                containment: ContainmentId::new("cgroup-v2:fixture".to_owned())
                    .expect("fixture containment"),
                session: None,
            },
        });
        let result = manager.finish_native_launch(native, |_| {
            Err(WatchdogError::IdentityMismatch(
                "injected proof failure".to_owned(),
            ))
        });
        assert!(matches!(
            result,
            Err(RuntimeLaunchError::CleanupUncertain(WatchdogError::Conflict(message)))
                if message.contains("injected proof failure")
        ));
    }
}

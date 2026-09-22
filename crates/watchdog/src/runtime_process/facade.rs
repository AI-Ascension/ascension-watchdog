//! Process manager and child lifecycle facade.
//!
//! This child owns the observable supervision surface of the runtime process
//! authority: the `RuntimeProcessManager` entrypoint, the `RuntimeChild`
//! handle and its synthetic/native variants, the `RuntimeObservation` /
//! `RuntimeStopOutcome` / `RuntimeLaunchError` result vocabulary and the
//! cleanup-uncertain classification used when a native launch cannot prove its
//! identity.  It delegates every platform effect to the coordinator's
//! `NativeBackend` dispatch and owns no platform authority of its own.
//!
//! The module is well below the 1,000-line target.  The body is a verbatim
//! move; the only edits are `pub(super)`/`pub(crate)` on the moved items (their
//! effective visibility is unchanged) and module-local imports.  The
//! coordinator re-exports the moved names so `runtime.rs`, the sibling runtime
//! modules and the existing regression tests are unchanged.

use crate::config::{ComponentConfig, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::platform::LaunchSpec;
use crate::process::{OutputSnapshot, OwnedChild, ProcessIdentity, ProcessSpawnError};
use crate::storage::{LaunchIntent, LaunchIntentState};
use serde_json::Value;

use super::{
    MAX_NATIVE_PROOF_BYTES, NATIVE_GRACEFUL_TIMEOUT, NativeBackend, NativeChild, OwnershipProof,
    preflight_synthetic_proof_budget, validate_proof,
};
#[cfg(target_os = "linux")]
use super::{broker_planned_containment_for, map_adapter_error};

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
    pub(super) synthetic: bool,
    pub(super) backend: Option<NativeBackend>,
    #[cfg(test)]
    pub(super) injected_stop_result: Option<std::result::Result<RuntimeStopOutcome, String>>,
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

    pub(super) fn finish_native_launch<F>(
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

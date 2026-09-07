//! Process ownership for the durable watchdog runtime.
//!
//! Synthetic children are retained only for explicitly opted-in fixtures.
//! Production children are launched through the platform containment
//! authority and carry a bounded, versioned proof in the launch-intent row.

#[cfg(target_os = "linux")]
use crate::config::DesiredMode;
use crate::config::{ComponentConfig, WatchdogConfig, validate_digest};
use crate::error::{Result, WatchdogError};
#[cfg(target_os = "linux")]
use crate::platform::{
    AdapterError, ContainmentId, Observation as PlatformObservation, OwnedProcess, ProcessAdapter,
    ProcessCreation, ProcessIdentity as PlatformProcessIdentity,
    StopOutcome as PlatformStopOutcome,
};
use crate::platform::{
    ComponentKind as PlatformComponentKind, LaunchSpec, SessionSelector as PlatformSessionSelector,
};
use crate::process::{OutputSnapshot, OwnedChild, ProcessIdentity};
#[cfg(target_os = "linux")]
use crate::storage::Store;
use crate::storage::{LaunchIntent, LaunchIntentState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const MAX_NATIVE_PROOF_BYTES: usize = 8 * 1024;
const NATIVE_MAX_PROCESSES: u32 = 64;
const NATIVE_GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_FORCE_TIMEOUT: Duration = Duration::from_secs(10);
const INCARNATION_PREFIX: &str = "watchdog-generation-";

/// A child together with the durable intent which admitted it.
pub(crate) struct RuntimeChild {
    portable_identity: ProcessIdentity,
    intent_id: String,
    ownership: OwnershipProof,
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
    #[cfg(windows)]
    Windows(ascension_platform_windows::JobOwnedProcess),
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
}

#[derive(Debug)]
enum NativeBackend {
    #[cfg(target_os = "linux")]
    Linux(crate::platform::LinuxProcessAdapter),
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
        }
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
    ) -> Result<RuntimeChild> {
        if self.synthetic {
            let child = OwnedChild::spawn(component, now_ms)?;
            let mut portable_identity = child.identity().clone();
            portable_identity
                .launch_nonce
                .clone_from(&specification.launch_nonce);
            let ownership = OwnershipProof::synthetic(
                intent_id,
                specification,
                planned_containment,
                &portable_identity,
            )?;
            return Ok(RuntimeChild {
                portable_identity,
                intent_id: intent_id.to_owned(),
                ownership,
                handle: RuntimeChildHandle::Synthetic(child),
            });
        }
        let native = self
            .ensure_native(config)?
            .launch(specification, planned_containment)?;
        let (portable_identity, ownership) =
            native.identity(intent_id, specification, planned_containment, now_ms)?;
        Ok(RuntimeChild {
            portable_identity,
            intent_id: intent_id.to_owned(),
            ownership,
            handle: RuntimeChildHandle::Native(native),
        })
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
}

impl RuntimeChild {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStopOutcome {
    Exited(Option<i32>),
    AlreadyExited,
    TimedOut,
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
            let probe = crate::platform::LinuxProcessAdapter::new(allowlist.clone())
                .map_err(map_adapter_error)?;
            let root = probe.cgroup_root().to_path_buf();
            let launcher = crate::platform::TrustedLinuxLauncher::current_executable()
                .map_err(map_adapter_error)?;
            let launcher = match &config.source_path {
                Some(path) => launcher
                    .with_protected_config_path(path)
                    .map_err(map_adapter_error)?,
                None => launcher,
            };
            crate::platform::LinuxProcessAdapter::with_cgroup_root_and_limit_and_launcher(
                root,
                allowlist,
                NATIVE_MAX_PROCESSES as usize,
                launcher,
            )
            .map(NativeBackend::Linux)
            .map_err(map_adapter_error)
        }
        #[cfg(windows)]
        {
            let launcher = ascension_platform_windows::WindowsProcessLauncher::new(
                ascension_platform_windows::WindowsPlatformConfig {
                    service_name: "ascension-watchdog".to_owned(),
                    pipe_name: r"\\.\pipe\ascension-watchdog-runtime".to_owned(),
                    allowlisted_executables: allowlist
                        .into_iter()
                        .map(|(kind, path)| (windows_component_kind(kind), path))
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
        specification: &LaunchSpec,
        planned_containment: &str,
    ) -> Result<NativeChild> {
        #[cfg(windows)]
        let _ = planned_containment;
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(adapter) => {
                let containment = ContainmentId::new(planned_containment.to_owned())
                    .map_err(map_adapter_error)?;
                adapter
                    .launch_with_planned_containment(specification, &containment)
                    .map(NativeChild::Linux)
                    .map_err(map_adapter_error)
            }
            #[cfg(windows)]
            Self::Windows(backend) => {
                let windows_spec = windows_launch_spec(specification)?;
                backend
                    .launcher
                    .launch(&windows_spec)
                    .map(NativeChild::Windows)
                    .map_err(map_windows_error)
            }
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
    Ok(())
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

fn native_allowlist(config: &WatchdogConfig) -> Result<BTreeMap<PlatformComponentKind, PathBuf>> {
    let mut allowlist = BTreeMap::new();
    for component in &config.components {
        let kind = component_kind(component)?;
        if component.executable_sha256.is_none() {
            return Err(WatchdogError::InvalidInput(format!(
                "native component {} requires an approved executable hash",
                component.id
            )));
        }
        if allowlist
            .insert(kind, component.executable.clone())
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
    crate::platform::run_hidden_helper_if_requested_with_bootstrap_authorizer(
        authorize_linux_helper,
    )
    .map_err(map_adapter_error)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub fn run_linux_helper_if_requested() -> Result<Option<i32>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn authorize_linux_helper(
    request: &crate::platform::LinuxHelperRequest,
    bootstrap: &crate::platform::LinuxHelperBootstrap,
) -> std::result::Result<crate::platform::LinuxHelperAuthorization, AdapterError> {
    let config = WatchdogConfig::from_file(bootstrap.protected_config_path())
        .map_err(watchdog_to_adapter_error)?;
    let store =
        Store::open_read_only(&config.database, &config).map_err(watchdog_to_adapter_error)?;
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
    let digest = component.executable_sha256.as_deref().ok_or_else(|| {
        AdapterError::Unsupported(
            "Linux helper component has no approved executable digest".to_owned(),
        )
    })?;
    let expected = LaunchSpec {
        deployment_id: status.deployment_id.clone(),
        instance_id: component.id.clone(),
        component: request.specification.component,
        incarnation: expected_incarnation,
        launch_nonce: request.specification.launch_nonce.clone(),
        executable: component.executable.clone(),
        executable_sha256: digest.to_owned(),
        arguments: component.args.clone(),
        working_directory: component.cwd.clone(),
        environment: component
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        session: PlatformSessionSelector::Explicit(0),
        graceful_timeout: NATIVE_GRACEFUL_TIMEOUT,
        force_timeout: NATIVE_FORCE_TIMEOUT,
    };
    if request.specification != expected {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper request differs from protected component configuration".to_owned(),
        ));
    }
    let planned = crate::platform::LinuxProcessAdapter::planned_containment_for(&expected)?;
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
    let expected_name = planned.as_str().strip_prefix("cgroup-v2:").ok_or_else(|| {
        AdapterError::Invalid("Linux containment identity is malformed".to_owned())
    })?;
    let actual_name = request
        .cgroup_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AdapterError::Invalid("Linux helper cgroup path is malformed".to_owned()))?;
    if actual_name != expected_name {
        return Err(AdapterError::IdentityMismatch(
            "Linux helper cgroup path differs from durable containment intent".to_owned(),
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
    Ok(crate::platform::LinuxHelperAuthorization {
        specification: expected,
        cgroup_path: request.cgroup_path.clone(),
        allowlisted_executables,
    })
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incarnation_requires_positive_generation() {
        assert_eq!(
            runtime_incarnation(7).expect("positive generation"),
            "watchdog-generation-7"
        );
        assert!(runtime_incarnation(0).is_err());
    }
}

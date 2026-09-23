//! Reconciliation loop and approved child supervision.

#[path = "runtime_admin.rs"]
pub(crate) mod runtime_admin;
#[path = "runtime_gateway_health.rs"]
mod runtime_gateway_health;
#[path = "runtime_gateway_health_admission.rs"]
mod runtime_gateway_health_admission;
#[path = "runtime_process.rs"]
pub(crate) mod runtime_process;
#[path = "runtime_worker.rs"]
pub(crate) mod runtime_worker;
#[cfg(any(windows, test))]
#[path = "runtime_worker_admission.rs"]
mod runtime_worker_admission;
#[path = "runtime_worker_bootstrap.rs"]
mod runtime_worker_bootstrap;
pub use runtime_gateway_health::GatewayHealthDiagnostics;
#[cfg(all(test, windows))]
#[path = "runtime_worker_windows_tests.rs"]
mod runtime_worker_windows_tests;

mod coordinator;
mod health;
mod launch_binding;
mod lifecycle;
mod recovery;

pub use self::launch_binding::{DirectRuntimeAdapter, RuntimeAdapter};
use self::launch_binding::{
    expected_runtime_backend, launch_spec_binding_digest, launch_spec_for,
    validate_persisted_launch_binding,
};
use self::runtime_process::{
    RuntimeChild, RuntimeLaunchError, RuntimeObservation, RuntimeProcessManager,
    RuntimeStopOutcome, platform_component_kind, runtime_incarnation,
};
use crate::config::{ComponentConfig, DesiredMode, WatchdogConfig, hex_digest};
use crate::error::{Result, WatchdogError};
use crate::policy::{
    ComponentObservation, ComponentState, ReconcileAction, ReconcileDecision, SupervisorPolicy,
};
use crate::process::{ProcessIdentity, ensure_identity};
use crate::storage::{
    ComponentRecord, LaunchIntent, LaunchIntentState, SingletonLock, Store, now_unix_ms,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A liveness witness from an authenticated worker probe.
///
/// This stays in memory for one reconciliation only.  The complete child
/// identity and launch nonce are retained so a worker response cannot be
/// reused after the supervisor's owned child has been replaced.  `observed_at`
/// is monotonic and is intentionally not persisted as a wall-clock value.
#[derive(Clone, Debug)]
pub(crate) struct WorkerHeartbeatWitness {
    pub(crate) component_id: String,
    pub(crate) identity: ProcessIdentity,
    pub(crate) worker_boot_id: String,
    pub(crate) observed_at: Instant,
}

/// A single loop's bounded result, useful for diagnostics and tests.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub observed_at_ms: u64,
    pub desired_mode: DesiredMode,
    pub decisions: Vec<ReconcileDecision>,
    pub started: Vec<String>,
    pub stopped: Vec<String>,
    pub quarantined: Vec<String>,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_health: Option<GatewayHealthDiagnostics>,
}

/// A running watchdog controller.  Status/config commands do not construct
/// this type with a lock, so they remain side-effect free.
pub struct Supervisor {
    pub(crate) store: Store,
    config: WatchdogConfig,
    policy: SupervisorPolicy,
    children: BTreeMap<String, RuntimeChild>,
    process_manager: RuntimeProcessManager,
    lock: Option<SingletonLock>,
    worker_id: String,
    /// One fresh watchdog worker-session identity per Supervisor instance.
    /// It is never restored from durable state or regenerated per request.
    worker_boot_id: String,
    /// Keep the controller image and release directory immutable while any
    /// worker may authenticate this supervisor's bootstrap identity.
    #[cfg(windows)]
    windows_controller_identity: Option<ascension_platform_windows::CurrentControllerIdentity>,
    /// Worker availability diagnostics are edge-triggered per phase so a
    /// persistent endpoint outage cannot fill the audit log on every loop.
    pub(crate) worker_deferred_phases: BTreeSet<String>,
    /// One authenticated worker liveness witness for the current
    /// reconciliation.  Process liveness alone never populates this field.
    pub(crate) worker_heartbeat: Option<WorkerHeartbeatWitness>,
    /// A soft failure in the pre-scheduling worker phase gates fresh claims
    /// for the rest of this reconciliation.  The post phase may still retry
    /// control/recovery, but it cannot turn a later healthy probe into a
    /// claim after the required pre-phase observation was unavailable.
    pub(crate) worker_phase_pre_failed: bool,
    gateway_health_witness: Option<runtime_gateway_health::GatewayHealthWitness>,
    initialized_runtime: bool,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("database", &self.store.path())
            .field("components", &self.config.components.len())
            .field("children", &self.children.keys().collect::<Vec<_>>())
            .field("worker_id", &self.worker_id)
            .field("worker_boot_id", &self.worker_boot_id)
            .finish_non_exhaustive()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Synthetic fixtures retain their direct Child drop semantics. Native
        // handles carry only the durable platform identity after launch, so
        // the platform authority must perform exact containment cleanup before
        // those handles are discarded.
        let ids = self
            .children
            .iter()
            .filter_map(|(id, child)| child.is_native().then_some(id.clone()))
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(child) = self.children.get_mut(&id) {
                let _ = self.process_manager.stop(child);
            }
        }
    }
}

impl Supervisor {}

/// Dispatch the hidden Linux launch-helper mode before ordinary CLI parsing.
/// Normal invocations return Ok(None) and continue through the CLI.
pub fn run_linux_helper_if_requested() -> Result<Option<i32>> {
    runtime_process::run_linux_helper_if_requested()
}

fn component_record(
    component: &ComponentConfig,
    identity: &ProcessIdentity,
    attempts: u32,
    now_ms: u64,
    error: Option<String>,
) -> ComponentRecord {
    ComponentRecord {
        id: component.id.clone(),
        state: ComponentState::Running,
        launch_nonce: Some(identity.launch_nonce.clone()),
        pid: Some(identity.pid),
        executable_digest: Some(identity.executable_digest.clone()),
        started_at_ms: Some(identity.started_at_ms),
        restart_attempts: attempts,
        last_restart_at_ms: Some(now_ms),
        last_error: error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{ComponentKind, LaunchSpec, SessionSelector};
    use serde_json::json;

    fn session_spec(session: SessionSelector) -> LaunchSpec {
        LaunchSpec {
            deployment_id: "deployment".to_owned(),
            instance_id: "host-broker".to_owned(),
            component: ComponentKind::HostBroker,
            incarnation: "incarnation-1".to_owned(),
            launch_nonce: "nonce-1".to_owned(),
            executable: std::env::current_exe().expect("test executable"),
            executable_sha256: "a".repeat(64),
            arguments: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            session,
            graceful_timeout: Duration::from_secs(5),
            force_timeout: Duration::from_secs(10),
        }
    }

    fn bound_intent(specification: &LaunchSpec, containment: &str) -> LaunchIntent {
        LaunchIntent {
            id: "intent-1".to_owned(),
            deployment_id: specification.deployment_id.clone(),
            component_id: specification.instance_id.clone(),
            launch_nonce: specification.launch_nonce.clone(),
            expected_incarnation: Some(specification.incarnation.clone()),
            expected_launch_spec_digest: Some(
                launch_spec_binding_digest(specification, containment)
                    .expect("launch binding digest"),
            ),
            planned_containment_id: Some(containment.to_owned()),
            state: LaunchIntentState::ProofRecorded,
            ownership_proof_json: None,
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    fn windows_proof(
        intent: &LaunchIntent,
        specification: &LaunchSpec,
        containment: &str,
        session_id: Option<u32>,
    ) -> Value {
        json!({
            "version": 1,
            "backend": "windows",
            "intent_id": &intent.id,
            "deployment_id": &intent.deployment_id,
            "instance_id": &specification.instance_id,
            "component": &intent.component_id,
            "incarnation": &specification.incarnation,
            "launch_nonce": &specification.launch_nonce,
            "containment_id": containment,
            "pid": 42,
            "creation_token": "creation-1",
            "executable": &specification.executable,
            "executable_sha256": &specification.executable_sha256,
            "session_id": session_id,
            "started_at_ms": 1,
        })
    }

    #[test]
    fn linux_service_session_requires_absent_platform_session() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Gateway;
        let containment = "linux-cgroup:nonce-1";
        let intent = bound_intent(&specification, containment);
        let mut proof = windows_proof(&intent, &specification, containment, None);
        proof["backend"] = json!("linux");
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                "linux"
            )
            .is_ok()
        );
        for invalid_session in [Some(0), Some(7)] {
            proof["session_id"] = json!(invalid_session);
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "linux"
                )
                .is_err()
            );
        }
        proof["session_id"] = Value::Null;
        for invalid_selector in [SessionSelector::Explicit(7), SessionSelector::ActiveUser] {
            specification.session = invalid_selector;
            specification.component = ComponentKind::HostBroker;
            let intent = bound_intent(&specification, containment);
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "linux"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn persisted_proof_cannot_select_synthetic_or_foreign_backend() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Gateway;
        let containment = "containment:nonce-1";
        let intent = bound_intent(&specification, containment);
        for expected in ["linux", "windows"] {
            let mut proof = windows_proof(&intent, &specification, containment, None);
            proof["backend"] = json!("synthetic");
            proof["executable_sha256"] = json!("unverified-synthetic");
            assert!(matches!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    expected
                ),
                Err(WatchdogError::IdentityMismatch(_))
            ));
            // Native proof relabeling cannot cross the platform boundary either.
            proof["backend"] = json!(if expected == "linux" {
                "windows"
            } else {
                "linux"
            });
            assert!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    expected
                )
                .is_err()
            );
        }
    }

    #[test]
    fn synthetic_proof_requires_explicit_synthetic_configuration() {
        let mut specification = session_spec(SessionSelector::Explicit(0));
        specification.component = ComponentKind::Synthetic;
        let containment = "synthetic:nonce-1";
        let intent = bound_intent(&specification, containment);
        let mut proof = windows_proof(&intent, &specification, containment, None);
        proof["backend"] = json!("synthetic");
        proof["executable_sha256"] = json!("unverified-synthetic");
        assert_eq!(expected_runtime_backend(true), "synthetic");
        assert_ne!(expected_runtime_backend(false), "synthetic");
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                expected_runtime_backend(true)
            )
            .is_ok()
        );
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &proof,
                expected_runtime_backend(false)
            )
            .is_err()
        );
    }

    #[test]
    fn active_user_windows_proof_requires_resolved_nonzero_session() {
        let specification = session_spec(SessionSelector::ActiveUser);
        let containment = "windows-job:nonce-1";
        let intent = bound_intent(&specification, containment);
        let valid = windows_proof(&intent, &specification, containment, Some(7));
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &valid,
                "windows"
            )
            .is_ok()
        );

        for unresolved in [None, Some(0)] {
            let proof = windows_proof(&intent, &specification, containment, unresolved);
            assert!(matches!(
                validate_persisted_launch_binding(
                    &intent,
                    &specification,
                    containment,
                    &proof,
                    "windows"
                ),
                Err(WatchdogError::IdentityMismatch(_))
            ));
        }
    }

    #[test]
    fn explicit_session_proof_mismatch_is_rejected() {
        let specification = session_spec(SessionSelector::Explicit(7));
        let containment = "windows-job:nonce-1";
        let intent = bound_intent(&specification, containment);
        let matching = windows_proof(&intent, &specification, containment, Some(7));
        assert!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &matching,
                "windows"
            )
            .is_ok()
        );
        let mismatched = windows_proof(&intent, &specification, containment, Some(8));
        assert!(matches!(
            validate_persisted_launch_binding(
                &intent,
                &specification,
                containment,
                &mismatched,
                "windows"
            ),
            Err(WatchdogError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn configured_release_catalog_requires_explicit_activation_before_launch() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = WatchdogConfig {
            database: directory.path().join("watchdog.sqlite3"),
            release_catalog: Some(crate::config::ReleaseCatalogConfig {
                root: directory.path().join("release-catalog"),
                owner_uid: 0,
            }),
            ..WatchdogConfig::default()
        };
        let supervisor = Supervisor::initialize(config)?;
        let error = supervisor
            .release_start_gate()
            .expect_err("catalog deployments must activate an exact release first");
        assert!(error.contains("no release has been explicitly activated"));
        Ok(())
    }
}

//! Process ownership for the durable watchdog runtime.
//!
//! Synthetic children are retained only for explicitly opted-in fixtures.
//! Production children are launched through the platform containment
//! authority and carry a bounded, versioned proof in the launch-intent row.
//!
//! This file stays the `runtime_process` coordinator so every existing
//! `crate::runtime::runtime_process::*` path keeps working.  The launch
//! ownership proof now lives in the cohesive `ownership` child module:
//! `runtime_process/ownership.rs` owns the closed `OwnershipProof` shape,
//! its bounded serialized size, construction from native/broker/synthetic
//! identities, the stable runtime incarnation and the strict recovery
//! validation applied before a persisted proof is adopted.  The coordinator
//! keeps `MAX_NATIVE_PROOF_BYTES` because it also enforces that bound when it
//! re-serializes a live child proof, and re-exports the moved items so
//! callers and the in-module regression tests are unchanged.
//!
//! The Linux helper admission surface — protected bootstrap validation, worker/gateway-health
//! binding checks and the exact delegated-cgroup-leaf proof — now lives in the
//! cohesive `linux_helper` child module (`runtime_process/linux_helper.rs`).
//! The coordinator re-exports `run_linux_helper_if_requested` and the two
//! cgroup predicates the in-module regression tests call, so callers and tests
//! are unchanged.
//!
//! The supervision facade — the `RuntimeProcessManager` entrypoint, the
//! `RuntimeChild` handle, the observation/stop/launch-error vocabulary and the
//! cleanup-uncertain classification — lives in the cohesive `facade` child
//! module (`runtime_process/facade.rs`).  The coordinator re-exports every
//! moved name its native dispatch, recovery path and regression tests still
//! call, so no caller changes.
//!
//! The Linux broker protocol seam — request identity and construction, the
//! versioned planned-containment encoding and its decoders, unit-name
//! derivation, broker error mapping and receipt correlation/binding — lives in
//! the cohesive `broker` child module (`runtime_process/broker.rs`),
//! compiled only on Linux.  The coordinator re-exports the helpers its dispatch,
//! recovery path and regression tests still call.
//!
//! The native backend dispatch — the `NativeBackend` enum and its
//! create/launch/reopen/inspect/stop/force-cleanup implementation over the Linux
//! adapter, the Linux broker client and the Windows job backend, the
//! `NativeChild` handle, and the platform observation/stop/error conversions —
//! lives in the cohesive `native_backend` child module
//! (`runtime_process/native_backend.rs`).  The coordinator keeps the shared
//! proof-size bound, the native timeouts and the containment policy
//! (`expected_containment_for`, `component_kind`, `native_allowlist`) that its
//! dispatch and recovery paths call.

use crate::config::{ComponentConfig, WatchdogConfig};
use crate::error::{Result, WatchdogError};
#[cfg(any(windows, test))]
use crate::platform::SessionSelector as PlatformSessionSelector;
use crate::platform::{ComponentKind as PlatformComponentKind, LaunchSpec};
#[cfg(all(target_os = "linux", test))]
use crate::platform::{
    ContainmentId, OwnedProcess, ProcessCreation, ProcessIdentity as PlatformProcessIdentity,
};
#[cfg(test)]
use crate::process::ProcessSpawnError;
#[cfg(test)]
use crate::storage::{LaunchIntent, LaunchIntentState};
use std::collections::BTreeMap;
#[cfg(all(target_os = "linux", test))]
use std::fs;
#[cfg(all(target_os = "linux", test))]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

// `runtime` is declared with `#[path]`, so this coordinator must name the
// child file explicitly instead of relying on directory derivation.
#[path = "runtime_process/ownership.rs"]
mod ownership;

pub(crate) use ownership::runtime_incarnation;
use ownership::{OwnershipProof, preflight_synthetic_proof_budget, validate_proof};
#[path = "runtime_process/linux_helper.rs"]
mod linux_helper;

pub(crate) use linux_helper::run_linux_helper_if_requested;
#[cfg(all(target_os = "linux", test))]
use linux_helper::{validate_exact_cgroup_child, validate_planned_cgroup_leaf};

#[path = "runtime_process/facade.rs"]
mod facade;

pub(crate) use facade::{
    RuntimeChild, RuntimeLaunchError, RuntimeObservation, RuntimeProcessManager, RuntimeStopOutcome,
};

#[cfg(target_os = "linux")]
#[path = "runtime_process/broker.rs"]
mod broker;

#[cfg(target_os = "linux")]
use broker::{
    broker_planned_containment_for, broker_planned_containment_for_request, broker_request_for,
    broker_request_from_planned_containment, broker_request_from_proof,
    map_broker_bootstrap_launch_error, map_broker_error, verify_broker_receipt,
    verify_broker_receipt_against_proof, verify_broker_receipt_binding,
};
#[cfg(all(target_os = "linux", test))]
use broker::{broker_unit_name, verify_broker_receipt_request};

#[path = "runtime_process/native_backend.rs"]
mod native_backend;

#[cfg(target_os = "linux")]
use native_backend::map_adapter_error;
use native_backend::{NativeBackend, NativeChild};

const MAX_NATIVE_PROOF_BYTES: usize = 8 * 1024;
const NATIVE_GRACEFUL_TIMEOUT: Duration = Duration::from_secs(5);

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

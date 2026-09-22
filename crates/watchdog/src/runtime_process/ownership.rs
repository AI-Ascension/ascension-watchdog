//! Launch ownership proof construction and validation.
//!
//! This child module owns the closed proof that ties a platform process
//! authority to a durable launch intent: its serialized shape, the bounded
//! size envelope, construction from native/broker/synthetic identities and the
//! strict recovery validation performed before a persisted proof is adopted.
//! It deliberately does not own process backends, broker transport or helper
//! admission; those consumers reach the proof through their parent
//! coordinator, which keeps the existing `runtime_process` import paths.
//!
//! The proof-size bound stays in the coordinator because the runtime facade
//! also enforces it when it re-serializes a live child proof; this module
//! imports that shared constant rather than duplicating it.

use super::MAX_NATIVE_PROOF_BYTES;
use crate::config::{WatchdogConfig, validate_digest};
use crate::error::{Result, WatchdogError};
use crate::platform::LaunchSpec;
use crate::process::ProcessIdentity;
use crate::storage::LaunchIntent;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use super::verify_broker_receipt;
#[cfg(target_os = "linux")]
use crate::platform::ProcessIdentity as PlatformProcessIdentity;

const INCARNATION_PREFIX: &str = "watchdog-generation-";

/// Closed proof tying a platform process authority to a launch intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnershipProof {
    pub(super) version: u32,
    pub(super) backend: String,
    pub(super) intent_id: String,
    pub(super) deployment_id: String,
    pub(super) instance_id: String,
    pub(super) component: String,
    pub(super) incarnation: String,
    pub(super) launch_nonce: String,
    pub(super) containment_id: String,
    pub(super) pid: u32,
    pub(super) creation_token: String,
    pub(super) executable: PathBuf,
    pub(super) executable_sha256: String,
    pub(super) session_id: Option<u32>,
    pub(super) started_at_ms: u64,
}

impl OwnershipProof {
    #[cfg(target_os = "linux")]
    pub(super) fn from_platform(
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
    pub(super) fn from_broker_receipt(
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

    pub(super) fn synthetic(
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

    pub(super) fn portable_identity(&self) -> ProcessIdentity {
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
pub(super) fn preflight_synthetic_proof_budget(
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

/// Stable incarnation shared by launch construction and helper authorization.
pub(crate) fn runtime_incarnation(restart_generation: i64) -> Result<String> {
    if restart_generation <= 0 {
        return Err(WatchdogError::Conflict(
            "restart generation must be positive before native launch".to_owned(),
        ));
    }
    Ok(format!("{INCARNATION_PREFIX}{restart_generation}"))
}

pub(super) fn validate_proof(
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
    let specification = super::super::launch_spec_for(
        config,
        component,
        intent.launch_nonce.clone(),
        proof.incarnation.clone(),
    )?;
    let expected_containment = super::expected_containment_for(config, &specification)?;
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

//! Linux broker request, planned-containment and receipt binding.
//!
//! This child module owns the protocol seam between the watchdog runtime and
//! the privileged Linux broker: the exact request identity derived from a
//! launch spec, the reversible `linux-broker-v1:<component>:<instance>:
//! <incarnation>:<nonce>` planned-containment encoding, the broker unit name
//! derivation, error mapping and the receipt verification helpers that prove a
//! returned or recovered receipt still correlates to the original request and
//! never let a lifecycle response rebind a live child.  It owns no process
//! authority of its own.
//!
//! The module is well below the 1,000-line target and is compiled only for
//! Linux.  The coordinator re-exports every helper its facade, recovery path
//! and regression tests still call, so no caller changes.
//!
//! The body is a verbatim move; the only edits are `pub(super)` on the moved
//! items (their effective visibility is unchanged) and module-local imports.

use super::{OwnershipProof, RuntimeLaunchError, platform_component_kind};
use crate::config::{hex_digest, validate_digest};
use crate::error::{Result, WatchdogError};
use crate::platform::{ComponentKind as PlatformComponentKind, LaunchSpec};
use sha2::Digest;

#[cfg(target_os = "linux")]
pub(super) const BROKER_CONTAINMENT_PREFIX: &str = "linux-broker-v1";

#[cfg(target_os = "linux")]
pub(super) fn map_broker_error(error: crate::platform::linux_broker::BrokerError) -> WatchdogError {
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
pub(super) fn map_broker_bootstrap_launch_error(
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
pub(super) fn broker_component(
    component: PlatformComponentKind,
) -> crate::platform::BrokerComponent {
    match component {
        PlatformComponentKind::Gateway => crate::platform::BrokerComponent::Gateway,
        PlatformComponentKind::Harness => crate::platform::BrokerComponent::Harness,
        PlatformComponentKind::HostBroker => crate::platform::BrokerComponent::HostBroker,
        PlatformComponentKind::Synthetic => crate::platform::BrokerComponent::Synthetic,
    }
}

#[cfg(target_os = "linux")]
pub(super) fn broker_component_name(component: crate::platform::BrokerComponent) -> &'static str {
    match component {
        crate::platform::BrokerComponent::Gateway => "gateway",
        crate::platform::BrokerComponent::Harness => "harness",
        crate::platform::BrokerComponent::HostBroker => "hostbroker",
        crate::platform::BrokerComponent::Synthetic => "synthetic",
    }
}

#[cfg(target_os = "linux")]
pub(super) fn broker_component_from_name(value: &str) -> Result<crate::platform::BrokerComponent> {
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
pub(super) fn valid_broker_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(target_os = "linux")]
pub(super) fn validate_broker_request(request: &crate::platform::BrokerRequest) -> Result<()> {
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
pub(super) fn broker_request_for(
    specification: &LaunchSpec,
) -> Result<crate::platform::BrokerRequest> {
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
pub(super) fn broker_unit_name(request: &crate::platform::BrokerRequest) -> String {
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
pub(super) fn broker_planned_containment_for(specification: &LaunchSpec) -> Result<String> {
    let request = broker_request_for(specification)?;
    broker_planned_containment_for_request(&request)
}

#[cfg(target_os = "linux")]
pub(super) fn broker_planned_containment_for_request(
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
pub(super) fn broker_request_from_planned_containment(
    value: &str,
) -> Result<crate::platform::BrokerRequest> {
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
pub(super) fn broker_request_from_proof(
    proof: &OwnershipProof,
) -> Result<crate::platform::BrokerRequest> {
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
pub(super) fn verify_broker_receipt(
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
pub(super) fn verify_broker_receipt_request(
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
pub(super) fn verify_broker_receipt_against_proof(
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
pub(super) fn verify_broker_receipt_binding(
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

//! Durable health-frame admission, independent of the observed pipe bytes.

use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::{Result, WatchdogError};
use crate::platform::LaunchSpec;
use crate::platform::gateway_health::{GatewayHealthAuthorization, GatewayHealthFrameBinding};
use crate::storage::{LaunchIntentState, Store};

#[cfg(windows)]
pub(super) fn authorize_windows(
    config: &WatchdogConfig,
    specification: &LaunchSpec,
    planned: &str,
    frame: &crate::platform::gateway_health::GatewayHealthBootstrap,
    watchdog_boot_id: &str,
    deadline: std::time::Instant,
) -> Result<Store> {
    check_deadline(deadline)?;
    let source = config.source_path.as_ref().ok_or_else(|| {
        WatchdogError::Unauthorized(
            "gateway launch requires a protected source configuration".to_owned(),
        )
    })?;
    let current = WatchdogConfig::from_file(source)?;
    check_deadline(deadline)?;
    if current.digest()? != config.digest()? || current.allow_synthetic_children {
        return invalid("gateway configuration changed before resumption");
    }
    let store = Store::open(&current.database, &current)?.reserve_launch_admission()?;
    check_deadline(deadline)?;
    if planned != format!("windows-job:{}", specification.launch_nonce) {
        return invalid("gateway planned Job differs from its launch nonce");
    }
    authorize_stored(
        &current,
        &store,
        specification,
        planned,
        &GatewayHealthFrameBinding::from_bootstrap(frame),
        Some(watchdog_boot_id),
    )?;
    check_deadline(deadline)?;
    // Keep the writer reservation through ResumeThread. A stop commits either
    // before this check or after resumption; the platform owns the guard.
    Ok(store)
}

pub(super) fn authorize_stored(
    config: &WatchdogConfig,
    store: &Store,
    specification: &LaunchSpec,
    planned: &str,
    observed: &GatewayHealthFrameBinding,
    expected_boot: Option<&str>,
) -> Result<GatewayHealthAuthorization> {
    if config.allow_synthetic_children {
        return invalid("gateway health admission requires native containment");
    }
    let status = store.status()?;
    if status.desired_mode != DesiredMode::Running {
        return Err(WatchdogError::Unauthorized(
            "gateway running intent was revoked before admission".to_owned(),
        ));
    }
    let health = config.gateway_health.as_ref().ok_or_else(|| {
        WatchdogError::Unauthorized("gateway health is not configured".to_owned())
    })?;
    let component = config
        .components
        .iter()
        .find(|component| component.id == health.component_id)
        .ok_or_else(|| {
            WatchdogError::IdentityMismatch("gateway health component is not approved".to_owned())
        })?;
    let expected = super::launch_spec_for(
        config,
        component,
        specification.launch_nonce.clone(),
        super::runtime_incarnation(status.restart_generation)?,
    )?;
    if specification != &expected
        || specification.component != crate::platform::ComponentKind::Gateway
    {
        return invalid("gateway health request differs from protected configuration");
    }
    let digest = super::launch_spec_binding_digest(specification, planned)?;
    let intents = store.launch_admission_intents(&component.id)?;
    if intents.len() != 1 {
        return invalid("gateway health requires exactly one unsettled launch intent");
    }
    let intent = &intents[0];
    if intent.state != LaunchIntentState::Prepared
        || intent.deployment_id != status.deployment_id
        || intent.component_id != component.id
        || intent.launch_nonce != specification.launch_nonce
        || intent.expected_incarnation.as_deref() != Some(specification.incarnation.as_str())
        || intent.expected_launch_spec_digest.as_deref() != Some(digest.as_str())
        || intent.planned_containment_id.as_deref() != Some(planned)
    {
        return invalid("gateway health has no exact prepared launch authority");
    }
    let binding = store.gateway_health_binding(&intent.id)?.ok_or_else(|| {
        WatchdogError::IdentityMismatch("gateway health has no persisted frame binding".to_owned())
    })?;
    if expected_boot.is_some_and(|boot| boot != binding.watchdog_boot_id) {
        return invalid("gateway health belongs to a different watchdog boot");
    }
    let nonce = uuid::Uuid::parse_str(&intent.launch_nonce).map_err(|_| {
        WatchdogError::IdentityMismatch("invalid persisted gateway nonce".to_owned())
    })?;
    let authorization = GatewayHealthAuthorization::from_persisted(nonce, binding.frame_sha256)
        .map_err(|error| WatchdogError::IdentityMismatch(error.to_string()))?;
    authorization
        .matches(observed)
        .map_err(|error| WatchdogError::IdentityMismatch(error.to_string()))?;
    let final_status = store.status()?;
    if final_status.desired_mode != DesiredMode::Running
        || final_status.restart_generation != status.restart_generation
    {
        return Err(WatchdogError::Unauthorized(
            "gateway launch authority changed during admission".to_owned(),
        ));
    }
    Ok(authorization)
}

#[cfg(windows)]
fn check_deadline(deadline: std::time::Instant) -> Result<()> {
    if std::time::Instant::now() >= deadline {
        return Err(WatchdogError::Timeout(
            "gateway pre-resume admission deadline elapsed".to_owned(),
        ));
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(WatchdogError::IdentityMismatch(message.to_owned()))
}

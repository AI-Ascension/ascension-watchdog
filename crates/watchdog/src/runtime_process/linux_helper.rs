//! Linux helper admission and exact cgroup proof.
//!
//! This child module owns the Linux-side privileged helper path: admitting a
//! helper launch against the protected bootstrap configuration and the durable
//! launch intent, verifying gateway-health/worker bootstrap bindings, and
//! proving that the helper occupies the exact leaf of the trusted delegated
//! cgroup root.  It deliberately delegates process authority to
//! `linux_launcher`/`linux_process` and does not widen that authority: the
//! containment rules here only refuse mismatches.
//!
//! The size of the admission surface is one cohesive boundary; the module is
//! well below the 1,000-line target, so no exception has to be documented.
//! `runtime_process.rs` re-exports `run_linux_helper_if_requested` so
//! `runtime.rs` and the existing regression tests keep their import path.

#[cfg(target_os = "linux")]
use super::{component_kind, map_adapter_error, runtime_incarnation};
#[cfg(target_os = "linux")]
use crate::config::{DesiredMode, WatchdogConfig};
use crate::error::Result;
#[cfg(target_os = "linux")]
use crate::error::WatchdogError;
#[cfg(target_os = "linux")]
use crate::platform::AdapterError;
#[cfg(target_os = "linux")]
use crate::storage::{LaunchIntentState, Store};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

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
    let expected = super::super::launch_spec_for(
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
            super::super::runtime_gateway_health_admission::authorize_stored(
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
    super::super::runtime_worker_bootstrap::verify_binding(
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
pub(super) fn validate_planned_cgroup_leaf(
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
pub(super) fn validate_exact_cgroup_child(
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

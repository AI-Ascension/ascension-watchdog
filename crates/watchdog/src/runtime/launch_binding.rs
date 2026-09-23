//! Launch binding and runtime adapter validation.
//!
//! This child module owns the exact launch request admitted for an approved
//! component, the digest that binds it to a persisted intent, the decoder and
//! validator for a persisted ownership proof, and the `RuntimeAdapter`
//! boundary used to reject a component the host cannot launch.
//!
//! The guarantees are unchanged.  Backend, session, component and
//! configuration binding are all checked against trusted runtime
//! configuration rather than a persisted proof, synthetic launches require an
//! explicit opt-in, and every original proof-rejection path is retained.
//! `runtime.rs` remains the facade that declares and re-exports the public
//! adapter values and keeps the crate-internal helper paths stable.

use super::{
    ComponentConfig, Duration, LaunchIntent, Result, Value, WatchdogConfig, WatchdogError,
    hex_digest, platform_component_kind,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The proof returned by the platform runtime is intentionally decoded at
/// this boundary.  Generic storage retains the bounded JSON for durability,
/// but it must not decide which incarnation or launch context a proof belongs
/// to.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeOwnershipProof {
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

#[derive(Serialize)]
struct LaunchSpecBinding<'a> {
    deployment_id: &'a str,
    instance_id: &'a str,
    component: &'static str,
    incarnation: &'a str,
    launch_nonce: &'a str,
    executable: &'a str,
    executable_sha256: &'a str,
    arguments: &'a [String],
    working_directory: Option<&'a str>,
    environment: &'a [(String, String)],
    session: String,
    graceful_timeout_ms: u64,
    force_timeout_ms: u64,
    planned_containment_id: &'a str,
}

pub(super) fn launch_component_kind_name(
    component: crate::platform::ComponentKind,
) -> &'static str {
    match component {
        crate::platform::ComponentKind::Gateway => "gateway",
        crate::platform::ComponentKind::Harness => "harness",
        crate::platform::ComponentKind::HostBroker => "host_broker",
        crate::platform::ComponentKind::Synthetic => "synthetic",
    }
}

pub(super) fn launch_session_name(session: crate::platform::SessionSelector) -> String {
    match session {
        crate::platform::SessionSelector::ActiveUser => "active_user".to_owned(),
        crate::platform::SessionSelector::Explicit(value) => format!("explicit:{value}"),
    }
}

/// Digest the exact request admitted before spawning.  The full request is
/// hashed rather than retained so environment values and other launch inputs
/// do not become durable watchdog state, while a changed configuration cannot
/// silently rebind a recovered proof.
pub(super) fn launch_spec_binding_digest(
    specification: &crate::platform::LaunchSpec,
    planned_containment_id: &str,
) -> Result<String> {
    specification
        .validate()
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
    let working_directory = specification
        .working_directory
        .as_deref()
        .map(|path| path.to_string_lossy().into_owned());
    let executable = specification.executable.to_string_lossy().into_owned();
    let binding = LaunchSpecBinding {
        deployment_id: &specification.deployment_id,
        instance_id: &specification.instance_id,
        component: launch_component_kind_name(specification.component),
        incarnation: &specification.incarnation,
        launch_nonce: &specification.launch_nonce,
        executable: &executable,
        executable_sha256: &specification.executable_sha256,
        arguments: &specification.arguments,
        working_directory: working_directory.as_deref(),
        environment: &specification.environment,
        session: launch_session_name(specification.session),
        graceful_timeout_ms: specification
            .graceful_timeout
            .as_millis()
            .try_into()
            .map_err(|_| {
                WatchdogError::InvalidInput("graceful timeout exceeds digest bound".to_owned())
            })?,
        force_timeout_ms: specification
            .force_timeout
            .as_millis()
            .try_into()
            .map_err(|_| {
                WatchdogError::InvalidInput("force timeout exceeds digest bound".to_owned())
            })?,
        planned_containment_id,
    };
    Ok(hex_digest(&serde_json::to_vec(&binding)?))
}

pub(super) fn expected_runtime_backend(synthetic: bool) -> &'static str {
    if synthetic {
        "synthetic"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unsupported"
    }
}

pub(super) fn validate_persisted_launch_binding(
    intent: &LaunchIntent,
    specification: &crate::platform::LaunchSpec,
    planned_containment_id: &str,
    proof_value: &Value,
    expected_backend: &str,
) -> Result<()> {
    let Some(expected_incarnation) = intent.expected_incarnation.as_deref() else {
        return Err(WatchdogError::Conflict(format!(
            "launch intent {} has no original incarnation binding",
            intent.id
        )));
    };
    let Some(expected_digest) = intent.expected_launch_spec_digest.as_deref() else {
        return Err(WatchdogError::Conflict(format!(
            "launch intent {} has no original launch specification binding",
            intent.id
        )));
    };
    if specification.incarnation != expected_incarnation {
        return Err(WatchdogError::IdentityMismatch(
            "launch specification incarnation differs from persisted intent".to_owned(),
        ));
    }
    let actual_digest = launch_spec_binding_digest(specification, planned_containment_id)?;
    if actual_digest != expected_digest {
        return Err(WatchdogError::IdentityMismatch(
            "launch specification differs from the persisted launch intent".to_owned(),
        ));
    }
    let proof: RuntimeOwnershipProof =
        serde_json::from_value(proof_value.clone()).map_err(|_| {
            WatchdogError::IdentityMismatch(
                "launch ownership proof has an invalid shape".to_owned(),
            )
        })?;
    // Select the backend from trusted runtime configuration, never from a
    // persisted proof: relabeling a native proof must not opt out of checks.
    if proof.backend != expected_backend
        || !matches!(expected_backend, "synthetic" | "linux" | "windows")
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch proof backend differs from configured process authority".to_owned(),
        ));
    }
    let session_matches = match (expected_backend, specification.session) {
        // Linux has no Windows session ID. Its adapter only accepts the
        // service selector Explicit(0), and persists that as None.
        ("linux", crate::platform::SessionSelector::Explicit(0)) => proof.session_id.is_none(),
        ("linux", _) => false,
        // ActiveUser is a selector, not a proof value.  The platform resolves
        // it during launch, so recovery must require a concrete non-service
        // session rather than comparing against `None`.
        (_, crate::platform::SessionSelector::ActiveUser) => {
            proof.session_id.is_some_and(|session| session != 0)
        }
        (_, crate::platform::SessionSelector::Explicit(expected)) => {
            proof.session_id == Some(expected)
        }
    };
    let executable_matches = proof.executable == specification.executable
        || std::fs::canonicalize(&proof.executable)
            .ok()
            .zip(std::fs::canonicalize(&specification.executable).ok())
            .is_some_and(|(actual, expected)| actual == expected);
    // The platform timestamp is part of the closed proof shape, but it is
    // not an authority binding: the persisted launch nonce/incarnation and
    // platform creation token provide that identity.
    let _ = proof.started_at_ms;
    if proof.version != 1
        || proof.intent_id != intent.id
        || proof.deployment_id != intent.deployment_id
        || proof.deployment_id != specification.deployment_id
        || proof.instance_id != specification.instance_id
        || proof.component != intent.component_id
        || proof.component != specification.instance_id
        || proof.incarnation != expected_incarnation
        || proof.launch_nonce != intent.launch_nonce
        || proof.launch_nonce != specification.launch_nonce
        || proof.containment_id != planned_containment_id
        || !executable_matches
        || (proof.backend != "synthetic"
            && proof.executable_sha256 != specification.executable_sha256)
        || (proof.backend != "synthetic" && !session_matches)
        || !matches!(proof.backend.as_str(), "synthetic" | "linux" | "windows")
        || proof.pid == 0
        || proof.creation_token.is_empty()
    {
        return Err(WatchdogError::IdentityMismatch(
            "launch ownership proof differs from the original launch intent".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn launch_spec_for(
    config: &WatchdogConfig,
    component: &ComponentConfig,
    launch_nonce: String,
    incarnation: String,
) -> Result<crate::platform::LaunchSpec> {
    let mut environment = component.environment.clone();
    if config
        .gateway_health
        .as_ref()
        .is_some_and(|health| health.component_id == component.id)
    {
        environment.insert(
            "STS2_GATEWAY_WATCHDOG_LAUNCH_NONCE".to_owned(),
            launch_nonce.clone(),
        );
    }
    Ok(crate::platform::LaunchSpec {
        deployment_id: config.deployment_id.clone(),
        instance_id: component.id.clone(),
        component: platform_component_kind(&component.id).or_else(|error| {
            if config.allow_synthetic_children {
                Ok(crate::platform::ComponentKind::Synthetic)
            } else {
                Err(error)
            }
        })?,
        incarnation,
        launch_nonce,
        executable: component.executable.clone(),
        executable_sha256: component
            .executable_sha256
            .clone()
            .unwrap_or_else(|| "0".repeat(64)),
        arguments: component.args.clone(),
        working_directory: component.cwd.clone(),
        environment: environment
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        // Native watchdog components are service-side background processes;
        // Explicit(0) is deliberately the service session.  This runtime
        // does not launch HostBroker, which would require a separately
        // approved nonzero interactive session.
        session: crate::platform::SessionSelector::Explicit(0),
        graceful_timeout: Duration::from_secs(5),
        force_timeout: Duration::from_secs(10),
    })
}

/// A placeholder-neutral runtime adapter hook for future native Windows/WSL
/// integration.  The vertical slice uses the direct process adapter above.
pub trait RuntimeAdapter {
    /// Validate that the adapter can launch this exact approved component.
    fn validate_component(&self, component: &ComponentConfig) -> Result<()>;
}

/// The portable adapter validates paths but performs no host-specific actions.
#[derive(Debug, Default)]
pub struct DirectRuntimeAdapter;

impl RuntimeAdapter for DirectRuntimeAdapter {
    fn validate_component(&self, component: &ComponentConfig) -> Result<()> {
        if !component.executable.is_absolute() || !Path::new(&component.executable).is_file() {
            return Err(WatchdogError::InvalidInput(format!(
                "approved executable is unavailable: {}",
                component.executable.display()
            )));
        }
        Ok(())
    }
}

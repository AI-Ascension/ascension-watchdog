//! Fresh launch material and read-only health observations for an owned gateway.

use crate::config::{ComponentConfig, DesiredMode};
use crate::error::{Result, WatchdogError};
use crate::gateway_health::{GatewayHealthClient, GatewayHealthStatus};
use crate::platform::LaunchSpec;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::process::ProcessIdentity;
use crate::storage::LaunchIntent;
use serde::Serialize;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "runtime_gateway_health_tests.rs"]
mod tests;

/// Both consumers receive one fresh key, exclusively through typed channels.
/// This value is intentionally neither Debug, Clone, nor serializable.
pub(crate) struct GatewayHealthLaunch {
    pub(crate) bootstrap: GatewayHealthBootstrap,
    pub(crate) client: GatewayHealthClient,
}

#[derive(Debug)]
pub(super) struct GatewayHealthWitness {
    identity: ProcessIdentity,
    probe_started_at: Instant,
    status: GatewayHealthStatus,
}

/// Authenticated gateway diagnostics, not host readiness or mutation authority.
#[derive(Clone, Debug, Serialize)]
pub struct GatewayHealthDiagnostics {
    pub phase: String,
    pub readiness: String,
    pub heartbeat_sequence: u64,
    pub heartbeat_age_ms: Option<u64>,
    pub meaningful_progress_age_ms: Option<u64>,
    pub phase_deadline: Option<String>,
    pub queue_depth: u64,
    pub queue_age_ms: Option<u64>,
    pub pending_operation_count: Option<u64>,
    pub lease_remaining_ms: Option<u64>,
    pub instance_incarnation: Option<String>,
}

impl From<&GatewayHealthStatus> for GatewayHealthDiagnostics {
    fn from(status: &GatewayHealthStatus) -> Self {
        Self {
            phase: status.phase().to_owned(),
            readiness: status.readiness().to_owned(),
            heartbeat_sequence: status.heartbeat_sequence(),
            heartbeat_age_ms: status.heartbeat_age_ms(),
            meaningful_progress_age_ms: status.meaningful_progress_age_ms(),
            phase_deadline: status.phase_deadline().map(str::to_owned),
            queue_depth: status.queue_depth(),
            queue_age_ms: status.queue_age_ms(),
            pending_operation_count: status.pending_operation_count(),
            lease_remaining_ms: status.lease_remaining_ms(),
            instance_incarnation: status.instance_incarnation().map(str::to_owned),
        }
    }
}

impl super::Supervisor {
    pub(crate) fn prepare_gateway_health(
        &self,
        component: &ComponentConfig,
        specification: &LaunchSpec,
    ) -> Result<Option<GatewayHealthLaunch>> {
        let Some(health) = self
            .config
            .gateway_health
            .as_ref()
            .filter(|health| health.component_id == component.id)
        else {
            return Ok(None);
        };
        if self.config.allow_synthetic_children {
            return Err(WatchdogError::Unsupported(
                "gateway health requires native retained child ownership".to_owned(),
            ));
        }
        let nonce = Uuid::parse_str(&specification.launch_nonce)
            .map_err(|_| WatchdogError::InvalidInput("invalid gateway launch nonce".to_owned()))?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| {
            WatchdogError::Conflict("gateway health entropy unavailable".to_owned())
        })?;
        let bootstrap = GatewayHealthBootstrap::for_launch(specification, *key)
            .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        let client = GatewayHealthClient::new(
            health.address,
            *key,
            health.binding(&self.config.deployment_id, nonce)?,
            Duration::from_millis(health.timeout_ms),
        )
        .map_err(|error| WatchdogError::InvalidInput(error.to_string()))?;
        Ok(Some(GatewayHealthLaunch { bootstrap, client }))
    }

    pub(crate) fn bind_prepared_gateway_health(
        &mut self,
        component: &ComponentConfig,
        intent: &LaunchIntent,
        launch: &GatewayHealthLaunch,
        now_ms: u64,
    ) -> Result<()> {
        let boot = Uuid::parse_str(&self.worker_boot_id)
            .map_err(|_| WatchdogError::Conflict("watchdog boot identity is invalid".to_owned()))?;
        if let Err(error) =
            self.store
                .bind_gateway_health(&intent.id, boot, &launch.bootstrap, now_ms)
        {
            if let Err(cleanup) = self.store.clean_launch_intent(&intent.id, now_ms) {
                self.quarantine_component(
                    component,
                    Some(intent.launch_nonce.clone()),
                    None,
                    None,
                    None,
                    "gateway health binding and prepared-intent cleanup failed".to_owned(),
                    now_ms,
                )?;
                return Err(WatchdogError::Conflict(format!(
                    "gateway health binding failed ({error}); intent cleanup failed ({cleanup})"
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn probe_gateway_health(
        &mut self,
        component: &ComponentConfig,
        desired_mode: DesiredMode,
        report: &mut super::ReconcileReport,
    ) {
        if self
            .config
            .gateway_health
            .as_ref()
            .is_none_or(|health| health.component_id != component.id)
            || desired_mode == DesiredMode::Stopped
            || desired_mode == DesiredMode::Draining
        {
            return;
        }
        self.gateway_health_witness = None;
        let Some(child) = self.children.get_mut(&component.id) else {
            return;
        };
        let probe_started_at = Instant::now();
        match self.process_manager.probe_gateway_health(child) {
            Ok(status) => {
                report.gateway_health = Some(GatewayHealthDiagnostics::from(&status));
                self.gateway_health_witness = Some(GatewayHealthWitness {
                    identity: child.identity().clone(),
                    probe_started_at,
                    status,
                });
            }
            Err(error) => report
                .errors
                .push(format!("gateway health unavailable: {error}")),
        }
    }

    pub(crate) fn gateway_heartbeat_age_ms(&self, component_id: &str) -> Option<u64> {
        let witness = self.gateway_health_witness.as_ref()?;
        let child = self.children.get(component_id)?;
        if self.config.gateway_health.as_ref()?.component_id != component_id
            || witness.identity != *child.identity()
        {
            return None;
        }
        // Include the entire bounded round trip conservatively. Starting age
        // at receipt would hide time spent carrying an already-aged heartbeat.
        let elapsed = u64::try_from(witness.probe_started_at.elapsed().as_millis()).ok()?;
        witness.status.heartbeat_age_ms()?.checked_add(elapsed)
    }

    /// Health can veto unavailable control transport, not demand an existing
    /// host fence before the harness work that establishes it can be claimed.
    /// Mutation readiness remains with the harness/gateway recovery protocol.
    pub(crate) fn gateway_allows_fresh_claim(&self) -> bool {
        let Some(config) = self.config.gateway_health.as_ref() else {
            return true;
        };
        // A fresh authenticated heartbeat cannot revoke durable quarantine
        // or authorize claims when the owner-local state cannot be read.
        let Ok(Some(component)) = self.store.component(&config.component_id) else {
            return false;
        };
        self.gateway_heartbeat_age_ms(&config.component_id)
            .is_some_and(|age| {
                age <= self
                    .config
                    .probe_interval_ms
                    .saturating_mul(u64::from(self.config.suspect_threshold))
                    && self.gateway_health_witness.as_ref().is_some_and(|witness| {
                        permits_bootstrap_work(&witness.status, component.state)
                    })
            })
    }
}

fn permits_bootstrap_work(status: &GatewayHealthStatus, state: super::ComponentState) -> bool {
    state == super::ComponentState::Running
        && !status.shutdown_requested()
        && status.phase() != "draining"
}

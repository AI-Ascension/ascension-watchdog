//! Service health advances only after the owning reconciliation loop completes.
//!
//! This is watchdog-loop readiness, not gateway, provider, or game readiness.
//! No timer or IPC worker can manufacture a completed reconciliation heartbeat.

use crate::admin::{HealthSnapshot, MainLoopHealth, MainLoopPhase};
use crate::config::DesiredMode;
use crate::error::{Result, WatchdogError};
use crate::runtime::{ReconcileReport, Supervisor};
use crate::storage::now_unix_ms;
use std::time::Duration;

/// Owns the controller and its monotonic sequence of completed loop iterations.
pub struct ServiceLoop {
    supervisor: Supervisor,
    health: MainLoopHealth,
    sequence: u64,
    probe_interval: Duration,
}

impl ServiceLoop {
    pub fn new(supervisor: Supervisor, probe_interval: Duration) -> Result<Self> {
        if probe_interval.is_zero() || probe_interval > Duration::from_mins(1) {
            return Err(WatchdogError::InvalidInput(
                "service probe interval must be positive and at most 60 seconds".to_owned(),
            ));
        }
        Ok(Self {
            supervisor,
            health: MainLoopHealth::new(),
            sequence: 0,
            probe_interval,
        })
    }

    /// Read-only publication handle for authenticated IPC workers.
    pub fn health(&self) -> MainLoopHealth {
        self.health.clone()
    }

    /// Drain authenticated commands on the same thread that owns reconciliation.
    pub fn drain_admin(&mut self, queue: &crate::admin::AdminQueue, now_ms: u64) -> usize {
        let mut dispatcher = crate::runtime::runtime_admin::Dispatcher {
            supervisor: &mut self.supervisor,
            health: &self.health,
        };
        queue.drain(
            &mut dispatcher,
            &self.health,
            now_ms,
            crate::admin::MAX_DRAIN_BATCH,
        )
    }

    /// A failed iteration never advances the successful-progress sequence.
    pub fn reconcile(&mut self, now_ms: u64) -> Result<ReconcileReport> {
        let report = match self.supervisor.reconcile_once(now_ms) {
            Ok(report) => report,
            Err(error) => {
                let mut snapshot = self.health.snapshot();
                snapshot.ready = false;
                snapshot.phase = MainLoopPhase::Blocked;
                self.health
                    .publish(snapshot)
                    .map_err(WatchdogError::InvalidInput)?;
                return Err(error);
            }
        };
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            WatchdogError::Conflict("service progress sequence exhausted".to_owned())
        })?;
        let phase = if !report.errors.is_empty() || !report.quarantined.is_empty() {
            MainLoopPhase::Blocked
        } else {
            match report.desired_mode {
                DesiredMode::Stopped => MainLoopPhase::Stopped,
                DesiredMode::Paused => MainLoopPhase::Paused,
                DesiredMode::Draining => MainLoopPhase::Draining,
                DesiredMode::Running => MainLoopPhase::Reconciling,
            }
        };
        self.health
            .publish(HealthSnapshot {
                phase,
                // Healthy paused/blocked control loops must remain observable;
                // this flag never represents child mutation readiness.
                ready: true,
                heartbeat_seq: self.sequence,
                progress_age_ms: Some(0),
                ..HealthSnapshot::default()
            })
            .map_err(WatchdogError::InvalidInput)?;
        Ok(report)
    }

    /// Without an admin endpoint, exit after stopped intent and verified cleanup.
    /// With authenticated control configured, remain available while stopped so
    /// the operator can inspect or start the deployment. Notifications reflect
    /// successful reconciliation on this same thread, never a transport worker.
    pub fn run_until_stopped(&mut self) -> Result<()> {
        let admin = self
            .supervisor
            .admin_configuration()
            .map(|config| {
                use crate::admin::{
                    AdminQueue, AdminServer, AdminServerConfig, AuthReferences, MAX_QUEUE,
                };
                let auth = AuthReferences::new(config.read_token_path, config.admin_token_path)?;
                let server_config = AdminServerConfig::new(config.endpoint, auth)?;
                #[cfg(windows)]
                let server_config = if let Some(sid) = config.allowed_peer_sid {
                    server_config.with_allowed_peer_sid(sid)?
                } else {
                    server_config
                };
                let queue = AdminQueue::new(MAX_QUEUE).map_err(WatchdogError::InvalidInput)?;
                let server = AdminServer::start(server_config, queue.clone(), self.health.clone())?;
                Ok::<_, WatchdogError>((queue, server))
            })
            .transpose()?;
        #[cfg(target_os = "linux")]
        let mut notifier = crate::platform::SystemdNotifier::from_environment()
            .map_err(WatchdogError::InvalidInput)?;
        #[cfg(target_os = "linux")]
        if notifier
            .watchdog_interval()
            .is_some_and(|deadline| self.probe_interval >= deadline / 2)
        {
            return Err(WatchdogError::InvalidInput(
                "probe interval must be below half the systemd watchdog deadline".to_owned(),
            ));
        }
        loop {
            if let Some((queue, _server)) = &admin {
                self.drain_admin(queue, now_unix_ms());
            }
            let report = self.reconcile(now_unix_ms())?;
            #[cfg(target_os = "linux")]
            notifier
                .progress(
                    self.sequence,
                    &format!("watchdog_loop={:?}", self.health.snapshot().phase),
                )
                .map_err(WatchdogError::InvalidInput)?;
            if admin.is_none()
                && report.desired_mode == DesiredMode::Stopped
                && self.supervisor.has_no_owned_children()
                && report.quarantined.is_empty()
                && report.errors.is_empty()
            {
                #[cfg(target_os = "linux")]
                notifier.stopping().map_err(WatchdogError::InvalidInput)?;
                return Ok(());
            }
            std::thread::sleep(self.probe_interval);
        }
    }
}

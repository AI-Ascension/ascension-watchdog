//! Deterministic reconciliation decisions.
//!
//! The policy is deliberately independent of SQLite and process handles.  It
//! consumes an explicit observation and timestamp, making timer and recovery
//! behavior reproducible in unit/property tests.

use crate::config::{DesiredMode, WatchdogConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Lifecycle observed for one approved component.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    #[default]
    Stopped,
    Starting,
    Running,
    Suspect,
    Backoff,
    Paused,
    Blocked,
    Quarantined,
}

/// A bounded observation supplied by the runtime adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentObservation {
    pub component_id: String,
    pub state: ComponentState,
    pub observed_at_ms: u64,
    #[serde(default)]
    pub heartbeat_age_ms: Option<u64>,
    #[serde(default)]
    pub progress_age_ms: Option<u64>,
    #[serde(default)]
    pub consecutive_misses: u32,
    #[serde(default)]
    pub restart_attempts: u32,
}

impl ComponentObservation {
    /// Construct a stopped observation at an explicit policy time.
    #[must_use]
    pub fn stopped(component_id: impl Into<String>, now_ms: u64) -> Self {
        Self {
            component_id: component_id.into(),
            state: ComponentState::Stopped,
            observed_at_ms: now_ms,
            heartbeat_age_ms: None,
            progress_age_ms: None,
            consecutive_misses: 0,
            restart_attempts: 0,
        }
    }
}

/// The smallest authorized action for a component.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileAction {
    Noop,
    Start,
    Stop,
    Wait,
    MarkSuspect,
    Quarantine,
}

/// A policy result with an auditable reason and optional next retry deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReconcileDecision {
    pub component_id: String,
    pub action: ReconcileAction,
    pub resulting_state: ComponentState,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at_ms: Option<u64>,
}

/// Pure watchdog policy.  Runtime effects happen only after the decision is
/// durably recorded by the caller.
#[derive(Clone, Debug)]
pub struct SupervisorPolicy {
    probe_interval_ms: u64,
    suspect_threshold: u32,
    startup_grace_ms: u64,
    restart_backoff_base_ms: u64,
    restart_backoff_cap_ms: u64,
    restart_budget_count: u32,
    restart_budget_window_ms: u64,
}

/// A bounded, deterministic restart budget driven only by a monotonic elapsed
/// observation. Wall-clock timestamps are intentionally not accepted here:
/// moving a calendar forward must never make prior failures disappear.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestartBudget {
    max_events: u32,
    window_ms: u64,
    last_elapsed_ms: u64,
    events: Vec<u64>,
}

impl RestartBudget {
    /// Construct a bounded budget. Zero values are represented as an already
    /// exhausted budget so an unvalidated caller cannot accidentally admit a
    /// restart.
    #[must_use]
    pub fn new(max_events: u32, window_ms: u64) -> Self {
        Self {
            max_events,
            window_ms,
            last_elapsed_ms: 0,
            events: Vec::new(),
        }
    }

    /// Observe monotonic elapsed time and age only events that are truly
    /// outside the configured window. Backward observations are clamped.
    pub fn observe(&mut self, elapsed_ms: u64) -> u32 {
        self.last_elapsed_ms = self.last_elapsed_ms.max(elapsed_ms);
        let cutoff = self.last_elapsed_ms.saturating_sub(self.window_ms);
        self.events.retain(|event| *event >= cutoff);
        u32::try_from(self.events.len()).unwrap_or(u32::MAX)
    }

    /// Record one restart at a monotonic elapsed observation. Once exhausted,
    /// no additional event is admitted and the bounded count remains stable.
    pub fn record(&mut self, elapsed_ms: u64) -> u32 {
        let count = self.observe(elapsed_ms);
        if count < self.max_events {
            self.events.push(self.last_elapsed_ms);
        }
        u32::try_from(self.events.len()).unwrap_or(u32::MAX)
    }

    /// Return whether another restart remains within the budget.
    #[must_use]
    pub fn admits_restart(&self) -> bool {
        self.max_events > 0 && self.events.len() < self.max_events as usize
    }

    /// Current bounded event count after the latest observation.
    #[must_use]
    pub fn count(&self) -> u32 {
        u32::try_from(self.events.len()).unwrap_or(u32::MAX)
    }
}

impl SupervisorPolicy {
    /// Build policy from validated configuration.
    #[must_use]
    pub fn from_config(config: &WatchdogConfig) -> Self {
        Self {
            probe_interval_ms: config.probe_interval_ms,
            suspect_threshold: config.suspect_threshold,
            startup_grace_ms: config.startup_grace_secs.saturating_mul(1_000),
            restart_backoff_base_ms: config.restart_backoff_base_secs.saturating_mul(1_000),
            restart_backoff_cap_ms: config.restart_backoff_cap_secs.saturating_mul(1_000),
            restart_budget_count: config.restart_budget_count,
            restart_budget_window_ms: config.restart_budget_window_secs.saturating_mul(1_000),
        }
    }

    /// Decide the smallest action for an observation and durable intent.
    ///
    /// `restart_count_in_window` is read from storage; policy never resets it
    /// merely because this process restarted.
    #[must_use]
    pub fn decide(
        &self,
        desired_mode: DesiredMode,
        restart_enabled: bool,
        observation: &ComponentObservation,
        now_ms: u64,
        restart_count_in_window: u32,
        last_restart_ms: Option<u64>,
    ) -> ReconcileDecision {
        let id = observation.component_id.clone();
        if desired_mode.stops_children() {
            return ReconcileDecision {
                component_id: id,
                action: if observation.state == ComponentState::Stopped {
                    ReconcileAction::Noop
                } else {
                    ReconcileAction::Stop
                },
                resulting_state: ComponentState::Stopped,
                reason: "durable stop intent takes precedence over autonomous recovery".to_string(),
                retry_at_ms: None,
            };
        }
        if desired_mode == DesiredMode::Draining {
            return ReconcileDecision {
                component_id: id,
                action: if observation.state == ComponentState::Stopped {
                    ReconcileAction::Noop
                } else {
                    ReconcileAction::Stop
                },
                resulting_state: ComponentState::Stopped,
                reason: "drain intent prevents new starts and stops owned children".to_string(),
                retry_at_ms: None,
            };
        }
        if desired_mode != DesiredMode::Running {
            return ReconcileDecision {
                component_id: id,
                action: if observation.state == ComponentState::Stopped {
                    ReconcileAction::Noop
                } else {
                    ReconcileAction::Wait
                },
                resulting_state: ComponentState::Paused,
                reason: "operator intent blocks new starts and dispatch".to_string(),
                retry_at_ms: None,
            };
        }

        match observation.state {
            ComponentState::Running => {
                if observation.consecutive_misses >= self.suspect_threshold {
                    ReconcileDecision {
                        component_id: id,
                        action: ReconcileAction::MarkSuspect,
                        resulting_state: ComponentState::Suspect,
                        reason: "consecutive health misses crossed suspect threshold".to_string(),
                        retry_at_ms: None,
                    }
                } else {
                    ReconcileDecision {
                        component_id: id,
                        action: ReconcileAction::Noop,
                        resulting_state: ComponentState::Running,
                        reason: "component is making progress within health bounds".to_string(),
                        retry_at_ms: None,
                    }
                }
            }
            ComponentState::Starting => {
                let age = now_ms.saturating_sub(observation.observed_at_ms);
                if age <= self.startup_grace_ms {
                    ReconcileDecision {
                        component_id: id,
                        action: ReconcileAction::Wait,
                        resulting_state: ComponentState::Starting,
                        reason: "startup remains within configured grace period".to_string(),
                        retry_at_ms: Some(now_ms.saturating_add(self.probe_interval_ms)),
                    }
                } else {
                    self.restart_decision(
                        desired_mode,
                        restart_enabled,
                        observation,
                        now_ms,
                        restart_count_in_window,
                        last_restart_ms,
                        "startup grace expired",
                    )
                }
            }
            ComponentState::Stopped | ComponentState::Suspect | ComponentState::Backoff => self
                .restart_decision(
                    desired_mode,
                    restart_enabled,
                    observation,
                    now_ms,
                    restart_count_in_window,
                    last_restart_ms,
                    "component is not running",
                ),
            ComponentState::Paused => ReconcileDecision {
                component_id: id,
                action: ReconcileAction::Wait,
                resulting_state: ComponentState::Paused,
                reason: "component remains paused by durable operator intent".to_string(),
                retry_at_ms: None,
            },
            ComponentState::Blocked | ComponentState::Quarantined => ReconcileDecision {
                component_id: id,
                action: ReconcileAction::Quarantine,
                resulting_state: ComponentState::Quarantined,
                reason: "component is blocked or quarantined; autonomous relaunch is disabled"
                    .to_string(),
                retry_at_ms: None,
            },
        }
    }

    fn restart_decision(
        &self,
        _desired_mode: DesiredMode,
        restart_enabled: bool,
        observation: &ComponentObservation,
        now_ms: u64,
        restart_count_in_window: u32,
        last_restart_ms: Option<u64>,
        reason: &str,
    ) -> ReconcileDecision {
        let id = observation.component_id.clone();
        if !restart_enabled {
            return ReconcileDecision {
                component_id: id,
                action: ReconcileAction::Quarantine,
                resulting_state: ComponentState::Quarantined,
                reason: "component restart is disabled by the approved configuration".to_string(),
                retry_at_ms: None,
            };
        }
        if restart_count_in_window >= self.restart_budget_count {
            return ReconcileDecision {
                component_id: id,
                action: ReconcileAction::Quarantine,
                resulting_state: ComponentState::Quarantined,
                reason: "restart budget exhausted; bounded diagnostics remain available"
                    .to_string(),
                retry_at_ms: None,
            };
        }
        let delay = self.backoff_delay_ms(&observation.component_id, observation.restart_attempts);
        if let Some(last_restart) = last_restart_ms {
            let next = last_restart.saturating_add(delay);
            if now_ms < next {
                return ReconcileDecision {
                    component_id: id,
                    action: ReconcileAction::Wait,
                    resulting_state: ComponentState::Backoff,
                    reason: "restart backoff is still active".to_string(),
                    retry_at_ms: Some(next),
                };
            }
        }
        ReconcileDecision {
            component_id: id,
            action: ReconcileAction::Start,
            resulting_state: ComponentState::Starting,
            reason: reason.to_string(),
            retry_at_ms: None,
        }
    }

    /// Deterministic exponential backoff with bounded, identity-derived
    /// jitter.  It needs no random source and therefore survives daemon restarts
    /// with the same durable attempt count.
    #[must_use]
    pub fn backoff_delay_ms(&self, component_id: &str, attempt: u32) -> u64 {
        let shift = attempt.min(31);
        let exponential = self
            .restart_backoff_base_ms
            .saturating_mul(1_u64 << shift)
            .min(self.restart_backoff_cap_ms);
        let mut hasher = Sha256::new();
        hasher.update(component_id.as_bytes());
        hasher.update(attempt.to_le_bytes());
        let digest = hasher.finalize();
        let spread = exponential / 4;
        if spread == 0 {
            return exponential;
        }
        let sample = u64::from(u16::from_le_bytes([digest[0], digest[1]]));
        let jitter = sample % (spread.saturating_mul(2).saturating_add(1));
        exponential
            .saturating_sub(spread)
            .saturating_add(jitter)
            .min(self.restart_backoff_cap_ms)
    }

    /// True when a restart record still belongs to the active rolling window.
    #[must_use]
    pub fn in_restart_window(&self, now_ms: u64, started_ms: u64) -> bool {
        now_ms.saturating_sub(started_ms) <= self.restart_budget_window_ms
    }

    /// Check a restart event against monotonic elapsed observations. This is
    /// the safe counterpart to [`Self::in_restart_window`], whose wall-clock
    /// signature remains for compatibility with older adapters.
    #[must_use]
    pub fn in_monotonic_restart_window(&self, elapsed_ms: u64, event_elapsed_ms: u64) -> bool {
        elapsed_ms.saturating_sub(event_elapsed_ms) <= self.restart_budget_window_ms
    }

    /// Construct a pure in-memory budget with the configured limits. Durable
    /// callers should persist the same event transitions through `Store`.
    #[must_use]
    pub fn restart_budget(&self) -> RestartBudget {
        RestartBudget::new(self.restart_budget_count, self.restart_budget_window_ms)
    }
}

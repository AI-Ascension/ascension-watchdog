// SPDX-License-Identifier: MIT

//! Deterministic health-policy regressions for the worker heartbeat seam.
//!
//! Worker transport is outside this deterministic policy suite. These tests
//! keep the health contract portable: only fresh heartbeat evidence can keep a
//! live component in `Running`, while failed or stale evidence remains
//! `Suspect`.

use ascension_watchdog::policy::{ComponentObservation, ComponentState};
use ascension_watchdog::{DesiredMode, ReconcileAction, SupervisorPolicy, WatchdogConfig};

fn running_observation(heartbeat_age_ms: Option<u64>) -> ComponentObservation {
    ComponentObservation {
        component_id: "harness".to_owned(),
        state: ComponentState::Running,
        observed_at_ms: 2_000,
        heartbeat_age_ms,
        progress_age_ms: None,
        consecutive_misses: 0,
        restart_attempts: 1,
    }
}

#[test]
fn fresh_heartbeat_keeps_a_running_component_healthy() {
    let config = WatchdogConfig::default();
    let policy = SupervisorPolicy::from_config(&config);
    let decision = policy.decide(
        DesiredMode::Running,
        true,
        &running_observation(Some(0)),
        2_000,
        0,
        None,
    );

    assert_eq!(decision.action, ReconcileAction::Noop);
    assert_eq!(decision.resulting_state, ComponentState::Running);
}

#[test]
fn missing_heartbeat_marks_a_running_component_suspect() {
    let config = WatchdogConfig::default();
    let policy = SupervisorPolicy::from_config(&config);
    for phase in ["probe", "control"] {
        let decision = policy.decide(
            DesiredMode::Running,
            true,
            &running_observation(None),
            2_000,
            0,
            None,
        );
        assert_eq!(
            decision.action,
            ReconcileAction::MarkSuspect,
            "{phase} failure"
        );
        assert_eq!(decision.resulting_state, ComponentState::Suspect);
    }
}

#[test]
fn stale_heartbeat_is_as_unsafe_as_a_missing_heartbeat() {
    let config = WatchdogConfig::default();
    let policy = SupervisorPolicy::from_config(&config);
    let limit = config
        .probe_interval_ms
        .saturating_mul(u64::from(config.suspect_threshold));
    for age in [None, Some(limit.saturating_add(1)), Some(u64::MAX)] {
        let decision = policy.decide(
            DesiredMode::Running,
            true,
            &running_observation(age),
            2_000,
            0,
            None,
        );
        assert_eq!(decision.action, ReconcileAction::MarkSuspect);
        assert_eq!(decision.resulting_state, ComponentState::Suspect);
    }
}

#[test]
fn stop_and_quarantine_intents_survive_a_fresh_heartbeat() {
    let config = WatchdogConfig::default();
    let policy = SupervisorPolicy::from_config(&config);

    let stopped = policy.decide(
        DesiredMode::Stopped,
        true,
        &running_observation(Some(0)),
        2_000,
        0,
        None,
    );
    assert_eq!(stopped.action, ReconcileAction::Stop);
    assert_eq!(stopped.resulting_state, ComponentState::Stopped);

    let mut quarantined = running_observation(Some(0));
    quarantined.state = ComponentState::Quarantined;
    let decision = policy.decide(DesiredMode::Running, true, &quarantined, 2_000, 0, None);
    assert_eq!(decision.action, ReconcileAction::Quarantine);
    assert_eq!(decision.resulting_state, ComponentState::Quarantined);
}

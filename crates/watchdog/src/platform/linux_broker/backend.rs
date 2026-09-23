//! `SystemdBackend` contract implemented by every broker backend.
//!
//! The trait describes the launch, containment, retirement and stop effects the
//! coordinator may request. The native systemd backend and the test fake
//! implement it; the shared receipt and observation contracts stay with the
//! broker coordinator.

#[allow(clippy::wildcard_imports)]
use super::*;

pub trait SystemdBackend: QueuedJobBackend {
    fn start(
        &mut self,
        unit: &str,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        deadline: Instant,
    ) -> BrokerResult<UnitObservation>;
    fn inspect(
        &mut self,
        unit: &str,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>>;
    /// Capture containment only for the freshly started process after policy
    /// verification. This is not an adoption path for a previous owner's unit.
    fn retain_containment(
        &mut self,
        request: &BrokerRequest,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Require an already retained original capability. Never recover a lost
    /// handle by reopening the unit pathname, even for a matching live process.
    fn require_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Local original-object proof for cleanup, including an unacknowledged
    /// launch whose manager-store transfer was uncertain. This never permits
    /// a launch acknowledgement or replacement-path acquisition.
    fn require_local_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Prove the original containment is empty, not merely that its unit name
    /// is absent. Missing retained evidence returns false or an error. This
    /// method performs no termination and grants no new launch authority.
    fn verify_retirement(
        &mut self,
        expected: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<bool>;
    /// Validate historical cleanup authority against the retained original
    /// object and current policy, without acquiring any new capability.
    fn require_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Clean up the already-owned containment when no live leader observation
    /// exists. Caller must durably record stop intent first. Never resolve a
    /// PID or unit pathname; success still requires a positive empty witness.
    fn stop_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        deadline: Instant,
    ) -> BrokerResult<()>;
    /// Drop only the descriptor-store capability for an already durable
    /// terminal receipt. Failure retains terminal state and is retryable;
    /// callers must never invoke this from read-only inspection.
    fn release_retired(&mut self, receipt: &LaunchReceipt, deadline: Instant) -> BrokerResult<()>;
    /// Stop only the unit object bound to this exact live observation. Native
    /// backends must use an immutable containment capability rather than resolving
    /// the caller-supplied unit name again at effect time.
    fn stop(
        &mut self,
        unit: &str,
        expected: &UnitObservation,
        deadline: Instant,
    ) -> BrokerResult<()>;
}

//! Deterministic in-memory backend fixture for the linux broker tests.
//!
//! Extracted verbatim from the `tests` coordinator; only visibility was widened
//! from private/`pub(super)`-in-`tests` to the equivalent linux-broker scope so the
//! coordinator, its sibling test modules and their consumers keep observing the
//! same fixture state. No behaviour changed.

use super::*;

pub(in crate::platform::linux_broker) struct FakeBackend {
    pub(in crate::platform::linux_broker) starts: usize,
    pub(in crate::platform::linux_broker) bootstraps:
        Vec<(bootstrap::BrokerBootstrapBinding, Vec<u8>)>,
    pub(super) inspects: usize,
    pub(super) stops: usize,
    pub(super) units: BTreeMap<String, UnitObservation>,
    pub(super) stop_error: Option<BrokerError>,
    pub(super) retain_on_stop: bool,
    pub(super) start_override: Option<UnitObservation>,
    pub(super) retained: BTreeMap<String, UnitObservation>,
    pub(super) emptied: BTreeMap<String, UnitObservation>,
    pub(super) containment_error: Option<BrokerError>,
    pub(super) store_error_after_capture: Option<BrokerError>,
    pub(super) withhold_empty_proof: bool,
    pub(super) releases: usize,
    pub(super) release_error: Option<BrokerError>,
    pub(super) orphan_stops: usize,
    pub(super) retirement_error: Option<BrokerError>,
    pub(super) inspect_error: Option<BrokerError>,
    pub(super) queued_job: Option<ledger::JobBinding>,
    pub(super) queued_resolution: QueuedJobResolution,
    pub(super) queued_cancellations: usize,
}

impl FakeBackend {
    pub(in crate::platform::linux_broker) fn new() -> Self {
        Self {
            starts: 0,
            bootstraps: Vec::new(),
            inspects: 0,
            stops: 0,
            units: BTreeMap::new(),
            stop_error: None,
            retain_on_stop: false,
            start_override: None,
            retained: BTreeMap::new(),
            emptied: BTreeMap::new(),
            containment_error: None,
            store_error_after_capture: None,
            withhold_empty_proof: false,
            releases: 0,
            release_error: None,
            orphan_stops: 0,
            retirement_error: None,
            inspect_error: None,
            queued_job: None,
            queued_resolution: QueuedJobResolution::Gone,
            queued_cancellations: 0,
        }
    }
}

impl SystemdBackend for FakeBackend {
    fn release_retired(
        &mut self,
        _receipt: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        self.releases += 1;
        if let Some(error) = &self.release_error {
            return Err(error.clone());
        }
        Ok(())
    }
    fn start(
        &mut self,
        unit: &str,
        _request: &BrokerRequest,
        policy: &LaunchPolicy,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        _deadline: Instant,
    ) -> BrokerResult<UnitObservation> {
        self.starts += 1;
        if let Some(bootstrap) = bootstrap {
            self.bootstraps
                .push((bootstrap.binding().clone(), bootstrap.frame().to_vec()));
        }
        let observation = self
            .start_override
            .clone()
            .unwrap_or_else(|| UnitObservation {
                unit: unit.to_owned(),
                pid: 42,
                creation_token: "start-token".to_owned(),
                executable: policy.executable.clone(),
                executable_sha256: policy.executable_sha256.clone(),
                uid: policy.target_uid,
                gid: policy.target_gid,
                capability_bounding_set: policy.capabilities.bounding_set,
                ambient_capabilities: policy.capabilities.ambient_set,
                no_new_privileges: true,
                control_group: format!("/system.slice/{unit}"),
            });
        self.units.insert(unit.to_owned(), observation.clone());
        Ok(observation)
    }

    fn inspect(
        &mut self,
        unit: &str,
        _policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<Option<UnitObservation>> {
        self.inspects += 1;
        if let Some(error) = &self.inspect_error {
            return Err(error.clone());
        }
        Ok(self.units.get(unit).cloned())
    }

    fn stop(
        &mut self,
        unit: &str,
        expected: &UnitObservation,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        self.stops += 1;
        if let Some(error) = self.stop_error.clone() {
            return Err(error);
        }
        if expected.unit != unit || self.units.get(unit) != Some(expected) {
            return Err(BrokerError::Conflict(
                "fake exact stop binding changed".to_owned(),
            ));
        }
        if !self.retain_on_stop {
            self.units.remove(unit);
            if !self.withhold_empty_proof {
                self.emptied.insert(unit.to_owned(), expected.clone());
            }
        }
        Ok(())
    }

    fn retain_containment(
        &mut self,
        _request: &BrokerRequest,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        if let Some(error) = self.containment_error.clone() {
            return Err(error);
        }
        expected.verify(&expected.unit, policy)?;
        if let Some(previous) = self.retained.get(&expected.unit) {
            if previous != expected {
                return Err(BrokerError::Conflict(
                    "retained identity changed".to_owned(),
                ));
            }
        } else {
            self.retained
                .insert(expected.unit.clone(), expected.clone());
        }
        if let Some(error) = &self.store_error_after_capture {
            return Err(error.clone());
        }
        Ok(())
    }

    fn verify_retirement(
        &mut self,
        expected: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<bool> {
        if let Some(error) = &self.retirement_error {
            return Err(error.clone());
        }
        let Some(original) = self.emptied.get(&expected.unit) else {
            return Ok(false);
        };
        if self.retained.get(&expected.unit) != Some(original)
            || !ledger::same_process_binding(
                &receipt_from(&expected.request, original, false),
                expected,
            )
        {
            return Err(BrokerError::Conflict(
                "foreign population witness".to_owned(),
            ));
        }
        Ok(true)
    }

    fn require_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        remaining(deadline)?;
        verify_receipt_identity(
            receipt,
            &receipt.request,
            &unit_name(&receipt.request),
            policy,
        )?;
        let original = self.retained.get(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment is unavailable".to_owned())
        })?;
        original.verify(&receipt.unit, policy)?;
        if !ledger::same_process_binding(&receipt_from(&receipt.request, original, false), receipt)
        {
            return Err(BrokerError::Conflict(
                "original receipt binding differs".to_owned(),
            ));
        }
        Ok(())
    }

    fn stop_retained_containment(
        &mut self,
        receipt: &LaunchReceipt,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        let original = self.retained.get(&receipt.unit).ok_or_else(|| {
            BrokerError::Conflict("original containment is unavailable".to_owned())
        })?;
        if !ledger::same_process_binding(&receipt_from(&receipt.request, original, false), receipt)
        {
            return Err(BrokerError::Conflict(
                "original receipt binding differs".to_owned(),
            ));
        }
        self.orphan_stops += 1;
        if let Some(error) = &self.stop_error {
            return Err(error.clone());
        }
        if !self.withhold_empty_proof {
            self.emptied.insert(receipt.unit.clone(), original.clone());
        }
        Ok(())
    }

    fn require_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        deadline: Instant,
    ) -> BrokerResult<()> {
        self.require_local_containment(expected, policy, deadline)?;
        if let Some(error) = &self.store_error_after_capture {
            return Err(error.clone());
        }
        Ok(())
    }

    fn require_local_containment(
        &mut self,
        expected: &UnitObservation,
        policy: &LaunchPolicy,
        _deadline: Instant,
    ) -> BrokerResult<()> {
        expected.verify(&expected.unit, policy)?;
        if self.retained.get(&expected.unit) != Some(expected) {
            return Err(BrokerError::Conflict(
                "original containment is unavailable".to_owned(),
            ));
        }
        Ok(())
    }
}

impl QueuedJobBackend for FakeBackend {
    fn queued_job_binding(&self, unit: &str) -> Option<&ledger::JobBinding> {
        self.queued_job.as_ref().filter(|job| job.unit() == unit)
    }

    fn resolve_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        _deadline: Instant,
    ) -> BrokerResult<QueuedJobResolution> {
        if self.queued_job.as_ref() != Some(binding) {
            return Err(BrokerError::Conflict(
                "fake queued job binding changed".to_owned(),
            ));
        }
        Ok(self.queued_resolution)
    }

    fn cancel_queued_job(
        &mut self,
        binding: &ledger::JobBinding,
        _deadline: Instant,
    ) -> BrokerResult<QueuedJobCancellation> {
        if self.queued_job.as_ref() != Some(binding) {
            return Err(BrokerError::Conflict(
                "fake queued job binding changed".to_owned(),
            ));
        }
        self.queued_cancellations += 1;
        Ok(QueuedJobCancellation::Submitted)
    }
}

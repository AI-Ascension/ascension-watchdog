//! Broker admission, receipts and durable lifecycle state.
//!
//! `LinuxSystemdBroker` owns launch admission, exact-nonce idempotence, the
//! durable receipt ledger transitions and the versioned inspect/stop
//! lifecycle, together with the `UnitObservation`, `LaunchReceipt` and
//! `BrokerLifecycleReceipt` contracts it shares with a backend.
//!
//! The `SystemdBackend` trait intentionally stays with the coordinator module:
//! the Unix socket server, the bounded client and the native backend all
//! consume it, so moving it here would either duplicate the contract or couple
//! the sibling splits.  The shared error vocabulary, the protocol bounds and
//! the `ledger`/`descriptor_store` module declarations also stay there.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(crate) fn unit_name(request: &BrokerRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.component.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(request.instance.as_bytes());
    hasher.update([0]);
    hasher.update(request.incarnation.as_bytes());
    hasher.update([0]);
    hasher.update(request.nonce.as_bytes());
    format!(
        "ascension-watchdog-{}-{}.service",
        request.component.as_str(),
        &hex_digest(&hasher.finalize())[..24]
    )
}

/// Process postcondition returned by a backend. The broker does not
/// acknowledge a launch without all fields being populated and checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnitObservation {
    pub unit: String,
    pub pid: u32,
    pub creation_token: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub no_new_privileges: bool,
    pub control_group: String,
}

impl UnitObservation {
    pub(super) fn verify(&self, unit: &str, policy: &LaunchPolicy) -> BrokerResult<()> {
        if self.unit != unit
            || self.pid == 0
            || self.creation_token.is_empty()
            || self.executable != policy.executable
            || self.executable_sha256 != policy.executable_sha256
            || self.uid != policy.target_uid
            || self.gid != policy.target_gid
            || self.capability_bounding_set != policy.capabilities.bounding_set
            || self.ambient_capabilities != policy.capabilities.ambient_set
            || self.no_new_privileges != policy.capabilities.no_new_privileges
            || !self.control_group.ends_with(&format!("/{unit}"))
        {
            return Err(BrokerError::Conflict(
                "systemd unit postcondition does not match fixed policy".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Public receipt returned to the bounded broker client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReceipt {
    pub request: BrokerRequest,
    pub unit: String,
    pub pid: u32,
    pub creation_token: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub control_group: String,
    pub duplicate: bool,
}

/// Result of a versioned inspect or stop operation.  The embedded launch
/// receipt is the broker-owned identity proof; the state is the only mutable
/// part of the lifecycle view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLifecycleReceipt {
    pub receipt: LaunchReceipt,
    pub state: BrokerLifecycleState,
    pub duplicate: bool,
}

/// Broker state and exact nonce idempotence. The backend owns all privileged
/// effects; this object owns admission and duplicate handling.
pub struct LinuxSystemdBroker<B> {
    pub(super) policy: BrokerPolicy,
    pub(super) backend: B,
    pub(super) ledger: BrokerLedger,
    pub(super) receipts: BTreeMap<BrokerRequest, LaunchReceipt>,
    pub(super) active_units: BTreeSet<String>,
}

impl<B: SystemdBackend> LinuxSystemdBroker<B> {
    pub fn new(policy: BrokerPolicy, backend: B) -> Self {
        Self::new_with_ledger(policy, backend, BrokerLedger::memory())
    }

    pub fn new_with_ledger(policy: BrokerPolicy, backend: B, ledger: BrokerLedger) -> Self {
        Self {
            policy,
            backend,
            ledger,
            receipts: BTreeMap::new(),
            active_units: BTreeSet::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn handle(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<LaunchReceipt> {
        let policy_timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(policy_timeout)
            .unwrap_or_else(Instant::now);
        self.handle_at_deadline(credentials, &request, deadline)
    }

    pub(super) fn handle_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        request_deadline: Instant,
    ) -> BrokerResult<LaunchReceipt> {
        self.handle_launch_at_deadline(credentials, request, None, request_deadline)
    }

    /// Launch a fixed policy with a separately typed stdin frame. The caller
    /// still owns durable deployment admission; parsing a frame is not proof
    /// of Running intent. The broker journals only its immutable frame binding.
    pub fn handle_with_bootstrap(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        bootstrap: &bootstrap::BrokerBootstrapLaunch,
    ) -> BrokerResult<LaunchReceipt> {
        let timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        self.handle_launch_at_deadline(credentials, request, Some(bootstrap), deadline)
    }

    pub(super) fn handle_launch_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        request: &BrokerRequest,
        bootstrap: Option<&bootstrap::BrokerBootstrapLaunch>,
        request_deadline: Instant,
    ) -> BrokerResult<LaunchReceipt> {
        request.validate()?;
        authenticate_peer(credentials, &self.policy.peer, request_deadline)?;
        if let Some(bootstrap) = bootstrap {
            bootstrap.validate_for_request(request)?;
            bootstrap_transport::authenticate_worker_peer(
                bootstrap,
                credentials,
                &self.policy.peer,
                request_deadline,
            )?;
        }
        let policy = self.policy.component(request.component)?;
        // Validate the sole generated environment value before reserving a
        // nonce. Invalid fixed policy must not create an uncertain launch.
        bootstrap_transport::launch_environment(policy, request, bootstrap)?;
        self.ledger.ensure_healthy()?;
        let unit = unit_name(request);
        if !self.active_units.contains(&unit) && self.active_units.len() >= MAX_ACTIVE_PROCESSES {
            return Err(BrokerError::Unavailable(
                "broker active-process capacity is exhausted".to_owned(),
            ));
        }
        let deadline = request_deadline.min(
            Instant::now()
                .checked_add(policy.timeout)
                .unwrap_or(request_deadline),
        );
        let existing = self.ledger.contains(request);
        if !existing {
            // An active deterministic unit without a durable pre-launch
            // reservation belongs to no recoverable operation.  Inspect it
            // before writing anything so this request can never adopt or stop
            // an orphan left by another broker incarnation.
            if self.backend.inspect(&unit, policy, deadline)?.is_some() {
                return Err(BrokerError::Conflict(
                    "active unit has no durable launch reservation".to_owned(),
                ));
            }
        }
        let newly_reserved = match bootstrap {
            Some(bootstrap) => self.ledger.reserve_with_bootstrap(
                request,
                &unit,
                policy,
                Some(bootstrap.binding()),
            )?,
            None => self.ledger.reserve(request, &unit, policy)?,
        };
        if !newly_reserved {
            if self.ledger.pending_cancel_requested(request, policy)? {
                return Err(BrokerError::Conflict(
                    "durable launch cancellation is pending; refusing to relaunch old nonce"
                        .to_owned(),
                ));
            }
            if let Some(observation) = self.backend.inspect(&unit, policy, deadline)? {
                observation.verify(&unit, policy)?;
                let receipt = receipt_from(request, &observation, true);
                self.backend
                    .require_containment(&observation, policy, deadline)?;
                self.ledger.commit(request, &receipt)?;
                self.active_units.insert(unit.clone());
                self.cache_receipt(request, &receipt);
                return Ok(receipt);
            }
            return Err(BrokerError::Conflict(
                "durable launch record has no active unit; refusing to relaunch old nonce"
                    .to_owned(),
            ));
        }
        // A start error does not prove that PID 1 created no unit.  Keep the
        // durable pending reservation and leave cleanup to a later exact-unit
        // reconciliation instead of stopping an orphan that may have raced
        // this request.
        let started = self
            .backend
            .start(&unit, request, policy, bootstrap, deadline);
        // Native systemd returns a unique job object before the unit reaches
        // its active postcondition. Bind that exact object into the pending
        // journal before acknowledging either success or failure. A backend
        // without a queued-job authority (the in-memory test backend and the
        // delegated adapter) conservatively leaves the reservation unbound.
        if let Some(job) = self.backend.queued_job_binding(&unit).cloned() {
            // Append the durable binding before consuming the backend's local
            // copy. If the journal is poisoned, the exact job remains
            // available to this broker incarnation for later reconciliation.
            self.ledger.bind_job(request, policy, &job)?;
            let consumed = self
                .backend
                .take_queued_job_binding(&unit, Instant::now() + MAX_CLEANUP_TIMEOUT)?;
            if consumed != job {
                return Err(BrokerError::Conflict(
                    "backend queued job changed while binding its durable identity".to_owned(),
                ));
            }
        }
        let observation = started?;
        // A failed postcondition cannot supply cleanup authority. In
        // particular, do not follow its cgroup or executable identity:
        // they may describe a different process. Preserve the pending
        // reservation for later exact, policy-verified reconciliation.
        observation.verify(&unit, policy)?;
        if let Err(error) = self
            .backend
            .retain_containment(request, &observation, policy, deadline)
        {
            let cleanup = self.cleanup_failed_launch(request, &observation);
            return Err(cleanup_error(error, cleanup));
        }
        let receipt = receipt_from(request, &observation, false);
        if let Err(error) = self.ledger.commit(request, &receipt) {
            if self.ledger.is_poisoned() {
                // The pending reservation and the exact unit remain for a
                // fresh broker owner to reconcile.  Stopping after an
                // uncertain ledger append would create a second unknown
                // effect and is therefore forbidden while this ledger is
                // poisoned.
                return Err(error);
            }
            let cleanup = self.cleanup_failed_launch(request, &observation);
            return Err(cleanup_error(error, cleanup));
        }
        self.active_units.insert(unit);
        self.cache_receipt(request, &receipt);
        Ok(receipt)
    }

    /// Inspect the exact unit reserved for a request.  This path is
    /// intentionally read-only with respect to the durable ledger and never
    /// adopts a unit or repairs a record.
    pub fn inspect(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle(credentials, BrokerLifecycleOperation::Inspect, request)
    }

    /// Stop only the exact, currently verified unit belonging to a committed
    /// request.  Ownership remains active until both the backend and the
    /// durable terminal transition are proven.
    pub fn stop(
        &mut self,
        credentials: PeerCredentials,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        self.lifecycle(credentials, BrokerLifecycleOperation::Stop, request)
    }

    // Keep ownership of the parsed envelope at this request boundary.
    #[allow(clippy::needless_pass_by_value)]
    fn lifecycle(
        &mut self,
        credentials: PeerCredentials,
        operation: BrokerLifecycleOperation,
        request: BrokerRequest,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        let policy_timeout = self.policy.component(request.component)?.timeout;
        let deadline = Instant::now()
            .checked_add(policy_timeout)
            .unwrap_or_else(Instant::now);
        self.lifecycle_at_deadline(credentials, operation, &request, deadline)
    }

    pub(super) fn lifecycle_at_deadline(
        &mut self,
        credentials: PeerCredentials,
        operation: BrokerLifecycleOperation,
        request: &BrokerRequest,
        request_deadline: Instant,
    ) -> BrokerResult<BrokerLifecycleReceipt> {
        request.validate()?;
        authenticate_peer(credentials, &self.policy.peer, request_deadline)?;
        let policy = self.policy.component(request.component)?;
        self.ledger.ensure_healthy()?;
        let unit = unit_name(request);
        let deadline = request_deadline.min(
            Instant::now()
                .checked_add(policy.timeout)
                .unwrap_or(request_deadline),
        );
        let Some(record) = self.ledger.lifecycle_record(request, &unit, policy)? else {
            return Err(BrokerError::Conflict(
                "lifecycle request has no durable launch reservation".to_owned(),
            ));
        };
        let record_is_stop_pending = matches!(&record, ledger::LifecycleRecord::StopPending(_));
        match record {
            ledger::LifecycleRecord::Pending => {
                if operation == BrokerLifecycleOperation::Stop {
                    // Record the intent before touching PID 1.  The bit is
                    // replayable after broker death and never serves as a
                    // terminal execution witness.
                    self.ledger.request_pending_stop(request, policy)?;
                    if let Some(job) = self.ledger.pending_job_binding(request, policy)? {
                        // A queued-job cancellation is an effect, but neither
                        // a successful CancelJob call nor a raced JobRemoved
                        // event proves whether the transient unit executed.
                        // Keep the pending reservation and force exact unit
                        // reconciliation before any terminal transition.
                        match self.backend.resolve_queued_job(&job, deadline)? {
                            native::QueuedJobResolution::Queued => {
                                let _ = self.backend.cancel_queued_job(&job, deadline)?;
                            }
                            native::QueuedJobResolution::Gone => {}
                        }
                    }
                }
                Err(BrokerError::Conflict(
                    "lifecycle request has an unresolved launch reservation; exact execution remains uncertain"
                        .to_owned(),
                ))
            }
            ledger::LifecycleRecord::Stopped(persisted) => {
                verify_receipt_identity(&persisted, request, &unit, policy)?;
                match self.backend.inspect(&unit, policy, deadline)? {
                    None => {
                        if operation == BrokerLifecycleOperation::Stop {
                            self.backend.release_retired(&persisted, deadline)?;
                        }
                        Ok(BrokerLifecycleReceipt {
                            receipt: persisted,
                            state: BrokerLifecycleState::Stopped,
                            duplicate: matches!(operation, BrokerLifecycleOperation::Stop),
                        })
                    }
                    Some(observation) => {
                        observation.verify(&unit, policy)?;
                        let current = receipt_from(request, &observation, false);
                        if !ledger::same_process_binding(&persisted, &current) {
                            return Err(BrokerError::Conflict(
                                "terminal lifecycle unit identity was replaced".to_owned(),
                            ));
                        }
                        Err(BrokerError::Conflict(
                            "terminal lifecycle unit was reactivated".to_owned(),
                        ))
                    }
                }
            }
            ledger::LifecycleRecord::Committed(persisted)
            | ledger::LifecycleRecord::StopPending(persisted) => {
                let stop_pending = record_is_stop_pending;
                verify_receipt_identity(&persisted, request, &unit, policy)?;
                let Some(observation) = self.backend.inspect(&unit, policy, deadline)? else {
                    if operation == BrokerLifecycleOperation::Stop {
                        // Errors are not a populated witness and must not
                        // authorize fallback cleanup. Only a readable original
                        // which is not empty may enter the retained-object path.
                        if !self.backend.verify_retirement(&persisted, deadline)? {
                            self.backend
                                .require_retained_containment(&persisted, policy, deadline)?;
                            if !stop_pending {
                                self.ledger.begin_stop(request, &persisted)?;
                            }
                            self.backend
                                .stop_retained_containment(&persisted, deadline)?;
                            if !self.backend.verify_retirement(&persisted, deadline)? {
                                return Err(BrokerError::Conflict(
                                    "original orphan containment retirement is unproven".to_owned(),
                                ));
                            }
                        }
                        let mut stopped_receipt = persisted;
                        stopped_receipt.duplicate = false;
                        // Idempotent when the populated path already synced
                        // intent, or when recovering a prior StopPending.
                        self.ledger.begin_stop(request, &stopped_receipt)?;
                        self.ledger.mark_stopped(request, &stopped_receipt)?;
                        self.active_units.remove(&unit);
                        self.backend.release_retired(&stopped_receipt, deadline)?;
                        return Ok(BrokerLifecycleReceipt {
                            receipt: stopped_receipt,
                            state: BrokerLifecycleState::Stopped,
                            duplicate: false,
                        });
                    }
                    return Err(BrokerError::Conflict(
                        if stop_pending {
                            "stop-pending lifecycle unit is inactive; absence is uncommitted"
                        } else {
                            "committed lifecycle unit is inactive or missing; ownership is uncertain"
                        }
                        .to_owned(),
                    ));
                };
                observation.verify(&unit, policy)?;
                let observed = receipt_from(request, &observation, false);
                if !ledger::same_process_binding(&persisted, &observed) {
                    return Err(BrokerError::Conflict(
                        "live lifecycle unit identity differs from its durable receipt".to_owned(),
                    ));
                }
                if operation == BrokerLifecycleOperation::Inspect {
                    if stop_pending {
                        return Err(BrokerError::Conflict(
                            "lifecycle stop is pending; active state is uncertain".to_owned(),
                        ));
                    }
                    return Ok(BrokerLifecycleReceipt {
                        receipt: observed,
                        state: BrokerLifecycleState::Active,
                        duplicate: false,
                    });
                }

                self.backend
                    .require_local_containment(&observation, policy, deadline)?;

                // Persist the intent before the first potentially destructive
                // backend call. This is the recovery authority if the broker
                // dies or the backend times out after its effect.
                if !stop_pending {
                    self.ledger.begin_stop(request, &observed)?;
                }
                if !self.active_units.contains(&unit)
                    && self.active_units.len() >= MAX_ACTIVE_PROCESSES
                {
                    return Err(BrokerError::Unavailable(
                        "broker active-process capacity is exhausted".to_owned(),
                    ));
                }
                self.active_units.insert(unit.clone());
                self.backend.stop(&unit, &observation, deadline)?;
                let confirmation_deadline = request_deadline.min(
                    Instant::now()
                        .checked_add(policy.timeout.min(MAX_CLEANUP_TIMEOUT))
                        .unwrap_or(request_deadline),
                );
                loop {
                    match self.backend.inspect(&unit, policy, confirmation_deadline)? {
                        None => {
                            if !self
                                .backend
                                .verify_retirement(&persisted, confirmation_deadline)?
                            {
                                return Err(BrokerError::Conflict(
                                    "original containment retirement is unproven".to_owned(),
                                ));
                            }
                            let mut stopped_receipt = persisted;
                            stopped_receipt.duplicate = false;
                            self.ledger.mark_stopped(request, &stopped_receipt)?;
                            self.active_units.remove(&unit);
                            self.backend
                                .release_retired(&stopped_receipt, confirmation_deadline)?;
                            return Ok(BrokerLifecycleReceipt {
                                receipt: stopped_receipt,
                                state: BrokerLifecycleState::Stopped,
                                duplicate: false,
                            });
                        }
                        Some(observation) => {
                            observation.verify(&unit, policy)?;
                            let current = receipt_from(request, &observation, false);
                            if !ledger::same_process_binding(&persisted, &current) {
                                return Err(BrokerError::Conflict(
                                    "unit identity changed while exact stop was in flight"
                                        .to_owned(),
                                ));
                            }
                        }
                    }
                    thread::sleep(remaining(confirmation_deadline)?.min(POLL_INTERVAL));
                }
            }
        }
    }

    fn cache_receipt(&mut self, request: &BrokerRequest, receipt: &LaunchReceipt) {
        if self.receipts.len() < MAX_RECEIPTS || self.receipts.contains_key(request) {
            self.receipts.insert(request.clone(), receipt.clone());
        }
    }

    pub(super) fn cleanup_failed_launch(
        &mut self,
        request: &BrokerRequest,
        expected: &UnitObservation,
    ) -> BrokerResult<()> {
        self.ledger.ensure_healthy()?;
        let deadline = Instant::now()
            .checked_add(MAX_CLEANUP_TIMEOUT)
            .unwrap_or_else(Instant::now);
        let policy = self.policy.component(request.component)?;
        self.backend
            .require_local_containment(expected, policy, deadline)?;
        let receipt = receipt_from(request, expected, false);
        // A failed acknowledgement still needs a durable exact process binding
        // before cleanup. Pending -> StopPending preserves retry authority
        // without manufacturing a successful launch acknowledgement.
        self.ledger
            .begin_failed_launch_cleanup(request, &receipt, policy)?;
        self.backend.stop(&expected.unit, expected, deadline)?;
        if !self.backend.verify_retirement(&receipt, deadline)? {
            return Err(BrokerError::Conflict(
                "failed launch containment is not proven empty".to_owned(),
            ));
        }
        self.ledger.mark_stopped(request, &receipt)?;
        self.active_units.remove(&expected.unit);
        self.backend.release_retired(&receipt, deadline)
    }
}

fn cleanup_error(error: BrokerError, cleanup: BrokerResult<()>) -> BrokerError {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => BrokerError::Conflict(format!(
            "launch failed and exact-unit cleanup was not proven: {error}; cleanup: {cleanup_error}"
        )),
    }
}

pub(crate) fn receipt_from(
    request: &BrokerRequest,
    observation: &UnitObservation,
    duplicate: bool,
) -> LaunchReceipt {
    LaunchReceipt {
        request: request.clone(),
        unit: observation.unit.clone(),
        pid: observation.pid,
        creation_token: observation.creation_token.clone(),
        executable: observation.executable.clone(),
        executable_sha256: observation.executable_sha256.clone(),
        uid: observation.uid,
        gid: observation.gid,
        capability_bounding_set: observation.capability_bounding_set,
        ambient_capabilities: observation.ambient_capabilities,
        control_group: observation.control_group.clone(),
        duplicate,
    }
}

pub(crate) fn verify_receipt_identity(
    receipt: &LaunchReceipt,
    request: &BrokerRequest,
    unit: &str,
    policy: &LaunchPolicy,
) -> BrokerResult<()> {
    if receipt.request != *request
        || receipt.unit != unit
        || receipt.pid == 0
        || receipt.creation_token.is_empty()
        || receipt.executable != policy.executable
        || receipt.executable_sha256 != policy.executable_sha256
        || receipt.uid != policy.target_uid
        || receipt.gid != policy.target_gid
        || receipt.capability_bounding_set != policy.capabilities.bounding_set
        || receipt.ambient_capabilities != policy.capabilities.ambient_set
        || !receipt.control_group.ends_with(&format!("/{unit}"))
    {
        return Err(BrokerError::Conflict(
            "durable lifecycle receipt does not match fixed policy".to_owned(),
        ));
    }
    Ok(())
}
